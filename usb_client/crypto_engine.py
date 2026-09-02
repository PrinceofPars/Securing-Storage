"""
crypto_engine.py — Split-Key AES-256-GCM Encryption Engine
============================================================
Implements the cryptographic core of the USB Killswitch system.

Key Architecture:
  K_local   : 32-byte key share stored ON the USB drive (local_key.bin)
  K_cloud   : 32-byte key share returned by the backend API
  K_master  : Derived from K_local XOR K_cloud (or HKDF if configured)
               → Used as the AES-256 encryption key for vault.enc

Vault Format (vault.enc):
  ┌─────────────────────────────────┐
  │  Magic header (8 bytes)         │  "USBVLT01"
  │  Salt (16 bytes)                │  Random, stored in plaintext
  │  AAD length (4 bytes, LE)       │  Length of Additional Auth Data
  │  AAD / metadata JSON            │  File list, timestamps, version
  │  ────── Per-file entries ─────  │
  │  [GCM Nonce (12 bytes)]         │
  │  [GCM Tag   (16 bytes)]         │
  │  [Ciphertext length (8 bytes)]  │
  │  [Ciphertext]                   │
  └─────────────────────────────────┘

Decryption produces files into a secure temporary directory which is
scrubbed on session end (lock command).

Dependencies: cryptography >= 41.0
"""

import io
import json
import logging
import os
import secrets
import shutil
import struct
import tempfile
import time
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

VAULT_MAGIC     = b'USBVLT01'   # 8 bytes — identifies a valid vault file
NONCE_SIZE      = 12            # GCM standard nonce size (bytes)
TAG_SIZE        = 16            # GCM authentication tag size (bytes)
KEY_SIZE        = 32            # AES-256 key size (bytes)
SALT_SIZE       = 16            # HKDF salt size (bytes)
CHUNK_SIZE      = 64 * 1024     # 64 KB read/write chunks

# Path (relative to USB root) for the local key share
LOCAL_KEY_FILENAME  = 'local_key.bin'


# ──────────────────────────────────────────────────────────────────────────────
# Key Management
# ──────────────────────────────────────────────────────────────────────────────

def generate_local_key() -> bytes:
    """
    Generate a new cryptographically random 256-bit local key share.
    Should be called exactly once during drive initialisation.
    """
    return secrets.token_bytes(KEY_SIZE)


def save_local_key(key_bytes: bytes, key_path: Path) -> None:
    """
    Persist the local key share to the USB drive.
    In a production system this file could be stored in a hidden/protected
    partition, but for the PoC it lives in the client directory.
    """
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key_bytes)
    logger.info(f"Local key share saved to: {key_path}")


def load_local_key(key_path: Path) -> bytes:
    """
    Load the local key share from the USB drive.
    Raises FileNotFoundError if the key file is missing.
    """
    if not key_path.exists():
        raise FileNotFoundError(
            f"Local key share not found at: {key_path}\n"
            "Has this drive been initialised? Run option [1] first."
        )
    key_bytes = key_path.read_bytes()
    if len(key_bytes) != KEY_SIZE:
        raise ValueError(
            f"Local key share has unexpected length: {len(key_bytes)} bytes "
            f"(expected {KEY_SIZE}). File may be corrupt."
        )
    return key_bytes


def derive_master_key(
    k_local: bytes,
    k_cloud: bytes,
    salt: Optional[bytes] = None,
    use_hkdf: bool = True
) -> Tuple[bytes, bytes]:
    """
    Derive the master encryption key from the two key shares.

    Method 1 (Default, use_hkdf=True):
      Combined = K_local XOR K_cloud   (bitwise XOR of two 32-byte values)
      K_master = HKDF-SHA256(IKM=Combined, salt=salt, info=b'usb-vault-key', length=32)

    Method 2 (use_hkdf=False):
      K_master = K_local XOR K_cloud   (direct XOR, simpler but less safe)

    Using HKDF is preferred because:
      - Even if one share leaks, HKDF adds an additional extraction step
      - Salt binds the derived key to this specific vault/session
      - Provides key domain separation via the info parameter

    Args:
        k_local:   32-byte local key share (from USB)
        k_cloud:   32-byte cloud key share (from backend)
        salt:      16-byte random salt. If None, a new one is generated.
        use_hkdf:  If True, apply HKDF after XOR combination.

    Returns:
        Tuple of (k_master: bytes, salt: bytes)
    """
    if len(k_local) != KEY_SIZE:
        raise ValueError(f"K_local must be {KEY_SIZE} bytes, got {len(k_local)}")
    if len(k_cloud) != KEY_SIZE:
        raise ValueError(f"K_cloud must be {KEY_SIZE} bytes, got {len(k_cloud)}")

    # Step 1: XOR combine the two shares
    xor_combined = bytes(a ^ b for a, b in zip(k_local, k_cloud))
    logger.debug("Key shares XOR-combined successfully.")

    if not use_hkdf:
        return xor_combined, b''

    # Step 2: HKDF extraction and expansion
    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=b'usb-vault-aes256-gcm-key-v1',
        backend=default_backend()
    )
    k_master = hkdf.derive(xor_combined)
    logger.debug(f"Master key derived via HKDF with salt: {salt.hex()}")

    return k_master, salt


# ──────────────────────────────────────────────────────────────────────────────
# Vault Encryption
# ──────────────────────────────────────────────────────────────────────────────

def _collect_files(source_dir: Path) -> List[Path]:
    """Recursively collect all files under source_dir."""
    files = []
    for item in sorted(source_dir.rglob('*')):
        if item.is_file():
            files.append(item)
    return files


def encrypt_folder_to_vault(
    source_dir: Path,
    vault_path: Path,
    k_local: bytes,
    k_cloud: bytes,
    progress_callback=None
) -> dict:
    """
    Encrypt an entire folder into a single vault.enc file.

    Algorithm per file:
      1. Generate random 12-byte GCM nonce
      2. Encrypt file content with AES-256-GCM using K_master
      3. Write [nonce | tag | ciphertext_length | ciphertext] to vault

    Args:
        progress_callback: Optional callable(current_index, total_count, rel_path_str)

    Returns a metadata dict with file list and vault stats.
    """
    k_master, salt = derive_master_key(k_local, k_cloud)
    aesgcm = AESGCM(k_master)

    files = _collect_files(source_dir)
    if not files:
        raise ValueError(f"No files found in source directory: {source_dir}")

    # Build Additional Authenticated Data (AAD) — metadata not encrypted but authenticated
    file_entries = []
    for f in files:
        rel = f.relative_to(source_dir)
        file_entries.append({
            'path':     str(rel).replace('\\', '/'),
            'size':     f.stat().st_size,
            'modified': int(f.stat().st_mtime)
        })

    aad_meta = {
        'version':    1,
        'created_at': int(time.time()),
        'file_count': len(files),
        'files':      file_entries
    }
    aad_bytes = json.dumps(aad_meta, separators=(',', ':')).encode('utf-8')

    total_encrypted = 0
    vault_path.parent.mkdir(parents=True, exist_ok=True)

    with open(vault_path, 'wb') as vf:
        # Write magic + salt + AAD header
        vf.write(VAULT_MAGIC)
        vf.write(salt)
        vf.write(struct.pack('<I', len(aad_bytes)))  # 4-byte LE AAD length
        vf.write(aad_bytes)

        # Encrypt each file
        for i, file_path in enumerate(files):
            rel_path = str(file_path.relative_to(source_dir)).replace('\\', '/')
            logger.info(f"  Encrypting [{i+1}/{len(files)}]: {rel_path}")
            if progress_callback:
                progress_callback(i + 1, len(files), rel_path)

            nonce = secrets.token_bytes(NONCE_SIZE)
            plaintext = file_path.read_bytes()

            # AAD for this specific file entry = its relative path bytes
            file_aad = rel_path.encode('utf-8')
            ciphertext = aesgcm.encrypt(nonce, plaintext, file_aad)
            # AES-GCM from cryptography lib appends the 16-byte tag at the END
            # ciphertext = actual_ciphertext + tag (last 16 bytes)
            actual_ct = ciphertext[:-TAG_SIZE]
            tag       = ciphertext[-TAG_SIZE:]

            vf.write(nonce)                                      # 12 bytes
            vf.write(tag)                                        # 16 bytes
            vf.write(struct.pack('<Q', len(actual_ct)))          # 8 bytes (uint64 LE)
            vf.write(actual_ct)

            total_encrypted += len(plaintext)

    # Overwrite master key from memory (best-effort in Python)
    k_master = bytes(KEY_SIZE)

    stats = {
        'vault_path':       str(vault_path),
        'source_dir':       str(source_dir),
        'files_encrypted':  len(files),
        'bytes_encrypted':  total_encrypted,
        'vault_size':       vault_path.stat().st_size,
        'salt_hex':         salt.hex(),
        'created_at':       aad_meta['created_at']
    }
    logger.info(f"✅ Vault created: {vault_path} ({len(files)} files, {total_encrypted} bytes)")
    return stats


# ──────────────────────────────────────────────────────────────────────────────
# Vault Decryption
# ──────────────────────────────────────────────────────────────────────────────

def decrypt_vault_to_temp(
    vault_path: Path,
    k_local: bytes,
    k_cloud: bytes
) -> Path:
    """
    Decrypt vault.enc into a secure temporary directory.

    The temp directory is created via tempfile.mkdtemp() and is
    NOT automatically deleted — the caller MUST call secure_wipe_temp()
    when the session ends to prevent data leakage.

    Returns:
        Path to the temporary decrypted directory.

    Raises:
        ValueError:            If the vault magic header is invalid.
        cryptography.exceptions.InvalidTag: If decryption fails (data tampered or wrong key).
    """
    if not vault_path.exists():
        raise FileNotFoundError(f"Vault file not found: {vault_path}")

    k_master, salt = None, None  # Will be set after reading the vault header

    with open(vault_path, 'rb') as vf:
        # Validate magic header
        magic = vf.read(len(VAULT_MAGIC))
        if magic != VAULT_MAGIC:
            raise ValueError(
                f"Invalid vault magic: {magic!r}. "
                "File is not a valid USB Killswitch vault."
            )

        # Read salt and derive master key
        salt = vf.read(SALT_SIZE)
        k_master, _ = derive_master_key(k_local, k_cloud, salt=salt, use_hkdf=True)
        aesgcm = AESGCM(k_master)

        # Read AAD (metadata)
        aad_len_bytes = vf.read(4)
        aad_len       = struct.unpack('<I', aad_len_bytes)[0]
        aad_bytes     = vf.read(aad_len)
        aad_meta      = json.loads(aad_bytes.decode('utf-8'))
        file_list     = aad_meta.get('files', [])
        file_count    = aad_meta.get('file_count', len(file_list))

        logger.info(f"Vault metadata: {file_count} files, created {aad_meta.get('created_at')}")

        # Create secure temp directory
        temp_dir = Path(tempfile.mkdtemp(prefix='usbvault_session_'))
        logger.info(f"Decrypting to temp dir: {temp_dir}")

        # Decrypt each file
        for i, file_entry in enumerate(file_list):
            rel_path = file_entry['path']
            logger.info(f"  Decrypting [{i+1}/{file_count}]: {rel_path}")

            nonce      = vf.read(NONCE_SIZE)
            tag        = vf.read(TAG_SIZE)
            ct_len     = struct.unpack('<Q', vf.read(8))[0]
            ciphertext = vf.read(ct_len)

            # Re-assemble to cryptography lib's expected format: ct + tag
            ct_with_tag = ciphertext + tag
            file_aad    = rel_path.encode('utf-8')

            # This will raise InvalidTag if auth fails — do not catch it here
            plaintext = aesgcm.decrypt(nonce, ct_with_tag, file_aad)

            # Write decrypted file, preserving directory structure
            out_path = temp_dir / rel_path
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(plaintext)

    # Overwrite master key from memory (best-effort)
    k_master = bytes(KEY_SIZE)

    logger.info(f"✅ Vault decrypted: {file_count} files to {temp_dir}")
    return temp_dir


# ──────────────────────────────────────────────────────────────────────────────
# Secure Session Cleanup
# ──────────────────────────────────────────────────────────────────────────────

def secure_wipe_temp(temp_dir: Path, progress_callback=None) -> int:
    """
    Securely erase all files in the temporary session directory.

    For each file:
      1. Overwrite with random bytes (one pass)
      2. Truncate to 0
      3. Delete

    Note: True forensic-grade wiping (DoD 5220.22-M / Gutmann) requires
    multiple passes and is beyond this PoC's scope. Modern SSDs/NVMe with
    wear-leveling may retain data regardless of overwrites.

    Args:
        temp_dir: Path returned by decrypt_vault_to_temp()
        progress_callback: Optional callable(current_count, total_count, rel_path_str)

    Returns:
        Number of files wiped.
    """
    if not temp_dir.exists():
        logger.warning(f"Temp dir does not exist, nothing to wipe: {temp_dir}")
        return 0

    wiped = 0
    errors = []

    files_to_wipe = [f for f in temp_dir.rglob('*') if f.is_file()]
    total_files = len(files_to_wipe)

    for i, file_path in enumerate(files_to_wipe):
        try:
            rel_path = file_path.relative_to(temp_dir)
            logger.info(f"  Wiping [{i+1}/{total_files}]: {rel_path}")
            if progress_callback:
                progress_callback(i + 1, total_files, str(rel_path))

            size = file_path.stat().st_size
            if size > 0:
                with open(file_path, 'r+b') as f:
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
            file_path.unlink()
            wiped += 1
        except Exception as e:
            errors.append((str(file_path), str(e)))
            logger.warning(f"Could not wipe {file_path}: {e}")

    # Remove directory tree
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception as e:
        logger.error(f"Failed to remove temp dir {temp_dir}: {e}")

    if errors:
        logger.warning(f"Wipe completed with {len(errors)} errors.")
    else:
        logger.info(f"✅ Secure wipe complete: {wiped} files erased from {temp_dir}")

    return wiped


# ──────────────────────────────────────────────────────────────────────────────
# Vault Inspection (read metadata without decrypting)
# ──────────────────────────────────────────────────────────────────────────────

def inspect_vault_header(vault_path: Path) -> Optional[dict]:
    """
    Read and return vault metadata (AAD) WITHOUT decrypting file contents.
    Useful for displaying vault info before authentication.
    """
    if not vault_path.exists():
        return None
    try:
        with open(vault_path, 'rb') as vf:
            magic = vf.read(len(VAULT_MAGIC))
            if magic != VAULT_MAGIC:
                return None
            _salt    = vf.read(SALT_SIZE)
            aad_len  = struct.unpack('<I', vf.read(4))[0]
            aad_bytes = vf.read(aad_len)
            return json.loads(aad_bytes.decode('utf-8'))
    except Exception as e:
        logger.warning(f"Could not inspect vault header: {e}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Cloud Key Share Parsing
# ──────────────────────────────────────────────────────────────────────────────

def hex_to_key_bytes(hex_str: str) -> bytes:
    """
    Convert a 64-character hex string (cloud or local key share) to 32 raw bytes.
    """
    hex_str = hex_str.strip().lower()
    if len(hex_str) != 64:
        raise ValueError(
            f"Key share must be 64 hex characters (32 bytes), got {len(hex_str)} chars."
        )
    return bytes.fromhex(hex_str)


def bytes_to_hex(b: bytes) -> str:
    """Convert raw bytes to hex string."""
    return b.hex()


# ──────────────────────────────────────────────────────────────────────────────
# CLI entrypoint (for standalone testing)
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys
    # Fix Windows console encoding
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    logging.basicConfig(level=logging.DEBUG)

    print("Crypto Engine - Self-test")
    print("-" * 40)

    # Test key derivation
    k_local = generate_local_key()
    k_cloud = generate_local_key()  # fake cloud key for testing
    print(f"K_local  (hex): {k_local.hex()}")
    print(f"K_cloud  (hex): {k_cloud.hex()}")

    k_master, salt = derive_master_key(k_local, k_cloud)
    print(f"K_master (hex): {k_master.hex()}")
    print(f"HKDF salt(hex): {salt.hex()}")

    # Verify same inputs → same output
    k_master2, _ = derive_master_key(k_local, k_cloud, salt=salt)
    assert k_master == k_master2, "DETERMINISM TEST FAILED"
    print("✅ Determinism test passed.")

    # Test encrypt/decrypt roundtrip
    if len(sys.argv) > 1:
        test_folder = Path(sys.argv[1])
        vault       = Path('./test_vault.enc')
        stats = encrypt_folder_to_vault(test_folder, vault, k_local, k_cloud)
        print(f"Encrypted: {stats}")
        tmp = decrypt_vault_to_temp(vault, k_local, k_cloud)
        print(f"Decrypted to: {tmp}")
        wiped = secure_wipe_temp(tmp)
        print(f"Wiped {wiped} files.")
