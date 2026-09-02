"""
crypto_engine.py — Split-Key AES-256-GCM Encryption Engine v2
================================================================
Implements the cryptographic core of the USB Killswitch system.

Key Architecture:
  K_local   : 32-byte key share stored ON the USB drive (local_key.bin)
  K_cloud   : 32-byte key share returned by the backend API
  K_master  : Derived from K_local XOR K_cloud via HKDF
               → Used as the AES-256 encryption key for vault.enc

Vault Format v2 (vault.enc) — Tail-Manifest Design:
  ┌──────────────────────────────────────────────┐
  │  Magic header       (8 bytes: "USBVLT02")   │
  │  Salt               (32 bytes)               │
  │  Manifest Offset    (8 bytes, uint64 LE)     │
  ├──────── DATA PAYLOAD ────────────────────────┤
  │  Encrypted file chunk 0                      │
  │  Encrypted file chunk 1                      │
  │  ...                                         │
  ├──────── MANIFEST (at tail) ──────────────────┤
  │  Manifest Nonce     (12 bytes)               │
  │  Manifest Tag       (16 bytes)               │
  │  Manifest CT Length  (4 bytes, uint32 LE)    │
  │  Manifest Ciphertext (encrypted JSON)        │
  └──────────────────────────────────────────────┘

The manifest is at the END of the file so new/modified files
can be appended without rewriting the entire vault.

Dependencies: cryptography >= 41.0
"""

import hashlib
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

VAULT_MAGIC_V3  = b'USBVLT03'   # 8 bytes — v3 encapsulated vault identifier (packed header)
VAULT_MAGIC_V2  = b'USBVLT02'   # 8 bytes — v2 vault identifier (tail-manifest, loose metadata)
VAULT_MAGIC_V1  = b'USBVLT01'   # 8 bytes — v1 (legacy, read-only support)
NONCE_SIZE      = 12             # GCM standard nonce (bytes)
TAG_SIZE        = 16             # GCM authentication tag (bytes)
KEY_SIZE        = 32             # AES-256 key size (bytes)
SALT_SIZE       = 32             # HKDF salt size (bytes)
HEADER_BLOCK_SIZE = 4096        # Fixed 4 KB sector-aligned header block for v3
HEADER_SIZE_V2  = 8 + 32 + 8    # magic + salt + manifest_offset = 48 bytes
HEADER_SIZE     = HEADER_SIZE_V2
DATA_START      = HEADER_SIZE

LOCAL_KEY_FILENAME = 'local_key.bin'

# Encapsulated Header Key Derivation Constants
HEADER_KDF_SECRET = b'ZeroTrustStorageVaultHeaderV3-AuthKey'
HEADER_KDF_SALT   = b'ZeroTrustStorageV3HeaderSalt'
HEADER_KDF_INFO   = b'usb-vault-header-v3-aes256'
HEADER_AAD        = b'USBVLT03-HEADER'


# ──────────────────────────────────────────────────────────────────────────────
# Header & Key Management
# ──────────────────────────────────────────────────────────────────────────────

def _derive_header_key() -> bytes:
    """Derive the AES-256 key used to encrypt/decrypt the encapsulated v3 header."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=HEADER_KDF_SALT,
        info=HEADER_KDF_INFO,
        backend=default_backend()
    )
    return hkdf.derive(HEADER_KDF_SECRET)


def pack_vault_header(
    config: dict,
    k_local: bytes,
    lease_data: Optional[dict] = None
) -> bytes:
    """
    Serialize and encrypt config, k_local, and optional lease_data into a 4096-byte header block.

    Wire Layout (4096 bytes):
      0..7:       Magic header: b"USBVLT03" (8 bytes)
      8..11:      Header version: uint32 LE (4 bytes = 3)
      12..23:     Header AES-GCM Nonce (12 bytes)
      24..39:     Header AES-GCM Tag (16 bytes)
      40..43:     Header Ciphertext Length (4 bytes, uint32 LE)
      44..43+L:   Header Ciphertext (AES-256-GCM encrypted JSON)
      44+L..4095: Zero padding to 4096 bytes
    """
    payload = {
        'config': config,
        'k_local': k_local.hex(),
        'lease': lease_data
    }
    payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')

    header_key = _derive_header_key()
    aesgcm = AESGCM(header_key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct_with_tag = aesgcm.encrypt(nonce, payload_json, HEADER_AAD)
    actual_ct = ct_with_tag[:-TAG_SIZE]
    tag = ct_with_tag[-TAG_SIZE:]

    ct_len = len(actual_ct)
    max_payload = HEADER_BLOCK_SIZE - 44
    if ct_len > max_payload:
        raise ValueError(f"Header payload too large ({ct_len} bytes, max {max_payload})")

    buf = bytearray(HEADER_BLOCK_SIZE)
    buf[0:8] = VAULT_MAGIC_V3
    struct.pack_into('<I', buf, 8, 3)
    buf[12:24] = nonce
    buf[24:40] = tag
    struct.pack_into('<I', buf, 40, ct_len)
    buf[44:44+ct_len] = actual_ct
    return bytes(buf)


def read_vault_header(vault_path: Path) -> dict:
    """
    Read and decrypt the encapsulated metadata header from a v3 vault.

    Returns:
        dict with:
          'config': dict,
          'k_local': bytes,
          'lease': Optional[dict],
          'version': int
    """
    if not vault_path.exists():
        raise FileNotFoundError(f"Vault not found: {vault_path}")

    with open(vault_path, 'rb') as vf:
        header_bytes = vf.read(HEADER_BLOCK_SIZE)
        if len(header_bytes) < HEADER_BLOCK_SIZE:
            raise ValueError("Vault file too small to contain a valid v3 header")

    magic = header_bytes[0:8]
    if magic != VAULT_MAGIC_V3:
        raise ValueError(f"Not a v3 encapsulated vault (magic: {magic!r})")

    version = struct.unpack_from('<I', header_bytes, 8)[0]
    nonce = header_bytes[12:24]
    tag = header_bytes[24:40]
    ct_len = struct.unpack_from('<I', header_bytes, 40)[0]

    if ct_len > HEADER_BLOCK_SIZE - 44:
        raise ValueError(f"Invalid header ciphertext length: {ct_len}")

    ciphertext = header_bytes[44:44+ct_len]
    header_key = _derive_header_key()
    aesgcm = AESGCM(header_key)
    ct_with_tag = ciphertext + tag
    plaintext = aesgcm.decrypt(nonce, ct_with_tag, HEADER_AAD)
    data = json.loads(plaintext.decode('utf-8'))

    k_local_hex = data.get('k_local')
    k_local = bytes.fromhex(k_local_hex) if k_local_hex else None

    return {
        'config': data.get('config', {}),
        'k_local': k_local,
        'lease': data.get('lease'),
        'version': version
    }


def update_vault_header(
    vault_path: Path,
    config: Optional[dict] = None,
    k_local: Optional[bytes] = None,
    lease_data: Optional[dict] = None,
    clear_lease: bool = False
) -> None:
    """
    In-place update of the 4096-byte header block in vault.enc.
    Modifies only the header; does not shift or rewrite payload data.
    """
    current = read_vault_header(vault_path)
    new_config = config if config is not None else current['config']
    new_k_local = k_local if k_local is not None else current['k_local']
    if clear_lease:
        new_lease = None
    elif lease_data is not None:
        new_lease = lease_data
    else:
        new_lease = current['lease']

    new_header = pack_vault_header(new_config, new_k_local, new_lease)
    with open(vault_path, 'r+b') as vf:
        vf.seek(0)
        vf.write(new_header)
        vf.flush()
        os.fsync(vf.fileno())
    logger.info(f"Encapsulated vault header updated in-place: {vault_path}")


class VaultLayout:
    """Represents the binary offsets of a vault file (v2 or v3)."""
    def __init__(
        self,
        version: int,
        salt: bytes,
        manifest_offset: int,
        manifest_offset_pos: int,
        data_start: int
    ):
        self.version = version
        self.salt = salt
        self.manifest_offset = manifest_offset
        self.manifest_offset_pos = manifest_offset_pos
        self.data_start = data_start


def _get_vault_layout(vf: BinaryIO) -> VaultLayout:
    """
    Inspect vault file and resolve layout offsets for v3 (encapsulated) or v2.
    """
    vf.seek(0)
    magic = vf.read(8)
    if magic == VAULT_MAGIC_V3:
        # Core data starts after 4096-byte header block
        vf.seek(HEADER_BLOCK_SIZE)
        salt = vf.read(SALT_SIZE)
        manifest_offset_pos = HEADER_BLOCK_SIZE + SALT_SIZE
        vf.seek(manifest_offset_pos)
        manifest_offset = struct.unpack('<Q', vf.read(8))[0]
        data_start = manifest_offset_pos + 8
        return VaultLayout(3, salt, manifest_offset, manifest_offset_pos, data_start)
    elif magic == VAULT_MAGIC_V2:
        salt = vf.read(SALT_SIZE)
        manifest_offset_pos = 8 + SALT_SIZE
        manifest_offset = struct.unpack('<Q', vf.read(8))[0]
        data_start = manifest_offset_pos + 8
        return VaultLayout(2, salt, manifest_offset, manifest_offset_pos, data_start)
    elif magic == VAULT_MAGIC_V1:
        raise ValueError("Legacy v1 vault format cannot be read directly by v3 engine")
    else:
        raise ValueError(f"Unrecognized vault magic: {magic!r}")


def generate_local_key() -> bytes:
    """Generate a new cryptographically random 256-bit local key share."""
    return secrets.token_bytes(KEY_SIZE)


def save_local_key(key_bytes: bytes, key_path: Path) -> None:
    """Persist the local key share to the USB drive (legacy support)."""
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key_bytes)
    logger.info(f"Local key share saved to: {key_path}")


def load_local_key(key_path: Path) -> bytes:
    """Load the local key share from the USB drive (legacy support)."""
    if not key_path.exists():
        raise FileNotFoundError(f"Local key share not found at: {key_path}")
    key_bytes = key_path.read_bytes()
    if len(key_bytes) != KEY_SIZE:
        raise ValueError(f"Local key has unexpected length: {len(key_bytes)} (expected {KEY_SIZE})")
    return key_bytes


def derive_master_key(
    k_local: bytes,
    k_cloud: bytes,
    salt: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    Derive the master encryption key from two key shares via HKDF.

    Steps:
      1. XOR combine K_local and K_cloud
      2. HKDF-SHA256(IKM=combined, salt=salt, info=domain_separator)

    Returns:
        (k_master, salt) tuple
    """
    if len(k_local) != KEY_SIZE:
        raise ValueError(f"K_local must be {KEY_SIZE} bytes, got {len(k_local)}")
    if len(k_cloud) != KEY_SIZE:
        raise ValueError(f"K_cloud must be {KEY_SIZE} bytes, got {len(k_cloud)}")

    xor_combined = bytes(a ^ b for a, b in zip(k_local, k_cloud))

    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=b'usb-vault-aes256-gcm-key-v2',
        backend=default_backend()
    )
    k_master = hkdf.derive(xor_combined)
    return k_master, salt


# ──────────────────────────────────────────────────────────────────────────────
# File Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _collect_files(source_dir: Path) -> List[Path]:
    """Recursively collect all files under source_dir."""
    return sorted([f for f in source_dir.rglob('*') if f.is_file()])


def _file_sha256(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def hex_to_key_bytes(hex_str: str) -> bytes:
    """Convert a 64-character hex string to 32 raw bytes."""
    hex_str = hex_str.strip().lower()
    if len(hex_str) != 64:
        raise ValueError(f"Key must be 64 hex chars (32 bytes), got {len(hex_str)}")
    return bytes.fromhex(hex_str)


def bytes_to_hex(b: bytes) -> str:
    """Convert raw bytes to hex string."""
    return b.hex()


# ──────────────────────────────────────────────────────────────────────────────
# Vault Encryption — v2 Tail-Manifest Format
# ──────────────────────────────────────────────────────────────────────────────

def encrypt_folder_to_vault(
    source_dir: Path,
    vault_path: Path,
    k_local: bytes,
    k_cloud: bytes,
    config: Optional[dict] = None,
    drive_metadata: Optional[dict] = None,
    progress_callback=None
) -> dict:
    """
    Encrypt an entire folder into an encapsulated v3 vault.enc file with packed header.

    Binary layout (v3):
      [HEADER BLOCK 4096B][SALT 32B][MANIFEST_OFFSET 8B][...file chunks...][MANIFEST BLOCK]

    The 4096-byte header contains the encrypted/authenticated config, K_local share,
    and optional lease token. File chunks start at offset 4136.

    Args:
        source_dir: Folder to encrypt
        vault_path: Output vault.enc path
        k_local: Local key share (32 bytes)
        k_cloud: Cloud key share (32 bytes)
        config: Optional configuration dict (drive_id, label, api_url, etc.)
        drive_metadata: Optional dict with label, owner_email, etc.
        progress_callback: Optional callable(current, total, rel_path)

    Returns:
        Stats dict with encryption results.
    """
    k_master, salt = derive_master_key(k_local, k_cloud)
    aesgcm = AESGCM(k_master)

    files = _collect_files(source_dir)
    if not files:
        raise ValueError(f"No files found in: {source_dir}")

    vault_path.parent.mkdir(parents=True, exist_ok=True)
    total_encrypted = 0

    cfg = dict(config) if config else {
        'drive_id': (drive_metadata or {}).get('drive_id', 'unknown'),
        'label': (drive_metadata or {}).get('label', 'Encrypted USB'),
        'version': 3,
        'created_at': int(time.time()),
        **(drive_metadata or {})
    }

    header_block = pack_vault_header(cfg, k_local)

    with open(vault_path, 'wb') as vf:
        # 1. Write encapsulated 4096-byte header
        vf.write(header_block)

        # 2. Write HKDF salt at offset 4096
        vf.write(salt)

        # 3. Placeholder manifest offset at offset 4128
        manifest_offset_pos = vf.tell()
        vf.write(struct.pack('<Q', 0))

        # 4. Write encrypted file chunks (starts at offset 4136)
        manifest_files = []
        for i, file_path in enumerate(files):
            rel_path = str(file_path.relative_to(source_dir)).replace('\\', '/')
            logger.info(f"  Encrypting [{i+1}/{len(files)}]: {rel_path}")
            if progress_callback:
                progress_callback(i + 1, len(files), rel_path)

            plaintext = file_path.read_bytes()
            original_size = len(plaintext)
            file_hash = hashlib.sha256(plaintext).hexdigest()

            nonce = secrets.token_bytes(NONCE_SIZE)
            ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, rel_path.encode('utf-8'))
            actual_ct = ciphertext_with_tag[:-TAG_SIZE]
            tag = ciphertext_with_tag[-TAG_SIZE:]

            offset = vf.tell()
            vf.write(actual_ct)

            manifest_files.append({
                'path': rel_path,
                'offset': offset,
                'size': len(actual_ct),
                'nonce': nonce.hex(),
                'tag': tag.hex(),
                'original_size': original_size,
                'modified': int(file_path.stat().st_mtime),
                'sha256': file_hash
            })
            total_encrypted += original_size

        # 5. Build and encrypt manifest at tail
        manifest = {
            'version': 3,
            'drive_metadata': drive_metadata or {},
            'files': manifest_files,
            'dead_space_bytes': 0,
            'last_modified': int(time.time())
        }

        manifest_offset = vf.tell()
        _write_encrypted_manifest(vf, aesgcm, manifest)

        # 6. Write actual manifest offset in header
        vf.seek(manifest_offset_pos)
        vf.write(struct.pack('<Q', manifest_offset))

    # Clear master key from memory (best-effort)
    k_master = bytes(KEY_SIZE)

    stats = {
        'vault_path': str(vault_path),
        'source_dir': str(source_dir),
        'files_encrypted': len(files),
        'bytes_encrypted': total_encrypted,
        'vault_size': vault_path.stat().st_size,
        'salt_hex': salt.hex(),
        'created_at': manifest['last_modified'],
        'version': 3
    }
    logger.info(f"✅ Vault v3 created: {vault_path} ({len(files)} files, {total_encrypted} bytes)")
    return stats


def _write_encrypted_manifest(vf: BinaryIO, aesgcm: AESGCM, manifest: dict):
    """Encrypt and write the manifest block at the current file position."""
    manifest_json = json.dumps(manifest, separators=(',', ':')).encode('utf-8')
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct_with_tag = aesgcm.encrypt(nonce, manifest_json, b'vault-manifest-v2')
    actual_ct = ct_with_tag[:-TAG_SIZE]
    tag = ct_with_tag[-TAG_SIZE:]

    vf.write(nonce)                                    # 12 bytes
    vf.write(tag)                                      # 16 bytes
    vf.write(struct.pack('<I', len(actual_ct)))         # 4 bytes
    vf.write(actual_ct)


# ──────────────────────────────────────────────────────────────────────────────
# Vault Manifest Reading (on-demand, no full extraction)
# ──────────────────────────────────────────────────────────────────────────────

def read_vault_manifest(
    vault_path: Path,
    k_local: bytes,
    k_cloud: bytes
) -> dict:
    """
    Decrypt and return ONLY the vault manifest (tail block).
    Supports both v3 encapsulated vaults and v2 legacy vaults.
    Does NOT decrypt any file data — used for populating the GUI file tree.

    Returns:
        Manifest dict with 'version', 'drive_metadata', 'files', etc.
    """
    if not vault_path.exists():
        raise FileNotFoundError(f"Vault not found: {vault_path}")

    with open(vault_path, 'rb') as vf:
        layout = _get_vault_layout(vf)

        # Derive master key
        k_master, _ = derive_master_key(k_local, k_cloud, salt=layout.salt)
        aesgcm = AESGCM(k_master)

        # Seek to manifest at tail
        vf.seek(layout.manifest_offset)
        manifest = _read_encrypted_manifest(vf, aesgcm)

    k_master = bytes(KEY_SIZE)
    return manifest


def _read_encrypted_manifest(vf: BinaryIO, aesgcm: AESGCM) -> dict:
    """Read and decrypt the manifest block from the current file position."""
    nonce = vf.read(NONCE_SIZE)
    tag = vf.read(TAG_SIZE)
    ct_len = struct.unpack('<I', vf.read(4))[0]
    ciphertext = vf.read(ct_len)

    ct_with_tag = ciphertext + tag
    plaintext = aesgcm.decrypt(nonce, ct_with_tag, b'vault-manifest-v2')
    return json.loads(plaintext.decode('utf-8'))


# ──────────────────────────────────────────────────────────────────────────────
# On-Demand Single File Decryption
# ──────────────────────────────────────────────────────────────────────────────

def decrypt_single_file(
    vault_path: Path,
    k_local: bytes,
    k_cloud: bytes,
    file_entry: dict
) -> bytes:
    """
    Decrypt a single file from the vault by seeking to its offset.

    Args:
        vault_path: Path to vault.enc
        k_local: Local key share
        k_cloud: Cloud key share
        file_entry: Dict from manifest with offset, size, nonce, tag, path

    Returns:
        Decrypted file bytes (plaintext).
    """
    with open(vault_path, 'rb') as vf:
        layout = _get_vault_layout(vf)
        k_master, _ = derive_master_key(k_local, k_cloud, salt=layout.salt)
        aesgcm = AESGCM(k_master)

        # Seek to file's data offset
        vf.seek(file_entry['offset'])
        ciphertext = vf.read(file_entry['size'])

    # Reconstruct nonce, tag, and AAD
    nonce = bytes.fromhex(file_entry['nonce'])
    tag = bytes.fromhex(file_entry['tag'])
    file_aad = file_entry['path'].encode('utf-8')

    ct_with_tag = ciphertext + tag
    plaintext = aesgcm.decrypt(nonce, ct_with_tag, file_aad)

    k_master = bytes(KEY_SIZE)
    return plaintext


def decrypt_single_file_to_temp(
    vault_path: Path,
    k_local: bytes,
    k_cloud: bytes,
    file_entry: dict
) -> Path:
    """
    Decrypt a single file to a temporary location for viewing.

    Returns:
        Path to the decrypted temporary file.
    """
    plaintext = decrypt_single_file(vault_path, k_local, k_cloud, file_entry)

    # Create temp dir preserving original filename
    temp_dir = Path(tempfile.mkdtemp(prefix='usbvault_view_'))
    filename = Path(file_entry['path']).name
    out_path = temp_dir / filename
    out_path.write_bytes(plaintext)
    logger.info(f"Decrypted single file to: {out_path}")
    return out_path


# ──────────────────────────────────────────────────────────────────────────────
# Bulk Decryption to Working Directory
# ──────────────────────────────────────────────────────────────────────────────

def decrypt_files_to_working_dir(
    vault_path: Path,
    k_local: bytes,
    k_cloud: bytes,
    manifest: dict,
    file_entries: Optional[List[dict]] = None,
    progress_callback=None
) -> Path:
    """
    Decrypt selected files (or all) into a working directory for editing.

    Args:
        vault_path: Path to vault.enc
        manifest: Already-loaded manifest dict
        file_entries: Specific files to extract. None = all files.
        progress_callback: Optional callable(current, total, filename)

    Returns:
        Path to the working directory.
    """
    entries = file_entries if file_entries is not None else manifest.get('files', [])
    if not entries:
        raise ValueError("No files to decrypt")

    with open(vault_path, 'rb') as vf:
        layout = _get_vault_layout(vf)
        k_master, _ = derive_master_key(k_local, k_cloud, salt=layout.salt)
        aesgcm = AESGCM(k_master)

        temp_dir = Path(tempfile.mkdtemp(prefix='usbvault_work_'))
        logger.info(f"Decrypting {len(entries)} files to working dir: {temp_dir}")

        for i, entry in enumerate(entries):
            rel_path = entry['path']
            if progress_callback:
                progress_callback(i + 1, len(entries), rel_path)

            logger.info(f"  Decrypting [{i+1}/{len(entries)}]: {rel_path}")

            vf.seek(entry['offset'])
            ciphertext = vf.read(entry['size'])

            nonce = bytes.fromhex(entry['nonce'])
            tag = bytes.fromhex(entry['tag'])
            file_aad = rel_path.encode('utf-8')

            ct_with_tag = ciphertext + tag
            plaintext = aesgcm.decrypt(nonce, ct_with_tag, file_aad)

            out_path = temp_dir / rel_path
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(plaintext)

            # Restore original modification time
            try:
                os.utime(out_path, (entry.get('modified', time.time()), entry.get('modified', time.time())))
            except Exception:
                pass

    k_master = bytes(KEY_SIZE)
    return temp_dir


def decrypt_directory_to_working_dir(
    vault_path: Path,
    k_local: bytes,
    k_cloud: bytes,
    manifest: dict,
    dir_prefix: str = '',
    target_dir: Optional[Path] = None,
    progress_callback=None
) -> Path:
    """
    Decrypt all files belonging to a specific directory prefix into a target working directory.
    """
    all_files = manifest.get('files', [])
    clean_prefix = dir_prefix.strip('/')
    if clean_prefix:
        matching = [f for f in all_files if f['path'] == clean_prefix or f['path'].startswith(clean_prefix + '/')]
    else:
        matching = all_files

    if not matching:
        raise ValueError(f"No files found under directory prefix: '{dir_prefix}'")

    if target_dir is None:
        target_dir = Path(tempfile.mkdtemp(prefix='usbvault_work_'))

    with open(vault_path, 'rb') as vf:
        layout = _get_vault_layout(vf)
        k_master, _ = derive_master_key(k_local, k_cloud, salt=layout.salt)
        aesgcm = AESGCM(k_master)

        for i, entry in enumerate(matching):
            rel_path = entry['path']
            if progress_callback:
                progress_callback(i + 1, len(matching), rel_path)

            vf.seek(entry['offset'])
            ciphertext = vf.read(entry['size'])

            nonce = bytes.fromhex(entry['nonce'])
            tag = bytes.fromhex(entry['tag'])
            file_aad = rel_path.encode('utf-8')

            ct_with_tag = ciphertext + tag
            plaintext = aesgcm.decrypt(nonce, ct_with_tag, file_aad)

            out_path = target_dir / rel_path
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(plaintext)

            try:
                os.utime(out_path, (entry.get('modified', time.time()), entry.get('modified', time.time())))
            except Exception:
                pass

    k_master = bytes(KEY_SIZE)
    return target_dir


# ──────────────────────────────────────────────────────────────────────────────
# Incremental Vault Update on Lock
# ──────────────────────────────────────────────────────────────────────────────

def update_vault_on_lock(
    vault_path: Path,
    k_local: bytes,
    k_cloud: bytes,
    working_dir: Path,
    manifest: dict,
    allow_partial: bool = False,
    progress_callback=None
) -> dict:
    """
    Detect modified/new/deleted files and update the vault incrementally.

    Args:
        vault_path: Path to vault.enc
        working_dir: Temp working directory with potentially edited files
        manifest: Current manifest dict (loaded earlier)
        allow_partial: If True, files not in working_dir are preserved (not deleted).
                       If False (full sync mode), missing files are treated as deleted.
        progress_callback: Optional callable(current, total, action_str)

    Returns:
        Updated manifest dict.
    """
    # Build lookup of current manifest files by path
    existing_files = {f['path']: f for f in manifest.get('files', [])}

    # Collect files from working directory
    working_files = {}
    for fp in _collect_files(working_dir):
        rel = str(fp.relative_to(working_dir)).replace('\\', '/')
        working_files[rel] = fp

    # Classify changes
    unchanged = []
    modified = []
    new_files = []
    deleted = []

    for rel_path, fp in working_files.items():
        current_hash = _file_sha256(fp)
        if rel_path in existing_files:
            if current_hash == existing_files[rel_path].get('sha256'):
                unchanged.append(existing_files[rel_path])
            else:
                modified.append((rel_path, fp, current_hash))
        else:
            new_files.append((rel_path, fp, current_hash))

    for rel_path in existing_files:
        if rel_path not in working_files:
            if allow_partial:
                unchanged.append(existing_files[rel_path])
            else:
                deleted.append(rel_path)

    total_actions = len(modified) + len(new_files)
    logger.info(f"Vault update: {len(unchanged)} unchanged, {len(modified)} modified, "
                f"{len(new_files)} new, {len(deleted)} deleted (allow_partial={allow_partial})")

    if total_actions == 0 and len(deleted) == 0:
        logger.info("No changes detected — vault unchanged.")
        return manifest

    # Read layout from vault header
    with open(vault_path, 'rb') as vf:
        layout = _get_vault_layout(vf)

    k_master, _ = derive_master_key(k_local, k_cloud, salt=layout.salt)
    aesgcm = AESGCM(k_master)

    # Calculate dead space from modified + deleted files
    dead_space = manifest.get('dead_space_bytes', 0)
    for rel_path, fp, _ in modified:
        old_entry = existing_files[rel_path]
        dead_space += old_entry['size']
    for rel_path in deleted:
        dead_space += existing_files[rel_path]['size']

    # Truncate the old manifest (we'll write a new one)
    with open(vault_path, 'r+b') as vf:
        vf.truncate(layout.manifest_offset)

    # Build new file list starting from unchanged entries
    new_file_list = list(unchanged)

    # Append modified + new files
    action_idx = 0
    with open(vault_path, 'r+b') as vf:
        vf.seek(0, 2)  # seek to end

        for rel_path, fp, file_hash in modified + new_files:
            action_idx += 1
            action = "Re-encrypting" if rel_path in existing_files else "Encrypting new"
            logger.info(f"  {action} [{action_idx}/{total_actions}]: {rel_path}")
            if progress_callback:
                progress_callback(action_idx, total_actions, f"{action}: {rel_path}")

            plaintext = fp.read_bytes()
            nonce = secrets.token_bytes(NONCE_SIZE)
            file_aad = rel_path.encode('utf-8')
            ct_with_tag = aesgcm.encrypt(nonce, plaintext, file_aad)
            actual_ct = ct_with_tag[:-TAG_SIZE]
            tag = ct_with_tag[-TAG_SIZE:]

            offset = vf.tell()
            vf.write(actual_ct)

            new_file_list.append({
                'path': rel_path,
                'offset': offset,
                'size': len(actual_ct),
                'nonce': nonce.hex(),
                'tag': tag.hex(),
                'original_size': len(plaintext),
                'modified': int(fp.stat().st_mtime),
                'sha256': file_hash
            })

        # Sort file list by path for consistency
        new_file_list.sort(key=lambda f: f['path'])

        # Write new manifest at current position (end of data)
        manifest_offset = vf.tell()
        manifest['files'] = new_file_list
        manifest['dead_space_bytes'] = dead_space
        manifest['last_modified'] = int(time.time())
        _write_encrypted_manifest(vf, aesgcm, manifest)

        # Update manifest offset in header
        vf.seek(layout.manifest_offset_pos)
        vf.write(struct.pack('<Q', manifest_offset))

    k_master = bytes(KEY_SIZE)
    logger.info(f"✅ Vault updated: {action_idx} files written, {len(deleted)} removed, "
                f"{dead_space} bytes dead space")
    return manifest


# ──────────────────────────────────────────────────────────────────────────────
# Vault Compaction
# ──────────────────────────────────────────────────────────────────────────────

def compact_vault(
    vault_path: Path,
    k_local: bytes,
    k_cloud: bytes,
    progress_callback=None
) -> dict:
    """
    Rewrite the vault to eliminate dead space from modified/deleted files.
    Preserves encapsulated v3 header and lease token.
    """
    manifest = read_vault_manifest(vault_path, k_local, k_cloud)
    drive_metadata = manifest.get('drive_metadata', {})

    header_data = None
    try:
        header_data = read_vault_header(vault_path)
    except Exception:
        pass

    # Decrypt all files to a temp dir
    temp_dir = decrypt_files_to_working_dir(
        vault_path, k_local, k_cloud, manifest, progress_callback=progress_callback
    )

    config = header_data.get('config') if header_data else None
    # Re-encrypt as a fresh vault
    stats = encrypt_folder_to_vault(
        temp_dir, vault_path, k_local, k_cloud,
        config=config,
        drive_metadata=drive_metadata,
        progress_callback=progress_callback
    )

    # Restore lease if present
    if header_data and header_data.get('lease'):
        update_vault_header(vault_path, lease_data=header_data['lease'])

    # Wipe temp
    secure_wipe_temp(temp_dir)

    logger.info("✅ Vault compacted. Old dead space eliminated.")
    return stats


def migrate_v2_to_v3(
    vault_path: Path,
    k_local: bytes,
    k_cloud: bytes,
    config: dict,
    lease_data: Optional[dict] = None
) -> dict:
    """
    Migrate a legacy v2 vault into a v3 encapsulated vault.
    Consolidates config, local key share, and optional lease token directly into vault.enc.
    """
    manifest = read_vault_manifest(vault_path, k_local, k_cloud)
    drive_metadata = manifest.get('drive_metadata', {})

    temp_dir = decrypt_files_to_working_dir(vault_path, k_local, k_cloud, manifest)

    stats = encrypt_folder_to_vault(
        temp_dir, vault_path, k_local, k_cloud,
        config=config,
        drive_metadata=drive_metadata
    )

    if lease_data:
        update_vault_header(vault_path, lease_data=lease_data)

    secure_wipe_temp(temp_dir)
    logger.info(f"✅ Migrated v2 vault to v3 encapsulated vault: {vault_path}")
    return stats


# ──────────────────────────────────────────────────────────────────────────────
# Secure Session Cleanup
# ──────────────────────────────────────────────────────────────────────────────

def secure_wipe_temp(temp_dir: Path, progress_callback=None) -> int:
    """
    Securely erase all files in a temporary session directory.

    For each file: overwrite with random bytes → truncate → delete.

    Args:
        temp_dir: Path to wipe
        progress_callback: Optional callable(current, total, filename)

    Returns:
        Number of files wiped.
    """
    if not temp_dir.exists():
        logger.warning(f"Temp dir does not exist: {temp_dir}")
        return 0

    wiped = 0
    files_to_wipe = [f for f in temp_dir.rglob('*') if f.is_file()]
    total = len(files_to_wipe)

    for i, fp in enumerate(files_to_wipe):
        try:
            rel = fp.relative_to(temp_dir)
            logger.info(f"  Wiping [{i+1}/{total}]: {rel}")
            if progress_callback:
                progress_callback(i + 1, total, str(rel))

            size = fp.stat().st_size
            if size > 0:
                with open(fp, 'r+b') as f:
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
            fp.unlink()
            wiped += 1
        except Exception as e:
            logger.warning(f"Could not wipe {fp}: {e}")

    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception as e:
        logger.error(f"Failed to remove temp dir: {e}")

    logger.info(f"✅ Secure wipe: {wiped}/{total} files erased")
    return wiped


# ──────────────────────────────────────────────────────────────────────────────
# Vault Inspection (read info without keys — limited to header check)
# ──────────────────────────────────────────────────────────────────────────────

def inspect_vault_header(vault_path: Path) -> Optional[dict]:
    """
    Read basic vault info without full file decryption.
    Checks validity of v3 or v2 headers and returns metadata.
    """
    if not vault_path.exists():
        return None
    try:
        with open(vault_path, 'rb') as vf:
            magic = vf.read(8)
            vault_size = vault_path.stat().st_size
            if magic == VAULT_MAGIC_V3:
                layout = _get_vault_layout(vf)
                return {
                    'version': 3,
                    'vault_size': vault_size,
                    'manifest_offset': layout.manifest_offset,
                    'valid': True,
                    'encapsulated': True
                }
            elif magic == VAULT_MAGIC_V2:
                layout = _get_vault_layout(vf)
                return {
                    'version': 2,
                    'vault_size': vault_size,
                    'manifest_offset': layout.manifest_offset,
                    'valid': True,
                    'encapsulated': False
                }
            elif magic == VAULT_MAGIC_V1:
                return {'version': 1, 'valid': True, 'legacy': True}
            return None
    except Exception as e:
        logger.warning(f"Could not inspect vault: {e}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# CLI Self-Test
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    logging.basicConfig(level=logging.DEBUG)

    print("Crypto Engine v2 — Self-test")
    print("-" * 40)

    # Test key derivation
    k_local = generate_local_key()
    k_cloud = generate_local_key()
    print(f"K_local  (hex): {k_local.hex()}")
    print(f"K_cloud  (hex): {k_cloud.hex()}")

    k_master, salt = derive_master_key(k_local, k_cloud)
    print(f"K_master (hex): {k_master.hex()}")
    print(f"HKDF salt(hex): {salt.hex()}")

    # Determinism check
    k_master2, _ = derive_master_key(k_local, k_cloud, salt=salt)
    assert k_master == k_master2, "DETERMINISM TEST FAILED"
    print("✅ Determinism test passed.")

    # Encrypt/decrypt roundtrip
    if len(sys.argv) > 1:
        test_folder = Path(sys.argv[1])
        vault = Path('./test_vault_v2.enc')
        metadata = {'label': 'Test Drive', 'owner_email': 'test@test.com', 'created_at': int(time.time())}

        print(f"\nEncrypting {test_folder}...")
        stats = encrypt_folder_to_vault(test_folder, vault, k_local, k_cloud, drive_metadata=metadata)
        print(f"Stats: {stats}")

        print("\nReading manifest...")
        manifest = read_vault_manifest(vault, k_local, k_cloud)
        print(f"Manifest: {len(manifest['files'])} files, metadata: {manifest['drive_metadata']}")

        print("\nDecrypting single file...")
        if manifest['files']:
            first = manifest['files'][0]
            data = decrypt_single_file(vault, k_local, k_cloud, first)
            print(f"Decrypted '{first['path']}': {len(data)} bytes")

        print("\nDecrypting all to working dir...")
        work_dir = decrypt_files_to_working_dir(vault, k_local, k_cloud, manifest)
        print(f"Working dir: {work_dir}")

        print("\nSimulating edit (modifying first file)...")
        first_file = work_dir / manifest['files'][0]['path']
        first_file.write_bytes(first_file.read_bytes() + b"\n# EDITED")

        print("\nUpdating vault on lock...")
        updated = update_vault_on_lock(vault, k_local, k_cloud, work_dir, manifest)
        print(f"Updated manifest: {len(updated['files'])} files, dead_space: {updated['dead_space_bytes']}")

        print("\nWiping working dir...")
        secure_wipe_temp(work_dir)

        print("\nCompacting vault...")
        compact_vault(vault, k_local, k_cloud)

        final_manifest = read_vault_manifest(vault, k_local, k_cloud)
        print(f"Final: {len(final_manifest['files'])} files, dead_space: {final_manifest['dead_space_bytes']}")

        # Cleanup
        vault.unlink(missing_ok=True)
        print("\n✅ All tests passed!")
