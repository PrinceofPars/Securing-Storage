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

VAULT_MAGIC_V2  = b'USBVLT02'   # 8 bytes — v2 vault identifier
VAULT_MAGIC_V1  = b'USBVLT01'   # 8 bytes — v1 (legacy, read-only support)
NONCE_SIZE      = 12             # GCM standard nonce (bytes)
TAG_SIZE        = 16             # GCM authentication tag (bytes)
KEY_SIZE        = 32             # AES-256 key size (bytes)
SALT_SIZE       = 32             # HKDF salt size (bytes) — increased from v1's 16
HEADER_SIZE     = 8 + 32 + 8    # magic + salt + manifest_offset = 48 bytes
DATA_START      = HEADER_SIZE    # Payload data begins immediately after header

LOCAL_KEY_FILENAME = 'local_key.bin'


# ──────────────────────────────────────────────────────────────────────────────
# Key Management
# ──────────────────────────────────────────────────────────────────────────────

def generate_local_key() -> bytes:
    """Generate a new cryptographically random 256-bit local key share."""
    return secrets.token_bytes(KEY_SIZE)


def save_local_key(key_bytes: bytes, key_path: Path) -> None:
    """Persist the local key share to the USB drive."""
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(key_bytes)
    logger.info(f"Local key share saved to: {key_path}")


def load_local_key(key_path: Path) -> bytes:
    """Load the local key share from the USB drive."""
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
    drive_metadata: Optional[dict] = None,
    progress_callback=None
) -> dict:
    """
    Encrypt an entire folder into a v2 vault.enc file with tail-manifest.

    Binary layout:
      [MAGIC 8B][SALT 32B][MANIFEST_OFFSET 8B][...file chunks...][MANIFEST BLOCK]

    Each file chunk is raw AES-GCM ciphertext. The per-file nonce and tag
    are stored in the manifest (not inline), keeping offset math simple.

    Args:
        source_dir: Folder to encrypt
        vault_path: Output vault.enc path
        k_local: Local key share (32 bytes)
        k_cloud: Cloud key share (32 bytes)
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

    with open(vault_path, 'wb') as vf:
        # ── Write header with placeholder manifest offset ──
        vf.write(VAULT_MAGIC_V2)
        vf.write(salt)
        vf.write(struct.pack('<Q', 0))  # placeholder, updated after writing manifest

        # ── Write encrypted file chunks ──
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
            # cryptography lib: ciphertext = actual_ct + tag (last 16 bytes)
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

        # ── Build and encrypt manifest ──
        manifest = {
            'version': 2,
            'drive_metadata': drive_metadata or {},
            'files': manifest_files,
            'dead_space_bytes': 0,
            'last_modified': int(time.time())
        }

        manifest_offset = vf.tell()
        _write_encrypted_manifest(vf, aesgcm, manifest)

        # ── Go back and write the real manifest offset ──
        vf.seek(8 + SALT_SIZE)  # right after magic + salt
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
        'created_at': manifest['last_modified']
    }
    logger.info(f"✅ Vault v2 created: {vault_path} ({len(files)} files, {total_encrypted} bytes)")
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
    Does NOT decrypt any file data — used for populating the GUI file tree.

    Returns:
        Manifest dict with 'version', 'drive_metadata', 'files', etc.
    """
    if not vault_path.exists():
        raise FileNotFoundError(f"Vault not found: {vault_path}")

    with open(vault_path, 'rb') as vf:
        # Read and validate header
        magic = vf.read(8)
        if magic != VAULT_MAGIC_V2:
            raise ValueError(f"Invalid vault magic: {magic!r} (expected USBVLT02)")

        salt = vf.read(SALT_SIZE)
        manifest_offset = struct.unpack('<Q', vf.read(8))[0]

        # Derive master key
        k_master, _ = derive_master_key(k_local, k_cloud, salt=salt)
        aesgcm = AESGCM(k_master)

        # Seek to manifest at tail
        vf.seek(manifest_offset)
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
        # Read salt from header
        vf.seek(8)  # skip magic
        salt = vf.read(SALT_SIZE)

        k_master, _ = derive_master_key(k_local, k_cloud, salt=salt)
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
        # Read salt
        vf.seek(8)
        salt = vf.read(SALT_SIZE)
        k_master, _ = derive_master_key(k_local, k_cloud, salt=salt)
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
        vf.seek(8)
        salt = vf.read(SALT_SIZE)
        k_master, _ = derive_master_key(k_local, k_cloud, salt=salt)
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

    # Read salt from vault header
    with open(vault_path, 'rb') as vf:
        vf.seek(8)
        salt = vf.read(SALT_SIZE)

    k_master, _ = derive_master_key(k_local, k_cloud, salt=salt)
    aesgcm = AESGCM(k_master)

    # Calculate dead space from modified + deleted files
    dead_space = manifest.get('dead_space_bytes', 0)
    for rel_path, fp, _ in modified:
        old_entry = existing_files[rel_path]
        dead_space += old_entry['size']
    for rel_path in deleted:
        dead_space += existing_files[rel_path]['size']

    # Open vault for appending new/modified data
    # We truncate at the old manifest offset (remove old manifest) then append
    manifest_offset = None
    with open(vault_path, 'rb') as vf:
        vf.seek(8 + SALT_SIZE)
        old_manifest_offset = struct.unpack('<Q', vf.read(8))[0]

    # Truncate the old manifest (we'll write a new one)
    with open(vault_path, 'r+b') as vf:
        vf.truncate(old_manifest_offset)

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
        vf.seek(8 + SALT_SIZE)
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

    Decrypts all live files, writes a fresh vault with no gaps.
    """
    manifest = read_vault_manifest(vault_path, k_local, k_cloud)
    drive_metadata = manifest.get('drive_metadata', {})

    # Decrypt all files to a temp dir
    temp_dir = decrypt_files_to_working_dir(
        vault_path, k_local, k_cloud, manifest, progress_callback=progress_callback
    )

    # Re-encrypt as a fresh vault
    stats = encrypt_folder_to_vault(
        temp_dir, vault_path, k_local, k_cloud,
        drive_metadata=drive_metadata,
        progress_callback=progress_callback
    )

    # Wipe temp
    secure_wipe_temp(temp_dir)

    logger.info(f"✅ Vault compacted. Old dead space eliminated.")
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
    Read basic vault info without decryption.
    Only tells you if it's a valid v2 vault and its file size.
    Manifest is encrypted so file list is NOT accessible without keys.
    """
    if not vault_path.exists():
        return None
    try:
        with open(vault_path, 'rb') as vf:
            magic = vf.read(8)
            if magic == VAULT_MAGIC_V2:
                _salt = vf.read(SALT_SIZE)
                manifest_offset = struct.unpack('<Q', vf.read(8))[0]
                vault_size = vault_path.stat().st_size
                return {
                    'version': 2,
                    'vault_size': vault_size,
                    'manifest_offset': manifest_offset,
                    'valid': True
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
