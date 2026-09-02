"""
usb_security_client.py — Main CLI Interface
============================================
Primary entry point for the Remote-Killable Encrypted USB Drive System.
Run this script directly from the USB drive.

Usage:
  python usb_security_client.py

Menu:
  [1] Initialise / Encrypt a folder into vault.enc
  [2] Unlock and mount vault (Online or Offline Lease check)
  [3] Lock / Eject vault (securely wipe decrypted temp files)
  [4] Simulate "Mark Drive as Lost" trigger
  [5] Display drive info & lease status
  [0] Exit

Configuration:
  Edit the CONFIG section below or use environment variables.

Folder Layout (USB Root):
  usb_security_client.py   ← This file
  fingerprint.py           ← Hardware fingerprinter
  crypto_engine.py         ← AES-256-GCM vault engine
  lease_manager.py         ← Offline lease manager
  config.json              ← Drive configuration (created on init)
  local_key.bin            ← K_local share (created on init, keep SECRET)
  vault.enc                ← Encrypted vault (created on option [1])
  lease.tok                ← Encrypted offline lease (created on online auth)
  requirements.txt         ← Python dependencies

Python 3.8+ required. Run:  pip install -r requirements.txt
"""
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# ──────────────────────────────────────────────────────────────────────────────
# Windows UTF-8 Console Fix
# Ensures emoji and Unicode box-drawing characters render correctly.
# ──────────────────────────────────────────────────────────────────────────────
if sys.platform == 'win32' and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# Logging Setup
# ──────────────────────────────────────────────────────────────────────────────

LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
# Suppress noisy sub-module loggers in normal mode
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.WARNING)

logger = logging.getLogger('usb_client')

# ──────────────────────────────────────────────────────────────────────────────
# Imports (local modules)
# ──────────────────────────────────────────────────────────────────────────────

try:
    import fingerprint as fp_module
    import crypto_engine as ce
    import lease_manager as lm
except ImportError as e:
    print(f"\n❌  Import error: {e}")
    print("Make sure all .py modules are in the same directory as this script.")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

# Base directory — script's own directory (USB root)
BASE_DIR = Path(__file__).parent.resolve()

# File paths (relative to USB root)
CONFIG_FILE    = BASE_DIR / 'config.json'
LOCAL_KEY_FILE = BASE_DIR / 'local_key.bin'
VAULT_FILE     = BASE_DIR / 'vault.enc'
LEASE_FILE     = BASE_DIR / 'lease.tok'

# Default backend URL (override in config.json or environment)
DEFAULT_API_URL = os.environ.get('USB_API_URL', 'http://localhost:3000')


# ──────────────────────────────────────────────────────────────────────────────
# Config Management
# ──────────────────────────────────────────────────────────────────────────────

def load_config() -> Optional[dict]:
    """Load drive configuration from config.json."""
    if not CONFIG_FILE.exists():
        return None
    try:
        return json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        return None


def save_config(config: dict) -> None:
    """Persist drive configuration to config.json."""
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding='utf-8')
    logger.debug(f"Config saved to {CONFIG_FILE}")


def get_config_or_exit() -> dict:
    """Load config, exit with helpful error if not initialised."""
    config = load_config()
    if not config:
        print("\n❌  Drive not initialised!")
        print("    Please run option [1] first to register and initialise this drive.")
        sys.exit(1)
    return config


# ──────────────────────────────────────────────────────────────────────────────
# Session State
# ──────────────────────────────────────────────────────────────────────────────

# Global session state — tracks active unlocked session
session_state = {
    'unlocked':          False,
    'temp_dir':          None,    # Path to decrypted temp directory
    'cloud_key_share':   None,    # Active cloud key share
    'unlock_time':       None,
    'was_online':        False
}


# ──────────────────────────────────────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    """Print the application banner."""
    print("\n" + "═" * 65)
    print("  🔐  Remote-Killable Encrypted USB Drive System  v1.0")
    print("  Split-Key Architecture | AES-256-GCM | Offline Lease")
    print("═" * 65)


def print_menu() -> None:
    """Print the main menu."""
    unlocked_tag = " [🔓 UNLOCKED]" if session_state['unlocked'] else " [🔒 LOCKED]"
    print(f"\n  Vault Status:{unlocked_tag}")
    print("  ─────────────────────────────────────────────────────")
    print("  [1]  Initialise / Encrypt folder → vault.enc")
    print("  [2]  Unlock vault  (Online or Offline Lease check)")
    print("  [3]  Lock vault    (Secure wipe of decrypted files)")
    print("  [4]  Simulate: Mark drive as LOST (remote kill)")
    print("  [5]  Drive info & lease status")
    print("  [6]  Open decrypted session folder")
    print("  [0]  Exit")
    print("  ─────────────────────────────────────────────────────")


# ──────────────────────────────────────────────────────────────────────────────
# Option [1]: Initialise / Encrypt
# ──────────────────────────────────────────────────────────────────────────────

def cmd_initialise() -> None:
    """
    Register a new drive with the backend, generate local key share,
    then encrypt a user-specified folder into vault.enc.
    """
    print("\n" + "─" * 60)
    print("  STEP 1/3: Initialise Drive")
    print("─" * 60)

    # Check for existing config
    existing = load_config()
    if existing:
        print(f"\n  ⚠️  Drive already initialised.")
        print(f"     Drive ID : {existing.get('drive_id')}")
        print(f"     Label    : {existing.get('label', 'N/A')}")
        confirm = input("\n  Reinitialise? This will OVERWRITE vault.enc! (yes/no): ").strip().lower()
        if confirm != 'yes':
            print("  Cancelled.")
            return

    # Collect inputs
    api_url = input(f"\n  Backend URL [{DEFAULT_API_URL}]: ").strip() or DEFAULT_API_URL
    admin_key = input("  Admin API Key: ").strip()
    label     = input("  Drive label (e.g. 'Work Laptop USB'): ").strip() or 'My USB Drive'

    print("\n  Registering drive with backend...")

    try:
        import requests
        response = requests.post(
            f"{api_url.rstrip('/')}/api/register",
            json={'label': label},
            headers={'X-Admin-Key': admin_key},
            timeout=10
        )
        data = response.json()

        if response.status_code != 201:
            print(f"\n  ❌  Registration failed: {data.get('error', 'Unknown error')}")
            return

    except Exception as e:
        print(f"\n  ❌  Cannot connect to backend: {e}")
        print("  Make sure the backend server is running and the URL is correct.")
        return

    drive_id        = data['drive_id']
    cloud_key_share = data['cloud_key_share']

    print(f"\n  ✅  Drive registered successfully!")
    print(f"     Drive ID         : {drive_id}")
    print(f"     Label            : {label}")
    print(f"     Cloud Key Share  : {cloud_key_share[:16]}...{cloud_key_share[-8:]} (stored on server)")

    # Generate and save local key share
    print("\n  Generating local key share (K_local)...")
    k_local = ce.generate_local_key()
    ce.save_local_key(k_local, LOCAL_KEY_FILE)
    print(f"  ✅  K_local saved to: {LOCAL_KEY_FILE}")
    print(f"     K_local (hex)    : {k_local.hex()[:16]}...{k_local.hex()[-8:]} (stored locally)")

    # Save configuration
    config = {
        'drive_id':   drive_id,
        'label':      label,
        'api_url':    api_url,
        'created_at': int(time.time()),
        'version':    1
    }
    save_config(config)

    # STEP 2: Encrypt a folder
    print("\n" + "─" * 60)
    print("  STEP 2/3: Encrypt Folder → vault.enc")
    print("─" * 60)

    while True:
        source_str = input("\n  Path to folder to encrypt: ").strip().strip('"')
        source_dir = Path(source_str)
        if source_dir.exists() and source_dir.is_dir():
            break
        print(f"  ❌  Not a valid directory: {source_str}")

    k_cloud_bytes = ce.hex_to_key_bytes(cloud_key_share)
    print(f"\n  Encrypting '{source_dir.name}' → vault.enc ...")

    try:
        stats = ce.encrypt_folder_to_vault(source_dir, VAULT_FILE, k_local, k_cloud_bytes)
        print(f"\n  ✅  Vault created successfully!")
        print(f"     Files encrypted : {stats['files_encrypted']}")
        print(f"     Data encrypted  : {stats['bytes_encrypted']:,} bytes")
        print(f"     Vault size      : {stats['vault_size']:,} bytes")
        print(f"     Vault path      : {stats['vault_path']}")
    except Exception as e:
        print(f"\n  ❌  Encryption failed: {e}")
        logger.exception("Encryption error")
        return

    # STEP 3: First online authentication (creates lease.tok)
    print("\n" + "─" * 60)
    print("  STEP 3/3: First Authentication (creates offline lease)")
    print("─" * 60)

    fingerprint = fp_module.generate_fingerprint()
    print(f"\n  Host fingerprint: {fingerprint[:32]}...")
    print("  Authenticating with backend...")

    success, cks, message, was_online = lm.authenticate(
        api_url, drive_id, fingerprint, k_local, LEASE_FILE
    )

    if success:
        print(f"\n  ✅  {message}")
        print("     Offline lease token saved for 7-day offline access.")
    else:
        print(f"\n  ⚠️  {message}")
        print("     The vault is encrypted. You must authenticate online before first use.")

    print("\n" + "─" * 60)
    print("  🎉  Drive initialisation complete!")
    print(f"     ⚠️  IMPORTANT: Secure the local_key.bin file —")
    print(f"                  Without it, the vault CANNOT be decrypted!")
    print("─" * 60)


# ──────────────────────────────────────────────────────────────────────────────
# Option [2]: Unlock Vault
# ──────────────────────────────────────────────────────────────────────────────

def cmd_unlock() -> None:
    """
    Unlock the vault — try online authentication first, fall back to offline lease.
    Decrypts vault.enc to a secure temporary directory.
    """
    if session_state['unlocked']:
        print(f"\n  ℹ️  Vault already unlocked.")
        print(f"     Session dir: {session_state['temp_dir']}")
        return

    if not VAULT_FILE.exists():
        print("\n  ❌  No vault.enc found. Run option [1] first.")
        return

    config  = get_config_or_exit()
    k_local = ce.load_local_key(LOCAL_KEY_FILE)

    drive_id = config['drive_id']
    api_url  = config.get('api_url', DEFAULT_API_URL)

    # Display vault metadata (unauthenticated peek)
    meta = ce.inspect_vault_header(VAULT_FILE)
    if meta:
        print(f"\n  Vault contains {meta.get('file_count', '?')} files")
        print(f"  Created: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(meta.get('created_at', 0)))}")

    # Collect hardware fingerprint
    print("\n  Collecting hardware fingerprint...")
    fingerprint = fp_module.generate_fingerprint()
    print(f"  Fingerprint: {fingerprint[:32]}...")

    # Authenticate (online → offline fallback)
    print("\n  Authenticating...")
    success, cloud_key_share_hex, message, was_online = lm.authenticate(
        api_url, drive_id, fingerprint, k_local, LEASE_FILE
    )

    if not success:
        print(f"\n  ❌  Authentication failed: {message}")
        print("\n  Access denied. Vault remains encrypted.")
        return

    print(f"\n  ✅  {message}")

    # Decrypt vault
    print("\n  Decrypting vault...")
    try:
        k_cloud = ce.hex_to_key_bytes(cloud_key_share_hex)
        temp_dir = ce.decrypt_vault_to_temp(VAULT_FILE, k_local, k_cloud)

        session_state['unlocked']        = True
        session_state['temp_dir']        = temp_dir
        session_state['cloud_key_share'] = cloud_key_share_hex
        session_state['unlock_time']     = time.time()
        session_state['was_online']      = was_online

        print(f"\n  🔓  Vault UNLOCKED successfully!")
        print(f"     Session directory: {temp_dir}")
        print(f"     Files are accessible for this session only.")
        print(f"     Run option [3] to lock and securely erase temp files.")

    except Exception as e:
        print(f"\n  ❌  Decryption failed: {e}")
        print("     This may indicate a wrong key or vault corruption.")
        logger.exception("Vault decryption error")


# ──────────────────────────────────────────────────────────────────────────────
# Option [3]: Lock / Eject
# ──────────────────────────────────────────────────────────────────────────────

def cmd_lock() -> None:
    """
    Lock the vault: securely wipe all decrypted temp files and clear session state.
    """
    if not session_state['unlocked']:
        print("\n  ℹ️  Vault is already locked.")
        return

    temp_dir = session_state['temp_dir']
    print(f"\n  Locking vault and wiping session files from: {temp_dir}")

    if temp_dir and Path(temp_dir).exists():
        confirm = input("  Confirm lock? All unsaved changes will be lost. (yes/no): ").strip().lower()
        if confirm != 'yes':
            print("  Cancelled.")
            return

        wiped = ce.secure_wipe_temp(Path(temp_dir))
        print(f"\n  ✅  Secure wipe complete: {wiped} files erased.")
    else:
        print("  Session directory already cleaned.")

    # Clear session state
    session_state['unlocked']        = False
    session_state['temp_dir']        = None
    session_state['cloud_key_share'] = None
    session_state['unlock_time']     = None
    session_state['was_online']      = False

    print("  🔒  Vault LOCKED. Decrypted data removed from memory/temp storage.")


# ──────────────────────────────────────────────────────────────────────────────
# Option [4]: Simulate Mark as Lost
# ──────────────────────────────────────────────────────────────────────────────

def cmd_mark_lost() -> None:
    """
    Simulate the remote kill-switch by calling POST /api/mark-lost.
    In production this would be triggered by the user's web dashboard or email.
    """
    config = get_config_or_exit()
    api_url  = config.get('api_url', DEFAULT_API_URL)
    drive_id = config['drive_id']

    print("\n" + "─" * 60)
    print("  ⚠️   REMOTE KILL SWITCH SIMULATION")
    print("─" * 60)
    print(f"\n  Drive ID : {drive_id}")
    print(f"  API URL  : {api_url}")
    print("\n  This will permanently mark the drive as LOST on the server.")
    print("  All future authentication attempts will be BLOCKED.")

    confirm = input("\n  Type 'MARK LOST' to confirm: ").strip()
    if confirm != 'MARK LOST':
        print("  Cancelled — kill switch NOT triggered.")
        return

    admin_key = input("  Admin API Key: ").strip()
    reason    = input("  Reason (optional): ").strip() or "Drive reported lost by owner."

    try:
        import requests
        response = requests.post(
            f"{api_url.rstrip('/')}/api/mark-lost",
            json={'drive_id': drive_id, 'reason': reason},
            headers={'X-Admin-Key': admin_key},
            timeout=10
        )
        data = response.json()

        if response.status_code == 200:
            print(f"\n  🔴  KILL SWITCH ACTIVATED!")
            print(f"     {data.get('message', 'Drive marked as LOST.')}")
            print(f"\n  Future authentication attempts will return:")
            print(f"     {{ \"status\": \"LOCKED\", \"message\": \"Drive marked as lost.\" }}")

            # If currently unlocked, force lock
            if session_state['unlocked']:
                print("\n  Auto-locking current session...")
                cmd_lock()
        else:
            print(f"\n  ❌  Failed: {data.get('error', 'Unknown error')}")

    except Exception as e:
        print(f"\n  ❌  Cannot connect to backend: {e}")


# ──────────────────────────────────────────────────────────────────────────────
# Option [5]: Drive Info & Lease Status
# ──────────────────────────────────────────────────────────────────────────────

def cmd_info() -> None:
    """Display drive configuration, hardware fingerprint, and lease token status."""
    config = load_config()

    print("\n" + "═" * 60)
    print("  📋  Drive Information")
    print("═" * 60)

    if config:
        print(f"  Drive ID    : {config.get('drive_id', 'N/A')}")
        print(f"  Label       : {config.get('label', 'N/A')}")
        print(f"  API URL     : {config.get('api_url', 'N/A')}")
        print(f"  Initialised : {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(config.get('created_at', 0)))}")
    else:
        print("  Not initialised (no config.json found)")

    print("\n  📁  File Status:")
    for f, label in [
        (LOCAL_KEY_FILE, 'local_key.bin'),
        (VAULT_FILE,     'vault.enc    '),
        (LEASE_FILE,     'lease.tok    '),
        (CONFIG_FILE,    'config.json  ')
    ]:
        size   = f"{f.stat().st_size:>10,} bytes" if f.exists() else "NOT FOUND    "
        status = "✅" if f.exists() else "❌"
        print(f"    {status}  {label}  {size}")

    print("\n  🖥️  Current Host Fingerprint:")
    try:
        fp_module.display_fingerprint_info()
    except Exception as e:
        print(f"    Error: {e}")

    if config and LOCAL_KEY_FILE.exists():
        print("  🗝️  Offline Lease Token:")
        try:
            k_local = ce.load_local_key(LOCAL_KEY_FILE)
            lm.display_lease_info(LEASE_FILE, k_local, config.get('drive_id', ''))
        except Exception as e:
            print(f"    Error reading lease: {e}")

    if session_state['unlocked']:
        elapsed = int(time.time() - session_state['unlock_time'])
        print(f"\n  🔓  Active Session:")
        print(f"    Unlocked : {elapsed // 60}m {elapsed % 60}s ago")
        print(f"    Session  : {session_state['temp_dir']}")
        print(f"    Online   : {'Yes' if session_state['was_online'] else 'No (offline lease)'}")

    print("═" * 60)


# ──────────────────────────────────────────────────────────────────────────────
# Option [6]: Open Session Folder
# ──────────────────────────────────────────────────────────────────────────────

def cmd_open_folder() -> None:
    """Open the decrypted session folder in the OS file manager."""
    if not session_state['unlocked']:
        print("\n  ❌  Vault is locked. Unlock first with option [2].")
        return

    temp_dir = session_state['temp_dir']
    if not temp_dir or not Path(temp_dir).exists():
        print("\n  ❌  Session directory not found.")
        return

    print(f"\n  Opening session folder: {temp_dir}")
    try:
        if sys.platform == 'win32':
            os.startfile(temp_dir)
        elif sys.platform == 'darwin':
            subprocess.Popen(['open', str(temp_dir)])
        else:
            subprocess.Popen(['xdg-open', str(temp_dir)])
        print("  ✅  File manager opened.")
    except Exception as e:
        print(f"  ❌  Could not open folder: {e}")
        print(f"  Path: {temp_dir}")


# ──────────────────────────────────────────────────────────────────────────────
# Cleanup on Exit
# ──────────────────────────────────────────────────────────────────────────────

def cleanup_on_exit() -> None:
    """Ensure temp files are wiped if session is still active on exit."""
    if session_state['unlocked'] and session_state['temp_dir']:
        print("\n  ⚠️  Session still active — auto-wiping temp files on exit...")
        temp_dir = Path(session_state['temp_dir'])
        if temp_dir.exists():
            wiped = ce.secure_wipe_temp(temp_dir)
            print(f"  ✅  {wiped} files wiped on exit.")


# ──────────────────────────────────────────────────────────────────────────────
# Main Loop
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Main CLI event loop."""
    import atexit
    atexit.register(cleanup_on_exit)

    print_banner()

    # Quick status check on startup
    config = load_config()
    if config:
        print(f"\n  Drive: {config.get('label', 'Unknown')} [{config.get('drive_id', '')[:8]}...]")
    else:
        print("\n  ⚠️  Drive not yet initialised. Run option [1] to set up.")

    while True:
        print_menu()
        choice = input("  Enter choice: ").strip()

        print()  # spacing

        if choice == '1':
            cmd_initialise()
        elif choice == '2':
            cmd_unlock()
        elif choice == '3':
            cmd_lock()
        elif choice == '4':
            cmd_mark_lost()
        elif choice == '5':
            cmd_info()
        elif choice == '6':
            cmd_open_folder()
        elif choice == '0':
            cleanup_on_exit()
            # Reset so atexit doesn't double-wipe
            session_state['unlocked'] = False
            print("  Goodbye. Stay secure! 🔐\n")
            break
        else:
            print(f"  ❓  Unknown option: '{choice}'. Enter 0-6.")


# ──────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    # Allow debug logging via env var
    if os.environ.get('USB_DEBUG', '').lower() in ('1', 'true', 'yes'):
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled.")

    main()
