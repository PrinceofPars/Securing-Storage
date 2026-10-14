"""
gui.py — USB Killswitch v2 Modern Desktop GUI Client
======================================================
Modern desktop application built with CustomTkinter.

Features:
  - Modern dark glassmorphism aesthetic
  - Split authentication & approval screen:
    - Left side: "Click to Show QR Code" for mobile phone camera scanning
    - Right side: "Continue with Google" for browser-based portal authentication
  - Live 2s polling that auto-detects owner approvals from phone or web portal
  - Tail-manifest file workspace with:
    - Open single file (with full edit & save-back support)
    - Open any specific directory or whole vault in Windows Explorer
    - Incremental Lock & Save that detects modified files and updates vault.enc
    - Secure wiping of all temporary working files on lock/exit

Run:  python gui.py
"""

import json
import logging
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox
import tkinter.ttk as ttk
from typing import Optional, List, Dict
import webbrowser

# Fix Windows UTF-8 console
if sys.platform == 'win32' and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

import customtkinter as ctk
from PIL import Image
import qrcode

# Local modules
import fingerprint as fp_module
import crypto_engine as ce
import lease_manager as lm

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.WARNING)
logger = logging.getLogger('usb_gui')

# ──────────────────────────────────────────────────────────────────────────────
# Configuration & Paths
# ──────────────────────────────────────────────────────────────────────────────

if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys.executable).parent.resolve()
else:
    BASE_DIR = Path(__file__).parent.resolve()

CONFIG_FILE    = BASE_DIR / 'config.json'
LOCAL_KEY_FILE = BASE_DIR / 'local_key.bin'
VAULT_FILE     = BASE_DIR / 'vault.enc'
LEASE_FILE     = BASE_DIR / 'lease.tok'
PROD_API_URL   = 'https://securing-storage.onrender.com'
DEV_API_URL    = 'http://localhost:3000'

def is_dev_mode() -> bool:
    """Return True only if explicitly running in development mode."""
    env_val = os.environ.get('USB_ENV', '').strip().lower()
    mode_val = os.environ.get('USB_MODE', '').strip().lower()
    api_override = os.environ.get('USB_API_URL', '').strip().lower()
    if env_val in ('dev', 'development', 'local'):
        return True
    if mode_val in ('dev', 'development', 'local'):
        return True
    if api_override and ('localhost' in api_override or '127.0.0.1' in api_override):
        return True
    return False

def get_api_url(config: Optional[dict] = None) -> str:
    """
    Return backend API URL.
    Strictly defaults to production Render URL ('https://securing-storage.onrender.com')
    unless explicitly running in development mode.
    """
    # 1. Explicit custom URL override via USB_API_URL
    custom_url = os.environ.get('USB_API_URL', '').strip()
    if custom_url:
        return custom_url.rstrip('/')

    # 2. Explicit development mode (e.g. USB_ENV=dev)
    if is_dev_mode():
        return DEV_API_URL

    # 3. Default is strictly PROD_API_URL
    # If drive config contains localhost from previous local dev test, ignore it in production mode.
    if config and config.get('api_url'):
        saved_url = config['api_url'].rstrip('/')
        if 'localhost' in saved_url or '127.0.0.1' in saved_url:
            return PROD_API_URL
        return saved_url

    return PROD_API_URL

DEFAULT_API    = get_api_url()

def set_base_dir(new_path: Path):
    global BASE_DIR, CONFIG_FILE, LOCAL_KEY_FILE, VAULT_FILE, LEASE_FILE
    BASE_DIR       = new_path
    CONFIG_FILE    = BASE_DIR / 'config.json'
    LOCAL_KEY_FILE = BASE_DIR / 'local_key.bin'
    VAULT_FILE     = BASE_DIR / 'vault.enc'
    LEASE_FILE     = BASE_DIR / 'lease.tok'

# ──────────────────────────────────────────────────────────────────────────────
# Modern Theme Configuration
# ──────────────────────────────────────────────────────────────────────────────

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLORS = {
    'bg':            '#0a0d14',
    'bg_card':       '#131722',
    'bg_card_alt':   '#181d2c',
    'bg_input':      '#1e2436',
    'accent':        '#6366f1',
    'accent_hover':  '#818cf8',
    'accent_purple': '#8b5cf6',
    'success':       '#10b981',
    'danger':        '#f43f5e',
    'danger_hover':  '#e11d48',
    'warning':       '#f59e0b',
    'text':          '#f8fafc',
    'text_dim':      '#94a3b8',
    'text_muted':    '#64748b',
    'border':        '#272e42',
    'border_focus':  '#4f46e5',
}

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def load_config() -> Optional[dict]:
    # Check encapsulated vault header first
    if VAULT_FILE.exists():
        try:
            hdr = ce.read_vault_header(VAULT_FILE)
            if hdr and hdr.get('config'):
                return hdr['config']
        except Exception:
            pass
    # Fallback to legacy loose config.json
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
        except Exception:
            pass
    return None

def load_local_key() -> Optional[bytes]:
    """Retrieve local key share from encapsulated vault header or fallback file."""
    if VAULT_FILE.exists():
        try:
            hdr = ce.read_vault_header(VAULT_FILE)
            if hdr and hdr.get('k_local'):
                return hdr['k_local']
        except Exception:
            pass
    if LOCAL_KEY_FILE.exists():
        try:
            return ce.load_local_key(LOCAL_KEY_FILE)
        except Exception:
            pass
    return None

def save_config(config: dict):
    # If vault exists and is v3 encapsulated, update header in-place
    if VAULT_FILE.exists():
        try:
            ce.update_vault_header(VAULT_FILE, config=config)
            return
        except Exception:
            pass
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding='utf-8')

def generate_qr_ctk_image(data_str: str, size: int = 170) -> ctk.CTkImage:
    """Generate a high-contrast CTkImage containing a QR code."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(data_str)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="white", back_color="#181d2c")
    # Extract underlying PIL.Image.Image if wrapped by PilImage
    pil_img = qr_img.get_image() if hasattr(qr_img, 'get_image') else qr_img
    pil_img = pil_img.convert('RGB')
    return ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(size, size))


# ══════════════════════════════════════════════════════════════════════════════
# Main Desktop Application
# ══════════════════════════════════════════════════════════════════════════════

class USBKillswitchApp(ctk.CTk):
    """Modern Desktop GUI client for USB Killswitch v2."""

    def __init__(self):
        super().__init__()

        self.title("Zero-Trust Storage Protection")
        self.geometry("880x700")
        self.minsize(800, 620)
        self.configure(fg_color=COLORS['bg'])

        # Session state
        self.session = {
            'unlocked':        False,
            'manifest':        None,
            'k_local':         None,
            'cloud_key_share': None,
            'working_dir':     None,
            'opened_files':    {},   # rel_path -> local Path
            'is_full_extract': False,
            'unlock_time':     None,
            'request_id':      None,
        }
        self._poll_thread = None
        self._poll_stop   = threading.Event()
        self._timer_id    = None

        # Route initial screen: check if vault exists and if an authorized offline lease is valid
        v_exists = VAULT_FILE.exists()
        hdr = None
        if v_exists:
            try:
                hdr = ce.read_vault_header(VAULT_FILE)
            except Exception:
                pass

        has_vault = bool(
            (hdr and hdr.get('config') and hdr.get('k_local')) or
            (load_config() and load_local_key() and v_exists)
        )

        if has_vault:
            if not self._try_startup_auto_unlock():
                self._show_unlock_screen()
        else:
            self._show_init_screen()

        # Handle window close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _show_splash_screen(self, message: str = "Authorizing hardware identity..."):
        self._clear_window()
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True)

        center = ctk.CTkFrame(frame, fg_color=COLORS['bg_card'], corner_radius=16,
                             border_width=1, border_color=COLORS['border'])
        center.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(center, text="🔒 SECURE VAULT ACCESS",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['accent']).pack(padx=60, pady=(32, 6))

        config = load_config()
        label = config.get('label', 'USB Storage Vault') if config else 'USB Storage Vault'
        ctk.CTkLabel(center, text=label,
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=COLORS['text']).pack(padx=60, pady=(0, 16))

        self.startup_status = ctk.CTkLabel(center, text=message,
                                           font=ctk.CTkFont(size=13),
                                           text_color=COLORS['warning'])
        self.startup_status.pack(padx=60, pady=(0, 32))

    def _focus_window(self):
        """Bring the application window to the foreground and focus it."""
        try:
            self.deiconify()  # restore if minimized
            self.lift()
            self.attributes('-topmost', True)
            self.after(200, lambda: self.attributes('-topmost', False))
            self.focus_force()

            if sys.platform == 'win32':
                import ctypes
                hwnd = self.winfo_id()
                try:
                    target_hwnd = ctypes.windll.user32.FindWindowW(None, "Zero-Trust Storage Protection")
                    if target_hwnd:
                        hwnd = target_hwnd
                except Exception:
                    pass
                ctypes.windll.user32.ShowWindow(hwnd, 9)  # SW_RESTORE = 9
                ctypes.windll.user32.SetForegroundWindow(hwnd)
        except Exception as e:
            logger.debug(f"Could not force foreground window: {e}")

    def _try_startup_auto_unlock(self) -> bool:
        """
        Check if an active offline lease token exists for this host system.
        If valid and bound to the current hardware fingerprint, auto-unlock and
        transition directly to the workspace file tree.
        """
        try:
            config = load_config()
            k_local = load_local_key()
            if not config or not k_local or not VAULT_FILE.exists():
                return False

            fp_hash = fp_module.generate_fingerprint()
            self._current_fingerprint = fp_hash
            drive_id = config.get('drive_id', '')

            lease = lm.load_lease_token(LEASE_FILE, k_local, drive_id, vault_path=VAULT_FILE)
            if not lease:
                return False

            now = int(time.time())
            expires_at = lease.get('expires_at', 0)
            lease_fp = lease.get('fingerprint', '')
            cks = lease.get('cloud_key_share')

            if not cks or now >= expires_at:
                logger.info("Startup check: lease token missing key share or expired.")
                return False

            if fp_hash.lower() != lease_fp.lower():
                logger.info("Startup check: lease hardware fingerprint does not match current host machine.")
                return False

            logger.info("Valid offline lease detected for authorized host hardware. Directly opening vault workspace...")
            self._show_splash_screen("Authorizing hardware identity...")
            self.after(50, lambda: self._load_vault_workspace(
                k_local, cks, "Offline Lease (Auto)", "Authorized offline session active"
            ))
            return True

        except Exception as e:
            logger.warning(f"Startup auto-unlock check encountered error: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────────
    # Screen 1: Initialization Setup Wizard
    # ──────────────────────────────────────────────────────────────────────

    def _show_init_screen(self):
        self._clear_window()
        self._selected_folder = None

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=40, pady=24)

        # Header Badge & Title
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.pack(pady=(0, 16))

        ctk.CTkLabel(header_box, text="🔐 ZERO-TRUST STORAGE SETUP",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=COLORS['accent']).pack()
        ctk.CTkLabel(header_box, text="Initialize Encrypted Vault",
                     font=ctk.CTkFont(size=24, weight="bold"),
                     text_color=COLORS['text']).pack(pady=(2, 2))
        ctk.CTkLabel(header_box, text="Configure your USB drive with split-key tail-manifest encryption",
                     font=ctk.CTkFont(size=13),
                     text_color=COLORS['text_dim']).pack()

        # Form Card
        card = ctk.CTkFrame(frame, fg_color=COLORS['bg_card'], corner_radius=16,
                            border_width=1, border_color=COLORS['border'])
        card.pack(fill="x", pady=(0, 14))

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=20)

        # Google Account Connection
        ctk.CTkLabel(inner, text="Drive Owner Identity",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['text_dim']).pack(anchor="w")

        # Google Sign-In Action Button
        self.init_google_btn = ctk.CTkButton(
            inner, text="  Continue with Google", height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#ffffff", hover_color="#f1f5f9",
            text_color="#1f2937", corner_radius=10,
            command=self._launch_init_google_auth
        )
        self.init_google_btn.pack(fill="x", pady=(4, 8))

        # Verified Email Badge / Manual Entry
        self.init_email_badge = ctk.CTkLabel(inner, text="Click 'Continue with Google' to verify owner identity",
                                             font=ctk.CTkFont(size=11),
                                             text_color=COLORS['text_muted'])
        self.init_email_badge.pack(anchor="w", pady=(0, 6))

        self.init_email = ctk.CTkEntry(inner, placeholder_text="Or enter email manually (e.g. owner@gmail.com)",
                                       height=32, fg_color=COLORS['bg_input'],
                                       border_color=COLORS['border'], corner_radius=8,
                                       font=ctk.CTkFont(size=11))
        self.init_email.pack(fill="x", pady=(0, 12))

        # Drive Label
        ctk.CTkLabel(inner, text="Drive Label (Optional)",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['text_dim']).pack(anchor="w")
        self.init_label = ctk.CTkEntry(inner, placeholder_text="e.g. Encrypted Work Drive",
                                       height=36, fg_color=COLORS['bg_input'],
                                       border_color=COLORS['border'], corner_radius=8)
        self.init_label.pack(fill="x", pady=(4, 12))

        # Folder selection
        folder_row = ctk.CTkFrame(inner, fg_color="transparent")
        folder_row.pack(fill="x", pady=(0, 6))

        ctk.CTkLabel(folder_row, text="Source Folder to Encrypt",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['text_dim']).pack(anchor="w")

        btn_row = ctk.CTkFrame(folder_row, fg_color="transparent")
        btn_row.pack(fill="x", pady=(4, 0))

        self.folder_label = ctk.CTkLabel(btn_row, text="No folder selected",
                                         text_color=COLORS['text_muted'],
                                         font=ctk.CTkFont(size=12))
        self.folder_label.pack(side="left", fill="x", expand=True, anchor="w")

        ctk.CTkButton(btn_row, text="Browse...", width=100, height=32,
                      fg_color=COLORS['bg_input'], hover_color=COLORS['border'],
                      text_color=COLORS['text'], corner_radius=8,
                      command=self._browse_folder).pack(side="right")

        # Wipe checkbox
        self.wipe_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(folder_row, text="Securely wipe original plaintext folder after encryption",
                        variable=self.wipe_var,
                        font=ctk.CTkFont(size=11), text_color=COLORS['danger'],
                        hover_color=COLORS['danger'], border_color=COLORS['border']).pack(anchor="w", pady=(8, 0))

        # Status & Progress
        self.init_status = ctk.CTkLabel(frame, text="", text_color=COLORS['text_dim'],
                                        font=ctk.CTkFont(size=12))
        self.init_status.pack(pady=(0, 4))

        self.init_progress = ctk.CTkProgressBar(frame, width=440, height=6,
                                                 progress_color=COLORS['accent'],
                                                 fg_color=COLORS['bg_input'])
        self.init_progress.pack(pady=(0, 10))
        self.init_progress.set(0)

        # Action Buttons
        ctk.CTkButton(frame, text="🚀 Initialize & Encrypt Drive", height=42,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      fg_color=COLORS['accent'], hover_color=COLORS['accent_hover'],
                      corner_radius=10,
                      command=self._do_init).pack(fill="x")

        ctk.CTkButton(frame, text="Open Existing Vault Folder...", height=30,
                      fg_color="transparent", border_width=1,
                      border_color=COLORS['border'], hover_color=COLORS['bg_card'],
                      text_color=COLORS['text_dim'], corner_radius=8,
                      command=self._open_existing_vault).pack(pady=(10, 0))

    def _launch_init_google_auth(self):
        """Open browser for Google login during initialization and auto-populate email."""
        import secrets
        current_api = get_api_url()
        session_id = f"init_{secrets.token_hex(8)}"
        auth_url = f"{current_api.rstrip('/')}/auth/google?session_id={session_id}"
        webbrowser.open(auth_url)

        self.init_email_badge.configure(text="⏳ Waiting for Google Sign-In in browser...", text_color=COLORS['warning'])

        def poll_google():
            import requests
            start_t = time.time()
            while time.time() - start_t < 180:
                try:
                    r = requests.get(f"{current_api.rstrip('/')}/api/auth/google/check-session?session_id={session_id}", timeout=5)
                    if r.ok:
                        data = r.json()
                        if data.get('authenticated') and data.get('email'):
                            verified_email = data['email']
                            self.after(0, lambda e=verified_email: self._on_google_verified(e))
                            return
                except Exception:
                    pass
                time.sleep(1)

        threading.Thread(target=poll_google, daemon=True).start()

    def _on_google_verified(self, email: str):
        self._focus_window()
        self.init_email.delete(0, 'end')
        self.init_email.insert(0, email)
        self.init_email_badge.configure(text=f"✅ Verified Google Owner: {email}", text_color=COLORS['success'])
        self.init_google_btn.configure(text=f"  Signed In as {email}", fg_color="#e2e8f0")

    def _open_existing_vault(self):
        path = filedialog.askdirectory(title="Select directory containing vault.enc")
        if path:
            set_base_dir(Path(path))
            hdr = None
            if VAULT_FILE.exists():
                try:
                    hdr = ce.read_vault_header(VAULT_FILE)
                except Exception:
                    pass
            if (hdr and hdr.get('config') and hdr.get('k_local')) or (load_config() and load_local_key() and VAULT_FILE.exists()):
                self._show_unlock_screen()
            else:
                messagebox.showerror("Error", f"No valid vault found in {path}")
                set_base_dir(Path(__file__).parent.resolve())

    def _browse_folder(self):
        path = filedialog.askdirectory(title="Select folder to encrypt into vault")
        if path:
            self._selected_folder = path
            name = Path(path).name
            self.folder_label.configure(text=f"📁  {name}/   ({path})", text_color=COLORS['text'])

    def _do_init(self):
        api_url = get_api_url()
        email   = self.init_email.get().strip()
        label   = self.init_label.get().strip() or 'My USB Drive'
        folder  = self._selected_folder

        if not email:
            self.init_status.configure(text="Please enter your Owner Email address.",
                                       text_color=COLORS['danger'])
            return
        if not folder or not Path(folder).is_dir():
            self.init_status.configure(text="Please select a valid folder to encrypt.",
                                       text_color=COLORS['danger'])
            return

        self.init_status.configure(text="Registering drive on server...",
                                   text_color=COLORS['warning'])
        self.update_idletasks()

        target_dir = Path(folder).parent
        set_base_dir(target_dir)

        def do_work():
            try:
                import requests
                fp = fp_module.generate_fingerprint()

                r = requests.post(
                    f"{api_url.rstrip('/')}/api/register",
                    json={
                        'label': label,
                        'owner_email': email,
                        'hardware_fingerprint': fp
                    },
                    timeout=10
                )
                if r.status_code not in (200, 201):
                    err_msg = r.json().get('error', r.text[:80]) if r.headers.get('content-type', '').startswith('application/json') else r.text[:80]
                    self.after(0, lambda: self.init_status.configure(
                        text=f"Registration error: {err_msg}",
                        text_color=COLORS['danger']))
                    return

                data          = r.json()
                drive_id      = data['drive_id']
                cloud_key_hex = data['cloud_key_share']

                # Generate local key share (stored directly inside vault.enc header)
                k_local = ce.generate_local_key()

                # Build config
                config = {
                    'drive_id':    drive_id,
                    'label':       label,
                    'api_url':     api_url,
                    'owner_email': email,
                    'created_at':  int(time.time()),
                    'version':     3
                }

                self.after(0, lambda: self.init_status.configure(
                    text="Encrypting folder into encapsulated vault...",
                    text_color=COLORS['warning']))

                def encrypt_cb(current, total, filename):
                    progress = current / total if total > 0 else 0
                    self.after(0, lambda p=progress, c=current, t=total, f=filename: self._update_encrypt_progress(p, c, t, f))

                k_cloud_bytes = ce.hex_to_key_bytes(cloud_key_hex)
                stats = ce.encrypt_folder_to_vault(
                    Path(folder), VAULT_FILE, k_local, k_cloud_bytes,
                    config=config,
                    drive_metadata={'label': label, 'owner_email': email, 'created_at': int(time.time())},
                    progress_callback=encrypt_cb
                )

                # Clean up transient config and raw key files (lease.tok and vault.enc are strictly preserved)
                for loose_file in (CONFIG_FILE, LOCAL_KEY_FILE):
                    try:
                        if loose_file.exists():
                            loose_file.unlink()
                    except Exception:
                        pass

                if self.wipe_var.get():
                    def wipe_cb(current, total, filename):
                        self.after(0, lambda: self.init_status.configure(
                            text=f"Wiping files [{current}/{total}]...", text_color=COLORS['warning']))

                    self.after(0, lambda: self.init_status.configure(
                        text="Securely erasing original files...", text_color=COLORS['warning']))
                    
                    encrypted_file_list = stats.get('encrypted_files')
                    wiped = ce.secure_wipe_source_files(
                        Path(folder),
                        files_to_wipe=encrypted_file_list,
                        progress_callback=wipe_cb
                    )
                    logger.info(f"Wiped {wiped} original files from source folder (protected .enc/.tok preserved).")

                # Initial auth (stores lease token directly in vault.enc header)
                lm.authenticate(api_url, drive_id, fp, email, k_local, lease_path=LEASE_FILE, vault_path=VAULT_FILE)

                files_count = stats['files_encrypted']
                self.after(0, lambda: self._init_complete(files_count, drive_id))

            except Exception as e:
                logger.exception("Init error")
                self.after(0, lambda: self.init_status.configure(
                    text=f"Error: {e}", text_color=COLORS['danger']))

        threading.Thread(target=do_work, daemon=True).start()

    def _init_complete(self, files_count, drive_id):
        if hasattr(self, 'init_progress'):
            self.init_progress.set(1.0)
        self.init_status.configure(
            text=f"Drive {drive_id[:8]}... initialized! {files_count} files encrypted.",
            text_color=COLORS['success'])
        self.after(1400, self._show_unlock_screen)

    def _update_encrypt_progress(self, progress, current, total, filename):
        try:
            if hasattr(self, 'init_progress') and self.init_progress.winfo_exists():
                self.init_progress.set(progress)
            if hasattr(self, 'init_status') and self.init_status.winfo_exists():
                short_name = filename if len(filename) < 38 else '...' + filename[-35:]
                self.init_status.configure(
                    text=f"Encrypting [{current}/{total}]: {short_name}",
                    text_color=COLORS['warning'])
        except Exception:
            pass

    # ──────────────────────────────────────────────────────────────────────
    # Screen 2: Modern Unlock / Login Screen
    # ──────────────────────────────────────────────────────────────────────

    def _show_unlock_screen(self):
        self._clear_window()
        config = load_config()

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=40, pady=24)

        # Title
        drive_label = config.get('label', 'USB Storage Vault') if config else 'USB Storage Vault'
        ctk.CTkLabel(frame, text="🔒 SECURE VAULT ACCESS",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=COLORS['accent']).pack()
        ctk.CTkLabel(frame, text=drive_label,
                     font=ctk.CTkFont(size=24, weight="bold"),
                     text_color=COLORS['text']).pack(pady=(2, 2))
        ctk.CTkLabel(frame, text="Authenticate hardware identity or request remote access",
                     font=ctk.CTkFont(size=13),
                     text_color=COLORS['text_dim']).pack(pady=(0, 16))

        # Main Card
        card = ctk.CTkFrame(frame, fg_color=COLORS['bg_card'], corner_radius=16,
                            border_width=1, border_color=COLORS['border'])
        card.pack(fill="x", pady=(0, 14))
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=20)

        # Email
        ctk.CTkLabel(inner, text="User / Owner Email",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['text_dim']).pack(anchor="w")
        self.unlock_email = ctk.CTkEntry(inner, placeholder_text="Enter your email address",
                                         height=38, fg_color=COLORS['bg_input'],
                                         border_color=COLORS['border'], corner_radius=8)
        self.unlock_email.pack(fill="x", pady=(4, 12))

        # Pre-fill email if available from config or lease token
        default_email = ''
        if config:
            default_email = config.get('owner_email') or config.get('user_email', '')
        if not default_email and config:
            k_local_peek = load_local_key()
            if k_local_peek:
                try:
                    lease_peek = lm.load_lease_token(LEASE_FILE, k_local_peek, config.get('drive_id', ''), vault_path=VAULT_FILE)
                    if lease_peek and lease_peek.get('user_email'):
                        default_email = lease_peek['user_email']
                except Exception:
                    pass
        if default_email:
            self.unlock_email.insert(0, default_email)

        # Fingerprint card
        fp_hash = fp_module.generate_fingerprint()
        self._current_fingerprint = fp_hash

        fp_frame = ctk.CTkFrame(inner, fg_color=COLORS['bg_input'], corner_radius=8,
                                border_width=1, border_color=COLORS['border'])
        fp_frame.pack(fill="x", pady=(0, 12))
        fp_inner = ctk.CTkFrame(fp_frame, fg_color="transparent")
        fp_inner.pack(fill="x", padx=14, pady=10)

        ctk.CTkLabel(fp_inner, text="Host Hardware Fingerprint",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=COLORS['text_muted']).pack(anchor="w")
        ctk.CTkLabel(fp_inner, text=f"{fp_hash[:32]}",
                     font=ctk.CTkFont(family="Consolas", size=11),
                     text_color=COLORS['accent']).pack(anchor="w")
        ctk.CTkLabel(fp_inner, text=f"{fp_hash[32:]}",
                     font=ctk.CTkFont(family="Consolas", size=11),
                     text_color=COLORS['accent']).pack(anchor="w")

        comps = fp_module.get_hardware_components()
        ctk.CTkLabel(fp_inner,
                     text=f"Host: {comps.get('platform','')} {comps.get('os_arch','')} | {comps.get('hostname','')}",
                     font=ctk.CTkFont(size=10),
                     text_color=COLORS['text_muted']).pack(anchor="w", pady=(4, 0))

        # Vault & Lease status
        meta = ce.inspect_vault_header(VAULT_FILE)
        if meta and meta.get('valid'):
            v_size_mb = meta.get('vault_size', 0) / (1024 * 1024)
            enc_tag = " (Encapsulated Header)" if meta.get('encapsulated') else ""
            vault_info = f"Vault v{meta.get('version', 3)} format{enc_tag} ({v_size_mb:.2f} MB)"
            ctk.CTkLabel(inner, text=vault_info,
                         font=ctk.CTkFont(size=11),
                         text_color=COLORS['text_dim']).pack(anchor="w", pady=(0, 4))

        # Server Environment Indicator (Production vs Dev)
        current_server = get_api_url(config)
        is_dev = is_dev_mode()
        server_tag = f"Server: 🛠️ Dev ({current_server})" if is_dev else "Server: ☁️ Production (Render)"
        server_color = COLORS['warning'] if is_dev else COLORS['accent_hover']
        ctk.CTkLabel(inner, text=server_tag,
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=server_color).pack(anchor="w", pady=(0, 4))

        k_local = load_local_key()
        if config and k_local:
            try:
                info = lm.get_lease_info(LEASE_FILE, k_local, config.get('drive_id', ''), vault_path=VAULT_FILE)
                if info and not info['is_expired']:
                    lease_text = f"Offline lease active: {info['days_left']}d {info['hours_left']}h remaining"
                    ctk.CTkLabel(inner, text=lease_text,
                                 font=ctk.CTkFont(size=11),
                                 text_color=COLORS['success']).pack(anchor="w", pady=(0, 4))
                elif info and info['is_expired']:
                    ctk.CTkLabel(inner, text="Offline lease expired — online authentication required",
                                 font=ctk.CTkFont(size=11),
                                 text_color=COLORS['warning']).pack(anchor="w", pady=(0, 4))
            except Exception:
                pass

        # Status
        self.unlock_status = ctk.CTkLabel(frame, text="",
                                          font=ctk.CTkFont(size=12),
                                          text_color=COLORS['text_dim'])
        self.unlock_status.pack(pady=(0, 6))

        # Buttons
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(fill="x")

        ctk.CTkButton(btn_frame, text="Unlock Vault", height=42,
                      font=ctk.CTkFont(size=14, weight="bold"),
                      fg_color=COLORS['accent'], hover_color=COLORS['accent_hover'],
                      corner_radius=10,
                      command=self._do_unlock).pack(fill="x", pady=(0, 6))

        ctk.CTkButton(btn_frame, text="🌐 Verify & Unlock with Google", height=36,
                      font=ctk.CTkFont(size=12, weight="bold"),
                      fg_color="#ffffff", hover_color="#f1f5f9",
                      text_color="#1f2937", corner_radius=10,
                      command=self._launch_unlock_google_auth).pack(fill="x", pady=(0, 8))

        bottom_row = ctk.CTkFrame(btn_frame, fg_color="transparent")
        bottom_row.pack(fill="x")

        ctk.CTkButton(bottom_row, text="Re-initialize Drive", height=30,
                      font=ctk.CTkFont(size=11),
                      fg_color="transparent", border_width=1,
                      border_color=COLORS['border'], hover_color=COLORS['bg_card'],
                      text_color=COLORS['text_dim'], corner_radius=8,
                      command=self._show_init_screen).pack(side="left")

    def _launch_unlock_google_auth(self):
        """Open browser for Google login during unlock and automatically focus back and unlock."""
        import secrets
        current_api = get_api_url()
        session_id = f"unlock_{secrets.token_hex(8)}"
        auth_url = f"{current_api.rstrip('/')}/auth/google?session_id={session_id}"
        webbrowser.open(auth_url)

        self.unlock_status.configure(text="⏳ Waiting for Google Sign-In in browser...", text_color=COLORS['warning'])

        def poll_google():
            import requests
            start_t = time.time()
            while time.time() - start_t < 180:
                try:
                    r = requests.get(f"{current_api.rstrip('/')}/api/auth/google/check-session?session_id={session_id}", timeout=5)
                    if r.ok:
                        data = r.json()
                        if data.get('authenticated') and data.get('email'):
                            verified_email = data['email']
                            self.after(0, lambda e=verified_email: self._on_unlock_google_verified(e))
                            return
                except Exception:
                    pass
                time.sleep(1)

        threading.Thread(target=poll_google, daemon=True).start()

    def _on_unlock_google_verified(self, email: str):
        self._focus_window()
        self.unlock_email.delete(0, 'end')
        self.unlock_email.insert(0, email)
        self.unlock_status.configure(text=f"✅ Google Verified: {email}. Unlocking...", text_color=COLORS['success'])
        self.after(200, self._do_unlock)

    def _do_unlock(self):
        config = load_config()
        if not config:
            self.unlock_status.configure(text="Drive configuration missing.", text_color=COLORS['danger'])
            return

        email = self.unlock_email.get().strip()
        if not email and config:
            email = config.get('owner_email') or config.get('user_email', '')
        if not email:
            self.unlock_status.configure(text="Please enter your email.", text_color=COLORS['danger'])
            return

        self.unlock_status.configure(text="Authenticating...", text_color=COLORS['warning'])
        self.update_idletasks()

        def do_auth():
            try:
                k_local  = load_local_key()
                if not k_local:
                    self.after(0, lambda: self.unlock_status.configure(
                        text="Local key share missing from vault header.", text_color=COLORS['danger']))
                    return

                fp       = self._current_fingerprint
                api_url  = get_api_url(config)
                drive_id = config['drive_id']

                result, cks, msg, was_online, request_id = lm.authenticate(
                    api_url, drive_id, fp, email, k_local,
                    lease_path=LEASE_FILE, vault_path=VAULT_FILE
                )

                if result in ('GRANTED', 'OFFLINE_GRANTED'):
                    self.session['cloud_key_share'] = cks
                    self.session['k_local'] = k_local
                    mode = "Online Verified" if was_online else "Offline Lease"
                    self.after(0, lambda: self._load_vault_workspace(k_local, cks, mode, msg))

                elif result == 'PENDING':
                    self.after(0, lambda: self._show_waiting_screen(
                        request_id, config, k_local, fp, email))

                elif result == 'LOCKED':
                    self.after(0, lambda: self.unlock_status.configure(
                        text="DRIVE IS MARKED LOST — ACCESS PERMANENTLY BLOCKED",
                        text_color=COLORS['danger']))

                elif result == 'DENIED':
                    self.after(0, lambda: self.unlock_status.configure(
                        text=f"Access denied: {msg}", text_color=COLORS['danger']))

                else:  # OFFLINE_DENIED
                    self.after(0, lambda: self.unlock_status.configure(
                        text=msg, text_color=COLORS['danger']))

            except Exception as e:
                logger.exception("Unlock error")
                self.after(0, lambda: self.unlock_status.configure(
                    text=f"Error: {e}", text_color=COLORS['danger']))

        threading.Thread(target=do_auth, daemon=True).start()

    def _load_vault_workspace(self, k_local, cloud_key_hex, mode, msg):
        def _set_status(txt, color):
            if hasattr(self, 'wait_status') and self.wait_status.winfo_exists():
                self.wait_status.configure(text=txt, text_color=color)
            elif hasattr(self, 'unlock_status') and self.unlock_status.winfo_exists():
                self.unlock_status.configure(text=txt, text_color=color)
            elif hasattr(self, 'startup_status') and self.startup_status.winfo_exists():
                self.startup_status.configure(text=txt, text_color=color)

        _set_status(f"Loading vault ({mode})...", COLORS['warning'])
        self.update_idletasks()

        def do_load():
            try:
                k_cloud = ce.hex_to_key_bytes(cloud_key_hex)
                manifest = ce.read_vault_manifest(VAULT_FILE, k_local, k_cloud)

                # Auto-migrate legacy v2 vaults or loose metadata files to encapsulated v3!
                vmeta = ce.inspect_vault_header(VAULT_FILE)
                if (vmeta and not vmeta.get('encapsulated')) or (CONFIG_FILE.exists() or LOCAL_KEY_FILE.exists()):
                    try:
                        cfg = load_config() or {'drive_id': manifest.get('drive_metadata', {}).get('drive_id', '')}
                        lease_info = lm.load_lease_token(LEASE_FILE, k_local, cfg.get('drive_id', ''))
                        ce.migrate_v2_to_v3(VAULT_FILE, k_local, k_cloud, cfg, lease_data=lease_info)
                        for f in (CONFIG_FILE, LOCAL_KEY_FILE, LEASE_FILE):
                            if f.exists():
                                try:
                                    f.unlink()
                                except Exception:
                                    pass
                        logger.info("Auto-migrated legacy vault to v3 encapsulated vault; removed loose files.")
                    except Exception as me:
                        logger.warning(f"Auto-migration skipped: {me}")

                # Initialize unified working directory for current session
                work_dir = Path(tempfile.mkdtemp(prefix='zerotrust_session_'))

                self.session['unlocked']        = True
                self.session['manifest']        = manifest
                self.session['k_local']         = k_local
                self.session['cloud_key_share'] = cloud_key_hex
                self.session['unlock_time']     = time.time()
                self.session['working_dir']     = work_dir
                self.session['opened_files']    = {}
                self.session['is_full_extract'] = False

                self.after(0, lambda: self._show_workspace_screen())

            except Exception as e:
                logger.exception("Manifest load error")
                self.after(0, lambda: _set_status(f"Decryption failed: {e}", COLORS['danger']))
                if hasattr(self, 'startup_status') and self.startup_status.winfo_exists():
                    self.after(1500, self._show_unlock_screen)

        threading.Thread(target=do_load, daemon=True).start()

    # ──────────────────────────────────────────────────────────────────────
    # Screen 3: Waiting for Approval (Modern Split Screen: QR Code + Google Login)
    # ──────────────────────────────────────────────────────────────────────

    def _show_waiting_screen(self, request_id, config, k_local, fingerprint, email):
        self._clear_window()
        self._poll_stop.clear()

        api_url     = get_api_url(config)
        approve_url = f"{api_url.rstrip('/')}/approve?req={request_id}"
        google_url  = f"{api_url.rstrip('/')}/auth/google?req={request_id}&email={email}"

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=32, pady=20)

        # Header Badge
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.pack(pady=(0, 14))

        ctk.CTkLabel(header_box, text="⚡ ACCESS APPROVAL REQUIRED",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=COLORS['warning']).pack()
        ctk.CTkLabel(header_box, text="Authorize This Device",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=COLORS['text']).pack(pady=(2, 2))
        ctk.CTkLabel(header_box, text="The drive owner must grant permission via Mobile QR or Google Sign-In portal",
                     font=ctk.CTkFont(size=12),
                     text_color=COLORS['text_dim']).pack()

        # Split Dual-Card Layout Container
        dual_card = ctk.CTkFrame(frame, fg_color="transparent")
        dual_card.pack(fill="x", pady=(0, 14))

        # ─── LEFT CARD: Mobile QR Code Fast Approval ───
        left_card = ctk.CTkFrame(dual_card, fg_color=COLORS['bg_card'], corner_radius=16,
                                 border_width=1, border_color=COLORS['border'])
        left_card.pack(side="left", fill="both", expand=True, padx=(0, 10))

        left_inner = ctk.CTkFrame(left_card, fg_color="transparent")
        left_inner.pack(fill="both", expand=True, padx=20, pady=18)

        ctk.CTkLabel(left_inner, text="📱 Mobile Approval",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=COLORS['text']).pack(anchor="w")
        ctk.CTkLabel(left_inner, text="Scan with owner's phone camera",
                     font=ctk.CTkFont(size=11),
                     text_color=COLORS['text_muted']).pack(anchor="w", pady=(0, 12))

        # Code pill
        code_pill = ctk.CTkFrame(left_inner, fg_color=COLORS['bg_input'], corner_radius=8)
        code_pill.pack(fill="x", pady=(0, 10))
        cp_inner = ctk.CTkFrame(code_pill, fg_color="transparent")
        cp_inner.pack(padx=12, pady=6)
        ctk.CTkLabel(cp_inner, text="REQUEST CODE:",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color=COLORS['text_muted']).pack(side="left")
        ctk.CTkLabel(cp_inner, text=f"  {request_id}",
                     font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
                     text_color=COLORS['warning']).pack(side="left")

        # QR Code Container
        self._qr_container = ctk.CTkFrame(left_inner, fg_color=COLORS['bg_card_alt'], corner_radius=12,
                                          border_width=1, border_color=COLORS['border'])
        self._qr_container.pack(fill="x", pady=(0, 10))

        self._qr_image_label = None
        self._qr_shown = False

        # Generate and show QR Code immediately by default
        try:
            qr_img = generate_qr_ctk_image(approve_url, size=150)
            self._qr_image_label = ctk.CTkLabel(self._qr_container, image=qr_img, text="")
            self._qr_image_label.pack(padx=10, pady=10)
            self._qr_shown = True
        except Exception as e:
            logger.warning(f"QR render init failed: {e}")

        self._qr_toggle_btn = ctk.CTkButton(
            left_inner, text="🙈 Hide QR Code" if self._qr_shown else "📷 Click to Show QR Code", height=34,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=COLORS['bg_input'], hover_color=COLORS['border'],
            text_color=COLORS['text'], corner_radius=8,
            command=lambda: self._toggle_qr_code(approve_url)
        )
        self._qr_toggle_btn.pack(fill="x")

        # ─── RIGHT CARD: Continue with Google / Portal Auth ───
        right_card = ctk.CTkFrame(dual_card, fg_color=COLORS['bg_card'], corner_radius=16,
                                  border_width=1, border_color=COLORS['border'])
        right_card.pack(side="right", fill="both", expand=True, padx=(10, 0))

        right_inner = ctk.CTkFrame(right_card, fg_color="transparent")
        right_inner.pack(fill="both", expand=True, padx=20, pady=18)

        ctk.CTkLabel(right_inner, text="🌐 Web Portal Approval",
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=COLORS['text']).pack(anchor="w")
        ctk.CTkLabel(right_inner, text="Sign in as drive owner in your browser",
                     font=ctk.CTkFont(size=11),
                     text_color=COLORS['text_muted']).pack(anchor="w", pady=(0, 16))

        # Google Button
        ctk.CTkButton(
            right_inner, text="  Continue with Google", height=44,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#ffffff", hover_color="#f1f5f9",
            text_color="#1f2937", corner_radius=10,
            command=lambda: webbrowser.open(google_url)
        ).pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(right_inner, text="Clicking opens your default browser to log in with Google, manage drives & grant instant approval.",
                     font=ctk.CTkFont(size=11),
                     text_color=COLORS['text_dim'],
                     wraplength=280).pack(pady=(0, 12))

        # Direct Portal Link button
        ctk.CTkButton(
            right_inner, text="Open Direct Approval Link", height=32,
            font=ctk.CTkFont(size=11),
            fg_color=COLORS['bg_input'], hover_color=COLORS['border'],
            text_color=COLORS['accent'], corner_radius=8,
            command=lambda: webbrowser.open(approve_url)
        ).pack(fill="x")

        # ─── Bottom Status & Polling ───
        bottom_card = ctk.CTkFrame(frame, fg_color=COLORS['bg_card'], corner_radius=12,
                                   border_width=1, border_color=COLORS['border'])
        bottom_card.pack(fill="x", pady=(0, 10))

        bc_inner = ctk.CTkFrame(bottom_card, fg_color="transparent")
        bc_inner.pack(fill="x", padx=16, pady=12)

        self.wait_status = ctk.CTkLabel(bc_inner, text="⏳ Waiting for owner decision (polling every 2s)...",
                                        font=ctk.CTkFont(size=12),
                                        text_color=COLORS['text_dim'])
        self.wait_status.pack(side="left")

        self.wait_progress = ctk.CTkProgressBar(bc_inner, mode="indeterminate",
                                                 width=200, height=4,
                                                 progress_color=COLORS['accent'])
        self.wait_progress.pack(side="right", padx=(10, 0))
        self.wait_progress.start()

        # Cancel button
        ctk.CTkButton(frame, text="Cancel Request", height=32, width=140,
                      fg_color="transparent", border_width=1,
                      border_color=COLORS['border'], hover_color=COLORS['bg_card'],
                      text_color=COLORS['text_dim'], corner_radius=8,
                      command=self._cancel_wait).pack()

        # Start 2-second background polling
        drive_id = config['drive_id']

        def poll_loop():
            while not self._poll_stop.is_set():
                try:
                    result, cks, msg = lm.poll_request_status(
                        api_url, request_id, drive_id,
                        fingerprint, email, k_local,
                        lease_path=LEASE_FILE, vault_path=VAULT_FILE
                    )

                    if result == 'APPROVED':
                        self._poll_stop.set()
                        self.after(0, lambda: self._on_approval_granted(k_local, cks, msg))
                        return
                    elif result == 'DENIED':
                        self._poll_stop.set()
                        self.after(0, lambda: self._on_approval_denied())
                        return

                except Exception as e:
                    logger.warning(f"Poll loop error: {e}")

                self._poll_stop.wait(2)

        self._poll_thread = threading.Thread(target=poll_loop, daemon=True)
        self._poll_thread.start()

    def _toggle_qr_code(self, approve_url: str):
        """Expand/collapse QR code on user click."""
        if not self._qr_shown:
            try:
                qr_img = generate_qr_ctk_image(approve_url, size=150)
                if not self._qr_image_label:
                    self._qr_image_label = ctk.CTkLabel(self._qr_container, image=qr_img, text="")
                    self._qr_image_label.pack(padx=10, pady=10)
                else:
                    self._qr_image_label.configure(image=qr_img)
                    self._qr_image_label.pack(padx=10, pady=10)

                self._qr_toggle_btn.configure(text="🙈 Hide QR Code")
                self._qr_shown = True
            except Exception as e:
                logger.warning(f"QR render failed: {e}")
        else:
            if self._qr_image_label:
                self._qr_image_label.pack_forget()
            self._qr_toggle_btn.configure(text="📷 Click to Show QR Code")
            self._qr_shown = False

    def _cancel_wait(self):
        self._poll_stop.set()
        self._show_unlock_screen()

    def _on_approval_granted(self, k_local, cloud_key_hex, msg):
        self._focus_window()
        self.wait_progress.stop()
        self.wait_status.configure(text=f"✅ Access Approved! {msg}", text_color=COLORS['success'])
        self.update_idletasks()
        self.after(500, lambda: self._load_vault_workspace(k_local, cloud_key_hex, "Approved", msg))

    def _on_approval_denied(self):
        self._focus_window()
        self.wait_progress.stop()
        self.wait_status.configure(text="🚫 Access DENIED by drive owner.",
                                   text_color=COLORS['danger'])
        self.after(2000, self._show_unlock_screen)

    # ──────────────────────────────────────────────────────────────────────
    # Screen 4: Vault Workspace (Manifest TreeView, On-Demand Decrypt, Directory Explorer, Lock & Save)
    # ──────────────────────────────────────────────────────────────────────

    def _show_workspace_screen(self):
        self._clear_window()
        config = load_config()
        manifest = self.session.get('manifest', {})
        raw_files = manifest.get('files', [])
        # Exclude OS system volume metadata (e.g. System Volume Information, $RECYCLE.BIN)
        files = [f for f in raw_files if not ce.is_system_file(f.get('path', ''))]

        # ─── Top Nav Bar ───
        top = ctk.CTkFrame(self, fg_color=COLORS['bg_card'], height=54, corner_radius=0,
                           border_width=1, border_color=COLORS['border'])
        top.pack(fill="x")
        top.pack_propagate(False)

        top_inner = ctk.CTkFrame(top, fg_color="transparent")
        top_inner.pack(fill="both", expand=True, padx=16)

        ctk.CTkLabel(top_inner, text=f"📂  {config.get('label', 'Vault')}",
                     font=ctk.CTkFont(size=15, weight="bold"),
                     text_color=COLORS['text']).pack(side="left")

        # Status badge
        status_frame = ctk.CTkFrame(top_inner, fg_color=COLORS['bg_input'], corner_radius=12)
        status_frame.pack(side="left", padx=(16, 0))
        sf_inner = ctk.CTkFrame(status_frame, fg_color="transparent")
        sf_inner.pack(padx=10, pady=3)

        self.ws_status_dot = ctk.CTkLabel(sf_inner, text="●",
                                          font=ctk.CTkFont(size=10),
                                          text_color=COLORS['success'])
        self.ws_status_dot.pack(side="left", padx=(0, 5))

        self.ws_status_text = ctk.CTkLabel(sf_inner, text="ACTIVE SESSION",
                                           font=ctk.CTkFont(size=11, weight="bold"),
                                           text_color=COLORS['success'])
        self.ws_status_text.pack(side="left")

        # Session Timer
        self.ws_timer = ctk.CTkLabel(top_inner, text="",
                                     font=ctk.CTkFont(size=12),
                                     text_color=COLORS['text_dim'])
        self.ws_timer.pack(side="right", padx=(0, 10))

        # Lock buttons
        ctk.CTkButton(top_inner, text="🔒 Lock & Save", height=32, width=120,
                      font=ctk.CTkFont(size=12, weight="bold"),
                      fg_color=COLORS['accent'], hover_color=COLORS['accent_hover'],
                      corner_radius=8,
                      command=self._do_lock_and_save).pack(side="right", padx=(6, 0))

        ctk.CTkButton(top_inner, text="Discard & Lock", height=32, width=110,
                      font=ctk.CTkFont(size=11),
                      fg_color=COLORS['danger'], hover_color=COLORS['danger_hover'],
                      corner_radius=8,
                      command=self._do_lock_no_save).pack(side="right", padx=(6, 0))

        # ─── Main Content ───
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=16, pady=12)

        browser_frame = ctk.CTkFrame(main, fg_color=COLORS['bg_card'], corner_radius=14,
                                    border_width=1, border_color=COLORS['border'])
        browser_frame.pack(fill="both", expand=True)

        # Header toolbar
        browser_header = ctk.CTkFrame(browser_frame, fg_color="transparent")
        browser_header.pack(fill="x", padx=16, pady=(12, 8))

        ctk.CTkLabel(browser_header, text=f"Encrypted Vault Files ({len(files)} items)",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=COLORS['text_dim']).pack(side="left")

        btn_bar = ctk.CTkFrame(browser_header, fg_color="transparent")
        btn_bar.pack(side="right")

        ctk.CTkButton(btn_bar, text="📄 Open File", height=28, width=105,
                      font=ctk.CTkFont(size=11),
                      fg_color=COLORS['bg_input'], hover_color=COLORS['border'],
                      text_color=COLORS['text'], corner_radius=6,
                      command=self._open_selected_item).pack(side="left", padx=(0, 6))

        ctk.CTkButton(btn_bar, text="✏️ Edit in Explorer", height=28, width=145,
                      font=ctk.CTkFont(size=11, weight="bold"),
                      fg_color=COLORS['accent_purple'], hover_color='#7c3aed',
                      text_color='#ffffff', corner_radius=6,
                      command=self._open_in_explorer).pack(side="left")

        # Treeview styling
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Vault.Treeview",
                        background=COLORS['bg_card'],
                        foreground=COLORS['text'],
                        fieldbackground=COLORS['bg_card'],
                        borderwidth=0,
                        rowheight=26,
                        font=('Inter', 10))
        style.configure("Vault.Treeview.Heading",
                        background=COLORS['bg_input'],
                        foreground=COLORS['text_dim'],
                        borderwidth=0,
                        font=('Inter', 10, 'bold'))
        style.map("Vault.Treeview",
                  background=[('selected', COLORS['accent'])],
                  foreground=[('selected', '#ffffff')])

        tree_container = ctk.CTkFrame(browser_frame, fg_color="transparent")
        tree_container.pack(fill="both", expand=True, padx=16, pady=(4, 12))

        self.file_tree = ttk.Treeview(tree_container, style="Vault.Treeview",
                                      columns=("size", "type", "modified"), show="tree headings",
                                      selectmode="browse")
        self.file_tree.heading("#0", text="Name / Path", anchor="w")
        self.file_tree.heading("size", text="Size", anchor="e")
        self.file_tree.heading("type", text="Type", anchor="w")
        self.file_tree.heading("modified", text="Modified", anchor="w")

        self.file_tree.column("#0", width=380, minwidth=240)
        self.file_tree.column("size", width=90, anchor="e")
        self.file_tree.column("type", width=70, anchor="w")
        self.file_tree.column("modified", width=140, anchor="w")

        scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=scrollbar.set)

        self.file_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Double click opens file or directory
        self.file_tree.bind("<Double-1>", lambda event: self._open_selected_item())

        # Populate tree
        self._populate_manifest_tree(files)

        # ─── Bottom Status Footer ───
        bottom = ctk.CTkFrame(self, fg_color=COLORS['bg_card'], height=34, corner_radius=0,
                              border_width=1, border_color=COLORS['border'])
        bottom.pack(fill="x")
        bottom.pack_propagate(False)

        bottom_inner = ctk.CTkFrame(bottom, fg_color="transparent")
        bottom_inner.pack(fill="both", expand=True, padx=16)

        drive_id_short = config.get('drive_id', '?')[:8] if config else '?'
        dead_space = manifest.get('dead_space_bytes', 0)
        dead_str = f" | Dead Space: {dead_space // 1024} KB" if dead_space > 0 else ""
        
        ctk.CTkLabel(bottom_inner, text=f"Drive ID: {drive_id_short}...{dead_str}",
                     font=ctk.CTkFont(size=10),
                     text_color=COLORS['text_muted']).pack(side="left")

        self.ws_status_footer = ctk.CTkLabel(bottom_inner, text="Vault on-demand mode active — modifications are auto-saved on Lock",
                                             font=ctk.CTkFont(size=10),
                                             text_color=COLORS['text_muted'])
        self.ws_status_footer.pack(side="right")

        self._start_timer()

    def _populate_manifest_tree(self, file_entries: List[dict]):
        self.file_tree.delete(*self.file_tree.get_children())
        nodes = {'': ''}
        self._tree_item_map = {}  # item_id -> {'is_dir': bool, 'path': str, 'entry': dict}

        # Ensure no system volume metadata files are added to tree view
        file_entries = [e for e in file_entries if not ce.is_system_file(e.get('path', ''))]

        for entry in sorted(file_entries, key=lambda e: e['path']):
            path_parts = entry['path'].split('/')
            curr_path = ''
            parent_id = ''

            for folder in path_parts[:-1]:
                curr_path = f"{curr_path}/{folder}" if curr_path else folder
                if curr_path not in nodes:
                    node_id = self.file_tree.insert(parent_id, 'end',
                                                     text=f"📁  {folder}/",
                                                     values=('', 'Folder', ''),
                                                     open=True)
                    nodes[curr_path] = node_id
                    self._tree_item_map[node_id] = {'is_dir': True, 'path': curr_path, 'entry': None}
                parent_id = nodes[curr_path]

            filename = path_parts[-1]
            size = entry.get('original_size', entry.get('size', 0))
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1024 * 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size / (1024*1024):.1f} MB"

            ext = Path(filename).suffix.lower()
            type_map = {
                '.txt': 'Text', '.md': 'Markdown', '.json': 'JSON',
                '.py': 'Python', '.js': 'JS', '.html': 'HTML',
                '.css': 'CSS', '.pdf': 'PDF', '.png': 'Image',
                '.jpg': 'Image', '.jpeg': 'Image', '.docx': 'Doc',
                '.xlsx': 'Excel', '.csv': 'Data',
            }
            file_type = type_map.get(ext, ext[1:].upper() if ext else 'File')

            mtime = entry.get('modified', 0)
            mtime_str = time.strftime('%Y-%m-%d %H:%M', time.localtime(mtime)) if mtime else '-'

            item_id = self.file_tree.insert(parent_id, 'end',
                                            text=f"📄  {filename}",
                                            values=(size_str, file_type, mtime_str))
            self._tree_item_map[item_id] = {'is_dir': False, 'path': entry['path'], 'entry': entry}

    def _open_selected_item(self):
        """Opens selected file in default app or opens folder in Windows Explorer."""
        selected = self.file_tree.selection()
        if not selected:
            # If nothing selected, open entire vault root in explorer
            self._open_all_in_explorer()
            return

        item_id = selected[0]
        meta = self._tree_item_map.get(item_id)
        if not meta:
            return

        if meta['is_dir']:
            # Selected a folder node -> decrypt and open that specific directory in explorer
            self._open_directory_path(meta['path'])
        else:
            # Selected a single file -> decrypt and open file
            self._open_single_file(meta['entry'])

    def _open_in_explorer(self):
        """Open selected folder in Explorer, or extract and open full vault if root/none selected."""
        selected = self.file_tree.selection()
        if not selected:
            self._open_all_in_explorer()
            return

        item_id = selected[0]
        meta = self._tree_item_map.get(item_id)
        if not meta:
            self._open_all_in_explorer()
            return

        if meta['is_dir']:
            self._open_directory_path(meta['path'])
        else:
            # If file selected, open its parent folder
            parent_dir = str(Path(meta['path']).parent).replace('\\', '/')
            if parent_dir and parent_dir != '.':
                self._open_directory_path(parent_dir)
            else:
                self._open_all_in_explorer()

    # Backwards-compatibility alias
    _open_selected_folder = _open_in_explorer

    def _open_single_file(self, entry: dict):
        """Decrypt single file to working directory and launch default application."""
        k_local = self.session.get('k_local')
        cloud_key_hex = self.session.get('cloud_key_share')
        work_dir = self.session.get('working_dir')

        if not k_local or not cloud_key_hex or not work_dir:
            messagebox.showerror("Error", "Session key material missing.")
            return

        try:
            k_cloud = ce.hex_to_key_bytes(cloud_key_hex)
            rel_path = entry['path']
            out_path = work_dir / rel_path

            # Decrypt if not already decrypted
            if not out_path.exists():
                plaintext = ce.decrypt_single_file(VAULT_FILE, k_local, k_cloud, entry)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(plaintext)
                try:
                    os.utime(out_path, (entry.get('modified', time.time()), entry.get('modified', time.time())))
                except Exception:
                    pass

            self.session['opened_files'][rel_path] = out_path

            # Launch default application
            if sys.platform == 'win32':
                os.startfile(str(out_path))
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', str(out_path)])
            else:
                subprocess.Popen(['xdg-open', str(out_path)])

            self.ws_status_footer.configure(text=f"Opened: {rel_path} — edits will be saved on Lock")
            self.ws_status_text.configure(text="EDIT MODE (ACTIVE)", text_color=COLORS['warning'])

        except Exception as e:
            logger.exception("Single file open error")
            messagebox.showerror("Decryption Error", f"Could not decrypt file: {e}")

    def _open_directory_path(self, dir_prefix: str):
        """Decrypt all files inside a specific directory prefix and open in Windows Explorer."""
        k_local = self.session.get('k_local')
        cloud_key_hex = self.session.get('cloud_key_share')
        manifest = self.session.get('manifest')
        work_dir = self.session.get('working_dir')

        if not k_local or not cloud_key_hex or not manifest or not work_dir:
            return

        self.ws_status_text.configure(text="EXTRACTING...", text_color=COLORS['warning'])
        self.update_idletasks()

        def do_extract():
            try:
                k_cloud = ce.hex_to_key_bytes(cloud_key_hex)
                ce.decrypt_directory_to_working_dir(
                    VAULT_FILE, k_local, k_cloud, manifest,
                    dir_prefix=dir_prefix, target_dir=work_dir
                )

                # Record all extracted files
                clean_p = dir_prefix.strip('/')
                for f in manifest.get('files', []):
                    if f['path'] == clean_p or f['path'].startswith(clean_p + '/'):
                        self.session['opened_files'][f['path']] = work_dir / f['path']

                target_folder = work_dir / clean_p
                target_folder.mkdir(parents=True, exist_ok=True)

                self.after(0, lambda: self._on_directory_ready(target_folder, clean_p))

            except Exception as e:
                logger.exception("Directory decrypt error")
                self.after(0, lambda: messagebox.showerror("Decryption Error", f"Could not open directory: {e}"))
                self.after(0, lambda: self.ws_status_text.configure(text="ACTIVE SESSION", text_color=COLORS['success']))

        threading.Thread(target=do_extract, daemon=True).start()

    def _on_directory_ready(self, target_folder: Path, dir_name: str):
        self.ws_status_text.configure(text="EDIT MODE (ACTIVE)", text_color=COLORS['warning'])
        self.ws_status_footer.configure(text=f"Opened directory: {dir_name}/ in Explorer")
        self._open_folder(target_folder)

    def _open_all_in_explorer(self):
        """Extract entire vault to working directory and open root in Explorer."""
        k_local = self.session.get('k_local')
        cloud_key_hex = self.session.get('cloud_key_share')
        manifest = self.session.get('manifest')
        work_dir = self.session.get('working_dir')

        if not k_local or not cloud_key_hex or not manifest or not work_dir:
            return

        self.ws_status_text.configure(text="EXTRACTING ALL...", text_color=COLORS['warning'])
        self.update_idletasks()

        def do_bulk():
            try:
                k_cloud = ce.hex_to_key_bytes(cloud_key_hex)
                clean_entries = [f for f in manifest.get('files', []) if not ce.is_system_file(f.get('path', ''))]
                ce.decrypt_files_to_working_dir(
                    VAULT_FILE, k_local, k_cloud, manifest,
                    file_entries=clean_entries
                )
                # Copy into unified work dir
                ce.decrypt_directory_to_working_dir(
                    VAULT_FILE, k_local, k_cloud, manifest,
                    dir_prefix='', target_dir=work_dir
                )

                self.session['is_full_extract'] = True
                for f in clean_entries:
                    self.session['opened_files'][f['path']] = work_dir / f['path']

                self.after(0, lambda: self._on_bulk_ready(work_dir))

            except Exception as e:
                logger.exception("Bulk decrypt error")
                self.after(0, lambda: messagebox.showerror("Decryption Error", f"Bulk decrypt failed: {e}"))
                self.after(0, lambda: self.ws_status_text.configure(text="ACTIVE SESSION", text_color=COLORS['success']))

        threading.Thread(target=do_bulk, daemon=True).start()

    def _on_bulk_ready(self, work_dir: Path):
        self.ws_status_text.configure(text="EDIT MODE (FULL VAULT)", text_color=COLORS['warning'])
        self.ws_status_footer.configure(text="All files extracted to temporary Explorer workspace")
        self._open_folder(work_dir)

    def _do_lock_and_save(self):
        """Inspects all opened/edited files, updates vault.enc incrementally, and wipes temp session."""
        if not self.session.get('unlocked'):
            return

        working_dir = self.session.get('working_dir')
        manifest = self.session.get('manifest')
        k_local = self.session.get('k_local')
        cloud_key_hex = self.session.get('cloud_key_share')
        is_full = self.session.get('is_full_extract', False)

        self.ws_status_text.configure(text="SAVING & LOCKING...", text_color=COLORS['warning'])
        self.update_idletasks()

        def do_save():
            try:
                k_cloud = ce.hex_to_key_bytes(cloud_key_hex)

                if working_dir and Path(working_dir).exists() and manifest:
                    # Update vault incrementally:
                    # If full extraction, deleted files are synced. If partial, untouched files are kept.
                    new_manifest = ce.update_vault_on_lock(
                        VAULT_FILE, k_local, k_cloud, Path(working_dir), manifest,
                        allow_partial=(not is_full)
                    )
                    ce.secure_wipe_temp(Path(working_dir))
                    logger.info("Vault updated and temp working files securely wiped.")

                self.after(0, self._lock_cleanup_and_exit)

            except Exception as e:
                logger.exception("Save & lock error")
                self.after(0, lambda: messagebox.showerror("Save Error", f"Failed to save vault changes: {e}"))
                self.after(0, lambda: self.ws_status_text.configure(text="ACTIVE SESSION", text_color=COLORS['success']))

        threading.Thread(target=do_save, daemon=True).start()

    def _do_lock_no_save(self):
        if not self.session.get('unlocked'):
            return

        if not messagebox.askyesno("Discard & Lock",
                                    "Discard all working edits and securely wipe temporary session files?"):
            return

        self.ws_status_text.configure(text="WIPING...", text_color=COLORS['danger'])
        self.update_idletasks()

        def do_wipe():
            working_dir = self.session.get('working_dir')
            if working_dir and Path(working_dir).exists():
                ce.secure_wipe_temp(Path(working_dir))

            self.after(0, self._lock_cleanup_and_exit)

        threading.Thread(target=do_wipe, daemon=True).start()

    def _lock_cleanup_and_exit(self):
        self.session = {
            'unlocked': False, 'manifest': None, 'k_local': None,
            'cloud_key_share': None, 'working_dir': None, 'opened_files': {},
            'is_full_extract': False, 'unlock_time': None, 'request_id': None
        }
        if self._timer_id:
            self.after_cancel(self._timer_id)
            self._timer_id = None
        self._show_unlock_screen()

    def _start_timer(self):
        if not self.session.get('unlocked'):
            return

        elapsed = int(time.time() - self.session['unlock_time'])
        mins = elapsed // 60
        secs = elapsed % 60
        hrs  = mins // 60
        mins = mins % 60

        if hrs > 0:
            timer_text = f"Session: {hrs}h {mins}m {secs}s"
        elif mins > 0:
            timer_text = f"Session: {mins}m {secs}s"
        else:
            timer_text = f"Session: {secs}s"

        try:
            self.ws_timer.configure(text=timer_text)
        except Exception:
            return

        self._timer_id = self.after(1000, self._start_timer)

    def _open_folder(self, folder: Path):
        try:
            if sys.platform == 'win32':
                os.startfile(str(folder))
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', str(folder)])
            else:
                subprocess.Popen(['xdg-open', str(folder)])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder: {e}")

    # ──────────────────────────────────────────────────────────────────────
    # Window Lifecycle
    # ──────────────────────────────────────────────────────────────────────

    def _clear_window(self):
        self._poll_stop.set()
        if self._timer_id:
            self.after_cancel(self._timer_id)
            self._timer_id = None
        for widget in self.winfo_children():
            widget.destroy()

    def _on_close(self):
        self._poll_stop.set()
        if self.session.get('unlocked'):
            working_dir = self.session.get('working_dir')
            if working_dir and Path(working_dir).exists():
                ce.secure_wipe_temp(Path(working_dir))
            logger.info("Session wiped on exit.")
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    if os.environ.get('USB_DEBUG', '').lower() in ('1', 'true', 'yes'):
        logging.getLogger().setLevel(logging.DEBUG)

    app = USBKillswitchApp()
    app.mainloop()
