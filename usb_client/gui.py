"""
gui.py — USB Killswitch v2 High-Assurance Desktop GUI Client
============================================================
Engineered desktop application built with CustomTkinter.
Designed for high usability, ergonomic clarity, and robust offline/online security.

Features:
  - High-craft, dark-mode-only industrial aesthetic (anti-AI, clean typography)
  - Split authorization gate:
      - Left: High-contrast QR code for mobile device scanning
      - Right: Direct browser portal authentication
  - Background polling (2s) auto-detecting remote owner decisions
  - Tail-manifest file workspace:
      - Single-file decrypt & launch with live modification tracking
      - Full-directory exploration in Windows Explorer
      - Incremental Save & Lock updating vault.enc
      - Cryptographic zeroing / secure wiping of temporary session data
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

# Fix Windows UTF-8 console output
if sys.platform == 'win32' and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

import customtkinter as ctk
from PIL import Image
import qrcode

# Local security modules
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
    """Return backend API URL with production fallback."""
    custom_url = os.environ.get('USB_API_URL', '').strip()
    if custom_url:
        return custom_url.rstrip('/')

    if is_dev_mode():
        return DEV_API_URL

    if config and config.get('api_url'):
        saved_url = config['api_url'].rstrip('/')
        if 'localhost' in saved_url or '127.0.0.1' in saved_url:
            return PROD_API_URL
        return saved_url

    return PROD_API_URL

DEFAULT_API = get_api_url()

def set_base_dir(new_path: Path):
    global BASE_DIR, CONFIG_FILE, LOCAL_KEY_FILE, VAULT_FILE, LEASE_FILE
    BASE_DIR       = new_path
    CONFIG_FILE    = BASE_DIR / 'config.json'
    LOCAL_KEY_FILE = BASE_DIR / 'local_key.bin'
    VAULT_FILE     = BASE_DIR / 'vault.enc'
    LEASE_FILE     = BASE_DIR / 'lease.tok'

# ──────────────────────────────────────────────────────────────────────────────
# Visual Design System (Engineered Dark Mode Only)
# ──────────────────────────────────────────────────────────────────────────────

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Precise, matte, industrial palette — high ergonomic contrast, no candy gradients
COLORS = {
    'bg':            '#0d1117',  # Deep matte canvas
    'bg_card':       '#161b22',  # Solid container surface
    'bg_card_alt':   '#1c2128',  # Elevated secondary panel / QR bed
    'bg_input':      '#1c2128',  # Input field background
    'bg_hover':      '#262c36',  # Action hover state
    'accent':        '#4f46e5',  # Authoritative royal indigo
    'accent_hover':  '#4338ca',  # Focused/hover indigo
    'accent_subtle': '#1e2338',  # Tinted accent background
    'success':       '#3fb950',  # Verified status emerald
    'success_bg':    '#12261a',  # Emerald tinted badge background
    'danger':        '#f85149',  # Crimson warning / lock
    'danger_hover':  '#da3633',  # Danger hover state
    'danger_bg':     '#2c1516',  # Danger badge background
    'warning':       '#e3b341',  # Amber caution / pending
    'warning_bg':    '#2b2210',  # Amber badge background
    'info':          '#58a6ff',  # Informational blue
    'text':          '#f0f6fc',  # Primary crisp text
    'text_dim':      '#8b949e',  # Secondary label text
    'text_muted':    '#6e7681',  # Tertiary metadata text
    'border':        '#30363d',  # Standard 1px panel border
    'border_subtle': '#21262d',  # Hairline interior divider
    'border_focus':  '#4f46e5',  # Input focus border
}

# ──────────────────────────────────────────────────────────────────────────────
# Storage & Metadata Helpers
# ──────────────────────────────────────────────────────────────────────────────

def load_config() -> Optional[dict]:
    """Retrieve configuration from encapsulated vault header or loose config.json."""
    if VAULT_FILE.exists():
        try:
            hdr = ce.read_vault_header(VAULT_FILE)
            if hdr and hdr.get('config'):
                return hdr['config']
        except Exception:
            pass
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
    if VAULT_FILE.exists():
        try:
            ce.update_vault_header(VAULT_FILE, config=config)
            return
        except Exception:
            pass
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding='utf-8')

def generate_qr_ctk_image(data_str: str, size: int = 160) -> ctk.CTkImage:
    """Generate high-contrast QR code embedded on dark matte container."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(data_str)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="white", back_color=COLORS['bg_card_alt'])
    pil_img = qr_img.get_image() if hasattr(qr_img, 'get_image') else qr_img
    pil_img = pil_img.convert('RGB')
    return ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(size, size))


# ══════════════════════════════════════════════════════════════════════════════
# Main Desktop Application Window
# ══════════════════════════════════════════════════════════════════════════════

class USBKillswitchApp(ctk.CTk):
    """Engineered desktop client for hardware-bound cryptographic storage."""

    def __init__(self):
        super().__init__()

        self.title("USB Killswitch — Storage Protection")
        self.geometry("900x700")
        self.minsize(820, 640)
        self.configure(fg_color=COLORS['bg'])

        # Active session context
        self.session = {
            'unlocked':        False,
            'manifest':        None,
            'k_local':         None,
            'cloud_key_share': None,
            'working_dir':     None,
            'opened_files':    {},
            'is_full_extract': False,
            'unlock_time':     None,
            'request_id':      None,
        }
        self._poll_thread = None
        self._poll_stop   = threading.Event()
        self._timer_id    = None
        self._current_fingerprint = fp_module.generate_fingerprint()

        # Route initial view
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

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _show_splash_screen(self, message: str = "Verifying host hardware binding..."):
        self._clear_window()
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True)

        center = ctk.CTkFrame(frame, fg_color=COLORS['bg_card'], corner_radius=10,
                             border_width=1, border_color=COLORS['border'])
        center.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(center, text="HARDWARE VERIFICATION",
                     font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                     text_color=COLORS['text_dim']).pack(padx=50, pady=(28, 4))

        config = load_config()
        label = config.get('label', 'Storage Vault') if config else 'Storage Vault'
        ctk.CTkLabel(center, text=label,
                     font=ctk.CTkFont(size=20, weight="bold"),
                     text_color=COLORS['text']).pack(padx=50, pady=(0, 14))

        self.startup_status = ctk.CTkLabel(center, text=message,
                                           font=ctk.CTkFont(size=12),
                                           text_color=COLORS['warning'])
        self.startup_status.pack(padx=50, pady=(0, 28))

    def _focus_window(self):
        """Bring window to foreground upon approval or critical state transition."""
        try:
            self.deiconify()
            self.lift()
            self.attributes('-topmost', True)
            self.after(200, lambda: self.attributes('-topmost', False))
            self.focus_force()

            if sys.platform == 'win32':
                import ctypes
                hwnd = self.winfo_id()
                try:
                    target_hwnd = ctypes.windll.user32.FindWindowW(None, "USB Killswitch — Storage Protection")
                    if target_hwnd:
                        hwnd = target_hwnd
                except Exception:
                    pass
                ctypes.windll.user32.ShowWindow(hwnd, 9)
                ctypes.windll.user32.SetForegroundWindow(hwnd)
        except Exception as e:
            logger.debug(f"Focus window exception: {e}")

    def _try_startup_auto_unlock(self) -> bool:
        """Check if this host's hardware fingerprint matches (via local lease or trusted server)."""
        try:
            config = load_config()
            k_local = load_local_key()
            if not config or not k_local or not VAULT_FILE.exists():
                return False

            fp_hash = fp_module.generate_fingerprint()
            self._current_fingerprint = fp_hash
            drive_id = config.get('drive_id', '')

            # 1. Check local offline lease first (offline or online)
            lease = lm.load_lease_token(LEASE_FILE, k_local, drive_id, vault_path=VAULT_FILE)
            if lease:
                now = int(time.time())
                expires_at = lease.get('expires_at', 0)
                lease_fp = lease.get('fingerprint', '')
                cks = lease.get('cloud_key_share')

                if cks and now < expires_at and fp_hash.lower() == lease_fp.lower():
                    logger.info("Valid offline lease active for this host. Directly opening workspace.")
                    self._show_splash_screen("Authorizing hardware identity...")
                    self.after(50, lambda: self._load_vault_workspace(
                        k_local, cks, "Offline Lease", "Authorized offline session active"
                    ))
                    return True

            # 2. Check if online and this hardware fingerprint is already trusted on server
            api_url = get_api_url(config)
            owner_email = config.get('owner_email') or config.get('user_email')
            if owner_email and lm.check_internet_connectivity():
                try:
                    res, cks, msg, req_id = lm.online_auth(
                        api_url, drive_id, fp_hash, owner_email, k_local,
                        lease_path=LEASE_FILE, vault_path=VAULT_FILE
                    )
                    if res == 'GRANTED' and cks:
                        logger.info("Hardware fingerprint verified via online trusted device. Directly opening workspace.")
                        self._show_splash_screen("Hardware identity verified...")
                        self.after(50, lambda: self._load_vault_workspace(
                            k_local, cks, "Online Verified", "Hardware identity verified"
                        ))
                        return True
                except Exception as oe:
                    logger.debug(f"Online auto-check failed: {oe}")

            return False

        except Exception as e:
            logger.warning(f"Startup auto-unlock error: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────────
    # View 1: Vault Initialization Setup
    # ──────────────────────────────────────────────────────────────────────

    def _show_init_screen(self):
        self._clear_window()
        self._selected_folder = None

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=48, pady=28)

        # Header Section
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.pack(pady=(0, 16), anchor="w")

        tag_row = ctk.CTkFrame(header_box, fg_color="transparent")
        tag_row.pack(anchor="w")
        ctk.CTkLabel(tag_row, text="SETUP WIZARD",
                     font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                     text_color=COLORS['accent']).pack(side="left")

        ctk.CTkLabel(header_box, text="Vault Initialization",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=COLORS['text']).pack(anchor="w", pady=(2, 2))
        ctk.CTkLabel(header_box, text="Create a split-key encrypted vault bound to hardware identity",
                     font=ctk.CTkFont(size=12),
                     text_color=COLORS['text_dim']).pack(anchor="w")

        # Main Configuration Card
        card = ctk.CTkFrame(frame, fg_color=COLORS['bg_card'], corner_radius=10,
                            border_width=1, border_color=COLORS['border'])
        card.pack(fill="x", pady=(0, 14))

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=24, pady=20)

        # 1. Owner Identity
        ctk.CTkLabel(inner, text="Vault Owner Identity",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['text']).pack(anchor="w")

        auth_subtext = ctk.CTkLabel(inner,
                                    text="Sign in with your Google Account to establish verified owner identity:",
                                    font=ctk.CTkFont(size=11),
                                    text_color=COLORS['text_muted'])
        auth_subtext.pack(anchor="w", pady=(2, 6))

        # Google Sign-In Action
        self._init_owner_email = None
        self.init_google_btn = ctk.CTkButton(
            inner, text="  Continue with Google", height=38,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#ffffff", hover_color="#f1f5f9",
            text_color="#1f2937", corner_radius=6,
            command=self._launch_init_google_auth
        )
        self.init_google_btn.pack(fill="x", pady=(0, 6))

        self.init_email_badge = ctk.CTkLabel(inner, text="Status: Awaiting Google authentication",
                                             font=ctk.CTkFont(family="Consolas", size=10),
                                             text_color=COLORS['text_muted'])
        self.init_email_badge.pack(anchor="w", pady=(0, 14))

        # 2. Vault Label
        ctk.CTkLabel(inner, text="Storage Unit Label",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['text']).pack(anchor="w")
        self.init_label = ctk.CTkEntry(inner, placeholder_text="e.g. Primary Work Vault",
                                       height=36, fg_color=COLORS['bg_input'],
                                       border_color=COLORS['border'], corner_radius=6)
        self.init_label.pack(fill="x", pady=(4, 14))

        # 3. Source Directory
        ctk.CTkLabel(inner, text="Source Folder to Encrypt",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['text']).pack(anchor="w")

        dir_picker_frame = ctk.CTkFrame(inner, fg_color=COLORS['bg_input'], corner_radius=6,
                                        border_width=1, border_color=COLORS['border'])
        dir_picker_frame.pack(fill="x", pady=(4, 8))

        self.folder_label = ctk.CTkLabel(dir_picker_frame, text="No folder selected",
                                         text_color=COLORS['text_muted'],
                                         font=ctk.CTkFont(size=12))
        self.folder_label.pack(side="left", padx=12, pady=8, fill="x", expand=True, anchor="w")

        ctk.CTkButton(dir_picker_frame, text="Browse...", width=90, height=28,
                      fg_color=COLORS['bg_card'], hover_color=COLORS['bg_hover'],
                      border_width=1, border_color=COLORS['border'],
                      text_color=COLORS['text'], corner_radius=4,
                      command=self._browse_folder).pack(side="right", padx=6, pady=4)

        # Secure Erase Option
        self.wipe_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(inner, text="Erase original plaintext files from drive after encryption completes",
                        variable=self.wipe_var,
                        font=ctk.CTkFont(size=11), text_color=COLORS['text_dim'],
                        hover_color=COLORS['danger'], border_color=COLORS['border'],
                        corner_radius=4).pack(anchor="w", pady=(4, 0))

        # Status & Progress Area
        self.init_status = ctk.CTkLabel(frame, text="", text_color=COLORS['text_dim'],
                                        font=ctk.CTkFont(size=12))
        self.init_status.pack(pady=(0, 4))

        self.init_progress = ctk.CTkProgressBar(frame, height=4,
                                                 progress_color=COLORS['accent'],
                                                 fg_color=COLORS['bg_input'])
        self.init_progress.pack(fill="x", pady=(0, 10))
        self.init_progress.set(0)

        # Primary Submission Buttons
        ctk.CTkButton(frame, text="Initialize Encrypted Vault", height=40,
                      font=ctk.CTkFont(size=13, weight="bold"),
                      fg_color=COLORS['accent'], hover_color=COLORS['accent_hover'],
                      corner_radius=6,
                      command=self._do_init).pack(fill="x")

        ctk.CTkButton(frame, text="Select Existing Vault Directory...", height=30,
                      fg_color="transparent", border_width=1,
                      border_color=COLORS['border'], hover_color=COLORS['bg_card'],
                      text_color=COLORS['text_dim'], corner_radius=6,
                      command=self._open_existing_vault).pack(pady=(8, 0))

    def _launch_init_google_auth(self):
        """Open web browser for Google authentication and listen for session result."""
        import secrets
        current_api = get_api_url()
        session_id = f"init_{secrets.token_hex(8)}"
        auth_url = f"{current_api.rstrip('/')}/auth/google?session_id={session_id}"
        webbrowser.open(auth_url)

        self.init_email_badge.configure(text="Status: Waiting for browser authentication...", text_color=COLORS['warning'])

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
        self._init_owner_email = email
        self.init_email_badge.configure(text=f"✓ Verified Owner: {email}", text_color=COLORS['success'])
        self.init_google_btn.configure(text=f"✓ Authenticated as {email}", fg_color=COLORS['bg_hover'], text_color=COLORS['text'])
        self.init_status.configure(text=f"Owner identity verified: {email}", text_color=COLORS['success'])

    def _open_existing_vault(self):
        path = filedialog.askdirectory(title="Select folder containing vault.enc")
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
                messagebox.showerror("Vault Error", f"No valid cryptographic vault found in {path}")
                set_base_dir(Path(__file__).parent.resolve())

    def _browse_folder(self):
        path = filedialog.askdirectory(title="Select directory to pack into vault")
        if path:
            self._selected_folder = path
            name = Path(path).name
            self.folder_label.configure(text=f"{name}/ ({path})", text_color=COLORS['text'])

    def _do_init(self):
        api_url = get_api_url()
        email   = getattr(self, '_init_owner_email', None)
        label   = self.init_label.get().strip() or 'Secure Storage Vault'
        folder  = self._selected_folder

        if not email:
            self.init_status.configure(text="Please click 'Continue with Google' to verify owner identity.", text_color=COLORS['warning'])
            self._launch_init_google_auth()
            return
        if not folder or not Path(folder).is_dir():
            self.init_status.configure(text="Please select a valid source directory to encrypt.", text_color=COLORS['danger'])
            return

        self.init_status.configure(text="Registering storage unit with server...", text_color=COLORS['warning'])
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
                    timeout=12
                )
                if r.status_code not in (200, 201):
                    err_msg = r.json().get('error', r.text[:80]) if r.headers.get('content-type', '').startswith('application/json') else r.text[:80]
                    self.after(0, lambda: self.init_status.configure(
                        text=f"Registration failed: {err_msg}",
                        text_color=COLORS['danger']))
                    return

                data          = r.json()
                drive_id      = data['drive_id']
                cloud_key_hex = data['cloud_key_share']

                k_local = ce.generate_local_key()

                config = {
                    'drive_id':    drive_id,
                    'label':       label,
                    'api_url':     api_url,
                    'owner_email': email,
                    'created_at':  int(time.time()),
                    'version':     3
                }

                self.after(0, lambda: self.init_status.configure(
                    text="Encrypting files into encapsulated vault container...",
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

                for loose_file in (CONFIG_FILE, LOCAL_KEY_FILE):
                    try:
                        if loose_file.exists():
                            loose_file.unlink()
                    except Exception:
                        pass

                if self.wipe_var.get():
                    def wipe_cb(current, total, filename):
                        self.after(0, lambda: self.init_status.configure(
                            text=f"Zeroing source files [{current}/{total}]...", text_color=COLORS['warning']))

                    self.after(0, lambda: self.init_status.configure(
                        text="Securely erasing plaintext files...", text_color=COLORS['warning']))

                    encrypted_file_list = stats.get('encrypted_files')
                    wiped = ce.secure_wipe_source_files(
                        Path(folder),
                        files_to_wipe=encrypted_file_list,
                        progress_callback=wipe_cb
                    )
                    logger.info(f"Securely erased {wiped} source files from disk.")

                # Initial auth (binds hardware lease)
                lm.authenticate(api_url, drive_id, fp, email, k_local, lease_path=LEASE_FILE, vault_path=VAULT_FILE)

                files_count = stats['files_encrypted']
                self.after(0, lambda: self._init_complete(files_count, drive_id))

            except Exception as e:
                logger.exception("Initialization failure")
                self.after(0, lambda: self.init_status.configure(
                    text=f"Initialization error: {e}", text_color=COLORS['danger']))

        threading.Thread(target=do_work, daemon=True).start()

    def _init_complete(self, files_count, drive_id):
        if hasattr(self, 'init_progress'):
            self.init_progress.set(1.0)
        self.init_status.configure(
            text=f"Vault initialized successfully. Encrypted {files_count} files.",
            text_color=COLORS['success'])
        self.after(1200, self._show_unlock_screen)

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
    # View 2: Vault Authentication Screen
    # ──────────────────────────────────────────────────────────────────────

    def _show_unlock_screen(self):
        self._clear_window()
        config = load_config()

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=48, pady=28)

        # Header Section
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.pack(pady=(0, 16), anchor="w")

        ctk.CTkLabel(header_box, text="VAULT ACCESS GATE",
                     font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                     text_color=COLORS['accent']).pack(anchor="w")

        drive_label = config.get('label', 'Storage Vault') if config else 'Storage Vault'
        ctk.CTkLabel(header_box, text=drive_label,
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=COLORS['text']).pack(anchor="w", pady=(2, 2))
        ctk.CTkLabel(header_box, text="Authenticate host identity or request out-of-band authorization",
                     font=ctk.CTkFont(size=12),
                     text_color=COLORS['text_dim']).pack(anchor="w")

        # Main Authentication Panel
        card = ctk.CTkFrame(frame, fg_color=COLORS['bg_card'], corner_radius=10,
                            border_width=1, border_color=COLORS['border'])
        card.pack(fill="x", pady=(0, 14))

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=24, pady=20)

        # Host Hardware Identity Inspection Card
        fp_hash = fp_module.generate_fingerprint()
        self._current_fingerprint = fp_hash
        comps = fp_module.get_hardware_components()

        fp_panel = ctk.CTkFrame(inner, fg_color=COLORS['bg_input'], corner_radius=6,
                                border_width=1, border_color=COLORS['border_subtle'])
        fp_panel.pack(fill="x", pady=(0, 14))

        fp_inner = ctk.CTkFrame(fp_panel, fg_color="transparent")
        fp_inner.pack(fill="x", padx=14, pady=12)

        fp_head = ctk.CTkFrame(fp_inner, fg_color="transparent")
        fp_head.pack(fill="x")
        ctk.CTkLabel(fp_head, text="HOST HARDWARE FINGERPRINT",
                     font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                     text_color=COLORS['text_dim']).pack(side="left")

        # Copy Hash Button
        def copy_fp():
            self.clipboard_clear()
            self.clipboard_append(fp_hash)
            self.unlock_status.configure(text="Hardware fingerprint copied to clipboard.", text_color=COLORS['text_dim'])

        ctk.CTkButton(fp_head, text="Copy", width=48, height=20,
                      font=ctk.CTkFont(size=10),
                      fg_color=COLORS['bg_card'], hover_color=COLORS['bg_hover'],
                      border_width=1, border_color=COLORS['border'],
                      text_color=COLORS['text_dim'], corner_radius=3,
                      command=copy_fp).pack(side="right")

        formatted_fp = f"{fp_hash[:16]}  {fp_hash[16:32]}  {fp_hash[32:48]}  {fp_hash[48:]}"
        ctk.CTkLabel(fp_inner, text=formatted_fp,
                     font=ctk.CTkFont(family="Consolas", size=11),
                     text_color=COLORS['info']).pack(anchor="w", pady=(4, 2))

        sys_spec = f"Host: {comps.get('platform','')} {comps.get('os_arch','')} | Node: {comps.get('hostname','')}"
        ctk.CTkLabel(fp_inner, text=sys_spec,
                     font=ctk.CTkFont(size=11),
                     text_color=COLORS['text_muted']).pack(anchor="w")

        # Container & Verification State
        meta = ce.inspect_vault_header(VAULT_FILE)
        v_size_mb = (meta.get('vault_size', 0) / (1024 * 1024)) if (meta and meta.get('valid')) else 0
        container_spec = f"Encapsulated Container: {v_size_mb:.2f} MB" if meta and meta.get('valid') else "Container: Ready"

        status_bar = ctk.CTkFrame(inner, fg_color="transparent")
        status_bar.pack(fill="x", pady=(0, 14))

        ctk.CTkLabel(status_bar, text=container_spec,
                     font=ctk.CTkFont(size=11),
                     text_color=COLORS['text_dim']).pack(side="left")

        ctk.CTkLabel(status_bar, text="Hardware Mismatch — Verification Required",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=COLORS['warning']).pack(side="right")

        # Google Sign-In Action (No manual email entry)
        self.btn_gate_google = ctk.CTkButton(
            inner, text="  Continue with Google", height=42,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#ffffff", hover_color="#f1f5f9",
            text_color="#1f2937", corner_radius=6,
            command=self._launch_gate_google_auth
        )
        self.btn_gate_google.pack(fill="x", pady=(4, 0))

        # Message / Status Feedback
        self.unlock_status = ctk.CTkLabel(frame, text="",
                                          font=ctk.CTkFont(size=12),
                                          text_color=COLORS['text_dim'])
        self.unlock_status.pack(pady=(0, 6))

        # Bottom Actions Bar
        bottom_row = ctk.CTkFrame(frame, fg_color="transparent")
        bottom_row.pack(fill="x", pady=(4, 0))

        ctk.CTkButton(bottom_row, text="Re-initialize", height=28,
                      font=ctk.CTkFont(size=11),
                      fg_color="transparent", border_width=1,
                      border_color=COLORS['border'], hover_color=COLORS['bg_card'],
                      text_color=COLORS['text_dim'], corner_radius=4,
                      command=self._confirm_reinitialize).pack(side="left")

        ctk.CTkButton(bottom_row, text="Change Working Vault...", height=28,
                      font=ctk.CTkFont(size=11),
                      fg_color="transparent", border_width=1,
                      border_color=COLORS['border'], hover_color=COLORS['bg_card'],
                      text_color=COLORS['text_dim'], corner_radius=4,
                      command=self._open_existing_vault).pack(side="right")

    def _confirm_reinitialize(self):
        if messagebox.askyesno("Re-initialize Vault", "Are you sure you want to re-initialize this drive?\n\nExisting encrypted vault data and temporary session files will be replaced."):
            if self.session.get('unlocked'):
                working_dir = self.session.get('working_dir')
                if working_dir and Path(working_dir).exists():
                    ce.secure_wipe_temp(Path(working_dir))
                self.session['unlocked'] = False
            if self._timer_id:
                try:
                    self.after_cancel(self._timer_id)
                except Exception:
                    pass
                self._timer_id = None
            self._show_init_screen()

    def _launch_gate_google_auth(self):
        config = load_config()
        if not config:
            self.unlock_status.configure(text="Vault configuration missing or corrupted.", text_color=COLORS['danger'])
            return

        api_url = get_api_url(config)
        import secrets
        session_id = f"gate_{secrets.token_hex(8)}"
        auth_url = f"{api_url.rstrip('/')}/auth/google?session_id={session_id}"
        webbrowser.open(auth_url)

        self.btn_gate_google.configure(state="disabled", text="  Awaiting Google Sign-In in Browser...")
        self.unlock_status.configure(text="Complete Google sign-in in your browser window...", text_color=COLORS['warning'])

        def poll_google():
            import requests
            start_t = time.time()
            while time.time() - start_t < 180:
                try:
                    r = requests.get(f"{api_url.rstrip('/')}/api/auth/google/check-session?session_id={session_id}", timeout=5)
                    if r.ok:
                        data = r.json()
                        if data.get('authenticated') and data.get('email'):
                            verified_email = data['email']
                            self.after(0, lambda e=verified_email: self._on_gate_google_verified(e))
                            return
                except Exception:
                    pass
                time.sleep(1)
            self.after(0, self._on_gate_google_timeout)

        threading.Thread(target=poll_google, daemon=True).start()

    def _on_gate_google_verified(self, email: str):
        self._focus_window()
        self.btn_gate_google.configure(text=f"  ✓ Verified: {email}", state="disabled")
        self.unlock_status.configure(text=f"Verified as {email}. Checking access permissions...", text_color=COLORS['info'])
        self._do_unlock_with_email(email)

    def _on_gate_google_timeout(self):
        if hasattr(self, 'btn_gate_google') and self.btn_gate_google.winfo_exists():
            self.btn_gate_google.configure(state="normal", text="  Continue with Google")
        if hasattr(self, 'unlock_status') and self.unlock_status.winfo_exists():
            self.unlock_status.configure(text="Authentication timed out. Click to try again.", text_color=COLORS['danger'])

    def _do_unlock_with_email(self, email: str):
        config = load_config()
        if not config:
            self._on_unlock_failed("Vault configuration missing or corrupted.")
            return

        def do_auth():
            try:
                k_local = load_local_key()
                if not k_local:
                    self.after(0, lambda: self._on_unlock_failed("Local key share missing from container header."))
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
                    self.after(0, lambda: self._on_unlock_failed("REMOTE KILLSWITCH ACTIVE: Storage access permanently revoked."))

                elif result == 'DENIED':
                    self.after(0, lambda: self._on_unlock_failed(f"Access denied: {msg}"))

                else:
                    self.after(0, lambda: self._on_unlock_failed(msg))

            except Exception as e:
                logger.exception("Unlock exception")
                self.after(0, lambda: self._on_unlock_failed(f"Connection failure: {e}"))

        threading.Thread(target=do_auth, daemon=True).start()

    def _on_unlock_failed(self, msg: str):
        if hasattr(self, 'btn_gate_google') and self.btn_gate_google.winfo_exists():
            self.btn_gate_google.configure(state="normal", text="  Continue with Google")
        if hasattr(self, 'unlock_status') and self.unlock_status.winfo_exists():
            self.unlock_status.configure(text=msg, text_color=COLORS['danger'])

    def _load_vault_workspace(self, k_local, cloud_key_hex, mode, msg):
        def _set_status(txt, color):
            if hasattr(self, 'wait_status') and self.wait_status.winfo_exists():
                self.wait_status.configure(text=txt, text_color=color)
            elif hasattr(self, 'unlock_status') and self.unlock_status.winfo_exists():
                self.unlock_status.configure(text=txt, text_color=color)

        _set_status(f"Decrypting tail manifest ({mode})...", COLORS['warning'])
        self.update_idletasks()

        def do_load():
            try:
                k_cloud = ce.hex_to_key_bytes(cloud_key_hex)
                manifest = ce.read_vault_manifest(VAULT_FILE, k_local, k_cloud)

                # Encapsulate legacy files if needed
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
                        logger.info("Migrated vault to encapsulated v3 format.")
                    except Exception as me:
                        logger.warning(f"Migration bypassed: {me}")

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
                logger.exception("Manifest decryption failure")
                self.after(0, lambda: _set_status(f"Decryption failed: {e}", COLORS['danger']))
                if hasattr(self, 'startup_status') and self.startup_status.winfo_exists():
                    self.after(1500, self._show_unlock_screen)

        threading.Thread(target=do_load, daemon=True).start()

    # ──────────────────────────────────────────────────────────────────────
    # View 3: Out-of-Band Authorization Gate (Mobile QR + Web Portal)
    # ──────────────────────────────────────────────────────────────────────

    def _show_waiting_screen(self, request_id, config, k_local, fingerprint, email):
        self._clear_window()
        self._poll_stop.clear()

        api_url     = get_api_url(config)
        approve_url = f"{api_url.rstrip('/')}/approve?req={request_id}"
        google_url  = f"{api_url.rstrip('/')}/auth/google?req={request_id}&email={email}"

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=40, pady=24)

        # Header Section
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.pack(pady=(0, 14), anchor="w")

        ctk.CTkLabel(header_box, text="OUT-OF-BAND AUTHORIZATION",
                     font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                     text_color=COLORS['warning']).pack(anchor="w")
        ctk.CTkLabel(header_box, text="Authorization Required",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color=COLORS['text']).pack(anchor="w", pady=(2, 2))
        ctk.CTkLabel(header_box, text="Drive owner confirmation needed to release cryptographic key share",
                     font=ctk.CTkFont(size=12),
                     text_color=COLORS['text_dim']).pack(anchor="w")

        # Split Dual-Panel Layout
        dual_card = ctk.CTkFrame(frame, fg_color="transparent")
        dual_card.pack(fill="x", pady=(0, 14))

        # ─── LEFT: Mobile Camera QR Channel ───
        left_card = ctk.CTkFrame(dual_card, fg_color=COLORS['bg_card'], corner_radius=10,
                                 border_width=1, border_color=COLORS['border'])
        left_card.pack(side="left", fill="both", expand=True, padx=(0, 8))

        left_inner = ctk.CTkFrame(left_card, fg_color="transparent")
        left_inner.pack(fill="both", expand=True, padx=20, pady=18)

        ctk.CTkLabel(left_inner, text="Method A: Mobile Device",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=COLORS['text']).pack(anchor="w")
        ctk.CTkLabel(left_inner, text="Scan with mobile phone camera",
                     font=ctk.CTkFont(size=11),
                     text_color=COLORS['text_muted']).pack(anchor="w", pady=(0, 10))

        # Verification Code Display
        code_box = ctk.CTkFrame(left_inner, fg_color=COLORS['bg_input'], corner_radius=6,
                                border_width=1, border_color=COLORS['border_subtle'])
        code_box.pack(fill="x", pady=(0, 10))
        cb_inner = ctk.CTkFrame(code_box, fg_color="transparent")
        cb_inner.pack(padx=12, pady=6)

        ctk.CTkLabel(cb_inner, text="CODE:",
                     font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                     text_color=COLORS['text_dim']).pack(side="left")
        ctk.CTkLabel(cb_inner, text=f" {request_id}",
                     font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
                     text_color=COLORS['warning']).pack(side="left")

        # QR Bed
        self._qr_container = ctk.CTkFrame(left_inner, fg_color=COLORS['bg_card_alt'], corner_radius=8,
                                          border_width=1, border_color=COLORS['border'])
        self._qr_container.pack(fill="x", pady=(0, 10))

        self._qr_image_label = None
        self._qr_shown = False

        try:
            qr_img = generate_qr_ctk_image(approve_url, size=140)
            self._qr_image_label = ctk.CTkLabel(self._qr_container, image=qr_img, text="")
            self._qr_image_label.pack(padx=8, pady=8)
            self._qr_shown = True
        except Exception as e:
            logger.warning(f"QR init error: {e}")

        self._qr_toggle_btn = ctk.CTkButton(
            left_inner, text="Hide QR Code" if self._qr_shown else "Show QR Code", height=30,
            font=ctk.CTkFont(size=11),
            fg_color=COLORS['bg_input'], hover_color=COLORS['bg_hover'],
            border_width=1, border_color=COLORS['border'],
            text_color=COLORS['text'], corner_radius=4,
            command=lambda: self._toggle_qr_code(approve_url)
        )
        self._qr_toggle_btn.pack(fill="x")

        # ─── RIGHT: Web Portal Channel ───
        right_card = ctk.CTkFrame(dual_card, fg_color=COLORS['bg_card'], corner_radius=10,
                                  border_width=1, border_color=COLORS['border'])
        right_card.pack(side="right", fill="both", expand=True, padx=(8, 0))

        right_inner = ctk.CTkFrame(right_card, fg_color="transparent")
        right_inner.pack(fill="both", expand=True, padx=20, pady=18)

        ctk.CTkLabel(right_inner, text="Method B: Web Portal",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=COLORS['text']).pack(anchor="w")
        ctk.CTkLabel(right_inner, text="Authorize in desktop browser",
                     font=ctk.CTkFont(size=11),
                     text_color=COLORS['text_muted']).pack(anchor="w", pady=(0, 14))

        ctk.CTkButton(
            right_inner, text="Sign In with Google to Authorize", height=38,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=COLORS['accent'], hover_color=COLORS['accent_hover'],
            text_color="#ffffff", corner_radius=6,
            command=lambda: webbrowser.open(google_url)
        ).pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(right_inner,
                     text="Opens your default browser. Once confirmed by the owner, this application unlocks automatically.",
                     font=ctk.CTkFont(size=11),
                     text_color=COLORS['text_dim'],
                     wraplength=270).pack(pady=(0, 12))

        ctk.CTkButton(
            right_inner, text="Open Direct Approval Link", height=30,
            font=ctk.CTkFont(size=11),
            fg_color=COLORS['bg_input'], hover_color=COLORS['bg_hover'],
            border_width=1, border_color=COLORS['border'],
            text_color=COLORS['text'], corner_radius=4,
            command=lambda: webbrowser.open(approve_url)
        ).pack(fill="x")

        # ─── Bottom Status & Polling ───
        status_card = ctk.CTkFrame(frame, fg_color=COLORS['bg_card'], corner_radius=8,
                                   border_width=1, border_color=COLORS['border'])
        status_card.pack(fill="x", pady=(0, 12))

        sc_inner = ctk.CTkFrame(status_card, fg_color="transparent")
        sc_inner.pack(fill="x", padx=16, pady=10)

        self.wait_status = ctk.CTkLabel(sc_inner, text="Listening for authorization signal (polling every 2s)...",
                                        font=ctk.CTkFont(size=12),
                                        text_color=COLORS['text_dim'])
        self.wait_status.pack(side="left")

        self.wait_progress = ctk.CTkProgressBar(sc_inner, mode="indeterminate",
                                                 width=180, height=3,
                                                 progress_color=COLORS['accent'])
        self.wait_progress.pack(side="right", padx=(8, 0))
        self.wait_progress.start()

        # Cancellation
        ctk.CTkButton(frame, text="Cancel Request", height=30, width=130,
                      fg_color="transparent", border_width=1,
                      border_color=COLORS['border'], hover_color=COLORS['bg_card'],
                      text_color=COLORS['text_dim'], corner_radius=4,
                      command=self._cancel_wait).pack()

        # 2-second background poll thread
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
                    logger.warning(f"Polling warning: {e}")

                self._poll_stop.wait(2)

        self._poll_thread = threading.Thread(target=poll_loop, daemon=True)
        self._poll_thread.start()

    def _toggle_qr_code(self, approve_url: str):
        if not self._qr_shown:
            try:
                qr_img = generate_qr_ctk_image(approve_url, size=140)
                if not self._qr_image_label:
                    self._qr_image_label = ctk.CTkLabel(self._qr_container, image=qr_img, text="")
                    self._qr_image_label.pack(padx=8, pady=8)
                else:
                    self._qr_image_label.configure(image=qr_img)
                    self._qr_image_label.pack(padx=8, pady=8)

                self._qr_toggle_btn.configure(text="Hide QR Code")
                self._qr_shown = True
            except Exception as e:
                logger.warning(f"QR render exception: {e}")
        else:
            if self._qr_image_label:
                self._qr_image_label.pack_forget()
            self._qr_toggle_btn.configure(text="Show QR Code")
            self._qr_shown = False

    def _cancel_wait(self):
        self._poll_stop.set()
        self._show_unlock_screen()

    def _on_approval_granted(self, k_local, cloud_key_hex, msg):
        self._focus_window()
        self.wait_progress.stop()
        self.wait_status.configure(text=f"Authorization granted: {msg}", text_color=COLORS['success'])
        self.update_idletasks()
        self.after(400, lambda: self._load_vault_workspace(k_local, cloud_key_hex, "Authorized", msg))

    def _on_approval_denied(self):
        self._focus_window()
        self.wait_progress.stop()
        self.wait_status.configure(text="Authorization rejected by drive owner.", text_color=COLORS['danger'])
        self.after(1800, self._show_unlock_screen)

    # ──────────────────────────────────────────────────────────────────────
    # View 4: Vault File Workspace (Engineered Explorer)
    # ──────────────────────────────────────────────────────────────────────

    def _show_workspace_screen(self):
        self._clear_window()
        config = load_config()
        manifest = self.session.get('manifest', {})
        raw_files = manifest.get('files', [])
        files = [f for f in raw_files if not ce.is_system_file(f.get('path', ''))]

        # Top Control Bar
        top = ctk.CTkFrame(self, fg_color=COLORS['bg_card'], height=52, corner_radius=0,
                           border_width=1, border_color=COLORS['border'])
        top.pack(fill="x")
        top.pack_propagate(False)

        top_inner = ctk.CTkFrame(top, fg_color="transparent")
        top_inner.pack(fill="both", expand=True, padx=16)

        vault_title = config.get('label', 'Storage Vault') if config else 'Storage Vault'
        ctk.CTkLabel(top_inner, text=vault_title,
                     font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=COLORS['text']).pack(side="left")

        # Session Pill
        status_frame = ctk.CTkFrame(top_inner, fg_color=COLORS['success_bg'], corner_radius=4,
                                   border_width=1, border_color=COLORS['border_subtle'])
        status_frame.pack(side="left", padx=(14, 0))
        sf_inner = ctk.CTkFrame(status_frame, fg_color="transparent")
        sf_inner.pack(padx=8, pady=2)

        self.ws_status_dot = ctk.CTkLabel(sf_inner, text="●",
                                          font=ctk.CTkFont(size=9),
                                          text_color=COLORS['success'])
        self.ws_status_dot.pack(side="left", padx=(0, 4))

        self.ws_status_text = ctk.CTkLabel(sf_inner, text="SESSION ACTIVE",
                                           font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                                           text_color=COLORS['success'])
        self.ws_status_text.pack(side="left")

        # Timer
        self.ws_timer = ctk.CTkLabel(top_inner, text="Session: 00:00:00",
                                     font=ctk.CTkFont(family="Consolas", size=11),
                                     text_color=COLORS['text_dim'])
        self.ws_timer.pack(side="right", padx=(0, 10))

        # Lock Command Actions
        ctk.CTkButton(top_inner, text="Save & Lock Vault", height=32, width=130,
                      font=ctk.CTkFont(size=11, weight="bold"),
                      fg_color=COLORS['accent'], hover_color=COLORS['accent_hover'],
                      corner_radius=4,
                      command=self._do_lock_and_save).pack(side="right", padx=(6, 0))

        ctk.CTkButton(top_inner, text="Discard & Exit", height=32, width=110,
                      font=ctk.CTkFont(size=11),
                      fg_color=COLORS['danger_bg'], hover_color=COLORS['danger_hover'],
                      border_width=1, border_color=COLORS['danger'],
                      text_color=COLORS['danger'], corner_radius=4,
                      command=self._do_lock_no_save).pack(side="right", padx=(6, 0))

        # Main Workspace Container
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=16, pady=12)

        browser_frame = ctk.CTkFrame(main, fg_color=COLORS['bg_card'], corner_radius=8,
                                    border_width=1, border_color=COLORS['border'])
        browser_frame.pack(fill="both", expand=True)

        # File List Toolbar
        browser_header = ctk.CTkFrame(browser_frame, fg_color="transparent")
        browser_header.pack(fill="x", padx=16, pady=(12, 8))

        ctk.CTkLabel(browser_header, text=f"Encrypted File Manifest ({len(files)} items)",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['text_dim']).pack(side="left")

        btn_bar = ctk.CTkFrame(browser_header, fg_color="transparent")
        btn_bar.pack(side="right")

        ctk.CTkButton(btn_bar, text="Open Selected Item", height=28, width=130,
                      font=ctk.CTkFont(size=11),
                      fg_color=COLORS['bg_input'], hover_color=COLORS['bg_hover'],
                      border_width=1, border_color=COLORS['border'],
                      text_color=COLORS['text'], corner_radius=4,
                      command=self._open_selected_item).pack(side="left", padx=(0, 6))

        ctk.CTkButton(btn_bar, text="Explore in File Manager", height=28, width=150,
                      font=ctk.CTkFont(size=11, weight="bold"),
                      fg_color=COLORS['bg_input'], hover_color=COLORS['bg_hover'],
                      border_width=1, border_color=COLORS['border'],
                      text_color=COLORS['text'], corner_radius=4,
                      command=self._open_in_explorer).pack(side="left")

        # TTK Treeview Styling (Engineered Dark Theme)
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
                        borderwidth=1,
                        relief="flat",
                        font=('Inter', 10, 'bold'))
        style.map("Vault.Treeview",
                  background=[('selected', COLORS['accent'])],
                  foreground=[('selected', '#ffffff')])

        tree_container = ctk.CTkFrame(browser_frame, fg_color="transparent")
        tree_container.pack(fill="both", expand=True, padx=16, pady=(4, 12))

        self.file_tree = ttk.Treeview(tree_container, style="Vault.Treeview",
                                      columns=("size", "type", "modified"), show="tree headings",
                                      selectmode="browse")
        self.file_tree.heading("#0", text="Path / Item", anchor="w")
        self.file_tree.heading("size", text="Size", anchor="e")
        self.file_tree.heading("type", text="Type", anchor="w")
        self.file_tree.heading("modified", text="Timestamp", anchor="w")

        self.file_tree.column("#0", width=400, minwidth=260)
        self.file_tree.column("size", width=90, anchor="e")
        self.file_tree.column("type", width=70, anchor="w")
        self.file_tree.column("modified", width=140, anchor="w")

        scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=scrollbar.set)

        self.file_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Ergonomic Interactions: double click or enter key
        self.file_tree.bind("<Double-1>", lambda event: self._open_selected_item())
        self.file_tree.bind("<Return>", lambda event: self._open_selected_item())

        self._populate_manifest_tree(files)

        # Bottom Status Shelf
        bottom = ctk.CTkFrame(self, fg_color=COLORS['bg_card'], height=32, corner_radius=0,
                              border_width=1, border_color=COLORS['border'])
        bottom.pack(fill="x")
        bottom.pack_propagate(False)

        bottom_inner = ctk.CTkFrame(bottom, fg_color="transparent")
        bottom_inner.pack(fill="both", expand=True, padx=16)

        ctk.CTkButton(bottom_inner, text="Re-initialize Drive", height=22, width=120,
                      font=ctk.CTkFont(size=10),
                      fg_color="transparent", border_width=1,
                      border_color=COLORS['border'], hover_color=COLORS['bg_card_alt'],
                      text_color=COLORS['text_dim'], corner_radius=4,
                      command=self._confirm_reinitialize).pack(side="left", padx=(0, 12))

        drive_id_short = config.get('drive_id', '?')[:8] if config else '?'
        ctk.CTkLabel(bottom_inner, text=f"Drive ID: {drive_id_short}...",
                     font=ctk.CTkFont(family="Consolas", size=10),
                     text_color=COLORS['text_muted']).pack(side="left")

        self.ws_status_footer = ctk.CTkLabel(bottom_inner,
                                             text="On-demand session ready — modifications are incrementally packaged upon lock",
                                             font=ctk.CTkFont(size=10),
                                             text_color=COLORS['text_muted'])
        self.ws_status_footer.pack(side="right")

        self._start_timer()

    def _populate_manifest_tree(self, file_entries: List[dict]):
        self.file_tree.delete(*self.file_tree.get_children())
        nodes = {'': ''}
        self._tree_item_map = {}

        file_entries = [e for e in file_entries if not ce.is_system_file(e.get('path', ''))]

        for entry in sorted(file_entries, key=lambda e: e['path']):
            path_parts = entry['path'].split('/')
            curr_path = ''
            parent_id = ''

            for folder in path_parts[:-1]:
                curr_path = f"{curr_path}/{folder}" if curr_path else folder
                if curr_path not in nodes:
                    node_id = self.file_tree.insert(parent_id, 'end',
                                                     text=f"▸ {folder}/",
                                                     values=('', 'DIR', ''),
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
                '.jpg': 'Image', '.jpeg': 'Image', '.docx': 'Document',
                '.xlsx': 'Spreadsheet', '.csv': 'Data',
            }
            file_type = type_map.get(ext, ext[1:].upper() if ext else 'File')

            mtime = entry.get('modified', 0)
            mtime_str = time.strftime('%Y-%m-%d %H:%M', time.localtime(mtime)) if mtime else '-'

            item_id = self.file_tree.insert(parent_id, 'end',
                                            text=f"  {filename}",
                                            values=(size_str, file_type, mtime_str))
            self._tree_item_map[item_id] = {'is_dir': False, 'path': entry['path'], 'entry': entry}

    def _open_selected_item(self):
        """Open single file or browse directory based on selection."""
        selected = self.file_tree.selection()
        if not selected:
            self._open_all_in_explorer()
            return

        item_id = selected[0]
        meta = self._tree_item_map.get(item_id)
        if not meta:
            return

        if meta['is_dir']:
            self._open_directory_path(meta['path'])
        else:
            self._open_single_file(meta['entry'])

    def _open_in_explorer(self):
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
            parent_dir = str(Path(meta['path']).parent).replace('\\', '/')
            if parent_dir and parent_dir != '.':
                self._open_directory_path(parent_dir)
            else:
                self._open_all_in_explorer()

    _open_selected_folder = _open_in_explorer

    def _open_single_file(self, entry: dict):
        k_local = self.session.get('k_local')
        cloud_key_hex = self.session.get('cloud_key_share')
        work_dir = self.session.get('working_dir')

        if not k_local or not cloud_key_hex or not work_dir:
            messagebox.showerror("Session Error", "Cryptographic key material missing.")
            return

        try:
            k_cloud = ce.hex_to_key_bytes(cloud_key_hex)
            rel_path = entry['path']
            out_path = work_dir / rel_path

            if not out_path.exists():
                plaintext = ce.decrypt_single_file(VAULT_FILE, k_local, k_cloud, entry)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(plaintext)
                try:
                    os.utime(out_path, (entry.get('modified', time.time()), entry.get('modified', time.time())))
                except Exception:
                    pass

            self.session['opened_files'][rel_path] = out_path

            if sys.platform == 'win32':
                os.startfile(str(out_path))
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', str(out_path)])
            else:
                subprocess.Popen(['xdg-open', str(out_path)])

            self.ws_status_footer.configure(text=f"Active File: {rel_path} (edits recorded on Lock)")
            self.ws_status_text.configure(text="WORKSPACE ACTIVE", text_color=COLORS['warning'])

        except Exception as e:
            logger.exception("Single file decrypt error")
            messagebox.showerror("Decryption Error", f"Could not decrypt item: {e}")

    def _open_directory_path(self, dir_prefix: str):
        k_local = self.session.get('k_local')
        cloud_key_hex = self.session.get('cloud_key_share')
        manifest = self.session.get('manifest')
        work_dir = self.session.get('working_dir')

        if not k_local or not cloud_key_hex or not manifest or not work_dir:
            return

        self.ws_status_text.configure(text="DECRYPTING DIR...", text_color=COLORS['warning'])
        self.update_idletasks()

        def do_extract():
            try:
                k_cloud = ce.hex_to_key_bytes(cloud_key_hex)
                ce.decrypt_directory_to_working_dir(
                    VAULT_FILE, k_local, k_cloud, manifest,
                    dir_prefix=dir_prefix, target_dir=work_dir
                )

                clean_p = dir_prefix.strip('/')
                for f in manifest.get('files', []):
                    if f['path'] == clean_p or f['path'].startswith(clean_p + '/'):
                        self.session['opened_files'][f['path']] = work_dir / f['path']

                target_folder = work_dir / clean_p
                target_folder.mkdir(parents=True, exist_ok=True)

                self.after(0, lambda: self._on_directory_ready(target_folder, clean_p))

            except Exception as e:
                logger.exception("Directory decrypt failure")
                self.after(0, lambda: messagebox.showerror("Decryption Error", f"Could not open directory: {e}"))
                self.after(0, lambda: self.ws_status_text.configure(text="SESSION ACTIVE", text_color=COLORS['success']))

        threading.Thread(target=do_extract, daemon=True).start()

    def _on_directory_ready(self, target_folder: Path, dir_name: str):
        self.ws_status_text.configure(text="WORKSPACE ACTIVE", text_color=COLORS['warning'])
        self.ws_status_footer.configure(text=f"Opened directory {dir_name}/ in system file manager")
        self._open_folder(target_folder)

    def _open_all_in_explorer(self):
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
                self.after(0, lambda: messagebox.showerror("Decryption Error", f"Extraction failed: {e}"))
                self.after(0, lambda: self.ws_status_text.configure(text="SESSION ACTIVE", text_color=COLORS['success']))

        threading.Thread(target=do_bulk, daemon=True).start()

    def _on_bulk_ready(self, work_dir: Path):
        self.ws_status_text.configure(text="WORKSPACE ACTIVE (FULL)", text_color=COLORS['warning'])
        self.ws_status_footer.configure(text="Full vault extracted to temporary session directory")
        self._open_folder(work_dir)

    def _do_lock_and_save(self):
        if not self.session.get('unlocked'):
            return

        working_dir = self.session.get('working_dir')
        manifest = self.session.get('manifest')
        k_local = self.session.get('k_local')
        cloud_key_hex = self.session.get('cloud_key_share')
        is_full = self.session.get('is_full_extract', False)

        self.ws_status_text.configure(text="PACKAGING & LOCKING...", text_color=COLORS['warning'])
        self.update_idletasks()

        def do_save():
            try:
                k_cloud = ce.hex_to_key_bytes(cloud_key_hex)

                if working_dir and Path(working_dir).exists() and manifest:
                    new_manifest = ce.update_vault_on_lock(
                        VAULT_FILE, k_local, k_cloud, Path(working_dir), manifest,
                        allow_partial=(not is_full)
                    )
                    ce.secure_wipe_temp(Path(working_dir))
                    logger.info("Vault package updated and temporary files wiped.")

                self.after(0, self._lock_cleanup_and_exit)

            except Exception as e:
                logger.exception("Save and lock failure")
                self.after(0, lambda: messagebox.showerror("Save Error", f"Could not package vault changes: {e}"))
                self.after(0, lambda: self.ws_status_text.configure(text="SESSION ACTIVE", text_color=COLORS['success']))

        threading.Thread(target=do_save, daemon=True).start()

    def _do_lock_no_save(self):
        if not self.session.get('unlocked'):
            return

        if not messagebox.askyesno("Discard & Exit",
                                    "Discard all working file modifications, securely erase temporary session data, and exit?"):
            return

        self.ws_status_text.configure(text="WIPING SESSION...", text_color=COLORS['danger'])
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
            try:
                self.after_cancel(self._timer_id)
            except Exception:
                pass
            self._timer_id = None
        self._poll_stop.set()
        try:
            self.destroy()
        except Exception:
            pass
        sys.exit(0)

    def _start_timer(self):
        if not self.session.get('unlocked'):
            return

        elapsed = int(time.time() - self.session['unlock_time'])
        mins = elapsed // 60
        secs = elapsed % 60
        hrs  = mins // 60
        mins = mins % 60

        timer_text = f"Session: {hrs:02d}:{mins:02d}:{secs:02d}"

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
            messagebox.showerror("Explorer Error", f"Could not launch file manager: {e}")

    # ──────────────────────────────────────────────────────────────────────
    # Lifecycle
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
            logger.info("Session files wiped on exit.")
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    if os.environ.get('USB_DEBUG', '').lower() in ('1', 'true', 'yes'):
        logging.getLogger().setLevel(logging.DEBUG)

    app = USBKillswitchApp()
    app.mainloop()
