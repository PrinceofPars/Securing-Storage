"""
gui.py — USB Killswitch v2 Desktop GUI Client
===============================================
Modern desktop application built with CustomTkinter.

Screens:
  1. Initialization — first-time drive setup wizard
  2. Unlock/Login — email + hardware fingerprint auth
  3. Waiting for Approval — live polling with spinner
  4. Vault Workspace — file browser + lease timer + lock button

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
from typing import Optional

# Fix Windows UTF-8 console
if sys.platform == 'win32' and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

import customtkinter as ctk

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
# Configuration
# ──────────────────────────────────────────────────────────────────────────────

# Detect PyInstaller frozen bundle vs normal script
if getattr(sys, 'frozen', False):
    # Running as .exe — use the directory where the .exe lives
    BASE_DIR = Path(sys.executable).parent.resolve()
else:
    BASE_DIR = Path(__file__).parent.resolve()

CONFIG_FILE    = BASE_DIR / 'config.json'
LOCAL_KEY_FILE = BASE_DIR / 'local_key.bin'
VAULT_FILE     = BASE_DIR / 'vault.enc'
LEASE_FILE     = BASE_DIR / 'lease.tok'
DEFAULT_API    = os.environ.get('USB_API_URL', 'http://localhost:3000')

def set_base_dir(new_path: Path):
    global BASE_DIR, CONFIG_FILE, LOCAL_KEY_FILE, VAULT_FILE, LEASE_FILE
    BASE_DIR       = new_path
    CONFIG_FILE    = BASE_DIR / 'config.json'
    LOCAL_KEY_FILE = BASE_DIR / 'local_key.bin'
    VAULT_FILE     = BASE_DIR / 'vault.enc'
    LEASE_FILE     = BASE_DIR / 'lease.tok'

# ──────────────────────────────────────────────────────────────────────────────
# Theme Configuration
# ──────────────────────────────────────────────────────────────────────────────

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Color palette
COLORS = {
    'bg':          '#0f1117',
    'bg_card':     '#1a1d28',
    'bg_input':    '#252836',
    'accent':      '#6366f1',
    'accent_hover':'#818cf8',
    'success':     '#10b981',
    'danger':      '#f43f5e',
    'warning':     '#f59e0b',
    'text':        '#f1f5f9',
    'text_dim':    '#94a3b8',
    'text_muted':  '#64748b',
    'border':      '#2d3043',
}


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def load_config() -> Optional[dict]:
    if not CONFIG_FILE.exists():
        return None
    try:
        return json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
    except Exception:
        return None

def save_config(config: dict):
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding='utf-8')


# ══════════════════════════════════════════════════════════════════════════════
# Main Application
# ══════════════════════════════════════════════════════════════════════════════

class USBKillswitchApp(ctk.CTk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        self.title("USB Killswitch v2")
        self.geometry("780x620")
        self.minsize(700, 560)
        self.configure(fg_color=COLORS['bg'])

        # Session state
        self.session = {
            'unlocked':        False,
            'temp_dir':        None,
            'cloud_key_share': None,
            'unlock_time':     None,
            'request_id':      None,
        }
        self._poll_thread = None
        self._poll_stop   = threading.Event()
        self._timer_id    = None

        # Determine initial screen
        config = load_config()
        if config and LOCAL_KEY_FILE.exists() and VAULT_FILE.exists():
            self._show_unlock_screen()
        else:
            self._show_init_screen()

        # Cleanup on close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ──────────────────────────────────────────────────────────────────────
    # Screen 1: Initialization Wizard
    # ──────────────────────────────────────────────────────────────────────

    def _show_init_screen(self):
        self._clear_window()
        self._selected_folder = None

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=40, pady=30)

        # Title
        ctk.CTkLabel(frame, text="USB Killswitch Setup",
                     font=ctk.CTkFont(size=26, weight="bold"),
                     text_color=COLORS['text']).pack(pady=(0, 4))
        ctk.CTkLabel(frame, text="Initialize your encrypted USB drive",
                     font=ctk.CTkFont(size=14),
                     text_color=COLORS['text_dim']).pack(pady=(0, 24))

        # Form card
        card = ctk.CTkFrame(frame, fg_color=COLORS['bg_card'], corner_radius=16)
        card.pack(fill="x", pady=(0, 16))

        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=24)

        # API URL
        ctk.CTkLabel(inner, text="Backend API URL",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['text_dim']).pack(anchor="w")
        self.init_api_url = ctk.CTkEntry(inner, placeholder_text="http://localhost:3000",
                                         height=38, fg_color=COLORS['bg_input'],
                                         border_color=COLORS['border'])
        self.init_api_url.pack(fill="x", pady=(4, 14))
        self.init_api_url.insert(0, DEFAULT_API)

        # Owner Email
        ctk.CTkLabel(inner, text="Owner Email",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['text_dim']).pack(anchor="w")
        self.init_email = ctk.CTkEntry(inner, placeholder_text="you@example.com",
                                       height=38, fg_color=COLORS['bg_input'],
                                       border_color=COLORS['border'])
        self.init_email.pack(fill="x", pady=(4, 14))

        # Admin Key
        ctk.CTkLabel(inner, text="Admin API Key",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['text_dim']).pack(anchor="w")
        self.init_admin_key = ctk.CTkEntry(inner, placeholder_text="Admin key",
                                           show="*", height=38,
                                           fg_color=COLORS['bg_input'],
                                           border_color=COLORS['border'])
        self.init_admin_key.pack(fill="x", pady=(4, 14))

        # Drive Label
        ctk.CTkLabel(inner, text="Drive Label",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['text_dim']).pack(anchor="w")
        self.init_label = ctk.CTkEntry(inner, placeholder_text="e.g. Work USB",
                                       height=38, fg_color=COLORS['bg_input'],
                                       border_color=COLORS['border'])
        self.init_label.pack(fill="x", pady=(4, 14))

        # Folder selection
        folder_row = ctk.CTkFrame(inner, fg_color="transparent")
        folder_row.pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(folder_row, text="Folder to Encrypt",
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
                      text_color=COLORS['text'],
                      command=self._browse_folder).pack(side="right")

        # Wipe checkbox
        self.wipe_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(folder_row, text="Securely wipe original files after encryption",
                        variable=self.wipe_var,
                        font=ctk.CTkFont(size=11), text_color=COLORS['danger'],
                        hover_color=COLORS['danger'], border_color=COLORS['border']).pack(anchor="w", pady=(8, 0))

        # Status label
        self.init_status = ctk.CTkLabel(frame, text="", text_color=COLORS['text_dim'],
                                        font=ctk.CTkFont(size=12))
        self.init_status.pack(pady=(0, 4))

        # Progress bar
        self.init_progress = ctk.CTkProgressBar(frame, width=400, height=8,
                                                 progress_color=COLORS['accent'],
                                                 fg_color=COLORS['bg_input'])
        self.init_progress.pack(pady=(0, 12))
        self.init_progress.set(0)

        # Initialize button
        ctk.CTkButton(frame, text="Initialize & Encrypt", height=44,
                      font=ctk.CTkFont(size=15, weight="bold"),
                      fg_color=COLORS['accent'],
                      hover_color=COLORS['accent_hover'],
                      command=self._do_init).pack(fill="x")

        # Open Existing button
        ctk.CTkButton(frame, text="Open Existing Vault...", height=32,
                      fg_color="transparent", border_width=1,
                      border_color=COLORS['border'], hover_color=COLORS['bg_card'],
                      text_color=COLORS['text_dim'],
                      command=self._open_existing_vault).pack(pady=(16, 0))

    def _open_existing_vault(self):
        path = filedialog.askdirectory(title="Select folder containing vault.enc and config.json")
        if path:
            set_base_dir(Path(path))
            config = load_config()
            if config and LOCAL_KEY_FILE.exists() and VAULT_FILE.exists():
                self._show_unlock_screen()
            else:
                messagebox.showerror("Error", f"No valid vault found in {path}")
                set_base_dir(Path(__file__).parent.resolve())

    def _browse_folder(self):
        path = filedialog.askdirectory(title="Select folder to encrypt into vault")
        if path:
            self._selected_folder = path
            name = Path(path).name
            self.folder_label.configure(text=f"  {name}/   ({path})", text_color=COLORS['text'])

    def _do_init(self):
        api_url   = self.init_api_url.get().strip()
        email     = self.init_email.get().strip()
        admin_key = self.init_admin_key.get().strip()
        label     = self.init_label.get().strip() or 'My USB Drive'
        folder    = self._selected_folder

        if not api_url or not email or not admin_key:
            self.init_status.configure(text="Please fill API URL, email, and admin key.",
                                       text_color=COLORS['danger'])
            return
        if not folder or not Path(folder).is_dir():
            self.init_status.configure(text="Please select a valid folder to encrypt.",
                                       text_color=COLORS['danger'])
            return

        self.init_status.configure(text="Registering drive with backend...",
                                   text_color=COLORS['warning'])
        self.update_idletasks()

        # Set output location to parent of selected folder
        target_dir = Path(folder).parent
        set_base_dir(target_dir)

        # Run in background thread
        def do_work():
            try:
                import requests
                r = requests.post(
                    f"{api_url.rstrip('/')}/api/register",
                    json={'label': label, 'owner_email': email},
                    headers={'X-Admin-Key': admin_key},
                    timeout=10
                )
                if r.status_code != 201:
                    self.after(0, lambda: self.init_status.configure(
                        text=f"Registration failed: {r.json().get('error', r.text[:80])}",
                        text_color=COLORS['danger']))
                    return

                data           = r.json()
                drive_id       = data['drive_id']
                cloud_key_hex  = data['cloud_key_share']

                # Generate local key
                k_local = ce.generate_local_key()
                ce.save_local_key(k_local, LOCAL_KEY_FILE)

                # Save config
                config = {
                    'drive_id':   drive_id,
                    'label':      label,
                    'api_url':    api_url,
                    'owner_email': email,
                    'created_at': int(time.time()),
                    'version':    2
                }
                save_config(config)

                # Update status
                self.after(0, lambda: self.init_status.configure(
                    text="Encrypting folder into vault.enc...",
                    text_color=COLORS['warning']))

                # Encrypt with progress callback
                def encrypt_cb(current, total, filename):
                    progress = current / total if total > 0 else 0
                    self.after(0, lambda p=progress, c=current, t=total, f=filename: self._update_encrypt_progress(p, c, t, f))

                k_cloud_bytes = ce.hex_to_key_bytes(cloud_key_hex)
                stats = ce.encrypt_folder_to_vault(
                    Path(folder), VAULT_FILE, k_local, k_cloud_bytes,
                    progress_callback=encrypt_cb
                )

                if self.wipe_var.get():
                    def wipe_cb(current, total, filename):
                        self.after(0, lambda: self.init_status.configure(
                            text=f"Wiping files [{current}/{total}]...", text_color=COLORS['warning']))

                    self.after(0, lambda: self.init_status.configure(
                        text="Wiping original files...", text_color=COLORS['warning']))
                    wiped = ce.secure_wipe_temp(Path(folder), progress_callback=wipe_cb)
                    logger.info(f"Wiped {wiped} original files from source folder.")

                # First auth for lease
                fp = fp_module.generate_fingerprint()
                result, cks, msg, was_online, req_id = lm.authenticate(
                    api_url, drive_id, fp, email, k_local, LEASE_FILE
                )

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
        self.after(1500, self._show_unlock_screen)

    def _update_encrypt_progress(self, progress, current, total, filename):
        """Update encryption progress bar and status from the main thread."""
        try:
            if hasattr(self, 'init_progress') and self.init_progress.winfo_exists():
                self.init_progress.set(progress)
            if hasattr(self, 'init_status') and self.init_status.winfo_exists():
                short_name = filename if len(filename) < 40 else '...' + filename[-37:]
                self.init_status.configure(
                    text=f"Encrypting [{current}/{total}]: {short_name}",
                    text_color=COLORS['warning'])
        except Exception:
            pass

    # ──────────────────────────────────────────────────────────────────────
    # Screen 2: Unlock / Login
    # ──────────────────────────────────────────────────────────────────────

    def _show_unlock_screen(self):
        self._clear_window()
        config = load_config()

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=40, pady=30)

        # Title
        drive_label = config.get('label', 'USB Drive') if config else 'USB Drive'
        ctk.CTkLabel(frame, text="Unlock Vault",
                     font=ctk.CTkFont(size=26, weight="bold"),
                     text_color=COLORS['text']).pack(pady=(0, 4))
        ctk.CTkLabel(frame, text=drive_label,
                     font=ctk.CTkFont(size=14),
                     text_color=COLORS['text_dim']).pack(pady=(0, 24))

        # Card
        card = ctk.CTkFrame(frame, fg_color=COLORS['bg_card'], corner_radius=16)
        card.pack(fill="x", pady=(0, 16))
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="x", padx=28, pady=24)

        # Email
        ctk.CTkLabel(inner, text="Your Email",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=COLORS['text_dim']).pack(anchor="w")
        self.unlock_email = ctk.CTkEntry(inner, placeholder_text="you@example.com",
                                         height=38, fg_color=COLORS['bg_input'],
                                         border_color=COLORS['border'])
        self.unlock_email.pack(fill="x", pady=(4, 14))
        if config and config.get('owner_email'):
            self.unlock_email.insert(0, config['owner_email'])

        # Fingerprint display
        fp_hash = fp_module.generate_fingerprint()
        self._current_fingerprint = fp_hash

        fp_frame = ctk.CTkFrame(inner, fg_color=COLORS['bg_input'], corner_radius=8)
        fp_frame.pack(fill="x", pady=(0, 14))
        fp_inner = ctk.CTkFrame(fp_frame, fg_color="transparent")
        fp_inner.pack(fill="x", padx=14, pady=10)

        ctk.CTkLabel(fp_inner, text="Hardware Fingerprint",
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
                     text=f"{comps.get('platform','')} {comps.get('os_arch','')} | {comps.get('hostname','')}",
                     font=ctk.CTkFont(size=10),
                     text_color=COLORS['text_muted']).pack(anchor="w", pady=(4, 0))

        # Vault info
        meta = ce.inspect_vault_header(VAULT_FILE)
        if meta:
            vault_info = f"Vault: {meta.get('file_count', '?')} files"
            ctk.CTkLabel(inner, text=vault_info,
                         font=ctk.CTkFont(size=12),
                         text_color=COLORS['text_dim']).pack(anchor="w", pady=(0, 8))

        # Lease info
        if config and LOCAL_KEY_FILE.exists():
            try:
                k_local = ce.load_local_key(LOCAL_KEY_FILE)
                info = lm.get_lease_info(LEASE_FILE, k_local, config.get('drive_id', ''))
                if info and not info['is_expired']:
                    lease_text = f"Offline lease: {info['days_left']}d {info['hours_left']}h remaining"
                    ctk.CTkLabel(inner, text=lease_text,
                                 font=ctk.CTkFont(size=12),
                                 text_color=COLORS['success']).pack(anchor="w", pady=(0, 8))
                elif info and info['is_expired']:
                    ctk.CTkLabel(inner, text="Offline lease expired — online auth required",
                                 font=ctk.CTkFont(size=12),
                                 text_color=COLORS['warning']).pack(anchor="w", pady=(0, 8))
            except Exception:
                pass

        # Status
        self.unlock_status = ctk.CTkLabel(frame, text="",
                                          font=ctk.CTkFont(size=12),
                                          text_color=COLORS['text_dim'])
        self.unlock_status.pack(pady=(0, 8))

        # Buttons
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(fill="x")

        ctk.CTkButton(btn_frame, text="Authenticate & Unlock", height=44,
                      font=ctk.CTkFont(size=15, weight="bold"),
                      fg_color=COLORS['accent'],
                      hover_color=COLORS['accent_hover'],
                      command=self._do_unlock).pack(fill="x", pady=(0, 8))

        bottom_row = ctk.CTkFrame(btn_frame, fg_color="transparent")
        bottom_row.pack(fill="x")

        ctk.CTkButton(bottom_row, text="Re-initialize Drive", height=32,
                      font=ctk.CTkFont(size=12),
                      fg_color="transparent", border_width=1,
                      border_color=COLORS['border'],
                      hover_color=COLORS['bg_card'],
                      text_color=COLORS['text_dim'],
                      command=self._show_init_screen).pack(side="left")

    def _do_unlock(self):
        config = load_config()
        if not config:
            self.unlock_status.configure(text="Drive not initialized!", text_color=COLORS['danger'])
            return

        email = self.unlock_email.get().strip()
        if not email:
            self.unlock_status.configure(text="Please enter your email.", text_color=COLORS['danger'])
            return

        self.unlock_status.configure(text="Authenticating...", text_color=COLORS['warning'])
        self.update_idletasks()

        def do_auth():
            try:
                k_local = ce.load_local_key(LOCAL_KEY_FILE)
                fp      = self._current_fingerprint
                api_url = config.get('api_url', DEFAULT_API)
                drive_id = config['drive_id']

                result, cks, msg, was_online, request_id = lm.authenticate(
                    api_url, drive_id, fp, email, k_local, LEASE_FILE
                )

                if result in ('GRANTED', 'OFFLINE_GRANTED'):
                    self.session['cloud_key_share'] = cks
                    mode = "Online" if was_online else "Offline Lease"
                    self.after(0, lambda: self._proceed_to_decrypt(k_local, cks, mode, msg))

                elif result == 'PENDING':
                    self.after(0, lambda: self._show_waiting_screen(
                        request_id, config, k_local, fp, email))

                elif result == 'LOCKED':
                    self.after(0, lambda: self.unlock_status.configure(
                        text="DRIVE MARKED AS LOST — ACCESS BLOCKED",
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

    def _proceed_to_decrypt(self, k_local, cloud_key_hex, mode, msg):
        """Decrypt vault and transition to workspace."""
        def set_status(text, color):
            try:
                if hasattr(self, 'unlock_status') and self.unlock_status.winfo_exists():
                    self.unlock_status.configure(text=text, text_color=color)
                elif hasattr(self, 'wait_status') and self.wait_status.winfo_exists():
                    self.wait_status.configure(text=text, text_color=color)
            except Exception:
                pass

        set_status(f"Decrypting vault ({mode})...", COLORS['warning'])
        self.update_idletasks()

        def do_decrypt():
            try:
                k_cloud  = ce.hex_to_key_bytes(cloud_key_hex)
                temp_dir = ce.decrypt_vault_to_temp(VAULT_FILE, k_local, k_cloud)

                self.session['unlocked']    = True
                self.session['temp_dir']    = temp_dir
                self.session['unlock_time'] = time.time()

                self.after(0, lambda: self._show_workspace_screen(temp_dir))

            except Exception as e:
                logger.exception("Decrypt error")
                self.after(0, lambda e=e: set_status(f"Decryption failed: {e}", COLORS['danger']))

        threading.Thread(target=do_decrypt, daemon=True).start()

    # ──────────────────────────────────────────────────────────────────────
    # Screen 3: Waiting for Approval
    # ──────────────────────────────────────────────────────────────────────

    def _show_waiting_screen(self, request_id, config, k_local, fingerprint, email):
        self._clear_window()
        self._poll_stop.clear()

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=40, pady=40)

        # Icon
        ctk.CTkLabel(frame, text="",
                     font=ctk.CTkFont(size=48)).pack(pady=(20, 16))

        ctk.CTkLabel(frame, text="Waiting for Approval",
                     font=ctk.CTkFont(size=24, weight="bold"),
                     text_color=COLORS['text']).pack(pady=(0, 8))

        ctk.CTkLabel(frame, text="An access request has been sent to the drive owner.",
                     font=ctk.CTkFont(size=13),
                     text_color=COLORS['text_dim']).pack(pady=(0, 24))

        # Request code card
        code_card = ctk.CTkFrame(frame, fg_color=COLORS['bg_card'], corner_radius=16)
        code_card.pack(fill="x", pady=(0, 24))
        code_inner = ctk.CTkFrame(code_card, fg_color="transparent")
        code_inner.pack(padx=28, pady=20)

        ctk.CTkLabel(code_inner, text="Request Code",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color=COLORS['text_muted']).pack()
        ctk.CTkLabel(code_inner, text=request_id,
                     font=ctk.CTkFont(family="Consolas", size=32, weight="bold"),
                     text_color=COLORS['warning']).pack(pady=(4, 0))
        ctk.CTkLabel(code_inner, text="Share this code with the drive owner if needed",
                     font=ctk.CTkFont(size=11),
                     text_color=COLORS['text_muted']).pack(pady=(4, 0))

        # Spinner / status
        self.wait_status = ctk.CTkLabel(frame, text="Polling for approval...",
                                        font=ctk.CTkFont(size=13),
                                        text_color=COLORS['text_dim'])
        self.wait_status.pack(pady=(0, 8))

        self.wait_progress = ctk.CTkProgressBar(frame, mode="indeterminate",
                                                 width=300, height=4,
                                                 progress_color=COLORS['accent'])
        self.wait_progress.pack(pady=(0, 24))
        self.wait_progress.start()

        # Cancel button
        ctk.CTkButton(frame, text="Cancel", height=40, width=200,
                      fg_color="transparent", border_width=1,
                      border_color=COLORS['border'],
                      hover_color=COLORS['bg_card'],
                      text_color=COLORS['text_dim'],
                      command=self._cancel_wait).pack()

        # Start polling thread
        api_url  = config.get('api_url', DEFAULT_API)
        drive_id = config['drive_id']

        def poll_loop():
            while not self._poll_stop.is_set():
                try:
                    result, cks, msg = lm.poll_request_status(
                        api_url, request_id, drive_id,
                        fingerprint, email, k_local, LEASE_FILE
                    )

                    if result == 'APPROVED':
                        self._poll_stop.set()
                        self.after(0, lambda: self._on_approval_granted(k_local, cks, msg))
                        return
                    elif result == 'DENIED':
                        self._poll_stop.set()
                        self.after(0, lambda: self._on_approval_denied())
                        return
                    # else PENDING or ERROR — keep polling

                except Exception as e:
                    logger.warning(f"Poll error: {e}")

                self._poll_stop.wait(3)  # Poll every 3 seconds

        self._poll_thread = threading.Thread(target=poll_loop, daemon=True)
        self._poll_thread.start()

    def _cancel_wait(self):
        self._poll_stop.set()
        self._show_unlock_screen()

    def _on_approval_granted(self, k_local, cloud_key_hex, msg):
        self.wait_progress.stop()
        self.wait_status.configure(text=f"Approved! {msg}", text_color=COLORS['success'])
        self.update_idletasks()
        self.after(800, lambda: self._proceed_to_decrypt(k_local, cloud_key_hex, "Approved", msg))

    def _on_approval_denied(self):
        self.wait_progress.stop()
        self.wait_status.configure(text="Access DENIED by drive owner.",
                                   text_color=COLORS['danger'])
        self.after(2500, self._show_unlock_screen)

    # ──────────────────────────────────────────────────────────────────────
    # Screen 4: Vault Workspace
    # ──────────────────────────────────────────────────────────────────────

    def _show_workspace_screen(self, temp_dir: Path):
        self._clear_window()
        config = load_config()

        # ─── Top bar ───
        top = ctk.CTkFrame(self, fg_color=COLORS['bg_card'], height=50, corner_radius=0)
        top.pack(fill="x")
        top.pack_propagate(False)

        top_inner = ctk.CTkFrame(top, fg_color="transparent")
        top_inner.pack(fill="both", expand=True, padx=16)

        ctk.CTkLabel(top_inner, text=f"  {config.get('label', 'Vault')}",
                     font=ctk.CTkFont(size=15, weight="bold"),
                     text_color=COLORS['text']).pack(side="left")

        # Status indicator
        status_frame = ctk.CTkFrame(top_inner, fg_color="transparent")
        status_frame.pack(side="left", padx=(20, 0))

        self.ws_status_dot = ctk.CTkLabel(status_frame, text="●",
                                          font=ctk.CTkFont(size=10),
                                          text_color=COLORS['success'])
        self.ws_status_dot.pack(side="left", padx=(0, 6))

        self.ws_status_text = ctk.CTkLabel(status_frame, text="UNLOCKED",
                                           font=ctk.CTkFont(size=11, weight="bold"),
                                           text_color=COLORS['success'])
        self.ws_status_text.pack(side="left")

        # Timer
        self.ws_timer = ctk.CTkLabel(top_inner, text="",
                                     font=ctk.CTkFont(size=12),
                                     text_color=COLORS['text_dim'])
        self.ws_timer.pack(side="right", padx=(0, 8))

        # Lock button
        ctk.CTkButton(top_inner, text="Lock & Eject", height=32, width=120,
                      font=ctk.CTkFont(size=12, weight="bold"),
                      fg_color=COLORS['danger'],
                      hover_color='#e11d48',
                      command=self._do_lock).pack(side="right", padx=(8, 0))

        # ─── Main content ───
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=16, pady=16)

        # File browser
        browser_frame = ctk.CTkFrame(main, fg_color=COLORS['bg_card'], corner_radius=12)
        browser_frame.pack(fill="both", expand=True)

        browser_header = ctk.CTkFrame(browser_frame, fg_color="transparent")
        browser_header.pack(fill="x", padx=16, pady=(12, 0))

        ctk.CTkLabel(browser_header, text="Decrypted Files",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color=COLORS['text_dim']).pack(side="left")

        ctk.CTkButton(browser_header, text="Open in Explorer", height=28, width=130,
                      font=ctk.CTkFont(size=11),
                      fg_color=COLORS['bg_input'],
                      hover_color=COLORS['border'],
                      text_color=COLORS['text'],
                      command=lambda: self._open_folder(temp_dir)).pack(side="right")

        # Treeview (using tkinter.ttk for proper tree widget)
        import tkinter.ttk as ttk

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Vault.Treeview",
                        background=COLORS['bg_card'],
                        foreground=COLORS['text'],
                        fieldbackground=COLORS['bg_card'],
                        borderwidth=0,
                        rowheight=26,
                        font=('Inter', 11))
        style.configure("Vault.Treeview.Heading",
                        background=COLORS['bg_input'],
                        foreground=COLORS['text_dim'],
                        borderwidth=0,
                        font=('Inter', 10, 'bold'))
        style.map("Vault.Treeview",
                  background=[('selected', COLORS['accent'])],
                  foreground=[('selected', '#ffffff')])

        tree_container = ctk.CTkFrame(browser_frame, fg_color="transparent")
        tree_container.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        self.file_tree = ttk.Treeview(tree_container, style="Vault.Treeview",
                                      columns=("size", "type"), show="tree headings",
                                      selectmode="browse")
        self.file_tree.heading("#0", text="Name", anchor="w")
        self.file_tree.heading("size", text="Size", anchor="e")
        self.file_tree.heading("type", text="Type", anchor="w")
        self.file_tree.column("#0", width=350, minwidth=200)
        self.file_tree.column("size", width=100, anchor="e")
        self.file_tree.column("type", width=80, anchor="w")

        scrollbar = ttk.Scrollbar(tree_container, orient="vertical",
                                  command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=scrollbar.set)

        self.file_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Populate tree
        self._populate_tree(temp_dir)

        # ─── Bottom info bar ───
        bottom = ctk.CTkFrame(self, fg_color=COLORS['bg_card'], height=36, corner_radius=0)
        bottom.pack(fill="x")
        bottom.pack_propagate(False)

        bottom_inner = ctk.CTkFrame(bottom, fg_color="transparent")
        bottom_inner.pack(fill="both", expand=True, padx=16)

        drive_id_short = config.get('drive_id', '?')[:8] if config else '?'
        ctk.CTkLabel(bottom_inner, text=f"Drive: {drive_id_short}...",
                     font=ctk.CTkFont(size=10),
                     text_color=COLORS['text_muted']).pack(side="left")

        ctk.CTkLabel(bottom_inner, text=f"Session: {str(temp_dir)[-30:]}",
                     font=ctk.CTkFont(family="Consolas", size=10),
                     text_color=COLORS['text_muted']).pack(side="right")

        # Start session timer
        self._start_timer()

    def _populate_tree(self, root_dir: Path, parent_id=''):
        """Recursively populate the treeview with directory contents."""
        try:
            entries = sorted(root_dir.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
            for entry in entries:
                if entry.is_dir():
                    node_id = self.file_tree.insert(parent_id, 'end',
                                                     text=f"  {entry.name}/",
                                                     values=('', 'Folder'))
                    self._populate_tree(entry, node_id)
                else:
                    size = entry.stat().st_size
                    if size < 1024:
                        size_str = f"{size} B"
                    elif size < 1024 * 1024:
                        size_str = f"{size / 1024:.1f} KB"
                    else:
                        size_str = f"{size / (1024*1024):.1f} MB"

                    ext = entry.suffix.lower()
                    type_map = {
                        '.txt': 'Text', '.md': 'Markdown', '.json': 'JSON',
                        '.py': 'Python', '.js': 'JS', '.html': 'HTML',
                        '.css': 'CSS', '.pdf': 'PDF', '.png': 'Image',
                        '.jpg': 'Image', '.jpeg': 'Image', '.gif': 'Image',
                    }
                    file_type = type_map.get(ext, ext[1:].upper() if ext else 'File')

                    self.file_tree.insert(parent_id, 'end',
                                          text=f"  {entry.name}",
                                          values=(size_str, file_type))
        except Exception as e:
            logger.warning(f"Error populating tree: {e}")

    def _start_timer(self):
        """Update the session timer every second."""
        if not self.session.get('unlocked'):
            return

        elapsed = int(time.time() - self.session['unlock_time'])
        mins    = elapsed // 60
        secs    = elapsed % 60
        hrs     = mins // 60
        mins    = mins % 60

        if hrs > 0:
            timer_text = f"Session: {hrs}h {mins}m {secs}s"
        elif mins > 0:
            timer_text = f"Session: {mins}m {secs}s"
        else:
            timer_text = f"Session: {secs}s"

        try:
            self.ws_timer.configure(text=timer_text)
        except Exception:
            return  # Widget might be destroyed

        self._timer_id = self.after(1000, self._start_timer)

    def _open_folder(self, folder: Path):
        """Open the decrypted session folder in OS file manager."""
        try:
            if sys.platform == 'win32':
                os.startfile(str(folder))
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', str(folder)])
            else:
                subprocess.Popen(['xdg-open', str(folder)])
        except Exception as e:
            messagebox.showerror("Error", f"Could not open folder: {e}")

    def _do_lock(self):
        """Lock the vault: wipe temp files and return to unlock screen."""
        if not self.session.get('unlocked'):
            return

        if not messagebox.askyesno("Lock Vault",
                                    "Lock vault and securely wipe all decrypted files?\n\n"
                                    "Unsaved changes will be lost."):
            return

        temp_dir = self.session.get('temp_dir')
        if temp_dir and Path(temp_dir).exists():
            def lock_wipe_cb(current, total, filename):
                try:
                    if hasattr(self, 'ws_status_text') and self.ws_status_text.winfo_exists():
                        self.ws_status_text.configure(text=f"WIPING [{current}/{total}]", text_color=COLORS['warning'])
                        self.update_idletasks()
                except Exception:
                    pass

            wiped = ce.secure_wipe_temp(Path(temp_dir), progress_callback=lock_wipe_cb)
            logger.info(f"Wiped {wiped} files on lock.")

        self.session = {
            'unlocked': False, 'temp_dir': None,
            'cloud_key_share': None, 'unlock_time': None,
            'request_id': None
        }

        if self._timer_id:
            self.after_cancel(self._timer_id)
            self._timer_id = None

        self._show_unlock_screen()

    # ──────────────────────────────────────────────────────────────────────
    # Window Management
    # ──────────────────────────────────────────────────────────────────────

    def _clear_window(self):
        """Remove all widgets from the window."""
        self._poll_stop.set()
        if self._timer_id:
            self.after_cancel(self._timer_id)
            self._timer_id = None
        for widget in self.winfo_children():
            widget.destroy()

    def _on_close(self):
        """Handle window close — wipe temp files if session active."""
        self._poll_stop.set()
        if self.session.get('unlocked') and self.session.get('temp_dir'):
            temp_dir = Path(self.session['temp_dir'])
            if temp_dir.exists():
                ce.secure_wipe_temp(temp_dir)
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
