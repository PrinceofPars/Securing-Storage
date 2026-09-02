# 🚀 USB Killswitch v2 — Quickstart Guide

Zero-Trust Remote-Killable Encrypted USB Drive System with Split-Key Architecture, Tail-Manifest Vaults, and Dual-Method Out-of-Band Device Approvals (Mobile QR + Google Web Portal).

---

## 📋 System Prerequisites

| Component | Requirements |
|---|---|
| **Backend Server** | Node.js v18+ & npm |
| **Desktop Client** | Windows 10/11 (macOS / Linux compatible) |
| **Python (Source Run)** | Python 3.10+ with `cryptography`, `customtkinter`, `requests`, `qrcode`, `Pillow`, `PyJWT` |
| **Pre-built Executable** | No Python installation needed (`dist/USB_Killswitch/USB_Killswitch.exe`) |

---

## ⚡ 1. Quick Launch

### 1.1. Start the Backend Server
Open a terminal in the project directory:

```bash
cd backend
npm install
npm start
```
The server will start at:
- **API Base**: `http://localhost:3000`
- **Owner & Admin Dashboard**: `http://localhost:3000/dashboard`
- **Mobile Device Approval Portal**: `http://localhost:3000/approve`

---

### 1.2. Launch the Desktop GUI Client

#### Option A: Run Pre-built Executable (Recommended)
Double-click:
```
dist/USB_Killswitch/USB_Killswitch.exe
```

#### Option B: Run from Python Source
```bash
pip install -r usb_client/requirements.txt
python usb_client/gui.py
```

---

## 🛠️ 2. Core User Workflows

### 2.1. Initializing a New Drive (First-Time Setup)

```
┌────────────────────────────────────────────────────────────┐
│                    USB KILLSWITCH SETUP                    │
│                 Initialize Encrypted Vault                 │
├────────────────────────────────────────────────────────────┤
│ Backend API URL:           http://localhost:3000           │
│ Owner Google / Work Email: alice.owner@gmail.com           │
│ Drive Label (Optional):    Secure Work USB                 │
│ Folder to Encrypt:         📁 C:/Documents/Project/Browse..│
│ [x] Securely wipe original folder files after encryption   │
│                                                            │
│          [ 🚀 Initialize & Encrypt Drive ]                 │
└────────────────────────────────────────────────────────────┘
```

1. Fill in the **Backend API URL** (default `http://localhost:3000`).
2. Enter your **Owner Email Address** (e.g. your Google account).
3. Select the folder containing files you want to encrypt.
4. *(Optional)* Check *"Securely wipe original folder files"* to purge plaintext originals from disk.
5. Click **Initialize & Encrypt Drive**.

> **What happens under the hood:**
> - Server registers the drive and generates a 256-bit Cloud Key Share ($K_{cloud}$).
> - Client generates a 256-bit Local Key Share ($K_{local}$) saved to `local_key.bin`.
> - Derives Master Key via HKDF-SHA256 from $K_{local} \oplus K_{cloud}$ and creates `vault.enc` (`USBVLT02`).
> - Automatically binds the owner's hardware fingerprint as **`FOREVER`** trusted.
> - Downloads an encrypted local offline lease (`lease.tok`).

---

### 2.2. Unlocking on the Owner's Machine

1. Open the USB Killswitch client.
2. The owner's email is pre-filled automatically.
3. Click **Unlock Vault**.
4. Access is **instantly granted** via the auto-trusted hardware fingerprint (or offline lease if without internet).

---

### 2.3. Authorizing a New Device / Guest User

When the drive is connected to an unrecognized computer (or used by a colleague/guest):

```
┌───────────────────────────────────────────────────────────────────────────┐
│                       ⚡ ACCESS APPROVAL REQUIRED                         │
│                          Authorize This Device                            │
├─────────────────────────────────────┬─────────────────────────────────────┤
│ 📱 Mobile Approval                  │ 🌐 Web Portal Approval              │
│ Scan with owner's phone camera      │ Sign in as drive owner in browser   │
│                                     │                                     │
│ [ REQUEST CODE: A1B2C3D4 ]          │ [  Continue with Google  ]          │
│                                     │                                     │
│ [ 📷 Click to Show QR Code ]       │ [ Open Direct Approval Link ]       │
│  └─ Reveals high-res QR code        │  └─ Opens Google / Portal login     │
├─────────────────────────────────────┴─────────────────────────────────────┤
│ ⏳ Waiting for owner decision (polling every 2s)...          [============]│
└───────────────────────────────────────────────────────────────────────────┘
```

The user is presented with two options to obtain owner approval:

#### Method A: Mobile Phone QR Code Scan
1. Click **`📷 Click to Show QR Code`** on the left card.
2. The drive owner scans the QR code with their mobile phone camera.
3. The mobile glassmorphism approval portal opens (`/approve?req=XXXXXX`).
4. The owner selects an approval scope:
   - **⚡ 1-Time Access (12 Hours)**: Single session access; automatically revokes upon completion.
   - **⏱️ 24-Hour Lease**: Timed lease token.
   - **📅 7-Day Lease**: Extended lease token.
   - **♾️ Trust Forever**: Permanently binds this machine.
   - **🚫 Deny Access**: Rejects the request.

#### Method B: Web Portal & Google Login
1. Click **`Continue with Google`** on the right card.
2. The default browser opens to the Google sign-in portal.
3. **If Drive Owner logs in**: Directed to the approval dashboard to view drives and grant access.
4. **If Guest / Colleague logs in**: Verified with their Google identity (e.g. `bob@partner.org`), updating the request so the owner sees exactly who is requesting access.

> 🔄 **Automated Real-Time Unlock**: As soon as the owner grants approval via either phone or browser, the desktop client's live 2-second poller detects it and automatically unlocks the vault!

---

### 2.4. Working in the Vault Workspace

```
┌───────────────────────────────────────────────────────────────────────────┐
│ 📂 Encrypted Vault        [● ACTIVE SESSION]     [Session: 14m 22s]       │
│                               [ Discard & Lock ]   [ 🔒 Lock & Save ]     │
├───────────────────────────────────────────────────────────────────────────┤
│ Encrypted Files (24 items)      [📄 Open Selected]  [✏️ Edit in Explorer] │
│ ───────────────────────────────────────────────────────────────────────── │
│  File Path                     │ Size    │ Type     │ Modified            │
│ ───────────────────────────────┼─────────┼──────────┼──────────────────── │
│  📁 financials/                │         │ Folder   │                     │
│    📄 q3_forecast.xlsx         │ 2.4 MB  │ Excel    │ 2026-09-02 14:30    │
│  📁 source/                    │         │ Folder   │                     │
│    📄 engine.py                │ 18.2 KB │ Python   │ 2026-09-02 18:15    │
│  📄 security_audit.pdf         │ 540 KB  │ PDF      │ 2026-09-02 12:00    │
├───────────────────────────────────────────────────────────────────────────┤
│ Drive ID: 5a26a120... | Dead Space: 0 KB      Vault on-demand mode active │
└───────────────────────────────────────────────────────────────────────────┘
```

- **On-Demand Single File Opening**:
  - Double-click any file or click **`Open Selected File`**.
  - Decrypts *only that specific file* on-the-fly and opens it in your default application without extracting the whole vault.
- **Bulk Editing in Windows Explorer**:
  - Click **`✏️ Edit All in Explorer`** to decrypt files into an isolated temporary workspace and open in Windows Explorer.
- **Lock & Save**:
  - Click **`🔒 Lock & Save`**.
  - The client scans for modified/new files, appends them incrementally to `vault.enc`, rewrites the tail manifest, and securely overwrites temporary files with random bytes.
- **Discard & Lock**:
  - Click **`Discard & Lock`** to wipe all session files immediately without modifying the encrypted vault.

---

### 2.5. Remote Kill Switch (Emergency Lockdown)

If a drive is lost or stolen:

1. Open the Web Dashboard at `http://localhost:3000/dashboard`.
2. Locate the drive under the **Drives** tab.
3. Click **🔴 Mark LOST**.
4. **Result**:
   - The drive is instantly marked `LOST` in the cloud database.
   - All pending access requests are denied.
   - All trusted device bindings and leases are revoked.
   - Any host attempting to authenticate will receive `403 LOCKED` and cannot derive the master key share.
5. If recovered later, the owner can click **🟢 Reactivate** to restore access.

---

## 🔐 3. Security & Architecture Specifications

| Feature | Implementation |
|---|---|
| **Cipher** | AES-256-GCM with unique 96-bit nonces per chunk and 128-bit authentication tags |
| **Key Splitting** | 2-of-2 split: $K_{local}$ (USB drive) + $K_{cloud}$ (Backend API) combined via XOR + HKDF-SHA256 |
| **Vault Structure** | Tail-manifest design (`USBVLT02`) with uint64 tail offset pointer |
| **Offline Leases** | Local `lease.tok` encrypted with HKDF key derived from $K_{local}$, bound to host SHA-256 hardware fingerprint |
| **Secure Wipe** | Multi-pass overwrite with `os.urandom()` followed by `fsync()` and unlink |
| **Out-of-Band Auth** | 3-way asynchronous polling with short readable request codes and mobile QR deep-links |

---

## 🧪 4. Running Automated Tests

To execute the test suite:

```bash
# Test Crypto Engine v2 (Encryption, Tail-Manifest, On-Demand, Incremental Update, Compaction)
python -m usb_client.crypto_engine

# Test Client Offline Lease Manager (Hardware Binding, Expiry, Tamper Protection)
python -c "import sys; sys.path.insert(0, 'usb_client'); import lease_manager, crypto_engine"

# Validate Syntax
node -c backend/server.js
```

---

## 📁 5. Project Directory Structure

```
Storage Protection/
├── backend/
│   ├── server.js              # Express backend API & authentication engine
│   ├── package.json           # Node.js dependencies
│   ├── public/
│   │   ├── index.html         # Web Admin & Owner Management Dashboard
│   │   └── approve.html       # Mobile Glassmorphism Approval Portal
│   └── data/
│       └── usb_drives.db      # SQLite WAL persistence database
├── usb_client/
│   ├── gui.py                 # Modern CustomTkinter Desktop Client
│   ├── crypto_engine.py       # AES-256-GCM Tail-Manifest Crypto Engine v2
│   ├── lease_manager.py       # Offline Lease Token Manager
│   ├── fingerprint.py         # Cross-platform Hardware Fingerprinter
│   └── requirements.txt       # Python dependencies
├── dist/
│   └── USB_Killswitch/
│       └── USB_Killswitch.exe # Standalone compiled desktop application
├── task.md                    # Architecture v2 Task Roadmap & Checklist
└── QUICKSTART.md              # This document
```
