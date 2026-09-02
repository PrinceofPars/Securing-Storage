# 🚀 USB Killswitch v2 — Complete Quickstart & Deployment Guide

A Zero-Trust, Remote-Killable Encrypted USB Drive System featuring Split-Key AES-256-GCM Cryptography, Tail-Manifest Vaults, a Web Management Dashboard, and Dual-Method Out-of-Band Device Approvals (Mobile QR Code + Google Web Portal).

---

## 📌 Architecture Overview

```
   ┌────────────────────────────────────────────────────────┐
   │                  1. BACKEND & WEB PORTAL               │
   │           Node.js Express + SQLite (Port 3000)         │
   │                                                        │
   │  • /dashboard : Drive Management & Access Lists        │
   │  • /approve   : Mobile Glassmorphism Decision Portal   │
   │  • /auth/google : Google Sign-in & Identity Verifier   │
   └───────────────────▲───────────────▲────────────────────┘
                       │               │
      2s Realtime Polling              │ Out-of-Band Owner Approval
      & Key Share Delivery             │ (QR Scan or Google Sign-In)
                       │               │
   ┌───────────────────▼───────────────┴────────────────────┐
   │                  2. DESKTOP CLIENT (GUI)               │
   │           CustomTkinter + Crypto Engine v2             │
   │                                                        │
   │  • Portable Standalone EXE: USB_Killswitch.exe         │
   │  • Local Key Share (K_local) + Hardware Fingerprint    │
   │  • Tail-Manifest Vault (vault.enc)                     │
   │  • On-Demand Decryption & Incremental Lock & Save      │
   └────────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Launch in 3 Steps

### Step 1: Start the Backend Server & Web Portals

Open a terminal in the project directory:

```bash
cd backend
npm install
npm start
```

Your server will be live with all web interfaces:
- 🌐 **Web Dashboard (Desktop)**: `http://localhost:3000/dashboard`
- 📱 **Mobile Approval Portal**: `http://localhost:3000/approve`
- 🔑 **Google Sign-In Entry**: `http://localhost:3000/auth/google`

---

### Step 2: Deploy & Launch the Desktop Client

#### 🌟 Recommended: Single-File Portable Executable
The desktop application is compiled into a single `.exe` file that contains all Python runtimes, cryptography, and UI assets.

- **File Location**: `dist/USB_Killswitch.exe`
- **Deployment**: Copy **`dist/USB_Killswitch.exe`** directly to your USB drive root (e.g., `D:\USB_Killswitch.exe`) and double-click to run.

> [!NOTE]
> **Fix for `Failed to load Python DLL '_internal'` Error**:
> If you previously copied only the `.exe` from a folder build, Windows could not find the sibling `_internal` directory. The new **`dist/USB_Killswitch.exe`** is a standalone single-file build (`--onefile`) with no external folder dependencies.

#### Alternative: Run from Python Source
```bash
pip install -r usb_client/requirements.txt
python usb_client/gui.py
```

---

## 🖥️ 3. Complete Frontend & Web Portal Tour

### 3.1. Web Dashboard (`/dashboard`)
Access at `http://localhost:3000/dashboard`.

```
┌───────────────────────────────────────────────────────────────────────────┐
│ 🔐 USB KILLSWITCH DASHBOARD              [Admin Key] [🔄 Refresh] [● Online]│
├───────────────────────────────────────────────────────────────────────────┤
│ [ 🔔 Approval Center (2) ]   [ 💾 Registered Drives ]   [ 📋 Activity Log ] │
├───────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│ 📨 Pending Access Requests                                                │
│ ┌───────────────────────────────────────────────────────────────────────┐ │
│ │ Access Request                                       [⏳ PENDING]      │ │
│ │ Drive: Alice Work Drive (USB 1) | Requester: bob@company.com          │ │
│ │ Device Fingerprint: 4f8a92b... | Requested: 2m ago                    │ │
│ │                                                                       │ │
│ │ [🔑 One-Time (12h)]  [⏱️ 24h Lease]  [📅 7d Lease]  [♾️ Trust]  [🚫 Deny] │
│ └───────────────────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────────┘
```

#### Key Capabilities:
1. **Approval Center**: View real-time pending access requests from unknown PCs. Click any button (`1-Time`, `24h Lease`, `7d Lease`, `Trust Forever`, `Deny`) to resolve instantly.
2. **Drives Management**:
   - View all registered USB drives, creation dates, user counts, and device counts.
   - **Access List Sharing**: Add or remove authorized user emails for any drive.
   - **Emergency Killswitch**: Click **🔴 Mark LOST** to instantly lock out all computers worldwide.
3. **Activity Log**: Full audit trail of all authentication events, IP addresses, timestamps, and outcomes (`GRANTED`, `PENDING_APPROVAL`, `LOCKED`, `DENIED`).

---

### 3.2. Mobile Device Approval Portal (`/approve?req=XXXXXX`)
Designed with a dark glassmorphism mobile UI for smartphone screens.

```
                  ┌──────────────────────────────┐
                  │              🔐              │
                  │     Drive Access Request     │
                  │   Remote authorization portal│
                  ├──────────────────────────────┤
                  │ Request Code:   [ A1B2C3D4 ] │
                  │                              │
                  │ Drive Name:     Work Vault   │
                  │ Drive Owner:    alice@...    │
                  │ Requester:      bob@...      │
                  │ Device ID:      a491...d02f  │
                  │ Status:         ⏳ PENDING   │
                  ├──────────────────────────────┤
                  │   [ ⚡ Approve 1-Time ]      │
                  │   [ ⏱️ Approve 24h Lease ]   │
                  │   [ 📅 Approve 7-Day Lease ] │
                  │   [ ♾️ Trust Permanently ]   │
                  │   [ 🚫 Deny Access ]         │
                  └──────────────────────────────┘
```

- When the drive owner scans the desktop QR code with their mobile phone, this portal opens directly with the request pre-loaded.
- Choosing any approval scope sends the decision to the backend and immediately unlocks the desktop client.

---

### 3.3. Google Identity Portal (`/auth/google`)

- Clicking **"Continue with Google"** on the desktop client launches this interface in the default browser.
- **When the Drive Owner logs in**: Recognizes the owner and opens the approval dashboard to grant access.
- **When a New User / Guest logs in**: Securely verifies their Google account (`guest@company.com`) and updates the access request so the owner sees their verified identity before deciding to approve.

---

## 💻 4. Desktop Client Step-by-Step Walkthrough

### Step A: Initialize an Encrypted USB Drive

1. Launch `USB_Killswitch.exe`.
2. Enter the **Backend URL** (e.g. `http://localhost:3000`) and **Owner Email** (e.g. `owner@gmail.com`).
3. Click **Browse...** and choose the folder you want to protect.
4. *(Optional)* Check *"Securely wipe original folder files"* to erase unencrypted originals.
5. Click **`🚀 Initialize & Encrypt Drive`**.

---

### Step B: Unlocking on Owner's Registered Computer

1. Open `USB_Killswitch.exe`.
2. Click **`Unlock Vault`**.
3. **Result**: Unlocks instantly via auto-trusted hardware fingerprint binding (or local `lease.tok` if offline).

---

### Step C: Connecting to an Unrecognized Computer (Guest / Colleague)

1. Open `USB_Killswitch.exe` on the new machine.
2. Enter email and click **`Unlock Vault`**.
3. The modern **Dual-Authentication Waiting Screen** appears:

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
├─────────────────────────────────────┴─────────────────────────────────────┤
│ ⏳ Waiting for owner decision (polling every 2s)...          [============]│
└───────────────────────────────────────────────────────────────────────────┘
```

4. **To Approve via Phone**:
   - Click **`📷 Click to Show QR Code`** on the left.
   - Owner scans the QR code on their phone and taps **Approve**.
5. **To Approve via Browser / Google**:
   - Click **`Continue with Google`** on the right.
   - Owner signs in and grants access.
6. **Automatic Unlock**: Within 2 seconds of approval, the desktop client receives the key share and unlocks the workspace!

---

### Step D: Managing Files in the Vault Workspace

```
┌───────────────────────────────────────────────────────────────────────────┐
│ 📂 Work Vault             [● ACTIVE SESSION]         [Session: 05m 12s]   │
│                               [ Discard & Lock ]   [ 🔒 Lock & Save ]     │
├───────────────────────────────────────────────────────────────────────────┤
│ Encrypted Files (8 items)       [📄 Open Selected]  [✏️ Edit in Explorer] │
│ ───────────────────────────────────────────────────────────────────────── │
│  📁 contracts/                                                            │
│    📄 agreement_2026.pdf       540 KB    PDF        2026-09-02 18:30      │
│  📁 financials/                                                           │
│    📄 q3_forecast.xlsx         1.2 MB    Excel      2026-09-02 19:15      │
└───────────────────────────────────────────────────────────────────────────┘
```

- **Instant On-Demand Decrypt**: Double-click any file. It decrypts *only that single file* on-the-fly into your default application without extracting the entire drive.
- **Bulk Editing**: Click **`✏️ Edit All in Explorer`** to open all files in Windows Explorer.
- **Lock & Save**: Click **`🔒 Lock & Save`** to incrementally re-encrypt only modified/new files and securely shred all temporary session files.
- **Discard & Lock**: Click **`Discard & Lock`** to wipe session files without saving changes.

---

### Step E: Emergency Remote Killswitch

If the USB drive is lost or stolen:
1. Open `http://localhost:3000/dashboard`.
2. Locate the drive and click **🔴 Mark LOST**.
3. **Immediate Effect**:
   - Drive status changes to `LOST`.
   - All leases and trusted devices are revoked.
   - Any computer attempting to authenticate receives **`403 LOCKED`** and cannot decrypt the vault.
4. When recovered, click **🟢 Reactivate** to restore access.

---

## 🧪 5. Automated Test Verification

Run all test suites at any time to verify system integrity:

```bash
# 1. Multi-USB 4-Drive Simulation (All user & approval scenarios)
node test_multi_usb_scenarios.js

# 2. Cryptographic Engine & Offline Vault Lifecycle
python test_multi_usb_crypto.py

# 3. Master Advanced Edge Cases (Concurrency, Access Lists, Killswitch recovery)
node test_all_advanced_scenarios.js
```

---

## 📦 6. Summary of Key Files

| Path | Description |
|---|---|
| **`dist/USB_Killswitch.exe`** | **Standalone Single-File Executable** (Portable, zero dependencies) |
| **`backend/server.js`** | Express backend API, auth engine, session manager, and routes |
| **`backend/public/index.html`** | Web Admin & Owner Management Dashboard |
| **`backend/public/approve.html`** | Mobile Glassmorphism Device Approval Portal |
| **`usb_client/gui.py`** | Modern CustomTkinter Desktop Client source code |
| **`usb_client/crypto_engine.py`** | Tail-Manifest AES-256-GCM Cryptographic Engine (`USBVLT02`) |
| **`usb_client/lease_manager.py`** | Offline Hardware-Bound Lease Manager (`lease.tok`) |
| **`usb_client/fingerprint.py`** | Hardware Fingerprinting Module |
