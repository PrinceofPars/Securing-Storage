# 🛡️ USB Killswitch v2 — Zero-Trust Encrypted Storage

> **Remote-Killable Encrypted USB Storage with Split-Key Cryptography, Tail-Manifest Vaults, Out-of-Band Mobile Approvals, and Offline Hardware Leases.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Node.js 20.x](https://img.shields.io/badge/Node.js-20.x-green.svg)](https://nodejs.org/)
[![Encryption](https://img.shields.io/badge/Security-AES--256--GCM-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Cross--Platform-lightgrey.svg)]()

---

## 📌 Executive Summary

Traditional hardware encryption (BitLocker To Go, VeraCrypt, static password USBs) suffers from a fundamental security flaw: **once an encrypted drive is lost or stolen, physical possession guarantees an offline brute-force attack vector, with zero remote revocation capability.**

**USB Killswitch** eliminates this physical possession threat by enforcing a **Zero-Trust Split-Key Model**:
1. **The Master Key is Split**: Half is stored in an encrypted local share on the USB drive, and the other half is retained securely on a cloud management server.
2. **Out-of-Band 2FA Approval**: When connected to an unrecognized machine, the client halts in a zero-trust holding pattern until the drive owner grants approval via a smartphone QR scan or web portal.
3. **Emergency Remote Killswitch**: Administrators can mark any drive as `LOST` with a single click, instantly cutting off key distribution worldwide and rendering the drive cryptographically unreadable.
4. **On-Demand Single-File Access**: Files are decrypted selectively into volatile memory only when opened, avoiding full-disk exposure and leaving zero residual trace upon locking.

---

## 🏗️ System Architecture

```mermaid
graph TB
    %% Themes
    classDef clientBox fill:#111827,stroke:#6366f1,stroke-width:2px,color:#f8fafc;
    classDef serverBox fill:#0f172a,stroke:#0ea5e9,stroke-width:2px,color:#f8fafc;
    classDef mobileBox fill:#1e1b4b,stroke:#a855f7,stroke-width:2px,color:#f8fafc;
    classDef nodeStyle fill:#1e293b,stroke:#475569,stroke-width:1.5px,color:#f1f5f9;
    classDef keyNode fill:#312e81,stroke:#818cf8,stroke-width:1.5px,color:#e0e7ff;
    classDef actionNode fill:#064e3b,stroke:#10b981,stroke-width:1.5px,color:#ecfdf5;
    classDef killswitchNode fill:#4c0519,stroke:#f43f5e,stroke-width:1.5px,color:#ffe4e6;

    %% Client
    subgraph EDGE["💾 1. PORTABLE EDGE CLIENT - Host Machine / USB"]
        direction TB
        E_HW["🔍 Hardware Fingerprint Collector"]:::nodeStyle
        E_QR["📱 Dynamic QR Code Generator"]:::nodeStyle
        E_LOCAL_KEY["🔑 Local Key Share - Encrypted on USB"]:::keyNode
        E_ENGINE["⚙️ Cryptographic Decryption Engine - RAM Only"]:::nodeStyle
        E_VAULT["📦 Encrypted Vault Container - AES-256-GCM"]:::nodeStyle
        E_LEASE["⏱️ Offline Hardware Lease Token"]:::nodeStyle

        E_HW --> E_QR
        E_LOCAL_KEY -.->|"Combine in Volatile RAM"| E_ENGINE
        E_ENGINE -->|"On-Demand Single File Decrypt"| E_VAULT
        E_LEASE -.->|"Offline Fallback Validation"| E_ENGINE
    end

    %% Server
    subgraph SERVER["☁️ 2. CENTRAL MANAGEMENT SERVER & API"]
        direction TB
        S_GATEWAY["🛡️ API Gateway & Device Authenticator"]:::nodeStyle
        S_REGISTRY["📋 Drive Fleet & User Access Registry"]:::nodeStyle
        S_REMOTE_KEY["🔐 Remote Server Key Store"]:::keyNode
        S_LEASE_SVC["⏱️ Ephemeral Lease & Token Manager"]:::nodeStyle
        S_AUDIT["📝 Real-Time Forensic Audit Logger"]:::nodeStyle
        S_KILL["🔴 Remote Killswitch Controller - Mark LOST"]:::killswitchNode

        S_GATEWAY --> S_REGISTRY
        S_REGISTRY --> S_LEASE_SVC
        S_LEASE_SVC --> S_REMOTE_KEY
        S_GATEWAY --> S_AUDIT
        S_KILL -.->|"Instant Global Revocation"| S_REMOTE_KEY
    end

    %% Mobile
    subgraph MOBILE["📱 3. OUT-OF-BAND APPROVAL CHANNEL - Owner Phone"]
        direction TB
        M_SCAN["📷 Smartphone Camera / QR Scanner"]:::nodeStyle
        M_PORTAL["🌐 Mobile Glassmorphism Decision Portal"]:::nodeStyle
        M_SCOPES["⚡ Scoped Access Decision - 1-Time / 24h / 7d / Trust / Deny"]:::actionNode

        M_SCAN --> M_PORTAL
        M_PORTAL --> M_SCOPES
    end

    %% Interactions
    E_HW ==>|"1. Unknown Machine Challenge / Access Request"| S_GATEWAY
    E_QR -.->|"2. Physical Out-of-Band Optical Scan"| M_SCAN
    M_SCOPES ==>|"3. Send Cryptographic Approval and Scope"| S_LEASE_SVC
    S_REMOTE_KEY ==>|"4. Deliver Remote Key Share via 2s Polling"| E_ENGINE
    S_KILL -.->|"5. Global Lockout on Compromised Drive"| E_HW

    class EDGE clientBox;
    class SERVER serverBox;
    class MOBILE mobileBox;
```

---

## ✨ Core Features

| Feature | Description |
|---|---|
| **Split-Key AES-256-GCM** | Military-grade authenticated encryption where the master key is divided between local drive storage and cloud backend. |
| **Zero-Config Cloud Pre-integration** | Pre-configured to communicate with the cloud management gateway out-of-the-box, without requiring manual server URL setup. |
| **Out-of-Band Mobile 2FA** | Real-time QR code display on the desktop client that can be scanned by the owner’s smartphone to approve or deny access. |
| **Instant Remote Killswitch** | One-click emergency lockout from the web dashboard that immediately revokes key delivery worldwide. |
| **Hardware Fingerprint Binding** | Binds sessions to unique CPU, motherboard, and disk signatures to prevent token cloning. |
| **Offline Time-Bounded Leases** | Digitally signed cryptographic tokens allow working offline (e.g., in-flight) for defined periods without active internet. |
| **Encapsulated 2-File Architecture** | Prepend the local key (`K_local`), configuration, and lease token into an authenticated 4 KB header inside `vault.enc` — exactly 2 files exist on the USB: `Zero-Trust.exe` and `vault.enc`. |
| **Tail-Manifest Vault Format** | Single-file encrypted container (`vault.enc`) with tamper-proof authenticated file manifests. |
| **Single-File On-Demand Decrypt** | Decrypts only the specific file opened into a temporary RAM workspace, re-encrypts changes, and securely shreds cache upon locking. |
| **Central Admin Dashboard** | Full web UI for managing drive fleets, access control lists (ACLs), approval queues, and immutable forensic audit logs. |

---

## 📂 Project Structure

```text
Storage Protection/
├── backend/                        # Node.js Express Server & Web Portals
│   ├── server.js                   # API routes, auth engine, session manager, & SQLite store
│   ├── package.json                # Server dependencies
│   └── public/
│       ├── index.html              # Admin & Fleet Management Web Dashboard
│       └── approve.html            # Mobile Glassmorphism Device Approval Portal
├── usb_client/                     # Python Desktop Client
│   ├── gui.py                      # CustomTkinter modern dark-mode Desktop GUI
│   ├── crypto_engine.py            # Tail-Manifest AES-256-GCM Cryptographic Engine
│   ├── fingerprint.py              # Hardware identification & device fingerprinting
│   ├── lease_manager.py            # Offline signed lease validator & storage
│   └── requirements.txt            # Python client dependencies
├── dist/
│   └── USB_Killswitch.exe          # Standalone, single-file compiled portable executable
├── QUICKSTART.md                   # Comprehensive deployment & usage guide
└── README.md                       # Main project documentation
```

---

## 🚀 Quick Start Guide

### 1. Start the Backend Management Server

```bash
cd backend
npm install
npm start
```
* The server will start on `http://localhost:3000`.
* **Admin Dashboard**: `http://localhost:3000/dashboard`
* **Mobile Approval Portal**: `http://localhost:3000/approve`

---

### 2. Launch the Desktop Client

#### Option A: Run the Standalone Portable Executable (Recommended)
Copy `dist/USB_Killswitch.exe` directly onto your USB drive and double-click to launch.

#### Option B: Run from Source
```bash
# Install Python dependencies
pip install -r usb_client/requirements.txt

# Launch Desktop GUI
python usb_client/gui.py
```

---

## 🔄 End-to-End Operational Workflow

### Step 1: Initialize & Encrypt a Drive
1. Launch the Desktop Client.
2. Sign in with **"Continue with Google"** or enter the **Owner Email** (e.g., `owner@gmail.com`).
3. Select the folder to protect and click **`🚀 Initialize & Encrypt Drive`**.
4. The client creates the encapsulated `vault.enc` container (packing configuration and local key share directly into the encrypted header) and registers the drive fingerprint with the backend automatically. No loose metadata files are written to the USB drive.

### Step 2: Unlocking on a Trusted Machine
* On recognized hardware with an active lease, clicking **`Unlock Vault`** grants instant access without approval prompts.

### Step 3: Unlocking on an Unrecognized Machine (Guest / Unknown PC)
1. When launched on a new computer, the client enters a waiting state and displays:
   - **QR Code** for smartphone camera scanning.
   - **Continue with Google** for browser-based identity verification.
2. The owner scans the QR code or opens the dashboard, choosing an access duration:
   - `⚡ Approve 1-Time (12 Hours)`
   - `⏱️ Approve 24h Lease`
   - `📅 Approve 7-Day Lease`
   - `♾️ Trust Permanently`
   - `🚫 Deny Access`
3. Within 2 seconds of approval, the desktop client receives the key share and unlocks automatically.

### Step 4: Vault File Workspace
* **Open File**: Double-click any file to decrypt and view it on-the-fly.
* **Edit in Explorer**: Open the temporary session folder to add or edit files.
* **Lock & Save**: Re-encrypts modified files back into the vault and securely shreds temporary disk cache.

### Step 5: Emergency Remote Killswitch
* If a drive is lost or stolen, open the Web Dashboard and click **🔴 Mark LOST**.
* The server immediately revokes all leases and blocks key retrieval, rendering the drive permanently unreadable.
* Clicking **🟢 Reactivate** restores access once the drive is safely recovered.

---

## 🧪 Testing & Verification

Run automated test suites to verify end-to-end functionality:

```bash
# 1. Multi-USB Simulation (All user & approval scenarios)
node test_multi_usb_scenarios.js

# 2. Cryptographic Engine & Offline Vault Lifecycle
python test_multi_usb_crypto.py

# 3. Edge Cases & Concurrency Verification
node test_all_advanced_scenarios.js
```

---

## 🔒 Security & Cryptography Details

* **Cipher Suite**: AES-256-GCM (Authenticated Galois/Counter Mode with 96-bit nonce and 128-bit authentication tag).
* **Key Derivation**: HKDF-SHA256 with cryptographically random salts.
* **Integrity Guarantee**: Tamper-proof tail-manifest containing per-file SHA-256 integrity hashes.
* **Zero Residual Footprint**: Volatile memory key assembly; automated multi-pass file shredding upon locking.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
