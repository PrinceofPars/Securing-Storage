"""
lease_manager.py — Offline Lease Manager v2
=============================================
Manages the cryptographically signed local lease token that enables
offline vault access after the last successful online authentication.

v2 Changes:
  - online_auth() now sends user_email, handles 202 PENDING_APPROVAL
  - New poll_request_status() for waiting-for-approval flow
  - authenticate() returns a four-tuple with PENDING as a possible outcome
  - Lease token now stores user_email

Dependencies: cryptography >= 41.0, requests >= 2.31, PyJWT >= 2.8
"""

import base64
import hashlib
import json
import logging
import secrets
import socket
import time
from pathlib import Path
from typing import Optional, Tuple

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

try:
    import crypto_engine as ce
except ImportError:
    try:
        from usb_client import crypto_engine as ce
    except ImportError:
        ce = None

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

LEASE_VERSION         = 3
CONNECTIVITY_TIMEOUT  = 3
CONNECTIVITY_HOST     = '8.8.8.8'
CONNECTIVITY_PORT     = 53
KEY_SIZE              = 32
NONCE_SIZE            = 12
TAG_SIZE              = 16


# ──────────────────────────────────────────────────────────────────────────────
# Network Connectivity Check
# ──────────────────────────────────────────────────────────────────────────────

def check_internet_connectivity(
    host: str = CONNECTIVITY_HOST,
    port: int = CONNECTIVITY_PORT,
    timeout: float = CONNECTIVITY_TIMEOUT
) -> bool:
    """
    Check if the host has internet connectivity.
    Tries raw TCP socket check first (fast), then falls back to HTTPS HEAD
    request to ensure environments blocking raw DNS TCP (port 53) are properly detected as online.
    """
    try:
        socket.setdefaulttimeout(timeout)
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, OSError):
        pass

    # Fallback to HTTP/HTTPS check (works through proxies, VPNs, and networks blocking raw TCP port 53)
    for test_url in ("https://www.google.com", "https://1.1.1.1"):
        try:
            r = requests.head(test_url, timeout=3)
            if r.status_code < 500:
                return True
        except Exception:
            continue

    return False


# ──────────────────────────────────────────────────────────────────────────────
# Lease Encryption Key Derivation
# ──────────────────────────────────────────────────────────────────────────────

def _derive_lease_key(k_local: bytes, drive_id: str, fingerprint_hash: Optional[str] = None) -> bytes:
    if fingerprint_hash:
        salt = hashlib.sha256(f"{drive_id}:{fingerprint_hash.strip().lower()}".encode('utf-8')).digest()
        info = b'lease-token-key-v3'
    else:
        salt = drive_id.encode('utf-8')
        info = b'lease-token-key-v2'

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(k_local)


# ──────────────────────────────────────────────────────────────────────────────
# Lease Token Storage
# ──────────────────────────────────────────────────────────────────────────────

def save_lease_token(
    lease_path: Optional[Path],
    k_local: bytes,
    drive_id: str,
    fingerprint_hash: str,
    cloud_key_share: str,
    jwt_token: str,
    issued_at: int,
    expires_at: int,
    user_email: str = '',
    vault_path: Optional[Path] = None
) -> None:
    """Encrypt and persist the lease token into vault.enc header or lease.tok."""
    inner_data = {
        'drive_id':        drive_id,
        'fingerprint':     fingerprint_hash,
        'cloud_key_share': cloud_key_share,
        'issued_at':       issued_at,
        'expires_at':      expires_at,
        'jwt':             jwt_token,
        'user_email':      user_email
    }
    plaintext = json.dumps(inner_data, separators=(',', ':')).encode('utf-8')

    lease_key = _derive_lease_key(k_local, drive_id, fingerprint_hash)
    aesgcm    = AESGCM(lease_key)
    nonce     = secrets.token_bytes(NONCE_SIZE)

    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = ciphertext_with_tag[:-TAG_SIZE]
    tag        = ciphertext_with_tag[-TAG_SIZE:]

    lease_envelope = {
        'v':     LEASE_VERSION,
        'nonce': base64.b64encode(nonce).decode('ascii'),
        'tag':   base64.b64encode(tag).decode('ascii'),
        'data':  base64.b64encode(ciphertext).decode('ascii')
    }

    # If vault_path is provided and exists, encapsulate directly inside vault header
    if vault_path and vault_path.exists():
        try:
            _ce = ce
            if _ce is None:
                import crypto_engine as _ce
            _ce.update_vault_header(vault_path, lease_data=lease_envelope)
            logger.info(f"Lease token encapsulated into vault header: {vault_path}")
            # Remove any loose lease file if it exists
            if lease_path and lease_path.exists():
                try:
                    lease_path.unlink()
                    logger.info(f"Removed redundant loose lease file: {lease_path}")
                except Exception:
                    pass
            return
        except Exception as e:
            logger.warning(f"Could not encapsulate lease into vault header ({e}), falling back to lease_path")

    if lease_path:
        lease_path.parent.mkdir(parents=True, exist_ok=True)
        lease_path.write_text(json.dumps(lease_envelope, indent=2), encoding='utf-8')
        logger.info(f"Lease token saved to fallback file: {lease_path}")


def load_lease_token(
    lease_path: Optional[Path],
    k_local: bytes,
    drive_id: str,
    vault_path: Optional[Path] = None,
    fingerprint_hash: Optional[str] = None
) -> Optional[dict]:
    """Load and decrypt the lease token from vault.enc header or lease.tok."""
    envelope = None

    # Check encapsulated vault header first
    if vault_path and vault_path.exists():
        try:
            _ce = ce
            if _ce is None:
                import crypto_engine as _ce
            header_data = _ce.read_vault_header(vault_path)
            if header_data and header_data.get('lease'):
                envelope = header_data['lease']
        except Exception as e:
            logger.debug(f"Could not read lease from vault header: {e}")

    # Fallback to standalone lease file
    if not envelope and lease_path and lease_path.exists():
        try:
            envelope = json.loads(lease_path.read_text(encoding='utf-8'))
        except Exception:
            envelope = None

    if not envelope:
        return None

    try:
        version = envelope.get('v', 0)
        if version not in (1, 2, 3):  # Accept v1, v2, v3 tokens
            return None

        nonce      = base64.b64decode(envelope['nonce'])
        tag        = base64.b64decode(envelope['tag'])
        ciphertext = base64.b64decode(envelope['data'])
        ct_with_tag = ciphertext + tag

        # Resolve host fingerprint if omitted
        target_fp = fingerprint_hash
        if not target_fp:
            try:
                import fingerprint as _fp
                target_fp = _fp.get_fingerprint()
            except Exception:
                target_fp = None

        # 1. Try v3 key bound to host hardware fingerprint first
        if target_fp:
            try:
                lease_key = _derive_lease_key(k_local, drive_id, target_fp)
                aesgcm    = AESGCM(lease_key)
                plaintext = aesgcm.decrypt(nonce, ct_with_tag, None)
                return json.loads(plaintext.decode('utf-8'))
            except Exception:
                pass

        # 2. Fall back to legacy v2 and v1 keys
        for info_tag in (b'lease-token-key-v2', b'lease-token-key-v1'):
            try:
                hkdf = HKDF(
                    algorithm=hashes.SHA256(), length=KEY_SIZE,
                    salt=drive_id.encode('utf-8'), info=info_tag,
                    backend=default_backend()
                )
                lease_key = hkdf.derive(k_local)
                aesgcm    = AESGCM(lease_key)
                plaintext = aesgcm.decrypt(nonce, ct_with_tag, None)
                return json.loads(plaintext.decode('utf-8'))
            except Exception:
                continue
        return None

    except Exception as e:
        logger.warning(f"Lease token load/decrypt failed: {type(e).__name__}: {e}")
        return None


def clear_lease_token(
    lease_path: Optional[Path] = None,
    vault_path: Optional[Path] = None
) -> None:
    """Clear lease token from vault header and remove loose lease file."""
    if vault_path and vault_path.exists():
        try:
            _ce = ce
            if _ce is None:
                import crypto_engine as _ce
            _ce.update_vault_header(vault_path, clear_lease=True)
            logger.info(f"Cleared lease token in vault header: {vault_path}")
        except Exception as e:
            logger.warning(f"Failed to clear lease in vault header: {e}")

    if lease_path and lease_path.exists():
        try:
            lease_path.unlink()
            logger.info(f"Deleted loose lease file: {lease_path}")
        except Exception as e:
            logger.warning(f"Failed to delete loose lease file: {e}")


# ──────────────────────────────────────────────────────────────────────────────
# Online Authentication Flow (v2: now handles PENDING_APPROVAL)
# ──────────────────────────────────────────────────────────────────────────────

def online_auth(
    api_base_url: str,
    drive_id: str,
    fingerprint_hash: str,
    user_email: str,
    k_local: bytes,
    lease_path: Optional[Path] = None,
    vault_path: Optional[Path] = None,
    timeout: int = 30,
    auth_token: Optional[str] = None
) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    """
    Attempt online authentication against the backend API.

    Returns:
        Tuple of (result, cloud_key_share, message, request_id)
        result is one of: 'GRANTED', 'LOCKED', 'DENIED', 'PENDING', 'ERROR'
    """
    url = f"{api_base_url.rstrip('/')}/api/auth-host"
    payload = {
        'drive_id':             drive_id,
        'hardware_fingerprint': fingerprint_hash,
        'user_email':           user_email
    }
    headers = {'Content-Type': 'application/json'}
    if auth_token:
        payload['auth_token'] = auth_token
        headers['Authorization'] = f'Bearer {auth_token}'

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=timeout)
        data     = response.json()

        if response.status_code == 200 and data.get('status') == 'GRANTED':
            cloud_key_share = data['cloud_key_share']
            jwt_token       = data.get('lease_token', '')
            expires_at_unix = data.get('expires_at_unix', int(time.time()) + 7 * 86400)
            issued_at       = int(time.time())

            resolved_email  = (data.get('user_email') or user_email or '').strip()

            save_lease_token(
                lease_path       = lease_path,
                k_local          = k_local,
                drive_id         = drive_id,
                fingerprint_hash = fingerprint_hash,
                cloud_key_share  = cloud_key_share,
                jwt_token        = jwt_token,
                issued_at        = issued_at,
                expires_at       = expires_at_unix,
                user_email       = resolved_email,
                vault_path       = vault_path
            )

            scope = data.get('trust_scope', 'LEASE')
            logger.info(f"Online auth GRANTED for drive {drive_id} ({scope})")
            return 'GRANTED', cloud_key_share, f"Access granted ({scope}).", None

        elif response.status_code == 202 and data.get('status') == 'PENDING_APPROVAL':
            request_id = data.get('request_id', '')
            logger.info(f"Online auth PENDING for drive {drive_id}, request: {request_id}")
            return 'PENDING', None, data.get('message', 'Waiting for approval.'), request_id

        elif response.status_code == 403:
            status  = data.get('status', 'DENIED')
            message = data.get('message', 'Access denied.')
            logger.warning(f"Online auth DENIED: {status} — {message}")
            if status == 'LOCKED':
                clear_lease_token(lease_path=lease_path, vault_path=vault_path)
                return 'LOCKED', None, message, None
            return 'DENIED', None, message, None

        elif response.status_code == 404:
            clear_lease_token(lease_path=lease_path, vault_path=vault_path)
            return 'ERROR', None, 'Drive ID not registered on server.', None

        else:
            err_msg = data.get('error') or data.get('message') or f"Server returned {response.status_code}"
            return 'ERROR', None, err_msg, None

    except requests.exceptions.ConnectionError:
        return 'ERROR', None, f"Cannot connect to server at {api_base_url}", None
    except requests.exceptions.Timeout:
        return 'ERROR', None, "Server request timed out.", None
    except Exception as e:
        return 'ERROR', None, f"Authentication error: {e}", None


# ──────────────────────────────────────────────────────────────────────────────
# Check Drive Revocation / Killswitch
# ──────────────────────────────────────────────────────────────────────────────

def check_drive_revocation(
    api_base_url: str,
    drive_id: str,
    lease_path: Optional[Path] = None,
    vault_path: Optional[Path] = None,
    timeout: int = 5
) -> Tuple[bool, bool, Optional[str]]:
    """
    Check if the drive is marked as LOST or revoked on the server.
    Returns:
        (is_online, is_revoked, reason)
    """
    if not check_internet_connectivity():
        return False, False, None

    url = f"{api_base_url.rstrip('/')}/api/status/{drive_id}"
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            status = data.get('status', 'ACTIVE')
            if status == 'LOST':
                reason = data.get('lost_reason') or 'Drive marked as lost/revoked by owner.'
                clear_lease_token(lease_path=lease_path, vault_path=vault_path)
                return True, True, reason
            return True, False, None
    except Exception as e:
        logger.debug(f"Drive revocation check error: {e}")

    return False, False, None


# ──────────────────────────────────────────────────────────────────────────────
# Poll Request Status (used during approval wait)
# ──────────────────────────────────────────────────────────────────────────────

def poll_request_status(
    api_base_url: str,
    request_id: str,
    drive_id: str,
    fingerprint_hash: str,
    user_email: str,
    k_local: bytes,
    lease_path: Optional[Path] = None,
    vault_path: Optional[Path] = None,
    timeout: int = 10
) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Poll the backend for the status of a pending approval request.

    Returns:
        Tuple of (result, cloud_key_share, message)
        result is one of: 'PENDING', 'APPROVED', 'DENIED', 'ERROR'
    """
    url = f"{api_base_url.rstrip('/')}/api/request-status"

    try:
        response = requests.post(
            url,
            json={'request_id': request_id, 'drive_id': drive_id},
            timeout=timeout
        )
        data = response.json()
        status = data.get('status', '')

        if status == 'PENDING':
            return 'PENDING', None, 'Waiting for owner approval...'

        elif status == 'APPROVED':
            cloud_key_share = data.get('cloud_key_share', '')
            jwt_token       = data.get('lease_token', '')
            expires_at_unix = data.get('expires_at_unix', int(time.time()) + 7 * 86400)
            scope           = data.get('granted_scope', 'CUSTOM_LEASE')

            resolved_email = (data.get('user_email') or user_email or '').strip()

            # Save lease token into vault header (or fallback file)
            if cloud_key_share:
                save_lease_token(
                    lease_path       = lease_path,
                    k_local          = k_local,
                    drive_id         = drive_id,
                    fingerprint_hash = fingerprint_hash,
                    cloud_key_share  = cloud_key_share,
                    jwt_token        = jwt_token,
                    issued_at        = int(time.time()),
                    expires_at       = expires_at_unix,
                    user_email       = resolved_email,
                    vault_path       = vault_path
                )

            return 'APPROVED', cloud_key_share, f"Approved ({scope})"

        elif status == 'DENIED':
            return 'DENIED', None, 'Access request denied by drive owner.'

        else:
            return 'ERROR', None, f"Unknown status: {status}"

    except Exception as e:
        return 'ERROR', None, f"Poll error: {e}"


# ──────────────────────────────────────────────────────────────────────────────
# Offline Lease Validation
# ──────────────────────────────────────────────────────────────────────────────

def offline_lease_check(
    lease_path: Optional[Path],
    k_local: bytes,
    drive_id: str,
    current_fingerprint: str,
    vault_path: Optional[Path] = None
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validate the local lease token for offline access."""
    # Check if a lease envelope actually exists before loading
    has_envelope = False
    if vault_path and vault_path.exists():
        try:
            _ce = ce
            if _ce is None:
                import crypto_engine as _ce
            hdr = _ce.read_vault_header(vault_path)
            if hdr and hdr.get('lease'):
                has_envelope = True
        except Exception:
            pass
    if not has_envelope and lease_path and lease_path.exists():
        has_envelope = True

    lease = load_lease_token(lease_path, k_local, drive_id, vault_path=vault_path, fingerprint_hash=current_fingerprint)

    if lease is None:
        if has_envelope:
            # Lease envelope exists but cannot be decrypted by current machine's fingerprint -> mismatch
            clear_lease_token(lease_path=lease_path, vault_path=vault_path)
            return False, None, (
                "Hardware fingerprint mismatch. "
                "This lease was bound to a different machine and has been deleted. "
                "Please connect to the internet and authenticate online to register this device."
            )
        return False, None, (
            "No valid offline lease found. "
            "Connect to internet and authenticate online to create a lease."
        )

    now = int(time.time())

    # Check expiry
    expires_at = lease.get('expires_at', 0)
    if now >= expires_at:
        remaining = now - expires_at
        return False, None, (
            f"Offline lease EXPIRED {remaining // 3600}h {(remaining % 3600) // 60}m ago. "
            "Connect to the internet to renew access."
        )

    # Check fingerprint binding
    lease_fingerprint = lease.get('fingerprint', '')
    if current_fingerprint.lower() != lease_fingerprint.lower():
        # Clear invalid lease token
        clear_lease_token(lease_path=lease_path, vault_path=vault_path)

        return False, None, (
            "Hardware fingerprint mismatch. "
            "This lease was bound to a different machine and has been deleted. "
            "Please connect to the internet and authenticate online to register this device."
        )

    time_left  = expires_at - now
    days_left  = time_left // 86400
    hours_left = (time_left % 86400) // 3600
    cloud_key_share = lease.get('cloud_key_share')

    return True, cloud_key_share, (
        f"Offline access granted. Lease expires in {days_left}d {hours_left}h."
    )


# ──────────────────────────────────────────────────────────────────────────────
# Main Entry: Smart Auth (Online / Offline)
# Returns: (result, cloud_key_share, message, was_online, request_id)
# result: 'GRANTED' | 'LOCKED' | 'DENIED' | 'PENDING' | 'OFFLINE_GRANTED' | 'OFFLINE_DENIED'
# ──────────────────────────────────────────────────────────────────────────────

def authenticate(
    api_base_url: str,
    drive_id: str,
    fingerprint_hash: str,
    user_email: str,
    k_local: bytes,
    lease_path: Optional[Path] = None,
    vault_path: Optional[Path] = None,
    auth_token: Optional[str] = None
) -> Tuple[str, Optional[str], str, bool, Optional[str]]:
    """
    High-level authentication dispatcher.

    Returns:
        (result, cloud_key_share, message, was_online, request_id)
    """
    is_online = check_internet_connectivity()

    if is_online:
        logger.info("Network detected — attempting online authentication...")
        result, cks, message, request_id = online_auth(
            api_base_url, drive_id, fingerprint_hash, user_email,
            k_local, lease_path=lease_path, vault_path=vault_path,
            auth_token=auth_token
        )

        if result == 'GRANTED':
            return 'GRANTED', cks, message, True, None
        elif result == 'PENDING':
            return 'PENDING', None, message, True, request_id
        elif result == 'LOCKED':
            clear_lease_token(lease_path=lease_path, vault_path=vault_path)
            return 'LOCKED', None, message, True, None
        elif result == 'DENIED':
            return 'DENIED', None, message, True, None
        else:
            # Network error during online attempt — verify if drive was revoked
            is_net, is_rev, rev_msg = check_drive_revocation(
                api_base_url, drive_id, lease_path=lease_path, vault_path=vault_path
            )
            if is_net and is_rev:
                clear_lease_token(lease_path=lease_path, vault_path=vault_path)
                return 'LOCKED', None, f"Drive revoked on server: {rev_msg}", True, None

            # Try offline lease
            logger.info(f"Online auth failed ({message}), trying offline lease...")
            success, cks, offline_msg = offline_lease_check(
                lease_path, k_local, drive_id, fingerprint_hash, vault_path=vault_path
            )
            if success:
                return 'OFFLINE_GRANTED', cks, offline_msg, False, None

            # Combine the online failure reason with offline status so user knows why it failed
            combined_err = f"{message} (Offline check: {offline_msg})" if message else offline_msg
            return 'OFFLINE_DENIED', None, combined_err, False, None
    else:
        logger.info("No network — checking offline lease...")
        success, cks, msg = offline_lease_check(
            lease_path, k_local, drive_id, fingerprint_hash, vault_path=vault_path
        )
        if success:
            return 'OFFLINE_GRANTED', cks, msg, False, None
        return 'OFFLINE_DENIED', None, msg, False, None
