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

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

LEASE_FILENAME        = 'lease.tok'
LEASE_VERSION         = 2
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
    try:
        socket.setdefaulttimeout(timeout)
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, OSError):
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Lease Encryption Key Derivation
# ──────────────────────────────────────────────────────────────────────────────

def _derive_lease_key(k_local: bytes, drive_id: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=drive_id.encode('utf-8'),
        info=b'lease-token-key-v2',
        backend=default_backend()
    )
    return hkdf.derive(k_local)


# ──────────────────────────────────────────────────────────────────────────────
# Lease Token Storage
# ──────────────────────────────────────────────────────────────────────────────

def save_lease_token(
    lease_path: Path,
    k_local: bytes,
    drive_id: str,
    fingerprint_hash: str,
    cloud_key_share: str,
    jwt_token: str,
    issued_at: int,
    expires_at: int,
    user_email: str = ''
) -> None:
    """Encrypt and persist the lease token to lease.tok."""
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

    lease_key = _derive_lease_key(k_local, drive_id)
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

    lease_path.parent.mkdir(parents=True, exist_ok=True)
    lease_path.write_text(json.dumps(lease_envelope, indent=2), encoding='utf-8')
    logger.info(f"Lease token saved to: {lease_path}")


def load_lease_token(
    lease_path: Path,
    k_local: bytes,
    drive_id: str
) -> Optional[dict]:
    """Load and decrypt the lease token from lease.tok."""
    if not lease_path.exists():
        return None
    try:
        envelope = json.loads(lease_path.read_text(encoding='utf-8'))
        version  = envelope.get('v', 0)
        if version not in (1, 2):  # Accept v1 tokens for backwards compat
            return None

        nonce      = base64.b64decode(envelope['nonce'])
        tag        = base64.b64decode(envelope['tag'])
        ciphertext = base64.b64decode(envelope['data'])

        # Try v2 key first, fall back to v1
        for info_tag in (b'lease-token-key-v2', b'lease-token-key-v1'):
            try:
                hkdf = HKDF(
                    algorithm=hashes.SHA256(), length=KEY_SIZE,
                    salt=drive_id.encode('utf-8'), info=info_tag,
                    backend=default_backend()
                )
                lease_key = hkdf.derive(k_local)
                aesgcm    = AESGCM(lease_key)
                ct_with_tag = ciphertext + tag
                plaintext = aesgcm.decrypt(nonce, ct_with_tag, None)
                return json.loads(plaintext.decode('utf-8'))
            except Exception:
                continue
        return None

    except Exception as e:
        logger.warning(f"Lease token load/decrypt failed: {type(e).__name__}: {e}")
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Online Authentication Flow (v2: now handles PENDING_APPROVAL)
# ──────────────────────────────────────────────────────────────────────────────

def online_auth(
    api_base_url: str,
    drive_id: str,
    fingerprint_hash: str,
    user_email: str,
    k_local: bytes,
    lease_path: Path,
    timeout: int = 10
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

    try:
        response = requests.post(url, json=payload, timeout=timeout)
        data     = response.json()

        if response.status_code == 200 and data.get('status') == 'GRANTED':
            cloud_key_share = data['cloud_key_share']
            jwt_token       = data.get('lease_token', '')
            expires_at_unix = data.get('expires_at_unix', int(time.time()) + 7 * 86400)
            issued_at       = int(time.time())

            save_lease_token(
                lease_path       = lease_path,
                k_local          = k_local,
                drive_id         = drive_id,
                fingerprint_hash = fingerprint_hash,
                cloud_key_share  = cloud_key_share,
                jwt_token        = jwt_token,
                issued_at        = issued_at,
                expires_at       = expires_at_unix,
                user_email       = user_email
            )

            scope = data.get('trust_scope', 'LEASE')
            label = data.get('drive_label', '')
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
                return 'LOCKED', None, message, None
            return 'DENIED', None, message, None

        elif response.status_code == 404:
            return 'ERROR', None, 'Drive ID not registered on server.', None

        else:
            return 'ERROR', None, f"Server returned {response.status_code}", None

    except requests.exceptions.ConnectionError:
        return 'ERROR', None, f"Cannot connect to server at {api_base_url}", None
    except requests.exceptions.Timeout:
        return 'ERROR', None, "Server request timed out.", None
    except Exception as e:
        return 'ERROR', None, f"Authentication error: {e}", None


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
    lease_path: Path,
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

            # Save lease token for offline use
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
                    user_email       = user_email
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
    lease_path: Path,
    k_local: bytes,
    drive_id: str,
    current_fingerprint: str
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validate the local lease token for offline access."""
    lease = load_lease_token(lease_path, k_local, drive_id)

    if lease is None:
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
        return False, None, (
            "Hardware fingerprint mismatch. "
            "This lease is bound to a different machine."
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
    lease_path: Path
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
            k_local, lease_path
        )

        if result == 'GRANTED':
            return 'GRANTED', cks, message, True, None
        elif result == 'PENDING':
            return 'PENDING', None, message, True, request_id
        elif result == 'LOCKED':
            return 'LOCKED', None, message, True, None
        elif result == 'DENIED':
            return 'DENIED', None, message, True, None
        else:
            # Network error during online attempt — try offline
            logger.info("Online auth failed with error, trying offline lease...")
            success, cks, msg = offline_lease_check(
                lease_path, k_local, drive_id, fingerprint_hash
            )
            if success:
                return 'OFFLINE_GRANTED', cks, msg, False, None
            return 'OFFLINE_DENIED', None, msg, False, None
    else:
        logger.info("No network — checking offline lease...")
        success, cks, msg = offline_lease_check(
            lease_path, k_local, drive_id, fingerprint_hash
        )
        if success:
            return 'OFFLINE_GRANTED', cks, msg, False, None
        return 'OFFLINE_DENIED', None, msg, False, None


# ──────────────────────────────────────────────────────────────────────────────
# Lease Info Display (for CLI/debugging)
# ──────────────────────────────────────────────────────────────────────────────

def get_lease_info(lease_path: Path, k_local: bytes, drive_id: str) -> Optional[dict]:
    """Return lease info dict or None."""
    lease = load_lease_token(lease_path, k_local, drive_id)
    if not lease:
        return None

    now        = int(time.time())
    expires_at = lease.get('expires_at', 0)
    time_left  = expires_at - now

    return {
        'drive_id':    lease.get('drive_id', ''),
        'fingerprint': lease.get('fingerprint', ''),
        'user_email':  lease.get('user_email', ''),
        'issued_at':   lease.get('issued_at', 0),
        'expires_at':  expires_at,
        'is_expired':  now >= expires_at,
        'time_left_seconds': max(time_left, 0),
        'days_left':   max(time_left // 86400, 0),
        'hours_left':  max((time_left % 86400) // 3600, 0)
    }
