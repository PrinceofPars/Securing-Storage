"""
integration_test.py — USB Killswitch v2 End-to-End Integration Test
====================================================================
Tests the complete approval workflow:
  Register → Auth (unknown device → PENDING) → Dashboard Approve → Poll → GRANTED
  → Vault encrypt/decrypt roundtrip → Mark LOST → Auth blocked

Run from usb_client/ with backend running on localhost:3000.
"""
import sys, os, json, time, tempfile, shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import requests
import fingerprint as fp
import crypto_engine as ce
import lease_manager as lm

API_URL   = 'http://localhost:3000'
ADMIN_KEY = 'super_secret_admin_key_change_me'
HEADERS   = {'Content-Type': 'application/json', 'X-Admin-Key': ADMIN_KEY}

PASS = 0
FAIL = 0

def check(condition, name, detail=''):
    global PASS, FAIL
    if condition:
        print(f"    [PASS] {name}")
        PASS += 1
    else:
        print(f"    [FAIL] {name} -- {detail}")
        FAIL += 1

print("=" * 60)
print("  USB Killswitch v2 -- Integration Test Suite")
print("=" * 60)
print()

# ============================================================
# [0] Health Check
# ============================================================
print("[0] Health check...")
try:
    r = requests.get(f'{API_URL}/api/health', timeout=5)
    check(r.status_code == 200, "Backend reachable")
    check('2.0' in r.json().get('version', ''), f"Version is 2.x: {r.json().get('version')}")
except Exception as e:
    print(f"    [FAIL] Cannot reach backend: {e}")
    print("\n    Start the backend first: cd backend && node server.js")
    sys.exit(1)
print()

# ============================================================
# [1] Register Drive with Owner Email
# ============================================================
print("[1] Registering drive with owner email...")
r = requests.post(f'{API_URL}/api/register',
    json={'label': 'Test Drive v2', 'owner_email': 'owner@test.com'},
    headers=HEADERS, timeout=5)
check(r.status_code == 201, "Register returns 201")
data = r.json()
drive_id      = data['drive_id']
cloud_key_hex = data['cloud_key_share']
check(len(drive_id) == 36, f"drive_id is UUID: {drive_id[:8]}...")
check(data.get('owner_email') == 'owner@test.com', "owner_email recorded")
print()

# ============================================================
# [2] Key Generation & Vault Roundtrip
# ============================================================
print("[2] Key generation & vault encrypt/decrypt roundtrip...")
k_local       = ce.generate_local_key()
k_cloud_bytes = ce.hex_to_key_bytes(cloud_key_hex)

tmp_src = Path(tempfile.mkdtemp(prefix='v2_test_src_'))
(tmp_src / 'secret.txt').write_text('TOP SECRET v2 CONTENT', encoding='utf-8')
(tmp_src / 'data.json').write_text('{"version": 2}', encoding='utf-8')
subdir = tmp_src / 'nested'
subdir.mkdir()
(subdir / 'deep.md').write_text('# Deep nested file', encoding='utf-8')

vault_path = tmp_src.parent / 'v2_test_vault.enc'
stats = ce.encrypt_folder_to_vault(tmp_src, vault_path, k_local, k_cloud_bytes)
check(stats['files_encrypted'] == 3, f"Encrypted 3 files")
check(vault_path.exists(), "vault.enc created")

meta = ce.inspect_vault_header(vault_path)
check(meta is not None, "Vault header readable")
check(meta['file_count'] == 3, "Header reports 3 files")

shutil.rmtree(tmp_src)

temp_dec = ce.decrypt_vault_to_temp(vault_path, k_local, k_cloud_bytes)
check(temp_dec.exists(), "Temp dir created for decrypted files")
check('TOP SECRET v2' in (temp_dec / 'secret.txt').read_text(encoding='utf-8'), "Content decrypted correctly")
check('Deep nested file' in (temp_dec / 'nested' / 'deep.md').read_text(encoding='utf-8'), "Nested file decrypted")
wiped = ce.secure_wipe_temp(temp_dec)
check(wiped == 3, f"Wiped {wiped} files")
print()

# ============================================================
# [3] Owner Auth — First Auth Auto-Trusts Device
# ============================================================
print("[3] Owner authentication (auto-trusts first device)...")
fingerprint_hash = fp.generate_fingerprint()
lease_path = vault_path.parent / 'v2_test_lease.tok'

result, cks, msg, was_online, req_id = lm.authenticate(
    API_URL, drive_id, fingerprint_hash, 'owner@test.com', k_local, lease_path
)
# First auth from owner should either be GRANTED or PENDING (depending on if auto-trust is enabled)
# In v2, unknown devices go to PENDING, but the owner email IS in access list
check(result in ('GRANTED', 'PENDING'), f"Owner first auth result: {result}")

if result == 'PENDING':
    # Auto-approve for test
    print("    (First device needs approval -- approving via API...)")
    r = requests.post(f'{API_URL}/api/approve-request',
        json={'request_id': req_id, 'scope': 'FOREVER'},
        headers=HEADERS, timeout=5)
    check(r.status_code == 200, "Approval succeeds")

    # Poll for approved
    poll_result, cks, poll_msg = lm.poll_request_status(
        API_URL, req_id, drive_id, fingerprint_hash, 'owner@test.com', k_local, lease_path
    )
    check(poll_result == 'APPROVED', f"Poll returns APPROVED: {poll_msg}")
    check(cks is not None and len(cks) == 64, "Cloud key share received via poll")
else:
    check(cks == cloud_key_hex, "Cloud key share matches")

check(lease_path.exists(), "lease.tok created")
print()

# ============================================================
# [4] Re-auth — Trusted Device Gets GRANTED Immediately
# ============================================================
print("[4] Re-auth on trusted device (should be instant GRANTED)...")
result2, cks2, msg2, _, _ = lm.authenticate(
    API_URL, drive_id, fingerprint_hash, 'owner@test.com', k_local, lease_path
)
check(result2 == 'GRANTED', f"Trusted device gets GRANTED: {result2}")
print()

# ============================================================
# [5] Unknown Device — PENDING Approval Flow
# ============================================================
print("[5] Unknown device approval flow...")
fake_fp = 'b' * 64  # Different fingerprint

# Add a secondary user
r = requests.post(f'{API_URL}/api/sharing/add-user',
    json={'drive_id': drive_id, 'email': 'colleague@test.com'},
    headers=HEADERS, timeout=5)
check(r.status_code == 201, "Secondary user added to access list")

# Auth from unknown device
r2 = requests.post(f'{API_URL}/api/auth-host',
    json={'drive_id': drive_id, 'hardware_fingerprint': fake_fp, 'user_email': 'colleague@test.com'},
    timeout=5)
check(r2.status_code == 202, f"Unknown device gets 202 PENDING: {r2.status_code}")
pending_data = r2.json()
check(pending_data['status'] == 'PENDING_APPROVAL', "Status is PENDING_APPROVAL")
new_req_id = pending_data['request_id']
check(len(new_req_id) > 0, f"Request ID: {new_req_id}")

# Check pending requests via dashboard endpoint
r3 = requests.get(f'{API_URL}/api/dashboard/pending', headers=HEADERS, timeout=5)
check(r3.status_code == 200, "Dashboard pending endpoint works")
pending_list = r3.json().get('pending', [])
check(len(pending_list) >= 1, f"Pending list has {len(pending_list)} items")

# Poll — should be PENDING
poll_r, _, poll_m = lm.poll_request_status(
    API_URL, new_req_id, drive_id, fake_fp, 'colleague@test.com',
    k_local, lease_path
)
check(poll_r == 'PENDING', f"Poll returns PENDING: {poll_r}")

# Approve with 24-hour lease
r4 = requests.post(f'{API_URL}/api/approve-request',
    json={'request_id': new_req_id, 'scope': 'CUSTOM_LEASE', 'lease_hours': 24},
    headers=HEADERS, timeout=5)
check(r4.status_code == 200, f"Approval with CUSTOM_LEASE(24h) succeeds")

# Poll again — should be APPROVED now
fake_lease_path = vault_path.parent / 'v2_fake_lease.tok'
poll_r2, cks_new, poll_m2 = lm.poll_request_status(
    API_URL, new_req_id, drive_id, fake_fp, 'colleague@test.com',
    k_local, fake_lease_path
)
check(poll_r2 == 'APPROVED', f"Poll returns APPROVED: {poll_m2}")
check(cks_new is not None, "Cloud key share received in approval")
check(fake_lease_path.exists(), "Lease token saved for approved device")
fake_lease_path.unlink(missing_ok=True)
print()

# ============================================================
# [6] Deny Request Flow
# ============================================================
print("[6] Deny request flow...")
fake_fp2 = 'c' * 64
r5 = requests.post(f'{API_URL}/api/auth-host',
    json={'drive_id': drive_id, 'hardware_fingerprint': fake_fp2, 'user_email': 'colleague@test.com'},
    timeout=5)
check(r5.status_code == 202, "Another unknown device gets PENDING")
deny_req_id = r5.json()['request_id']

r6 = requests.post(f'{API_URL}/api/deny-request',
    json={'request_id': deny_req_id},
    headers=HEADERS, timeout=5)
check(r6.status_code == 200, "Deny request succeeds")

poll_r3, _, poll_m3 = lm.poll_request_status(
    API_URL, deny_req_id, drive_id, fake_fp2, 'colleague@test.com',
    k_local, lease_path
)
check(poll_r3 == 'DENIED', f"Poll returns DENIED: {poll_m3}")
print()

# ============================================================
# [7] Unauthorised Email Blocked
# ============================================================
print("[7] Unauthorised email blocked...")
r7 = requests.post(f'{API_URL}/api/auth-host',
    json={'drive_id': drive_id, 'hardware_fingerprint': fingerprint_hash, 'user_email': 'intruder@evil.com'},
    timeout=5)
check(r7.status_code == 403, "Unauthorised email gets 403")
check(r7.json().get('status') == 'DENIED', f"Status is DENIED: {r7.json().get('message')}")
print()

# ============================================================
# [8] Offline Lease Validation
# ============================================================
print("[8] Offline lease validation...")
ok, cks_offline, msg_offline = lm.offline_lease_check(
    lease_path, k_local, drive_id, fingerprint_hash
)
check(ok, f"Offline lease valid: {msg_offline}")

# Fingerprint mismatch
ok2, _, msg2 = lm.offline_lease_check(lease_path, k_local, drive_id, 'd' * 64)
check(not ok2, f"Fingerprint mismatch blocked: {msg2[:50]}")
print()

# ============================================================
# [9] Drive Status & Dashboard
# ============================================================
print("[9] Drive status & dashboard endpoints...")
r8 = requests.get(f'{API_URL}/api/status/{drive_id}', timeout=5)
check(r8.status_code == 200, "Status endpoint works")
status_data = r8.json()
check(status_data['status'] == 'ACTIVE', "Drive is ACTIVE")
check(status_data['owner_email'] == 'owner@test.com', "Owner email in status")
check(len(status_data.get('access_list', [])) >= 2, "Access list has owner + colleague")

r9 = requests.get(f'{API_URL}/api/dashboard/drives', headers=HEADERS, timeout=5)
check(r9.status_code == 200, "Dashboard drives endpoint works")
check(len(r9.json().get('drives', [])) >= 1, "At least 1 drive in dashboard")
print()

# ============================================================
# [10] Remote Kill Switch
# ============================================================
print("[10] Remote kill switch (mark as LOST)...")
r10 = requests.post(f'{API_URL}/api/mark-lost',
    json={'drive_id': drive_id, 'reason': 'Integration test kill v2'},
    headers=HEADERS, timeout=5)
check(r10.status_code == 200, "mark-lost returns 200")
check(r10.json()['status'] == 'LOST', "Drive status is LOST")
print()

# ============================================================
# [11] Auth Blocked After LOST
# ============================================================
print("[11] Auth blocked after kill switch...")
r11 = requests.post(f'{API_URL}/api/auth-host',
    json={'drive_id': drive_id, 'hardware_fingerprint': fingerprint_hash, 'user_email': 'owner@test.com'},
    timeout=5)
check(r11.status_code == 403, "LOST drive returns 403")
check(r11.json().get('status') == 'LOCKED', "Response status is LOCKED")
print()

# ============================================================
# [12] Reactivation
# ============================================================
print("[12] Drive reactivation...")
r12 = requests.post(f'{API_URL}/api/reactivate',
    json={'drive_id': drive_id},
    headers=HEADERS, timeout=5)
check(r12.status_code == 200, "Reactivation succeeds")
check(r12.json()['status'] == 'ACTIVE', "Drive is ACTIVE again")

# Verify status
r13 = requests.get(f'{API_URL}/api/status/{drive_id}', timeout=5)
check(r13.json()['status'] == 'ACTIVE', "Status confirms ACTIVE")
print()

# ============================================================
# Cleanup
# ============================================================
vault_path.unlink(missing_ok=True)
lease_path.unlink(missing_ok=True)

print("=" * 60)
print(f"  Results: {PASS} passed, {FAIL} failed")
if FAIL == 0:
    print("  ALL TESTS PASSED!")
else:
    print("  SOME TESTS FAILED -- review output above.")
print("=" * 60)
sys.exit(0 if FAIL == 0 else 1)
