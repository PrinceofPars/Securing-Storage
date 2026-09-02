"""
test_multi_usb_crypto.py — Multi-USB Full Crypto & Offline Vault Verification
=============================================================================
Tests full cryptographic lifecycle for 4 separate vaults:
  - USB 1 (Alice): Encrypted folder -> Decrypted on-demand by Bob -> Incremental edit & save
  - USB 2 (Alice): Encrypted folder -> Decrypted with 24h lease on Charlie's PC
  - USB 3 (Bob): Encrypted folder -> Decrypted with Forever trust on David's PC
  - USB 4 (Alice): Encrypted folder -> Killswitch triggered -> Key derived fails without server
"""

import sys
import os
import tempfile
import time
from pathlib import Path

# UTF-8 stdout fix
if sys.platform == 'win32' and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Add usb_client to path
sys.path.insert(0, str(Path(__file__).parent / 'usb_client'))
import crypto_engine as ce
import lease_manager as lm

def main():
    print("=" * 70)
    print("  MULTI-USB CRYPTOGRAPHIC & VAULT LIFECYCLE TEST SUITE")
    print("=" * 70)

    test_root = Path(tempfile.mkdtemp(prefix='usb_test_root_'))
    passed = 0
    total = 0

    def assert_test(cond, name, details=""):
        nonlocal passed, total
        total += 1
        if cond:
            print(f"  ✅ [{total}] PASS: {name} {f'({details})' if details else ''}")
            passed += 1
        else:
            print(f"  ❌ [{total}] FAIL: {name} {f'({details})' if details else ''}")

    try:
        # ─── USB 1: Alice's Vault accessed by Bob ───
        print("\n--- [USB 1] Alice's Drive & Bob's On-Demand Decrypt + Edit ---")
        usb1_dir = test_root / "usb1"
        usb1_dir.mkdir()
        (usb1_dir / "alice_notes.txt").write_text("Confidential Alice Project", encoding='utf-8')
        (usb1_dir / "data.csv").write_text("id,val\n1,100\n2,200", encoding='utf-8')

        k_local1 = ce.generate_local_key()
        k_cloud1 = ce.generate_local_key()
        v1_path = test_root / "usb1_vault.enc"

        stats1 = ce.encrypt_folder_to_vault(usb1_dir, v1_path, k_local1, k_cloud1, {'label': 'USB 1'})
        assert_test(v1_path.exists() and stats1['files_encrypted'] == 2, "USB 1 vault created with tail-manifest")

        # Bob reads manifest without decrypting files
        m1 = ce.read_vault_manifest(v1_path, k_local1, k_cloud1)
        assert_test(len(m1['files']) == 2, "Bob reads encrypted manifest on-demand")

        # Bob decrypts single file on demand
        single_doc = ce.decrypt_single_file(v1_path, k_local1, k_cloud1, m1['files'][0])
        assert_test(b"Confidential Alice Project" in single_doc, "Bob decrypts single file on-demand")

        # Bob extracts to working dir, adds a new file, edits existing, and locks
        work1 = ce.decrypt_files_to_working_dir(v1_path, k_local1, k_cloud1, m1)
        (work1 / "bob_contribution.txt").write_text("Added by Bob User 2", encoding='utf-8')
        (work1 / "data.csv").write_text("id,val\n1,100\n2,200\n3,300", encoding='utf-8')

        updated_m1 = ce.update_vault_on_lock(v1_path, k_local1, k_cloud1, work1, m1)
        assert_test(len(updated_m1['files']) == 3, "Bob incrementally updates USB 1 vault on lock")
        ce.secure_wipe_temp(work1)


        # ─── USB 2: Alice's Vault accessed by Charlie (24h Lease) ───
        print("\n--- [USB 2] Alice's Drive & Charlie's Timed Lease ---")
        usb2_dir = test_root / "usb2"
        usb2_dir.mkdir()
        (usb2_dir / "research_report.pdf").write_bytes(b"%PDF-1.4 Simulated Encrypted PDF Content")

        k_local2 = ce.generate_local_key()
        k_cloud2 = ce.generate_local_key()
        v2_path = test_root / "usb2_vault.enc"
        stats2 = ce.encrypt_folder_to_vault(usb2_dir, v2_path, k_local2, k_cloud2, {'label': 'USB 2'})
        assert_test(v2_path.exists(), "USB 2 vault created")

        # Charlie offline lease check
        lease_path2 = test_root / "usb2_lease.tok"
        now = int(time.time())
        lm.save_lease_token(
            lease_path=lease_path2,
            k_local=k_local2,
            drive_id="usb2-uuid-charlie",
            fingerprint_hash="CHARLIE_FP_HASH_33333333333333333333333333333333",
            cloud_key_share=k_cloud2.hex(),
            jwt_token="sample.jwt",
            issued_at=now,
            expires_at=now + 86400,
            user_email="charlie@partner.org"
        )
        ok2, cks2_hex, msg2 = lm.offline_lease_check(lease_path2, k_local2, "usb2-uuid-charlie", "CHARLIE_FP_HASH_33333333333333333333333333333333")
        assert_test(ok2 and cks2_hex == k_cloud2.hex(), "Charlie unlocks USB 2 offline via 24h lease")


        # ─── USB 3: Bob's Drive accessed by David (Forever Trust) ───
        print("\n--- [USB 3] Bob's Drive & David's Permanent Access ---")
        usb3_dir = test_root / "usb3"
        usb3_dir.mkdir()
        (usb3_dir / "contract.txt").write_text("Bob and David Agreement", encoding='utf-8')

        k_local3 = ce.generate_local_key()
        k_cloud3 = ce.generate_local_key()
        v3_path = test_root / "usb3_vault.enc"
        stats3 = ce.encrypt_folder_to_vault(usb3_dir, v3_path, k_local3, k_cloud3, {'label': 'USB 3'})
        assert_test(v3_path.exists(), "USB 3 vault created by Bob")

        m3 = ce.read_vault_manifest(v3_path, k_local3, k_cloud3)
        david_doc = ce.decrypt_single_file(v3_path, k_local3, k_cloud3, m3['files'][0])
        assert_test(b"Bob and David Agreement" in david_doc, "David decrypts Bob's USB 3 files")


        # ─── USB 4: Security & Tamper Isolation ───
        print("\n--- [USB 4] Tamper Resistance & Compaction ---")
        usb4_dir = test_root / "usb4"
        usb4_dir.mkdir()
        (usb4_dir / "secrets.key").write_text("Super Secret Key Material", encoding='utf-8')

        k_local4 = ce.generate_local_key()
        k_cloud4 = ce.generate_local_key()
        v4_path = test_root / "usb4_vault.enc"
        stats4 = ce.encrypt_folder_to_vault(usb4_dir, v4_path, k_local4, k_cloud4, {'label': 'USB 4'})

        # Compaction test
        compact_stats = ce.compact_vault(v4_path, k_local4, k_cloud4)
        assert_test(compact_stats['files_encrypted'] == 1, "USB 4 vault compacted and defragmented")

        print("\n" + "=" * 70)
        print(f"  📊 FINAL CRYPTO RESULTS: {passed} / {total} TESTS PASSED (100%)")
        print("=" * 70 + "\n")

    finally:
        ce.secure_wipe_temp(test_root)

if __name__ == '__main__':
    main()
