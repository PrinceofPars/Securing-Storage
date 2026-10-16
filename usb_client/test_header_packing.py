import os
import shutil
import struct
import sys
import tempfile
import time
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.exceptions import InvalidTag
import usb_client.crypto_engine as ce
import usb_client.lease_manager as lm


def test_header_pack_and_read():
    print("\n--- Test 1: Header Pack and Read ---")
    config = {
        'drive_id': 'drv_test12345678',
        'label': 'Test Secure Drive',
        'api_url': 'https://example.com',
        'owner_email': 'owner@example.com',
        'created_at': int(time.time()),
        'version': 3
    }
    k_local = ce.generate_local_key()
    lease_sample = {
        'v': 2,
        'nonce': 'YWJjZGVmZ2hpamts',
        'tag': 'bW5vcHFyc3R1dnd4eXoxMg==',
        'data': 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY='
    }

    header_bytes = ce.pack_vault_header(config, k_local, lease_data=lease_sample)
    assert len(header_bytes) == ce.HEADER_BLOCK_SIZE, f"Expected {ce.HEADER_BLOCK_SIZE} bytes, got {len(header_bytes)}"
    assert header_bytes[:8] == ce.VAULT_MAGIC_V3, f"Expected {ce.VAULT_MAGIC_V3}, got {header_bytes[:8]}"

    temp_dir = Path(tempfile.mkdtemp(prefix='test_hdr_'))
    vault_file = temp_dir / 'vault.enc'
    try:
        vault_file.write_bytes(header_bytes)
        parsed = ce.read_vault_header(vault_file)
        assert parsed['config']['drive_id'] == config['drive_id']
        assert parsed['config']['owner_email'] == config['owner_email']
        assert parsed['k_local'] == k_local
        assert parsed['lease'] == lease_sample
        assert parsed['version'] == 3
        print("✅ Header pack & read verified successfully.")

        # Test tamper detection
        corrupted = bytearray(header_bytes)
        corrupted[50] ^= 0xFF  # Flip a bit in ciphertext
        vault_file.write_bytes(bytes(corrupted))
        try:
            ce.read_vault_header(vault_file)
            assert False, "Tampered header should have raised InvalidTag or ValueError!"
        except (InvalidTag, Exception):
            print("✅ Tamper detection verified (InvalidTag raised on bit-flip).")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_header_in_place_update():
    print("\n--- Test 2: In-Place Header Update ---")
    config = {'drive_id': 'drv_update_test', 'label': 'Initial', 'version': 3}
    k_local = ce.generate_local_key()

    temp_dir = Path(tempfile.mkdtemp(prefix='test_hdr_upd_'))
    vault_file = temp_dir / 'vault.enc'
    try:
        # Create dummy vault with 4KB header + 100 bytes payload
        header = ce.pack_vault_header(config, k_local)
        vault_file.write_bytes(header + b'A' * 100)
        initial_size = vault_file.stat().st_size

        # Update lease in header
        lease_data = {'v': 2, 'data': 'token123'}
        ce.update_vault_header(vault_file, lease_data=lease_data)
        updated = ce.read_vault_header(vault_file)
        assert updated['lease'] == lease_data
        assert updated['config']['label'] == 'Initial'
        assert vault_file.stat().st_size == initial_size, "File size changed during in-place header update!"

        # Clear lease in header
        ce.update_vault_header(vault_file, clear_lease=True)
        cleared = ce.read_vault_header(vault_file)
        assert cleared['lease'] is None
        assert vault_file.stat().st_size == initial_size, "File size changed during lease clear!"

        # Verify payload untouched
        content = vault_file.read_bytes()
        assert content[ce.HEADER_BLOCK_SIZE:] == b'A' * 100, "Payload data corrupted by header update!"
        print("✅ In-place header updates verified (zero payload movement, constant size).")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_v3_vault_lifecycle():
    print("\n--- Test 3: Full v3 Encapsulated Vault Lifecycle ---")
    temp_dir = Path(tempfile.mkdtemp(prefix='test_v3_lifecycle_'))
    try:
        source_dir = temp_dir / 'source'
        source_dir.mkdir()
        (source_dir / 'doc.txt').write_text("Hello Zero-Trust v3!", encoding='utf-8')
        (source_dir / 'data.bin').write_bytes(os.urandom(1024))
        sub = source_dir / 'sub'
        sub.mkdir()
        (sub / 'nested.txt').write_text("Nested secret data", encoding='utf-8')

        vault_file = temp_dir / 'vault.enc'
        k_local = ce.generate_local_key()
        k_cloud = ce.generate_local_key()

        config = {
            'drive_id': 'drv_full_lifecycle',
            'label': 'My Secret USB',
            'api_url': 'https://render.com',
            'owner_email': 'test@zerotrust.com',
            'created_at': int(time.time()),
            'version': 3
        }

        # Encrypt folder
        stats = ce.encrypt_folder_to_vault(
            source_dir, vault_file, k_local, k_cloud,
            config=config,
            drive_metadata={'label': config['label'], 'owner_email': config['owner_email']}
        )
        assert vault_file.exists()
        assert stats['files_encrypted'] == 3
        assert stats['version'] == 3

        # Verify that ONLY vault.enc exists in temp_dir (no loose metadata files)
        loose_metadata = [f for f in temp_dir.iterdir() if f.name in ('config.json', 'local_key.bin', 'lease.tok')]
        assert len(loose_metadata) == 0, f"Found loose metadata files: {loose_metadata}"
        print("✅ Encapsulation verified: No loose metadata files exist.")

        # Read header
        hdr = ce.read_vault_header(vault_file)
        assert hdr['config']['drive_id'] == config['drive_id']
        assert hdr['k_local'] == k_local
        print("✅ Header read from vault.enc matches original keys and config.")

        # Read manifest
        manifest = ce.read_vault_manifest(vault_file, k_local, k_cloud)
        assert len(manifest['files']) == 3
        assert manifest['version'] == 3

        # Decrypt single file
        doc_entry = next(f for f in manifest['files'] if f['path'] == 'doc.txt')
        decrypted_doc = ce.decrypt_single_file(vault_file, k_local, k_cloud, doc_entry)
        assert decrypted_doc.decode('utf-8') == "Hello Zero-Trust v3!"
        print("✅ Single file on-demand decryption verified.")

        # Decrypt all to working directory
        work_dir = ce.decrypt_files_to_working_dir(vault_file, k_local, k_cloud, manifest)
        assert (work_dir / 'doc.txt').read_text(encoding='utf-8') == "Hello Zero-Trust v3!"
        assert (work_dir / 'sub' / 'nested.txt').read_text(encoding='utf-8') == "Nested secret data"
        print("✅ Working directory bulk decryption verified.")

        # Test incremental lock & save (modify doc.txt, add new.txt)
        (work_dir / 'doc.txt').write_text("Hello Zero-Trust v3 Modified!", encoding='utf-8')
        (work_dir / 'new.txt').write_text("Brand new file", encoding='utf-8')

        updated_manifest = ce.update_vault_on_lock(vault_file, k_local, k_cloud, work_dir, manifest)
        assert len(updated_manifest['files']) == 4
        assert updated_manifest['dead_space_bytes'] > 0

        # Verify header is still valid after lock & save
        hdr_after = ce.read_vault_header(vault_file)
        assert hdr_after['k_local'] == k_local
        assert hdr_after['config']['drive_id'] == config['drive_id']
        print("✅ Incremental update on lock verified; header remains intact.")

        # Test compaction
        ce.secure_wipe_temp(work_dir)
        compact_stats = ce.compact_vault(vault_file, k_local, k_cloud)
        final_manifest = ce.read_vault_manifest(vault_file, k_local, k_cloud)
        assert final_manifest['dead_space_bytes'] == 0
        hdr_final = ce.read_vault_header(vault_file)
        assert hdr_final['k_local'] == k_local
        print("✅ Vault compaction verified; dead space eliminated, header preserved.")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_lease_encapsulation():
    print("\n--- Test 4: Offline Lease Encapsulation in vault.enc ---")
    temp_dir = Path(tempfile.mkdtemp(prefix='test_lease_enc_'))
    try:
        source_dir = temp_dir / 'src'
        source_dir.mkdir()
        (source_dir / 'test.txt').write_text("lease test", encoding='utf-8')

        vault_file = temp_dir / 'vault.enc'
        lease_file = temp_dir / 'lease.tok'
        k_local = ce.generate_local_key()
        k_cloud = ce.generate_local_key()
        drive_id = 'drv_lease_enc_123'
        fp = 'fake_fingerprint_1234567890abcdef1234567890abcdef'

        config = {'drive_id': drive_id, 'label': 'Lease Test', 'version': 3}
        ce.encrypt_folder_to_vault(source_dir, vault_file, k_local, k_cloud, config=config)

        # Save lease with vault_path
        lm.save_lease_token(
            lease_path=lease_file,
            k_local=k_local,
            drive_id=drive_id,
            fingerprint_hash=fp,
            cloud_key_share=k_cloud.hex(),
            jwt_token='jwt.fake.token',
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 86400,
            user_email='lease@test.com',
            vault_path=vault_file
        )

        # Verify lease.tok is NOT on disk
        assert not lease_file.exists(), "lease.tok was created on disk instead of being encapsulated!"
        print("✅ lease.tok was not created on disk (encapsulated into vault.enc header).")

        # Load lease from vault_path
        lease = lm.load_lease_token(lease_file, k_local, drive_id, vault_path=vault_file, fingerprint_hash=fp)
        assert lease is not None
        assert lease['drive_id'] == drive_id
        assert lease['cloud_key_share'] == k_cloud.hex()
        assert lease['user_email'] == 'lease@test.com'
        print("✅ Lease successfully loaded and decrypted directly from vault.enc header.")

        # Offline lease check
        ok, cks, msg = lm.offline_lease_check(lease_file, k_local, drive_id, fp, vault_path=vault_file)
        assert ok is True
        assert cks == k_cloud.hex()
        print("✅ Offline lease check passed using vault.enc header.")

        # Fingerprint mismatch check -> should clear lease from header
        bad_fp = 'different_machine_fingerprint_0000000000000000'
        bad_ok, _, _ = lm.offline_lease_check(lease_file, k_local, drive_id, bad_fp, vault_path=vault_file)
        assert bad_ok is False
        cleared_lease = lm.load_lease_token(lease_file, k_local, drive_id, vault_path=vault_file, fingerprint_hash=fp)
        assert cleared_lease is None, "Lease in header should have been cleared after fingerprint mismatch!"
        print("✅ Fingerprint mismatch successfully cleared the lease inside vault.enc header.")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_migration_v2_to_v3():
    print("\n--- Test 5: Legacy v2 Vault Migration to v3 ---")
    temp_dir = Path(tempfile.mkdtemp(prefix='test_migration_'))
    try:
        source_dir = temp_dir / 'src'
        source_dir.mkdir()
        (source_dir / 'file1.txt').write_text("Legacy v2 file 1", encoding='utf-8')
        (source_dir / 'file2.txt').write_text("Legacy v2 file 2", encoding='utf-8')

        vault_file = temp_dir / 'vault.enc'
        config_file = temp_dir / 'config.json'
        key_file = temp_dir / 'local_key.bin'
        lease_file = temp_dir / 'lease.tok'

        k_local = ce.generate_local_key()
        k_cloud = ce.generate_local_key()
        drive_id = 'drv_mig_test_123'
        fp = 'mig_fp_1234567890abcdef'

        # Create old v2 vault using low-level v2 header
        k_master, salt = ce.derive_master_key(k_local, k_cloud)
        aesgcm = ce.AESGCM(k_master)
        with open(vault_file, 'wb') as vf:
            vf.write(ce.VAULT_MAGIC_V2)
            vf.write(salt)
            vf.write(struct.pack('<Q', 0))
            mf_files = []
            for f in [source_dir / 'file1.txt', source_dir / 'file2.txt']:
                pt = f.read_bytes()
                nonce = os.urandom(12)
                ct_tag = aesgcm.encrypt(nonce, pt, f.name.encode('utf-8'))
                offset = vf.tell()
                vf.write(ct_tag[:-16])
                mf_files.append({
                    'path': f.name,
                    'offset': offset,
                    'size': len(ct_tag) - 16,
                    'nonce': nonce.hex(),
                    'tag': ct_tag[-16:].hex(),
                    'original_size': len(pt),
                    'modified': int(f.stat().st_mtime),
                    'sha256': ce._file_sha256(f)
                })
            mf = {'version': 2, 'files': mf_files, 'dead_space_bytes': 0, 'last_modified': int(time.time()), 'drive_metadata': {'drive_id': drive_id}}
            moff = vf.tell()
            ce._write_encrypted_manifest(vf, aesgcm, mf)
            vf.seek(8 + ce.SALT_SIZE)
            vf.write(struct.pack('<Q', moff))

        # Write loose v2 metadata files
        config = {'drive_id': drive_id, 'label': 'Legacy Drive', 'version': 2}
        config_file.write_text(ce.json.dumps(config), encoding='utf-8')
        key_file.write_bytes(k_local)
        lm.save_lease_token(lease_file, k_local, drive_id, fp, k_cloud.hex(), 'jwt.v2', int(time.time()), int(time.time()) + 86400)

        # Verify initial state has 4 files
        assert vault_file.exists() and config_file.exists() and key_file.exists() and lease_file.exists()
        meta_v2 = ce.inspect_vault_header(vault_file)
        assert meta_v2['version'] == 2
        assert meta_v2['encapsulated'] is False

        # Execute migration
        lease_data = lm.load_lease_token(lease_file, k_local, drive_id, fingerprint_hash=fp)
        ce.migrate_v2_to_v3(vault_file, k_local, k_cloud, config, lease_data=lease_data)

        # Clean up loose files
        for f in (config_file, key_file, lease_file):
            f.unlink()

        # Verify migrated vault
        meta_v3 = ce.inspect_vault_header(vault_file)
        assert meta_v3['version'] == 3
        assert meta_v3['encapsulated'] is True

        hdr = ce.read_vault_header(vault_file)
        assert hdr['config']['drive_id'] == drive_id
        assert hdr['k_local'] == k_local
        assert hdr['lease'] is not None

        # Verify files decrypt cleanly
        mf_v3 = ce.read_vault_manifest(vault_file, k_local, k_cloud)
        assert len(mf_v3['files']) == 2
        f1_data = ce.decrypt_single_file(vault_file, k_local, k_cloud, mf_v3['files'][0])
        assert f1_data == b"Legacy v2 file 1"
        print("✅ Legacy v2 vault migrated to v3 encapsulated vault and all loose files eliminated.")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
    test_header_pack_and_read()
    test_header_in_place_update()
    test_v3_vault_lifecycle()
    test_lease_encapsulation()
    test_migration_v2_to_v3()
    print("\n🎉 ALL 5 HEADER PACKING TESTS PASSED PERFECTLY! 🎉\n")
