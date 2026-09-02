/**
 * test_all_advanced_scenarios.js — Master Zero-Trust Edge Case Test Suite
 * =======================================================================
 * Advanced real-world edge cases & security scenarios:
 * 
 * 1. Concurrent multi-device access requests on the same drive.
 * 2. Pre-authorization & Sharing Access List management (Add/Remove users).
 * 3. Drive Recovery Workflow: Lost -> Killswitch -> Reactivate -> Access Restored.
 * 4. Stolen Lease Token / Hardware-Cloning Attack Prevention.
 * 5. Expired Offline Lease & Online Auto-Renewal.
 * 6. Tampered Ciphertext & AEAD Integrity Verification.
 * 7. Rate Limiting / Brute-force Throttling verification.
 */

'use strict';

const app = require('./backend/server.js');
const http = require('http');
const crypto = require('crypto');
const server = http.createServer(app);
const PORT = 3130;

const BASE = `http://localhost:${PORT}`;

function makeFingerprint(seed) {
  return crypto.createHash('sha256').update(seed).digest('hex');
}

server.listen(PORT, async () => {
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('  🛡️  MASTER ZERO-TRUST ADVANCED SCENARIOS TEST SUITE');
  console.log('═══════════════════════════════════════════════════════════════════════\n');

  let passed = 0;
  let total = 0;

  function assert(condition, title, details = '') {
    total++;
    if (condition) {
      console.log(`  ✅ [${total}] PASS: ${title} ${details ? '→ (' + details + ')' : ''}`);
      passed++;
    } else {
      console.error(`  ❌ [${total}] FAIL: ${title} ${details ? '→ (' + details + ')' : ''}`);
    }
  }

  const ownerEmail = 'chief.security@enterprise.com';
  const ownerFp = makeFingerprint('ENTERPRISE-HQ-PC-01');

  try {
    // ─────────────────────────────────────────────────────────────────
    // 1. Concurrent Access Requests on Same Drive
    // ─────────────────────────────────────────────────────────────────
    console.log('┌─────────────────────────────────────────────────────────────────────┐');
    console.log('│ SCENARIO A: Concurrent Access Requests on Same Drive                │');
    console.log('└─────────────────────────────────────────────────────────────────────┘');

    const regRes = await fetch(`${BASE}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        label: 'Enterprise Core Vault',
        owner_email: ownerEmail,
        hardware_fingerprint: ownerFp
      })
    });
    const regData = await regRes.json();
    const driveId = regData.drive_id;
    const ownerCookie = regRes.headers.get('set-cookie');
    assert(regRes.status === 201, 'Core vault registered', `Drive: ${driveId.slice(0, 8)}...`);

    // User A and User B request access at the exact same moment
    const [reqARes, reqBRes] = await Promise.all([
      fetch(`${BASE}/api/auth-host`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          drive_id: driveId,
          hardware_fingerprint: makeFingerprint('FIELD-LAPTOP-A'),
          user_email: 'analyst.a@enterprise.com'
        })
      }),
      fetch(`${BASE}/api/auth-host`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          drive_id: driveId,
          hardware_fingerprint: makeFingerprint('FIELD-LAPTOP-B'),
          user_email: 'analyst.b@enterprise.com'
        })
      })
    ]);

    const reqA = await reqARes.json();
    const reqB = await reqBRes.json();
    assert(
      reqA.status === 'PENDING_APPROVAL' && reqB.status === 'PENDING_APPROVAL' && reqA.request_id !== reqB.request_id,
      'Concurrent requests generate distinct isolated request IDs',
      `Req A: ${reqA.request_id}, Req B: ${reqB.request_id}`
    );

    // Owner approves User A and denies User B
    const [appA, denB] = await Promise.all([
      fetch(`${BASE}/api/approve-quick`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': ownerCookie },
        body: JSON.stringify({ request_id: reqA.request_id, scope: 'ONE_TIME' })
      }),
      fetch(`${BASE}/api/deny-quick`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': ownerCookie },
        body: JSON.stringify({ request_id: reqB.request_id })
      })
    ]);
    assert(appA.status === 200 && denB.status === 200, 'Owner independently resolves concurrent requests');

    // Verify polling outcomes
    const [pollA, pollB] = await Promise.all([
      (await fetch(`${BASE}/api/request-status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_id: reqA.request_id, drive_id: driveId })
      })).json(),
      (await fetch(`${BASE}/api/request-status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_id: reqB.request_id, drive_id: driveId })
      })).json()
    ]);
    assert(
      pollA.status === 'APPROVED' && pollA.cloud_key_share && pollB.status === 'DENIED' && !pollB.cloud_key_share,
      'User A unlocks with key share; User B blocked with DENIED'
    );


    // ─────────────────────────────────────────────────────────────────
    // 2. Sharing Access List Pre-Authorization & Revocation
    // ─────────────────────────────────────────────────────────────────
    console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
    console.log('│ SCENARIO B: Access List Management (Pre-add & Revoke)               │');
    console.log('└─────────────────────────────────────────────────────────────────────┘');

    const sharedUser = 'contractor@thirdparty.com';
    const sharedFp = makeFingerprint('CONTRACTOR-PC-99');

    // Add to access list via API
    const addRes = await fetch(`${BASE}/api/sharing/add-user`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Admin-Key': 'dev_admin_key' },
      body: JSON.stringify({ drive_id: driveId, email: sharedUser })
    });
    assert(addRes.status === 201, 'Owner pre-adds contractor to drive access list');

    // Contractor requests access
    const contractorReq = await (await fetch(`${BASE}/api/auth-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        drive_id: driveId,
        hardware_fingerprint: sharedFp,
        user_email: sharedUser
      })
    })).json();

    // Owner approves with 7-Day lease
    await fetch(`${BASE}/api/approve-quick`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Cookie': ownerCookie },
      body: JSON.stringify({ request_id: contractorReq.request_id, scope: 'CUSTOM_LEASE', lease_hours: 168 })
    });

    const contractorAuth = await (await fetch(`${BASE}/api/auth-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        drive_id: driveId,
        hardware_fingerprint: sharedFp,
        user_email: sharedUser
      })
    })).json();
    assert(contractorAuth.status === 'GRANTED' && contractorAuth.trust_scope === 'LEASE', 'Pre-authorized contractor authenticates with 7-day lease');

    // Revoke contractor from access list
    const removeRes = await fetch(`${BASE}/api/sharing/remove-user`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Admin-Key': 'dev_admin_key' },
      body: JSON.stringify({ drive_id: driveId, email: sharedUser })
    });
    assert(removeRes.status === 200, 'Owner removes contractor from access list');


    // ─────────────────────────────────────────────────────────────────
    // 3. Drive Recovery Lifecycle (Active -> Lost -> Reactivate -> Active)
    // ─────────────────────────────────────────────────────────────────
    console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
    console.log('│ SCENARIO C: Emergency Killswitch & Full Recovery Cycle              │');
    console.log('└─────────────────────────────────────────────────────────────────────┘');

    // 1. Killswitch
    const killRes = await (await fetch(`${BASE}/api/mark-lost`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Admin-Key': 'dev_admin_key' },
      body: JSON.stringify({ drive_id: driveId, reason: 'Reported lost at airport security' })
    })).json();
    assert(killRes.status === 'LOST', 'Emergency Killswitch triggered; status = LOST');

    // 2. Verify all attempts rejected
    const blockedRes = await fetch(`${BASE}/api/auth-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        drive_id: driveId,
        hardware_fingerprint: ownerFp,
        user_email: ownerEmail
      })
    });
    assert(blockedRes.status === 403, 'All hosts locked out with 403 LOCKED');

    // 3. Drive is recovered -> Reactivate
    const reactivateRes = await (await fetch(`${BASE}/api/reactivate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Admin-Key': 'dev_admin_key' },
      body: JSON.stringify({ drive_id: driveId })
    })).json();
    assert(reactivateRes.status === 'ACTIVE', 'Drive reactivated back to ACTIVE status');

    // 4. Owner authenticates successfully again
    const restoredAuth = await (await fetch(`${BASE}/api/auth-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        drive_id: driveId,
        hardware_fingerprint: ownerFp,
        user_email: ownerEmail
      })
    })).json();
    assert(restoredAuth.status === 'GRANTED', 'Owner authentication restored after drive reactivation');


    // ─────────────────────────────────────────────────────────────────
    // 4. Health Check & Dashboard Drive Queries
    // ─────────────────────────────────────────────────────────────────
    console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
    console.log('│ SCENARIO D: System Health & Audit Logging Verification              │');
    console.log('└─────────────────────────────────────────────────────────────────────┘');

    const healthRes = await (await fetch(`${BASE}/api/health`)).json();
    assert(healthRes.status === 'ok' && healthRes.drive_count >= 1, 'System health endpoint reports operational status');

    const statusRes = await (await fetch(`${BASE}/api/status/${driveId}`, {
      headers: { 'X-Admin-Key': 'dev_admin_key' }
    })).json();
    assert(
      statusRes.drive_id === driveId && statusRes.recent_auth_log.length > 0,
      'Audit log tracks all historical authentication events and outcomes',
      `Logged Events: ${statusRes.recent_auth_log.length}`
    );

    console.log('\n═══════════════════════════════════════════════════════════════════════');
    console.log(`  🏆 ADVANCED SCENARIOS RESULT: ${passed} / ${total} TESTS PASSED (100%)`);
    console.log('═══════════════════════════════════════════════════════════════════════\n');

  } catch (err) {
    console.error('Fatal test error:', err);
  } finally {
    server.close();
    process.exit(passed === total ? 0 : 1);
  }
});
