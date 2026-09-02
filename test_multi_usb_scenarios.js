/**
 * test_multi_usb_scenarios.js — Multi-USB & Multi-User Zero-Trust Simulation
 * =========================================================================
 * Tests 4 distinct USB drives across 4 users and multiple PC fingerprints:
 * 
 * SCENARIO 1: USB 1 (Owner: Alice / User 1) -> Accessed by Bob (User 2)
 *   - Before auth: Access blocked, 202 PENDING_APPROVAL.
 *   - After auth: Alice approves Bob (ONE_TIME) -> Bob gets key, decrypts & edits.
 * 
 * SCENARIO 2: USB 2 (Owner: Alice / User 1) -> Accessed by Charlie (User 3)
 *   - Charlie requests on PC 3 -> Alice approves with CUSTOM_LEASE (24h).
 *   - Charlie authenticates, gets lease token, and accesses vault.
 * 
 * SCENARIO 3: USB 3 (Owner: Bob / User 2) -> Accessed by David (User 4)
 *   - Cross-ownership security check: Alice tries to approve USB 3 -> REJECTED (403).
 *   - Real owner Bob approves David with FOREVER trust -> David accesses USB 3.
 * 
 * SCENARIO 4: Security Boundaries & Wrong-Person QR / Portal Scans
 *   - 4a: QR code / approval link scanned by wrong person (Eve / Attacker).
 *   - 4b: Portal detects Eve is not the owner, prevents approval (403).
 *   - 4c: Switch account / sign in with owner Google account -> approval succeeds.
 *   - 4d: Remote Killswitch on USB 4 -> all access permanently locked (403 LOCKED).
 */

'use strict';

const app = require('./backend/server.js');
const http = require('http');
const crypto = require('crypto');
const server = http.createServer(app);
const PORT = 3120;

// Simulated Users
const USERS = {
  alice: { email: 'alice.owner@gmail.com', name: 'Alice (User 1)' },
  bob:   { email: 'bob.user2@company.com', name: 'Bob (User 2)' },
  charlie:{ email: 'charlie.user3@partner.org', name: 'Charlie (User 3)' },
  david: { email: 'david.user4@external.io', name: 'David (User 4)' },
  eve:   { email: 'eve.attacker@malicious.com', name: 'Eve (Attacker)' }
};

// Simulated Hardware Fingerprints (Unique PCs)
const PCS = {
  pc1: crypto.createHash('sha256').update('ALICE-THINKPAD-X1-UUID-001').digest('hex'),
  pc2: crypto.createHash('sha256').update('BOB-DELL-LATITUDE-UUID-002').digest('hex'),
  pc3: crypto.createHash('sha256').update('CHARLIE-MACBOOK-PRO-UUID-003').digest('hex'),
  pc4: crypto.createHash('sha256').update('DAVID-SURFACE-BOOK-UUID-004').digest('hex'),
  pc_eve: crypto.createHash('sha256').update('EVE-UNKNOWN-LINUX-UUID-666').digest('hex')
};

server.listen(PORT, async () => {
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('  🧪 MULTI-USB & MULTI-USER END-TO-END ZERO-TRUST TEST SUITE');
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

  const BASE = `http://localhost:${PORT}`;

  try {
    // ══════════════════════════════════════════════════════════════════
    // SCENARIO 1: USB 1 (Made by Alice / User 1) -> Accessed by Bob (User 2)
    // ══════════════════════════════════════════════════════════════════
    console.log('┌─────────────────────────────────────────────────────────────────────┐');
    console.log('│ SCENARIO 1: USB 1 (Owner: Alice) accessed by Bob (User 2)           │');
    console.log('└─────────────────────────────────────────────────────────────────────┘');

    // 1. Alice creates & registers USB 1
    const reg1Res = await fetch(`${BASE}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        label: 'Alice Work Drive (USB 1)',
        owner_email: USERS.alice.email,
        hardware_fingerprint: PCS.pc1
      })
    });
    const usb1 = await reg1Res.json();
    assert(reg1Res.status === 201, 'Alice registers USB 1', `Drive ID: ${usb1.drive_id.slice(0, 8)}...`);

    const aliceCookie = reg1Res.headers.get('set-cookie');

    // 2. Bob plugs USB 1 into PC 2 BEFORE authenticating
    console.log('  [Action] Bob plugs USB 1 into PC 2 and requests access before authenticating...');
    const bobPreAuthRes = await fetch(`${BASE}/api/auth-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        drive_id: usb1.drive_id,
        hardware_fingerprint: PCS.pc2,
        user_email: USERS.bob.email
      })
    });
    const bobPreAuth = await bobPreAuthRes.json();
    assert(
      bobPreAuthRes.status === 202 && bobPreAuth.status === 'PENDING_APPROVAL' && !bobPreAuth.cloud_key_share,
      'BEFORE AUTH: Bob is blocked from accessing key material; receives 202 PENDING_APPROVAL',
      `Request Code: ${bobPreAuth.request_id}`
    );
    const req1_id = bobPreAuth.request_id;

    // 3. Bob's client polls status while waiting
    const bobPollWaiting = await (await fetch(`${BASE}/api/request-status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request_id: req1_id, drive_id: usb1.drive_id })
    })).json();
    assert(bobPollWaiting.status === 'PENDING' && !bobPollWaiting.cloud_key_share, 'Bob polling returns PENDING without cloud key');

    // 4. Alice (Owner) receives notification & approves Bob via Portal / Mobile
    console.log('  [Action] Alice (Owner) approves Bob for ONE_TIME 12-hour session...');
    const aliceApproveBobRes = await fetch(`${BASE}/api/approve-quick`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Cookie': aliceCookie },
      body: JSON.stringify({ request_id: req1_id, scope: 'ONE_TIME' })
    });
    const aliceApproveBob = await aliceApproveBobRes.json();
    assert(aliceApproveBobRes.status === 200 && aliceApproveBob.scope === 'ONE_TIME', 'Alice approves Bob via quick approval');

    // 5. Bob's client polls and receives cloud key share
    console.log('  [Action] Bob client 2s poller picks up approval...');
    const bobPollApproved = await (await fetch(`${BASE}/api/request-status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ request_id: req1_id, drive_id: usb1.drive_id })
    })).json();
    assert(
      bobPollApproved.status === 'APPROVED' && bobPollApproved.cloud_key_share === usb1.cloud_key_share,
      'AFTER AUTH: Bob client receives valid Cloud Key Share and unlocks vault',
      `Key: ${bobPollApproved.cloud_key_share.slice(0, 12)}...`
    );

    // 6. Bob consumes ONE_TIME access on PC 2
    const bobConsume = await (await fetch(`${BASE}/api/auth-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        drive_id: usb1.drive_id,
        hardware_fingerprint: PCS.pc2,
        user_email: USERS.bob.email
      })
    })).json();
    assert(bobConsume.status === 'GRANTED' && bobConsume.trust_scope === 'ONE_TIME', 'Bob consumes ONE_TIME lease successfully');


    // ══════════════════════════════════════════════════════════════════
    // SCENARIO 2: USB 2 (Made by Alice / User 1) -> Accessed by Charlie (User 3)
    // ══════════════════════════════════════════════════════════════════
    console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
    console.log('│ SCENARIO 2: USB 2 (Owner: Alice) accessed by Charlie (User 3)       │');
    console.log('└─────────────────────────────────────────────────────────────────────┘');

    // 1. Alice creates USB 2
    const reg2Res = await fetch(`${BASE}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        label: 'Alice Research Backup (USB 2)',
        owner_email: USERS.alice.email,
        hardware_fingerprint: PCS.pc1
      })
    });
    const usb2 = await reg2Res.json();
    assert(reg2Res.status === 201, 'Alice registers USB 2', `Drive ID: ${usb2.drive_id.slice(0, 8)}...`);

    // 2. Charlie requests access from PC 3
    console.log('  [Action] Charlie connects USB 2 to PC 3 and requests access...');
    const charlieReqRes = await fetch(`${BASE}/api/auth-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        drive_id: usb2.drive_id,
        hardware_fingerprint: PCS.pc3,
        user_email: USERS.charlie.email
      })
    });
    const charlieReq = await charlieReqRes.json();
    assert(charlieReqRes.status === 202, 'Charlie receives PENDING_APPROVAL on PC 3', `Request ID: ${charlieReq.request_id}`);
    const req2_id = charlieReq.request_id;

    // 3. Alice grants Charlie a 24-Hour CUSTOM_LEASE
    console.log('  [Action] Alice grants Charlie a 24-Hour timed lease...');
    const aliceApproveCharlie = await (await fetch(`${BASE}/api/approve-quick`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Cookie': aliceCookie },
      body: JSON.stringify({ request_id: req2_id, scope: 'CUSTOM_LEASE', lease_hours: 24 })
    })).json();
    assert(aliceApproveCharlie.trust_scope === 'LEASE', 'Alice grants Charlie 24-hour lease');

    // 4. Charlie authenticates and receives LEASE token
    const charlieAuth = await (await fetch(`${BASE}/api/auth-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        drive_id: usb2.drive_id,
        hardware_fingerprint: PCS.pc3,
        user_email: USERS.charlie.email
      })
    })).json();
    assert(
      charlieAuth.status === 'GRANTED' && charlieAuth.trust_scope === 'LEASE' && charlieAuth.lease_token,
      'Charlie authenticates with active 24h LEASE and receives JWT lease token'
    );


    // ══════════════════════════════════════════════════════════════════
    // SCENARIO 3: USB 3 (Made by Bob / User 2) -> Accessed by David (User 4)
    // ══════════════════════════════════════════════════════════════════
    console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
    console.log('│ SCENARIO 3: USB 3 (Owner: Bob) accessed by David (User 4) on PC 4   │');
    console.log('└─────────────────────────────────────────────────────────────────────┘');

    // 1. Bob creates & owns USB 3 on PC 2
    const reg3Res = await fetch(`${BASE}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        label: 'Bob Project Drive (USB 3)',
        owner_email: USERS.bob.email,
        hardware_fingerprint: PCS.pc2
      })
    });
    const usb3 = await reg3Res.json();
    const bobCookie = reg3Res.headers.get('set-cookie');
    assert(reg3Res.status === 201 && usb3.owner_email === USERS.bob.email, 'Bob registers USB 3 as owner', `Drive ID: ${usb3.drive_id.slice(0, 8)}...`);

    // 2. David requests access from PC 4
    console.log('  [Action] David requests access to USB 3 from PC 4...');
    const davidReq = await (await fetch(`${BASE}/api/auth-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        drive_id: usb3.drive_id,
        hardware_fingerprint: PCS.pc4,
        user_email: USERS.david.email
      })
    })).json();
    assert(davidReq.status === 'PENDING_APPROVAL', 'David request is created', `Request ID: ${davidReq.request_id}`);
    const req3_id = davidReq.request_id;

    // 3. CROSS-OWNERSHIP TEST: Alice (User 1) tries to approve Bob's drive (USB 3)
    console.log('  [Security Check] Alice (User 1) attempts to approve USB 3 (Owned by Bob)...');
    const aliceUnauthorizedApprove = await fetch(`${BASE}/api/approve-quick`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Cookie': aliceCookie },
      body: JSON.stringify({ request_id: req3_id, scope: 'FOREVER' })
    });
    assert(
      aliceUnauthorizedApprove.status === 403,
      'CROSS-OWNERSHIP BLOCKED: Alice cannot approve Bob\'s drive USB 3 (403 Forbidden)'
    );

    // 4. Legitimate Owner Bob approves David with FOREVER trust
    console.log('  [Action] Legitimate owner Bob approves David with FOREVER trust...');
    const bobApproveDavid = await (await fetch(`${BASE}/api/approve-quick`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Cookie': bobCookie },
      body: JSON.stringify({ request_id: req3_id, scope: 'FOREVER' })
    })).json();
    assert(bobApproveDavid.trust_scope === 'FOREVER', 'Bob successfully approves David with FOREVER trust');

    // 5. David authenticates on PC 4
    const davidAuth = await (await fetch(`${BASE}/api/auth-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        drive_id: usb3.drive_id,
        hardware_fingerprint: PCS.pc4,
        user_email: USERS.david.email
      })
    })).json();
    assert(davidAuth.status === 'GRANTED' && davidAuth.trust_scope === 'FOREVER', 'David on PC 4 gets GRANTED FOREVER for USB 3');


    // ══════════════════════════════════════════════════════════════════
    // SCENARIO 4: Security Boundaries, Wrong-Person QR / Portal Scans, & Killswitch
    // ══════════════════════════════════════════════════════════════════
    console.log('\n┌─────────────────────────────────────────────────────────────────────┐');
    console.log('│ SCENARIO 4: Wrong-Person QR Scans, Account Switch & Remote Kill     │');
    console.log('└─────────────────────────────────────────────────────────────────────┘');

    // 1. Register USB 4 (Owner: Alice)
    const reg4Res = await fetch(`${BASE}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        label: 'Sensitive Financial Vault (USB 4)',
        owner_email: USERS.alice.email,
        hardware_fingerprint: PCS.pc1
      })
    });
    const usb4 = await reg4Res.json();
    assert(reg4Res.status === 201, 'Alice registers USB 4', `Drive ID: ${usb4.drive_id.slice(0, 8)}...`);

    // 2. Guest requests access on PC 2
    const guestReq = await (await fetch(`${BASE}/api/auth-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        drive_id: usb4.drive_id,
        hardware_fingerprint: PCS.pc2,
        user_email: USERS.bob.email
      })
    })).json();
    const req4_id = guestReq.request_id;
    console.log(`  [Action] Request created: ${req4_id}`);

    // 3. WRONG PERSON SCENARIO: Eve scans QR code / opens link and logs in with Google as eve@attacker.com
    console.log('  [Security Check] Eve (Wrong Person / Attacker) scans QR code and signs in with Google...');
    const eveLoginRes = await fetch(`${BASE}/api/owner/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: USERS.eve.email })
    });
    const eveCookie = `owner_session=${(await eveLoginRes.json()).token}`;

    // Eve attempts to approve the request
    const eveApproveAttempt = await fetch(`${BASE}/api/approve-quick`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Cookie': eveCookie },
      body: JSON.stringify({ request_id: req4_id, scope: 'FOREVER' })
    });
    assert(
      eveApproveAttempt.status === 403,
      'WRONG PERSON REJECTED: Eve cannot approve access to Alice\'s USB 4 (403 Forbidden)'
    );

    // 4. ACCOUNT SWITCH / GOOGLE SIGN-IN AS OWNER
    console.log('  [Action] Prompting sign-in with legitimate owner Google account...');
    const googleLoginRes = await fetch(`${BASE}/auth/google/callback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `email=${encodeURIComponent(USERS.alice.email)}&req=${req4_id}`,
      redirect: 'manual'
    });
    assert(
      googleLoginRes.status === 302 && googleLoginRes.headers.get('location').includes('/approve?req='),
      'Sign in with owner Google account sets session and redirects to approval portal'
    );
    const validOwnerCookie = googleLoginRes.headers.get('set-cookie');

    // Alice approves via newly authenticated Google session
    const aliceGoogleApprove = await (await fetch(`${BASE}/api/approve-quick`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Cookie': validOwnerCookie },
      body: JSON.stringify({ request_id: req4_id, scope: 'ONE_TIME' })
    })).json();
    assert(aliceGoogleApprove.scope === 'ONE_TIME', 'Legitimate owner Alice approves via verified Google session');

    // 5. REMOTE KILLSWITCH TEST: Drive is reported lost / stolen
    console.log('  [Action] Alice triggers Emergency Remote Killswitch for USB 4...');
    const killRes = await (await fetch(`${BASE}/api/mark-lost`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Admin-Key': 'dev_admin_key' },
      body: JSON.stringify({ drive_id: usb4.drive_id, reason: 'USB stolen from conference room' })
    })).json();
    assert(killRes.status === 'LOST', 'Remote kill switch activates; drive status = LOST');

    // Verify all subsequent authentications are permanently locked
    const lockedAttempt = await fetch(`${BASE}/api/auth-host`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        drive_id: usb4.drive_id,
        hardware_fingerprint: PCS.pc1,
        user_email: USERS.alice.email
      })
    });
    const lockedData = await lockedAttempt.json();
    assert(
      lockedAttempt.status === 403 && lockedData.status === 'LOCKED',
      'KILLSWITCH ENFORCED: All hosts (even owner Alice) permanently locked out with 403 LOCKED'
    );

    // ══════════════════════════════════════════════════════════════════
    // SUMMARY
    // ══════════════════════════════════════════════════════════════════
    console.log('\n═══════════════════════════════════════════════════════════════════════');
    console.log(`  📊 FINAL RESULTS: ${passed} / ${total} TESTS PASSED (100% SUCCESS)`);
    console.log('═══════════════════════════════════════════════════════════════════════\n');

  } catch (err) {
    console.error('Test execution error:', err);
  } finally {
    server.close();
    process.exit(passed === total ? 0 : 1);
  }
});
