/**
 * ============================================================
 * USB Killswitch v2 — Identity & Key Management Backend
 * ============================================================
 *
 * Features:
 *  - Multi-user identity model with owner_email + access_list
 *  - Out-of-band device approval workflow (PENDING → Dashboard → Client)
 *  - Flexible trust scopes: ONE_TIME, LEASE (N-hour), FOREVER
 *  - Web admin dashboard served at /dashboard
 *  - JWT-signed lease tokens with hardware fingerprint binding
 *  - SQLite persistence with WAL mode
 *  - Rate limiting, audit logging, admin key auth
 *
 * API Endpoints:
 *  POST /api/register            — Register new drive with owner_email
 *  POST /api/auth-host           — Authenticate drive + fingerprint + email
 *  POST /api/request-status      — Poll pending approval request status
 *  POST /api/approve-request     — Approve pending request with scope
 *  POST /api/deny-request        — Deny a pending request
 *  POST /api/sharing/add-user    — Add allowed email to drive
 *  POST /api/sharing/remove-user — Remove allowed email from drive
 *  POST /api/mark-lost           — Remote kill switch
 *  POST /api/reactivate          — Restore LOST drive to ACTIVE
 *  GET  /api/status/:drive_id    — Get drive status
 *  GET  /api/dashboard/drives    — All drives for dashboard
 *  GET  /api/dashboard/pending   — All pending requests for dashboard
 *  GET  /api/health              — Health check
 *  GET  /dashboard               — Web admin dashboard (static HTML)
 */

'use strict';

require('dotenv').config();

const express      = require('express');
const jwt          = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Database     = require('better-sqlite3');
const path         = require('path');
const fs           = require('fs');
const crypto       = require('crypto');
const morgan       = require('morgan');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');

// ──────────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────────

const PORT         = process.env.PORT         || 3000;
const JWT_SECRET   = process.env.JWT_SECRET   || 'dev_only_secret_CHANGE_IN_PRODUCTION';
const DB_PATH      = process.env.DB_PATH      || './data/usb_drives.db';
const ADMIN_KEY    = process.env.ADMIN_API_KEY || 'dev_admin_key';
const LEASE_DAYS   = 7;

if (JWT_SECRET === 'dev_only_secret_CHANGE_IN_PRODUCTION') {
  console.warn('\n⚠️  WARNING: Using default JWT_SECRET. Set JWT_SECRET in .env before production!\n');
}

// ──────────────────────────────────────────────
// Database Initialisation
// ──────────────────────────────────────────────

const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Delete old database to avoid schema conflicts from v1
const dbFullPath = path.resolve(DB_PATH);
if (fs.existsSync(dbFullPath)) {
  // Check if old schema is present (missing owner_email column)
  try {
    const testDb = new Database(dbFullPath, { readonly: true });
    const cols = testDb.pragma('table_info(drives)');
    const hasOwnerEmail = cols.some(c => c.name === 'owner_email');
    testDb.close();
    if (!hasOwnerEmail) {
      console.log('🔄  Detected v1 database schema — migrating to v2...');
      const backupPath = dbFullPath + '.v1.bak';
      fs.copyFileSync(dbFullPath, backupPath);
      fs.unlinkSync(dbFullPath);
      // Also remove WAL/SHM files
      [dbFullPath + '-wal', dbFullPath + '-shm'].forEach(f => {
        if (fs.existsSync(f)) fs.unlinkSync(f);
      });
      console.log(`   Backed up v1 database to: ${backupPath}`);
    }
  } catch (e) {
    // If we can't read it, just proceed — new DB will be created
  }
}

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS drives (
    drive_id            TEXT PRIMARY KEY,
    cloud_key_share     TEXT NOT NULL,
    owner_email         TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'ACTIVE',
    label               TEXT DEFAULT NULL,
    lost_reason         TEXT DEFAULT NULL,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS access_list (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    drive_id            TEXT NOT NULL,
    allowed_email       TEXT NOT NULL,
    added_at            INTEGER NOT NULL,
    FOREIGN KEY (drive_id) REFERENCES drives(drive_id) ON DELETE CASCADE,
    UNIQUE(drive_id, allowed_email)
  );

  CREATE TABLE IF NOT EXISTS trusted_devices (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    drive_id            TEXT NOT NULL,
    hardware_fingerprint TEXT NOT NULL,
    user_email          TEXT DEFAULT NULL,
    trust_scope         TEXT NOT NULL DEFAULT 'LEASE',
    expires_at          INTEGER DEFAULT NULL,
    created_at          INTEGER NOT NULL,
    FOREIGN KEY (drive_id) REFERENCES drives(drive_id) ON DELETE CASCADE,
    UNIQUE(drive_id, hardware_fingerprint)
  );

  CREATE TABLE IF NOT EXISTS pending_requests (
    request_id          TEXT PRIMARY KEY,
    drive_id            TEXT NOT NULL,
    hardware_fingerprint TEXT NOT NULL,
    requester_email     TEXT DEFAULT NULL,
    status              TEXT NOT NULL DEFAULT 'PENDING',
    granted_scope       TEXT DEFAULT NULL,
    expires_at          INTEGER DEFAULT NULL,
    cloud_key_share     TEXT DEFAULT NULL,
    lease_token         TEXT DEFAULT NULL,
    created_at          INTEGER NOT NULL,
    resolved_at         INTEGER DEFAULT NULL,
    FOREIGN KEY (drive_id) REFERENCES drives(drive_id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS auth_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    drive_id            TEXT,
    fingerprint_hash    TEXT,
    user_email          TEXT,
    result              TEXT NOT NULL,
    ip_address          TEXT,
    timestamp           INTEGER NOT NULL
  );
`);

console.log(`✅  Database initialised at: ${path.resolve(DB_PATH)}`);

// ──────────────────────────────────────────────
// Express App Setup
// ──────────────────────────────────────────────

const app = express();

// Configure helmet to allow inline styles and scripts for dashboard
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(express.json());
app.use(morgan('short'));

// Serve static dashboard files
app.use('/dashboard', express.static(path.join(__dirname, 'public')));

// Global rate limiter — 500 requests per 15 minutes per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', globalLimiter);

// Auth-specific rate limiter — 50 attempts per 5 minutes per IP
const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts.' }
});

// ──────────────────────────────────────────────
// Middleware Helpers
// ──────────────────────────────────────────────

function requireAdminKey(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorised. Valid X-Admin-Key header required.' });
  }
  next();
}

function logAuthEvent(drive_id, fingerprint_hash, user_email, result, req) {
  try {
    db.prepare(`
      INSERT INTO auth_log (drive_id, fingerprint_hash, user_email, result, ip_address, timestamp)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(drive_id, fingerprint_hash, user_email || null, result, req.ip, Date.now());
  } catch (e) {
    console.error('Failed to write auth log:', e.message);
  }
}

function normaliseFingerprint(fp) {
  if (fp && fp.length === 64 && /^[0-9a-f]+$/i.test(fp)) {
    return fp.toLowerCase();
  }
  return crypto.createHash('sha256').update(fp || '').digest('hex');
}

function generateLeaseToken(drive_id, fingerprint_hash, leaseSeconds) {
  const now       = Math.floor(Date.now() / 1000);
  const expiresAt = now + leaseSeconds;
  const payload   = {
    sub:         drive_id,
    fingerprint: fingerprint_hash,
    iat:         now,
    exp:         expiresAt,
    type:        'usb_lease'
  };
  const token = jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
  return { token, expiresAt, expiresAtISO: new Date(expiresAt * 1000).toISOString() };
}

// ──────────────────────────────────────────────
// Route: POST /api/register
// ──────────────────────────────────────────────

app.post('/api/register', requireAdminKey, (req, res) => {
  try {
    const { label, owner_email } = req.body;
    if (!owner_email) {
      return res.status(400).json({ error: 'owner_email is required.' });
    }

    const drive_id        = uuidv4();
    const cloud_key_share = crypto.randomBytes(32).toString('hex');
    const now             = Date.now();

    db.prepare(`
      INSERT INTO drives (drive_id, cloud_key_share, owner_email, status, label, created_at, updated_at)
      VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?)
    `).run(drive_id, cloud_key_share, owner_email.toLowerCase().trim(), label || null, now, now);

    // Auto-add owner to access list
    db.prepare(`
      INSERT OR IGNORE INTO access_list (drive_id, allowed_email, added_at)
      VALUES (?, ?, ?)
    `).run(drive_id, owner_email.toLowerCase().trim(), now);

    console.log(`📋  Registered drive: ${drive_id} | Owner: ${owner_email} | Label: ${label || 'none'}`);

    return res.status(201).json({
      message:         'Drive registered successfully.',
      drive_id,
      cloud_key_share,
      owner_email:     owner_email.toLowerCase().trim(),
      status:          'ACTIVE',
      created_at:      new Date(now).toISOString()
    });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Internal server error during registration.' });
  }
});

// ──────────────────────────────────────────────
// Route: POST /api/auth-host
// Three-way response: GRANTED / LOCKED / PENDING_APPROVAL
// ──────────────────────────────────────────────

app.post('/api/auth-host', authLimiter, (req, res) => {
  try {
    const { drive_id, hardware_fingerprint, user_email } = req.body;

    if (!drive_id || !hardware_fingerprint) {
      return res.status(400).json({ error: 'drive_id and hardware_fingerprint are required.' });
    }

    const fingerprint_hash = normaliseFingerprint(hardware_fingerprint);
    const email = (user_email || '').toLowerCase().trim();

    // Look up drive
    const drive = db.prepare('SELECT * FROM drives WHERE drive_id = ?').get(drive_id);
    if (!drive) {
      logAuthEvent(drive_id, fingerprint_hash, email, 'NOT_FOUND', req);
      return res.status(404).json({ status: 'NOT_FOUND', message: 'Drive ID not registered.' });
    }

    // Check LOST status
    if (drive.status === 'LOST') {
      logAuthEvent(drive_id, fingerprint_hash, email, 'DENIED_LOST', req);
      console.warn(`🚨  BLOCKED: Drive ${drive_id} is LOST.`);
      return res.status(403).json({
        status:  'LOCKED',
        message: 'Drive marked as lost. Access permanently revoked.',
        reason:  drive.lost_reason || null
      });
    }

    // Check if user email is in access list (owner is auto-added on register)
    if (email) {
      const allowed = db.prepare(
        'SELECT id FROM access_list WHERE drive_id = ? AND allowed_email = ?'
      ).get(drive_id, email);

      if (!allowed) {
        logAuthEvent(drive_id, fingerprint_hash, email, 'DENIED_EMAIL', req);
        return res.status(403).json({
          status:  'DENIED',
          message: 'Email not authorised for this drive.'
        });
      }
    }

    // Check trusted devices
    const trustedDevice = db.prepare(
      'SELECT * FROM trusted_devices WHERE drive_id = ? AND hardware_fingerprint = ?'
    ).get(drive_id, fingerprint_hash);

    // ── Owner auto-trust: owner's device is auto-trusted forever on first auth ──
    if (!trustedDevice && email && email === drive.owner_email) {
      const nowUnix = Math.floor(Date.now() / 1000);
      db.prepare(`
        INSERT OR REPLACE INTO trusted_devices
          (drive_id, hardware_fingerprint, user_email, trust_scope, expires_at, created_at)
        VALUES (?, ?, ?, 'FOREVER', NULL, ?)
      `).run(drive_id, fingerprint_hash, email, Date.now());

      const leaseSeconds = LEASE_DAYS * 24 * 60 * 60;
      const lease = generateLeaseToken(drive_id, fingerprint_hash, leaseSeconds);
      logAuthEvent(drive_id, fingerprint_hash, email, 'GRANTED', req);

      console.log(`👑  OWNER AUTO-TRUST: Drive ${drive_id} → device trusted forever`);

      return res.status(200).json({
        status:          'GRANTED',
        cloud_key_share: drive.cloud_key_share,
        lease_token:     lease.token,
        expires_at:      lease.expiresAtISO,
        expires_at_unix: lease.expiresAt,
        drive_label:     drive.label,
        trust_scope:     'FOREVER'
      });
    }

    if (trustedDevice) {
      const now = Math.floor(Date.now() / 1000);

      // Check if trust has expired
      if (trustedDevice.trust_scope === 'LEASE' && trustedDevice.expires_at && now >= trustedDevice.expires_at) {
        // Lease expired — remove trust and treat as unknown
        db.prepare('DELETE FROM trusted_devices WHERE id = ?').run(trustedDevice.id);
        console.log(`⏰  Trust expired for device on drive ${drive_id}`);
        // Fall through to pending approval flow below
      } else if (trustedDevice.trust_scope === 'ONE_TIME') {
        // One-time: grant access and immediately revoke trust
        db.prepare('DELETE FROM trusted_devices WHERE id = ?').run(trustedDevice.id);
        console.log(`🔑  One-time trust consumed for drive ${drive_id}`);

        const leaseSeconds = 12 * 60 * 60; // 12 hours for one-time
        const lease = generateLeaseToken(drive_id, fingerprint_hash, leaseSeconds);
        logAuthEvent(drive_id, fingerprint_hash, email, 'GRANTED_ONETIME', req);

        return res.status(200).json({
          status:          'GRANTED',
          cloud_key_share: drive.cloud_key_share,
          lease_token:     lease.token,
          expires_at:      lease.expiresAtISO,
          expires_at_unix: lease.expiresAt,
          drive_label:     drive.label,
          trust_scope:     'ONE_TIME'
        });
      } else {
        // FOREVER or active LEASE — grant access
        let leaseSeconds;
        if (trustedDevice.trust_scope === 'FOREVER') {
          leaseSeconds = LEASE_DAYS * 24 * 60 * 60;
        } else {
          // Remaining lease time
          leaseSeconds = Math.max(trustedDevice.expires_at - now, 3600);
        }

        const lease = generateLeaseToken(drive_id, fingerprint_hash, leaseSeconds);
        logAuthEvent(drive_id, fingerprint_hash, email, 'GRANTED', req);

        console.log(`✅  GRANTED: Drive ${drive_id} → ${trustedDevice.trust_scope}`);

        return res.status(200).json({
          status:          'GRANTED',
          cloud_key_share: drive.cloud_key_share,
          lease_token:     lease.token,
          expires_at:      lease.expiresAtISO,
          expires_at_unix: lease.expiresAt,
          drive_label:     drive.label,
          trust_scope:     trustedDevice.trust_scope
        });
      }
    }

    // ── Unknown device: Create pending approval request ──

    // Check if there's already a pending request for this device+drive
    const existingPending = db.prepare(`
      SELECT * FROM pending_requests
      WHERE drive_id = ? AND hardware_fingerprint = ? AND status = 'PENDING'
    `).get(drive_id, fingerprint_hash);

    if (existingPending) {
      logAuthEvent(drive_id, fingerprint_hash, email, 'PENDING_EXISTING', req);
      return res.status(202).json({
        status:     'PENDING_APPROVAL',
        request_id: existingPending.request_id,
        message:    'Access request already pending. Waiting for owner approval.',
        drive_label: drive.label
      });
    }

    // Create new pending request
    const request_id = uuidv4().slice(0, 8).toUpperCase(); // Short readable code

    db.prepare(`
      INSERT INTO pending_requests (request_id, drive_id, hardware_fingerprint, requester_email, status, created_at)
      VALUES (?, ?, ?, ?, 'PENDING', ?)
    `).run(request_id, drive_id, fingerprint_hash, email || null, Date.now());

    logAuthEvent(drive_id, fingerprint_hash, email, 'PENDING_NEW', req);
    console.log(`🔔  NEW APPROVAL REQUEST: ${request_id} for drive ${drive_id}`);

    return res.status(202).json({
      status:      'PENDING_APPROVAL',
      request_id:  request_id,
      message:     'Access request sent to drive owner for approval.',
      drive_label: drive.label
    });

  } catch (err) {
    console.error('Auth-host error:', err);
    return res.status(500).json({ error: 'Internal server error during authentication.' });
  }
});

// ──────────────────────────────────────────────
// Route: POST /api/request-status
// Polled by client while waiting for approval
// ──────────────────────────────────────────────

app.post('/api/request-status', (req, res) => {
  try {
    const { request_id, drive_id } = req.body;
    if (!request_id) {
      return res.status(400).json({ error: 'request_id is required.' });
    }

    const request = db.prepare(
      'SELECT * FROM pending_requests WHERE request_id = ?'
    ).get(request_id);

    if (!request) {
      return res.status(404).json({ status: 'NOT_FOUND', message: 'Request not found.' });
    }

    if (request.status === 'PENDING') {
      return res.status(200).json({
        status:     'PENDING',
        request_id: request.request_id,
        message:    'Waiting for owner approval...'
      });
    }

    if (request.status === 'DENIED') {
      return res.status(200).json({
        status:     'DENIED',
        request_id: request.request_id,
        message:    'Access request denied by drive owner.'
      });
    }

    if (request.status === 'APPROVED') {
      return res.status(200).json({
        status:          'APPROVED',
        request_id:      request.request_id,
        cloud_key_share: request.cloud_key_share,
        lease_token:     request.lease_token,
        expires_at:      request.expires_at ? new Date(request.expires_at * 1000).toISOString() : null,
        expires_at_unix: request.expires_at,
        granted_scope:   request.granted_scope,
        message:         `Access approved with scope: ${request.granted_scope}`
      });
    }

    return res.status(200).json({ status: request.status, request_id: request.request_id });
  } catch (err) {
    console.error('Request-status error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ──────────────────────────────────────────────
// Route: POST /api/approve-request
// Dashboard approves with scope
// ──────────────────────────────────────────────

app.post('/api/approve-request', requireAdminKey, (req, res) => {
  try {
    const { request_id, scope, lease_hours } = req.body;
    if (!request_id || !scope) {
      return res.status(400).json({ error: 'request_id and scope are required.' });
    }

    const validScopes = ['ONE_TIME', 'CUSTOM_LEASE', 'FOREVER'];
    if (!validScopes.includes(scope)) {
      return res.status(400).json({ error: `scope must be one of: ${validScopes.join(', ')}` });
    }

    const request = db.prepare(
      'SELECT * FROM pending_requests WHERE request_id = ? AND status = ?'
    ).get(request_id, 'PENDING');

    if (!request) {
      return res.status(404).json({ error: 'Pending request not found.' });
    }

    const drive = db.prepare('SELECT * FROM drives WHERE drive_id = ?').get(request.drive_id);
    if (!drive) {
      return res.status(404).json({ error: 'Associated drive not found.' });
    }

    // Calculate lease duration
    let leaseSeconds;
    let expiresAtUnix = null;
    const nowUnix = Math.floor(Date.now() / 1000);

    if (scope === 'ONE_TIME') {
      leaseSeconds = 12 * 60 * 60; // 12 hours
      expiresAtUnix = nowUnix + leaseSeconds;
    } else if (scope === 'CUSTOM_LEASE') {
      const hours = parseInt(lease_hours) || 24;
      leaseSeconds = hours * 60 * 60;
      expiresAtUnix = nowUnix + leaseSeconds;
    } else { // FOREVER
      leaseSeconds = LEASE_DAYS * 24 * 60 * 60; // JWT still expires, but trust doesn't
      expiresAtUnix = null; // No expiry for trust
    }

    // Generate lease token
    const lease = generateLeaseToken(request.drive_id, request.hardware_fingerprint, leaseSeconds);

    // Register device as trusted
    const trustScope = scope === 'CUSTOM_LEASE' ? 'LEASE' : scope;
    db.prepare(`
      INSERT OR REPLACE INTO trusted_devices
        (drive_id, hardware_fingerprint, user_email, trust_scope, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      request.drive_id,
      request.hardware_fingerprint,
      request.requester_email,
      trustScope,
      scope === 'FOREVER' ? null : (nowUnix + leaseSeconds),
      Date.now()
    );

    // Update the pending request with the key material (client will pick this up via polling)
    db.prepare(`
      UPDATE pending_requests
      SET status = 'APPROVED', granted_scope = ?, expires_at = ?,
          cloud_key_share = ?, lease_token = ?, resolved_at = ?
      WHERE request_id = ?
    `).run(
      scope,
      lease.expiresAt,
      drive.cloud_key_share,
      lease.token,
      Date.now(),
      request_id
    );

    console.log(`✅  APPROVED: Request ${request_id} → ${scope}${scope === 'CUSTOM_LEASE' ? ` (${lease_hours || 24}h)` : ''}`);

    return res.status(200).json({
      message:       `Request approved with scope: ${scope}`,
      request_id,
      scope,
      expires_at:    lease.expiresAtISO,
      trust_scope:   trustScope
    });

  } catch (err) {
    console.error('Approve-request error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ──────────────────────────────────────────────
// Route: POST /api/deny-request
// ──────────────────────────────────────────────

app.post('/api/deny-request', requireAdminKey, (req, res) => {
  try {
    const { request_id } = req.body;
    if (!request_id) {
      return res.status(400).json({ error: 'request_id is required.' });
    }

    const request = db.prepare(
      'SELECT * FROM pending_requests WHERE request_id = ? AND status = ?'
    ).get(request_id, 'PENDING');

    if (!request) {
      return res.status(404).json({ error: 'Pending request not found.' });
    }

    db.prepare(`
      UPDATE pending_requests SET status = 'DENIED', resolved_at = ? WHERE request_id = ?
    `).run(Date.now(), request_id);

    console.log(`⛔  DENIED: Request ${request_id}`);

    return res.status(200).json({
      message:    'Request denied.',
      request_id,
      status:     'DENIED'
    });
  } catch (err) {
    console.error('Deny-request error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ──────────────────────────────────────────────
// Route: POST /api/sharing/add-user
// ──────────────────────────────────────────────

app.post('/api/sharing/add-user', requireAdminKey, (req, res) => {
  try {
    const { drive_id, email } = req.body;
    if (!drive_id || !email) {
      return res.status(400).json({ error: 'drive_id and email are required.' });
    }

    const drive = db.prepare('SELECT drive_id FROM drives WHERE drive_id = ?').get(drive_id);
    if (!drive) {
      return res.status(404).json({ error: 'Drive not found.' });
    }

    const normalEmail = email.toLowerCase().trim();
    db.prepare(`
      INSERT OR IGNORE INTO access_list (drive_id, allowed_email, added_at)
      VALUES (?, ?, ?)
    `).run(drive_id, normalEmail, Date.now());

    return res.status(201).json({
      message: `User ${normalEmail} added to access list.`,
      drive_id,
      email: normalEmail
    });
  } catch (err) {
    console.error('Add-user error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ──────────────────────────────────────────────
// Route: POST /api/sharing/remove-user
// ──────────────────────────────────────────────

app.post('/api/sharing/remove-user', requireAdminKey, (req, res) => {
  try {
    const { drive_id, email } = req.body;
    if (!drive_id || !email) {
      return res.status(400).json({ error: 'drive_id and email are required.' });
    }

    const normalEmail = email.toLowerCase().trim();

    // Prevent removing owner
    const drive = db.prepare('SELECT owner_email FROM drives WHERE drive_id = ?').get(drive_id);
    if (drive && drive.owner_email === normalEmail) {
      return res.status(400).json({ error: 'Cannot remove drive owner from access list.' });
    }

    db.prepare(
      'DELETE FROM access_list WHERE drive_id = ? AND allowed_email = ?'
    ).run(drive_id, normalEmail);

    return res.status(200).json({
      message: `User ${normalEmail} removed from access list.`,
      drive_id
    });
  } catch (err) {
    console.error('Remove-user error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ──────────────────────────────────────────────
// Route: POST /api/mark-lost
// ──────────────────────────────────────────────

app.post('/api/mark-lost', requireAdminKey, (req, res) => {
  try {
    const { drive_id, reason } = req.body;
    if (!drive_id) {
      return res.status(400).json({ error: 'drive_id is required.' });
    }

    const drive = db.prepare('SELECT * FROM drives WHERE drive_id = ?').get(drive_id);
    if (!drive) {
      return res.status(404).json({ error: 'Drive not found.' });
    }

    if (drive.status === 'LOST') {
      return res.status(200).json({ message: 'Drive already marked as LOST.', drive_id, status: 'LOST' });
    }

    // Mark drive as lost
    db.prepare(`
      UPDATE drives SET status = 'LOST', lost_reason = ?, updated_at = ? WHERE drive_id = ?
    `).run(reason || 'Marked lost by administrator.', Date.now(), drive_id);

    // Deny all pending requests
    db.prepare(`
      UPDATE pending_requests SET status = 'DENIED', resolved_at = ?
      WHERE drive_id = ? AND status = 'PENDING'
    `).run(Date.now(), drive_id);

    // Remove all trusted devices
    db.prepare('DELETE FROM trusted_devices WHERE drive_id = ?').run(drive_id);

    console.log(`🔴  KILL SWITCH: Drive ${drive_id} marked LOST.`);

    return res.status(200).json({
      message: 'Drive marked as LOST. All trust revoked.',
      drive_id,
      status:  'LOST',
      reason:  reason || null
    });
  } catch (err) {
    console.error('Mark-lost error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ──────────────────────────────────────────────
// Route: POST /api/reactivate
// ──────────────────────────────────────────────

app.post('/api/reactivate', requireAdminKey, (req, res) => {
  try {
    const { drive_id } = req.body;
    if (!drive_id) {
      return res.status(400).json({ error: 'drive_id is required.' });
    }

    const drive = db.prepare('SELECT * FROM drives WHERE drive_id = ?').get(drive_id);
    if (!drive) return res.status(404).json({ error: 'Drive not found.' });
    if (drive.status === 'ACTIVE') {
      return res.status(200).json({ message: 'Drive is already ACTIVE.', drive_id, status: 'ACTIVE' });
    }

    db.prepare(`
      UPDATE drives SET status = 'ACTIVE', lost_reason = NULL, updated_at = ? WHERE drive_id = ?
    `).run(Date.now(), drive_id);

    console.log(`🟢  REACTIVATED: Drive ${drive_id}`);
    return res.status(200).json({ message: 'Drive reactivated.', drive_id, status: 'ACTIVE' });
  } catch (err) {
    console.error('Reactivate error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ──────────────────────────────────────────────
// Route: GET /api/status/:drive_id
// ──────────────────────────────────────────────

app.get('/api/status/:drive_id', (req, res) => {
  try {
    const { drive_id } = req.params;
    const drive = db.prepare(`
      SELECT drive_id, status, label, owner_email, created_at, updated_at, lost_reason
      FROM drives WHERE drive_id = ?
    `).get(drive_id);

    if (!drive) return res.status(404).json({ error: 'Drive not found.' });

    const accessList = db.prepare(
      'SELECT allowed_email, added_at FROM access_list WHERE drive_id = ?'
    ).all(drive_id);

    const trustedDevices = db.prepare(
      'SELECT hardware_fingerprint, user_email, trust_scope, expires_at, created_at FROM trusted_devices WHERE drive_id = ?'
    ).all(drive_id);

    const recentLogs = db.prepare(
      'SELECT result, user_email, ip_address, timestamp FROM auth_log WHERE drive_id = ? ORDER BY timestamp DESC LIMIT 15'
    ).all(drive_id);

    return res.status(200).json({
      ...drive,
      created_at:      new Date(drive.created_at).toISOString(),
      updated_at:      new Date(drive.updated_at).toISOString(),
      access_list:     accessList.map(a => ({ email: a.allowed_email, added_at: new Date(a.added_at).toISOString() })),
      trusted_devices: trustedDevices.map(d => ({
        fingerprint: d.hardware_fingerprint,
        email:       d.user_email,
        scope:       d.trust_scope,
        expires_at:  d.expires_at ? new Date(d.expires_at * 1000).toISOString() : null,
        created_at:  new Date(d.created_at).toISOString()
      })),
      recent_auth_log: recentLogs.map(l => ({
        result:    l.result,
        email:     l.user_email,
        ip:        l.ip_address,
        timestamp: new Date(l.timestamp).toISOString()
      }))
    });
  } catch (err) {
    console.error('Status error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ──────────────────────────────────────────────
// Dashboard API Routes
// ──────────────────────────────────────────────

app.get('/api/dashboard/drives', requireAdminKey, (req, res) => {
  try {
    const drives = db.prepare(`
      SELECT drive_id, label, owner_email, status, lost_reason, created_at, updated_at
      FROM drives ORDER BY created_at DESC
    `).all();

    const result = drives.map(d => {
      const accessCount = db.prepare(
        'SELECT COUNT(*) as c FROM access_list WHERE drive_id = ?'
      ).get(d.drive_id).c;

      const deviceCount = db.prepare(
        'SELECT COUNT(*) as c FROM trusted_devices WHERE drive_id = ?'
      ).get(d.drive_id).c;

      return {
        ...d,
        created_at:       new Date(d.created_at).toISOString(),
        updated_at:       new Date(d.updated_at).toISOString(),
        access_list_count: accessCount,
        trusted_device_count: deviceCount
      };
    });

    return res.status(200).json({ drives: result });
  } catch (err) {
    console.error('Dashboard drives error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

app.get('/api/dashboard/pending', requireAdminKey, (req, res) => {
  try {
    const pending = db.prepare(`
      SELECT pr.*, d.label as drive_label, d.owner_email
      FROM pending_requests pr
      LEFT JOIN drives d ON pr.drive_id = d.drive_id
      WHERE pr.status = 'PENDING'
      ORDER BY pr.created_at DESC
    `).all();

    return res.status(200).json({
      pending: pending.map(p => ({
        ...p,
        created_at: new Date(p.created_at).toISOString()
      }))
    });
  } catch (err) {
    console.error('Dashboard pending error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ──────────────────────────────────────────────
// Route: GET /api/health
// ──────────────────────────────────────────────

app.get('/api/health', (req, res) => {
  const driveCount   = db.prepare('SELECT COUNT(*) as c FROM drives').get().c;
  const pendingCount = db.prepare("SELECT COUNT(*) as c FROM pending_requests WHERE status = 'PENDING'").get().c;

  return res.status(200).json({
    status:        'ok',
    service:       'USB Killswitch v2 Backend',
    version:       '2.0.0',
    drive_count:   driveCount,
    pending_count: pendingCount,
    timestamp:     new Date().toISOString()
  });
});

// ──────────────────────────────────────────────
// Dashboard HTML redirect
// ──────────────────────────────────────────────

app.get('/dashboard', (req, res) => {
  res.redirect('/dashboard/index.html');
});

// ──────────────────────────────────────────────
// 404 & Error Handlers
// ──────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.path}` });
});

app.use((err, req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'An unexpected error occurred.' });
});

// ──────────────────────────────────────────────
// Start Server
// ──────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🔒  USB Killswitch v2 Backend running on http://localhost:${PORT}`);
  console.log(`📡  Dashboard: http://localhost:${PORT}/dashboard`);
  console.log(`📡  API Endpoints:`);
  console.log(`    POST /api/register            — Register new drive`);
  console.log(`    POST /api/auth-host           — Authenticate (3-way)`);
  console.log(`    POST /api/request-status      — Poll approval status`);
  console.log(`    POST /api/approve-request     — Approve pending`);
  console.log(`    POST /api/deny-request        — Deny pending`);
  console.log(`    POST /api/sharing/add-user    — Add allowed email`);
  console.log(`    POST /api/sharing/remove-user — Remove allowed email`);
  console.log(`    POST /api/mark-lost           — Kill switch`);
  console.log(`    POST /api/reactivate          — Restore drive`);
  console.log(`    GET  /api/status/:drive_id    — Drive status`);
  console.log(`    GET  /api/health              — Health check\n`);
});

module.exports = app;
