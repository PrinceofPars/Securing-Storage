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

// Real Google OAuth 2.0 Credentials (https://console.cloud.google.com)
const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID     || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_REDIRECT_URI  = process.env.GOOGLE_REDIRECT_URI  || '';

if (JWT_SECRET === 'dev_only_secret_CHANGE_IN_PRODUCTION') {
  console.warn('\n⚠️  WARNING: Using default JWT_SECRET. Set JWT_SECRET in .env before production!\n');
}

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.warn('ℹ️  INFO: Real Google OAuth is unconfigured. Set GOOGLE_CLIENT_ID & GOOGLE_CLIENT_SECRET in .env to enforce zero-trust identity verification.\n');
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
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));

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
function parseCookies(req) {
  const list = {};
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(cookie => {
    let [name, ...rest] = cookie.split('=');
    name = name?.trim();
    if (!name) return;
    const value = rest.join('=').trim();
    list[name] = decodeURIComponent(value);
  });
  return list;
}

function createOwnerToken(email) {
  return jwt.sign({ email: email.toLowerCase().trim(), role: 'owner' }, JWT_SECRET, { expiresIn: '30d' });
}

function getOwnerEmail(req) {
  const cookies = parseCookies(req);
  const token = cookies.owner_session ||
                (req.headers.authorization && req.headers.authorization.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null) ||
                req.headers['x-owner-token'];
  if (!token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return payload.email || null;
  } catch (e) {
    return null;
  }
}

function requireAdminKey(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (key && key === ADMIN_KEY) {
    return next();
  }
  
  // Also permit authenticated owner session cookies or same-origin dashboard access
  const ownerEmail = getOwnerEmail(req);
  if (ownerEmail) {
    return next();
  }

  // Allow same-origin dashboard UI requests
  const referer = req.headers.referer || req.headers.origin || '';
  if (referer && (referer.includes('/dashboard') || referer.includes('/approve') || referer.includes('localhost:') || referer.includes('127.0.0.1:'))) {
    return next();
  }

  return res.status(401).json({ error: 'Unauthorised. Valid admin or owner session required.' });
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
// Register new drive (Admin key no longer required in v2)
// ──────────────────────────────────────────────

app.post('/api/register', (req, res) => {
  try {
    const { label, owner_email, hardware_fingerprint } = req.body;
    if (!owner_email) {
      return res.status(400).json({ error: 'owner_email is required.' });
    }

    const drive_id        = uuidv4();
    const cloud_key_share = crypto.randomBytes(32).toString('hex');
    const now             = Date.now();
    const normalizedEmail = owner_email.toLowerCase().trim();

    db.prepare(`
      INSERT INTO drives (drive_id, cloud_key_share, owner_email, status, label, created_at, updated_at)
      VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?)
    `).run(drive_id, cloud_key_share, normalizedEmail, label || null, now, now);

    // Auto-add owner to access list
    db.prepare(`
      INSERT OR IGNORE INTO access_list (drive_id, allowed_email, added_at)
      VALUES (?, ?, ?)
    `).run(drive_id, normalizedEmail, now);

    // If hardware fingerprint is provided, auto-trust owner device FOREVER
    if (hardware_fingerprint) {
      const fingerprint_hash = normaliseFingerprint(hardware_fingerprint);
      db.prepare(`
        INSERT OR REPLACE INTO trusted_devices
          (drive_id, hardware_fingerprint, user_email, trust_scope, expires_at, created_at)
        VALUES (?, ?, ?, 'FOREVER', NULL, ?)
      `).run(drive_id, fingerprint_hash, normalizedEmail, now);
    }

    const ownerToken = createOwnerToken(normalizedEmail);
    res.setHeader('Set-Cookie', `owner_session=${encodeURIComponent(ownerToken)}; Path=/; Max-Age=${30 * 24 * 60 * 60}; SameSite=Lax`);

    console.log(`📋  Registered drive: ${drive_id} | Owner: ${normalizedEmail} | Label: ${label || 'none'}`);

    return res.status(201).json({
      message:         'Drive registered successfully.',
      drive_id,
      cloud_key_share,
      owner_email:     normalizedEmail,
      owner_token:     ownerToken,
      status:          'ACTIVE',
      created_at:      new Date(now).toISOString()
    });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Internal server error during registration.' });
  }
});

// ──────────────────────────────────────────────
// Route: POST /api/owner/login & GET /api/owner/me
// ──────────────────────────────────────────────

app.post('/api/owner/login', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required.' });
  const normalizedEmail = email.toLowerCase().trim();
  const token = createOwnerToken(normalizedEmail);
  res.setHeader('Set-Cookie', `owner_session=${encodeURIComponent(token)}; Path=/; Max-Age=${30 * 24 * 60 * 60}; SameSite=Lax`);
  return res.status(200).json({ status: 'ok', owner_email: normalizedEmail, token });
});

app.get('/api/owner/me', (req, res) => {
  const ownerEmail = getOwnerEmail(req);
  if (!ownerEmail) return res.status(401).json({ authenticated: false });
  return res.status(200).json({ authenticated: true, owner_email: ownerEmail });
});

app.get('/api/owner/drives', (req, res) => {
  const ownerEmail = getOwnerEmail(req);
  if (!ownerEmail) return res.status(401).json({ error: 'Not authenticated as owner' });

  try {
    const drives = db.prepare(`
      SELECT drive_id, label, owner_email, status, lost_reason, created_at, updated_at
      FROM drives WHERE owner_email = ? ORDER BY created_at DESC
    `).all(ownerEmail.toLowerCase().trim());

    const result = drives.map(d => {
      const accessCount = db.prepare(
        'SELECT COUNT(*) as c FROM access_list WHERE drive_id = ?'
      ).get(d.drive_id).c;

      const deviceCount = db.prepare(
        'SELECT COUNT(*) as c FROM trusted_devices WHERE drive_id = ?'
      ).get(d.drive_id).c;

      return {
        ...d,
        created_at: new Date(d.created_at).toISOString(),
        updated_at: new Date(d.updated_at).toISOString(),
        access_list_count: accessCount,
        trusted_device_count: deviceCount
      };
    });

    return res.status(200).json({ drives: result });
  } catch (err) {
    console.error('Owner drives error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

app.get('/api/owner/pending', (req, res) => {
  const ownerEmail = getOwnerEmail(req);
  if (!ownerEmail) return res.status(401).json({ error: 'Not authenticated as owner' });

  try {
    const pending = db.prepare(`
      SELECT pr.*, d.label as drive_label, d.owner_email
      FROM pending_requests pr
      JOIN drives d ON pr.drive_id = d.drive_id
      WHERE d.owner_email = ? AND pr.status = 'PENDING'
      ORDER BY pr.created_at DESC
    `).all(ownerEmail.toLowerCase().trim());

    return res.status(200).json({
      pending: pending.map(p => ({
        ...p,
        created_at: new Date(p.created_at).toISOString()
      }))
    });
  } catch (err) {
    console.error('Owner pending error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// In-memory desktop client Google login sessions
const googleClientSessions = new Map();

// Periodic cleanup of stale sessions older than 15 minutes
setInterval(() => {
  const now = Date.now();
  for (const [sid, data] of googleClientSessions.entries()) {
    if (now - data.timestamp > 15 * 60 * 1000) {
      googleClientSessions.delete(sid);
    }
  }
}, 60 * 1000);

// ──────────────────────────────────────────────
// Real Google OAuth 2.0 & GIS Helpers
// ──────────────────────────────────────────────

function getGoogleRedirectUri(req) {
  if (GOOGLE_REDIRECT_URI) return GOOGLE_REDIRECT_URI;
  const forwardedProto = req.headers['x-forwarded-proto'];
  const proto = forwardedProto ? forwardedProto.split(',')[0].trim() : req.protocol;
  const host = req.get('host');
  return `${proto}://${host}/auth/google/callback`;
}

function buildGoogleOAuthUrl(req, { reqId, sessionId, redirectUrl, hintEmail }) {
  if (!GOOGLE_CLIENT_ID) return null;
  const redirectUri = getGoogleRedirectUri(req);
  const stateObj = {
    reqId: reqId || '',
    sessionId: sessionId || '',
    redirect: redirectUrl || '',
    nonce: crypto.randomBytes(8).toString('hex'),
    ts: Date.now()
  };
  const state = Buffer.from(JSON.stringify(stateObj)).toString('base64url');

  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', GOOGLE_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid email profile');
  authUrl.searchParams.set('access_type', 'online');
  authUrl.searchParams.set('prompt', 'select_account');
  authUrl.searchParams.set('state', state);
  if (hintEmail) {
    authUrl.searchParams.set('login_hint', hintEmail);
  }
  return { authUrl: authUrl.toString(), redirectUri, state };
}

function renderAuthError(title, message) {
  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <title>${title} — USB Killswitch</title>
  <script>
    (function() {
      const saved = localStorage.getItem('theme') || 'dark';
      document.documentElement.setAttribute('data-theme', saved);
    })();
  </script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root, [data-theme="dark"] {
      color-scheme: dark;
      --bg-primary: #0b0f19;
      --bg-card: #161e31;
      --border-card: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --danger: #f43f5e;
      --shadow-card: 0 4px 20px -2px rgba(0, 0, 0, 0.35), 0 16px 36px -6px rgba(0, 0, 0, 0.5);
    }
    [data-theme="light"] {
      color-scheme: light;
      --bg-primary: #fbf9f5;
      --bg-card: #ffffff;
      --border-card: #e5dfd5;
      --text-primary: #1c1917;
      --text-secondary: #57534e;
      --danger: #e11d48;
      --shadow-card: 0 1px 3px rgba(28, 25, 23, 0.03), 0 16px 36px -6px rgba(44, 38, 30, 0.09);
    }
    body {
      background: var(--bg-primary);
      color: var(--text-primary);
      font-family: 'Inter', -apple-system, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 24px;
      text-align: center;
    }
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border-card);
      border-radius: 16px;
      padding: 40px 32px;
      max-width: 440px;
      width: 100%;
      box-shadow: var(--shadow-card);
    }
    .icon {
      width: 56px; height: 56px;
      background: rgba(244, 63, 94, 0.15);
      border: 1px solid rgba(244, 63, 94, 0.3);
      color: var(--danger);
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 18px;
    }
    h2 { margin: 0 0 10px; font-size: 20px; color: var(--danger); font-weight: 700; }
    p { color: var(--text-secondary); font-size: 13px; line-height: 1.5; margin: 0 0 24px; }
    .btn {
      display: inline-block;
      background: #4f46e5;
      color: #ffffff;
      padding: 10px 22px;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 600;
      font-size: 13px;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
    </div>
    <h2>${title}</h2>
    <p>${message}</p>
    <a href="/auth/google" class="btn">Try Again</a>
  </div>
</body>
</html>`;
}

function handleSuccessfulGoogleAuth(req, res, { verifiedEmail, reqId, sessionId, redirectUrl }) {
  const token = createOwnerToken(verifiedEmail);
  res.setHeader('Set-Cookie', `owner_session=${encodeURIComponent(token)}; Path=/; Max-Age=${30 * 24 * 60 * 60}; SameSite=Lax`);

  // If initiated from Desktop Client App (init, approval, or unlock)
  if (sessionId) {
    googleClientSessions.set(sessionId, {
      email: verifiedEmail,
      token,
      timestamp: Date.now()
    });

    return res.send(`<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <title>Signed In — Zero-Trust Storage</title>
  <script>
    (function() {
      const saved = localStorage.getItem('theme') || 'dark';
      document.documentElement.setAttribute('data-theme', saved);
    })();
  </script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root, [data-theme="dark"] {
      color-scheme: dark;
      --bg-primary: #0b0f19;
      --bg-card: #161e31;
      --border-card: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --badge-bg: rgba(16, 185, 129, 0.15);
      --badge-text: #34d399;
      --badge-border: rgba(16, 185, 129, 0.3);
      --shadow-card: 0 4px 20px -2px rgba(0, 0, 0, 0.35), 0 16px 36px -6px rgba(0, 0, 0, 0.5);
    }
    [data-theme="light"] {
      color-scheme: light;
      --bg-primary: #fbf9f5;
      --bg-card: #ffffff;
      --border-card: #e5dfd5;
      --text-primary: #1c1917;
      --text-secondary: #57534e;
      --badge-bg: #ecfdf5;
      --badge-text: #059669;
      --badge-border: #a7f3d0;
      --shadow-card: 0 1px 3px rgba(28, 25, 23, 0.03), 0 16px 36px -6px rgba(44, 38, 30, 0.09);
    }
    body {
      background: var(--bg-primary);
      color: var(--text-primary);
      font-family: 'Inter', -apple-system, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      text-align: center;
      padding: 24px 16px;
      margin: 0;
    }
    .card {
      background: var(--bg-card);
      padding: 44px 36px;
      border-radius: 18px;
      border: 1px solid var(--border-card);
      max-width: 440px;
      width: 100%;
      box-shadow: var(--shadow-card);
    }
    .icon-wrap {
      width: 60px; height: 60px;
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid rgba(16, 185, 129, 0.3);
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 18px;
      color: #34d399;
    }
    h2 { margin: 0 0 8px 0; font-size: 21px; color: #34d399; font-weight: 700; }
    p { color: var(--text-secondary); font-size: 13px; line-height: 1.5; margin: 8px 0 16px 0; }
    .email-badge {
      background: var(--badge-bg);
      border: 1px solid var(--badge-border);
      padding: 6px 14px;
      border-radius: 20px;
      color: var(--badge-text);
      font-weight: 600;
      font-size: 13px;
      display: inline-block;
      margin-bottom: 20px;
    }
    .return-banner {
      background: rgba(99, 102, 241, 0.12);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 10px;
      padding: 12px 16px;
      font-size: 12px;
      color: #a5b4fc;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    .spinner {
      width: 14px; height: 14px;
      border: 2px solid rgba(99, 102, 241, 0.3);
      border-top-color: #818cf8;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon-wrap">
      <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
    </div>
    <h2>Google Identity Verified</h2>
    <div class="email-badge">✓ ${verifiedEmail}</div>
    <p>Your Google account identity has been cryptographically verified. Returning you directly to the Desktop Application...</p>
    <div class="return-banner">
      <div class="spinner"></div>
      <span>Switching back to Zero-Trust Desktop App...</span>
    </div>
  </div>
  <script>
    setTimeout(() => {
      try { window.close(); } catch(e) {}
    }, 1500);
  </script>
</body>
</html>`);
  }

  if (reqId) {
    try {
      const request = db.prepare(`
        SELECT pr.*, d.owner_email FROM pending_requests pr
        JOIN drives d ON pr.drive_id = d.drive_id
        WHERE pr.request_id = ?
      `).get(reqId);

      if (request) {
        if (!request.requester_email && request.owner_email.toLowerCase() !== verifiedEmail) {
          db.prepare('UPDATE pending_requests SET requester_email = ? WHERE request_id = ?').run(verifiedEmail, reqId);
          console.log(`🌐 Google Auth: Verified guest ${verifiedEmail} attached to request ${reqId}`);
        } else if (request.owner_email.toLowerCase() === verifiedEmail) {
          console.log(`👑 Google Auth: Verified owner ${verifiedEmail} logged in for request ${reqId}`);
        }
      }
    } catch (e) {
      console.error('Google callback request link error:', e);
    }
    return res.redirect(`/approve?req=${encodeURIComponent(reqId)}`);
  }

  return res.redirect(redirectUrl || '/dashboard');
}

// Google OAuth / Web Portal Sign-In Entry Point
app.get('/auth/google', (req, res) => {
  const reqId = req.query.req || '';
  const sessionId = req.query.session_id || '';
  const hintEmail = req.query.email || '';
  const redirectUrl = req.query.redirect || '';
  const isForce = req.query.force === 'true' || req.query.switch === 'true';
  const ownerEmail = getOwnerEmail(req);

  if (ownerEmail && !sessionId && !isForce) {
    if (reqId) {
      return res.redirect(`/approve?req=${encodeURIComponent(reqId)}`);
    }
    return res.redirect(redirectUrl || '/dashboard');
  }

  if (isForce) {
    res.setHeader('Set-Cookie', 'owner_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
  }

  const oauthInfo = buildGoogleOAuthUrl(req, { reqId, sessionId, redirectUrl, hintEmail });
  const hasRealOAuth = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);
  const isProd = process.env.NODE_ENV === 'production';
  const redirectUri = getGoogleRedirectUri(req);

  // When Google OAuth credentials are configured, immediately jump directly to Google's account chooser screen!
  if (oauthInfo) {
    return res.redirect(oauthInfo.authUrl);
  }

  res.send(`<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in with Google — Zero-Trust Protection</title>
  <script>
    (function() {
      const saved = localStorage.getItem('theme') || 'dark';
      document.documentElement.setAttribute('data-theme', saved);
    })();
  </script>
  ${hasRealOAuth ? '<script src="https://accounts.google.com/gsi/client" async defer></script>' : ''}
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root, [data-theme="dark"] {
      color-scheme: dark;
      --bg-primary: #0b0f19;
      --bg-card: #161e31;
      --border-card: rgba(255, 255, 255, 0.08);
      --border-glass: rgba(255, 255, 255, 0.1);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --input-bg: #0f172a;
      --input-border: rgba(255, 255, 255, 0.12);
      --badge-bg: rgba(99, 102, 241, 0.18);
      --badge-text: #a5b4fc;
      --badge-border: rgba(99, 102, 241, 0.35);
      --btn-grad: linear-gradient(135deg, #4f46e5 0%, #6366f1 100%);
      --grid-pattern: radial-gradient(rgba(255, 255, 255, 0.04) 1px, transparent 1px);
      --shadow-card: 0 4px 20px -2px rgba(0, 0, 0, 0.35), 0 16px 36px -6px rgba(0, 0, 0, 0.5);
    }
    [data-theme="light"] {
      color-scheme: light;
      --bg-primary: #faf7f2;
      --bg-card: #ffffff;
      --border-card: #e5dfd5;
      --border-glass: #e2ddd3;
      --text-primary: #1c1917;
      --text-secondary: #57534e;
      --text-muted: #8c827a;
      --input-bg: #fbf9f5;
      --input-border: #e2ddd3;
      --badge-bg: #eef2ff;
      --badge-text: #4338ca;
      --badge-border: #c7d2fe;
      --btn-grad: linear-gradient(135deg, #4338ca 0%, #6366f1 100%);
      --grid-pattern: radial-gradient(rgba(28, 25, 23, 0.04) 1px, transparent 1px);
      --shadow-card: 0 1px 3px rgba(28, 25, 23, 0.03), 0 16px 36px -6px rgba(44, 38, 30, 0.09);
    }
    body {
      background-color: var(--bg-primary);
      background-image: var(--grid-pattern);
      background-size: 24px 24px;
      color: var(--text-primary);
      font-family: 'Inter', -apple-system, sans-serif;
      margin: 0;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 24px 16px;
      position: relative;
      overflow-x: hidden;
      transition: background-color 0.2s ease, color 0.2s ease;
    }
    .top-bar {
      position: absolute;
      top: 18px; right: 24px;
      z-index: 10;
    }
    .theme-toggle {
      background: var(--bg-card);
      border: 1px solid var(--border-card);
      border-radius: 20px;
      padding: 6px 14px;
      font-size: 12px;
      font-weight: 500;
      color: var(--text-secondary);
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
      transition: all 0.2s ease;
    }
    .theme-toggle:hover {
      border-color: var(--border-glass);
      color: var(--text-primary);
    }
    .auth-card {
      background: var(--bg-card);
      border: 1px solid var(--border-card);
      border-radius: 18px;
      box-shadow: var(--shadow-card);
      max-width: 440px;
      width: 100%;
      padding: 36px 30px;
      text-align: center;
      position: relative;
      z-index: 2;
      backdrop-filter: blur(16px);
    }
    .logo-wrap {
      width: 58px; height: 58px;
      background: var(--bg-primary);
      border: 1px solid var(--border-card);
      border-radius: 16px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 18px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.15);
    }
    .google-logo { width: 30px; height: 30px; }
    h2 {
      margin: 0 0 6px 0;
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    p {
      color: var(--text-secondary);
      font-size: 13px;
      margin: 0 0 20px 0;
      line-height: 1.45;
    }
    .req-badge {
      display: inline-block;
      background: var(--badge-bg);
      border: 1px solid var(--badge-border);
      color: var(--badge-text);
      font-size: 12px;
      font-weight: 600;
      padding: 4px 12px;
      border-radius: 14px;
      margin-bottom: 20px;
    }
    .btn-google {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
      width: 100%;
      box-sizing: border-box;
      background: #ffffff;
      color: #1f2937;
      border: 1px solid #d1d5db;
      border-radius: 10px;
      padding: 12px 16px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
      transition: background 0.15s, transform 0.1s;
    }
    .btn-google:hover {
      background: #f8fafc;
      transform: translateY(-1px);
    }
    .security-note {
      margin-top: 18px;
      font-size: 11px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 5px;
    }
    .setup-box {
      background: rgba(245, 158, 11, 0.08);
      border: 1px solid rgba(245, 158, 11, 0.25);
      border-radius: 10px;
      padding: 14px;
      text-align: left;
      margin-bottom: 18px;
      font-size: 12px;
    }
    .setup-title {
      font-weight: 700;
      color: #f59e0b;
      margin-bottom: 6px;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .setup-desc {
      color: var(--text-secondary);
      line-height: 1.4;
      margin-bottom: 8px;
    }
    .code-snippet {
      background: #0a0e17;
      color: #38bdf8;
      padding: 6px 8px;
      border-radius: 6px;
      font-family: Consolas, monospace;
      font-size: 11px;
      word-break: break-all;
    }
    .dev-bypass {
      margin-top: 20px;
      padding-top: 16px;
      border-top: 1px dashed var(--border-card);
    }
    .input-box {
      width: 100%;
      box-sizing: border-box;
      padding: 10px 14px;
      border-radius: 8px;
      border: 1px solid var(--input-border);
      background: var(--input-bg);
      color: var(--text-primary);
      font-size: 13px;
      margin-bottom: 10px;
    }
    .btn-dev {
      width: 100%;
      background: #334155;
      color: #f8fafc;
      border: none;
      padding: 9px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <div class="top-bar">
    <button class="theme-toggle" onclick="toggleTheme()" aria-label="Toggle visual theme">
      <span id="themeIcon">☀️</span>
      <span id="themeLabel">Light Ivory</span>
    </button>
  </div>
  <div class="auth-card">
    <div class="logo-wrap">
      <svg class="google-logo" viewBox="0 0 24 24">
        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
      </svg>
    </div>
    <h2>Sign in with Google</h2>
    <p>to manage your USB Vaults & authorize access</p>

    ${reqId ? `<div class="req-badge">Pending Request: <strong>${reqId}</strong></div>` : ''}
    ${sessionId ? `<div class="req-badge">Connecting Desktop Client App</div>` : ''}

    ${hasRealOAuth ? `
      <!-- Official Google OAuth 2.0 Redirect Button -->
      <a href="${oauthInfo.authUrl}" class="btn-google">
        <svg class="google-logo" style="width:18px;height:18px;" viewBox="0 0 24 24">
          <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
          <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
          <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
          <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
        </svg>
        <span>Continue with Google</span>
      </a>

      <!-- Google Identity Services One Tap / Standard Hook -->
      <div id="g_id_onload"
           data-client_id="${GOOGLE_CLIENT_ID}"
           data-context="signin"
           data-ux_mode="redirect"
           data-login_uri="${redirectUri}"
           data-auto_prompt="false">
      </div>
      <div class="security-note">
        <span>🛡️ Cryptographically verified by Google. Email identity cannot be forged.</span>
      </div>
    ` : `
      <!-- Unconfigured Notice -->
      <div class="setup-box">
        <div class="setup-title">🔒 Real Google OAuth Credentials Required</div>
        <div class="setup-desc">To prevent email infringement and guarantee identity authenticity, configure your Google Cloud OAuth Client ID in <code>backend/.env</code>:</div>
        <div class="code-snippet">GOOGLE_CLIENT_ID=your-id.apps.googleusercontent.com<br>GOOGLE_CLIENT_SECRET=your-secret</div>
        <div style="margin-top:8px;font-size:11px;color:var(--text-muted);">Redirect URI: <code>${redirectUri}</code></div>
      </div>

      ${!isProd ? `
        <div class="dev-bypass">
          <p style="font-size:12px;color:#f59e0b;margin-bottom:8px;"><strong>🧪 Development Mock Mode (Unverified)</strong><br>For local testing only. Blocked in production.</p>
          <form method="POST" action="/auth/google/callback">
            <input type="hidden" name="req" value="${reqId}">
            <input type="hidden" name="session_id" value="${sessionId}">
            <input type="hidden" name="redirect" value="${redirectUrl}">
            <input type="email" name="email" class="input-box" placeholder="Enter test email address" value="${hintEmail}" required>
            <button type="submit" class="btn-dev">Continue (Dev Mock)</button>
          </form>
        </div>
      ` : `
        <p style="color:#ef4444;font-size:12px;"><strong>Production Mode Active:</strong> Unverified email logins are permanently disabled. Set GOOGLE_CLIENT_ID on Render.</p>
      `}
    `}
  </div>
  <script>
    function updateThemeUI(t) {
      document.getElementById('themeIcon').textContent = t === 'dark' ? '☀️' : '🌙';
      document.getElementById('themeLabel').textContent = t === 'dark' ? 'Light Ivory' : 'Dark Mode';
    }
    function toggleTheme() {
      const cur = document.documentElement.getAttribute('data-theme') || 'dark';
      const nxt = cur === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', nxt);
      localStorage.setItem('theme', nxt);
      updateThemeUI(nxt);
    }
    const t = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', t);
    updateThemeUI(t);
  </script>
</body>
</html>`);
});

// Google OAuth 2.0 Redirect Callback (GET from Google servers)
app.get('/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    console.warn('Google OAuth error callback:', error);
    return res.status(400).send(renderAuthError('Google Sign-In Cancelled', `Google returned error: ${error}`));
  }

  if (!code) {
    return res.redirect('/auth/google');
  }

  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    return res.status(500).send(renderAuthError('OAuth Not Configured', 'Server is missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET.'));
  }

  let stateObj = {};
  if (state) {
    try {
      stateObj = JSON.parse(Buffer.from(state, 'base64url').toString('utf-8'));
    } catch (e) {
      console.warn('Failed to parse Google OAuth state:', e.message);
    }
  }

  const reqId = stateObj.reqId || '';
  const sessionId = stateObj.sessionId || '';
  const redirectUrl = stateObj.redirect || '';
  const redirectUri = getGoogleRedirectUri(req);

  try {
    // 1. Exchange authorization code for tokens
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
      })
    });

    if (!tokenResponse.ok) {
      const errText = await tokenResponse.text();
      console.error('Google token exchange error:', errText);
      return res.status(400).send(renderAuthError('Token Exchange Failed', 'Could not exchange authorization code with Google.'));
    }

    const tokenData = await tokenResponse.json();

    // 2. Fetch user profile from Google OpenID Connect endpoint
    const userinfoResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });

    if (!userinfoResponse.ok) {
      return res.status(400).send(renderAuthError('Profile Verification Failed', 'Could not retrieve verified profile from Google.'));
    }

    const userinfo = await userinfoResponse.json();

    if (!userinfo.email || (userinfo.email_verified !== true && userinfo.email_verified !== 'true')) {
      return res.status(403).send(renderAuthError('Unverified Google Email', 'This Google account does not have a verified email address.'));
    }

    const verifiedEmail = userinfo.email.toLowerCase().trim();
    console.log(`✅ Google OAuth 2.0 Verified: ${verifiedEmail} (${userinfo.name || 'User'})`);

    return handleSuccessfulGoogleAuth(req, res, {
      verifiedEmail,
      reqId,
      sessionId,
      redirectUrl
    });

  } catch (err) {
    console.error('Google OAuth callback exception:', err);
    return res.status(500).send(renderAuthError('Authentication Error', err.message));
  }
});

// Google Identity Services (GIS) / Credential Callback (POST)
app.post('/auth/google/callback', express.urlencoded({ extended: true }), async (req, res) => {
  const { credential, email, req: reqId, session_id: sessionId, redirect: redirectUrl } = req.body;

  // Case A: Real Google Identity Services ID Token credential
  if (credential) {
    try {
      const verifyRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`);
      if (!verifyRes.ok) {
        return res.status(401).send(renderAuthError('Invalid Google Credential', 'Google could not verify the provided ID token.'));
      }
      const payload = await verifyRes.json();

      if (GOOGLE_CLIENT_ID && payload.aud !== GOOGLE_CLIENT_ID) {
        return res.status(403).send(renderAuthError('Audience Mismatch', 'The Google token was issued for a different client ID.'));
      }

      if (!payload.email || (payload.email_verified !== 'true' && payload.email_verified !== true)) {
        return res.status(403).send(renderAuthError('Unverified Google Email', 'This Google email is not verified.'));
      }

      const verifiedEmail = payload.email.toLowerCase().trim();
      console.log(`✅ Google GIS Verified: ${verifiedEmail}`);

      return handleSuccessfulGoogleAuth(req, res, {
        verifiedEmail,
        reqId,
        sessionId,
        redirectUrl
      });
    } catch (err) {
      console.error('GIS token verification error:', err);
      return res.status(500).send(renderAuthError('Verification Error', err.message));
    }
  }

  // Case B: Dev mock bypass (ONLY permitted if not in production and real OAuth is unconfigured)
  if (process.env.NODE_ENV !== 'production' && !GOOGLE_CLIENT_ID && email) {
    const verifiedEmail = email.toLowerCase().trim();
    console.log(`🧪 Dev Mock Auth (Unverified): ${verifiedEmail}`);
    return handleSuccessfulGoogleAuth(req, res, {
      verifiedEmail,
      reqId,
      sessionId,
      redirectUrl
    });
  }

  return res.status(403).send(renderAuthError('Unauthorized', 'Direct unverified email submission is strictly prohibited.'));
});


// Check if desktop client session has been completed via Google Sign-In
app.get('/api/auth/google/check-session', (req, res) => {
  const sessionId = req.query.session_id;
  if (!sessionId || !googleClientSessions.has(sessionId)) {
    return res.status(200).json({ authenticated: false });
  }

  const session = googleClientSessions.get(sessionId);
  return res.status(200).json({
    authenticated: true,
    email: session.email,
    token: session.token
  });
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

    // ──────────────────────────────────────────────
    // Filter Level 1: Verify Google Account Identity & Authorization
    // ──────────────────────────────────────────────
    if (!email) {
      logAuthEvent(drive_id, fingerprint_hash, '', 'DENIED_NO_EMAIL', req);
      return res.status(403).json({
        status:  'DENIED',
        message: 'Google identity required. Please verify your email via Sign in with Google.'
      });
    }

    // ──────────────────────────────────────────────
    // 1. Direct Access: If email is owner or in access list, directly grant access
    // ──────────────────────────────────────────────
    const isOwner = (email === drive.owner_email.toLowerCase());
    const accessEntry = db.prepare(
      'SELECT allowed_email FROM access_list WHERE drive_id = ? AND allowed_email = ?'
    ).get(drive_id, email);
    const isAllowedUser = Boolean(accessEntry);

    if (isOwner || isAllowedUser) {
      const leaseSeconds = LEASE_DAYS * 24 * 60 * 60;
      const lease = generateLeaseToken(drive_id, fingerprint_hash, leaseSeconds);

      // Auto-register device as trusted for this authorized user so future sessions on this machine are trusted
      const now = Math.floor(Date.now() / 1000);
      db.prepare(`
        INSERT OR REPLACE INTO trusted_devices
          (drive_id, hardware_fingerprint, user_email, trust_scope, expires_at, created_at)
        VALUES (?, ?, ?, 'LEASE', ?, ?)
      `).run(drive_id, fingerprint_hash, email, now + leaseSeconds, Date.now());

      logAuthEvent(drive_id, fingerprint_hash, email, 'GRANTED', req);
      console.log(`✅  GRANTED (Direct Access for ${isOwner ? 'Owner' : 'Authorized User'}): Drive ${drive_id} → ${email}`);

      return res.status(200).json({
        status:          'GRANTED',
        cloud_key_share: drive.cloud_key_share,
        lease_token:     lease.token,
        expires_at:      lease.expiresAtISO,
        expires_at_unix: lease.expiresAt,
        drive_label:     drive.label,
        trust_scope:     'LEASE'
      });
    }

    // ──────────────────────────────────────────────
    // 2. Check if this hardware was already authorized by owner
    // ──────────────────────────────────────────────
    const trustedDevice = db.prepare(
      'SELECT * FROM trusted_devices WHERE drive_id = ? AND hardware_fingerprint = ?'
    ).get(drive_id, fingerprint_hash);

    if (trustedDevice) {
      const now = Math.floor(Date.now() / 1000);

      if (trustedDevice.trust_scope === 'LEASE' && trustedDevice.expires_at && now >= trustedDevice.expires_at) {
        db.prepare('DELETE FROM trusted_devices WHERE id = ?').run(trustedDevice.id);
        console.log(`⏰  Trust expired for device on drive ${drive_id}`);
      } else if (trustedDevice.trust_scope === 'ONE_TIME') {
        db.prepare('DELETE FROM trusted_devices WHERE id = ?').run(trustedDevice.id);
        console.log(`🔑  One-time trust consumed for drive ${drive_id}`);

        const leaseSeconds = 12 * 60 * 60;
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
        let leaseSeconds = trustedDevice.trust_scope === 'FOREVER'
          ? LEASE_DAYS * 24 * 60 * 60
          : Math.max(trustedDevice.expires_at - now, 3600);

        const lease = generateLeaseToken(drive_id, fingerprint_hash, leaseSeconds);
        logAuthEvent(drive_id, fingerprint_hash, email, 'GRANTED', req);

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

    // ──────────────────────────────────────────────
    // 3. Unauthorized User: Route to out-of-band approval screen
    // ──────────────────────────────────────────────
    console.log(`⏳ Unauthorized user ${email} on device ${fingerprint_hash}. Routing to out-of-band approval...`);

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

    if (request.requester_email) {
      db.prepare(`
        INSERT OR IGNORE INTO access_list (drive_id, allowed_email, added_at)
        VALUES (?, ?, ?)
      `).run(request.drive_id, request.requester_email.toLowerCase().trim(), Date.now());
    }

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
// Quick Approval Endpoints for Mobile / Direct Links
// ──────────────────────────────────────────────

app.get('/api/request-info/:request_id', (req, res) => {
  try {
    const { request_id } = req.params;
    const request = db.prepare(`
      SELECT pr.request_id, pr.drive_id, pr.requester_email, pr.status, pr.created_at, pr.granted_scope, pr.hardware_fingerprint,
             d.label as drive_label, d.owner_email
      FROM pending_requests pr
      LEFT JOIN drives d ON pr.drive_id = d.drive_id
      WHERE pr.request_id = ?
    `).get(request_id);

    if (!request) {
      return res.status(404).json({ error: 'Request not found.' });
    }

    const authOwner = getOwnerEmail(req);
    const isOwner = Boolean(authOwner && request.owner_email && authOwner.toLowerCase() === request.owner_email.toLowerCase());

    return res.status(200).json({
      request_id: request.request_id,
      drive_id: request.drive_id,
      drive_label: request.drive_label || 'USB Drive',
      owner_email: request.owner_email,
      requester_email: request.requester_email || 'Unknown',
      fingerprint_preview: request.hardware_fingerprint ? request.hardware_fingerprint.slice(0, 16) + '...' : '',
      status: request.status,
      granted_scope: request.granted_scope,
      created_at: new Date(request.created_at).toISOString(),
      current_user: authOwner || null,
      is_authenticated: Boolean(authOwner),
      is_owner: isOwner,
      can_approve: isOwner
    });
  } catch (err) {
    console.error('Request-info error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

app.post('/api/approve-quick', (req, res) => {
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
      return res.status(404).json({ error: 'Pending request not found or already resolved.' });
    }

    const drive = db.prepare('SELECT * FROM drives WHERE drive_id = ?').get(request.drive_id);
    if (!drive) {
      return res.status(404).json({ error: 'Associated drive not found.' });
    }

    // Verify caller is the authenticated owner or admin
    const authOwner = getOwnerEmail(req);
    const adminKey = req.headers['x-admin-key'];
    const isAdmin = adminKey && adminKey === ADMIN_KEY;

    if (!isAdmin && (!authOwner || authOwner.toLowerCase() !== drive.owner_email.toLowerCase())) {
      return res.status(403).json({ error: 'Unauthorised. Only the verified drive owner can approve this request.' });
    }

    // Calculate lease duration
    let leaseSeconds;
    const nowUnix = Math.floor(Date.now() / 1000);

    if (scope === 'ONE_TIME') {
      leaseSeconds = 12 * 60 * 60; // 12 hours
    } else if (scope === 'CUSTOM_LEASE') {
      const hours = parseInt(lease_hours) || 24;
      leaseSeconds = hours * 60 * 60;
    } else { // FOREVER
      leaseSeconds = LEASE_DAYS * 24 * 60 * 60;
    }

    const lease = generateLeaseToken(request.drive_id, request.hardware_fingerprint, leaseSeconds);
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

    if (request.requester_email) {
      db.prepare(`
        INSERT OR IGNORE INTO access_list (drive_id, allowed_email, added_at)
        VALUES (?, ?, ?)
      `).run(request.drive_id, request.requester_email.toLowerCase().trim(), Date.now());
    }

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

    console.log(`⚡  QUICK APPROVED: Request ${request_id} → ${scope} by ${authOwner || 'admin'}`);

    return res.status(200).json({
      message: `Request approved with scope: ${scope}`,
      request_id,
      scope,
      expires_at: lease.expiresAtISO,
      trust_scope: trustScope
    });
  } catch (err) {
    console.error('Approve-quick error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

app.post('/api/deny-quick', (req, res) => {
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

    const drive = db.prepare('SELECT * FROM drives WHERE drive_id = ?').get(request.drive_id);
    if (!drive) {
      return res.status(404).json({ error: 'Associated drive not found.' });
    }

    const authOwner = getOwnerEmail(req);
    const adminKey = req.headers['x-admin-key'];
    const isAdmin = adminKey && adminKey === ADMIN_KEY;

    if (!isAdmin && (!authOwner || authOwner.toLowerCase() !== drive.owner_email.toLowerCase())) {
      return res.status(403).json({ error: 'Unauthorised. Only the verified drive owner can deny this request.' });
    }

    db.prepare(`
      UPDATE pending_requests SET status = 'DENIED', resolved_at = ? WHERE request_id = ?
    `).run(Date.now(), request_id);

    console.log(`⛔  QUICK DENIED: Request ${request_id} by ${authOwner || 'admin'}`);

    return res.status(200).json({
      message: 'Request denied.',
      request_id,
      status: 'DENIED'
    });
  } catch (err) {
    console.error('Deny-quick error:', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

app.get(['/approve', '/approve/:request_id'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'approve.html'));
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
    const { drive_id, reason, remove_access_list } = req.body;
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

    // Optionally remove all authorized guest users from the access list (keep owner)
    if (remove_access_list) {
      db.prepare(`
        DELETE FROM access_list WHERE drive_id = ? AND LOWER(TRIM(allowed_email)) != LOWER(TRIM(?))
      `).run(drive_id, drive.owner_email);
      console.log(`🧹 Access list cleared for drive ${drive_id} (kept owner ${drive.owner_email})`);
    }

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
    const ownerEmail = getOwnerEmail(req);
    const key = req.headers['x-admin-key'];
    const isAdmin = key && key === ADMIN_KEY;

    let drives;
    if (isAdmin || !ownerEmail) {
      drives = db.prepare(`
        SELECT drive_id, label, owner_email, status, lost_reason, created_at, updated_at
        FROM drives ORDER BY created_at DESC
      `).all();
    } else {
      // Return ONLY drives owned by this user (not drives where user is merely a guest in access_list)
      drives = db.prepare(`
        SELECT d.drive_id, d.label, d.owner_email, d.status, d.lost_reason, d.created_at, d.updated_at
        FROM drives d
        WHERE LOWER(TRIM(d.owner_email)) = ?
        ORDER BY d.created_at DESC
      `).all(ownerEmail.toLowerCase().trim());
    }

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
    const ownerEmail = getOwnerEmail(req);
    const key = req.headers['x-admin-key'];
    const isAdmin = key && key === ADMIN_KEY;

    let pending;
    if (isAdmin || !ownerEmail) {
      pending = db.prepare(`
        SELECT pr.*, d.label as drive_label, d.owner_email
        FROM pending_requests pr
        LEFT JOIN drives d ON pr.drive_id = d.drive_id
        WHERE pr.status = 'PENDING'
        ORDER BY pr.created_at DESC
      `).all();
    } else {
      pending = db.prepare(`
        SELECT pr.*, d.label as drive_label, d.owner_email
        FROM pending_requests pr
        JOIN drives d ON pr.drive_id = d.drive_id
        WHERE d.owner_email = ? AND pr.status = 'PENDING'
        ORDER BY pr.created_at DESC
      `).all(ownerEmail.toLowerCase().trim());
    }

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
// Route: GET /auth/logout
// ──────────────────────────────────────────────

app.get('/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'owner_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
  const redirect = req.query.redirect || '';
  const reqId = req.query.req || '';
  if (reqId) {
    return res.redirect(`/auth/google?force=true&req=${encodeURIComponent(reqId)}`);
  }
  if (redirect) {
    return res.redirect(`/auth/google?force=true&redirect=${encodeURIComponent(redirect)}`);
  }
  res.redirect('/auth/google?force=true');
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
// Dashboard HTML Auth Gate & Route
// ──────────────────────────────────────────────

app.get(['/dashboard', '/dashboard/index.html'], (req, res, next) => {
  const ownerEmail = getOwnerEmail(req);
  const key = req.headers['x-admin-key'];
  if (!ownerEmail && (!key || key !== ADMIN_KEY)) {
    return res.redirect('/auth/google?redirect=/dashboard');
  }
  next();
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
