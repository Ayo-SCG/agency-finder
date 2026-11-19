// Agency Finder server. Ayo Strategic Consulting Group, LLC.
// Serves the tool only to signed in users, saves each user's target list,
// counts usage, and relays USAspending and the nightly SAM.gov file so the
// page keeps working from one address.
//
// Settings (environment variables):
//   DATABASE_URL    Postgres connection string (Railway provides this)
//   ADMIN_EMAIL     Email of the owner account, created at start up
//   ADMIN_PASSWORD  Password for the owner account (12 characters or more)
//   NODE_ENV        Set to "production" on the host so cookies are secure
//   OPPS_BASE       Optional. Where the nightly opportunity files live
//   OPPS_TOKEN      Optional. GitHub token, needed only if the repository is private
//   PGSSL           Optional. Set to 1 if the database requires SSL

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const PROD = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;
const USA = 'https://api.usaspending.gov/api/v2';
const OPPS_BASE = process.env.OPPS_BASE || 'https://raw.githubusercontent.com/Ayo-SCG/agency-finder/data/opps/';
const SESSION_DAYS = 30;
const COOKIE = 'af_session';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is not set. Add a Postgres database and try again.');
  process.exit(1);
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === '1' ? { rejectUnauthorized: false } : undefined,
  max: 8,
});
const q = (text, params) => pool.query(text, params);

async function migrate() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL DEFAULT '',
      company TEXT NOT NULL DEFAULT '',
      password_hash TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      disabled BOOLEAN NOT NULL DEFAULT FALSE,
      access_until TIMESTAMPTZ,
      code_used TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_seen TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS access_codes (
      code TEXT PRIMARY KEY,
      label TEXT NOT NULL DEFAULT '',
      max_uses INTEGER NOT NULL DEFAULT 100,
      uses INTEGER NOT NULL DEFAULT 0,
      access_days INTEGER NOT NULL DEFAULT 365,
      expires_at TIMESTAMPTZ,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS lists (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS events (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      detail TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS events_user_time ON events (user_id, created_at);
    CREATE INDEX IF NOT EXISTS events_type_time ON events (type, created_at);
  `);
  const email = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const pw = process.env.ADMIN_PASSWORD || '';
  if (email && pw.length >= 12) {
    const hash = await bcrypt.hash(pw, 11);
    await q(
      `INSERT INTO users (email, name, password_hash, is_admin)
       VALUES ($1, 'Owner', $2, TRUE)
       ON CONFLICT (email) DO UPDATE SET password_hash = $2, is_admin = TRUE, disabled = FALSE, access_until = NULL`,
      [email, hash]
    );
  } else {
    console.warn('ADMIN_EMAIL and ADMIN_PASSWORD (12 characters or more) are not both set. No owner account was created.');
  }
  await q('DELETE FROM sessions WHERE expires_at < now()');
}

const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 11);
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const cleanEmail = (s) => String(s || '').trim().toLowerCase().slice(0, 200);
const cleanText = (s, n) => String(s || '').trim().slice(0, n);
const validEmail = (s) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s);

function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return '';
}
function setCookie(res, token, days) {
  const bits = [`${COOKIE}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${Math.round(days * 86400)}`];
  if (PROD) bits.push('Secure');
  res.setHeader('Set-Cookie', bits.join('; '));
}
async function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  await q(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, now() + ($3 || ' days')::interval)`, [sha(token), userId, String(SESSION_DAYS)]);
  setCookie(res, token, SESSION_DAYS);
}
function logEvent(userId, type, detail) {
  q('INSERT INTO events (user_id, type, detail) VALUES ($1, $2, $3)', [userId, type, cleanText(detail, 300)]).catch(() => {});
}

// Simple limit on sign in and sign up attempts, per address.
const attempts = new Map();
function tooMany(key, limit, windowMs) {
  const now = Date.now();
  const rec = attempts.get(key);
  if (!rec || now - rec.start > windowMs) { attempts.set(key, { start: now, n: 1 }); return false; }
  rec.n += 1;
  return rec.n > limit;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of attempts) if (now - v.start > 3600e3) attempts.delete(k); }, 600e3).unref();

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (PROD) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});
app.use(express.json({ limit: '300kb' }));

// Requests that change anything must come from this site.
app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  const origin = req.headers.origin;
  if (origin) {
    let host = '';
    try { host = new URL(origin).host; } catch (e) { /* ignore */ }
    if (host !== req.headers.host) return res.status(403).json({ error: 'This request did not come from the Agency Finder.' });
  }
  next();
});

// Attach the signed in user, if any.
app.use(async (req, res, next) => {
  try {
    const token = readCookie(req, COOKIE);
    if (token) {
      const r = await q(
        `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > now()`,
        [sha(token)]
      );
      const u = r.rows[0];
      if (u && !u.disabled && (!u.access_until || new Date(u.access_until) > new Date())) {
        req.user = u;
        if (!u.last_seen || Date.now() - new Date(u.last_seen).getTime() > 300e3) {
          q('UPDATE users SET last_seen = now() WHERE id = $1', [u.id]).catch(() => {});
        }
      } else if (u) {
        req.lapsed = true;
      }
    }
    next();
  } catch (e) { next(e); }
});
const needUser = (req, res, next) => (req.user ? next() : res.status(401).json({ error: 'Please sign in.' }));
const needAdmin = (req, res, next) => (req.user && req.user.is_admin ? next() : res.status(403).json({ error: 'Owner access only.' }));

const page = (name) => path.join(__dirname, name);
app.get('/', (req, res) => {
  if (!req.user) return res.redirect(req.lapsed ? '/signin?ended=1' : '/signin');
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(page('index.html'));
});
app.get('/signin', (req, res) => { if (req.user) return res.redirect('/'); res.setHeader('Cache-Control', 'no-store'); res.sendFile(page('signin.html')); });
app.get('/admin', (req, res) => {
  if (!req.user) return res.redirect('/signin');
  if (!req.user.is_admin) return res.redirect('/');
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(page('admin.html'));
});
app.get('/healthz', (req, res) => res.json({ ok: true }));

app.get('/api/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Please sign in.' });
  const u = req.user;
  res.json({ email: u.email, name: u.name, company: u.company, isAdmin: u.is_admin, accessUntil: u.access_until });
});

app.post('/api/signin', async (req, res, next) => {
  try {
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || '');
    if (tooMany('in|' + req.ip + '|' + email, 10, 900e3)) return res.status(429).json({ error: 'Too many tries. Wait 15 minutes and try again.' });
    const r = await q('SELECT * FROM users WHERE email = $1', [email]);
    const u = r.rows[0];
    const ok = await bcrypt.compare(password, u ? u.password_hash : DUMMY_HASH) && !!u;
    if (!ok) return res.status(401).json({ error: 'That email and password do not match.' });
    if (u.disabled) return res.status(403).json({ error: 'This account has been turned off. Contact Ayo Strategic Consulting Group, LLC.' });
    if (u.access_until && new Date(u.access_until) <= new Date()) return res.status(403).json({ error: 'Your access period has ended. Contact Ayo Strategic Consulting Group, LLC to renew.' });
    await startSession(res, u.id);
    logEvent(u.id, 'signin', '');
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.post('/api/signup', async (req, res, next) => {
  const client = await pool.connect();
  try {
    if (tooMany('up|' + req.ip, 15, 3600e3)) return res.status(429).json({ error: 'Too many tries. Wait an hour and try again.' });
    const email = cleanEmail(req.body.email);
    const name = cleanText(req.body.name, 120);
    const company = cleanText(req.body.company, 160);
    const password = String(req.body.password || '');
    const code = cleanText(req.body.code, 60).toUpperCase();
    if (!name) return res.status(400).json({ error: 'Enter your name.' });
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (password.length < 10) return res.status(400).json({ error: 'Choose a password with 10 characters or more.' });
    if (password.length > 200) return res.status(400).json({ error: 'That password is too long.' });
    if (!code) return res.status(400).json({ error: 'Enter the access code you were given.' });
    await client.query('BEGIN');
    const c = (await client.query('SELECT * FROM access_codes WHERE code = $1 FOR UPDATE', [code])).rows[0];
    if (!c || !c.active || (c.expires_at && new Date(c.expires_at) <= new Date())) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'That access code is not valid. Check the code and try again.' });
    }
    if (c.uses >= c.max_uses) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'That access code has been used the maximum number of times.' });
    }
    const exists = (await client.query('SELECT 1 FROM users WHERE email = $1', [email])).rowCount;
    if (exists) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'An account with that email already exists. Use Sign in.' });
    }
    const hash = await bcrypt.hash(password, 11);
    const u = (await client.query(
      `INSERT INTO users (email, name, company, password_hash, code_used, access_until)
       VALUES ($1, $2, $3, $4, $5, now() + ($6 || ' days')::interval) RETURNING id`,
      [email, name, company, hash, code, String(c.access_days)]
    )).rows[0];
    await client.query('UPDATE access_codes SET uses = uses + 1 WHERE code = $1', [code]);
    await client.query('COMMIT');
    await startSession(res, u.id);
    logEvent(u.id, 'signup', code);
    res.json({ ok: true });
  } catch (e) { try { await client.query('ROLLBACK'); } catch (x) { /* ignore */ } next(e); }
  finally { client.release(); }
});

app.post('/api/signout', async (req, res, next) => {
  try {
    const token = readCookie(req, COOKIE);
    if (token) await q('DELETE FROM sessions WHERE token_hash = $1', [sha(token)]);
    setCookie(res, '', 0);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.post('/api/password', needUser, async (req, res, next) => {
  try {
    const cur = String(req.body.current || ''), nw = String(req.body.next || '');
    if (nw.length < 10 || nw.length > 200) return res.status(400).json({ error: 'Choose a password with 10 characters or more.' });
    if (!(await bcrypt.compare(cur, req.user.password_hash))) return res.status(400).json({ error: 'Your current password is not correct.' });
    await q('UPDATE users SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(nw, 11), req.user.id]);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// Target list, saved to the account.
app.get('/api/list', needUser, async (req, res, next) => {
  try {
    const r = await q('SELECT data FROM lists WHERE user_id = $1', [req.user.id]);
    res.json(r.rows[0] ? r.rows[0].data : { items: [], notes: '' });
  } catch (e) { next(e); }
});
app.put('/api/list', needUser, async (req, res, next) => {
  try {
    const b = req.body || {};
    const items = Array.isArray(b.items) ? b.items.slice(0, 500).map((it) => ({
      key: cleanText(it.key, 400), kind: cleanText(it.kind, 40), name: cleanText(it.name, 400),
      detail: cleanText(it.detail, 800), link: /^https:\/\//.test(String(it.link || '')) ? cleanText(it.link, 600) : '',
      note: String(it.note || '').slice(0, 4000),
    })) : [];
    const data = { items, notes: String(b.notes || '').slice(0, 20000) };
    await q(
      `INSERT INTO lists (user_id, data) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET data = $2, updated_at = now()`,
      [req.user.id, JSON.stringify(data)]
    );
    res.json({ ok: true });
  } catch (e) { next(e); }
});

const EVENT_TYPES = new Set(['print', 'copy', 'solicitation']);
app.post('/api/event', needUser, (req, res) => {
  const type = String(req.body.type || '');
  if (EVENT_TYPES.has(type)) logEvent(req.user.id, type, req.body.detail);
  res.json({ ok: true });
});

// Small in memory cache so repeat searches are fast and the tool leans less on USAspending.
const cache = new Map();
function cacheGet(key) {
  const hit = cache.get(key);
  if (!hit) return null;
  if (Date.now() > hit.until) { cache.delete(key); return null; }
  return hit;
}
function cacheSet(key, value, ttlMs) {
  if (cache.size > 3000) { const first = cache.keys().next().value; cache.delete(first); }
  cache.set(key, Object.assign({ until: Date.now() + ttlMs }, value));
}
async function fetchWithTimeout(url, opts, ms) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try { return await fetch(url, Object.assign({ signal: ctl.signal }, opts)); } finally { clearTimeout(t); }
}

const USA_ALLOWED = [
  /^search\/spending_by_category\/(awarding_agency|awarding_subagency|recipient)\/$/,
  /^search\/spending_over_time\/$/,
  /^search\/spending_by_award\/$/,
  /^search\/spending_by_award_count\/$/,
  /^autocomplete\/naics\/$/,
  /^references\/naics\/\d{2,6}\/$/,
  /^awards\/[A-Za-z0-9_.\-]{1,200}\/$/,
];
app.all('/api/usa/*', needUser, async (req, res) => {
  const sub = req.params[0] || '';
  if (!USA_ALLOWED.some((re) => re.test(sub)) || (req.method !== 'GET' && req.method !== 'POST')) {
    return res.status(404).json({ error: 'Not available.' });
  }
  const body = req.method === 'POST' ? JSON.stringify(req.body || {}) : '';
  const key = req.method + ' ' + sub + ' ' + sha(body);
  if (req.method === 'POST' && sub === 'search/spending_by_category/awarding_agency/' && req.body && req.body.limit === 10) {
    const f = req.body.filters || {};
    logEvent(req.user.id, 'search', (f.naics_codes || []).join(','));
  }
  if (sub === 'search/spending_by_award_count/') {
    const f = (req.body && req.body.filters) || {};
    logEvent(req.user.id, 'contracts', (f.naics_codes || []).join(',') + ' | ' + (f.agencies || []).map((a) => a.name).join('; '));
  }
  const hit = cacheGet(key);
  if (hit) { res.setHeader('X-Cache', 'hit'); return res.status(hit.status).type('application/json').send(hit.text); }
  try {
    const r = await fetchWithTimeout(USA + '/' + sub, {
      method: req.method,
      headers: req.method === 'POST' ? { 'Content-Type': 'application/json' } : {},
      body: req.method === 'POST' ? body : undefined,
    }, 60000);
    const text = await r.text();
    if (r.ok) cacheSet(key, { status: r.status, text }, sub.startsWith('autocomplete') || sub.startsWith('references') ? 7 * 86400e3 : 12 * 3600e3);
    res.status(r.status).type('application/json').send(text);
  } catch (e) {
    res.status(502).json({ error: 'USAspending did not answer. Try again in a moment.' });
  }
});

app.get('/api/opps/:file', needUser, async (req, res) => {
  const file = req.params.file;
  if (!/^(index|\d{6})\.json$/.test(file)) return res.status(404).json({ error: 'Not available.' });
  const key = 'opps ' + file;
  const hit = cacheGet(key);
  if (hit) return res.status(hit.status).type('application/json').send(hit.text);
  try {
    const headers = process.env.OPPS_TOKEN ? { Authorization: 'Bearer ' + process.env.OPPS_TOKEN } : {};
    const r = await fetchWithTimeout(OPPS_BASE + file, { headers }, 30000);
    const text = await r.text();
    if (r.ok) cacheSet(key, { status: 200, text }, 3600e3);
    if (!r.ok) return res.status(r.status === 404 ? 404 : 502).json({ error: 'Not available.' });
    res.type('application/json').send(text);
  } catch (e) {
    res.status(502).json({ error: 'The nightly opportunity list did not answer.' });
  }
});

// Owner pages.
function newCode() {
  const letters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = '';
  const bytes = crypto.randomBytes(8);
  for (let i = 0; i < 8; i++) s += letters[bytes[i] % letters.length];
  return 'AYO' + s;
}
app.get('/api/admin/summary', needAdmin, async (req, res, next) => {
  try {
    const [users, codes, totals, daily, naics] = await Promise.all([
      q(`SELECT u.id, u.email, u.name, u.company, u.is_admin, u.disabled, u.access_until, u.code_used, u.created_at, u.last_seen,
                COALESCE(e.searches, 0)::int AS searches, COALESCE(e.contracts, 0)::int AS contracts,
                COALESCE(e.prints, 0)::int AS prints, COALESCE(e.days, 0)::int AS days_active
         FROM users u LEFT JOIN (
           SELECT user_id,
                  COUNT(*) FILTER (WHERE type = 'search') AS searches,
                  COUNT(*) FILTER (WHERE type = 'contracts') AS contracts,
                  COUNT(*) FILTER (WHERE type IN ('print', 'copy')) AS prints,
                  COUNT(DISTINCT created_at::date) AS days
           FROM events GROUP BY user_id) e ON e.user_id = u.id
         ORDER BY u.last_seen DESC NULLS LAST, u.created_at DESC`),
      q('SELECT * FROM access_codes ORDER BY created_at DESC'),
      q(`SELECT (SELECT COUNT(*) FROM users WHERE NOT is_admin)::int AS users,
                (SELECT COUNT(DISTINCT user_id) FROM events WHERE created_at > now() - interval '7 days')::int AS active7,
                (SELECT COUNT(DISTINCT user_id) FROM events WHERE created_at > now() - interval '30 days')::int AS active30,
                (SELECT COUNT(*) FROM events WHERE type = 'search' AND created_at > now() - interval '30 days')::int AS searches30,
                (SELECT COUNT(*) FROM events WHERE type = 'contracts' AND created_at > now() - interval '30 days')::int AS contracts30,
                (SELECT COUNT(*) FROM events WHERE type IN ('print', 'copy') AND created_at > now() - interval '30 days')::int AS prints30`),
      q(`SELECT created_at::date AS day, COUNT(DISTINCT user_id)::int AS people, COUNT(*) FILTER (WHERE type = 'search')::int AS searches
         FROM events WHERE created_at > now() - interval '30 days' GROUP BY 1 ORDER BY 1 DESC`),
      q(`SELECT detail AS code, COUNT(*)::int AS n FROM events WHERE type = 'search' AND detail <> '' AND created_at > now() - interval '90 days'
         GROUP BY 1 ORDER BY 2 DESC LIMIT 15`),
    ]);
    res.json({ users: users.rows, codes: codes.rows, totals: totals.rows[0], daily: daily.rows, naics: naics.rows });
  } catch (e) { next(e); }
});
app.post('/api/admin/codes', needAdmin, async (req, res, next) => {
  try {
    const label = cleanText(req.body.label, 120);
    const maxUses = Math.min(5000, Math.max(1, parseInt(req.body.maxUses, 10) || 50));
    const days = Math.min(3660, Math.max(1, parseInt(req.body.accessDays, 10) || 365));
    const custom = cleanText(req.body.code, 40).toUpperCase().replace(/[^A-Z0-9]/g, '');
    const code = custom.length >= 6 ? custom : newCode();
    const r = await q(
      `INSERT INTO access_codes (code, label, max_uses, access_days) VALUES ($1, $2, $3, $4) ON CONFLICT (code) DO NOTHING RETURNING code`,
      [code, label, maxUses, days]
    );
    if (!r.rowCount) return res.status(400).json({ error: 'That code already exists. Choose another.' });
    res.json({ ok: true, code });
  } catch (e) { next(e); }
});
app.post('/api/admin/codes/:code/toggle', needAdmin, async (req, res, next) => {
  try { await q('UPDATE access_codes SET active = NOT active WHERE code = $1', [req.params.code]); res.json({ ok: true }); } catch (e) { next(e); }
});
app.post('/api/admin/users/:id/toggle', needAdmin, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (id === req.user.id) return res.status(400).json({ error: 'You cannot turn off your own account.' });
    await q('UPDATE users SET disabled = NOT disabled WHERE id = $1 AND NOT is_admin', [id]);
    await q('DELETE FROM sessions WHERE user_id = $1 AND user_id IN (SELECT id FROM users WHERE disabled)', [id]);
    res.json({ ok: true });
  } catch (e) { next(e); }
});
app.post('/api/admin/users/:id/extend', needAdmin, async (req, res, next) => {
  try {
    const days = Math.min(3660, Math.max(1, parseInt(req.body.days, 10) || 365));
    await q(`UPDATE users SET access_until = GREATEST(COALESCE(access_until, now()), now()) + ($2 || ' days')::interval WHERE id = $1 AND NOT is_admin`, [parseInt(req.params.id, 10), String(days)]);
    res.json({ ok: true });
  } catch (e) { next(e); }
});
app.post('/api/admin/users/:id/reset', needAdmin, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    const temp = crypto.randomBytes(9).toString('base64').replace(/[^A-Za-z0-9]/g, 'x') + '7k';
    const r = await q('UPDATE users SET password_hash = $1 WHERE id = $2 AND NOT is_admin', [await bcrypt.hash(temp, 11), id]);
    if (!r.rowCount) return res.status(400).json({ error: 'That account cannot be reset here.' });
    await q('DELETE FROM sessions WHERE user_id = $1', [id]);
    res.json({ ok: true, tempPassword: temp });
  } catch (e) { next(e); }
});

app.use((req, res) => res.status(404).type('text/plain').send('Not found.'));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'That request could not be read.' });
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on our side. Try again.' });
});

migrate().then(() => {
  app.listen(PORT, () => console.log('Agency Finder is listening on port ' + PORT));
}).catch((e) => { console.error('Could not start:', e); process.exit(1); });
