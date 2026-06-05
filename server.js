#!/usr/bin/env node
/**
 * SecureChat v2 — Pure Node.js, zero dependencies
 * Features: passcode login, file sharing, rename, persistent chat logs,
 *           device fingerprint paper trail, private group chats with passwords,
 *           admin dashboard with clear-all-users, download logs, full audit trail
 */

const http = require('http');
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const url  = require('url');
const os   = require('os');

// ── Config ─────────────────────────────────────────────────────────────────────
const PORT        = process.env.PORT || 3000;
const UPLOAD_DIR  = path.join(__dirname, 'uploads');
const DATA_DIR    = path.join(__dirname, 'data');
const LOG_FILE    = path.join(DATA_DIR, 'chatlog.json');
const STATE_FILE  = path.join(DATA_DIR, 'state.json');
const AUDIT_FILE  = path.join(DATA_DIR, 'audit.json');
const MAX_FILE_MB = 10;
const MAX_MESSAGES = 1000;

for (const d of [UPLOAD_DIR, DATA_DIR]) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

// ── Persistent state ────────────────────────────────────────────────────────────
function loadJSON(file, def) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return def; }
}
function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

const savedState = loadJSON(STATE_FILE, {});

let state = {
  passcode:      savedState.passcode      || 'secret123',
  adminPassword: savedState.adminPassword || 'admin999',
  groups:        savedState.groups        || {},   // id → { name, password, createdAt, createdBy }
};

// messages: loaded from log file, kept in memory
let messages    = loadJSON(LOG_FILE,   []);
let auditLog    = loadJSON(AUDIT_FILE, []);
let sessions    = {};   // token → { username, joinedAt, lastSeen, ip, ua, deviceId, fingerprint }
let bannedTokens = new Set();
let groupMessages = {}; // groupId → [msg, ...]

// Load group messages
for (const gid of Object.keys(state.groups)) {
  const gf = path.join(DATA_DIR, `group_${gid}.json`);
  groupMessages[gid] = loadJSON(gf, []);
}

function persistState()  { saveJSON(STATE_FILE, { passcode: state.passcode, adminPassword: state.adminPassword, groups: state.groups }); }
function persistMessages(){ saveJSON(LOG_FILE, messages); }
function persistAudit()  { saveJSON(AUDIT_FILE, auditLog); }
function persistGroup(gid){ saveJSON(path.join(DATA_DIR, `group_${gid}.json`), groupMessages[gid] || []); }

// Auto-save every 30 seconds
setInterval(() => { persistMessages(); persistAudit(); }, 30000);

// Save on exit
process.on('SIGINT',  () => { persistMessages(); persistAudit(); persistState(); process.exit(0); });
process.on('SIGTERM', () => { persistMessages(); persistAudit(); persistState(); process.exit(0); });

// ── Helpers ─────────────────────────────────────────────────────────────────────
function uid()   { return crypto.randomBytes(12).toString('hex'); }
function now()   { return Date.now(); }
function tsStr() { return new Date().toISOString(); }

function deviceFingerprint(req) {
  const ua  = req.headers['user-agent'] || 'unknown';
  const ip  = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const lang = req.headers['accept-language'] || '';
  const enc  = req.headers['accept-encoding'] || '';
  const raw  = `${ip}|${ua}|${lang}|${enc}`;
  const hash = crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16);
  return { ip, ua, lang, fingerprint: hash };
}

function parseUA(ua) {
  if (!ua || ua === 'unknown') return { browser: 'Unknown', os: 'Unknown', device: '?' };
  let browser = 'Unknown', osName = 'Unknown', device = 'Desktop';
  if (/Mobile|Android|iPhone|iPad/.test(ua)) device = 'Mobile';
  if (/Tablet|iPad/.test(ua)) device = 'Tablet';
  if (/Chrome\//.test(ua) && !/Chromium|Edg/.test(ua)) browser = 'Chrome';
  else if (/Firefox\//.test(ua)) browser = 'Firefox';
  else if (/Safari\//.test(ua) && !/Chrome/.test(ua)) browser = 'Safari';
  else if (/Edg\//.test(ua)) browser = 'Edge';
  else if (/OPR\/|Opera/.test(ua)) browser = 'Opera';
  if (/Windows NT/.test(ua)) osName = 'Windows';
  else if (/Mac OS X/.test(ua)) osName = 'macOS';
  else if (/Linux/.test(ua)) osName = 'Linux';
  else if (/Android/.test(ua)) osName = 'Android';
  else if (/iPhone|iPad|iOS/.test(ua)) osName = 'iOS';
  return { browser, os: osName, device };
}

function addAudit(type, data) {
  auditLog.push({ id: uid(), type, ts: tsStr(), ...data });
  if (auditLog.length > 5000) auditLog = auditLog.slice(-5000);
}

// ── Session helpers ─────────────────────────────────────────────────────────────
function createSession(username, req) {
  const token = uid();
  const fp = deviceFingerprint(req);
  const dev = parseUA(fp.ua);
  sessions[token] = {
    username,
    joinedAt: now(),
    lastSeen: now(),
    ip: fp.ip,
    ua: fp.ua,
    lang: fp.lang,
    fingerprint: fp.fingerprint,
    browser: dev.browser,
    os: dev.os,
    device: dev.device,
    groupMemberships: {},  // groupId → true (after entering password)
  };
  addAudit('login', { username, ip: fp.ip, fingerprint: fp.fingerprint, browser: dev.browser, os: dev.os, device: dev.device, ua: fp.ua });
  persistAudit();
  return token;
}

function getSession(token) {
  const s = sessions[token];
  if (!s || bannedTokens.has(token)) return null;
  s.lastSeen = now();
  return s;
}

function onlineUsers() {
  const cutoff = now() - 30000;
  return Object.entries(sessions)
    .filter(([t, s]) => s.lastSeen > cutoff && !bannedTokens.has(t))
    .map(([t, s]) => ({ token: t, username: s.username, lastSeen: s.lastSeen, joinedAt: s.joinedAt }));
}

// ── Multipart parser ────────────────────────────────────────────────────────────
function parseMultipart(req, cb) {
  const ct = req.headers['content-type'] || '';
  const bm = ct.match(/boundary=(.+)$/);
  if (!bm) return cb(new Error('No boundary'), null, null);
  const boundary = '--' + bm[1];
  let chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    const buf = Buffer.concat(chunks);
    const parts = splitBuffer(buf, Buffer.from('\r\n' + boundary));
    const fields = {};
    let file = null;
    for (const part of parts) {
      const he = indexOfBuffer(part, Buffer.from('\r\n\r\n'));
      if (he === -1) continue;
      const hs = part.slice(0, he).toString();
      const body = part.slice(he + 4);
      const nm = hs.match(/name="([^"]+)"/);
      const fm = hs.match(/filename="([^"]+)"/);
      if (!nm) continue;
      if (fm) {
        const safeName = Date.now() + '_' + fm[1].replace(/[^a-zA-Z0-9._-]/g, '_');
        const fp = path.join(UPLOAD_DIR, safeName);
        let fd = body;
        const em = Buffer.from('\r\n--' + bm[1] + '--');
        const ei = indexOfBuffer(fd, em);
        if (ei !== -1) fd = fd.slice(0, ei);
        fs.writeFileSync(fp, fd);
        file = { originalName: fm[1], savedName: safeName, size: fd.length };
      } else {
        let val = body.toString();
        if (val.endsWith('\r\n')) val = val.slice(0, -2);
        fields[nm[1]] = val;
      }
    }
    cb(null, fields, file);
  });
  req.on('error', cb);
}

function splitBuffer(buf, sep) {
  const parts = []; let start = 0, idx;
  while ((idx = indexOfBuffer(buf, sep, start)) !== -1) { parts.push(buf.slice(start, idx)); start = idx + sep.length; }
  parts.push(buf.slice(start));
  return parts;
}

function indexOfBuffer(buf, search, offset = 0) {
  for (let i = offset; i <= buf.length - search.length; i++) {
    let found = true;
    for (let j = 0; j < search.length; j++) { if (buf[i+j] !== search[j]) { found = false; break; } }
    if (found) return i;
  }
  return -1;
}

// ── HTTP helpers ────────────────────────────────────────────────────────────────
function jsonRes(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let d = '';
    req.on('data', c => d += c);
    req.on('end', () => { try { resolve(JSON.parse(d || '{}')); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

// ── Router ──────────────────────────────────────────────────────────────────────
const routes = {};
function route(method, path_, handler) { routes[method + ':' + path_] = handler; }

// ── Auth ────────────────────────────────────────────────────────────────────────
route('POST', '/api/login', async (req, res) => {
  const { passcode, username } = await readBody(req);
  if (!passcode || passcode !== state.passcode) return jsonRes(res, { error: 'Wrong passcode' }, 401);
  if (!username || username.trim().length < 2) return jsonRes(res, { error: 'Username must be 2+ chars' }, 400);
  const clean = username.trim().slice(0, 24);
  const token = createSession(clean, req);
  const msg = { id: uid(), type: 'system', text: `${clean} joined the chat`, ts: tsStr() };
  messages.push(msg);
  if (messages.length > MAX_MESSAGES) messages = messages.slice(-MAX_MESSAGES);
  jsonRes(res, { token, username: clean, groups: publicGroupList() });
});

route('POST', '/api/rename', async (req, res) => {
  const { token, username } = await readBody(req);
  const s = getSession(token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  if (!username || username.trim().length < 2) return jsonRes(res, { error: 'Username must be 2+ chars' }, 400);
  const old = s.username;
  s.username = username.trim().slice(0, 24);
  addAudit('rename', { from: old, to: s.username, ip: s.ip, fingerprint: s.fingerprint });
  persistAudit();
  messages.push({ id: uid(), type: 'system', text: `${old} changed name to ${s.username}`, ts: tsStr() });
  jsonRes(res, { ok: true, username: s.username });
});

// ── Main chat messages ──────────────────────────────────────────────────────────
route('POST', '/api/messages', async (req, res) => {
  const { token, text } = await readBody(req);
  const s = getSession(token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  if (!text || !text.trim()) return jsonRes(res, { error: 'Empty message' }, 400);
  const msg = { id: uid(), type: 'text', username: s.username, text: text.trim().slice(0, 2000), ts: tsStr() };
  messages.push(msg);
  if (messages.length > MAX_MESSAGES) messages = messages.slice(-MAX_MESSAGES);
  jsonRes(res, { ok: true, message: msg });
});

route('GET', '/api/messages', (req, res) => {
  const q = url.parse(req.url, true).query;
  const s = getSession(q.token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  const since = parseInt(q.since) || 0;
  const msgs = since ? messages.filter(m => new Date(m.ts).getTime() > since) : messages.slice(-100);
  jsonRes(res, { messages: msgs, users: onlineUsers(), serverTime: now(), groups: publicGroupList() });
});

// ── File upload ─────────────────────────────────────────────────────────────────
routes['POST:/api/upload'] = (req, res) => {
  const token = url.parse(req.url, true).query.token;
  const groupId = url.parse(req.url, true).query.groupId;
  const s = getSession(token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  const cl = parseInt(req.headers['content-length'] || '0');
  if (cl > MAX_FILE_MB * 1024 * 1024) return jsonRes(res, { error: `Max ${MAX_FILE_MB}MB` }, 413);
  parseMultipart(req, (err, fields, file) => {
    if (err || !file) return jsonRes(res, { error: 'Upload failed' }, 400);
    const msg = { id: uid(), type: 'file', username: s.username, fileName: file.originalName, filePath: '/uploads/' + file.savedName, fileSize: file.size, ts: tsStr() };
    if (groupId && state.groups[groupId] && s.groupMemberships[groupId]) {
      if (!groupMessages[groupId]) groupMessages[groupId] = [];
      groupMessages[groupId].push(msg);
      persistGroup(groupId);
    } else {
      messages.push(msg);
      if (messages.length > MAX_MESSAGES) messages = messages.slice(-MAX_MESSAGES);
    }
    jsonRes(res, { ok: true, message: msg });
  });
};

// ── Private Groups ──────────────────────────────────────────────────────────────
function publicGroupList() {
  return Object.entries(state.groups).map(([id, g]) => ({ id, name: g.name, createdAt: g.createdAt, createdBy: g.createdBy, memberCount: Object.values(sessions).filter(s => s.groupMemberships && s.groupMemberships[id]).length }));
}

route('POST', '/api/groups/create', async (req, res) => {
  const { token, name, password } = await readBody(req);
  const s = getSession(token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  if (!name || name.trim().length < 2) return jsonRes(res, { error: 'Group name must be 2+ chars' }, 400);
  if (!password || password.length < 3) return jsonRes(res, { error: 'Password must be 3+ chars' }, 400);
  const id = uid().slice(0, 8);
  state.groups[id] = { name: name.trim().slice(0, 32), password, createdAt: tsStr(), createdBy: s.username };
  groupMessages[id] = [];
  s.groupMemberships[id] = true;
  persistState();
  persistGroup(id);
  addAudit('group_create', { groupId: id, groupName: name.trim(), by: s.username, ip: s.ip, fingerprint: s.fingerprint });
  persistAudit();
  jsonRes(res, { ok: true, groupId: id, groups: publicGroupList() });
});

route('POST', '/api/groups/join', async (req, res) => {
  const { token, groupId, password } = await readBody(req);
  const s = getSession(token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  const g = state.groups[groupId];
  if (!g) return jsonRes(res, { error: 'Group not found' }, 404);
  if (g.password !== password) return jsonRes(res, { error: 'Wrong group password' }, 401);
  s.groupMemberships[groupId] = true;
  addAudit('group_join', { groupId, groupName: g.name, by: s.username, ip: s.ip, fingerprint: s.fingerprint });
  persistAudit();
  jsonRes(res, { ok: true, groupName: g.name });
});

route('POST', '/api/groups/messages', async (req, res) => {
  const { token, groupId, text } = await readBody(req);
  const s = getSession(token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  if (!state.groups[groupId]) return jsonRes(res, { error: 'Group not found' }, 404);
  if (!s.groupMemberships[groupId]) return jsonRes(res, { error: 'Not a member' }, 403);
  if (!text || !text.trim()) return jsonRes(res, { error: 'Empty message' }, 400);
  const msg = { id: uid(), type: 'text', username: s.username, text: text.trim().slice(0, 2000), ts: tsStr() };
  if (!groupMessages[groupId]) groupMessages[groupId] = [];
  groupMessages[groupId].push(msg);
  if (groupMessages[groupId].length > MAX_MESSAGES) groupMessages[groupId] = groupMessages[groupId].slice(-MAX_MESSAGES);
  persistGroup(groupId);
  jsonRes(res, { ok: true, message: msg });
});

route('GET', '/api/groups/messages', (req, res) => {
  const q = url.parse(req.url, true).query;
  const s = getSession(q.token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  const gid = q.groupId;
  if (!state.groups[gid]) return jsonRes(res, { error: 'Group not found' }, 404);
  if (!s.groupMemberships[gid]) return jsonRes(res, { error: 'Not a member' }, 403);
  const since = parseInt(q.since) || 0;
  const gm = groupMessages[gid] || [];
  const msgs = since ? gm.filter(m => new Date(m.ts).getTime() > since) : gm.slice(-100);
  jsonRes(res, { messages: msgs, serverTime: now() });
});

// ── Admin auth helper ───────────────────────────────────────────────────────────
function checkAdmin(req, bodyToken) {
  const q = url.parse(req.url, true).query;
  const expected = 'admin_' + state.adminPassword;
  return (q.adminToken === expected) || (bodyToken === expected);
}

route('POST', '/api/admin/login', async (req, res) => {
  const { password } = await readBody(req);
  if (password !== state.adminPassword) return jsonRes(res, { error: 'Wrong password' }, 401);
  addAudit('admin_login', { ip: req.socket.remoteAddress });
  persistAudit();
  jsonRes(res, { ok: true, adminToken: 'admin_' + state.adminPassword });
});

route('GET', '/api/admin/stats', (req, res) => {
  if (!checkAdmin(req)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  const online = onlineUsers();
  jsonRes(res, {
    passcode: state.passcode,
    totalMessages: messages.length,
    onlineUsers: online,
    allSessions: Object.entries(sessions).map(([t, s]) => ({
      token: t, username: s.username, joinedAt: s.joinedAt, lastSeen: s.lastSeen,
      ip: s.ip, fingerprint: s.fingerprint, browser: s.browser, os: s.os, device: s.device,
      ua: s.ua, lang: s.lang, banned: bannedTokens.has(t),
      groupMemberships: Object.keys(s.groupMemberships || {})
    })),
    recentMessages: messages.slice(-50),
    groups: publicGroupList(),
    auditCount: auditLog.length,
  });
});

route('POST', '/api/admin/kick', async (req, res) => {
  const body = await readBody(req);
  if (!checkAdmin(req, body.adminToken)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  const { token } = body;
  if (sessions[token]) {
    const name = sessions[token].username;
    bannedTokens.add(token);
    messages.push({ id: uid(), type: 'system', text: `${name} was removed by admin`, ts: tsStr() });
    addAudit('admin_kick', { username: name, token, ip: sessions[token].ip, fingerprint: sessions[token].fingerprint });
    persistAudit();
  }
  jsonRes(res, { ok: true });
});

// NEW: Clear ALL online users (wipe all sessions)
route('POST', '/api/admin/clearUsers', async (req, res) => {
  const body = await readBody(req);
  if (!checkAdmin(req, body.adminToken)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  const count = Object.keys(sessions).length;
  sessions = {};
  bannedTokens = new Set();
  messages.push({ id: uid(), type: 'system', text: `All users were cleared by admin`, ts: tsStr() });
  addAudit('admin_clear_users', { count });
  persistAudit();
  jsonRes(res, { ok: true, count });
});

route('POST', '/api/admin/clearMessages', async (req, res) => {
  const body = await readBody(req);
  if (!checkAdmin(req, body.adminToken)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  messages = [{ id: uid(), type: 'system', text: 'Chat cleared by admin', ts: tsStr() }];
  persistMessages();
  addAudit('admin_clear_messages', {});
  persistAudit();
  jsonRes(res, { ok: true });
});

route('POST', '/api/admin/changePasscode', async (req, res) => {
  const body = await readBody(req);
  if (!checkAdmin(req, body.adminToken)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  if (!body.newPasscode || body.newPasscode.length < 4) return jsonRes(res, { error: 'Must be 4+ chars' }, 400);
  state.passcode = body.newPasscode;
  persistState();
  addAudit('admin_change_passcode', {});
  persistAudit();
  jsonRes(res, { ok: true });
});

route('POST', '/api/admin/changeAdminPassword', async (req, res) => {
  const body = await readBody(req);
  if (!checkAdmin(req, body.adminToken)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  if (!body.newPassword || body.newPassword.length < 4) return jsonRes(res, { error: 'Must be 4+ chars' }, 400);
  state.adminPassword = body.newPassword;
  persistState();
  jsonRes(res, { ok: true });
});

// Download chat log as plain text
route('GET', '/api/admin/downloadLog', (req, res) => {
  if (!checkAdmin(req)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  const q = url.parse(req.url, true).query;
  const groupId = q.groupId;
  let msgs, label;
  if (groupId && state.groups[groupId]) {
    msgs = groupMessages[groupId] || [];
    label = 'group_' + state.groups[groupId].name.replace(/\s+/g,'_');
  } else {
    msgs = messages;
    label = 'main_chat';
  }
  const lines = msgs.map(m => {
    if (m.type === 'system') return `[${m.ts}] *** ${m.text} ***`;
    if (m.type === 'file') return `[${m.ts}] ${m.username}: [FILE] ${m.fileName} (${m.fileSize} bytes)`;
    return `[${m.ts}] ${m.username}: ${m.text}`;
  });
  const filename = `securechat_${label}_${new Date().toISOString().slice(0,10)}.txt`;
  res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Disposition': `attachment; filename="${filename}"` });
  res.end(lines.join('\n'));
});

// Download audit log
route('GET', '/api/admin/downloadAudit', (req, res) => {
  if (!checkAdmin(req)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  const lines = auditLog.map(e => `[${e.ts}] [${e.type}] ${JSON.stringify(e)}`);
  res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename="securechat_audit.txt"' });
  res.end(lines.join('\n'));
});

// Admin: view audit log entries
route('GET', '/api/admin/audit', (req, res) => {
  if (!checkAdmin(req)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  jsonRes(res, { audit: auditLog.slice(-200).reverse() });
});

// Admin: delete a group
route('POST', '/api/admin/deleteGroup', async (req, res) => {
  const body = await readBody(req);
  if (!checkAdmin(req, body.adminToken)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  const { groupId } = body;
  if (!state.groups[groupId]) return jsonRes(res, { error: 'Group not found' }, 404);
  const name = state.groups[groupId].name;
  delete state.groups[groupId];
  delete groupMessages[groupId];
  const gf = path.join(DATA_DIR, `group_${groupId}.json`);
  if (fs.existsSync(gf)) fs.unlinkSync(gf);
  persistState();
  addAudit('admin_delete_group', { groupId, groupName: name });
  persistAudit();
  jsonRes(res, { ok: true });
});

// ── Static files ────────────────────────────────────────────────────────────────
const MIME = { '.html':'text/html','.js':'application/javascript','.css':'text/css','.png':'image/png','.jpg':'image/jpeg','.gif':'image/gif','.pdf':'application/pdf','.zip':'application/zip','.txt':'text/plain','.mp4':'video/mp4','.webm':'video/webm' };

// ── Server ──────────────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;

  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST','Access-Control-Allow-Headers':'Content-Type' });
    return res.end();
  }

  if (pathname.startsWith('/uploads/')) {
    const fn = path.basename(pathname);
    const fp = path.join(UPLOAD_DIR, fn);
    if (!fs.existsSync(fp)) { res.writeHead(404); return res.end('Not found'); }
    const ext = path.extname(fn).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext]||'application/octet-stream', 'Content-Disposition':`attachment; filename="${fn}"` });
    return fs.createReadStream(fp).pipe(res);
  }

  const key = req.method + ':' + pathname;
  if (routes[key]) return routes[key](req, res);

  if (pathname === '/' || pathname === '/index.html') { res.writeHead(200,{'Content-Type':'text/html'}); return res.end(getFrontendHTML()); }
  if (pathname === '/admin' || pathname === '/admin.html') { res.writeHead(200,{'Content-Type':'text/html'}); return res.end(getAdminHTML()); }

  res.writeHead(404); res.end('Not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🔐 SecureChat v2 is running!`);
  console.log(`   Chat:    http://localhost:${PORT}`);
  console.log(`   Admin:   http://localhost:${PORT}/admin`);
  console.log(`   Data stored in: ${DATA_DIR}`);
  console.log(`\n   Default passcode:       secret123`);
  console.log(`   Default admin password: admin999`);
  console.log(`\n   Messages persist to disk automatically.\n`);
});

// ══════════════════════════════════════════════════════════════════════════════
// FRONTEND HTML
// ══════════════════════════════════════════════════════════════════════════════
function getFrontendHTML() { return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureChat</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#0a0a0f;--surface:#111118;--border:#1e1e2e;--accent:#7c6af7;--accent2:#f76a8a;--text:#e2e0f0;--muted:#5a5875;--sys:#3a5a4a;--sys-text:#7ddfaa;--bubble-me:#1e1a3a;--bubble-other:#16161f;--file-bg:#1a1530;--group:#1a0f2e;--group-border:#3a2060}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'DM Mono',monospace;height:100dvh;display:flex;flex-direction:column;overflow:hidden}
#login-screen{display:flex;align-items:center;justify-content:center;flex:1;background:radial-gradient(ellipse at 30% 50%,#1a0a2e 0%,var(--bg) 60%)}
.login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:48px 40px;width:380px;max-width:90vw;box-shadow:0 0 80px #7c6af720}
.login-logo{font-family:'Syne',sans-serif;font-size:28px;font-weight:800;margin-bottom:8px}
.login-logo span{color:var(--accent)}
.login-sub{color:var(--muted);font-size:12px;margin-bottom:32px}
.field{margin-bottom:16px}
.field label{display:block;font-size:11px;color:var(--muted);margin-bottom:6px;letter-spacing:.08em;text-transform:uppercase}
.field input{width:100%;background:#0d0d16;border:1px solid var(--border);border-radius:8px;padding:10px 14px;color:var(--text);font-family:inherit;font-size:14px;outline:none;transition:border-color .2s}
.field input:focus{border-color:var(--accent)}
.btn{width:100%;background:var(--accent);color:#fff;border:none;border-radius:8px;padding:12px;font-family:'Syne',sans-serif;font-size:15px;font-weight:600;cursor:pointer;transition:opacity .2s,transform .1s}
.btn:hover{opacity:.9}.btn:active{transform:scale(.98)}
.err{color:var(--accent2);font-size:12px;margin-top:8px;min-height:16px}
.login-admin-link{text-align:center;margin-top:20px;font-size:11px;color:var(--muted)}
.login-admin-link a{color:var(--accent);text-decoration:none}
#chat-screen{display:none;flex-direction:column;flex:1;overflow:hidden}
header{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.header-logo{font-family:'Syne',sans-serif;font-weight:800;font-size:18px}
.header-logo span{color:var(--accent)}
.header-spacer{flex:1}
.online-count{font-size:11px;color:var(--sys-text);background:var(--sys);padding:3px 10px;border-radius:20px}
.user-badge{font-size:12px;color:var(--muted)}
.user-badge strong{color:var(--text)}
.icon-btn{background:transparent;border:1px solid var(--border);color:var(--muted);border-radius:8px;padding:6px 10px;font-size:12px;cursor:pointer;font-family:inherit;transition:all .2s;white-space:nowrap}
.icon-btn:hover{border-color:var(--accent);color:var(--accent)}
.chat-body{display:flex;flex:1;overflow:hidden}
#left-sidebar{width:220px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;overflow:hidden}
.sidebar-section{padding:12px;border-bottom:1px solid var(--border)}
.sidebar-title{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:8px;display:flex;justify-content:space-between;align-items:center}
.sidebar-title button{background:transparent;border:none;color:var(--accent);font-size:16px;cursor:pointer;line-height:1;padding:0}
.user-item{font-size:12px;color:var(--text);padding:5px 8px;border-radius:6px;display:flex;align-items:center;gap:6px}
.user-item::before{content:'';width:6px;height:6px;border-radius:50%;background:var(--sys-text);flex-shrink:0}
.groups-list{padding:8px;overflow-y:auto;flex:1}
.group-item{display:flex;align-items:center;gap:6px;padding:7px 10px;border-radius:8px;cursor:pointer;margin-bottom:4px;border:1px solid transparent;transition:all .2s;font-size:12px}
.group-item:hover{background:var(--group);border-color:var(--group-border)}
.group-item.active{background:var(--group);border-color:var(--accent);color:var(--accent)}
.group-icon{font-size:14px;flex-shrink:0}
.group-name{flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.group-lock{font-size:10px;color:var(--muted)}
.group-main{border:1px solid var(--border);color:var(--sys-text)}
#chat-area{flex:1;display:flex;flex-direction:column;overflow:hidden}
#messages{flex:1;overflow-y:auto;padding:20px 16px;display:flex;flex-direction:column;gap:10px}
#messages::-webkit-scrollbar{width:4px}
#messages::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
.msg{display:flex;flex-direction:column;max-width:70%}
.msg.me{align-self:flex-end;align-items:flex-end}
.msg.other{align-self:flex-start;align-items:flex-start}
.msg.sys{align-self:center;align-items:center}
.msg-name{font-size:10px;color:var(--muted);margin-bottom:3px}
.msg-bubble{padding:10px 14px;border-radius:12px;font-size:13px;line-height:1.5;word-break:break-word}
.msg.me .msg-bubble{background:var(--bubble-me);border-bottom-right-radius:3px;border:1px solid #2a2050}
.msg.other .msg-bubble{background:var(--bubble-other);border-bottom-left-radius:3px;border:1px solid var(--border)}
.msg.sys .msg-bubble{background:transparent;color:var(--sys-text);font-size:11px;padding:4px 12px;border:1px solid var(--sys);border-radius:20px}
.msg-time{font-size:10px;color:var(--muted);margin-top:3px}
.file-msg{background:var(--file-bg);border:1px solid #2a2060;border-radius:10px;padding:12px 14px;display:flex;align-items:center;gap:10px;min-width:180px}
.file-icon{font-size:22px}
.file-info{flex:1;min-width:0}
.file-name{font-size:12px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.file-size{font-size:10px;color:var(--muted)}
.file-dl{color:var(--accent);font-size:11px;text-decoration:none;margin-top:2px;display:inline-block}
.file-dl:hover{text-decoration:underline}
footer{background:var(--surface);border-top:1px solid var(--border);padding:12px 16px;display:flex;gap:8px;align-items:flex-end}
#msg-input{flex:1;background:#0d0d16;border:1px solid var(--border);border-radius:10px;padding:10px 14px;color:var(--text);font-family:inherit;font-size:13px;outline:none;resize:none;max-height:120px;transition:border-color .2s}
#msg-input:focus{border-color:var(--accent)}
.chat-label{background:var(--surface);border-bottom:1px solid var(--border);padding:8px 16px;font-size:11px;color:var(--muted);display:flex;align-items:center;gap:8px}
.chat-label strong{color:var(--text)}
.chat-label .group-badge{background:var(--group);border:1px solid var(--group-border);color:#b09af7;padding:2px 8px;border-radius:12px;font-size:10px}
.send-btn{background:var(--accent);color:#fff;border:none;border-radius:10px;padding:10px 18px;font-family:'Syne',sans-serif;font-weight:600;font-size:13px;cursor:pointer;transition:opacity .2s}
.send-btn:hover{opacity:.85}
.attach-btn{background:#0d0d16;color:var(--muted);border:1px solid var(--border);border-radius:10px;padding:10px 12px;font-size:16px;cursor:pointer;transition:all .2s;line-height:1}
.attach-btn:hover{border-color:var(--accent);color:var(--accent)}
.modal-overlay{display:none;position:fixed;inset:0;background:#00000090;z-index:100;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:32px;width:340px;max-width:90vw}
.modal h3{font-family:'Syne',sans-serif;font-size:18px;margin-bottom:20px}
.modal-btns{display:flex;gap:8px;margin-top:16px}
.btn-sec{flex:1;background:transparent;border:1px solid var(--border);color:var(--text);border-radius:8px;padding:10px;font-family:inherit;font-size:13px;cursor:pointer}
.btn-pri{flex:1;background:var(--accent);color:#fff;border:none;border-radius:8px;padding:10px;font-family:'Syne',sans-serif;font-weight:600;font-size:13px;cursor:pointer}
#file-input{display:none}
.new-group-btn{width:100%;background:transparent;border:1px dashed var(--group-border);color:#b09af7;border-radius:8px;padding:8px;font-size:11px;cursor:pointer;font-family:inherit;transition:all .2s;margin-top:4px}
.new-group-btn:hover{background:var(--group);border-style:solid}
.locked-group-notice{text-align:center;padding:20px;color:var(--muted);font-size:12px}
@media(max-width:600px){#left-sidebar{display:none}.msg{max-width:90%}}
</style>
</head>
<body>
<div id="login-screen">
  <div class="login-box">
    <div class="login-logo">Secure<span>Chat</span></div>
    <div class="login-sub">// protected messaging platform</div>
    <div class="field"><label>Passcode</label><input type="password" id="passcode" placeholder="Enter access passcode"></div>
    <div class="field"><label>Your Username</label><input type="text" id="username" placeholder="Choose a name" maxlength="24"></div>
    <button class="btn" onclick="login()">Enter Chat →</button>
    <div class="err" id="login-err"></div>
    <div class="login-admin-link"><a href="/admin">Admin Dashboard</a></div>
  </div>
</div>

<div id="chat-screen">
  <header>
    <div class="header-logo">Secure<span>Chat</span></div>
    <span class="online-count" id="online-count">0 online</span>
    <div class="header-spacer"></div>
    <span class="user-badge">as <strong id="current-user"></strong></span>
    <button class="icon-btn" onclick="openRename()">✎ Rename</button>
    <button class="icon-btn" onclick="logout()">⏻ Leave</button>
  </header>
  <div class="chat-body">
    <div id="left-sidebar">
      <div class="sidebar-section">
        <div class="sidebar-title">Online</div>
        <div id="user-list"></div>
      </div>
      <div class="sidebar-section" style="flex:1;display:flex;flex-direction:column;overflow:hidden;border-bottom:none">
        <div class="sidebar-title">Chats <button onclick="openCreateGroup()" title="New group">＋</button></div>
        <div class="groups-list" id="groups-list"></div>
      </div>
    </div>
    <div id="chat-area">
      <div class="chat-label" id="chat-label"><strong>Main Chat</strong></div>
      <div id="messages"></div>
      <footer>
        <input type="file" id="file-input" onchange="uploadFile()">
        <button class="attach-btn" onclick="document.getElementById('file-input').click()" title="Attach file">📎</button>
        <textarea id="msg-input" rows="1" placeholder="Type a message..." onkeydown="msgKey(event)" oninput="autoResize(this)"></textarea>
        <button class="send-btn" onclick="sendMessage()">Send</button>
      </footer>
    </div>
  </div>
</div>

<!-- Rename modal -->
<div class="modal-overlay" id="rename-modal">
  <div class="modal">
    <h3>Change Username</h3>
    <div class="field"><label>New Username</label><input type="text" id="new-username" maxlength="24" placeholder="Enter new name"></div>
    <div class="err" id="rename-err"></div>
    <div class="modal-btns"><button class="btn-sec" onclick="closeModal('rename-modal')">Cancel</button><button class="btn-pri" onclick="rename()">Update</button></div>
  </div>
</div>

<!-- Create group modal -->
<div class="modal-overlay" id="create-group-modal">
  <div class="modal">
    <h3>Create Private Group</h3>
    <div class="field"><label>Group Name</label><input type="text" id="grp-name" maxlength="32" placeholder="e.g. Project Alpha"></div>
    <div class="field"><label>Group Password</label><input type="password" id="grp-pass" placeholder="Members need this to join"></div>
    <div class="err" id="grp-err"></div>
    <div class="modal-btns"><button class="btn-sec" onclick="closeModal('create-group-modal')">Cancel</button><button class="btn-pri" onclick="createGroup()">Create</button></div>
  </div>
</div>

<!-- Join group modal -->
<div class="modal-overlay" id="join-group-modal">
  <div class="modal">
    <h3>Join Group</h3>
    <div style="font-size:13px;color:var(--muted);margin-bottom:16px">Enter the password for <strong id="join-group-name" style="color:var(--text)"></strong></div>
    <div class="field"><label>Group Password</label><input type="password" id="join-grp-pass" placeholder="Enter group password"></div>
    <div class="err" id="join-grp-err"></div>
    <div class="modal-btns"><button class="btn-sec" onclick="closeModal('join-group-modal')">Cancel</button><button class="btn-pri" onclick="joinGroup()">Join</button></div>
  </div>
</div>

<script>
let token = localStorage.getItem('sc_token');
let myUsername = localStorage.getItem('sc_username');
let lastSeen = 0;
let lastGroupSeen = {};
let pollTimer;
let currentGroupId = null; // null = main chat
let allGroups = [];
let joinedGroups = {};
let pendingJoinGroupId = null;
const seenIds = new Set();

function fmt(b){if(!b)return'';if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(1)+' MB';}
function escHtml(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function fmtTime(ts){return new Date(ts).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});}
function fileIcon(n){const e=(n.split('.').pop()||'').toLowerCase();return{pdf:'📄',png:'🖼️',jpg:'🖼️',jpeg:'🖼️',gif:'🖼️',mp4:'🎬',webm:'🎬',mp3:'🎵',wav:'🎵',zip:'🗜️',rar:'🗜️',doc:'📝',docx:'📝',xls:'📊',xlsx:'📊',txt:'📃'}[e]||'📎';}

async function login(){
  const passcode=document.getElementById('passcode').value;
  const username=document.getElementById('username').value.trim();
  document.getElementById('login-err').textContent='';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passcode,username})});
    const d=await r.json();
    if(!r.ok)return document.getElementById('login-err').textContent=d.error;
    token=d.token;myUsername=d.username;
    localStorage.setItem('sc_token',token);localStorage.setItem('sc_username',myUsername);
    allGroups=d.groups||[];
    showChat();
  }catch(e){document.getElementById('login-err').textContent='Connection error';}
}

function showChat(){
   document.getElementById('login-screen').style.display='none';
   document.getElementById('chat-screen').style.display='flex';
   document.getElementById('current-user').textContent=myUsername;
   lastSeen=0;currentGroupId=null;
   renderGroups();
   // Delay poll to ensure page is rendered before first API call
   setTimeout(poll, 100);
}

async function poll(){
   try{
      if(currentGroupId){
        const r=await fetch('/api/groups/messages?token='+token+'&groupId='+currentGroupId+'&since='+(lastGroupSeen[currentGroupId]||0));
        if(!r.ok){
          if(r.status===401){logout();return;}
          pollTimer=setTimeout(poll,1500);
          return;
        }
        const d=await r.json();
        if(d.messages&&d.messages.length){d.messages.forEach(appendMsg);lastGroupSeen[currentGroupId]=d.serverTime;}
        const r2=await fetch('/api/messages?token='+token+'&since='+lastSeen);
        if(r2.ok){const d2=await r2.json();if(d2.users)updateUsers(d2.users);if(d2.groups){allGroups=d2.groups;renderGroups();}}
      } else {
        const r=await fetch('/api/messages?token='+token+'&since='+lastSeen);
        if(!r.ok){
          if(r.status===401){logout();return;}
          pollTimer=setTimeout(poll,1500);
          return;
        }
        const d=await r.json();
        if(d.messages&&d.messages.length){d.messages.forEach(appendMsg);lastSeen=d.serverTime;}
        if(d.users)updateUsers(d.users);
        if(d.groups){allGroups=d.groups;renderGroups();}
      }
   }catch(e){}
   pollTimer=setTimeout(poll,1500);
}
 

function appendMsg(msg){
  if(seenIds.has(msg.id))return;seenIds.add(msg.id);
  const el=document.getElementById('messages');
  const div=document.createElement('div');
  div.className='msg '+(msg.type==='system'?'sys':msg.username===myUsername?'me':'other');
  if(msg.type==='system'){
    div.innerHTML='<div class="msg-bubble">'+escHtml(msg.text)+'</div>';
  } else if(msg.type==='file'){
    div.innerHTML=(msg.username!==myUsername?'<div class="msg-name">'+escHtml(msg.username)+'</div>':'')+
      '<div class="msg-bubble" style="padding:0;background:transparent;border:none;"><div class="file-msg"><div class="file-icon">'+fileIcon(msg.fileName)+'</div><div class="file-info"><div class="file-name">'+escHtml(msg.fileName)+'</div><div class="file-size">'+fmt(msg.fileSize)+'</div><a class="file-dl" href="'+escHtml(msg.filePath)+'" download>↓ Download</a></div></div></div>'+
      '<div class="msg-time">'+fmtTime(msg.ts)+'</div>';
  } else {
    div.innerHTML=(msg.username!==myUsername?'<div class="msg-name">'+escHtml(msg.username)+'</div>':'')+
      '<div class="msg-bubble">'+escHtml(msg.text).replace(/\n/g,'<br>')+'</div>'+
      '<div class="msg-time">'+fmtTime(msg.ts)+'</div>';
  }
  el.appendChild(div);el.scrollTop=el.scrollHeight;
}

function updateUsers(users){
  document.getElementById('online-count').textContent=users.length+' online';
  document.getElementById('user-list').innerHTML=users.map(u=>'<div class="user-item">'+escHtml(u.username)+'</div>').join('');
}

function renderGroups(){
  const el=document.getElementById('groups-list');
  let html='<div class="group-item group-main '+(currentGroupId===null?'active':'')+'" onclick="switchToMain()"><span class="group-icon">💬</span><span class="group-name">Main Chat</span></div>';
  for(const g of allGroups){
    const isJoined=!!joinedGroups[g.id];
    const isActive=currentGroupId===g.id;
    html+='<div class="group-item '+(isActive?'active':'')+'" onclick="clickGroup(\''+g.id+'\',\''+escHtml(g.name)+'\','+isJoined+')">'+
      '<span class="group-icon">'+(isJoined?'🔓':'🔒')+'</span>'+
      '<span class="group-name">'+escHtml(g.name)+'</span>'+
      '</div>';
  }
  html+='<button class="new-group-btn" onclick="openCreateGroup()">＋ New Private Group</button>';
  el.innerHTML=html;
}

function switchToMain(){
  currentGroupId=null;seenIds.clear();lastSeen=0;
  document.getElementById('messages').innerHTML='';
  document.getElementById('chat-label').innerHTML='<strong>Main Chat</strong>';
  clearTimeout(pollTimer);poll();
  renderGroups();
}

function clickGroup(id,name,isJoined){
  if(isJoined){switchToGroup(id,name);}
  else{pendingJoinGroupId=id;document.getElementById('join-group-name').textContent=name;document.getElementById('join-grp-pass').value='';document.getElementById('join-grp-err').textContent='';openModal('join-group-modal');}
}

function switchToGroup(id,name){
  currentGroupId=id;seenIds.clear();if(!lastGroupSeen[id])lastGroupSeen[id]=0;
  document.getElementById('messages').innerHTML='';
  document.getElementById('chat-label').innerHTML='<strong>'+escHtml(name)+'</strong> <span class="group-badge">🔒 Private Group</span>';
  clearTimeout(pollTimer);poll();renderGroups();
}

async function sendMessage(){
  const input=document.getElementById('msg-input');
  const text=input.value.trim();if(!text)return;
  input.value='';autoResize(input);
  if(currentGroupId){
    await fetch('/api/groups/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,groupId:currentGroupId,text})});
  } else {
    await fetch('/api/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,text})});
  }
}

function msgKey(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMessage();}}
function autoResize(el){el.style.height='auto';el.style.height=Math.min(el.scrollHeight,120)+'px';}

async function uploadFile(){
  const fi=document.getElementById('file-input');const file=fi.files[0];if(!file)return;
  if(file.size>10*1024*1024){alert('File too large (max 10MB)');return;}
  const fd=new FormData();fd.append('file',file);fi.value='';
  const qp=currentGroupId?'?token='+token+'&groupId='+currentGroupId:'?token='+token;
  await fetch('/api/upload'+qp,{method:'POST',body:fd});
}

function openModal(id){document.getElementById(id).classList.add('open');setTimeout(()=>{const i=document.querySelector('#'+id+' input');if(i)i.focus();},100);}
function closeModal(id){document.getElementById(id).classList.remove('open');}
function openRename(){document.getElementById('new-username').value='';document.getElementById('rename-err').textContent='';openModal('rename-modal');}

async function rename(){
  const username=document.getElementById('new-username').value.trim();
  document.getElementById('rename-err').textContent='';
  const r=await fetch('/api/rename',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,username})});
  const d=await r.json();
  if(!r.ok)return document.getElementById('rename-err').textContent=d.error;
  myUsername=d.username;localStorage.setItem('sc_username',myUsername);
  document.getElementById('current-user').textContent=myUsername;closeModal('rename-modal');
}

function openCreateGroup(){document.getElementById('grp-name').value='';document.getElementById('grp-pass').value='';document.getElementById('grp-err').textContent='';openModal('create-group-modal');}

async function createGroup(){
  const name=document.getElementById('grp-name').value.trim();
  const password=document.getElementById('grp-pass').value;
  document.getElementById('grp-err').textContent='';
  const r=await fetch('/api/groups/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,name,password})});
  const d=await r.json();
  if(!r.ok)return document.getElementById('grp-err').textContent=d.error;
  joinedGroups[d.groupId]=true;allGroups=d.groups;
  closeModal('create-group-modal');renderGroups();switchToGroup(d.groupId,name);
}

async function joinGroup(){
  const password=document.getElementById('join-grp-pass').value;
  const groupId=pendingJoinGroupId;
  document.getElementById('join-grp-err').textContent='';
  const r=await fetch('/api/groups/join',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,groupId,password})});
  const d=await r.json();
  if(!r.ok)return document.getElementById('join-grp-err').textContent=d.error;
  joinedGroups[groupId]=true;
  closeModal('join-group-modal');
  const g=allGroups.find(x=>x.id===groupId);
  if(g)switchToGroup(groupId,g.name);
}

// Auto-login
if(token){
  fetch('/api/messages?token='+token+'&since=0').then(r=>{
    if(r.ok){r.json().then(d=>{allGroups=d.groups||[];showChat();});}
    else{localStorage.clear();}
  }).catch(()=>{});
}
document.getElementById('passcode').addEventListener('keydown',e=>{if(e.key==='Enter')document.getElementById('username').focus();});
document.getElementById('username').addEventListener('keydown',e=>{if(e.key==='Enter')login();});
document.getElementById('join-grp-pass').addEventListener('keydown',e=>{if(e.key==='Enter')joinGroup();});
</script>
</body></html>`; }

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN HTML
// ══════════════════════════════════════════════════════════════════════════════
function getAdminHTML() { return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureChat Admin</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#07070e;--surface:#0f0f1a;--border:#1c1c2e;--accent:#f76a8a;--accent2:#7c6af7;--text:#e0ddf5;--muted:#4a4868;--green:#7ddfaa;--green-bg:#0d1f16;--red:#f76a8a;--red-bg:#1f0d13;--yellow:#f7c96a;--yellow-bg:#1f1a0d}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'DM Mono',monospace;min-height:100vh}
#admin-login{display:flex;align-items:center;justify-content:center;min-height:100vh;background:radial-gradient(ellipse at 70% 30%,#1f0a1a 0%,var(--bg) 60%)}
.admin-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:48px 40px;width:360px;max-width:90vw;box-shadow:0 0 80px #f76a8a15}
.admin-logo{font-family:'Syne',sans-serif;font-size:24px;font-weight:800;margin-bottom:4px}
.admin-logo span{color:var(--accent)}
.admin-sub{color:var(--muted);font-size:11px;margin-bottom:32px}
.field label{display:block;font-size:10px;color:var(--muted);margin-bottom:6px;letter-spacing:.1em;text-transform:uppercase}
.field input,.field select{width:100%;background:#090914;border:1px solid var(--border);border-radius:8px;padding:10px 14px;color:var(--text);font-family:inherit;font-size:13px;outline:none;transition:border-color .2s}
.field input:focus{border-color:var(--accent)}.field{margin-bottom:16px}
.btn-admin{width:100%;background:var(--accent);color:#fff;border:none;border-radius:8px;padding:12px;font-family:'Syne',sans-serif;font-size:14px;font-weight:700;cursor:pointer}
.err{color:var(--accent);font-size:12px;margin-top:8px}
#dashboard{display:none}
nav{background:var(--surface);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.nav-logo{font-family:'Syne',sans-serif;font-weight:800;font-size:18px}
.nav-logo span{color:var(--accent)}
.nav-spacer{flex:1}
.nav-badge{font-size:11px;background:var(--red-bg);color:var(--red);padding:4px 10px;border-radius:20px;border:1px solid #3a1020}
.nav-btn{background:transparent;border:1px solid var(--border);color:var(--muted);border-radius:6px;padding:6px 12px;font-size:11px;cursor:pointer;font-family:inherit}
.nav-btn:hover{border-color:var(--accent);color:var(--accent)}

/* Tabs */
.tabs{display:flex;gap:2px;padding:16px 24px 0;border-bottom:1px solid var(--border);background:var(--surface)}
.tab{padding:10px 18px;font-size:12px;cursor:pointer;border:1px solid transparent;border-bottom:none;border-radius:8px 8px 0 0;color:var(--muted);font-family:inherit;background:transparent;transition:all .2s}
.tab.active{background:var(--bg);border-color:var(--border);color:var(--text)}
.tab-content{display:none;padding:24px}
.tab-content.active{display:block}

.dash-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px}
.card h3{font-family:'Syne',sans-serif;font-size:13px;color:var(--muted);margin-bottom:16px;text-transform:uppercase;letter-spacing:.08em;display:flex;justify-content:space-between;align-items:center}
.stat-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.stat{background:#0a0a14;border:1px solid var(--border);border-radius:8px;padding:14px}
.stat-val{font-size:28px;font-weight:500;color:var(--text)}
.stat-label{font-size:10px;color:var(--muted);margin-top:2px}
.card-full{grid-column:1/-1}

/* User rows */
.user-row{display:flex;align-items:flex-start;gap:10px;padding:10px;border-radius:8px;margin-bottom:8px;background:#0a0a14;border:1px solid var(--border)}
.user-dot{width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0;margin-top:4px}
.user-dot.offline{background:var(--muted)}
.user-info{flex:1;min-width:0}
.user-name-row{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.user-name{font-size:13px;font-weight:500}
.device-badges{display:flex;gap:4px;flex-wrap:wrap}
.badge{font-size:10px;padding:2px 7px;border-radius:12px;border:1px solid var(--border);color:var(--muted)}
.badge.browser{border-color:#2a2060;color:#b09af7}
.badge.os{border-color:#0a2a1a;color:var(--green)}
.badge.device{border-color:#2a1a0a;color:var(--yellow)}
.fingerprint{font-size:10px;color:var(--muted);margin-top:4px;font-family:'DM Mono',monospace;letter-spacing:.05em}
.fingerprint span{color:#6a6890}
.ip-row{font-size:10px;color:var(--muted);margin-top:2px}
.user-actions{display:flex;flex-direction:column;gap:4px;flex-shrink:0}
.kick-btn{background:var(--red-bg);color:var(--red);border:1px solid #3a1020;border-radius:6px;padding:4px 10px;font-size:11px;cursor:pointer;font-family:inherit;white-space:nowrap}
.kick-btn:hover{background:#2a0f17}

/* Messages */
.msg-row{padding:8px 10px;border-bottom:1px solid var(--border);font-size:12px}
.msg-row:last-child{border-bottom:none}
.msg-who{color:var(--accent2);margin-right:8px}
.msg-sys{color:var(--green);font-style:italic}
.msg-list{max-height:400px;overflow-y:auto}
.msg-list::-webkit-scrollbar{width:3px}
.msg-list::-webkit-scrollbar-thumb{background:var(--border)}

/* Audit */
.audit-row{padding:7px 10px;border-bottom:1px solid #0f0f18;font-size:11px;display:flex;gap:10px}
.audit-type{color:var(--accent2);min-width:120px;flex-shrink:0}
.audit-time{color:var(--muted);min-width:80px;flex-shrink:0;font-size:10px}
.audit-detail{color:var(--muted);flex:1;word-break:break-all}
.audit-list{max-height:500px;overflow-y:auto;background:#0a0a14;border-radius:8px;border:1px solid var(--border)}

/* Groups */
.group-row{display:flex;align-items:center;gap:10px;padding:10px;border-radius:8px;margin-bottom:6px;background:#0a0a14;border:1px solid var(--border)}
.group-info{flex:1}
.group-row-name{font-size:13px;margin-bottom:2px}
.group-meta{font-size:10px;color:var(--muted)}

.setting-row{display:flex;gap:8px;margin-bottom:10px;align-items:center}
.setting-row input{flex:1;background:#090914;border:1px solid var(--border);border-radius:8px;padding:8px 12px;color:var(--text);font-family:inherit;font-size:12px;outline:none}
.setting-row input:focus{border-color:var(--accent)}
.apply-btn{background:var(--accent2);color:#fff;border:none;border-radius:8px;padding:8px 14px;font-size:12px;cursor:pointer;font-family:'Syne',sans-serif;font-weight:600;white-space:nowrap}
.apply-btn:hover{opacity:.85}
.danger-btn{background:var(--red-bg);color:var(--red);border:1px solid #3a1020;border-radius:8px;padding:8px 14px;font-size:12px;cursor:pointer;font-family:inherit;width:100%;margin-top:6px}
.danger-btn:hover{background:#2a0f17}
.warn-btn{background:var(--yellow-bg);color:var(--yellow);border:1px solid #3a2a10;border-radius:8px;padding:8px 14px;font-size:12px;cursor:pointer;font-family:inherit;width:100%;margin-top:6px}
.warn-btn:hover{background:#2a200a}
.ok-msg{color:var(--green);font-size:11px;margin-top:6px}
.passcode-display{background:#0a0a14;border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:12px;font-size:13px;color:var(--yellow);letter-spacing:.1em}
.passcode-label{font-size:10px;color:var(--muted);margin-bottom:4px}
.dl-btn{background:#0a1a2a;color:#7ab8f7;border:1px solid #1a3a5a;border-radius:8px;padding:8px 14px;font-size:12px;cursor:pointer;font-family:inherit;text-decoration:none;display:inline-block;margin-top:6px;margin-right:6px}
.dl-btn:hover{background:#0f2030}
@media(max-width:600px){.dash-grid{grid-template-columns:1fr}.tabs{flex-wrap:wrap}}
</style>
</head>
<body>
<div id="admin-login">
  <div class="admin-box">
    <div class="admin-logo">Secure<span>Chat</span> Admin</div>
    <div class="admin-sub">// restricted access</div>
    <div class="field"><label>Admin Password</label><input type="password" id="admin-pass" placeholder="Enter password"></div>
    <button class="btn-admin" onclick="adminLogin()">Access Dashboard</button>
    <div class="err" id="admin-err"></div>
    <div style="margin-top:16px;font-size:11px;color:var(--muted);text-align:center"><a href="/" style="color:var(--accent2);text-decoration:none">← Back to Chat</a></div>
  </div>
</div>

<div id="dashboard">
  <nav>
    <div class="nav-logo">Secure<span>Chat</span> <span style="font-size:13px;color:var(--muted)">Admin</span></div>
    <div class="nav-spacer"></div>
    <span class="nav-badge" id="admin-status">Loading...</span>
    <button class="nav-btn" onclick="refreshStats()">↻ Refresh</button>
    <button class="nav-btn" onclick="adminLogout()">⏻ Exit</button>
  </nav>
  <div class="tabs">
    <button class="tab active" onclick="showTab('overview')">Overview</button>
    <button class="tab" onclick="showTab('users')">Users &amp; Devices</button>
    <button class="tab" onclick="showTab('messages')">Messages</button>
    <button class="tab" onclick="showTab('groups')">Groups</button>
    <button class="tab" onclick="showTab('audit')">Audit Trail</button>
    <button class="tab" onclick="showTab('settings')">Settings</button>
  </div>

  <!-- OVERVIEW -->
  <div class="tab-content active" id="tab-overview">
    <div class="dash-grid">
      <div class="card">
        <h3>Live Stats</h3>
        <div class="stat-grid">
          <div class="stat"><div class="stat-val" id="s-online">0</div><div class="stat-label">Online Now</div></div>
          <div class="stat"><div class="stat-val" id="s-msgs">0</div><div class="stat-label">Total Messages</div></div>
          <div class="stat"><div class="stat-val" id="s-sessions">0</div><div class="stat-label">Sessions</div></div>
          <div class="stat"><div class="stat-val" id="s-groups">0</div><div class="stat-label">Groups</div></div>
        </div>
      </div>
      <div class="card">
        <h3>Quick Actions</h3>
        <button class="warn-btn" onclick="clearUsers()" style="margin-top:0">⚡ Clear All Online Users</button>
        <button class="danger-btn" onclick="clearChat()">🗑 Clear Main Chat</button>
        <a class="dl-btn" id="dl-main-log" href="#">↓ Download Chat Log</a>
        <a class="dl-btn" id="dl-audit-log" href="#">↓ Download Audit Log</a>
      </div>
    </div>
  </div>

  <!-- USERS -->
  <div class="tab-content" id="tab-users">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <div style="font-size:12px;color:var(--muted)">All known sessions — includes device fingerprint &amp; browser info</div>
      <button class="warn-btn" style="width:auto;margin:0" onclick="clearUsers()">⚡ Clear All Users</button>
    </div>
    <div id="all-users-list"></div>
  </div>

  <!-- MESSAGES -->
  <div class="tab-content" id="tab-messages">
    <div style="margin-bottom:12px;display:flex;gap:8px;align-items:center">
      <div style="font-size:12px;color:var(--muted);flex:1">Last 50 messages from main chat</div>
      <a class="dl-btn" id="dl-main-log2" href="#">↓ Download Full Log</a>
    </div>
    <div class="msg-list" id="msg-list"></div>
  </div>

  <!-- GROUPS -->
  <div class="tab-content" id="tab-groups">
    <div style="margin-bottom:16px;font-size:12px;color:var(--muted)">All private groups — you can delete groups and download their logs</div>
    <div id="groups-admin-list"></div>
  </div>

  <!-- AUDIT -->
  <div class="tab-content" id="tab-audit">
    <div style="margin-bottom:12px;display:flex;gap:8px;align-items:center">
      <div style="font-size:12px;color:var(--muted);flex:1">Full activity trail — logins, renames, group joins, admin actions</div>
      <a class="dl-btn" id="dl-audit-log2" href="#">↓ Download</a>
    </div>
    <div class="audit-list" id="audit-list"></div>
  </div>

  <!-- SETTINGS -->
  <div class="tab-content" id="tab-settings">
    <div class="dash-grid">
      <div class="card">
        <h3>Chat Passcode</h3>
        <div class="passcode-label">Current Passcode</div>
        <div class="passcode-display" id="current-passcode">—</div>
        <div class="setting-row"><input type="text" id="new-passcode" placeholder="New passcode (4+ chars)"><button class="apply-btn" onclick="changePasscode()">Update</button></div>
        <div class="ok-msg" id="passcode-ok"></div>
      </div>
      <div class="card">
        <h3>Admin Password</h3>
        <div style="font-size:11px;color:var(--muted);margin-bottom:12px">Changing this will log you out</div>
        <div class="setting-row"><input type="password" id="new-admin-pw" placeholder="New admin password (4+ chars)"><button class="apply-btn" onclick="changeAdminPw()">Update</button></div>
        <div class="ok-msg" id="adminpw-ok"></div>
      </div>
    </div>
  </div>
</div>

<script>
let adminToken = sessionStorage.getItem('adminToken');
let statsData = null;

function showTab(name){
  document.querySelectorAll('.tab').forEach((t,i)=>t.classList.toggle('active',['overview','users','messages','groups','audit','settings'][i]===name));
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
}

async function adminLogin(){
  const pw=document.getElementById('admin-pass').value;
  const r=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  const d=await r.json();
  if(!r.ok)return document.getElementById('admin-err').textContent=d.error;
  adminToken=d.adminToken;sessionStorage.setItem('adminToken',adminToken);showDashboard();
}
function adminLogout(){sessionStorage.clear();location.reload();}
function showDashboard(){document.getElementById('admin-login').style.display='none';document.getElementById('dashboard').style.display='block';refreshStats();setInterval(refreshStats,6000);}

function escHtml(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function fmt(b){if(!b)return'';if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(1)+' MB';}
function fmtTime(ts){return new Date(ts).toLocaleString([],{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});}
function fmtShort(ts){return new Date(ts).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});}

async function refreshStats(){
  const r=await fetch('/api/admin/stats?adminToken='+adminToken);
  if(r.status===401){adminLogout();return;}
  const d=await r.json();statsData=d;
  const onlineSet=new Set(d.onlineUsers.map(u=>u.token));
  document.getElementById('s-online').textContent=d.onlineUsers.length;
  document.getElementById('s-msgs').textContent=d.totalMessages;
  document.getElementById('s-sessions').textContent=d.allSessions.length;
  document.getElementById('s-groups').textContent=d.groups.length;
  document.getElementById('admin-status').textContent=d.onlineUsers.length+' online';
  document.getElementById('current-passcode').textContent=d.passcode;

  const logUrl='/api/admin/downloadLog?adminToken='+adminToken;
  const auditUrl='/api/admin/downloadAudit?adminToken='+adminToken;
  ['dl-main-log','dl-main-log2'].forEach(id=>{const e=document.getElementById(id);if(e){e.href=logUrl;}});
  ['dl-audit-log','dl-audit-log2'].forEach(id=>{const e=document.getElementById(id);if(e){e.href=auditUrl;}});

  // Users tab
  const ul=document.getElementById('all-users-list');
  ul.innerHTML=d.allSessions.length===0?'<div style="color:var(--muted);font-size:12px;padding:16px">No sessions recorded</div>':
    d.allSessions.map(s=>\`
    <div class="user-row">
      <div class="user-dot \${onlineSet.has(s.token)?'':'offline'}"></div>
      <div class="user-info">
        <div class="user-name-row">
          <div class="user-name">\${escHtml(s.username)}\${s.banned?' <span style="color:var(--red);font-size:10px">[kicked]</span>':''}</div>
        </div>
        <div class="device-badges">
          <span class="badge browser">🌐 \${escHtml(s.browser||'?')}</span>
          <span class="badge os">💻 \${escHtml(s.os||'?')}</span>
          <span class="badge device">\${s.device==='Mobile'?'📱':s.device==='Tablet'?'🗒️':'🖥️'} \${escHtml(s.device||'?')}</span>
          \${onlineSet.has(s.token)?'<span class="badge" style="border-color:#1a3a1a;color:var(--green)">● online</span>':'<span class="badge">offline</span>'}
        </div>
        <div class="ip-row">IP: <span style="color:#7ab8f7">\${escHtml(s.ip||'unknown')}</span> &nbsp;|&nbsp; Lang: \${escHtml(s.lang||'—')}</div>
        <div class="fingerprint"><span>Device ID:</span> \${escHtml(s.fingerprint||'—')}</div>
        <div style="font-size:10px;color:var(--muted);margin-top:2px">Joined: \${fmtTime(s.joinedAt)} &nbsp;|&nbsp; Last seen: \${fmtTime(s.lastSeen)}</div>
      </div>
      <div class="user-actions">
        \${!s.banned?'<button class="kick-btn" onclick="kick(\''+s.token+'\')">Kick</button>':''}
      </div>
    </div>\`).join('');

  // Messages tab
  const ml=document.getElementById('msg-list');
  ml.innerHTML=d.recentMessages.slice().reverse().map(m=>{
    if(m.type==='system')return'<div class="msg-row"><span class="msg-sys">⚙ '+escHtml(m.text)+'</span> <span style="color:var(--muted);font-size:10px">'+fmtShort(m.ts)+'</span></div>';
    if(m.type==='file')return'<div class="msg-row"><span class="msg-who">'+escHtml(m.username)+'</span><span>📎 '+escHtml(m.fileName)+' ('+fmt(m.fileSize)+')</span> <span style="color:var(--muted);font-size:10px">'+fmtShort(m.ts)+'</span></div>';
    return'<div class="msg-row"><span class="msg-who">'+escHtml(m.username)+'</span><span>'+escHtml(m.text)+'</span> <span style="color:var(--muted);font-size:10px">'+fmtShort(m.ts)+'</span></div>';
  }).join('');

  // Groups tab
  const gl=document.getElementById('groups-admin-list');
  gl.innerHTML=d.groups.length===0?'<div style="color:var(--muted);font-size:12px;padding:16px">No private groups created</div>':
    d.groups.map(g=>\`<div class="group-row">
      <div class="group-info">
        <div class="group-row-name">🔒 \${escHtml(g.name)}</div>
        <div class="group-meta">Created by \${escHtml(g.createdBy)} on \${fmtTime(g.createdAt)} &nbsp;|&nbsp; \${g.memberCount} member(s) online</div>
      </div>
      <div style="display:flex;gap:6px;flex-shrink:0">
        <a class="dl-btn" style="margin:0" href="/api/admin/downloadLog?adminToken=\${adminToken}&groupId=\${g.id}">↓ Log</a>
        <button class="kick-btn" onclick="deleteGroup('\${g.id}',''+escHtml(g.name)+'')">Delete</button>
      </div>
    </div>\`).join('');

  // Audit tab — fetch separately
  const ar=await fetch('/api/admin/audit?adminToken='+adminToken);
  if(ar.ok){
    const ad=await ar.json();
    const al=document.getElementById('audit-list');
    al.innerHTML=ad.audit.map(e=>\`<div class="audit-row">
      <div class="audit-time">\${fmtShort(e.ts)}</div>
      <div class="audit-type">\${escHtml(e.type)}</div>
      <div class="audit-detail">\${escHtml(fmtAudit(e))}</div>
    </div>\`).join('');
  }
}

function fmtAudit(e){
  if(e.type==='login')return e.username+' from '+e.ip+' ('+e.browser+'/'+e.os+') fingerprint:'+e.fingerprint;
  if(e.type==='rename')return e.from+' → '+e.to;
  if(e.type==='group_create')return 'Group "'+e.groupName+'" created by '+e.by;
  if(e.type==='group_join')return e.by+' joined group "'+e.groupName+'"';
  if(e.type==='admin_kick')return 'Kicked '+e.username+' (fp:'+e.fingerprint+')';
  if(e.type==='admin_clear_users')return 'Cleared '+e.count+' sessions';
  if(e.type==='admin_clear_messages')return 'Cleared all messages';
  if(e.type==='admin_delete_group')return 'Deleted group "'+e.groupName+'"';
  if(e.type==='admin_login')return 'Admin login from '+e.ip;
  return JSON.stringify(e);
}

async function kick(token){
  if(!confirm('Kick this user?'))return;
  await fetch('/api/admin/kick',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken,token})});
  refreshStats();
}

async function clearUsers(){
  if(!confirm('This will disconnect ALL users immediately. Continue?'))return;
  const r=await fetch('/api/admin/clearUsers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken})});
  const d=await r.json();
  alert('Cleared '+d.count+' sessions.');refreshStats();
}

async function clearChat(){
  if(!confirm('Clear ALL main chat messages? Cannot be undone.'))return;
  await fetch('/api/admin/clearMessages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken})});
  refreshStats();
}

async function deleteGroup(groupId,name){
  if(!confirm('Delete group "'+name+'"? All its messages will be lost.'))return;
  await fetch('/api/admin/deleteGroup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken,groupId})});
  refreshStats();
}

async function changePasscode(){
  const newPasscode=document.getElementById('new-passcode').value.trim();
  const r=await fetch('/api/admin/changePasscode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken,newPasscode})});
  const d=await r.json();
  if(r.ok){document.getElementById('passcode-ok').textContent='✓ Updated';document.getElementById('new-passcode').value='';refreshStats();}
  else document.getElementById('passcode-ok').textContent=d.error;
}

async function changeAdminPw(){
  const newPassword=document.getElementById('new-admin-pw').value;
  const r=await fetch('/api/admin/changeAdminPassword',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken,newPassword})});
  const d=await r.json();
  if(r.ok){document.getElementById('adminpw-ok').textContent='✓ Updated — logging out...';sessionStorage.clear();setTimeout(()=>location.reload(),1500);}
  else document.getElementById('adminpw-ok').textContent=d.error;
}

if(adminToken)showDashboard();
document.getElementById('admin-pass').addEventListener('keydown',e=>{if(e.key==='Enter')adminLogin();});
</script>
</body></html>`; }
