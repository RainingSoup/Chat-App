#!/usr/bin/env node
/**
 * SecureChat Server — v2
 * Pure Node.js — no external dependencies.
 * Run: node server.js
 * Open: http://localhost:3000  |  Admin: http://localhost:3000/admin
 *
 * New in v2:
 *  - Device fingerprinting & audit log (browser, OS, screen, timezone, language, IP)
 *  - "Clear All Users" button in admin (boots everyone, resets sessions)
 *  - Expandable device detail panel per user in admin
 */

const http = require('http');
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const url  = require('url');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const MAX_FILE_MB  = 10;
const MAX_MESSAGES = 500;

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ── State ─────────────────────────────────────────────────────────────────────
let state = {
  passcode:      'secret123',
  adminPassword: 'admin999',
  messages: [],
  // token → { username, joinedAt, lastSeen, ip, device:{browser,os,screen,tz,lang,ua} }
  sessions: {},
  bannedTokens: new Set(),
  // Permanent audit log — survives session clears
  auditLog: [],   // { ts, event, username, token, ip, device }
};

function uid()   { return crypto.randomBytes(12).toString('hex'); }
function now()   { return Date.now(); }
function tsStr() { return new Date().toISOString(); }

function logAudit(event, username, token, ip, device) {
  state.auditLog.push({ ts: tsStr(), event, username, token: token || '', ip: ip || '', device: device || {} });
  if (state.auditLog.length > 2000) state.auditLog = state.auditLog.slice(-2000);
}

// ── Session helpers ───────────────────────────────────────────────────────────
function createSession(username, ip, device) {
  const token = uid();
  state.sessions[token] = { username, joinedAt: now(), lastSeen: now(), ip, device: device || {} };
  logAudit('JOIN', username, token, ip, device);
  return token;
}

function getSession(token) {
  const s = state.sessions[token];
  if (!s || state.bannedTokens.has(token)) return null;
  s.lastSeen = now();
  return s;
}

function onlineUsers() {
  const cutoff = now() - 30000;
  return Object.entries(state.sessions)
    .filter(([t, s]) => s.lastSeen > cutoff && !state.bannedTokens.has(t))
    .map(([t, s]) => ({ token: t, username: s.username, lastSeen: s.lastSeen, joinedAt: s.joinedAt }));
}

// ── Multipart parser ──────────────────────────────────────────────────────────
function parseMultipart(req, cb) {
  const ct = req.headers['content-type'] || '';
  const bm = ct.match(/boundary=(.+)$/);
  if (!bm) return cb(new Error('No boundary'), null, null);
  const boundary = '--' + bm[1];
  let chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    const buf   = Buffer.concat(chunks);
    const parts = splitBuf(buf, Buffer.from('\r\n' + boundary));
    const fields = {};
    let file = null;
    for (const part of parts) {
      const he = idxBuf(part, Buffer.from('\r\n\r\n'));
      if (he === -1) continue;
      const hdr  = part.slice(0, he).toString();
      const body = part.slice(he + 4);
      const nm = hdr.match(/name="([^"]+)"/);
      const fn = hdr.match(/filename="([^"]+)"/);
      if (!nm) continue;
      if (fn) {
        const safe = Date.now() + '_' + fn[1].replace(/[^a-zA-Z0-9._-]/g, '_');
        const fp   = path.join(UPLOAD_DIR, safe);
        let data   = body;
        const em   = Buffer.from('\r\n--' + bm[1] + '--');
        const ei   = idxBuf(data, em);
        if (ei !== -1) data = data.slice(0, ei);
        fs.writeFileSync(fp, data);
        file = { originalName: fn[1], savedName: safe, size: data.length };
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
function splitBuf(buf, sep) {
  const parts = []; let start = 0, idx;
  while ((idx = idxBuf(buf, sep, start)) !== -1) { parts.push(buf.slice(start, idx)); start = idx + sep.length; }
  parts.push(buf.slice(start)); return parts;
}
function idxBuf(buf, search, offset = 0) {
  for (let i = offset; i <= buf.length - search.length; i++) {
    let ok = true;
    for (let j = 0; j < search.length; j++) { if (buf[i+j] !== search[j]) { ok = false; break; } }
    if (ok) return i;
  }
  return -1;
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────
function jsonRes(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}
function readBody(req) {
  return new Promise((res, rej) => {
    let d = '';
    req.on('data', c => d += c);
    req.on('end', () => { try { res(JSON.parse(d || '{}')); } catch { res({}); } });
    req.on('error', rej);
  });
}

// ── Routes ────────────────────────────────────────────────────────────────────
const routes = {};
function route(method, p, handler) { routes[method + ':' + p] = handler; }

// ── Login (now accepts device fingerprint) ────────────────────────────────────
route('POST', '/api/login', async (req, res) => {
  const { passcode, username, device } = await readBody(req);

  if (!passcode || passcode !== state.passcode)
    return jsonRes(res, { error: 'Wrong passcode' }, 401);

  let clean = (username || '').trim();

  if (!clean)
    clean = 'Guest' + Math.floor(Math.random() * 100000);

  clean = clean.slice(0, 24);

  const ip =
    req.headers['x-forwarded-for'] ||
    req.socket.remoteAddress ||
    'unknown';

  const token = createSession(clean, ip, device || {});

  state.messages.push({
    id: uid(),
    type: 'system',
    text: `${clean} joined the chat`,
    ts: tsStr()
  });

  jsonRes(res, { token, username: clean });
});
// ── Rename ────────────────────────────────────────────────────────────────────
route('POST', '/api/rename', async (req, res) => {
  const { token, username } = await readBody(req);
  const s = getSession(token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  let clean = (username || '').trim();

if (!clean)
  clean = 'Guest' + Math.floor(Math.random() * 100000);

clean = clean.slice(0, 24);
  const old = s.username;
  s.username = username.trim().slice(0, 24);
  logAudit('RENAME', s.username, token, s.ip, s.device);
  state.messages.push({ id: uid(), type: 'system', text: `${old} changed name to ${s.username}`, ts: tsStr() });
  jsonRes(res, { ok: true, username: s.username });
});

// ── Send message ──────────────────────────────────────────────────────────────
route('POST', '/api/messages', async (req, res) => {
  const { token, text } = await readBody(req);
  const s = getSession(token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  if (!text || !text.trim()) return jsonRes(res, { error: 'Empty message' }, 400);
  const msg = { id: uid(), type: 'text', username: s.username, text: text.trim().slice(0, 2000), ts: tsStr() };
  state.messages.push(msg);
  if (state.messages.length > MAX_MESSAGES) state.messages = state.messages.slice(-MAX_MESSAGES);
  jsonRes(res, { ok: true, message: msg });
});

// ── Get messages ──────────────────────────────────────────────────────────────
route('GET', '/api/messages', (req, res) => {
  const q = url.parse(req.url, true).query;
  const s = getSession(q.token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  const since = parseInt(q.since) || 0;
  const msgs  = since ? state.messages.filter(m => new Date(m.ts).getTime() > since) : state.messages.slice(-100);
  jsonRes(res, { messages: msgs, users: onlineUsers(), serverTime: now() });
});

// ── Upload ────────────────────────────────────────────────────────────────────
routes['POST:/api/upload'] = (req, res) => {
  const token = url.parse(req.url, true).query.token;
  const s = getSession(token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  const cl = parseInt(req.headers['content-length'] || '0');
  if (cl > MAX_FILE_MB * 1024 * 1024) return jsonRes(res, { error: `Max ${MAX_FILE_MB}MB` }, 413);
  parseMultipart(req, (err, fields, file) => {
    if (err || !file) return jsonRes(res, { error: 'Upload failed' }, 400);
    const msg = { id: uid(), type: 'file', username: s.username, fileName: file.originalName, filePath: '/uploads/' + file.savedName, fileSize: file.size, ts: tsStr() };
    state.messages.push(msg);
    if (state.messages.length > MAX_MESSAGES) state.messages = state.messages.slice(-MAX_MESSAGES);
    jsonRes(res, { ok: true, message: msg });
  });
};

// ── Admin helpers ─────────────────────────────────────────────────────────────
route('POST', '/api/admin/login', async (req, res) => {
  const { password } = await readBody(req);
  if (password !== state.adminPassword) return jsonRes(res, { error: 'Wrong password' }, 401);
  jsonRes(res, { ok: true, adminToken: 'admin_' + state.adminPassword });
});

function checkAdmin(req, bodyToken) {
  const q = url.parse(req.url, true).query;
  const expected = 'admin_' + state.adminPassword;
  return q.adminToken === expected || bodyToken === expected;
}

// ── Admin: stats ──────────────────────────────────────────────────────────────
route('GET', '/api/admin/stats', (req, res) => {
  if (!checkAdmin(req, '')) return jsonRes(res, { error: 'Unauthorized' }, 401);
  jsonRes(res, {
    passcode: state.passcode,
    totalMessages: state.messages.length,
    onlineUsers: onlineUsers(),
    allSessions: Object.entries(state.sessions).map(([t, s]) => ({
      token: t, username: s.username, joinedAt: s.joinedAt, lastSeen: s.lastSeen,
      ip: s.ip, device: s.device, banned: state.bannedTokens.has(t)
    })),
    recentMessages: state.messages.slice(-50),
    auditLog: state.auditLog.slice(-200),
  });
});

// ── Admin: kick one ───────────────────────────────────────────────────────────
route('POST', '/api/admin/kick', async (req, res) => {
  const body = await readBody(req);
  if (!checkAdmin(req, body.adminToken)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  const { token } = body;
  if (state.sessions[token]) {
    const name = state.sessions[token].username;
    state.bannedTokens.add(token);
    logAudit('KICKED', name, token, state.sessions[token].ip, state.sessions[token].device);
    state.messages.push({ id: uid(), type: 'system', text: `${name} was removed by admin`, ts: tsStr() });
  }
  jsonRes(res, { ok: true });
});

// ── Admin: clear ALL users (new) ──────────────────────────────────────────────
route('POST', '/api/admin/clearUsers', async (req, res) => {
  const body = await readBody(req);
  if (!checkAdmin(req, body.adminToken)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  const count = Object.keys(state.sessions).length;
  // Log each user before wiping
  for (const [t, s] of Object.entries(state.sessions)) {
    logAudit('CLEARED_BY_ADMIN', s.username, t, s.ip, s.device);
  }
  state.sessions = {};
  state.bannedTokens = new Set();
  state.messages.push({ id: uid(), type: 'system', text: `Admin cleared all ${count} user session(s)`, ts: tsStr() });
  jsonRes(res, { ok: true, cleared: count });
});

// ── Admin: clear messages ─────────────────────────────────────────────────────
route('POST', '/api/admin/clearMessages', async (req, res) => {
  const body = await readBody(req);
  if (!checkAdmin(req, body.adminToken)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  state.messages = [{ id: uid(), type: 'system', text: 'Chat cleared by admin', ts: tsStr() }];
  jsonRes(res, { ok: true });
});

// ── Admin: change passcode ────────────────────────────────────────────────────
route('POST', '/api/admin/changePasscode', async (req, res) => {
  const body = await readBody(req);
  if (!checkAdmin(req, body.adminToken)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  if (!body.newPasscode || body.newPasscode.length < 4) return jsonRes(res, { error: 'Passcode 4+ chars' }, 400);
  state.passcode = body.newPasscode;
  jsonRes(res, { ok: true });
});

// ── Admin: change admin password ──────────────────────────────────────────────
route('POST', '/api/admin/changeAdminPassword', async (req, res) => {
  const body = await readBody(req);
  if (!checkAdmin(req, body.adminToken)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  if (!body.newPassword || body.newPassword.length < 4) return jsonRes(res, { error: 'Password 4+ chars' }, 400);
  state.adminPassword = body.newPassword;
  jsonRes(res, { ok: true });
});

// ── MIME types ────────────────────────────────────────────────────────────────
const MIME = {
  '.html':'text/html','.js':'application/javascript','.css':'text/css',
  '.png':'image/png','.jpg':'image/jpeg','.gif':'image/gif',
  '.pdf':'application/pdf','.zip':'application/zip',
  '.txt':'text/plain','.mp4':'video/mp4','.webm':'video/webm',
};

// ── HTTP server ───────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname;

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST','Access-Control-Allow-Headers':'Content-Type'});
    return res.end();
  }

  if (pathname.startsWith('/uploads/')) {
    const fn = path.basename(pathname);
    const fp = path.join(UPLOAD_DIR, fn);
    if (!fs.existsSync(fp)) { res.writeHead(404); return res.end('Not found'); }
    const ext = path.extname(fn).toLowerCase();
    res.writeHead(200, {'Content-Type': MIME[ext]||'application/octet-stream','Content-Disposition':`attachment; filename="${fn}"`});
    return fs.createReadStream(fp).pipe(res);
  }

  const key = req.method + ':' + pathname;
  if (routes[key]) return routes[key](req, res);

  if (pathname === '/' || pathname === '/index.html') {
    res.writeHead(200, {'Content-Type':'text/html'});
    return res.end(getFrontendHTML());
  }
  if (pathname === '/admin' || pathname === '/admin.html') {
    res.writeHead(200, {'Content-Type':'text/html'});
    return res.end(getAdminHTML());
  }

  res.writeHead(404); res.end('Not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🔐 SecureChat v2 is running!`);
  console.log(`   Local:   http://localhost:${PORT}`);
  console.log(`   Admin:   http://localhost:${PORT}/admin`);
  console.log(`\n   Default passcode:       secret123`);
  console.log(`   Default admin password: admin999`);
  console.log(`\n   Change these immediately after first login!\n`);
});

// ═════════════════════════════════════════════════════════════════════════════
// FRONTEND HTML
// ═════════════════════════════════════════════════════════════════════════════
function getFrontendHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureChat</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#0d0d14; --surface:#13131e; --surface2:#1a1a28; --border:#242436;
    --accent:#6c63ff; --accent-glow:#6c63ff30; --accent2:#ff6b8a;
    --text:#eeeaf8; --muted:#6b6888;
    --sys-text:#6debb8; --sys-bg:#0d2420; --sys-border:#1a4035;
    --bubble-me:#1e1b3a; --bubble-me-b:#2d2860; --bubble-other:#161620;
    --file-bg:#16142a;
  }
  *{margin:0;padding:0;box-sizing:border-box;}
  body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;height:100dvh;display:flex;flex-direction:column;overflow:hidden;}
  #login-screen{display:flex;align-items:center;justify-content:center;flex:1;background:radial-gradient(ellipse 80% 60% at 50% 40%,#1a1035 0%,var(--bg) 70%);}
  .lw{width:100%;max-width:400px;padding:24px;}
  .lh{text-align:center;margin-bottom:32px;}
  .lico{width:60px;height:60px;background:var(--accent);border-radius:16px;display:inline-flex;align-items:center;justify-content:center;font-size:26px;margin-bottom:12px;box-shadow:0 0 40px var(--accent-glow);}
  .lt{font-family:'Syne',sans-serif;font-size:24px;font-weight:800;margin-bottom:8px;}
  .lt span{color:var(--accent);}
  .ldesc{color:var(--muted);font-size:12px;line-height:1.5;background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:10px 14px;display:flex;align-items:center;gap:8px;}
  .ldesc::before{content:'ℹ️';font-size:13px;flex-shrink:0;}
  .lcard{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:28px;box-shadow:0 20px 60px #00000050;}
  .step{display:flex;align-items:center;gap:10px;margin-bottom:16px;}
  .sn{width:22px;height:22px;border-radius:50%;background:var(--accent);color:#fff;font-size:11px;font-weight:600;display:flex;align-items:center;justify-content:center;flex-shrink:0;}
  .st{font-size:12px;color:var(--muted);}
  .sdiv{border:none;border-top:1px solid var(--border);margin:16px 0;}
  .field{margin-bottom:16px;}
  .field label{display:flex;align-items:center;gap:6px;font-size:11px;font-weight:500;color:var(--muted);margin-bottom:6px;letter-spacing:.04em;}
  .field input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:11px 13px;color:var(--text);font-family:inherit;font-size:14px;outline:none;transition:border-color .2s,box-shadow .2s;}
  .field input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow);}
  .field input::placeholder{color:var(--muted);}
  .lbtn{width:100%;background:var(--accent);color:#fff;border:none;border-radius:10px;padding:13px;font-family:'Syne',sans-serif;font-size:14px;font-weight:700;cursor:pointer;box-shadow:0 4px 20px var(--accent-glow);transition:opacity .2s,transform .1s;}
  .lbtn:hover{opacity:.9;} .lbtn:active{transform:scale(.98);}
  .lerr{color:var(--accent2);font-size:12px;margin-top:8px;min-height:16px;}
  .lerr:not(:empty)::before{content:'⚠ ';}
  .lfooter{text-align:center;margin-top:16px;font-size:11px;color:var(--muted);}
  .lfooter a{color:var(--accent);text-decoration:none;}
  #chat-screen{display:none;flex-direction:column;flex:1;overflow:hidden;}
  header{background:var(--surface);border-bottom:1px solid var(--border);padding:10px 16px;display:flex;align-items:center;gap:10px;flex-shrink:0;}
  .hlogo{font-family:'Syne',sans-serif;font-weight:800;font-size:17px;}
  .hlogo span{color:var(--accent);}
  .hpill{font-size:11px;font-weight:500;padding:3px 10px;border-radius:20px;background:var(--sys-bg);color:var(--sys-text);border:1px solid var(--sys-border);}
  .hsp{flex:1;}
  .huser{font-size:12px;color:var(--muted);}
  .huser strong{color:var(--text);}
  .hbtn{background:var(--surface2);border:1px solid var(--border);color:var(--muted);border-radius:8px;padding:6px 11px;font-size:12px;cursor:pointer;font-family:inherit;transition:all .15s;}
  .hbtn:hover{border-color:var(--accent);color:var(--accent);}
  .chat-body{display:flex;flex:1;overflow:hidden;}
  #sidebar{width:190px;background:var(--surface);border-right:1px solid var(--border);padding:14px 10px;overflow-y:auto;flex-shrink:0;}
  .sbt{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:10px;padding:0 4px;}
  .sbu{font-size:12px;color:var(--text);padding:7px 8px;border-radius:8px;display:flex;align-items:center;gap:8px;}
  .sbd{width:6px;height:6px;border-radius:50%;background:var(--sys-text);flex-shrink:0;}
  #messages{flex:1;overflow-y:auto;padding:16px 14px;display:flex;flex-direction:column;gap:8px;}
  #messages::-webkit-scrollbar{width:3px;}
  #messages::-webkit-scrollbar-thumb{background:var(--border);}
  .msg{display:flex;flex-direction:column;max-width:72%;}
  .msg.me{align-self:flex-end;align-items:flex-end;}
  .msg.other{align-self:flex-start;align-items:flex-start;}
  .msg.sys{align-self:center;align-items:center;max-width:90%;}
  .mn{font-size:10px;color:var(--muted);margin-bottom:3px;font-weight:500;}
  .mb{padding:10px 13px;border-radius:12px;font-size:13px;line-height:1.55;word-break:break-word;}
  .msg.me .mb{background:var(--bubble-me);border:1px solid var(--bubble-me-b);border-bottom-right-radius:3px;}
  .msg.other .mb{background:var(--bubble-other);border:1px solid var(--border);border-bottom-left-radius:3px;}
  .msg.sys .mb{background:var(--sys-bg);color:var(--sys-text);font-size:11px;padding:4px 14px;border:1px solid var(--sys-border);border-radius:20px;}
  .mt{font-size:10px;color:var(--muted);margin-top:3px;}
  .fbub{background:var(--file-bg);border:1px solid #2a2050;border-radius:11px;padding:11px 13px;display:flex;align-items:center;gap:10px;min-width:190px;}
  .fico{font-size:24px;line-height:1;}
  .finf{flex:1;min-width:0;}
  .fname{font-size:12px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
  .fsize{font-size:10px;color:var(--muted);margin-top:1px;}
  .fdl{color:var(--accent);font-size:11px;text-decoration:none;margin-top:3px;display:inline-block;}
  .fdl:hover{text-decoration:underline;}
  footer{background:var(--surface);border-top:1px solid var(--border);padding:10px 14px;display:flex;gap:8px;align-items:flex-end;flex-shrink:0;}
  #msg-input{flex:1;background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:10px 13px;color:var(--text);font-family:inherit;font-size:13px;outline:none;resize:none;max-height:120px;transition:border-color .2s;}
  #msg-input:focus{border-color:var(--accent);}
  #msg-input::placeholder{color:var(--muted);}
  .fsend{background:var(--accent);color:#fff;border:none;border-radius:10px;padding:10px 16px;font-family:'Syne',sans-serif;font-weight:700;font-size:13px;cursor:pointer;transition:opacity .2s;flex-shrink:0;}
  .fsend:hover{opacity:.85;}
  .fatt{background:var(--surface2);color:var(--muted);border:1px solid var(--border);border-radius:10px;padding:10px 11px;font-size:16px;cursor:pointer;transition:all .15s;line-height:1;flex-shrink:0;}
  .fatt:hover{border-color:var(--accent);color:var(--accent);}
  .modal-overlay{display:none;position:fixed;inset:0;background:#00000088;z-index:100;align-items:center;justify-content:center;}
  .modal-overlay.open{display:flex;}
  .modal{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:28px;width:310px;max-width:90vw;}
  .modal h3{font-family:'Syne',sans-serif;font-size:17px;margin-bottom:18px;}
  .mbtns{display:flex;gap:8px;margin-top:14px;}
  .mcancel{flex:1;background:transparent;border:1px solid var(--border);color:var(--muted);border-radius:8px;padding:10px;font-family:inherit;font-size:13px;cursor:pointer;}
  .mok{flex:1;background:var(--accent);color:#fff;border:none;border-radius:8px;padding:10px;font-family:'Syne',sans-serif;font-weight:700;font-size:13px;cursor:pointer;}
  #file-input{display:none;}
  @media(max-width:580px){#sidebar{display:none;}.msg{max-width:88%;}.huser{display:none;}}
</style>
</head>
<body>
<div id="login-screen">
  <div class="lw">
    <div class="lh">
      <div class="lico">💬</div>
      <div class="lt">Secure<span>Chat</span></div>
      <div class="ldesc">No account needed — enter the passcode and pick a username to join.</div>
    </div>
    <div class="lcard">
      <div class="step"><div class="sn">1</div><div class="st">Enter the passcode you were given</div></div>
      <div class="field"><label>🔑 Chat Passcode</label><input type="password" id="passcode" placeholder="Enter passcode" autocomplete="off"></div>
      <hr class="sdiv">
      <div class="step"><div class="sn">2</div><div class="st">Choose your display name</div></div>
      <div class="field"><label>👤 Display Name</label><input type="text" id="username" placeholder="e.g. Alex or CoolCat99" maxlength="24" autocomplete="off"></div>
      <button class="lbtn" onclick="login()">Join Chat →</button>
      <div class="lerr" id="login-err"></div>
    </div>
    <div class="lfooter"><a href="/admin">Admin Dashboard</a></div>
  </div>
</div>

<div id="chat-screen">
  <header>
    <div class="hlogo">Secure<span>Chat</span></div>
    <span class="hpill" id="online-count">0 online</span>
    <div class="hsp"></div>
    <span class="huser">You are <strong id="current-user"></strong></span>
    <button class="hbtn" onclick="openRename()">✎ Rename</button>
    <button class="hbtn" onclick="logout()">Leave</button>
  </header>
  <div class="chat-body">
    <div id="sidebar"><div class="sbt">Online Now</div><div id="user-list"></div></div>
    <div id="messages"></div>
  </div>
  <footer>
    <input type="file" id="file-input" onchange="uploadFile()">
    <button class="fatt" onclick="document.getElementById('file-input').click()" title="Attach file">📎</button>
    <textarea id="msg-input" rows="1" placeholder="Type a message… (Enter to send, Shift+Enter for new line)" onkeydown="msgKey(event)" oninput="autoResize(this)"></textarea>
    <button class="fsend" onclick="sendMessage()">Send</button>
  </footer>
</div>

<div class="modal-overlay" id="rename-modal">
  <div class="modal">
    <h3>Change Your Name</h3>
    <div class="field"><label>New Display Name</label><input type="text" id="new-username" maxlength="24" placeholder="Enter new name"></div>
    <div class="lerr" id="rename-err"></div>
    <div class="mbtns"><button class="mcancel" onclick="closeRename()">Cancel</button><button class="mok" onclick="rename()">Update</button></div>
  </div>
</div>

<script>
let token = localStorage.getItem('sc_token');
let myUsername = localStorage.getItem('sc_username');
let lastSeen = 0, pollTimer;

function collectDevice() {
  const ua = navigator.userAgent;
  let browser = 'Unknown', os = 'Unknown';
  if (/Edg\//.test(ua)) browser = 'Edge';
  else if (/OPR\//.test(ua)) browser = 'Opera';
  else if (/Chrome\//.test(ua)) browser = 'Chrome';
  else if (/Firefox\//.test(ua)) browser = 'Firefox';
  else if (/Safari\//.test(ua) && !/Chrome/.test(ua)) browser = 'Safari';
  if (/Windows NT 10/.test(ua)) os = 'Windows 10/11';
  else if (/Windows NT 6\.3/.test(ua)) os = 'Windows 8.1';
  else if (/Windows NT 6\.1/.test(ua)) os = 'Windows 7';
  else if (/Windows/.test(ua)) os = 'Windows';
  else if (/Mac OS X/.test(ua)) { os = /iPhone|iPad/.test(ua) ? 'iOS' : 'macOS'; }
  else if (/Android/.test(ua)) os = 'Android';
  else if (/Linux/.test(ua)) os = 'Linux';
  const bv = (ua.match(/(?:Chrome|Firefox|Safari|Edg|OPR)\\/([\\d.]+)/) || [])[1] || '';
  return {
    browser: browser + (bv ? ' ' + bv.split('.')[0] : ''),
    os,
    screen: screen.width + 'x' + screen.height,
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown',
    lang: navigator.language || 'unknown',
    ua: ua.slice(0, 200)
  };
}

function fmt(b){if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';return (b/1048576).toFixed(1)+' MB';}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function fmtTime(ts){return new Date(ts).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});}
function fileIcon(n){const e=(n.split('.').pop()||'').toLowerCase();return{pdf:'📄',png:'🖼️',jpg:'🖼️',jpeg:'🖼️',gif:'🖼️',mp4:'🎬',webm:'🎬',mp3:'🎵',wav:'🎵',zip:'🗜️',rar:'🗜️',doc:'📝',docx:'📝',xls:'📊',xlsx:'📊',txt:'📃'}[e]||'📎';}

async function login() {
  const passcode = document.getElementById('passcode').value;
  const username = document.getElementById('username').value.trim();
  const errEl = document.getElementById('login-err');
  errEl.textContent = '';
  if (!passcode) return errEl.textContent = 'Please enter the passcode';
  if (!username) return errEl.textContent = 'Please enter a display name';
  const device = collectDevice();
  try {
    const r = await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passcode,username,device})});
    const d = await r.json();
    if (!r.ok) { errEl.textContent = d.error==='Wrong passcode'?'Wrong passcode — check with whoever shared the link':d.error; return; }
    token = d.token; myUsername = d.username;
    localStorage.setItem('sc_token',token); localStorage.setItem('sc_username',myUsername);
    showChat();
  } catch(e) { errEl.textContent = 'Could not connect to server'; }
}

function showChat() {
  document.getElementById('login-screen').style.display='none';
  document.getElementById('chat-screen').style.display='flex';
  document.getElementById('current-user').textContent = myUsername;
  lastSeen = 0; poll();
}
function logout() { localStorage.clear(); clearTimeout(pollTimer); location.reload(); }

async function poll() {
  try {
    const r = await fetch(\`/api/messages?token=\${token}&since=\${lastSeen}\`);
    if (r.status === 401) { logout(); return; }
    const d = await r.json();
    if (d.messages && d.messages.length) { d.messages.forEach(appendMsg); lastSeen = d.serverTime; }
    if (d.users) updateUsers(d.users);
  } catch(e) {}
  pollTimer = setTimeout(poll, 1500);
}

const seenIds = new Set();
function appendMsg(msg) {
  if (seenIds.has(msg.id)) return; seenIds.add(msg.id);
  const el = document.getElementById('messages');
  const div = document.createElement('div');
  div.className = 'msg ' + (msg.type==='system'?'sys':msg.username===myUsername?'me':'other');
  if (msg.type==='system') {
    div.innerHTML = \`<div class="mb">\${esc(msg.text)}</div>\`;
  } else if (msg.type==='file') {
    div.innerHTML = \`\${msg.username!==myUsername?\`<div class="mn">\${esc(msg.username)}</div>\`:''}
      <div class="mb" style="padding:0;background:transparent;border:none;">
        <div class="fbub"><div class="fico">\${fileIcon(msg.fileName)}</div>
          <div class="finf"><div class="fname">\${esc(msg.fileName)}</div>
          <div class="fsize">\${fmt(msg.fileSize)}</div>
          <a class="fdl" href="\${esc(msg.filePath)}" download>↓ Download</a></div></div></div>
      <div class="mt">\${fmtTime(msg.ts)}</div>\`;
  } else {
    div.innerHTML = \`\${msg.username!==myUsername?\`<div class="mn">\${esc(msg.username)}</div>\`:''}
      <div class="mb">\${esc(msg.text).replace(/\\n/g,'<br>')}</div>
      <div class="mt">\${fmtTime(msg.ts)}</div>\`;
  }
  el.appendChild(div); el.scrollTop = el.scrollHeight;
}

function updateUsers(users) {
  document.getElementById('online-count').textContent = users.length + ' online';
  document.getElementById('user-list').innerHTML = users.map(u=>\`<div class="sbu"><div class="sbd"></div>\${esc(u.username)}</div>\`).join('');
}

async function sendMessage() {
  const input = document.getElementById('msg-input');
  const text = input.value.trim(); if (!text) return;
  input.value = ''; autoResize(input);
  await fetch('/api/messages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,text})});
}
function msgKey(e) { if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMessage();} }
function autoResize(el) { el.style.height='auto'; el.style.height=Math.min(el.scrollHeight,120)+'px'; }

async function uploadFile() {
  const fi = document.getElementById('file-input');
  const file = fi.files[0]; if(!file) return;
  if(file.size>10*1024*1024){alert('Max 10MB');return;}
  const fd=new FormData(); fd.append('file',file); fi.value='';
  await fetch(\`/api/upload?token=\${token}\`,{method:'POST',body:fd});
}

function openRename() { document.getElementById('new-username').value=''; document.getElementById('rename-err').textContent=''; document.getElementById('rename-modal').classList.add('open'); setTimeout(()=>document.getElementById('new-username').focus(),80); }
function closeRename() { document.getElementById('rename-modal').classList.remove('open'); }
async function rename() {
  const username = document.getElementById('new-username').value.trim();
  document.getElementById('rename-err').textContent='';
  const r = await fetch('/api/rename',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,username})});
  const d = await r.json();
  if(!r.ok) return document.getElementById('rename-err').textContent=d.error;
  myUsername=d.username; localStorage.setItem('sc_username',myUsername);
  document.getElementById('current-user').textContent=myUsername; closeRename();
}

if (token) {
  fetch(\`/api/messages?token=\${token}&since=0\`).then(r=>{ if(r.ok) showChat(); else localStorage.clear(); }).catch(()=>{});
}
document.getElementById('passcode').addEventListener('keydown',e=>{if(e.key==='Enter')document.getElementById('username').focus();});
document.getElementById('username').addEventListener('keydown',e=>{if(e.key==='Enter')login();});
</script>
</body>
</html>`;
}

// ═════════════════════════════════════════════════════════════════════════════
// ADMIN HTML
// ═════════════════════════════════════════════════════════════════════════════
function getAdminHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureChat Admin</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#07070e;--surface:#0f0f1a;--border:#1c1c2e;
    --accent:#f76a8a;--accent2:#7c6af7;--text:#e0ddf5;--muted:#4a4868;
    --green:#7ddfaa;--green-bg:#0d1f16;
    --red:#f76a8a;--red-bg:#1f0d13;
    --yellow:#f7c96a;--blue:#6ab8f7;--blue-bg:#0d1a2a;
  }
  *{margin:0;padding:0;box-sizing:border-box;}
  body{background:var(--bg);color:var(--text);font-family:'DM Mono',monospace;min-height:100vh;}
  #admin-login{display:flex;align-items:center;justify-content:center;min-height:100vh;background:radial-gradient(ellipse at 70% 30%,#1f0a1a 0%,var(--bg) 60%);}
  .abox{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:44px 36px;width:340px;max-width:90vw;box-shadow:0 0 80px #f76a8a12;}
  .alogo{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;margin-bottom:4px;}
  .alogo span{color:var(--accent);}
  .asub{color:var(--muted);font-size:11px;margin-bottom:28px;}
  .field label{display:block;font-size:10px;color:var(--muted);margin-bottom:6px;letter-spacing:.1em;text-transform:uppercase;}
  .field input{width:100%;background:#090914;border:1px solid var(--border);border-radius:8px;padding:10px 13px;color:var(--text);font-family:inherit;font-size:13px;outline:none;transition:border-color .2s;}
  .field input:focus{border-color:var(--accent);}
  .field{margin-bottom:14px;}
  .abtn{width:100%;background:var(--accent);color:#fff;border:none;border-radius:8px;padding:12px;font-family:'Syne',sans-serif;font-size:14px;font-weight:700;cursor:pointer;}
  .aerr{color:var(--accent);font-size:12px;margin-top:8px;}
  #dashboard{display:none;}
  nav{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;}
  .nlogo{font-family:'Syne',sans-serif;font-weight:800;font-size:17px;}
  .nlogo span{color:var(--accent);}
  .nsp{flex:1;}
  .nbadge{font-size:11px;background:var(--red-bg);color:var(--red);padding:3px 10px;border-radius:20px;border:1px solid #3a1020;}
  .nbtn{background:transparent;border:1px solid var(--border);color:var(--muted);border-radius:6px;padding:5px 11px;font-size:11px;cursor:pointer;font-family:inherit;}
  .nbtn:hover{border-color:var(--accent);color:var(--accent);}
  /* Tabs */
  .tabs{display:flex;gap:0;border-bottom:1px solid var(--border);background:var(--surface);padding:0 20px;}
  .tab{padding:11px 18px;font-size:12px;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;font-family:'DM Mono',monospace;}
  .tab:hover{color:var(--text);}
  .tab.active{color:var(--accent);border-bottom-color:var(--accent);}
  .tab-panel{display:none;padding:20px;}
  .tab-panel.active{display:block;}
  /* Cards */
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px;margin-bottom:20px;}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px;}
  .card h3{font-family:'Syne',sans-serif;font-size:13px;color:var(--muted);margin-bottom:14px;text-transform:uppercase;letter-spacing:.08em;}
  .sgrid{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
  .stat{background:#0a0a14;border:1px solid var(--border);border-radius:8px;padding:12px;}
  .sv{font-size:26px;font-weight:500;}
  .sl{font-size:10px;color:var(--muted);margin-top:2px;}
  /* User rows */
  .urow{background:#0a0a14;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;overflow:hidden;}
  .urow-top{display:flex;align-items:center;gap:8px;padding:10px 12px;cursor:pointer;}
  .urow-top:hover{background:#0f0f1e;}
  .udot{width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0;}
  .udot.off{background:var(--muted);}
  .udot.banned{background:var(--red);}
  .uname{flex:1;font-size:12px;font-weight:500;}
  .utag{font-size:10px;padding:2px 7px;border-radius:4px;margin-left:4px;}
  .utag.online{background:var(--green-bg);color:var(--green);border:1px solid #1a4030;}
  .utag.offline{background:#141420;color:var(--muted);border:1px solid var(--border);}
  .utag.banned{background:var(--red-bg);color:var(--red);border:1px solid #3a1020;}
  .utime{font-size:10px;color:var(--muted);}
  .ukick{background:var(--red-bg);color:var(--red);border:1px solid #3a1020;border-radius:6px;padding:4px 9px;font-size:11px;cursor:pointer;font-family:inherit;}
  .ukick:hover{background:#2a0f17;}
  .uexpand{color:var(--muted);font-size:14px;transition:transform .2s;margin-left:4px;}
  .urow-top.expanded .uexpand{transform:rotate(180deg);}
  /* Device detail panel */
  .device-panel{display:none;padding:12px 14px 14px;border-top:1px solid var(--border);background:#080812;}
  .device-panel.open{display:grid;grid-template-columns:1fr 1fr;gap:6px 16px;}
  .dp-row{font-size:11px;}
  .dp-label{color:var(--muted);margin-bottom:1px;}
  .dp-val{color:var(--text);word-break:break-all;}
  .dp-full{grid-column:1/-1;}
  /* Audit log */
  .alog-row{padding:8px 10px;border-bottom:1px solid var(--border);font-size:11px;display:flex;gap:8px;align-items:baseline;}
  .alog-row:last-child{border-bottom:none;}
  .alog-ts{color:var(--muted);flex-shrink:0;font-size:10px;}
  .alog-event{padding:1px 6px;border-radius:4px;font-size:10px;font-weight:500;flex-shrink:0;}
  .ev-JOIN{background:var(--green-bg);color:var(--green);}
  .ev-KICKED,.ev-CLEARED_BY_ADMIN{background:var(--red-bg);color:var(--red);}
  .ev-RENAME{background:var(--blue-bg);color:var(--blue);}
  .ev-default{background:#141420;color:var(--muted);}
  .alog-who{color:var(--accent2);flex-shrink:0;}
  .alog-ip{color:var(--muted);font-size:10px;}
  .alog-dev{color:var(--muted);font-size:10px;flex:1;}
  .alog-list{max-height:420px;overflow-y:auto;}
  .alog-list::-webkit-scrollbar{width:3px;}
  .alog-list::-webkit-scrollbar-thumb{background:var(--border);}
  /* Messages */
  .mrow{padding:8px 10px;border-bottom:1px solid var(--border);font-size:12px;}
  .mrow:last-child{border-bottom:none;}
  .mwho{color:var(--accent2);margin-right:6px;}
  .msys{color:var(--green);font-style:italic;}
  .mlist{max-height:340px;overflow-y:auto;}
  .mlist::-webkit-scrollbar{width:3px;}
  .mlist::-webkit-scrollbar-thumb{background:var(--border);}
  /* Settings */
  .srow{display:flex;gap:8px;margin-bottom:10px;align-items:center;}
  .srow input{flex:1;background:#090914;border:1px solid var(--border);border-radius:8px;padding:8px 12px;color:var(--text);font-family:inherit;font-size:12px;outline:none;}
  .srow input:focus{border-color:var(--accent);}
  .sapply{background:var(--accent2);color:#fff;border:none;border-radius:8px;padding:8px 13px;font-size:12px;cursor:pointer;font-family:'Syne',sans-serif;font-weight:600;white-space:nowrap;}
  .sapply:hover{opacity:.85;}
  .dbtn{background:var(--red-bg);color:var(--red);border:1px solid #3a1020;border-radius:8px;padding:9px 13px;font-size:12px;cursor:pointer;font-family:inherit;width:100%;margin-top:8px;text-align:left;}
  .dbtn:hover{background:#2a0f17;}
  .okmsg{color:var(--green);font-size:11px;margin-top:6px;min-height:14px;}
  .pdisp{background:#0a0a14;border:1px solid var(--border);border-radius:8px;padding:11px 13px;margin-bottom:12px;font-size:13px;color:var(--yellow);letter-spacing:.1em;}
  .plabel{font-size:10px;color:var(--muted);margin-bottom:4px;}
  hr.div{border:none;border-top:1px solid var(--border);margin:14px 0;}
  @media(max-width:600px){.grid{grid-template-columns:1fr;}.device-panel.open{grid-template-columns:1fr;}}
</style>
</head>
<body>

<div id="admin-login">
  <div class="abox">
    <div class="alogo">Secure<span>Chat</span> Admin</div>
    <div class="asub">// restricted access</div>
    <div class="field"><label>Admin Password</label><input type="password" id="admin-pass" placeholder="Enter password"></div>
    <button class="abtn" onclick="adminLogin()">Access Dashboard</button>
    <div class="aerr" id="admin-err"></div>
    <div style="margin-top:16px;font-size:11px;color:var(--muted);text-align:center"><a href="/" style="color:var(--accent2);text-decoration:none">← Back to Chat</a></div>
  </div>
</div>

<div id="dashboard">
  <nav>
    <div class="nlogo">Secure<span>Chat</span> <span style="font-size:12px;color:var(--muted);font-family:'DM Mono'">Admin</span></div>
    <div class="nsp"></div>
    <span class="nbadge" id="admin-status">Loading…</span>
    <button class="nbtn" onclick="refreshStats()">↻ Refresh</button>
    <button class="nbtn" onclick="adminLogout()">⏻ Exit</button>
  </nav>

  <div class="tabs">
    <div class="tab active" onclick="switchTab('overview')">Overview</div>
    <div class="tab" onclick="switchTab('users')">Users & Devices</div>
    <div class="tab" onclick="switchTab('audit')">Audit Log</div>
    <div class="tab" onclick="switchTab('messages')">Messages</div>
    <div class="tab" onclick="switchTab('settings')">Settings</div>
  </div>

  <!-- OVERVIEW -->
  <div class="tab-panel active" id="tab-overview">
    <div class="grid">
      <div class="card">
        <h3>Live Stats</h3>
        <div class="sgrid">
          <div class="stat"><div class="sv" id="s-online">0</div><div class="sl">Online Now</div></div>
          <div class="stat"><div class="sv" id="s-msgs">0</div><div class="sl">Messages</div></div>
          <div class="stat"><div class="sv" id="s-sessions">0</div><div class="sl">Sessions</div></div>
          <div class="stat"><div class="sv" id="s-banned">0</div><div class="sl">Banned</div></div>
        </div>
      </div>
      <div class="card">
        <h3>Quick Actions</h3>
        <button class="dbtn" onclick="clearAllUsers()">👥 Clear All Users &amp; Sessions</button>
        <button class="dbtn" onclick="clearChat()">🗑 Clear All Messages</button>
      </div>
    </div>
    <div class="card">
      <h3>Currently Online</h3>
      <div id="overview-online"><div style="color:var(--muted);font-size:12px;">No users online</div></div>
    </div>
  </div>

  <!-- USERS & DEVICES -->
  <div class="tab-panel" id="tab-users">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
      <div style="font-size:12px;color:var(--muted);">All sessions — click any row to expand device info</div>
      <button class="dbtn" style="width:auto;margin:0;padding:6px 14px;" onclick="clearAllUsers()">👥 Clear All Users</button>
    </div>
    <div id="users-list"></div>
  </div>

  <!-- AUDIT LOG -->
  <div class="tab-panel" id="tab-audit">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
      <div style="font-size:12px;color:var(--muted);">Full activity trail — joins, renames, kicks, clears</div>
      <button class="nbtn" onclick="refreshStats()">↻ Refresh</button>
    </div>
    <div class="card" style="padding:0;overflow:hidden;">
      <div class="alog-list" id="audit-log"></div>
    </div>
  </div>

  <!-- MESSAGES -->
  <div class="tab-panel" id="tab-messages">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
      <div style="font-size:12px;color:var(--muted);">Last 50 messages (newest first)</div>
      <button class="dbtn" style="width:auto;margin:0;padding:6px 14px;" onclick="clearChat()">🗑 Clear Chat</button>
    </div>
    <div class="card" style="padding:0;overflow:hidden;">
      <div class="mlist" id="msg-list"></div>
    </div>
  </div>

  <!-- SETTINGS -->
  <div class="tab-panel" id="tab-settings">
    <div class="grid">
      <div class="card">
        <h3>Chat Passcode</h3>
        <div class="plabel">Current Passcode</div>
        <div class="pdisp" id="cur-passcode">—</div>
        <div class="srow">
          <input type="text" id="new-passcode" placeholder="New passcode (4+ chars)">
          <button class="sapply" onclick="changePasscode()">Update</button>
        </div>
        <div class="okmsg" id="passcode-ok"></div>
      </div>
      <div class="card">
        <h3>Admin Password</h3>
        <div style="font-size:11px;color:var(--muted);margin-bottom:12px;">Changing this will log you out immediately.</div>
        <div class="srow">
          <input type="password" id="new-admin-pw" placeholder="New password (4+ chars)">
          <button class="sapply" onclick="changeAdminPw()">Update</button>
        </div>
        <div class="okmsg" id="adminpw-ok"></div>
      </div>
    </div>
  </div>
</div>

<script>
let adminToken = sessionStorage.getItem('adminToken');

async function adminLogin() {
  const pw = document.getElementById('admin-pass').value;
  const r = await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  const d = await r.json();
  if (!r.ok) return document.getElementById('admin-err').textContent = d.error;
  adminToken = d.adminToken;
  sessionStorage.setItem('adminToken', adminToken);
  showDashboard();
}
function adminLogout() { sessionStorage.clear(); location.reload(); }

function showDashboard() {
  document.getElementById('admin-login').style.display='none';
  document.getElementById('dashboard').style.display='block';
  refreshStats();
  setInterval(refreshStats, 5000);
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i)=>{
    const names=['overview','users','audit','messages','settings'];
    t.classList.toggle('active', names[i]===name);
  });
  document.querySelectorAll('.tab-panel').forEach(p=>{
    p.classList.toggle('active', p.id==='tab-'+name);
  });
}

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function fmt(b){if(!b)return '';if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';return (b/1048576).toFixed(1)+' MB';}
function fmtTime(ts){return new Date(ts).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});}
function fmtDate(ts){return new Date(ts).toLocaleString([],{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});}

async function refreshStats() {
  const r = await fetch(\`/api/admin/stats?adminToken=\${adminToken}\`);
  if (r.status===401) { adminLogout(); return; }
  const d = await r.json();

  const onlineSet = new Set(d.onlineUsers.map(u=>u.token));
  document.getElementById('s-online').textContent = d.onlineUsers.length;
  document.getElementById('s-msgs').textContent   = d.totalMessages;
  document.getElementById('s-sessions').textContent = d.allSessions.length;
  document.getElementById('s-banned').textContent   = d.allSessions.filter(s=>s.banned).length;
  document.getElementById('admin-status').textContent = d.onlineUsers.length + ' online';
  document.getElementById('cur-passcode').textContent = d.passcode;

  // Overview: online only
  const oo = document.getElementById('overview-online');
  const onlineList = d.allSessions.filter(s=>onlineSet.has(s.token));
  oo.innerHTML = onlineList.length===0
    ? '<div style="color:var(--muted);font-size:12px;">No users online right now</div>'
    : onlineList.map(s=>userRowHTML(s, true)).join('');

  // Users tab: all sessions
  const ul = document.getElementById('users-list');
  ul.innerHTML = d.allSessions.length===0
    ? '<div style="color:var(--muted);font-size:12px;">No sessions yet</div>'
    : d.allSessions.map(s=>userRowHTML(s, onlineSet.has(s.token))).join('');

  // Audit log
  const al = document.getElementById('audit-log');
  al.innerHTML = (d.auditLog||[]).length===0
    ? '<div style="padding:12px;color:var(--muted);font-size:12px;">No audit entries yet</div>'
    : d.auditLog.slice().reverse().map(e=>{
        const evClass = ['JOIN','KICKED','CLEARED_BY_ADMIN','RENAME'].includes(e.event) ? 'ev-'+e.event : 'ev-default';
        const dev = e.device ? (e.device.browser||'?') + ' / ' + (e.device.os||'?') : '';
        return \`<div class="alog-row">
          <span class="alog-ts">\${fmtDate(e.ts)}</span>
          <span class="alog-event \${evClass}">\${esc(e.event)}</span>
          <span class="alog-who">\${esc(e.username||'')}</span>
          <span class="alog-ip">\${esc(e.ip||'')}</span>
          <span class="alog-dev">\${esc(dev)}</span>
        </div>\`;
      }).join('');

  // Messages
  const ml = document.getElementById('msg-list');
  ml.innerHTML = d.recentMessages.slice().reverse().map(m=>{
    if(m.type==='system') return \`<div class="mrow"><span class="msys">⚙ \${esc(m.text)}</span> <span style="color:var(--muted);font-size:10px;">\${fmtTime(m.ts)}</span></div>\`;
    if(m.type==='file')   return \`<div class="mrow"><span class="mwho">\${esc(m.username)}</span>📎 \${esc(m.fileName)} (\${fmt(m.fileSize)}) <span style="color:var(--muted);font-size:10px;">\${fmtTime(m.ts)}</span></div>\`;
    return \`<div class="mrow"><span class="mwho">\${esc(m.username)}</span>\${esc(m.text)} <span style="color:var(--muted);font-size:10px;">\${fmtTime(m.ts)}</span></div>\`;
  }).join('');
}

function userRowHTML(s, isOnline) {
  const status = s.banned ? 'banned' : isOnline ? 'online' : 'offline';
  const dotClass = s.banned ? 'banned' : isOnline ? '' : 'off';
  const dev = s.device || {};
  const rowId = 'urow_' + s.token;
  return \`<div class="urow" id="\${rowId}">
    <div class="urow-top" onclick="toggleDevice('\${rowId}')">
      <div class="udot \${dotClass}"></div>
      <div class="uname">\${esc(s.username)} <span class="utag \${status}">\${status}</span></div>
      <div class="utime">\${fmtTime(s.lastSeen)}</div>
      \${!s.banned ? \`<button class="ukick" onclick="event.stopPropagation();kick('\${s.token}')">Kick</button>\` : ''}
      <span class="uexpand">▾</span>
    </div>
    <div class="device-panel" id="dp_\${rowId}">
      <div class="dp-row"><div class="dp-label">IP Address</div><div class="dp-val">\${esc(s.ip||'unknown')}</div></div>
      <div class="dp-row"><div class="dp-label">Browser</div><div class="dp-val">\${esc(dev.browser||'unknown')}</div></div>
      <div class="dp-row"><div class="dp-label">OS</div><div class="dp-val">\${esc(dev.os||'unknown')}</div></div>
      <div class="dp-row"><div class="dp-label">Screen</div><div class="dp-val">\${esc(dev.screen||'unknown')}</div></div>
      <div class="dp-row"><div class="dp-label">Timezone</div><div class="dp-val">\${esc(dev.tz||'unknown')}</div></div>
      <div class="dp-row"><div class="dp-label">Language</div><div class="dp-val">\${esc(dev.lang||'unknown')}</div></div>
      <div class="dp-row"><div class="dp-label">Joined</div><div class="dp-val">\${fmtDate(s.joinedAt)}</div></div>
      <div class="dp-row"><div class="dp-label">Session Token</div><div class="dp-val" style="font-size:10px;color:var(--muted);">\${esc(s.token)}</div></div>
      <div class="dp-row dp-full"><div class="dp-label">User-Agent</div><div class="dp-val" style="font-size:10px;color:var(--muted);">\${esc(dev.ua||'unknown')}</div></div>
    </div>
  </div>\`;
}

function toggleDevice(rowId) {
  const top = document.querySelector('#'+rowId+' .urow-top');
  const panel = document.getElementById('dp_'+rowId);
  const isOpen = panel.classList.contains('open');
  panel.classList.toggle('open', !isOpen);
  top.classList.toggle('expanded', !isOpen);
}

async function kick(token) {
  if(!confirm('Kick this user?')) return;
  await fetch('/api/admin/kick',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken,token})});
  refreshStats();
}

async function clearAllUsers() {
  if(!confirm('This will disconnect ALL users and wipe all sessions. They will need to log in again. Continue?')) return;
  const r = await fetch('/api/admin/clearUsers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken})});
  const d = await r.json();
  if(r.ok) { alert('Cleared ' + d.cleared + ' session(s).'); refreshStats(); }
}

async function clearChat() {
  if(!confirm('Clear ALL messages? Cannot be undone.')) return;
  await fetch('/api/admin/clearMessages',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken})});
  refreshStats();
}

async function changePasscode() {
  const np = document.getElementById('new-passcode').value.trim();
  const r = await fetch('/api/admin/changePasscode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken,newPasscode:np})});
  const d = await r.json();
  document.getElementById('passcode-ok').textContent = r.ok ? '✓ Passcode updated' : d.error;
  if(r.ok) { document.getElementById('new-passcode').value=''; refreshStats(); }
}

async function changeAdminPw() {
  const np = document.getElementById('new-admin-pw').value;
  const r = await fetch('/api/admin/changeAdminPassword',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken,newPassword:np})});
  const d = await r.json();
  if(r.ok) { document.getElementById('adminpw-ok').textContent='✓ Updated — logging out…'; sessionStorage.clear(); setTimeout(()=>location.reload(),1500); }
  else document.getElementById('adminpw-ok').textContent = d.error;
}

if (adminToken) showDashboard();
document.getElementById('admin-pass').addEventListener('keydown',e=>{if(e.key==='Enter')adminLogin();});
</script>
</body>
</html>`;
}
