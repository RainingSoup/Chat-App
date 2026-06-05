#!/usr/bin/env node
/**
 * SecureChat Server
 * Pure Node.js — no external dependencies required.
 * Run: node server.js
 * Then open: http://localhost:3000
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const MAX_FILE_MB = 10;
const MAX_MESSAGES = 500;

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ── In-memory state ───────────────────────────────────────────────────────────
let state = {
  passcode: 'secret123',          // Change this!
  adminPassword: 'TapuTapu01',      // Admin dashboard password
  messages: [],
  sessions: {},                   // token → { username, joinedAt, lastSeen, ip }
  bannedTokens: new Set(),
};

function uid() { return crypto.randomBytes(12).toString('hex'); }
function now() { return Date.now(); }
function tsStr() { return new Date().toISOString(); }

// ── Session helpers ───────────────────────────────────────────────────────────
function createSession(username, ip) {
  const token = uid();
  state.sessions[token] = { username, joinedAt: now(), lastSeen: now(), ip };
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

// ── Multipart file parser (built-in, no multer) ───────────────────────────────
function parseMultipart(req, cb) {
  const ct = req.headers['content-type'] || '';
  const boundaryMatch = ct.match(/boundary=(.+)$/);
  if (!boundaryMatch) return cb(new Error('No boundary'), null, null);
  const boundary = '--' + boundaryMatch[1];

  let chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    const buf = Buffer.concat(chunks);
    const parts = splitBuffer(buf, Buffer.from('\r\n' + boundary));
    const fields = {};
    let file = null;

    for (const part of parts) {
      const headerEnd = indexOfBuffer(part, Buffer.from('\r\n\r\n'));
      if (headerEnd === -1) continue;
      const headerStr = part.slice(0, headerEnd).toString();
      const body = part.slice(headerEnd + 4);
      const nameMatch = headerStr.match(/name="([^"]+)"/);
      const filenameMatch = headerStr.match(/filename="([^"]+)"/);
      if (!nameMatch) continue;
      if (filenameMatch) {
        const safeName = Date.now() + '_' + filenameMatch[1].replace(/[^a-zA-Z0-9._-]/g, '_');
        const filePath = path.join(UPLOAD_DIR, safeName);
        // Strip trailing \r\n--boundary-- if present
        let fileData = body;
        const endMarker = Buffer.from('\r\n--' + boundaryMatch[1] + '--');
        const endIdx = indexOfBuffer(fileData, endMarker);
        if (endIdx !== -1) fileData = fileData.slice(0, endIdx);
        fs.writeFileSync(filePath, fileData);
        file = { originalName: filenameMatch[1], savedName: safeName, size: fileData.length };
      } else {
        let val = body.toString();
        if (val.endsWith('\r\n')) val = val.slice(0, -2);
        fields[nameMatch[1]] = val;
      }
    }
    cb(null, fields, file);
  });
  req.on('error', cb);
}

function splitBuffer(buf, sep) {
  const parts = [];
  let start = 0;
  let idx;
  while ((idx = indexOfBuffer(buf, sep, start)) !== -1) {
    parts.push(buf.slice(start, idx));
    start = idx + sep.length;
  }
  parts.push(buf.slice(start));
  return parts;
}

function indexOfBuffer(buf, search, offset = 0) {
  for (let i = offset; i <= buf.length - search.length; i++) {
    let found = true;
    for (let j = 0; j < search.length; j++) {
      if (buf[i + j] !== search[j]) { found = false; break; }
    }
    if (found) return i;
  }
  return -1;
}

// ── JSON helpers ──────────────────────────────────────────────────────────────
function jsonRes(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let d = '';
    req.on('data', c => d += c);
    req.on('end', () => {
      try { resolve(JSON.parse(d || '{}')); } catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

// ── Routes ────────────────────────────────────────────────────────────────────
const routes = {};

function route(method, path_, handler) {
  routes[method + ':' + path_] = handler;
}

// Auth
route('POST', '/api/login', async (req, res) => {
  const { passcode, username } = await readBody(req);
  if (!passcode || passcode !== state.passcode) return jsonRes(res, { error: 'Wrong passcode' }, 401);
  if (!username || username.trim().length < 2) return jsonRes(res, { error: 'Username must be 2+ chars' }, 400);
  const clean = username.trim().slice(0, 24);
  const token = createSession(clean, req.socket.remoteAddress);
  state.messages.push({ id: uid(), type: 'system', text: `${clean} joined the chat`, ts: tsStr() });
  jsonRes(res, { token, username: clean });
});

// Rename
route('POST', '/api/rename', async (req, res) => {
  const { token, username } = await readBody(req);
  const s = getSession(token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  if (!username || username.trim().length < 2) return jsonRes(res, { error: 'Username must be 2+ chars' }, 400);
  const old = s.username;
  s.username = username.trim().slice(0, 24);
  state.messages.push({ id: uid(), type: 'system', text: `${old} changed name to ${s.username}`, ts: tsStr() });
  jsonRes(res, { ok: true, username: s.username });
});

// Send message
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

// Get messages
route('GET', '/api/messages', (req, res) => {
  const q = url.parse(req.url, true).query;
  const s = getSession(q.token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);
  const since = parseInt(q.since) || 0;
  const msgs = since ? state.messages.filter(m => new Date(m.ts).getTime() > since) : state.messages.slice(-100);
  jsonRes(res, { messages: msgs, users: onlineUsers(), serverTime: now() });
});

// Upload file
routes['POST:/api/upload'] = (req, res) => {
  const token = url.parse(req.url, true).query.token;
  const s = getSession(token);
  if (!s) return jsonRes(res, { error: 'Invalid session' }, 401);

  const cl = parseInt(req.headers['content-length'] || '0');
  if (cl > MAX_FILE_MB * 1024 * 1024) return jsonRes(res, { error: `File too large (max ${MAX_FILE_MB}MB)` }, 413);

  parseMultipart(req, (err, fields, file) => {
    if (err || !file) return jsonRes(res, { error: 'Upload failed' }, 400);
    const msg = {
      id: uid(), type: 'file', username: s.username,
      fileName: file.originalName, filePath: '/uploads/' + file.savedName,
      fileSize: file.size, ts: tsStr()
    };
    state.messages.push(msg);
    if (state.messages.length > MAX_MESSAGES) state.messages = state.messages.slice(-MAX_MESSAGES);
    jsonRes(res, { ok: true, message: msg });
  });
};

// ── Admin routes ──────────────────────────────────────────────────────────────
route('POST', '/api/admin/login', async (req, res) => {
  const { password } = await readBody(req);
  if (password !== state.adminPassword) return jsonRes(res, { error: 'Wrong password' }, 401);
  jsonRes(res, { ok: true, adminToken: 'admin_' + state.adminPassword });
});

function checkAdmin(req, res) {
  const q = url.parse(req.url, true).query;
  const body_token = req._adminToken;
  return (q.adminToken === 'admin_' + state.adminPassword) || (body_token === 'admin_' + state.adminPassword);
}

route('GET', '/api/admin/stats', (req, res) => {
  if (!checkAdmin(req, res)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  jsonRes(res, {
    passcode: state.passcode,
    totalMessages: state.messages.length,
    onlineUsers: onlineUsers(),
    allSessions: Object.entries(state.sessions).map(([t, s]) => ({
      token: t, ...s, banned: state.bannedTokens.has(t)
    })),
    recentMessages: state.messages.slice(-50)
  });
});

route('POST', '/api/admin/kick', async (req, res) => {
  const body = await readBody(req);
  req._adminToken = body.adminToken;
  if (!checkAdmin(req, res)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  const { token } = body;
  if (state.sessions[token]) {
    const name = state.sessions[token].username;
    state.bannedTokens.add(token);
    state.messages.push({ id: uid(), type: 'system', text: `${name} was removed by admin`, ts: tsStr() });
  }
  jsonRes(res, { ok: true });
});

route('POST', '/api/admin/clearMessages', async (req, res) => {
  const body = await readBody(req);
  req._adminToken = body.adminToken;
  if (!checkAdmin(req, res)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  state.messages = [{ id: uid(), type: 'system', text: 'Chat cleared by admin', ts: tsStr() }];
  jsonRes(res, { ok: true });
});

route('POST', '/api/admin/changePasscode', async (req, res) => {
  const body = await readBody(req);
  req._adminToken = body.adminToken;
  if (!checkAdmin(req, res)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  if (!body.newPasscode || body.newPasscode.length < 4) return jsonRes(res, { error: 'Passcode must be 4+ chars' }, 400);
  state.passcode = body.newPasscode;
  jsonRes(res, { ok: true });
});

route('POST', '/api/admin/changeAdminPassword', async (req, res) => {
  const body = await readBody(req);
  req._adminToken = body.adminToken;
  if (!checkAdmin(req, res)) return jsonRes(res, { error: 'Unauthorized' }, 401);
  if (!body.newPassword || body.newPassword.length < 4) return jsonRes(res, { error: 'Password must be 4+ chars' }, 400);
  state.adminPassword = body.newPassword;
  jsonRes(res, { ok: true });
});

// ── Static file server ────────────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.gif': 'image/gif',
  '.pdf': 'application/pdf', '.zip': 'application/zip',
  '.txt': 'text/plain', '.mp4': 'video/mp4', '.webm': 'video/webm',
};

// ── HTTP server ───────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST', 'Access-Control-Allow-Headers': 'Content-Type' });
    return res.end();
  }

  // Serve uploaded files
  if (pathname.startsWith('/uploads/')) {
    const fileName = path.basename(pathname);
    const filePath = path.join(UPLOAD_DIR, fileName);
    if (!fs.existsSync(filePath)) { res.writeHead(404); return res.end('Not found'); }
    const ext = path.extname(fileName).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Content-Disposition': `attachment; filename="${fileName}"` });
    return fs.createReadStream(filePath).pipe(res);
  }

  // API routes
  const key = req.method + ':' + pathname;
  if (routes[key]) return routes[key](req, res);

  // Serve frontend HTML
  if (pathname === '/' || pathname === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(getFrontendHTML());
  }
  if (pathname === '/admin' || pathname === '/admin.html') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(getAdminHTML());
  }

  res.writeHead(404); res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`\n🔐 SecureChat is running!`);
  console.log(`   Local:   http://localhost:${PORT}`);
  console.log(`   Admin:   http://localhost:${PORT}/admin`);
  console.log(`\n   Default passcode:       secret123`);
  console.log(`   Default admin password: TapuTapu01`);
  console.log(`\n   Change these after first login!\n`);
});

// ── Frontend HTML ─────────────────────────────────────────────────────────────
function getFrontendHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureChat</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0a0f;
    --surface: #111118;
    --border: #1e1e2e;
    --accent: #7c6af7;
    --accent2: #f76a8a;
    --text: #e2e0f0;
    --muted: #5a5875;
    --sys: #3a5a4a;
    --sys-text: #7ddfaa;
    --bubble-me: #1e1a3a;
    --bubble-other: #16161f;
    --file-bg: #1a1530;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--text); font-family:'DM Mono',monospace; height:100dvh; display:flex; flex-direction:column; overflow:hidden; }

  /* Login screen */
  #login-screen {
    display:flex; align-items:center; justify-content:center; flex:1;
    background: radial-gradient(ellipse at 30% 50%, #1a0a2e 0%, var(--bg) 60%);
  }
  .login-box {
    background:var(--surface); border:1px solid var(--border); border-radius:16px;
    padding:48px 40px; width:360px; max-width:90vw;
    box-shadow: 0 0 80px #7c6af720;
  }
  .login-logo { font-family:'Syne',sans-serif; font-size:28px; font-weight:800; margin-bottom:8px; }
  .login-logo span { color:var(--accent); }
  .login-sub { color:var(--muted); font-size:12px; margin-bottom:32px; }
  .field { margin-bottom:16px; }
  .field label { display:block; font-size:11px; color:var(--muted); margin-bottom:6px; letter-spacing:.08em; text-transform:uppercase; }
  .field input {
    width:100%; background:#0d0d16; border:1px solid var(--border); border-radius:8px;
    padding:10px 14px; color:var(--text); font-family:inherit; font-size:14px; outline:none;
    transition: border-color .2s;
  }
  .field input:focus { border-color:var(--accent); }
  .btn {
    width:100%; background:var(--accent); color:#fff; border:none; border-radius:8px;
    padding:12px; font-family:'Syne',sans-serif; font-size:15px; font-weight:600; cursor:pointer;
    transition: opacity .2s, transform .1s;
  }
  .btn:hover { opacity:.9; } .btn:active { transform:scale(.98); }
  .err { color:var(--accent2); font-size:12px; margin-top:8px; min-height:16px; }
  .login-admin-link { text-align:center; margin-top:20px; font-size:11px; color:var(--muted); }
  .login-admin-link a { color:var(--accent); text-decoration:none; }

  /* Chat screen */
  #chat-screen { display:none; flex-direction:column; flex:1; overflow:hidden; }

  header {
    background:var(--surface); border-bottom:1px solid var(--border);
    padding:12px 20px; display:flex; align-items:center; gap:12px;
  }
  .header-logo { font-family:'Syne',sans-serif; font-weight:800; font-size:18px; }
  .header-logo span { color:var(--accent); }
  .header-spacer { flex:1; }
  .online-count { font-size:11px; color:var(--sys-text); background:var(--sys); padding:3px 10px; border-radius:20px; }
  .user-badge { font-size:12px; color:var(--muted); }
  .user-badge strong { color:var(--text); }
  .icon-btn {
    background:transparent; border:1px solid var(--border); color:var(--muted);
    border-radius:8px; padding:6px 10px; font-size:13px; cursor:pointer;
    font-family:inherit; transition: all .2s;
  }
  .icon-btn:hover { border-color:var(--accent); color:var(--accent); }

  .chat-body { display:flex; flex:1; overflow:hidden; }

  /* Sidebar */
  #sidebar {
    width:200px; background:var(--surface); border-right:1px solid var(--border);
    padding:16px 12px; overflow-y:auto; flex-shrink:0;
  }
  .sidebar-title { font-size:10px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); margin-bottom:10px; }
  .user-item { font-size:12px; color:var(--text); padding:6px 8px; border-radius:6px; display:flex; align-items:center; gap:6px; }
  .user-item::before { content:''; width:6px; height:6px; border-radius:50%; background:var(--sys-text); flex-shrink:0; }

  /* Messages */
  #messages {
    flex:1; overflow-y:auto; padding:20px 16px;
    display:flex; flex-direction:column; gap:10px;
  }
  #messages::-webkit-scrollbar { width:4px; }
  #messages::-webkit-scrollbar-track { background:transparent; }
  #messages::-webkit-scrollbar-thumb { background:var(--border); border-radius:4px; }

  .msg { display:flex; flex-direction:column; max-width:70%; }
  .msg.me { align-self:flex-end; align-items:flex-end; }
  .msg.other { align-self:flex-start; align-items:flex-start; }
  .msg.sys { align-self:center; align-items:center; }

  .msg-name { font-size:10px; color:var(--muted); margin-bottom:3px; }
  .msg-bubble {
    padding:10px 14px; border-radius:12px; font-size:13px; line-height:1.5;
    word-break:break-word; position:relative;
  }
  .msg.me .msg-bubble { background:var(--bubble-me); border-bottom-right-radius:3px; border:1px solid #2a2050; }
  .msg.other .msg-bubble { background:var(--bubble-other); border-bottom-left-radius:3px; border:1px solid var(--border); }
  .msg.sys .msg-bubble { background:transparent; color:var(--sys-text); font-size:11px; padding:4px 12px; border:1px solid var(--sys); border-radius:20px; }
  .msg-time { font-size:10px; color:var(--muted); margin-top:3px; }

  .file-msg {
    background:var(--file-bg); border:1px solid #2a2060; border-radius:10px;
    padding:12px 14px; display:flex; align-items:center; gap:10px; min-width:180px;
  }
  .file-icon { font-size:22px; }
  .file-info { flex:1; min-width:0; }
  .file-name { font-size:12px; color:var(--text); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .file-size { font-size:10px; color:var(--muted); }
  .file-dl { color:var(--accent); font-size:11px; text-decoration:none; margin-top:2px; display:inline-block; }
  .file-dl:hover { text-decoration:underline; }

  /* Input area */
  footer {
    background:var(--surface); border-top:1px solid var(--border);
    padding:12px 16px; display:flex; gap:8px; align-items:flex-end;
  }
  #msg-input {
    flex:1; background:#0d0d16; border:1px solid var(--border); border-radius:10px;
    padding:10px 14px; color:var(--text); font-family:inherit; font-size:13px;
    outline:none; resize:none; max-height:120px; transition: border-color .2s;
  }
  #msg-input:focus { border-color:var(--accent); }
  .send-btn {
    background:var(--accent); color:#fff; border:none; border-radius:10px;
    padding:10px 18px; font-family:'Syne',sans-serif; font-weight:600; font-size:13px;
    cursor:pointer; transition: opacity .2s;
  }
  .send-btn:hover { opacity:.85; }
  .attach-btn {
    background:#0d0d16; color:var(--muted); border:1px solid var(--border); border-radius:10px;
    padding:10px 12px; font-size:16px; cursor:pointer; transition: all .2s; line-height:1;
  }
  .attach-btn:hover { border-color:var(--accent); color:var(--accent); }

  /* Rename modal */
  .modal-overlay {
    display:none; position:fixed; inset:0; background:#00000090; z-index:100;
    align-items:center; justify-content:center;
  }
  .modal-overlay.open { display:flex; }
  .modal {
    background:var(--surface); border:1px solid var(--border); border-radius:14px;
    padding:32px; width:320px; max-width:90vw;
  }
  .modal h3 { font-family:'Syne',sans-serif; font-size:18px; margin-bottom:20px; }
  .modal-btns { display:flex; gap:8px; margin-top:16px; }
  .btn-sec { flex:1; background:transparent; border:1px solid var(--border); color:var(--text); border-radius:8px; padding:10px; font-family:inherit; font-size:13px; cursor:pointer; }
  .btn-pri { flex:1; background:var(--accent); color:#fff; border:none; border-radius:8px; padding:10px; font-family:'Syne',sans-serif; font-weight:600; font-size:13px; cursor:pointer; }

  #file-input { display:none; }
  .upload-progress { font-size:11px; color:var(--muted); padding:4px 0; }

  @media(max-width:600px) {
    #sidebar { display:none; }
    .msg { max-width:90%; }
  }
</style>
</head>
<body>

<!-- Login -->
<div id="login-screen">
  <div class="login-box">
    <div class="login-logo">Secure<span>Chat</span></div>
    <div class="login-sub">// end-to-end protected messaging</div>
    <div class="field"><label>Passcode</label><input type="password" id="passcode" placeholder="Enter access passcode" autocomplete="off"></div>
    <div class="field"><label>Your Username</label><input type="text" id="username" placeholder="Choose a name" maxlength="24"></div>
    <button class="btn" onclick="login()">Enter Chat →</button>
    <div class="err" id="login-err"></div>
    <div class="login-admin-link"><a href="/admin">Admin Dashboard</a></div>
  </div>
</div>

<!-- Chat -->
<div id="chat-screen">
  <header>
    <div class="header-logo">Secure<span>Chat</span></div>
    <span class="online-count" id="online-count">0 online</span>
    <div class="header-spacer"></div>
    <span class="user-badge">Logged in as <strong id="current-user"></strong></span>
    <button class="icon-btn" onclick="openRename()">✎ Rename</button>
    <button class="icon-btn" onclick="logout()">⏻ Leave</button>
  </header>
  <div class="chat-body">
    <div id="sidebar">
      <div class="sidebar-title">Online Now</div>
      <div id="user-list"></div>
    </div>
    <div id="messages"></div>
  </div>
  <footer>
    <input type="file" id="file-input" onchange="uploadFile()">
    <button class="attach-btn" onclick="document.getElementById('file-input').click()" title="Attach file">📎</button>
    <textarea id="msg-input" rows="1" placeholder="Type a message..." onkeydown="msgKey(event)" oninput="autoResize(this)"></textarea>
    <button class="send-btn" onclick="sendMessage()">Send</button>
  </footer>
</div>

<!-- Rename modal -->
<div class="modal-overlay" id="rename-modal">
  <div class="modal">
    <h3>Change Username</h3>
    <div class="field"><label>New Username</label><input type="text" id="new-username" maxlength="24" placeholder="Enter new name"></div>
    <div class="err" id="rename-err"></div>
    <div class="modal-btns">
      <button class="btn-sec" onclick="closeRename()">Cancel</button>
      <button class="btn-pri" onclick="rename()">Update</button>
    </div>
  </div>
</div>

<script>
let token = localStorage.getItem('sc_token');
let myUsername = localStorage.getItem('sc_username');
let lastSeen = 0;
let pollTimer;

function fmt(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes/1024).toFixed(1) + ' KB';
  return (bytes/1048576).toFixed(1) + ' MB';
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fmtTime(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
}

function fileIcon(name) {
  const ext = (name.split('.').pop()||'').toLowerCase();
  const icons = {pdf:'📄',png:'🖼️',jpg:'🖼️',jpeg:'🖼️',gif:'🖼️',mp4:'🎬',webm:'🎬',mp3:'🎵',wav:'🎵',zip:'🗜️',rar:'🗜️',doc:'📝',docx:'📝',xls:'📊',xlsx:'📊',txt:'📃'};
  return icons[ext] || '📎';
}

async function login() {
  const passcode = document.getElementById('passcode').value;
  const username = document.getElementById('username').value.trim();
  document.getElementById('login-err').textContent = '';
  try {
    const r = await fetch('/api/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passcode,username})});
    const d = await r.json();
    if (!r.ok) return document.getElementById('login-err').textContent = d.error;
    token = d.token; myUsername = d.username;
    localStorage.setItem('sc_token', token);
    localStorage.setItem('sc_username', myUsername);
    showChat();
  } catch(e) { document.getElementById('login-err').textContent = 'Connection error'; }
}

function showChat() {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('chat-screen').style.display = 'flex';
  document.getElementById('current-user').textContent = myUsername;
  lastSeen = 0;
  poll();
}

function logout() {
  localStorage.removeItem('sc_token');
  localStorage.removeItem('sc_username');
  clearTimeout(pollTimer);
  location.reload();
}

async function poll() {
  try {
    const r = await fetch(\`/api/messages?token=\${token}&since=\${lastSeen}\`);
    if (r.status === 401) { logout(); return; }
    const d = await r.json();
    if (d.messages && d.messages.length) {
      d.messages.forEach(appendMsg);
      lastSeen = d.serverTime;
    }
    if (d.users) updateUsers(d.users);
  } catch(e) {}
  pollTimer = setTimeout(poll, 1500);
}

const seenIds = new Set();

function appendMsg(msg) {
  if (seenIds.has(msg.id)) return;
  seenIds.add(msg.id);
  const el = document.getElementById('messages');
  const div = document.createElement('div');
  div.className = 'msg ' + (msg.type === 'system' ? 'sys' : msg.username === myUsername ? 'me' : 'other');

  if (msg.type === 'system') {
    div.innerHTML = \`<div class="msg-bubble">\${escHtml(msg.text)}</div>\`;
  } else if (msg.type === 'file') {
    div.innerHTML = \`
      \${msg.username !== myUsername ? \`<div class="msg-name">\${escHtml(msg.username)}</div>\` : ''}
      <div class="msg-bubble" style="padding:0;background:transparent;border:none;">
        <div class="file-msg">
          <div class="file-icon">\${fileIcon(msg.fileName)}</div>
          <div class="file-info">
            <div class="file-name">\${escHtml(msg.fileName)}</div>
            <div class="file-size">\${fmt(msg.fileSize)}</div>
            <a class="file-dl" href="\${escHtml(msg.filePath)}" download>↓ Download</a>
          </div>
        </div>
      </div>
      <div class="msg-time">\${fmtTime(msg.ts)}</div>\`;
  } else {
    div.innerHTML = \`
      \${msg.username !== myUsername ? \`<div class="msg-name">\${escHtml(msg.username)}</div>\` : ''}
      <div class="msg-bubble">\${escHtml(msg.text).replace(/\\n/g,'<br>')}</div>
      <div class="msg-time">\${fmtTime(msg.ts)}</div>\`;
  }
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
}

function updateUsers(users) {
  document.getElementById('online-count').textContent = users.length + ' online';
  document.getElementById('user-list').innerHTML = users
    .map(u => \`<div class="user-item">\${escHtml(u.username)}</div>\`).join('');
}

async function sendMessage() {
  const input = document.getElementById('msg-input');
  const text = input.value.trim();
  if (!text) return;
  input.value = ''; autoResize(input);
  await fetch('/api/messages', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,text})});
}

function msgKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}

function autoResize(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 120) + 'px';
}

async function uploadFile() {
  const fileInput = document.getElementById('file-input');
  const file = fileInput.files[0];
  if (!file) return;
  if (file.size > 10 * 1024 * 1024) { alert('File too large (max 10MB)'); return; }
  const fd = new FormData();
  fd.append('file', file);
  fileInput.value = '';
  await fetch(\`/api/upload?token=\${token}\`, {method:'POST',body:fd});
}

function openRename() {
  document.getElementById('new-username').value = '';
  document.getElementById('rename-err').textContent = '';
  document.getElementById('rename-modal').classList.add('open');
  setTimeout(() => document.getElementById('new-username').focus(), 100);
}
function closeRename() { document.getElementById('rename-modal').classList.remove('open'); }

async function rename() {
  const username = document.getElementById('new-username').value.trim();
  document.getElementById('rename-err').textContent = '';
  const r = await fetch('/api/rename', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,username})});
  const d = await r.json();
  if (!r.ok) return document.getElementById('rename-err').textContent = d.error;
  myUsername = d.username;
  localStorage.setItem('sc_username', myUsername);
  document.getElementById('current-user').textContent = myUsername;
  closeRename();
}

// Auto-login if token exists
if (token) {
  fetch(\`/api/messages?token=\${token}&since=0\`).then(r => {
    if (r.ok) { showChat(); } else { localStorage.clear(); }
  }).catch(() => {});
}

document.getElementById('passcode').addEventListener('keydown', e => { if(e.key==='Enter') document.getElementById('username').focus(); });
document.getElementById('username').addEventListener('keydown', e => { if(e.key==='Enter') login(); });
</script>
</body>
</html>`;
}

// ── Admin HTML ─────────────────────────────────────────────────────────────────
function getAdminHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureChat Admin</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#07070e; --surface:#0f0f1a; --border:#1c1c2e; --accent:#f76a8a;
    --accent2:#7c6af7; --text:#e0ddf5; --muted:#4a4868;
    --green:#7ddfaa; --green-bg:#0d1f16;
    --red:#f76a8a; --red-bg:#1f0d13;
    --yellow:#f7c96a; --yellow-bg:#1f1a0d;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--text); font-family:'DM Mono',monospace; min-height:100vh; }

  #admin-login {
    display:flex; align-items:center; justify-content:center; min-height:100vh;
    background: radial-gradient(ellipse at 70% 30%, #1f0a1a 0%, var(--bg) 60%);
  }
  .admin-box {
    background:var(--surface); border:1px solid var(--border); border-radius:16px;
    padding:48px 40px; width:360px; max-width:90vw;
    box-shadow: 0 0 80px #f76a8a15;
  }
  .admin-logo { font-family:'Syne',sans-serif; font-size:24px; font-weight:800; margin-bottom:4px; }
  .admin-logo span { color:var(--accent); }
  .admin-sub { color:var(--muted); font-size:11px; margin-bottom:32px; }
  .field label { display:block; font-size:10px; color:var(--muted); margin-bottom:6px; letter-spacing:.1em; text-transform:uppercase; }
  .field input { width:100%; background:#090914; border:1px solid var(--border); border-radius:8px; padding:10px 14px; color:var(--text); font-family:inherit; font-size:13px; outline:none; transition:border-color .2s; }
  .field input:focus { border-color:var(--accent); }
  .field { margin-bottom:16px; }
  .btn-admin { width:100%; background:var(--accent); color:#fff; border:none; border-radius:8px; padding:12px; font-family:'Syne',sans-serif; font-size:14px; font-weight:700; cursor:pointer; }
  .err { color:var(--accent); font-size:12px; margin-top:8px; }

  #dashboard { display:none; }
  nav {
    background:var(--surface); border-bottom:1px solid var(--border);
    padding:14px 24px; display:flex; align-items:center; gap:16px;
  }
  .nav-logo { font-family:'Syne',sans-serif; font-weight:800; font-size:18px; }
  .nav-logo span { color:var(--accent); }
  .nav-spacer { flex:1; }
  .nav-badge { font-size:11px; background:var(--red-bg); color:var(--red); padding:4px 10px; border-radius:20px; border:1px solid #3a1020; }
  .nav-btn { background:transparent; border:1px solid var(--border); color:var(--muted); border-radius:6px; padding:6px 12px; font-size:11px; cursor:pointer; font-family:inherit; }
  .nav-btn:hover { border-color:var(--accent); color:var(--accent); }

  .dash-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:16px; padding:24px; }

  .card {
    background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:20px;
  }
  .card h3 { font-family:'Syne',sans-serif; font-size:14px; color:var(--muted); margin-bottom:16px; text-transform:uppercase; letter-spacing:.08em; }

  .stat-grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  .stat { background:#0a0a14; border:1px solid var(--border); border-radius:8px; padding:14px; }
  .stat-val { font-size:28px; font-weight:500; color:var(--text); }
  .stat-label { font-size:10px; color:var(--muted); margin-top:2px; }

  .user-row {
    display:flex; align-items:center; gap:10px; padding:8px 10px;
    border-radius:8px; margin-bottom:6px; background:#0a0a14; border:1px solid var(--border);
  }
  .user-dot { width:7px; height:7px; border-radius:50%; background:var(--green); flex-shrink:0; }
  .user-dot.offline { background:var(--muted); }
  .user-name { flex:1; font-size:12px; }
  .user-time { font-size:10px; color:var(--muted); }
  .kick-btn { background:var(--red-bg); color:var(--red); border:1px solid #3a1020; border-radius:6px; padding:4px 10px; font-size:11px; cursor:pointer; font-family:inherit; }
  .kick-btn:hover { background:#2a0f17; }

  .msg-row { padding:8px 10px; border-bottom:1px solid var(--border); font-size:12px; }
  .msg-row:last-child { border-bottom:none; }
  .msg-who { color:var(--accent2); margin-right:8px; }
  .msg-sys { color:var(--green); font-style:italic; }

  .setting-row { display:flex; gap:8px; margin-bottom:10px; align-items:center; }
  .setting-row input { flex:1; background:#090914; border:1px solid var(--border); border-radius:8px; padding:8px 12px; color:var(--text); font-family:inherit; font-size:12px; outline:none; }
  .setting-row input:focus { border-color:var(--accent); }
  .apply-btn { background:var(--accent2); color:#fff; border:none; border-radius:8px; padding:8px 14px; font-size:12px; cursor:pointer; font-family:'Syne',sans-serif; font-weight:600; white-space:nowrap; }
  .apply-btn:hover { opacity:.85; }
  .danger-btn { background:var(--red-bg); color:var(--red); border:1px solid #3a1020; border-radius:8px; padding:8px 14px; font-size:12px; cursor:pointer; font-family:inherit; width:100%; margin-top:6px; }
  .danger-btn:hover { background:#2a0f17; }
  .ok-msg { color:var(--green); font-size:11px; margin-top:6px; }
  .card-full { grid-column: 1 / -1; }
  .msg-list { max-height:300px; overflow-y:auto; }
  .msg-list::-webkit-scrollbar { width:3px; }
  .msg-list::-webkit-scrollbar-thumb { background:var(--border); }
  .passcode-display { background:#0a0a14; border:1px solid var(--border); border-radius:8px; padding:12px; margin-bottom:12px; font-size:13px; color:var(--yellow); letter-spacing:.1em; }
  .passcode-label { font-size:10px; color:var(--muted); margin-bottom:4px; }

  @media(max-width:600px) { .dash-grid { padding:12px; } }
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
    <div style="margin-top:16px;font-size:11px;color:var(--muted);text-align:center">
      <a href="/" style="color:var(--accent2);text-decoration:none">← Back to Chat</a>
    </div>
  </div>
</div>

<div id="dashboard">
  <nav>
    <div class="nav-logo">Secure<span>Chat</span> Admin</div>
    <div class="nav-spacer"></div>
    <span class="nav-badge" id="admin-status">Loading...</span>
    <button class="nav-btn" onclick="refreshStats()">↻ Refresh</button>
    <button class="nav-btn" onclick="adminLogout()">⏻ Exit</button>
  </nav>
  <div class="dash-grid">
    <!-- Stats -->
    <div class="card">
      <h3>Statistics</h3>
      <div class="stat-grid">
        <div class="stat"><div class="stat-val" id="s-online">0</div><div class="stat-label">Online Now</div></div>
        <div class="stat"><div class="stat-val" id="s-msgs">0</div><div class="stat-label">Total Messages</div></div>
        <div class="stat"><div class="stat-val" id="s-sessions">0</div><div class="stat-label">All Sessions</div></div>
        <div class="stat"><div class="stat-val" id="s-banned">0</div><div class="stat-label">Banned</div></div>
      </div>
    </div>
    <!-- Passcode -->
    <div class="card">
      <h3>Access Control</h3>
      <div class="passcode-label">Current Passcode</div>
      <div class="passcode-display" id="current-passcode">—</div>
      <div class="setting-row">
        <input type="text" id="new-passcode" placeholder="New passcode (4+ chars)">
        <button class="apply-btn" onclick="changePasscode()">Update</button>
      </div>
      <div class="ok-msg" id="passcode-ok"></div>
      <hr style="border-color:var(--border);margin:14px 0">
      <div style="font-size:11px;color:var(--muted);margin-bottom:8px;">Admin Password</div>
      <div class="setting-row">
        <input type="password" id="new-admin-pw" placeholder="New admin password">
        <button class="apply-btn" onclick="changeAdminPw()">Update</button>
      </div>
      <div class="ok-msg" id="adminpw-ok"></div>
    </div>
    <!-- Online users -->
    <div class="card">
      <h3>Online Users</h3>
      <div id="online-users-list"><div style="color:var(--muted);font-size:12px;">No users online</div></div>
    </div>
    <!-- Danger zone -->
    <div class="card">
      <h3>Danger Zone</h3>
      <button class="danger-btn" onclick="clearChat()">🗑 Clear All Messages</button>
    </div>
    <!-- Recent messages -->
    <div class="card card-full">
      <h3>Recent Messages</h3>
      <div class="msg-list" id="msg-list"></div>
    </div>
  </div>
</div>

<script>
let adminToken = sessionStorage.getItem('adminToken');

async function adminLogin() {
  const pw = document.getElementById('admin-pass').value;
  const r = await fetch('/api/admin/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  const d = await r.json();
  if (!r.ok) return document.getElementById('admin-err').textContent = d.error;
  adminToken = d.adminToken;
  sessionStorage.setItem('adminToken', adminToken);
  showDashboard();
}

function adminLogout() { sessionStorage.clear(); location.reload(); }

function showDashboard() {
  document.getElementById('admin-login').style.display = 'none';
  document.getElementById('dashboard').style.display = 'block';
  refreshStats();
  setInterval(refreshStats, 5000);
}

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function fmt(bytes) {
  if (!bytes) return '';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes/1024).toFixed(1) + ' KB';
  return (bytes/1048576).toFixed(1) + ' MB';
}
function fmtTime(ts) { return new Date(ts).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}); }

async function refreshStats() {
  const r = await fetch(\`/api/admin/stats?adminToken=\${adminToken}\`);
  if (r.status === 401) { adminLogout(); return; }
  const d = await r.json();

  const onlineSet = new Set(d.onlineUsers.map(u => u.token));
  document.getElementById('s-online').textContent = d.onlineUsers.length;
  document.getElementById('s-msgs').textContent = d.totalMessages;
  document.getElementById('s-sessions').textContent = d.allSessions.length;
  document.getElementById('s-banned').textContent = d.allSessions.filter(s => s.banned).length;
  document.getElementById('admin-status').textContent = d.onlineUsers.length + ' online';
  document.getElementById('current-passcode').textContent = d.passcode;

  // Online users
  const ul = document.getElementById('online-users-list');
  ul.innerHTML = d.allSessions.length === 0 ? '<div style="color:var(--muted);font-size:12px;">No sessions</div>' : d.allSessions.map(s => \`
    <div class="user-row">
      <div class="user-dot \${onlineSet.has(s.token) ? '' : 'offline'}"></div>
      <div class="user-name">\${escHtml(s.username)} \${s.banned ? '<span style="color:var(--red);font-size:10px;">[banned]</span>' : ''}</div>
      <div class="user-time">\${fmtTime(s.lastSeen)}</div>
      \${!s.banned ? \`<button class="kick-btn" onclick="kick('\${s.token}')">Kick</button>\` : ''}
    </div>\`).join('');

  // Messages
  const ml = document.getElementById('msg-list');
  ml.innerHTML = d.recentMessages.slice().reverse().map(m => {
    if (m.type === 'system') return \`<div class="msg-row"><span class="msg-sys">⚙ \${escHtml(m.text)}</span> <span style="color:var(--muted);font-size:10px;">\${fmtTime(m.ts)}</span></div>\`;
    if (m.type === 'file') return \`<div class="msg-row"><span class="msg-who">\${escHtml(m.username)}</span><span>📎 \${escHtml(m.fileName)} (\${fmt(m.fileSize)})</span> <span style="color:var(--muted);font-size:10px;">\${fmtTime(m.ts)}</span></div>\`;
    return \`<div class="msg-row"><span class="msg-who">\${escHtml(m.username)}</span><span>\${escHtml(m.text)}</span> <span style="color:var(--muted);font-size:10px;">\${fmtTime(m.ts)}</span></div>\`;
  }).join('');
}

async function kick(token) {
  if (!confirm('Kick this user?')) return;
  await fetch('/api/admin/kick', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken,token})});
  refreshStats();
}

async function changePasscode() {
  const newPasscode = document.getElementById('new-passcode').value.trim();
  const r = await fetch('/api/admin/changePasscode', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken,newPasscode})});
  const d = await r.json();
  if (r.ok) { document.getElementById('passcode-ok').textContent = '✓ Updated'; document.getElementById('new-passcode').value = ''; refreshStats(); }
  else document.getElementById('passcode-ok').textContent = d.error;
}

async function changeAdminPw() {
  const newPassword = document.getElementById('new-admin-pw').value;
  const r = await fetch('/api/admin/changeAdminPassword', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken,newPassword})});
  const d = await r.json();
  if (r.ok) { document.getElementById('adminpw-ok').textContent = '✓ Updated — please re-login'; sessionStorage.clear(); setTimeout(() => location.reload(), 1500); }
  else document.getElementById('adminpw-ok').textContent = d.error;
}

async function clearChat() {
  if (!confirm('Clear ALL messages? This cannot be undone.')) return;
  await fetch('/api/admin/clearMessages', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminToken})});
  refreshStats();
}

if (adminToken) showDashboard();
document.getElementById('admin-pass').addEventListener('keydown', e => { if(e.key==='Enter') adminLogin(); });
</script>
</body>
</html>`;
}
