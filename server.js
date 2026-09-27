/**
 * CloudDrive 多用户网盘服务器
 * 功能：用户注册/登录、个人文件空间隔离、分享链接+分享密码
 * 零依赖，Node.js 内置模块
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const STORAGE_DIR = path.join(__dirname, 'storage');
const PUBLIC_DIR = path.join(__dirname, 'public');

[DATA_DIR, STORAGE_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const SHARES_FILE = path.join(DATA_DIR, 'shares.json');

function loadJSON(file, def) {
  try { return JSON.parse(fs.readFileSync(file, 'utf-8')); }
  catch { return def; }
}
function saveJSON(file, obj) { fs.writeFileSync(file, JSON.stringify(obj, null, 2)); }

let users = loadJSON(USERS_FILE, {});
let sessions = loadJSON(SESSIONS_FILE, {});
let shares = loadJSON(SHARES_FILE, {});

function hashPassword(pwd, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  return { salt, hash: crypto.scryptSync(pwd, salt, 32).toString('hex') };
}
function verifyPassword(pwd, salt, hash) {
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(crypto.scryptSync(pwd, salt, 32), 'hex'));
}
function makeToken() { return crypto.randomBytes(24).toString('hex'); }
function getUserDir(username) {
  const dir = path.join(STORAGE_DIR, username);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
}
function safeName(name) { return path.basename(name).replace(/[<>:"/\\|?*\x00-\x1f]/g, '_'); }
function getUserFromReq(req) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '');
  if (token && sessions[token]) return { username: sessions[token].username, token };
  return null;
}
function sendJSON(res, code, data) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let total = 0;
    req.on('data', c => {
      total += c.length;
      if (total > limit) { reject(new Error('too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function parseMultipart(body, boundary) {
  const result = { fields: {}, files: [] };
  const delim = Buffer.from('--' + boundary);
  let pos = body.indexOf(delim);
  if (pos === -1) return result;
  pos += delim.length;
  while (pos < body.length) {
    if (body[pos] === 45 && body[pos + 1] === 45) break;
    pos += 2;
    const next = body.indexOf(delim, pos);
    if (next === -1) break;
    const part = body.slice(pos, next - 2);
    const he = part.indexOf('\r\n\r\n');
    if (he !== -1) {
      const hs = part.slice(0, he).toString('utf-8');
      const content = part.slice(he + 4);
      const m = hs.match(/Content-Disposition:\s*form-data;\s*name="([^"]*)"(?:;\s*filename="([^"]*)")?/i);
      if (m) {
        if (m[2]) result.files.push({ field: m[1], filename: m[2], data: content });
        else result.fields[m[1]] = content.toString('utf-8');
      }
    }
    pos = next + delim.length;
  }
  return result;
}
function listUserFiles(username) {
  const dir = getUserDir(username);
  return fs.readdirSync(dir)
    .filter(f => fs.statSync(path.join(dir, f)).isFile())
    .map(name => {
      const s = fs.statSync(path.join(dir, name));
      return { name, size: s.size, mtime: Math.floor(s.mtimeMs) };
    })
    .sort((a, b) => b.mtime - a.mtime);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = decodeURIComponent(url.pathname);

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  try {
    // 注册
    if (pathname === '/api/register' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req, 4096)).toString() || '{}');
      const { username, password } = body;
      if (!username || !password || username.length < 2 || password.length < 4)
        return sendJSON(res, 400, { error: '用户名至少2字符，密码至少4位' });
      if (users[username]) return sendJSON(res, 409, { error: '用户名已存在' });
      const { salt, hash } = hashPassword(password);
      users[username] = { salt, hash, createdAt: Date.now() };
      saveJSON(USERS_FILE, users);
      getUserDir(username);
      const token = makeToken();
      sessions[token] = { username, createdAt: Date.now() };
      saveJSON(SESSIONS_FILE, sessions);
      return sendJSON(res, 200, { ok: true, token, username });
    }

    // 登录
    if (pathname === '/api/login' && req.method === 'POST') {
      const body = JSON.parse((await readBody(req, 4096)).toString() || '{}');
      const { username, password } = body;
      const u = users[username];
      if (!u || !verifyPassword(password, u.salt, u.hash))
        return sendJSON(res, 401, { error: '用户名或密码错误' });
      const token = makeToken();
      sessions[token] = { username, createdAt: Date.now() };
      saveJSON(SESSIONS_FILE, sessions);
      return sendJSON(res, 200, { ok: true, token, username });
    }

    // 登出
    if (pathname === '/api/logout' && req.method === 'POST') {
      const u = getUserFromReq(req);
      if (u) { delete sessions[u.token]; saveJSON(SESSIONS_FILE, sessions); }
      return sendJSON(res, 200, { ok: true });
    }

    // 当前用户
    if (pathname === '/api/me' && req.method === 'GET') {
      const u = getUserFromReq(req);
      if (!u) return sendJSON(res, 401, { error: '未登录' });
      return sendJSON(res, 200, { username: u.username });
    }

    // 文件列表（需登录）
    if (pathname === '/api/files' && req.method === 'GET') {
      const u = getUserFromReq(req);
      if (!u) return sendJSON(res, 401, { error: '未登录' });
      return sendJSON(res, 200, { files: listUserFiles(u.username) });
    }

    // 上传（需登录）
    if (pathname === '/api/upload' && req.method === 'POST') {
      const u = getUserFromReq(req);
      if (!u) return sendJSON(res, 401, { error: '未登录' });
      const bm = (req.headers['content-type'] || '').match(/boundary=(.+)$/);
      if (!bm) return sendJSON(res, 400, { error: 'Bad request' });
      const body = await readBody(req, 500 * 1024 * 1024);
      const parsed = parseMultipart(body, bm[1]);
      const dir = getUserDir(u.username);
      const uploaded = [];
      for (const f of parsed.files) {
        const name = safeName(f.filename);
        if (!name) continue;
        fs.writeFileSync(path.join(dir, name), f.data);
        uploaded.push({ name, size: f.data.length });
      }
      return sendJSON(res, 200, { ok: true, files: uploaded });
    }

    // 删除（需登录）
    if (pathname.startsWith('/api/files/') && req.method === 'DELETE') {
      const u = getUserFromReq(req);
      if (!u) return sendJSON(res, 401, { error: '未登录' });
      const name = safeName(decodeURIComponent(pathname.slice('/api/files/'.length)));
      const fp = path.join(getUserDir(u.username), name);
      if (fs.existsSync(fp)) { fs.unlinkSync(fp); return sendJSON(res, 200, { ok: true }); }
      return sendJSON(res, 404, { error: '文件不存在' });
    }

    // 创建分享（需登录）
    if (pathname === '/api/share' && req.method === 'POST') {
      const u = getUserFromReq(req);
      if (!u) return sendJSON(res, 401, { error: '未登录' });
      const body = JSON.parse((await readBody(req, 4096)).toString() || '{}');
      const filename = safeName(body.filename);
      const sharePwd = body.password || '';
      const fp = path.join(getUserDir(u.username), filename);
      if (!fs.existsSync(fp)) return sendJSON(res, 404, { error: '文件不存在' });
      const token = makeToken().slice(0, 12);
      shares[token] = { username: u.username, filename, password: sharePwd, size: fs.statSync(fp).size, createdAt: Date.now() };
      saveJSON(SHARES_FILE, shares);
      return sendJSON(res, 200, { ok: true, shareToken: token, sharePassword: sharePwd });
    }

    // 验证分享密码 + 获取文件信息（不需登录）
    if (pathname.startsWith('/api/shared/') && req.method === 'POST') {
      const token = pathname.slice('/api/shared/'.length);
      const s = shares[token];
      if (!s) return sendJSON(res, 404, { error: '分享不存在或已失效' });
      const body = JSON.parse((await readBody(req, 1024)).toString() || '{}');
      if (s.password && body.password !== s.password)
        return sendJSON(res, 403, { error: '分享密码错误' });
      return sendJSON(res, 200, { filename: s.filename, size: s.size, owner: s.username });
    }

    // 下载分享文件（不需登录）
    if (pathname.startsWith('/share-dl/')) {
      const token = pathname.slice('/share-dl/'.length);
      const s = shares[token];
      if (!s) return sendJSON(res, 404, { error: '分享不存在' });
      const pwd = url.searchParams.get('pwd') || '';
      if (s.password && pwd !== s.password) return sendJSON(res, 403, { error: '密码错误' });
      const fp = path.join(getUserDir(s.username), s.filename);
      if (!fs.existsSync(fp)) return sendJSON(res, 404, { error: '文件不存在' });
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename*=UTF-8''${encodeURIComponent(s.filename)}`,
        'Content-Length': fs.statSync(fp).size,
      });
      fs.createReadStream(fp).pipe(res);
      return;
    }

    // 静态页面
    let fp = pathname === '/' ? '/index.html' : pathname;
    fp = path.normalize(path.join(PUBLIC_DIR, fp));
    if (!fp.startsWith(PUBLIC_DIR)) return sendJSON(res, 403, { error: '禁止' });
    if (fs.existsSync(fp) && fs.statSync(fp).isFile()) {
      const ext = path.extname(fp).toLowerCase();
      const mime = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript', '.css': 'text/css', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' }[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': mime });
      fs.createReadStream(fp).pipe(res);
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      fs.createReadStream(path.join(PUBLIC_DIR, 'index.html')).pipe(res);
    }
  } catch (e) {
    sendJSON(res, 500, { error: e.message });
  }
});

// 超时设置，防止挂起请求卡死事件循环
server.timeout = 30000;        // 30秒不活动断开
server.headersTimeout = 35000;
server.requestTimeout = 60000; // 60秒请求超时

server.listen(PORT, () => {
  console.log('CloudDrive 多用户网盘已启动: http://localhost:' + PORT);
});
