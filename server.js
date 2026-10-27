'use strict';

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 8080;
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const UPLOAD_DIR = path.join(ROOT, 'uploads');
const CONFIG_PATH = path.join(ROOT, 'config.json');

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// 访问密码配置，改了 config.json 不用重启，下一次请求就生效
const DEFAULT_CONFIG = { passwordEnabled: false, password: '', secret: 'lan-transfer-secret' };
let configCache = { mtimeMs: 0, data: DEFAULT_CONFIG };

function getConfig() {
  try {
    const st = fs.statSync(CONFIG_PATH);
    if (!configCache.data || st.mtimeMs !== configCache.mtimeMs) {
      const parsed = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
      configCache = { mtimeMs: st.mtimeMs, data: Object.assign({}, DEFAULT_CONFIG, parsed) };
    }
  } catch (_) {
    return DEFAULT_CONFIG;
  }
  return configCache.data;
}

function authToken(cfg) {
  return crypto
    .createHmac('sha256', String(cfg.secret || ''))
    .update(String(cfg.password || ''))
    .digest('hex');
}

function parseCookies(header) {
  const out = {};
  String(header || '')
    .split(';')
    .forEach((part) => {
      const i = part.indexOf('=');
      if (i < 0) return;
      out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    });
  return out;
}

function isAuthed(req) {
  const cfg = getConfig();
  if (!cfg.passwordEnabled || !cfg.password) return true;
  const token = parseCookies(req.headers.cookie)['lt_auth'];
  if (!token) return false;
  const expect = authToken(cfg);
  if (token.length !== expect.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expect));
  } catch (_) {
    return false;
  }
}

// 匿名聊天记录，只放内存，最多保留 300 条
const chatMessages = [];
let chatSeq = 0;
const CHAT_MAX = 300;
const CHAT_TEXT_MAX = 500;

let QRCode = null;
try {
  QRCode = require('qrcode');
} catch (_) {
  QRCode = null;
}

function sendJSON(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

// 只保留文件名本身，去掉路径和非法字符，防止路径穿越
function safeName(raw) {
  let name = path.basename(String(raw || '').replace(/\\/g, '/'));
  name = name.replace(/[\x00-\x1f<>:"/\\|?*]/g, '_');
  name = name.replace(/^[.\s]+/, '').trim();
  if (!name) name = 'unnamed';
  if (name.length > 160) {
    const ext = path.extname(name).slice(0, 20);
    name = name.slice(0, 160 - ext.length) + ext;
  }
  return name;
}

function uniqueName(name) {
  const ext = path.extname(name);
  const base = path.basename(name, ext);
  let candidate = name;
  let i = 1;
  while (fs.existsSync(path.join(UPLOAD_DIR, candidate))) {
    candidate = `${base} (${i++})${ext}`;
  }
  return candidate;
}

function existingFile(raw) {
  const name = path.basename(String(raw || ''));
  if (!name || name.startsWith('.')) return null;
  const full = path.join(UPLOAD_DIR, name);
  if (!full.startsWith(UPLOAD_DIR + path.sep)) return null;
  try {
    const st = fs.statSync(full);
    return st.isFile() ? { name, full, stat: st } : null;
  } catch (_) {
    return null;
  }
}

function listFiles() {
  let names = [];
  try {
    names = fs.readdirSync(UPLOAD_DIR);
  } catch (_) {
    return [];
  }
  const files = [];
  for (const name of names) {
    if (name.startsWith('.')) continue;
    try {
      const st = fs.statSync(path.join(UPLOAD_DIR, name));
      if (!st.isFile()) continue;
      files.push({ name, size: st.size, mtime: st.mtimeMs });
    } catch (_) {
      /* 文件可能刚被删除，跳过 */
    }
  }
  files.sort((a, b) => b.mtime - a.mtime);
  return files;
}

function serveStatic(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not Found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    const types = {
      '.html': 'text/html; charset=utf-8',
      '.js': 'text/javascript; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.svg': 'image/svg+xml',
      '.png': 'image/png',
      '.ico': 'image/x-icon'
    };
    res.writeHead(200, {
      'Content-Type': types[ext] || 'application/octet-stream',
      'Cache-Control': 'no-cache'
    });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // 登录页和登录接口本身不鉴权，其余请求都要先通过密码验证
  const publicPaths = ['/login', '/api/login', '/favicon.ico'];
  if (publicPaths.indexOf(pathname) < 0 && !isAuthed(req)) {
    if (req.method === 'GET' && !pathname.startsWith('/api/')) {
      res.writeHead(302, { Location: '/login' });
      res.end();
      return;
    }
    return sendJSON(res, 401, { ok: false, error: '需要访问密码', auth: true });
  }

  // 登录：校验密码后写一个签名过的 cookie
  if (req.method === 'POST' && pathname === '/api/login') {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 4096) {
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      let payload = {};
      try {
        payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch (_) {
        /* 空请求按空密码处理 */
      }
      const cfg = getConfig();
      if (!cfg.passwordEnabled || !cfg.password) {
        return sendJSON(res, 200, { ok: true });
      }
      const given = Buffer.from(String(payload.password || ''));
      const real = Buffer.from(String(cfg.password));
      const same = given.length === real.length && crypto.timingSafeEqual(given, real);
      if (!same) {
        // 稍微延迟，降低暴力尝试的速度
        setTimeout(() => sendJSON(res, 401, { ok: false, error: '密码不正确' }), 300);
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Set-Cookie': `lt_auth=${authToken(cfg)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800`
      });
      res.end(JSON.stringify({ ok: true }));
    });
    return;
  }

  if (req.method === 'GET' && pathname === '/login') {
    return serveStatic(res, path.join(PUBLIC_DIR, 'login.html'));
  }

  // 列表
  if (req.method === 'GET' && pathname === '/api/files') {
    const files = listFiles();
    const total = files.reduce((s, f) => s + f.size, 0);
    return sendJSON(res, 200, { ok: true, files, total });
  }

  // 上传：直接把请求体当成文件内容，流式写入磁盘
  if (req.method === 'POST' && pathname === '/api/upload') {
    const name = uniqueName(safeName(url.searchParams.get('name')));
    const full = path.join(UPLOAD_DIR, name);
    const ws = fs.createWriteStream(full);
    let bytes = 0;
    let finished = false;

    const fail = (msg) => {
      if (finished) return;
      finished = true;
      ws.destroy();
      fs.unlink(full, () => {});
      sendJSON(res, 500, { ok: false, error: msg });
    };

    req.on('data', (chunk) => {
      bytes += chunk.length;
    });
    req.on('aborted', () => fail('上传被中断'));
    req.on('error', (err) => fail(err.message));
    ws.on('error', (err) => fail(err.message));
    ws.on('finish', () => {
      if (finished) return;
      finished = true;
      sendJSON(res, 200, { ok: true, name, size: bytes });
    });
    req.pipe(ws);
    return;
  }

  // 下载
  if (req.method === 'GET' && pathname === '/api/download') {
    const file = existingFile(url.searchParams.get('name'));
    if (!file) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('文件不存在');
      return;
    }
    const ascii = file.name.replace(/[^\x20-\x7e]/g, '_').replace(/"/g, "'");
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': file.stat.size,
      'Content-Disposition': `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(file.name)}`
    });
    const rs = fs.createReadStream(file.full);
    rs.on('error', () => res.destroy());
    rs.pipe(res);
    return;
  }

  // 删除
  if (req.method === 'DELETE' && pathname === '/api/file') {
    const file = existingFile(url.searchParams.get('name'));
    if (!file) return sendJSON(res, 404, { ok: false, error: '文件不存在' });
    fs.unlink(file.full, (err) => {
      if (err) return sendJSON(res, 500, { ok: false, error: err.message });
      sendJSON(res, 200, { ok: true });
    });
    return;
  }

  // 聊天：拉取 since 之后的新消息
  if (req.method === 'GET' && pathname === '/api/chat') {
    const since = Number(url.searchParams.get('since')) || 0;
    const messages = chatMessages.filter((m) => m.id > since);
    return sendJSON(res, 200, { ok: true, messages, last: chatSeq });
  }

  // 聊天：发送消息
  if (req.method === 'POST' && pathname === '/api/chat') {
    const chunks = [];
    let size = 0;
    let tooBig = false;

    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 8192) {
        tooBig = true;
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      let payload;
      try {
        payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch (_) {
        return sendJSON(res, 400, { ok: false, error: '格式错误' });
      }

      const text = String(payload.text || '')
        .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '')
        .trim()
        .slice(0, CHAT_TEXT_MAX);
      if (!text) return sendJSON(res, 400, { ok: false, error: '内容不能为空' });

      const name =
        String(payload.name || '')
          .replace(/[\x00-\x1f<>]/g, '')
          .trim()
          .slice(0, 24) || '匿名';

      const message = { id: ++chatSeq, name, text, ts: Date.now() };
      chatMessages.push(message);
      if (chatMessages.length > CHAT_MAX) chatMessages.shift();

      sendJSON(res, 200, { ok: true, message });
    });

    req.on('error', () => {
      if (!tooBig) sendJSON(res, 400, { ok: false, error: '请求出错' });
    });
    return;
  }

  // 二维码：内容就是当前访问地址，扫码直接打开
  if (req.method === 'GET' && pathname === '/api/qr') {
    if (!QRCode) return sendJSON(res, 501, { ok: false, error: '未安装 qrcode 模块' });
    const target = `http://${req.headers.host}/`;
    QRCode.toString(target, { type: 'svg', margin: 1, width: 260 })
      .then((svg) => {
        res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'no-store' });
        res.end(svg);
      })
      .catch((err) => sendJSON(res, 500, { ok: false, error: err.message }));
    return;
  }

  if (pathname === '/favicon.ico') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    return serveStatic(res, path.join(PUBLIC_DIR, 'index.html'));
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found');
});

function lanUrls() {
  const urls = [];
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === 'IPv4' && !net.internal) {
        urls.push(`http://${net.address}:${PORT}`);
      }
    }
  }
  return urls;
}

server.listen(PORT, '0.0.0.0', () => {
  const urls = lanUrls();
  console.log('');
  console.log('  局域网快传已启动');
  console.log('  ----------------------------------------');
  if (urls.length === 0) {
    console.log('  未检测到局域网 IP，请确认已连接 Wi-Fi 或网线');
  }
  for (const u of urls) {
    console.log('  ' + u);
  }
  console.log('  ----------------------------------------');
  console.log('  同一 Wi-Fi 下的手机/电脑浏览器打开上面地址即可互传');
  const cfg = getConfig();
  if (cfg.passwordEnabled && cfg.password) {
    console.log('  访问密码：已开启（打开页面后需输入密码）');
  } else {
    console.log('  访问密码：未开启（config.json 里 passwordEnabled 设为 true 可开启）');
  }
  console.log('  文件保存在: ' + UPLOAD_DIR);
  console.log('  按 Ctrl+C 停止服务');
  console.log('');

  if (QRCode && urls.length > 0) {
    QRCode.toString(urls[0] + '/', { type: 'terminal', small: true })
      .then((s) => {
        console.log(s);
        console.log('  手机扫码直接打开（终端显示不正常时忽略，用浏览器扫页面里的二维码）');
      })
      .catch(() => {});
  }
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`端口 ${PORT} 已被占用，换一个端口运行：set PORT=8090 && node server.js`);
  } else {
    console.error('服务启动失败：', err.message);
  }
  process.exit(1);
});
