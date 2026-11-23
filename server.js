'use strict';
// Zero-dependency server: POST /api/scan {url, ref?} -> shallow-clones the repo, reads its manifests, returns SBOM + graph.
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { scan, SKIP_DIRS } = require('./sbom');

const PORT = Number(process.env.PORT) || 8080;
const INDEX = path.join(__dirname, 'public', 'index.html');

function git(args, cwd) {
  return new Promise((resolve, reject) => {
    execFile('git', ['-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always', ...args], {
      cwd, timeout: 180000, maxBuffer: 10 * 1024 * 1024,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_LFS_SKIP_SMUDGE: '1' },
    }, (err, stdout, stderr) => (err ? reject(new Error((stderr || err.message).trim())) : resolve(stdout.trim())));
  });
}

// Runs syft (if installed) on the clone. Offline: update checks off, same directories skipped as our own walk.
function runSyft(dir) {
  const bin = process.env.SYFT_PATH || 'syft';
  const excludes = [...SKIP_DIRS].flatMap((d) => ['--exclude', './**/' + d + '/**']);
  return new Promise((resolve) => {
    execFile(bin, ['scan', 'dir:' + dir, '-o', 'syft-json', '-q', ...excludes], {
      timeout: 300000, maxBuffer: 512 * 1024 * 1024,
      env: { ...process.env, SYFT_CHECK_FOR_APP_UPDATE: 'false' },
    }, (err, stdout, stderr) => {
      if (err) return resolve({ error: err.code === 'ENOENT' ? 'syft is not installed (brew install syft)' : (stderr || err.message).trim().slice(0, 500) });
      try { resolve({ json: JSON.parse(stdout) }); } catch (e) { resolve({ error: 'syft output was not valid JSON' }); }
    });
  });
}

// Accepts https repo URLs, including GitHub/GitLab/Bitbucket "tree/<branch>" browser links.
function normalize(input, ref) {
  let u;
  try { u = new URL(String(input).trim()); } catch { throw new Error('Not a valid URL'); }
  if (u.protocol !== 'https:') throw new Error('Only https:// repository URLs are accepted');
  if (u.username || u.password) throw new Error('URLs with credentials are not accepted');
  if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|\[)/.test(u.hostname)) throw new Error('Local/private hosts are not accepted');
  let p = u.pathname.replace(/\/+$/, '');
  if (['github.com', 'bitbucket.org', 'codeberg.org'].includes(u.hostname)) {
    const seg = p.split('/').filter(Boolean);
    if (seg.length < 2) throw new Error('Expected https://host/owner/repo');
    if (!ref && (seg[2] === 'tree' || seg[2] === 'src') && seg[3]) ref = seg.slice(3).join('/');
    p = '/' + seg[0] + '/' + seg[1].replace(/\.git$/, '');
  } else if (p.includes('/-/')) {
    const [repo, rest] = p.split('/-/');
    const m = rest.match(/^tree\/(.+)$/);
    if (!ref && m) ref = m[1];
    p = repo;
  }
  if (ref && !/^[\w.\/-]+$/.test(ref)) throw new Error('Invalid branch/tag name');
  if (ref && ref.startsWith('-')) throw new Error('Invalid branch/tag name');
  return { url: u.origin + p, ref: ref || null };
}

async function runScan(body) {
  const { url, ref } = normalize(body.url, body.ref && String(body.ref).trim());
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kestral-'));
  const dir = path.join(tmp, 'repo');
  try {
    await git(['clone', '--depth', '1', '--single-branch', '--no-tags', ...(ref ? ['--branch', ref] : []), '--', url, dir]);
    const sha = await git(['rev-parse', 'HEAD'], dir);
    const syft = body.useSyft === false ? null : await runSyft(dir);
    const result = scan(dir, url, sha, syft);
    if (syft && syft.json) result.syftRaw = syft.json;
    result.repo.requestedRef = ref;
    return result;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

http.createServer((req, res) => {
  const send = (code, type, data) => { res.writeHead(code, { 'Content-Type': type }); res.end(data); };
  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) return send(200, 'text/html; charset=utf-8', fs.readFileSync(INDEX));
  if (req.method === 'POST' && req.url === '/api/scan') {
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 1e5) req.destroy(); });
    req.on('end', async () => {
      try {
        const out = await runScan(JSON.parse(raw || '{}'));
        send(200, 'application/json', JSON.stringify(out));
      } catch (e) {
        send(400, 'application/json', JSON.stringify({ error: String(e.message || e) }));
      }
    });
    return;
  }
  send(404, 'text/plain', 'Not found');
}).listen(PORT, '127.0.0.1', () => console.log(`Kestral SBOM running at http://127.0.0.1:${PORT}`));
