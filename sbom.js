'use strict';
// Builds an SBOM + dependency graph from the manifest/lock files that actually exist in a cloned repo.
// Every component and every edge carries the file + line it was read from. Nothing is inferred or invented:
// if a file does not state a relationship, no edge is emitted.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SKIP_DIRS = new Set(['.git', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__', 'bower_components']);
const NPM_LOCKS = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock'];
const UNSUPPORTED = new Set(['pnpm-lock.yaml', 'bun.lockb', 'bun.lock', 'build.gradle', 'build.gradle.kts', 'gradle.lockfile',
  'packages.lock.json', 'Package.resolved', 'pubspec.lock', 'mix.lock', 'Podfile.lock', 'conan.lock', 'Gopkg.lock']);
const MAX_FILE = 50 * 1024 * 1024;

// ---------- helpers ----------

function walk(root) {
  const out = [];
  const stack = [''];
  while (stack.length) {
    const rel = stack.pop();
    let ents;
    try { ents = fs.readdirSync(path.join(root, rel), { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      const r = rel ? rel + '/' + e.name : e.name;
      if (e.isSymbolicLink()) continue; // never follow links out of the clone
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(r); }
      else if (e.isFile()) out.push(r);
    }
  }
  return out.sort();
}

function detect(rel) {
  const b = path.posix.basename(rel);
  if (b === 'package-lock.json' || b === 'npm-shrinkwrap.json') return 'npm-lock';
  if (b === 'yarn.lock') return 'yarn-lock';
  if (b === 'package.json') return 'package-json';
  if (/^requirements.*\.txt$/i.test(b) || (/\.txt$/i.test(b) && path.posix.basename(path.posix.dirname(rel)) === 'requirements')) return 'requirements';
  if (b === 'poetry.lock') return 'poetry-lock';
  if (b === 'uv.lock') return 'uv-lock';
  if (b === 'Pipfile.lock') return 'pipfile-lock';
  if (b === 'go.mod') return 'go-mod';
  if (b === 'Cargo.lock') return 'cargo-lock';
  if (b === 'Gemfile.lock') return 'gem-lock';
  if (b === 'composer.lock') return 'composer-lock';
  if (b === 'pom.xml') return 'pom';
  return null;
}

const normPy = (n) => n.toLowerCase().replace(/[-_.]+/g, '-');
const enc = (s) => encodeURIComponent(s);

function comp(eco, name, version, range) {
  let ns = null, n = name;
  if (eco === 'npm' && name.startsWith('@') && name.includes('/')) { const i = name.indexOf('/'); ns = name.slice(0, i); n = name.slice(i + 1); }
  else if ((eco === 'golang' || eco === 'composer') && name.includes('/')) { const i = name.lastIndexOf('/'); ns = name.slice(0, i); n = name.slice(i + 1); }
  else if (eco === 'maven') { const i = name.indexOf(':'); ns = name.slice(0, i); n = name.slice(i + 1); }
  if (eco === 'pypi') { n = normPy(n); name = n; }
  const base = 'pkg:' + eco + '/' + (ns ? ns.split('/').map(enc).join('/') + '/' : '') + enc(n);
  if (version) return { ref: base + '@' + enc(version), purl: base + '@' + enc(version), name, version, ecosystem: eco };
  return { ref: base + '#unresolved:' + (range || '*'), purl: base, name, version: null, range: range || '*', ecosystem: eco };
}

function sriToHashes(integrity) {
  const alg = { sha1: 'SHA-1', sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' };
  const out = [];
  for (const part of String(integrity || '').split(/\s+/)) {
    const m = part.match(/^(sha1|sha256|sha384|sha512)-(.+)$/);
    if (m) out.push({ alg: alg[m[1]], content: Buffer.from(m[2], 'base64').toString('hex') });
  }
  return out;
}

// Maps a JSON path (keys joined by \0, array items by index) to the 1-based line where it appears.
// Works on pretty-printed JSON (what npm/composer/pipenv write).
function jsonIndex(text) {
  const idx = new Map();
  const stack = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (!t) continue;
    if (t[0] === '}' || t[0] === ']') { stack.pop(); continue; }
    const m = t.match(/^"((?:[^"\\]|\\.)*)"\s*:\s*(.*)$/);
    let key = null, rest = t;
    const top = stack[stack.length - 1];
    if (m && !(top && top.arr)) { key = m[1]; rest = m[2]; }
    else if (top && top.arr) key = String(top.n++);
    if (key !== null) idx.set(stack.slice(1).map((s) => s.key).concat(key).join('\0'), i + 1);
    const r = rest.replace(/,$/, '');
    if (r.endsWith('{') || r.endsWith('[')) stack.push({ key: key === null ? '' : key, arr: r.endsWith('['), n: 0 });
  }
  return (...p) => idx.get(p.join('\0')) || 1;
}

// Minimal reader for TOML lockfiles made of [[package]] blocks (Cargo.lock, poetry.lock, uv.lock).
function tomlPackages(text) {
  const lines = text.split('\n');
  const pkgs = [];
  let cur = null, section = null, acc = null;
  const depth = (s) => { let d = 0, q = false; for (let k = 0; k < s.length; k++) { const c = s[k]; if (c === '\\' && q) { k++; continue; } if (c === '"') q = !q; else if (!q && (c === '[' || c === '{')) d++; else if (!q && (c === ']' || c === '}')) d--; } return d; };
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (acc) { acc.v.parts.push({ t, line: i + 1 }); acc.v.raw += ' ' + t; acc.d += depth(t); if (acc.d <= 0) acc = null; continue; }
    if (!t || t[0] === '#') continue;
    if (t === '[[package]]') { cur = { line: i + 1, f: {}, t: {} }; pkgs.push(cur); section = null; continue; }
    let m = t.match(/^\[package\.([^\]]+)\]$/);
    if (m && cur) { section = m[1]; cur.t[section] = cur.t[section] || {}; continue; }
    if (t[0] === '[') { cur = null; continue; }
    if (!cur) continue;
    m = t.match(/^"?([^"=]+?)"?\s*=\s*(.*)$/);
    if (!m) continue;
    const v = { raw: m[2], line: i + 1, parts: [{ t: m[2], line: i + 1 }] };
    (section ? cur.t[section] : cur.f)[m[1]] = v;
    const d = depth(m[2]);
    if (d > 0) acc = { v, d };
  }
  return pkgs;
}
const tLine = (p) => (p.f.name ? p.f.name.line : p.line);
const tStr = (v) => (v ? v.raw.replace(/^"(.*)"$/, '$1') : undefined);
const tStrings = (v) => { const out = []; if (!v) return out; for (const p of v.parts) for (const m of p.t.matchAll(/"((?:[^"\\]|\\.)*)"/g)) out.push({ s: m[1], line: p.line }); return out; };
const tTables = (v) => {
  const out = [];
  if (!v) return out;
  for (const p of v.parts) {
    let d = 0, q = false, start = -1;
    for (let k = 0; k < p.t.length; k++) {
      const c = p.t[k];
      if (q) { if (c === '\\') k++; else if (c === '"') q = false; continue; }
      if (c === '"') q = true;
      else if (c === '{') { if (d++ === 0) start = k; }
      else if (c === '}' && --d === 0) {
        const body = p.t.slice(start + 1, k).replace(/\{[^{}]*\}/g, '');
        const n = body.match(/(?:^|[\s,])name\s*=\s*"([^"]+)"/), ver = body.match(/(?:^|[\s,])version\s*=\s*"([^"]+)"/);
        if (n) out.push({ name: n[1], version: ver && ver[1], line: p.line });
      }
    }
  }
  return out;
};

// ---------- graph ----------

class Graph {
  constructor(ctx) {
    this.ctx = ctx;
    this.components = new Map();
    this.edges = [];
    this.edgeKeys = new Map();
  }
  ev(file, line, how = 'parsed') {
    return { file, line: line || null, text: line ? this.ctx.lineText(file, line) : null, permalink: this.ctx.permalink(file, line), how };
  }
  add(c, file, line, how = 'parsed') {
    const by = how === 'parsed' ? 'kestral' : 'syft';
    let e = this.components.get(c.ref);
    if (!e) {
      e = { kind: 'library', scope: 'required', ...c, sources: [], hashes: [], licenses: [], evidence: [] };
      this.components.set(c.ref, e);
    } else if (c.scope === 'required') e.scope = 'required';
    if (!e.sources.includes(by)) e.sources.push(by);
    for (const h of c.hashes || []) if (!e.hashes.some((x) => x.alg === h.alg && x.content === h.content)) e.hashes.push(h);
    for (const l of c.licenses || []) if (l && !e.licenses.includes(l)) e.licenses.push(l);
    if (!e.evidence.some((x) => x.file === file && x.line === (line || null))) e.evidence.push(this.ev(file, line, how));
    return e.ref;
  }
  addRoot(file, name, version, eco) {
    return this.add({ ref: 'manifest:' + file, name: name || file, version: version || null, ecosystem: eco, kind: 'manifest' }, file, null);
  }
  edge(from, to, file, line, how = 'parsed') {
    if (!from || !to || from === to) return;
    const k = from + '\n' + to;
    if (this.edgeKeys.has(k)) return;
    const e = { from, to, sources: [how === 'parsed' ? 'kestral' : 'syft'], ...this.ev(file, line, how) };
    this.edgeKeys.set(k, e);
    this.edges.push(e);
  }
}

// ---------- parsers (each returns the manifest root ref) ----------

function siblingPackageJson(g, ctx, rel) {
  const pj = path.posix.join(path.posix.dirname(rel), 'package.json');
  if (!ctx.exists(pj)) return null;
  try {
    const text = ctx.read(pj);
    const j = JSON.parse(text);
    const L = jsonIndex(text);
    const deps = [];
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      for (const [n, r] of Object.entries(j[field] || {})) deps.push({ name: n, range: String(r), field, file: pj, line: L(field, n) });
    }
    return { json: j, deps };
  } catch { return null; }
}

function resolveNpm(pk, fromKey, name) {
  let base = fromKey;
  for (;;) {
    const cand = (base ? base + '/node_modules/' : 'node_modules/') + name;
    if (pk[cand]) return cand;
    if (base === '') return null;
    const i = base.lastIndexOf('/node_modules/');
    base = i >= 0 ? base.slice(0, i) : '';
  }
}

function parseNpmLock(g, rel, text, ctx) {
  const j = JSON.parse(text);
  const L = jsonIndex(text);
  const root = g.addRoot(rel, j.name, j.version, 'npm');
  if (j.packages) {
    const pk = j.packages;
    const refs = new Map();
    const refFor = (key, seen = new Set()) => {
      if (refs.has(key)) return refs.get(key);
      const ent = pk[key];
      if (!ent || seen.has(key)) return null;
      seen.add(key);
      let r;
      if (key === '') r = root;
      else if (ent.link) r = refFor(ent.resolved, seen);
      else {
        const isWs = !key.includes('node_modules/');
        const name = ent.name || (isWs ? key : key.slice(key.lastIndexOf('node_modules/') + 13));
        r = g.add({
          ...comp('npm', name, ent.version),
          kind: isWs ? 'workspace' : 'library',
          scope: ent.dev ? 'excluded' : ent.optional ? 'optional' : 'required',
          hashes: sriToHashes(ent.integrity),
          licenses: ent.license ? [typeof ent.license === 'string' ? ent.license : ent.license.type] : [],
        }, rel, L('packages', key));
        if (isWs) g.edge(root, r, rel, L('packages', key)); // local workspace package of this project
      }
      refs.set(key, r);
      return r;
    };
    for (const key of Object.keys(pk)) {
      const ent = pk[key];
      if (ent.link) continue;
      const from = refFor(key);
      for (const field of ['dependencies', 'optionalDependencies', 'devDependencies', 'peerDependencies']) {
        for (const dn of Object.keys(ent[field] || {})) {
          const tk = resolveNpm(pk, key, dn);
          if (tk !== null) g.edge(from, refFor(tk), rel, L('packages', key, field, dn));
        }
      }
    }
  } else if (j.dependencies) {
    // lockfileVersion 1: nested tree with "requires"
    const visit = (name, ent, jp, scopes) => {
      const me = comp('npm', name, ent.version).ref;
      g.add({ ...comp('npm', name, ent.version), scope: ent.dev ? 'excluded' : ent.optional ? 'optional' : 'required', hashes: sriToHashes(ent.integrity) }, rel, L(...jp));
      const own = ent.dependencies ? [ent.dependencies, ...scopes] : scopes;
      for (const [cn, ce] of Object.entries(ent.dependencies || {})) visit(cn, ce, [...jp, 'dependencies', cn], own);
      for (const rn of Object.keys(ent.requires || {})) {
        const scope = own.find((s) => s[rn]);
        if (scope) g.edge(me, comp('npm', rn, scope[rn].version).ref, rel, L(...jp, 'requires', rn));
      }
    };
    for (const [n, e] of Object.entries(j.dependencies)) visit(n, e, ['dependencies', n], [j.dependencies]);
    // v1 does not mark direct deps; take them from package.json next to it
    const pj = siblingPackageJson(g, ctx, rel);
    for (const d of pj ? pj.deps : []) {
      const e = j.dependencies[d.name];
      if (e) g.edge(root, comp('npm', d.name, e.version).ref, d.file, d.line);
    }
  }
  return root;
}

function parseYarnLock(g, rel, text, ctx) {
  const lines = text.split('\n');
  const entries = [];
  let cur = null, sub = null;
  const kv = (t) => { const m = t.match(/^"([^"]+)":?\s+(.*)$/) || t.match(/^([^\s:"]+):?\s+(.*)$/); return m ? [m[1], m[2].replace(/^"(.*)"$/, '$1')] : null; };
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    const t = ln.trim();
    if (!t || t[0] === '#') continue;
    const ind = ln.length - ln.trimStart().length;
    if (ind === 0) {
      if (t.startsWith('__metadata')) { cur = null; continue; }
      const descs = t.replace(/:$/, '').split(',').map((s) => s.trim().replace(/^"|"$/g, '')).filter(Boolean);
      cur = { descs, line: i + 1, f: {}, deps: [] };
      entries.push(cur);
      sub = null;
      continue;
    }
    if (!cur) continue;
    if (ind === 2) {
      sub = null;
      if (/^(dependencies|optionalDependencies):$/.test(t)) { sub = 'deps'; continue; }
      const p = kv(t);
      if (p) cur.f[p[0]] = p[1];
    } else if (ind >= 4 && sub === 'deps') {
      const p = kv(t);
      if (p) cur.deps.push({ name: p[0], range: p[1], line: i + 1 });
    }
  }
  const byDesc = new Map();
  const root = g.addRoot(rel, null, null, 'npm');
  for (const e of entries) {
    const d0 = e.descs[0];
    const at = d0.indexOf('@', 1);
    const name = at > 0 ? d0.slice(0, at) : d0;
    let ref;
    if ((e.f.resolution || '').includes('@workspace:') || d0.includes('@workspace:')) {
      const wsPath = (e.f.resolution || d0).split('@workspace:')[1];
      ref = wsPath === '.' ? root : g.add({ ...comp('npm', name, e.f.version), kind: 'workspace' }, rel, e.line);
    } else {
      ref = g.add({ ...comp('npm', name, e.f.version), hashes: sriToHashes(e.f.integrity) }, rel, e.line);
    }
    e.ref = ref;
    for (const d of e.descs) byDesc.set(d, ref);
  }
  const find = (n, r) => byDesc.get(n + '@' + r) || byDesc.get(n + '@npm:' + r);
  for (const e of entries) for (const d of e.deps) g.edge(e.ref, find(d.name, d.range), rel, d.line);
  const hasWsRoot = entries.some((e) => e.ref === root);
  if (!hasWsRoot) {
    const pj = siblingPackageJson(g, ctx, rel);
    for (const d of pj ? pj.deps : []) g.edge(root, find(d.name, d.range), d.file, d.line);
    // yarn v1 workspaces: the workspace packages are not in yarn.lock, their package.json files declare their deps
    const ws = pj && (Array.isArray(pj.json.workspaces) ? pj.json.workspaces : (pj.json.workspaces && pj.json.workspaces.packages) || []);
    const dir = path.posix.dirname(rel);
    const rootPj = path.posix.join(dir, 'package.json');
    for (const pattern of ws || []) {
      const wl = ctx.lineOf(rootPj, JSON.stringify(pattern));
      const prefix = path.posix.join(dir, pattern.replace(/\/\*$/, ''));
      const cands = pattern.endsWith('/*')
        ? [...ctx.files].filter((f) => f.startsWith(prefix + '/') && f.slice(prefix.length + 1).split('/').length === 2 && f.endsWith('/package.json'))
        : [path.posix.join(prefix, 'package.json')].filter((f) => ctx.exists(f));
      for (const wf of cands) {
        const w = siblingPackageJson(g, ctx, wf);
        if (!w) continue;
        const wref = g.add({ ...comp('npm', w.json.name || path.posix.dirname(wf), w.json.version), kind: 'workspace' }, wf, null);
        g.edge(root, wref, rootPj, wl);
        for (const d of w.deps) g.edge(wref, find(d.name, d.range), d.file, d.line);
      }
    }
  }
  return root;
}

function parsePackageJson(g, rel, text) {
  const j = JSON.parse(text);
  const L = jsonIndex(text);
  const root = g.addRoot(rel, j.name, j.version, 'npm');
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [n, r] of Object.entries(j[field] || {})) {
      const to = g.add({ ...comp('npm', n, null, String(r)), scope: field === 'devDependencies' ? 'excluded' : field === 'dependencies' ? 'required' : 'optional' }, rel, L(field, n));
      g.edge(root, to, rel, L(field, n));
    }
  }
  return root;
}

function parseRequirements(g, rel, text) {
  const root = g.addRoot(rel, null, null, 'pypi');
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const start = i;
    let s = lines[i];
    while (s.endsWith('\\') && i + 1 < lines.length) s = s.slice(0, -1) + ' ' + lines[++i];
    s = s.replace(/(^|\s)#.*$/, '').trim();
    if (!s || s[0] === '-' || /^[a-z+]+:\/\//i.test(s)) continue;
    const m = s.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([^;@]*)/);
    if (!m) continue;
    const spec = m[3].replace(/\s--hash=\S+/g, '').trim();
    const pin = spec.match(/^===?\s*([^\s,]+)$/);
    const to = g.add(comp('pypi', m[1], pin ? pin[1] : null, spec || '*'), rel, start + 1);
    g.edge(root, to, rel, start + 1);
  }
  return root;
}

// direct deps declared in pyproject.toml ([project].dependencies, [tool.poetry.*dependencies]) or Pipfile
function pyDirectDeps(ctx, dir, fileName) {
  const f = path.posix.join(dir, fileName);
  if (!ctx.exists(f)) return [];
  const lines = ctx.read(f).split('\n');
  const out = [];
  let sec = '', inArr = false, dev = false;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    const h = t.match(/^\[([^\]]+)\]$/);
    if (h) { sec = h[1]; inArr = false; continue; }
    if (fileName === 'Pipfile') {
      if (sec === 'packages' || sec === 'dev-packages') { const m = t.match(/^"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=/); if (m) out.push({ name: normPy(m[1]), file: f, line: i + 1, dev: sec === 'dev-packages' }); }
      continue;
    }
    if (/^tool\.poetry\.(dependencies|dev-dependencies|group\.[^.]+\.dependencies)$/.test(sec)) {
      const m = t.match(/^"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=/);
      if (m && m[1].toLowerCase() !== 'python') out.push({ name: normPy(m[1]), file: f, line: i + 1, dev: sec !== 'tool.poetry.dependencies' });
      continue;
    }
    if (sec === 'project' || sec === 'project.optional-dependencies' || sec === 'dependency-groups') {
      if (!inArr) { const m = t.match(/^([A-Za-z0-9_-]+)\s*=\s*\[(.*)$/); if (m && (sec !== 'project' || m[1] === 'dependencies')) { inArr = true; dev = sec === 'dependency-groups'; } else continue; }
      for (const m of t.matchAll(/["']([A-Za-z0-9][A-Za-z0-9._-]*)/g)) out.push({ name: normPy(m[1]), file: f, line: i + 1, dev });
      if (/\]\s*(#.*)?$/.test(t)) inArr = false;
    }
  }
  return out;
}

function parsePoetryLock(g, rel, text, ctx) {
  const root = g.addRoot(rel, null, null, 'pypi');
  const byName = new Map();
  const pkgs = tomlPackages(text);
  for (const p of pkgs) {
    const c = comp('pypi', tStr(p.f.name), tStr(p.f.version));
    p.ref = g.add({ ...c, scope: tStr(p.f.category) === 'dev' ? 'excluded' : 'required' }, rel, tLine(p));
    if (!byName.has(c.name)) byName.set(c.name, []);
    byName.get(c.name).push(p.ref);
  }
  for (const p of pkgs) for (const [dn, v] of Object.entries(p.t.dependencies || {})) for (const to of byName.get(normPy(dn)) || []) g.edge(p.ref, to, rel, v.line);
  for (const d of pyDirectDeps(ctx, path.posix.dirname(rel), 'pyproject.toml')) for (const to of byName.get(d.name) || []) g.edge(root, to, d.file, d.line);
  return root;
}

function parseUvLock(g, rel, text) {
  const root = g.addRoot(rel, null, null, 'pypi');
  const byName = new Map();
  const pkgs = tomlPackages(text);
  for (const p of pkgs) {
    const src = p.f.source ? p.f.source.raw : '';
    const local = src.match(/(editable|virtual|directory)\s*=\s*"([^"]+)"/);
    if (local && local[2] === '.') p.ref = root;
    else p.ref = g.add({ ...comp('pypi', tStr(p.f.name), tStr(p.f.version)), kind: local ? 'workspace' : 'library' }, rel, tLine(p));
    const n = normPy(tStr(p.f.name));
    if (!byName.has(n)) byName.set(n, []);
    byName.get(n).push(p);
  }
  const link = (from, d) => {
    const cands = (byName.get(normPy(d.name)) || []).filter((p) => !d.version || tStr(p.f.version) === d.version);
    for (const p of cands) g.edge(from, p.ref, rel, d.line);
  };
  for (const p of pkgs) {
    for (const d of tTables(p.f.dependencies)) link(p.ref, d);
    for (const sec of ['optional-dependencies', 'dev-dependencies']) for (const v of Object.values(p.t[sec] || {})) for (const d of tTables(v)) link(p.ref, d);
  }
  return root;
}

function parsePipfileLock(g, rel, text, ctx) {
  const j = JSON.parse(text);
  const L = jsonIndex(text);
  const root = g.addRoot(rel, null, null, 'pypi');
  const byName = new Map();
  for (const sec of ['default', 'develop']) {
    for (const [n, e] of Object.entries(j[sec] || {})) {
      const v = (e.version || '').replace(/^==/, '') || null;
      const r = g.add({ ...comp('pypi', n, v, e.version), scope: sec === 'develop' ? 'excluded' : 'required' }, rel, L(sec, n));
      byName.set(normPy(n), r);
    }
  }
  for (const d of pyDirectDeps(ctx, path.posix.dirname(rel), 'Pipfile')) g.edge(root, byName.get(d.name), d.file, d.line);
  return root;
}

function parseGoMod(g, rel, text) {
  const lines = text.split('\n');
  const mod = (text.match(/^module\s+(\S+)/m) || [])[1];
  const root = g.addRoot(rel, mod, null, 'golang');
  let inReq = false;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (/^require\s*\($/.test(t)) { inReq = true; continue; }
    if (inReq && t === ')') { inReq = false; continue; }
    const m = inReq ? t.match(/^(\S+)\s+(\S+)(.*)$/) : t.match(/^require\s+(\S+)\s+(\S+)(.*)$/);
    if (!m || m[1].startsWith('//')) continue;
    const indirect = /\/\/\s*indirect/.test(m[3]);
    const to = g.add({ ...comp('golang', m[1], m[2]), properties: indirect ? [{ name: 'go.mod', value: 'indirect' }] : [] }, rel, i + 1);
    // go.mod says which module is direct, but not which module pulls in an indirect one, so only direct edges are proven
    if (!indirect) g.edge(root, to, rel, i + 1);
  }
  return root;
}

function parseCargoLock(g, rel, text) {
  const root = g.addRoot(rel, null, null, 'cargo');
  const pkgs = tomlPackages(text);
  const byName = new Map();
  for (const p of pkgs) {
    const local = !p.f.source;
    const ck = tStr(p.f.checksum);
    p.ref = g.add({ ...comp('cargo', tStr(p.f.name), tStr(p.f.version)), kind: local ? 'workspace' : 'library', hashes: ck ? [{ alg: 'SHA-256', content: ck }] : [] }, rel, tLine(p));
    if (local) g.edge(root, p.ref, rel, tLine(p)); // package without a source = crate that lives in this repo
    const n = tStr(p.f.name);
    if (!byName.has(n)) byName.set(n, []);
    byName.get(n).push(p);
  }
  for (const p of pkgs) {
    for (const d of tStrings(p.f.dependencies)) {
      const [n, v] = d.s.split(' ');
      for (const t of (byName.get(n) || []).filter((x) => !v || tStr(x.f.version) === v)) g.edge(p.ref, t.ref, rel, d.line);
    }
  }
  return root;
}

function parseGemLock(g, rel, text) {
  const root = g.addRoot(rel, null, null, 'gem');
  const lines = text.split('\n');
  const specs = new Map();
  const pend = [];
  let sec = null, cur = null;
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    if (/^\S/.test(ln)) { sec = ln.trim(); cur = null; continue; }
    if (sec === 'GEM' || sec === 'GIT' || sec === 'PATH') {
      let m = ln.match(/^ {4}(\S+) \(([^)]+)\)\s*$/);
      if (m) {
        cur = g.add({ ...comp('gem', m[1], m[2]), kind: sec === 'PATH' ? 'workspace' : 'library' }, rel, i + 1);
        if (!specs.has(m[1])) specs.set(m[1], []);
        specs.get(m[1]).push(cur);
        continue;
      }
      m = ln.match(/^ {6}(\S+)/);
      if (m && cur) pend.push([cur, m[1], i + 1]);
    } else if (sec === 'DEPENDENCIES') {
      const m = ln.match(/^ {2}([^\s!]+)/);
      if (m) pend.push([root, m[1], i + 1]);
    }
  }
  for (const [from, n, line] of pend) for (const to of specs.get(n) || []) g.edge(from, to, rel, line);
  return root;
}

function parseComposerLock(g, rel, text, ctx) {
  const j = JSON.parse(text);
  const L = jsonIndex(text);
  const root = g.addRoot(rel, null, null, 'composer');
  const byName = new Map();
  const all = [];
  for (const sec of ['packages', 'packages-dev']) {
    (j[sec] || []).forEach((p, i) => {
      const sha = p.dist && p.dist.shasum;
      const r = g.add({ ...comp('composer', p.name, p.version), scope: sec === 'packages-dev' ? 'excluded' : 'required', hashes: sha ? [{ alg: 'SHA-1', content: sha }] : [], licenses: p.license || [] }, rel, L(sec, i));
      byName.set(p.name.toLowerCase(), r);
      all.push({ p, r, sec, i });
    });
  }
  const isPkg = (n) => n.includes('/'); // php, ext-*, lib-* are platform requirements, not packages
  for (const { p, r, sec, i } of all) for (const dn of Object.keys(p.require || {})) if (isPkg(dn)) g.edge(r, byName.get(dn.toLowerCase()), rel, L(sec, i, 'require', dn));
  const cj = path.posix.join(path.posix.dirname(rel), 'composer.json');
  if (ctx.exists(cj)) {
    try {
      const ct = ctx.read(cj);
      const c = JSON.parse(ct);
      const CL = jsonIndex(ct);
      for (const f of ['require', 'require-dev']) for (const dn of Object.keys(c[f] || {})) if (isPkg(dn)) g.edge(root, byName.get(dn.toLowerCase()), cj, CL(f, dn));
    } catch { /* composer.json unreadable: no direct edges */ }
  }
  return root;
}

function parsePom(g, rel, text) {
  const blank = (m) => m.replace(/[^\n]/g, ' '); // keep line numbers stable
  let s = text.replace(/<!--[\s\S]*?-->/g, blank)
    .replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/g, blank)
    .replace(/<build>[\s\S]*?<\/build>/g, blank)
    .replace(/<profiles>[\s\S]*?<\/profiles>/g, blank);
  const tag = (x, t) => { const m = x.match(new RegExp('<' + t + '>\\s*([^<]*?)\\s*</' + t + '>')); return m ? m[1] : null; };
  const props = {};
  const pm = s.match(/<properties>([\s\S]*?)<\/properties>/);
  if (pm) for (const m of pm[1].matchAll(/<([\w.-]+)>\s*([^<]*?)\s*<\/\1>/g)) props[m[1]] = m[2];
  const head = s.replace(/<parent>[\s\S]*?<\/parent>/, blank).replace(/<dependencies>[\s\S]*<\/dependencies>/, blank);
  const pv = tag(head, 'version');
  if (pv) props['project.version'] = pv;
  const root = g.addRoot(rel, [tag(head, 'groupId'), tag(head, 'artifactId')].filter(Boolean).join(':') || null, pv, 'maven');
  const sub = (v) => (v ? v.replace(/\$\{([^}]+)\}/g, (m, k) => (k in props ? props[k] : m)) : v);
  for (const m of s.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const b = m[1];
    const gid = sub(tag(b, 'groupId')), aid = sub(tag(b, 'artifactId'));
    if (!gid || !aid) continue;
    let ver = sub(tag(b, 'version'));
    const resolved = ver && !ver.includes('${') && !/[\[\(,]/.test(ver);
    const line = text.slice(0, m.index + m[0].indexOf('<artifactId>')).split('\n').length;
    const scope = tag(b, 'scope');
    const to = g.add({ ...comp('maven', gid + ':' + aid, resolved ? ver : null, ver || 'managed-by-parent'), scope: scope === 'test' ? 'excluded' : tag(b, 'optional') === 'true' ? 'optional' : 'required' }, rel, line);
    g.edge(root, to, rel, line);
  }
  return root;
}

const PARSERS = {
  'npm-lock': parseNpmLock, 'yarn-lock': parseYarnLock, 'package-json': parsePackageJson, requirements: parseRequirements,
  'poetry-lock': parsePoetryLock, 'uv-lock': parseUvLock, 'pipfile-lock': parsePipfileLock, 'go-mod': parseGoMod,
  'cargo-lock': parseCargoLock, 'gem-lock': parseGemLock, 'composer-lock': parseComposerLock, pom: parsePom,
};

// ---------- syft merge ----------
// Syft finds more package types; we keep its findings but label them with the proof we can actually show.
// Matched with our parse -> component is confirmed by both. Syft-only -> we look for the exact line in the file
// Syft named (name + version on/near the same line); if we can't find it, the proof stays file-level and says so.

const SYFT_TYPES = { npm: 'npm', python: 'pypi', 'go-module': 'golang', 'rust-crate': 'cargo', gem: 'gem', 'php-composer': 'composer', 'java-archive': 'maven', 'jenkins-plugin': 'maven' };

function parsePurl(p) {
  const m = String(p || '').match(/^pkg:([^/]+)\/([^@?#]+)(?:@([^?#]+))?/);
  if (!m) return null;
  const segs = m[2].split('/').map(decodeURIComponent);
  const name = segs.pop();
  return { type: m[1].toLowerCase(), ns: segs.join('/') || null, name, version: m[3] ? decodeURIComponent(m[3]) : null };
}
function matchKey(type, ns, name, ver) {
  const n = (ns ? ns + '/' : '') + name;
  return type + '|' + (type === 'pypi' ? normPy(n) : n.toLowerCase()) + '|' + (ver || '');
}
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function locateLine(ctx, file, name, ver) {
  if (!ver || !ctx.exists(file)) return null;
  let lines;
  try { lines = ctx.read(file).split('\n'); } catch { return null; }
  const nre = new RegExp('(?<![A-Za-z0-9_./-])' + reEsc(name) + '(?![A-Za-z0-9_-])');
  const vre = new RegExp('(?<![0-9A-Za-z.])v?' + reEsc(ver.replace(/^v/, '')) + '(?![0-9A-Za-z.])');
  for (let i = 0; i < lines.length; i++) {
    if (!nre.test(lines[i])) continue;
    for (let k = i; k < Math.min(lines.length, i + 6); k++) if (vre.test(lines[k])) return i + 1;
  }
  return null;
}

function mergeSyft(g, ctx, syft) {
  const stats = { artifacts: 0, confirmed: 0, added: 0, addedWithLine: 0, edgesConfirmed: 0, edgesAdded: 0 };
  const idx = new Map();
  for (const c of g.components.values()) {
    const p = c.kind !== 'manifest' && parsePurl(c.purl);
    if (p) idx.set(matchKey(p.type, p.ns, p.name, c.version || c.range), c.ref);
    if (p && !c.version) idx.set(matchKey(p.type, p.ns, p.name, ''), c.ref); // syft reports no version for the same unresolved dep
  }
  const idToRef = new Map();
  for (const a of syft.artifacts || []) {
    stats.artifacts++;
    const p = parsePurl(a.purl) || { type: SYFT_TYPES[a.type] || a.type, ns: null, name: a.name, version: null };
    const ver = p.version || (a.version && a.version !== 'UNKNOWN' ? a.version : null); // syft writes UNKNOWN when it has no version
    const files = (a.locations || []).map((l) => String(l.path || '').replace(/^\//, '')).filter(Boolean);
    const licenses = (a.licenses || []).map((l) => l.spdxExpression || l.value).filter(Boolean);
    let ref = idx.get(matchKey(p.type, p.ns, p.name, ver));
    if (ref) {
      stats.confirmed++;
      const c = g.components.get(ref);
      if (!c.sources.includes('syft')) c.sources.push('syft');
      for (const l of licenses) if (!c.licenses.includes(l)) c.licenses.push(l);
      for (const f of files) if (!c.evidence.some((e) => e.file === f)) g.add({ ref }, f, null, 'syft'); // only files we hadn't already proven
    } else {
      ref = a.purl || 'syft:' + a.type + '/' + a.name + '@' + (ver || '');
      const base = { ref, purl: a.purl || undefined, name: a.name, version: ver, range: ver ? undefined : 'unknown (syft)', ecosystem: p.type, kind: 'library', licenses };
      let lined = false;
      for (const f of files) {
        const line = locateLine(ctx, f, a.name, ver);
        if (line) lined = true;
        g.add(base, f, line, line ? 'syft+text-search' : 'syft');
      }
      if (!files.length) continue;
      stats.added++;
      if (lined) stats.addedWithLine++;
    }
    const c = g.components.get(ref);
    c.syftFoundBy = a.foundBy;
    c.syftType = a.type;
    for (const l of a.licenses || []) {
      const v = l.spdxExpression || l.value;
      if (v) (c.licenseEvidence = c.licenseEvidence || []).push({ license: v, by: 'syft', files: (l.locations || []).map((x) => String(x.path || '').replace(/^\//, '')) });
    }
    idToRef.set(a.id, ref);
  }
  for (const r of syft.artifactRelationships || []) {
    if (r.type !== 'dependency-of') continue; // syft: parent is the dependency, child depends on it
    const from = idToRef.get(r.child), to = idToRef.get(r.parent);
    if (!from || !to || from === to) continue;
    const existing = g.edgeKeys.get(from + '\n' + to);
    if (existing) { if (!existing.sources.includes('syft')) { existing.sources.push('syft'); stats.edgesConfirmed++; } continue; }
    const src = g.components.get(from).evidence.find((e) => e.how !== 'parsed') || g.components.get(from).evidence[0];
    g.edge(from, to, src.file, null, 'syft');
    stats.edgesAdded++;
  }
  return stats;
}

// ---------- scan + CycloneDX ----------

function permalinker(repoUrl, sha) {
  const u = new URL(repoUrl);
  const base = u.origin + u.pathname.replace(/\.git$/, '').replace(/\/$/, '');
  const p = (f) => f.split('/').map(enc).join('/');
  const h = u.hostname;
  if (h === 'github.com') return { file: (f, l) => `${base}/blob/${sha}/${p(f)}${l ? '#L' + l : ''}`, commit: `${base}/commit/${sha}` };
  if (h === 'gitlab.com' || h.startsWith('gitlab.')) return { file: (f, l) => `${base}/-/blob/${sha}/${p(f)}${l ? '#L' + l : ''}`, commit: `${base}/-/commit/${sha}` };
  if (h === 'bitbucket.org') return { file: (f, l) => `${base}/src/${sha}/${p(f)}${l ? '#lines-' + l : ''}`, commit: `${base}/commits/${sha}` };
  if (h === 'codeberg.org') return { file: (f, l) => `${base}/src/commit/${sha}/${p(f)}${l ? '#L' + l : ''}`, commit: `${base}/commit/${sha}` };
  return { file: () => null, commit: null };
}

function scan(dir, repoUrl, sha, syft) {
  const cache = new Map();
  const links = permalinker(repoUrl, sha);
  const files = walk(dir);
  const fileSet = new Set(files);
  const ctx = {
    exists: (f) => fileSet.has(f),
    files: fileSet,
    lineOf(f, needle) { const i = ctx.read(f).split('\n').findIndex((l) => l.includes(needle)); return i >= 0 ? i + 1 : null; },
    read(f) {
      if (!cache.has(f)) {
        const full = path.join(dir, f);
        if (fs.statSync(full).size > MAX_FILE) throw new Error('file larger than 50MB');
        cache.set(f, fs.readFileSync(full, 'utf8'));
      }
      return cache.get(f);
    },
    lineText(f, l) {
      const key = '\0lines:' + f;
      if (!cache.has(key)) cache.set(key, ctx.read(f).split('\n'));
      const t = cache.get(key)[l - 1];
      return t === undefined ? null : t.trim().slice(0, 300);
    },
    permalink: (f, l) => links.file(f, l),
  };
  const g = new Graph(ctx);
  const repoName = new URL(repoUrl).pathname.replace(/^\/|\.git$/g, '');
  const repoRef = 'repo:' + repoName + '@' + sha;
  const manifests = [], unsupported = [], errors = [];

  const npmLockDirs = new Set(files.filter((f) => NPM_LOCKS.includes(path.posix.basename(f))).map((f) => path.posix.dirname(f)));
  const underNpmLock = (d) => { for (;;) { if (npmLockDirs.has(d)) return true; if (d === '.' || d === '') return false; d = path.posix.dirname(d); } };

  for (const f of files) {
    const b = path.posix.basename(f);
    if (UNSUPPORTED.has(b) || /\.(csproj|fsproj|vbproj)$/.test(b)) unsupported.push(f);
    const kind = detect(f);
    if (!kind) continue;
    if (kind === 'package-json' && underNpmLock(path.posix.dirname(f))) continue; // covered by a lockfile
    try {
      const root = PARSERS[kind](g, f, ctx.read(f), ctx);
      manifests.push({ file: f, type: kind, root, permalink: ctx.permalink(f, null) });
    } catch (e) {
      errors.push({ file: f, error: String(e.message || e) });
    }
  }

  let syftInfo = { used: false };
  if (syft && syft.json) {
    try { syftInfo = { used: true, version: (syft.json.descriptor || {}).version, ...mergeSyft(g, ctx, syft.json) }; }
    catch (e) { syftInfo = { used: false, error: 'could not merge syft output: ' + e.message }; }
  } else if (syft) syftInfo = { used: false, error: syft.error };

  const components = [...g.components.values()];
  const hasParent = new Set(g.edges.map((e) => e.to));
  const orphans = components.filter((c) => c.kind !== 'manifest' && !hasParent.has(c.ref)).length;

  return {
    repo: { url: repoUrl, name: repoName, commit: sha, ref: repoRef, commitUrl: links.commit },
    scannedAt: new Date().toISOString(),
    filesScanned: files.length,
    manifests, unsupported, errors,
    syft: syftInfo,
    stats: { lineProof: components.filter((c) => c.kind !== 'manifest' && c.evidence.some((e) => e.line)).length, fileProofOnly: components.filter((c) => c.kind !== 'manifest' && !c.evidence.some((e) => e.line)).length, components: components.filter((c) => c.kind !== 'manifest').length, edges: g.edges.length, unresolved: components.filter((c) => c.kind !== 'manifest' && !c.version).length, withoutProvenParent: orphans },
    components, edges: g.edges,
    cyclonedx: toCycloneDX(repoName, repoUrl, sha, repoRef, components, g.edges, manifests, syftInfo),
  };
}

function toCycloneDX(repoName, repoUrl, sha, repoRef, components, edges, manifests, syftInfo) {
  const deps = new Map([[repoRef, new Set(manifests.map((m) => m.root))]]);
  for (const c of components) deps.set(c.ref, deps.get(c.ref) || new Set());
  for (const e of edges) deps.get(e.from).add(e.to);
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: 'urn:uuid:' + crypto.randomUUID(),
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: 'application', name: 'kestral-sbom', version: '0.1.0' }, ...(syftInfo && syftInfo.used ? [{ type: 'application', author: 'anchore', name: 'syft', version: syftInfo.version }] : [])] },
      component: { type: 'application', 'bom-ref': repoRef, name: repoName, version: sha, externalReferences: [{ type: 'vcs', url: repoUrl }] },
    },
    components: components.map((c) => {
      const o = { type: c.kind === 'manifest' ? 'application' : 'library', 'bom-ref': c.ref, name: c.name };
      if (c.version) o.version = c.version;
      if (c.purl) o.purl = c.purl;
      if (c.kind !== 'manifest') o.scope = c.scope;
      if (c.hashes.length) o.hashes = c.hashes;
      if (c.licenses.length) o.licenses = c.licenses.map((l) => ({ license: { name: String(l) } }));
      o.evidence = { occurrences: c.evidence.map((e) => (e.line ? { location: e.file, line: e.line } : { location: e.file })) };
      const props = [{ name: 'kestral:ecosystem', value: c.ecosystem }, { name: 'kestral:kind', value: c.kind }, { name: 'kestral:sources', value: c.sources.join(',') }, { name: 'kestral:proof', value: c.evidence.some((e) => e.line) ? 'line' : 'file' }];
      if (c.range) props.push({ name: 'kestral:declared-range', value: c.range });
      for (const p of c.properties || []) props.push({ name: 'kestral:' + p.name, value: p.value });
      o.properties = props;
      return o;
    }),
    dependencies: [...deps].map(([ref, s]) => ({ ref, dependsOn: [...s] })),
  };
}

module.exports = { scan, SKIP_DIRS };
