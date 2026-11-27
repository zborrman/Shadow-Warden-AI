#!/usr/bin/env node
// Zero-dependency architecture snapshot for /arch-audit (.claude/commands/).
// Prints JSON so the audit reads one report instead of the whole tree.
//
// Adapted to Shadow Warden (2026-11-27). The generic version missed the Python
// engine entirely, looked for llms.txt only at the repo root (ours is
// site/public/llms.txt), and let vendored skill copies, mutmut output and the
// generated landing/ build fill the "largest files" list. This version:
//   - reads only files git tracks (falls back to a directory walk outside a
//     checkout), so local build output never counts;
//   - skips generated and vendored trees (landing/, .agents/, skills/, mutants/);
//   - counts Python and resolves `from warden.x import y` and relative imports,
//     top-level imports only: a lazy import inside a function is how this
//     codebase breaks cycles on purpose, so it is not a cycle;
//   - finds llms.txt / robots.txt / sitemaps wherever they live (and the
//     @astrojs/sitemap integration), and reads robots.txt for AI-crawler rules;
//   - reports source vs test files and god files (> 300 lines) per area.
// Usage: node scripts/analyze-arch.mjs [--top N]
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

const ROOT = process.cwd();
const topArg = process.argv.indexOf('--top');
const TOP = topArg > -1 ? Number(process.argv[topArg + 1]) || 15 : 15;
const GOD_LINES = 300;
const NUL = String.fromCharCode(0);
const IGNORE = new Set([
  'node_modules', '.git', '.next', 'dist', 'build', '.astro', '.claude', 'coverage', '__pycache__',
  '.venv', 'venv', '.mypy_cache', '.ruff_cache', '.pytest_cache', '.vercel', '.wrangler',
  // generated or vendored: not this project's code
  'landing', '.agents', 'skills', 'mutants', 'strix_runs',
]);
const CODE_EXT = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.vue', '.svelte', '.css', '.scss', '.py', '.astro']);
const AI_FILES = new Set(['llms.txt', 'llms-full.txt', 'robots.txt', 'sitemap.xml', 'sitemap-index.xml']);
const AI_BOTS = ['GPTBot', 'ClaudeBot', 'PerplexityBot', 'Google-Extended', 'CCBot'];

const files = [];
const importsMap = new Map();
const aiFound = {};
const add = (k, v) => { (aiFound[k] ??= []).push(v); };
const posix = p => p.split(path.sep).join('/');

function pyImports(content) {
  const out = [];
  for (const line of content.split('\n')) {
    let m = line.match(/^from\s+(\.*[\w.]*)\s+import\s+/);
    if (m) { out.push(m[1]); continue; }
    m = line.match(/^import\s+([\w.]+)/);
    if (m) out.push(m[1]);
  }
  return out;
}

function jsImports(content) {
  const re = /(?:import|export)\s+(?:[^'"]*?\s+from\s+)?['"](.+?)['"]|require\(['"](.+?)['"]\)/g;
  return [...content.matchAll(re)].map(m => m[1] || m[2]).filter(Boolean);
}

const TEST_RE = [/(^|\/)(tests?|e2e|__tests__)\//, /\.(test|spec)\.[jt]sx?$/, /(^|\/)test_[^/]+\.py$/];

function visit(rel) {
  if (rel.split('/').some(seg => IGNORE.has(seg))) return;
  const name = rel.split('/').pop();
  const full = path.join(ROOT, rel);
  if (AI_FILES.has(name)) add(name, rel);
  if (/^robots\.(ts|js)$/.test(name) || /^sitemap(\.xml)?\.(ts|js|astro)$/.test(name)) add('generated', rel);
  if (/^astro\.config\.(mjs|ts|js)$/.test(name)) {
    try { if (/sitemap\(/.test(fs.readFileSync(full, 'utf8'))) add('generated', `${rel} (@astrojs/sitemap)`); } catch { /* unreadable */ }
  }
  const ext = path.extname(name);
  if (!CODE_EXT.has(ext)) return;
  let content;
  try { content = fs.readFileSync(full, 'utf8'); } catch { return; }
  files.push({ path: rel, lines: content.split('\n').length, ext, test: TEST_RE.some(r => r.test(rel)) });
  importsMap.set(rel, ext === '.py' ? pyImports(content) : jsImports(content));
}

function walk(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (IGNORE.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full); else visit(posix(path.relative(ROOT, full)));
  }
}

function tracked() {
  try {
    return execSync('git ls-files -z', { cwd: ROOT, maxBuffer: 1 << 28 }).toString('utf8').split(NUL).filter(Boolean);
  } catch { return null; }
}

const gitFiles = tracked();
if (gitFiles) gitFiles.forEach(visit); else walk(ROOT);

function resolveLocal(fromFile, spec) {
  if (fromFile.endsWith('.py')) {
    let mod;
    if (spec.startsWith('.')) {
      const dots = spec.match(/^\.+/)[0].length;
      const parts = path.posix.dirname(fromFile).split('/');
      mod = [...parts.slice(0, parts.length - (dots - 1)), ...spec.slice(dots).split('.').filter(Boolean)].join('/');
    } else {
      mod = spec.split('.').join('/');
    }
    return [`${mod}.py`, `${mod}/__init__.py`].find(c => importsMap.has(c)) || null;
  }
  if (!spec.startsWith('.')) return null;
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), spec));
  return ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '/index.ts', '/index.tsx', '/index.js']
    .map(e => base + e).find(c => importsMap.has(c)) || null;
}

const cycles = [];
const seenCycle = new Set();
const visited = new Set();
const onStack = new Set();
function dfs(node, trail) {
  if (onStack.has(node)) {
    const cyc = [...trail.slice(trail.indexOf(node)), node];
    const key = cyc.slice(0, -1).sort().join('|');
    if (!seenCycle.has(key)) { seenCycle.add(key); cycles.push(cyc); }
    return;
  }
  if (visited.has(node)) return;
  visited.add(node); onStack.add(node);
  for (const spec of importsMap.get(node) || []) {
    const t = resolveLocal(node, spec);
    if (t) dfs(t, [...trail, node]);
  }
  onStack.delete(node);
}
for (const f of importsMap.keys()) dfs(f, []);

// How many local imports resolved, per language: a resolver that silently
// resolves nothing would also report zero cycles.
const resolved = { py: 0, js: 0 };
for (const [f, specs] of importsMap) for (const s of specs) if (resolveLocal(f, s)) resolved[f.endsWith('.py') ? 'py' : 'js']++;

const src = files.filter(f => !f.test && f.ext !== '.css' && f.ext !== '.scss');
const byArea = {};
for (const f of src) {
  const a = (byArea[f.path.split('/')[0]] ??= { files: 0, lines: 0, godFiles: 0 });
  a.files++; a.lines += f.lines; if (f.lines > GOD_LINES) a.godFiles++;
}

const robots = (aiFound['robots.txt'] || []).map(p => {
  const txt = fs.readFileSync(path.join(ROOT, p), 'utf8');
  return {
    path: p,
    explicitAiBots: AI_BOTS.filter(b => new RegExp(`user-agent:\\s*${b}`, 'i').test(txt)),
    wildcardRule: /user-agent:\s*\*/i.test(txt),
  };
});

const pkg = (() => { try { return JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')); } catch { return null; } })();

console.log(JSON.stringify({
  summary: {
    source: gitFiles ? 'git ls-files' : 'directory walk',
    sourceFiles: src.length,
    sourceLines: src.reduce((a, f) => a + f.lines, 0),
    testFiles: files.filter(f => f.test).length,
    godFiles: src.filter(f => f.lines > GOD_LINES).length,
    rootDependencies: pkg ? Object.keys(pkg.dependencies || {}).length : 0,
  },
  byArea: Object.fromEntries(Object.entries(byArea).sort((a, b) => b[1].lines - a[1].lines)),
  largestFiles: [...src].sort((a, b) => b.lines - a.lines).slice(0, TOP).map(({ path: p, lines }) => ({ path: p, lines })),
  circularDependencies: { count: cycles.length, resolvedLocalImports: resolved, examples: cycles.slice(0, 20) },
  aiReadiness: {
    llmsTxt: aiFound['llms.txt'] || [],
    llmsFullTxt: aiFound['llms-full.txt'] || [],
    robotsTxt: robots,
    sitemaps: [...(aiFound['sitemap.xml'] || []), ...(aiFound['sitemap-index.xml'] || []), ...(aiFound['generated'] || [])],
  },
}, null, 2));
