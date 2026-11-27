#!/usr/bin/env node
// AI-search readiness audit of the BUILT site, for /geo-implement.
// Zero dependencies; prints JSON.
//
// Most AI crawlers do not run JavaScript, so "is the content there without JS"
// is measured on the built HTML (text inside <main> with scripts and styles
// stripped), not guessed from 'use client'. Also: robots.txt rules for AI
// search bots vs training bots, llms.txt shape (llmstxt.org), llms-full.txt,
// entity grounding (sameAs), citable structure (tables, FAQPage).
//
// Usage: node scripts/audit-ai-search.mjs [distDir=site/dist] [publicDir=site/public]
import fs from 'node:fs';
import path from 'node:path';

const DIST = path.resolve(process.argv[2] || 'site/dist');
const PUB = path.resolve(process.argv[3] || 'site/public');
if (!fs.existsSync(DIST)) {
  console.error(`No build at ${DIST}. Run: cd site && npm run build`);
  process.exit(2);
}
const read = f => { try { return fs.readFileSync(f, 'utf8'); } catch { return null; } };
const pick = name => read(path.join(PUB, name)) ?? read(path.join(DIST, name));

// Bots that send readers (search / answer engines) vs bots that collect training data.
const SEARCH_BOTS = ['OAI-SearchBot', 'ChatGPT-User', 'PerplexityBot', 'Claude-SearchBot', 'Claude-User', 'Applebot', 'Bingbot', 'Googlebot'];
const TRAINING_BOTS = ['GPTBot', 'ClaudeBot', 'Google-Extended', 'CCBot', 'Applebot-Extended'];

function groups(robots) {
  const out = []; let cur = null;
  for (const raw of robots.split(/\r?\n/)) {
    const line = raw.replace(/#.*/, '').trim();
    const m = line.match(/^([\w-]+)\s*:\s*(.*)$/); if (!m) continue;
    const [, k, v] = m;
    if (/^user-agent$/i.test(k)) { if (!cur || cur.rules.length) out.push(cur = { agents: [], rules: [] }); cur.agents.push(v.toLowerCase()); }
    else if (cur && /^(allow|disallow)$/i.test(k)) cur.rules.push([k.toLowerCase(), v]);
  }
  return out;
}
function blockedAtRoot(gs, bot) {
  const g = gs.find(x => x.agents.includes(bot.toLowerCase())) || gs.find(x => x.agents.includes('*'));
  return !!g && g.rules.some(([k, v]) => k === 'disallow' && v === '/') && !g.rules.some(([k, v]) => k === 'allow' && v === '/');
}

const robots = pick('robots.txt') || '';
const gs = groups(robots);
const llms = pick('llms.txt');
const llmsIssues = [];
if (!llms) llmsIssues.push('llms.txt missing');
else {
  if (!/^#\s+\S/m.test(llms)) llmsIssues.push('no H1 title');
  if (!/^>\s+\S/m.test(llms)) llmsIssues.push('no blockquote summary');
  if (!/^##\s+\S/m.test(llms)) llmsIssues.push('no H2 sections');
  if (!/\]\(https?:\/\/[^)\s]+\)/.test(llms)) llmsIssues.push('no absolute links');
}

const pages = [];
(function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full); else if (e.name.endsWith('.html')) pages.push(full);
  }
})(DIST);

const thin = [], noMain = [];
let tables = 0, sameAs = false, faq = false, sameAsLinks = new Set();
for (const file of pages) {
  const rel = '/' + path.relative(DIST, file).split(path.sep).join('/').replace(/index\.html$/, '');
  const html = fs.readFileSync(file, 'utf8');
  if (/http-equiv=["']refresh["']/i.test(html)) continue;
  for (const m of html.matchAll(/"sameAs"\s*:\s*(\[[^\]]*\]|"[^"]*")/g)) { sameAs = true; for (const u of m[1].match(/https?:\/\/[^"\s]+/g) || []) sameAsLinks.add(u); }
  if (/"@type"\s*:\s*"FAQPage"/.test(html)) faq = true;
  if (/<table[\s>]/i.test(html)) tables++;
  const main = (html.match(/<main\b[\s\S]*?<\/main>/i) || [])[0];
  if (!main) { noMain.push(rel); continue; }
  const text = main.replace(/<(script|style|template)\b[\s\S]*?<\/\1>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  if (text.length < 400) thin.push({ page: rel, chars: text.length });
}

console.log(JSON.stringify({
  robotsPolicy: {
    explicitlyNamed: [...SEARCH_BOTS, ...TRAINING_BOTS].filter(b => gs.some(g => g.agents.includes(b.toLowerCase()))),
    searchBotsBlocked: SEARCH_BOTS.filter(b => blockedAtRoot(gs, b)),
    trainingBotsBlocked: TRAINING_BOTS.filter(b => blockedAtRoot(gs, b)),
    sitemapDeclared: /^sitemap\s*:/im.test(robots),
  },
  llmsTxt: { exists: !!llms, issues: llmsIssues, fullVersion: !!pick('llms-full.txt') },
  noJsContent: { pagesChecked: pages.length, withoutMain: noMain, thinWithoutJs: thin },
  citationReadiness: { entitySameAs: sameAs, sameAsLinks: [...sameAsLinks], faqPageSchema: faq, pagesWithTables: tables },
}, null, 2));
