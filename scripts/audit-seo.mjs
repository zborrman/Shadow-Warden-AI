#!/usr/bin/env node
// Technical-SEO audit of the BUILT site, for /seo-implement (.claude/commands/).
// Zero dependencies; prints JSON.
//
// Why built HTML and not source: in Astro the title, description, canonical,
// OpenGraph and JSON-LD come from BaseLayout props, so a source scan reports
// every page as missing them. The built HTML is what a crawler receives.
//
// Usage: node scripts/audit-seo.mjs [distDir=site/dist] [publicDir=site/public]
import fs from 'node:fs';
import path from 'node:path';

const DIST = path.resolve(process.argv[2] || 'site/dist');
const PUB = path.resolve(process.argv[3] || 'site/public');
if (!fs.existsSync(DIST)) {
  console.error(`No build at ${DIST}. Run: cd site && npm run build`);
  process.exit(2);
}

const pages = [];
(function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full);
    else if (e.name.endsWith('.html')) pages.push(full);
  }
})(DIST);

const attr = (tag, name) => (tag.match(new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, 'i')) || [])[1];
const metaContent = (html, key, value) => {
  for (const tag of html.match(/<meta\b[^>]*>/gi) || []) if ((attr(tag, key) || '').toLowerCase() === value) return attr(tag, 'content') ?? '';
  return null;
};

const issues = [];
let jsonLdPages = 0;
for (const file of pages) {
  const rel = '/' + path.relative(DIST, file).split(path.sep).join('/').replace(/index\.html$/, '').replace(/\.html$/, '');
  const html = fs.readFileSync(file, 'utf8');
  const missing = [], warnings = [];
  const redirect = /<meta[^>]+http-equiv=["']refresh["']/i.test(html);
  if (redirect) continue; // redirect stubs carry no content to rank
  const noindex = /<meta[^>]+name=["']robots["'][^>]+noindex/i.test(html);

  const title = (html.match(/<title>([^<]*)<\/title>/i) || [])[1]?.trim();
  const desc = metaContent(html, 'name', 'description');
  const canonical = ((html.match(/<link\b[^>]*rel=["']canonical["'][^>]*>/i) || [])[0] || '');
  if (!title) missing.push('title'); else if (title.length > 65) warnings.push(`title ${title.length} chars (> 65)`);
  if (desc == null) missing.push('meta description');
  else if (desc.length < 70 || desc.length > 170) warnings.push(`description ${desc.length} chars (aim 70-170)`);
  if (!canonical) missing.push('canonical');
  if (metaContent(html, 'property', 'og:title') == null) missing.push('og:title');
  if (metaContent(html, 'property', 'og:image') == null) missing.push('og:image');

  const body = html.replace(/<script\b[\s\S]*?<\/script>/gi, '');
  const h1 = (body.match(/<h1[\s>]/gi) || []).length;
  if (h1 === 0) warnings.push('no <h1>'); else if (h1 > 1) warnings.push(`${h1} <h1> elements`);
  const noAlt = (body.match(/<img\b[^>]*>/gi) || []).filter(t => !/\balt\s*=/.test(t)).length;
  if (noAlt) warnings.push(`${noAlt} <img> without alt`);

  const blocks = [...html.matchAll(/<script[^>]+application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]);
  if (blocks.length) jsonLdPages++;
  for (const b of blocks) { try { JSON.parse(b); } catch { missing.push('valid JSON-LD (a block does not parse)'); } }
  if (!blocks.length) missing.push('JSON-LD');

  if (missing.length || warnings.length) issues.push({ page: rel, noindex, missing, warnings });
}

const has = f => fs.existsSync(path.join(PUB, f)) || fs.existsSync(path.join(DIST, f));
console.log(JSON.stringify({
  dist: path.relative(process.cwd(), DIST),
  globalArtifacts: {
    robotsTxt: has('robots.txt'),
    sitemap: has('sitemap-index.xml') || has('sitemap.xml') || has('sitemap-0.xml'),
    llmsTxt: has('llms.txt'),
    llmsFullTxt: has('llms-full.txt'),
    webManifest: has('manifest.json') || has('site.webmanifest') || has('manifest.webmanifest'),
    indexNowKey: fs.existsSync(PUB) && fs.readdirSync(PUB).some(f => /^[a-f0-9]{32}\.txt$/i.test(f)),
  },
  pagesChecked: pages.length,
  pagesWithJsonLd: jsonLdPages,
  issueCount: issues.length,
  issues,
}, null, 2));
