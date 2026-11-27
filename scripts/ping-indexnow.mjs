#!/usr/bin/env node
// Tell IndexNow engines (Bing, Yandex, Seznam, Naver…) which URLs changed, so they
// recrawl without waiting. One POST to api.indexnow.org fans out to all of them.
//
//   node scripts/ping-indexnow.mjs [--dry-run] [--from-sitemap | /path ...]
//
// Key: INDEXNOW_KEY, or the single site/public/<32 hex>.txt file (the protocol
// publishes the key at https://<host>/<key>.txt, so it is not a secret).
// Host: SITE_HOST, default www.shadow-warden-ai.com.
// --from-sitemap submits every URL in site/dist/sitemap-0.xml (run a build first).
// Sending is an outward action: use --dry-run until the owner has agreed.
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const dry = args.includes('--dry-run');
const host = process.env.SITE_HOST || 'www.shadow-warden-ai.com';
const pub = path.resolve('site/public');
const key = process.env.INDEXNOW_KEY
  || (fs.existsSync(pub) ? fs.readdirSync(pub).find(f => /^[a-f0-9]{32}\.txt$/i.test(f))?.slice(0, -4) : undefined);

let urls;
if (args.includes('--from-sitemap')) {
  const map = path.resolve('site/dist/sitemap-0.xml');
  if (!fs.existsSync(map)) { console.error('No site/dist/sitemap-0.xml — build the site first.'); process.exit(2); }
  urls = [...fs.readFileSync(map, 'utf8').matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => m[1].replace(/^https?:\/\/[^/]+/, `https://${host}`));
} else {
  urls = args.filter(a => !a.startsWith('--')).map(p => `https://${host}${p.startsWith('/') ? p : `/${p}`}`);
}

if (!key || !/^[a-f0-9]{32}$/i.test(key) || urls.length === 0) {
  console.error('Usage: node scripts/ping-indexnow.mjs [--dry-run] [--from-sitemap | /path ...]\n'
    + 'Needs INDEXNOW_KEY or a site/public/<32-hex>.txt key file containing the key.');
  process.exit(1);
}
if (urls.length > 10000) { console.error(`IndexNow takes at most 10,000 URLs per request (${urls.length}).`); process.exit(1); }

const body = { host, key, keyLocation: `https://${host}/${key}.txt`, urlList: urls };
if (dry) { console.log(JSON.stringify({ dryRun: true, host, keyLocation: body.keyLocation, urls: urls.length, sample: urls.slice(0, 5) }, null, 2)); process.exit(0); }

const res = await fetch('https://api.indexnow.org/indexnow', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json; charset=utf-8' },
  body: JSON.stringify(body),
});
// 200 accepted, 202 accepted (key pending verification); 403 key not found at keyLocation; 422 host/URL mismatch.
console.log(`IndexNow: HTTP ${res.status} for ${urls.length} URL(s)`);
if (res.status !== 200 && res.status !== 202) process.exit(1);
