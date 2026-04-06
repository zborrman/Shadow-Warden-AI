/**
 * Shadow Warden AI — Installer Worker
 * ─────────────────────────────────────
 * Serves install.sh from GitHub, counts installs per country/plan,
 * and rate-limits abuse.
 *
 * Routes handled:
 *   GET  /install        → install.sh (plain text)
 *   GET  /install.sh     → same
 *   GET  /stats          → JSON install statistics (protected by STATS_TOKEN)
 *   GET  /health         → {"ok": true}
 *
 * KV schema (INSTALL_STATS namespace):
 *   stats:total          → number   — lifetime installs
 *   stats:trial          → number   — trial installs
 *   stats:paid           → number   — paid installs
 *   stats:country:{CC}   → number   — per-country count
 *   stats:date:{YYYY-MM-DD} → number — daily count (auto-expires 90d)
 *   ratelimit:{ip}       → "1"      — 10 installs/hour per IP (TTL 3600s)
 */

const GITHUB_RAW =
  "https://raw.githubusercontent.com/zborrman/Shadow-Warden-AI/main/scripts/install.sh";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
};

// ── Entry point ────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url  = new URL(request.url);
    const path = url.pathname.replace(/\/$/, "") || "/";

    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });

    if (path === "/health") {
      return json({ ok: true, version: env.SCRIPT_VERSION || "2.9" });
    }

    if (path === "/stats") {
      return handleStats(request, env);
    }

    if (path === "/install" || path === "/install.sh") {
      return handleInstall(request, env, ctx, url);
    }

    return new Response("Not found.\n\nInstall Shadow Warden AI:\n  curl -sSL https://get.shadowwarden.ai/install | bash -s -- --trial\n", {
      status: 404,
      headers: { "Content-Type": "text/plain" },
    });
  },
};

// ── Install handler ────────────────────────────────────────────────────────────

async function handleInstall(request, env, ctx, url) {
  const ip      = request.headers.get("CF-Connecting-IP") || "unknown";
  const country = request.headers.get("CF-IPCountry")     || "XX";
  const plan    = url.searchParams.get("plan") || detectPlan(url);

  // Rate-limit: 10 downloads/hour per IP
  const rlKey = `ratelimit:${ip}`;
  if (env.INSTALL_STATS) {
    const hits = await env.INSTALL_STATS.get(rlKey);
    if (hits && parseInt(hits) >= 10) {
      return new Response("Rate limit exceeded. Max 10 installs/hour per IP.\n", {
        status: 429,
        headers: { "Retry-After": "3600", "Content-Type": "text/plain" },
      });
    }
  }

  // Fetch script from GitHub (cache 5 minutes at edge)
  const scriptResp = await fetch(GITHUB_RAW, {
    cf: { cacheTtl: 300, cacheEverything: true },
  });

  if (!scriptResp.ok) {
    return new Response(
      `Failed to fetch installer (GitHub returned ${scriptResp.status}).\n` +
      `Try directly: curl -sSL ${GITHUB_RAW} | bash\n`,
      { status: 502, headers: { "Content-Type": "text/plain" } }
    );
  }

  const script = await scriptResp.text();

  // Record stats + rate-limit counter asynchronously (don't block response)
  ctx.waitUntil(recordInstall(env, ip, country, plan, rlKey));

  return new Response(script, {
    headers: {
      "Content-Type":        "text/x-shellscript; charset=utf-8",
      "Content-Disposition": "inline; filename=install.sh",
      "Cache-Control":       "no-store",   // client must always get latest
      "X-Script-Version":    env.SCRIPT_VERSION || "2.9",
      "X-Install-Country":   country,
      ...CORS,
    },
  });
}

// ── Stats recording ────────────────────────────────────────────────────────────

async function recordInstall(env, ip, country, plan, rlKey) {
  if (!env.INSTALL_STATS) return;

  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD

  const ops = [
    incrKV(env, "stats:total"),
    incrKV(env, `stats:country:${country}`),
    incrKV(env, `stats:date:${today}`, 90 * 24 * 3600),   // expire after 90 days
  ];

  if (plan === "trial") ops.push(incrKV(env, "stats:trial"));
  if (plan === "paid")  ops.push(incrKV(env, "stats:paid"));

  // Rate-limit counter: increment with 1-hour TTL
  ops.push(
    env.INSTALL_STATS.get(rlKey).then(async (val) => {
      const n = val ? parseInt(val) + 1 : 1;
      await env.INSTALL_STATS.put(rlKey, String(n), { expirationTtl: 3600 });
    })
  );

  await Promise.allSettled(ops);
}

async function incrKV(env, key, ttl = null) {
  const val = await env.INSTALL_STATS.get(key);
  const n   = val ? parseInt(val) + 1 : 1;
  const opts = ttl ? { expirationTtl: ttl } : {};
  await env.INSTALL_STATS.put(key, String(n), opts);
}

// ── Stats endpoint ─────────────────────────────────────────────────────────────

async function handleStats(request, env) {
  // Protect with a token from env secret (set via: wrangler secret put STATS_TOKEN)
  const token = request.headers.get("X-Stats-Token") || "";
  if (env.STATS_TOKEN && token !== env.STATS_TOKEN) {
    return new Response("Unauthorized", { status: 401 });
  }

  if (!env.INSTALL_STATS) {
    return json({ error: "KV not configured" }, 503);
  }

  const [total, trial, paid] = await Promise.all([
    env.INSTALL_STATS.get("stats:total"),
    env.INSTALL_STATS.get("stats:trial"),
    env.INSTALL_STATS.get("stats:paid"),
  ]);

  // List country stats
  const countryList = await env.INSTALL_STATS.list({ prefix: "stats:country:" });
  const countries   = {};
  await Promise.all(
    countryList.keys.map(async ({ name }) => {
      const cc  = name.replace("stats:country:", "");
      const val = await env.INSTALL_STATS.get(name);
      countries[cc] = parseInt(val || "0");
    })
  );

  // Last 7 days
  const dates = {};
  for (let i = 0; i < 7; i++) {
    const d   = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    const val = await env.INSTALL_STATS.get(`stats:date:${d}`);
    if (val) dates[d] = parseInt(val);
  }

  return json({
    total:     parseInt(total  || "0"),
    trial:     parseInt(trial  || "0"),
    paid:      parseInt(paid   || "0"),
    countries: Object.entries(countries)
                .sort(([, a], [, b]) => b - a)
                .slice(0, 20)
                .reduce((o, [k, v]) => ({ ...o, [k]: v }), {}),
    last_7_days: dates,
    version:   env.SCRIPT_VERSION || "2.9",
  });
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function detectPlan(url) {
  // install.sh sends ?plan=trial or ?plan=paid after activation
  const p = url.searchParams.get("plan");
  if (p === "trial" || p === "paid") return p;
  return "unknown";
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}
