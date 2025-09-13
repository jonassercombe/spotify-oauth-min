// api/watch/cron-sync-all.js
export const config = { runtime: "nodejs" };

// --- helpers ---
function need(n) { const v = process.env[n]; if (!v) throw new Error(`missing env: ${n}`); return v; }
async function sb(path, init = {}) {
  const url = need("SUPABASE_URL") + path;
  const headers = {
    apikey: need("SUPABASE_SERVICE_ROLE_KEY"),
    Authorization: `Bearer ${need("SUPABASE_SERVICE_ROLE_KEY")}`,
    "Content-Type": "application/json",
    ...(init.headers || {}),
  };
  return fetch(url, { ...init, headers });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export default async function handler(req, res) {
  // Absicherung für Vercel Cron
  const want = process.env.CRON_SECRET;
  const got = req.headers?.authorization || "";
  if (want && got !== `Bearer ${want}`) {
    return res.status(401).json({ error: "unauthorized_cron" });
  }

  try {
    const base = process.env.PUBLIC_BASE_URL || `https://${process.env.VERCEL_URL}`;
    if (!base) throw new Error("missing PUBLIC_BASE_URL/VERCEL_URL");

    // optionale Tuning-Parameter
    const limit = encodeURIComponent(req.query.limit || "50");         // Playlists pro Connection pro Run
    const concurrency = encodeURIComponent(req.query.concurrency || "3");

    // alle Connections ziehen
    const r = await sb(`/rest/v1/spotify_connections?select=id`);
    if (!r.ok) return res.status(500).json({ error: "supabase_select_failed", body: await r.text() });
    const conns = await r.json();

    let dispatched_ok = 0, dispatched_fail = 0;
    for (const c of conns) {
      const url = `${base}/api/watch/sync-needed?limit=${limit}&concurrency=${concurrency}`;
      const resp = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-app-secret": process.env.APP_WEBHOOK_SECRET || ""
        },
        body: JSON.stringify({ connection_id: c.id })
      });
      resp.ok ? dispatched_ok++ : dispatched_fail++;
      await sleep(80);
    }

    return res.status(200).json({
      ok: true,
      connections: conns.length,
      dispatched_ok,
      dispatched_fail
    });
  } catch (e) {
    return res.status(500).json({ error: "server_error", message: String(e) });
  }
}
