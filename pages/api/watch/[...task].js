// api/[...task].js
export const config = { runtime: "nodejs" };

/* -------------------- utils -------------------- */
function need(n) {
  const v = process.env[n];
  if (!v) throw new Error(`missing env: ${n}`);
  return v;
}
async function readJsonBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  return new Promise((resolve) => {
    let d = "";
    req.on("data", (c) => (d += c));
    req.on("end", () => {
      try { resolve(JSON.parse(d || "{}")); } catch { resolve({}); }
    });
  });
}
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

/* -------------------- auth helpers -------------------- */
function checkCronAuth(req) {
  const want = process.env.CRON_SECRET;
  const got = req.headers?.authorization || "";
  if (want && got !== `Bearer ${want}`) return false;
  return true;
}
function checkAppSecret(req) {
  const want = process.env.APP_WEBHOOK_SECRET;
  const got = req.headers["x-app-secret"];
  if (want && got !== want) return false;
  return true;
}

/* -------------------- spotify token -------------------- */
import crypto from "crypto";
function decryptToken(b64) {
  const hex = need("ENC_SECRET");
  if (hex.length < 64) throw new Error("ENC_SECRET must be 32-byte hex (64 chars)");
  const key = Buffer.from(hex, "hex");
  const raw = Buffer.from(String(b64), "base64");
  const iv = raw.subarray(0, 12), tag = raw.subarray(12, 28), ct = raw.subarray(28);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}
async function getAccessToken(connection_id) {
  const r = await sb(`/rest/v1/spotify_connections?select=refresh_token_enc&limit=1&id=eq.${encodeURIComponent(connection_id)}`);
  if (!r.ok) throw new Error(`supabase select connection failed: ${r.status} ${await r.text()}`);
  const a = await r.json();
  if (!a?.[0]?.refresh_token_enc) throw new Error("connection_not_found_or_no_token");
  const refresh_token = decryptToken(a[0].refresh_token_enc);

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token,
    client_id: need("SPOTIFY_CLIENT_ID"),
    client_secret: need("SPOTIFY_CLIENT_SECRET"),
  });
  const t = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const j = await t.json();
  if (!t.ok || !j.access_token) throw new Error(`refresh_failed ${t.status} ${JSON.stringify(j)}`);
  return j.access_token;
}

/* -------------------- RL state per connection -------------------- */
async function getCooldown(connection_id) {
  const r = await sb(`/rest/v1/connection_rl_state?select=cooldown_until&connection_id=eq.${encodeURIComponent(connection_id)}&limit=1`);
  if (!r.ok) return null;
  const a = await r.json();
  return a?.[0]?.cooldown_until ? new Date(a[0].cooldown_until) : null;
}
async function setCooldown(connection_id, untilIso) {
  await sb(`/rest/v1/connection_rl_state`, {
    method: "POST",
    headers: { Prefer: "resolution=merge-duplicates" },
    body: JSON.stringify({ connection_id, cooldown_until: untilIso })
  });
}

/* -------------------- check-updates logic -------------------- */
function backoffMs(changed) {
  // simpel & RL-freundlich: bei Änderung 5min, sonst 15min (kannst du später exponentiell machen)
  return changed ? 5 * 60 * 1000 : 15 * 60 * 1000;
}

async function runCheckUpdates({ connection_id, limit = "200", concurrency = "4" }) {
  // globaler Cooldown?
  const cd = await getCooldown(connection_id);
  if (cd && cd > new Date()) {
    return { ok: true, skipped: true, reason: "cooldown", until: cd.toISOString() };
  }

  // fällige Playlists für diesen Account
  const order = encodeURIComponent("next_check_at.asc.nullsfirst");
  const q =
    `/rest/v1/playlists?select=id,playlist_id,snapshot_id,next_check_at,last_snapshot_checked_at,error_count` +
    `&connection_id=eq.${encodeURIComponent(connection_id)}` +
    `&is_owner=is.true&is_public=is.true` +
    `&or=(next_check_at.is.null,next_check_at.lte.${encodeURIComponent(new Date().toISOString())})` +
    `&order=${order}&limit=${encodeURIComponent(limit)}`;
  const sel = await sb(q);
  if (!sel.ok) return { error: "supabase_select_failed", body: await sel.text() };
  const rows = await sel.json();
  if (rows.length === 0) return { ok: true, checked: 0, updated: 0, marked: 0 };

  const token = await getAccessToken(connection_id);
  let marked = 0, updated = 0, checked = 0, got429 = false, retryAfter = 1;

  // simple concurrency controller
  let i = 0, running = 0;
  await new Promise((resolve) => {
    const kick = () => {
      while (running < Number(concurrency) && i < rows.length && !got429) {
        const row = rows[i++]; running++;
        (async () => {
          try {
            const r = await fetch(
              `https://api.spotify.com/v1/playlists/${encodeURIComponent(row.playlist_id)}?fields=snapshot_id`,
              { headers: { Authorization: `Bearer ${token}` } }
            );
            if (r.status === 429) {
              got429 = true;
              retryAfter = Number(r.headers.get("retry-after") || "5");
            } else {
              const j = await r.json().catch(() => ({}));
              if (r.ok) {
                const current = j?.snapshot_id || null;
                const changed = current && row.snapshot_id && current !== row.snapshot_id;
                const nowIso = new Date().toISOString();
                const nextIso = new Date(Date.now() + backoffMs(changed)).toISOString();
                const patch = {
                  last_snapshot_checked_at: nowIso,
                  next_check_at: nextIso
                };
                if (current && current !== row.snapshot_id) {
                  patch.needs_sync = true; // Snapshot differiert → später syncen
                  // Snapshot NICHT sofort setzen – erst nach erfolgreichem Sync
                  marked++;
                }
                const up = await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(row.id)}`, {
                  method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify(patch)
                });
                if (up.ok) updated++;
                checked++;
              } else {
                // softer Fehler: 30min schieben
                const next = new Date(Date.now() + 30 * 60 * 1000).toISOString();
                await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(row.id)}`, {
                  method: "PATCH", headers: { Prefer: "return=minimal" },
                  body: JSON.stringify({
                    next_check_at: next,
                    last_snapshot_checked_at: new Date().toISOString(),
                    error_count: (row.error_count || 0) + 1
                  })
                });
              }
            }
            await sleep(40);
          } catch {
            const next = new Date(Date.now() + 30 * 60 * 1000).toISOString();
            await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(row.id)}`, {
              method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ next_check_at: next })
            });
          } finally {
            running--; kick();
          }
        })();
      }
      if (running === 0 && (i >= rows.length || got429)) resolve();
    };
    kick();
  });

  if (got429) {
    const until = new Date(Date.now() + (retryAfter + 0.5) * 1000).toISOString();
    await setCooldown(connection_id, until);
    return { ok: true, hit_429: true, retry_after: retryAfter, set_cooldown_until: until, checked, marked, updated };
  }
  return { ok: true, checked, marked, updated };
}

/* -------------------- sync-needed logic -------------------- */
async function runSyncNeeded({ connection_id, limit = "50", concurrency = "3" }) {
  const r = await sb(`/rest/v1/playlists?select=id&connection_id=eq.${encodeURIComponent(connection_id)}&needs_sync=is.true&limit=${encodeURIComponent(limit)}`);
  if (!r.ok) return { error: "supabase_select_failed", body: await r.text() };
  const rows = await r.json();
  if (rows.length === 0) return { ok: true, synced: 0 };

  // Existierenden Playlist-Sync-Endpoint aufrufen
  const base = process.env.PUBLIC_BASE_URL || `https://${process.env.VERCEL_URL}`;
  if (!base) throw new Error("missing PUBLIC_BASE_URL/VERCEL_URL");
  const syncUrl = `${base}/api/playlists/sync-items`;

  let synced = 0, failed = 0;

  let i = 0, running = 0;
  await new Promise((resolve) => {
    const kick = () => {
      while (running < Number(concurrency) && i < rows.length) {
        const row = rows[i++]; running++;
        (async () => {
          try {
            const resp = await fetch(syncUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json", "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
              body: JSON.stringify({ playlist_row_id: row.id })
            });
            if (resp.ok) {
              // needs_sync zurücksetzen
              await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(row.id)}`, {
                method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ needs_sync: false })
              });
              synced++;
            } else {
              failed++;
            }
            await sleep(80);
          } catch {
            failed++;
          } finally {
            running--; kick();
          }
        })();
      }
      if (running === 0 && i >= rows.length) resolve();
    };
    kick();
  });

  return { ok: true, synced, failed };
}

/* -------------------- cron orchestrators (all connections) -------------------- */
async function runCronCheckAll({ limit, concurrency }) {
  const r = await sb(`/rest/v1/spotify_connections?select=id`);
  if (!r.ok) return { error: "supabase_select_failed", body: await r.text() };
  const conns = await r.json();

  let ok = 0, fail = 0;
  for (const c of conns) {
    const out = await runCheckUpdates({ connection_id: c.id, limit, concurrency });
    out?.ok ? ok++ : fail++;
    await sleep(80);
  }
  return { ok: true, connections: conns.length, dispatched_ok: ok, dispatched_fail: fail };
}
async function runCronSyncAll({ limit, concurrency }) {
  const r = await sb(`/rest/v1/spotify_connections?select=id`);
  if (!r.ok) return { error: "supabase_select_failed", body: await r.text() };
  const conns = await r.json();

  let ok = 0, fail = 0;
  for (const c of conns) {
    const out = await runSyncNeeded({ connection_id: c.id, limit, concurrency });
    out?.ok ? ok++ : fail++;
    await sleep(80);
  }
  return { ok: true, connections: conns.length, dispatched_ok: ok, dispatched_fail: fail };
}

/* -------------------- main router -------------------- */
export default async function handler(req, res) {
  try {
    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,x-app-secret");
    if (req.method === "OPTIONS") return res.status(204).end();

    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname; // e.g. /api/watch/check-updates
    const qs = Object.fromEntries(url.searchParams.entries());

    // ---- watch/check-updates (POST, internal) ----
    if (path.endsWith("/watch/check-updates")) {
      if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });
      if (!checkAppSecret(req)) return res.status(401).json({ error: "unauthorized" });
      const body = await readJsonBody(req);
      if (!body.connection_id) return res.status(400).json({ error: "missing_connection_id" });
      const out = await runCheckUpdates({ connection_id: body.connection_id, limit: qs.limit || "200", concurrency: qs.concurrency || "4" });
      if (out.error) return res.status(500).json(out);
      return res.status(200).json(out);
    }

    // ---- watch/sync-needed (POST, internal) ----
    if (path.endsWith("/watch/sync-needed")) {
      if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });
      if (!checkAppSecret(req)) return res.status(401).json({ error: "unauthorized" });
      const body = await readJsonBody(req);
      if (!body.connection_id) return res.status(400).json({ error: "missing_connection_id" });
      const out = await runSyncNeeded({ connection_id: body.connection_id, limit: qs.limit || "50", concurrency: qs.concurrency || "3" });
      if (out.error) return res.status(500).json(out);
      return res.status(200).json(out);
    }

    // ---- watch/cron-check-all (Cron) ----
    if (path.endsWith("/watch/cron-check-all")) {
      if (!checkCronAuth(req)) return res.status(401).json({ error: "unauthorized_cron" });
      const out = await runCronCheckAll({ limit: qs.limit || "200", concurrency: qs.concurrency || "4" });
      if (out.error) return res.status(500).json(out);
      return res.status(200).json(out);
    }

    // ---- watch/cron-sync-all (Cron) ----
    if (path.endsWith("/watch/cron-sync-all")) {
      if (!checkCronAuth(req)) return res.status(401).json({ error: "unauthorized_cron" });
      const out = await runCronSyncAll({ limit: qs.limit || "50", concurrency: qs.concurrency || "3" });
      if (out.error) return res.status(500).json(out);
      return res.status(200).json(out);
    }

    // ---- watch/cron-all (kombiniert: check + sync) ----
    if (path.endsWith("/watch/cron-all")) {
      // Für Supabase Scheduler: nimm x-app-secret (einfacher) ODER Authorization Bearer CRON_SECRET
      const valid = checkAppSecret(req) || checkCronAuth(req);
      if (!valid) return res.status(401).json({ error: "unauthorized_cron" });

      const out1 = await runCronCheckAll({ limit: qs.limit_check || "200", concurrency: qs.conc_check || "4" });
      const out2 = await runCronSyncAll({ limit: qs.limit_sync || "50", concurrency: qs.conc_sync || "3" });
      if (out1.error || out2.error) return res.status(500).json({ error: "cron_error", check: out1, sync: out2 });
      return res.status(200).json({ ok: true, check: out1, sync: out2 });
    }

    // nichts gematcht
    return res.status(404).json({ error: "not_found" });
  } catch (e) {
    return res.status(500).json({ error: "server_error", message: String(e) });
  }
}
