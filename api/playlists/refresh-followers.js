// api/playlists/refresh-followers.js
export const config = { runtime: "nodejs" };

/* -------------------- helpers -------------------- */

function need(n) {
  const v = process.env[n];
  if (!v) throw new Error(`missing env: ${n}`);
  return v;
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

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try { resolve(JSON.parse(data || "{}")); } catch { resolve({}); }
    });
  });
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function mapLimited(items, limit, mapper) {
  const res = Array(items.length);
  let i = 0, running = 0, rejectOnce;
  return new Promise((resolve, reject) => {
    rejectOnce = reject;
    const kick = () => {
      while (running < limit && i < items.length) {
        const idx = i++; running++;
        Promise.resolve(mapper(items[idx], idx))
          .then((v) => { res[idx] = v; running--; kick(); })
          .catch((e) => reject(e));
      }
      if (running === 0 && i >= items.length) resolve(res);
    };
    kick();
  });
}

/* -------------------- spotify helpers -------------------- */

import crypto from "crypto";

function decryptToken(b64) {
  const hex = need("ENC_SECRET");
  if (hex.length < 64) throw new Error("ENC_SECRET must be 32-byte hex (64 chars)");
  const key = Buffer.from(hex, "hex");
  const raw = Buffer.from(String(b64), "base64");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ct = raw.subarray(28);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}

async function getAccessTokenFromConnection(connection_id) {
  const r = await sb(`/rest/v1/spotify_connections?select=refresh_token_enc&limit=1&id=eq.${encodeURIComponent(connection_id)}`);
  const arr = await r.json();
  const enc = arr?.[0]?.refresh_token_enc;
  if (!enc) throw new Error("no refresh token on connection");
  const refresh_token = decryptToken(enc);

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token,
    client_id: need("SPOTIFY_CLIENT_ID"),
    client_secret: need("SPOTIFY_CLIENT_SECRET"),
  });
  const t = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const j = await t.json();
  if (!t.ok || !j.access_token) throw new Error(`refresh failed: ${t.status} ${JSON.stringify(j)}`);
  return j.access_token;
}

async function fetchFollowersOne(id, access_token) {
  const url = `https://api.spotify.com/v1/playlists/${id}?fields=followers(total)`;
  while (true) {
    const r = await fetch(url, { headers: { Authorization: `Bearer ${access_token}` } });
    if (r.status === 429) {
      const retry = Number(r.headers.get("retry-after") || "1");
      await sleep((retry + 0.2) * 1000);
      continue;
    }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return { id, followers: null, ok: false, status: r.status };
    return { id, followers: j?.followers?.total ?? null, ok: true, status: 200 };
  }
}

/* -------------------- db helpers -------------------- */

async function getConnection(connection_id) {
  const r = await sb(`/rest/v1/spotify_connections?select=id,bubble_user_id,spotify_user_id&limit=1&id=eq.${encodeURIComponent(connection_id)}`);
  const j = await r.json();
  return j[0];
}

async function getPlaylistIdsNeedingRefresh(connection_id, staleHours, limit) {
  const sinceIso = new Date(Date.now() - staleHours * 3600 * 1000).toISOString();
  const order = encodeURIComponent("followers_checked_at.asc.nullsfirst");
  const path =
    `/rest/v1/playlists` +
    `?select=playlist_id` +
    `&connection_id=eq.${encodeURIComponent(connection_id)}` +
    `&is_owner=is.true&is_public=is.true` +
    `&or=(followers.is.null,followers_checked_at.lt.${encodeURIComponent(sinceIso)})` +
    `&order=${order}` +
    `&limit=${limit}`;
  const r = await sb(path);
  if (!r.ok) throw new Error(`supabase select failed: ${r.status} ${await r.text()}`);
  const rows = await r.json();
  return rows.map((x) => x.playlist_id);
}

async function upsertFollowersRows(rows) {
  // rows: [{ playlist_id, connection_id, bubble_user_id, followers, followers_checked_at, updated_at }]
  const r = await sb(`/rest/v1/playlists?on_conflict=playlist_id`, {
    method: "POST",
    headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify(rows),
  });
  if (!r.ok) throw new Error(`supabase upsert failed: ${r.status} ${await r.text()}`);
}

/* -------------------- handler -------------------- */

export default async function handler(req, res) {
  try {
    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,x-app-secret");
    if (req.method === "OPTIONS") return res.status(204).end();
    if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

    // optionaler Secret-Header
    const expected = process.env.APP_WEBHOOK_SECRET;
    if (expected) {
      const got = req.headers["x-app-secret"];
      if (got !== expected) return res.status(401).json({ error: "unauthorized" });
    }

    // Params
    const body = await readBody(req);
    const connection_id = body.connection_id;
    if (!connection_id) return res.status(400).json({ error: "missing_connection_id" });

    // Optionen
    const staleHours = Number(req.query.stale_hours || "24");  // wie alt ist „alt“
    const maxTotal   = Number(req.query.max || "1000");        // max Playlists pro Run
    const conc       = Number(req.query.concurrency || "4");   // parallele Spotify-Calls
    const perWrite   = Number(req.query.batch || "100");       // DB-Write-Batchgröße

    // Connection prüfen (holt auch bubble_user_id)
    const conn = await getConnection(connection_id);
    if (!conn) return res.status(404).json({ error: "connection_not_found" });

    // Kandidaten bestimmen
    const ids = await getPlaylistIdsNeedingRefresh(connection_id, staleHours, maxTotal);
    if (ids.length === 0) {
      return res.status(200).json({ ok: true, attempted: 0, updated: 0, failed: [] , reason: "up_to_date" });
    }

    // Spotify Access Token
    const access_token = await getAccessTokenFromConnection(connection_id);

    // Followers abrufen (429-safe, concurrency-limited)
    const results = await mapLimited(ids, conc, async (id) => {
      const r = await fetchFollowersOne(id, access_token);
      // kleines pacing
      await sleep(50);
      return r;
    });

    const nowIso = new Date().toISOString();
    // Erfolgreiche in Upsert-Rows konvertieren (inkl. NOT NULL Felder)
    const rows = results
      .filter((x) => x.ok)
      .map((x) => ({
        playlist_id: x.id,
        connection_id,                 // NOT NULL
        bubble_user_id: conn.bubble_user_id, // NOT NULL
        followers: x.followers,
        followers_checked_at: nowIso,
        updated_at: nowIso,
      }));

    // In Batches upserten
    for (let i = 0; i < rows.length; i += perWrite) {
      await upsertFollowersRows(rows.slice(i, i + perWrite));
    }

    const failed = results.filter((x) => !x.ok).map((x) => ({ id: x.id, status: x.status }));
    return res.status(200).json({
      ok: true,
      attempted: ids.length,
      updated: rows.length,
      failed,
    });
  } catch (e) {
    return res.status(500).json({ error: "server_error", message: String(e) });
  }
}
