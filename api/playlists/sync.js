// api/playlists/sync.js
export const config = { runtime: "nodejs" };

import crypto from "crypto";

/* -------------------- helpers -------------------- */

function need(name) {
  const v = process.env[name];
  if (!v) throw new Error(`missing env: ${name}`);
  return v;
}

// AES-256-GCM decrypt (muss zu enc() aus callback.js passen)
function decryptToken(b64) {
  const hex = need("ENC_SECRET");
  if (hex.length < 64) throw new Error("ENC_SECRET must be 32-byte hex (64 chars)");
  const key = Buffer.from(hex, "hex");
  const raw = Buffer.from(String(b64), "base64");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ct = raw.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString("utf8");
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

async function getConnectionById(id) {
  const r = await sb(
    `/rest/v1/spotify_connections` +
      `?select=id,bubble_user_id,spotify_user_id,refresh_token_enc` +
      `&limit=1&id=eq.${encodeURIComponent(id)}`
  );
  if (!r.ok) throw new Error(`supabase select connection failed: ${r.status} ${await r.text()}`);
  const arr = await r.json();
  return arr[0];
}

async function refreshAccessToken(refresh_token) {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token,
    client_id: need("SPOTIFY_CLIENT_ID"),
    client_secret: need("SPOTIFY_CLIENT_SECRET"),
  });
  const r = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const j = await r.json();
  if (!r.ok || !j.access_token) {
    throw new Error(`spotify refresh failed: ${r.status} ${JSON.stringify(j)}`);
  }
  return j; // { access_token, expires_in, ... }
}

async function fetchAllOwnPlaylists(access_token) {
  let url = "https://api.spotify.com/v1/me/playlists?limit=50";
  const out = [];
  while (url) {
    const r = await fetch(url, { headers: { Authorization: `Bearer ${access_token}` } });
    const j = await r.json();
    if (!r.ok) {
      throw new Error(`spotify /me/playlists failed: ${r.status} ${JSON.stringify(j)}`);
    }
    out.push(...(j.items || []));
    url = j.next;
  }
  return out;
}

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(data || "{}"));
      } catch {
        resolve({});
      }
    });
  });
}

function chunk(arr, n) {
  const out = [];
  for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n));
  return out;
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

    // optionaler Schutz-Header
    const expected = process.env.APP_WEBHOOK_SECRET;
    if (expected) {
      const got = req.headers["x-app-secret"];
      if (got !== expected) return res.status(401).json({ error: "unauthorized" });
    }

    // Params
    const includePrivate = req.query.include_private === "1";
    const body = await readBody(req);
    const connection_id = body.connection_id;
    if (!connection_id) return res.status(400).json({ error: "missing_connection_id" });

    // 1) Verbindung + Refresh-Token
    const conn = await getConnectionById(connection_id);
    if (!conn) return res.status(404).json({ error: "connection_not_found" });

    const refresh_token = decryptToken(conn.refresh_token_enc);

    // 2) Access-Token via Refresh
    const token = await refreshAccessToken(refresh_token);
    const access_token = token.access_token;

    // 3) Alle Playlists holen
    const all = await fetchAllOwnPlaylists(access_token);

    // 4) Filter: owned + public (oder private inkludieren, wenn ?include_private=1)
    const filtered = all.filter(
      (p) => p?.owner?.id === conn.spotify_user_id && (includePrivate ? true : p?.public === true)
    );

    // 5) Deduplizieren & Upsert in Batches (on_conflict=playlist_id)
    const nowIso = new Date().toISOString();
    const mapById = new Map();
    for (const p of filtered) {
      mapById.set(p.id, {
        playlist_id: p.id,
        connection_id: conn.id,
        bubble_user_id: conn.bubble_user_id,
        name: p.name || null,
        description: p.description || null,
        image: p.images?.[0]?.url || null,
        followers: p.followers?.total ?? null,
        is_owner: true,
        is_public: !!p.public,
        tracks_total: p.tracks?.total ?? 0,
        snapshot_id: p.snapshot_id || null,
        last_checked_at: nowIso,
        updated_at: nowIso,
      });
    }
    const rows = Array.from(mapById.values());

    if (rows.length === 0) {
      return res
        .status(200)
        .json({ ok: true, upserts: 0, reason: "no_owned_public_playlists" });
    }

    const batches = chunk(rows, 100);
    let upserts = 0;
    for (const batch of batches) {
      const up = await sb(`/rest/v1/playlists?on_conflict=playlist_id`, {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify(batch),
      });
      if (!up.ok) {
        const txt = await up.text();
        return res.status(500).json({ error: "supabase_upsert_failed", body: txt });
      }
      upserts += batch.length;
    }

    return res.status(200).json({ ok: true, upserts, filtered: filtered.length });
  } catch (e) {
    return res.status(500).json({
      error: "server_error",
      message: String(e),
    });
  }
}
