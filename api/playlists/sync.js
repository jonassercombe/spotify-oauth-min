// api/playlists/sync.js
import crypto from "crypto";

// --- helpers from earlier ---
async function getSRK() { return process.env.SUPABASE_SERVICE_ROLE_KEY; }
function reqSupabase(path, init={}) {
  const url = process.env.SUPABASE_URL + path;
  const headers = {
    apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
    "Content-Type": "application/json",
    ...(init.headers || {})
  };
  return fetch(url, { ...init, headers });
}

async function getConnection(connId) {
  const r = await reqSupabase(`/rest/v1/spotify_connections?id=eq.${encodeURIComponent(connId)}&select=id,bubble_user_id,spotify_user_id,refresh_token_enc,access_token_enc,access_expires_at&limit=1`);
  const arr = await r.json();
  return arr[0];
}

// VERY simple decrypt helper (nur wenn du enc() symmetrisch machen willst; aktuell speichern wir nur verschlüsselt und brauchen zum Refresh den Klartext – deshalb am besten Tokens im Backend verschlüsseln/entschlüsseln, gleiche secret wie im callback.js verwenden)
function decToPlain(b64) {
  const hex = process.env.ENC_SECRET;
  const key = Buffer.from(hex, "hex");
  const buf = Buffer.from(b64, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ct = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString("utf8");
}

async function refreshAccessToken(refresh_token) {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token,
    client_id: process.env.SPOTIFY_CLIENT_ID,
    client_secret: process.env.SPOTIFY_CLIENT_SECRET
  });
  const r = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const j = await r.json();
  if (!r.ok || !j.access_token) throw new Error("refresh_failed: " + JSON.stringify(j));
  return j; // { access_token, expires_in, ... }
}

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });
    const { connection_id } = await (async () => {
      try { return await req.json?.() || await new Promise((r) => {
        let data=""; req.on("data", c=>data+=c); req.on("end", ()=>r(JSON.parse(data||"{}")));
      }); } catch { return {}; }
    })();

    if (!connection_id) return res.status(400).json({ error: "missing_connection_id" });

    // 1) Connection + Tokens
    const conn = await getConnection(connection_id);
    if (!conn) return res.status(404).json({ error: "connection_not_found" });

    const refresh_token = decToPlain(conn.refresh_token_enc);
    const token = await refreshAccessToken(refresh_token);
    const access_token = token.access_token;

    // 2) Fetch playlists of the user
    let items = [];
    let url = "https://api.spotify.com/v1/me/playlists?limit=50";
    while (url) {
      const r = await fetch(url, { headers: { Authorization: `Bearer ${access_token}` }});
      const j = await r.json();
      if (!r.ok) return res.status(400).json({ error: "spotify_error", body: j });
      items = items.concat(j.items || []);
      url = j.next;
    }

    // 3) Filter: owned + public
    const ownedPublic = items.filter(p =>
      p?.owner?.id === conn.spotify_user_id && (p?.public === true)
    );

    // 4) Upsert playlists
    // PATCH (update) if exists; else POST (insert)
    const upserts = [];
    for (const p of ownedPublic) {
      const payload = {
        playlist_id: p.id,
        connection_id: conn.id,
        bubble_user_id: conn.bubble_user_id,
        name: p.name || null,
        description: p.description || null,
        image: p.images?.[0]?.url || null,
        followers: p.followers?.total ?? null,
        is_owner: true,
        is_public: true,
        tracks_total: p.tracks?.total ?? 0,
        snapshot_id: p.snapshot_id || null,
        last_checked_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      // try patch
      const patch = await reqSupabase(`/rest/v1/playlists?playlist_id=eq.${encodeURIComponent(p.id)}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
        headers: { Prefer: "return=minimal" }
      });
      if (patch.ok) {
        // check if any row affected (PostgREST minimal returns 204)
        if (patch.status === 204) {
          // nothing to know, assume updated-or-not
        }
      } else {
        // if 404-like, then insert
        await reqSupabase("/rest/v1/playlists", {
          method: "POST",
          body: JSON.stringify(payload),
        });
      }
      upserts.push(p.id);
    }

    return res.status(200).json({ ok: true, upserts: upserts.length });
  } catch (e) {
    return res.status(500).json({ error: "server_error", message: String(e) });
  }
}

