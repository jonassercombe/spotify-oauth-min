// pages/api/[...task].js
export const config = { runtime: "nodejs" };

/* ==============================
   Shared Utils (Server-only)
============================== */
const json = (res, code, payload) => res.status(code).json(payload);
const bad  = (res, code, msg) => json(res, code, { error: msg });
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function parseJsonSafe(resp) {
  const txt = await resp.text();
  try { return { json: JSON.parse(txt), text: txt }; }
  catch { return { json: null, text: txt }; }
}

function withCORS(handler) {
  return async (req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Bubble-User-Id,x-app-secret,x-service-key");
    if (req.method === "OPTIONS") return res.status(204).end();
    return handler(req, res);
  };
}

function need(n) {
  const v = process.env[n];
  if (!v) throw new Error(`missing env: ${n}`);
  return v;
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

/* ==============================
   Spotify helpers
============================== */
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

function encToken(plain) {
  const hex = need("ENC_SECRET");
  if (hex.length < 64) throw new Error("ENC_SECRET must be 32-byte hex (64 chars)");
  const key = Buffer.from(hex, "hex");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString("base64");
}

async function refreshAccessToken(refresh_token) {
  const body = new URLSearchParams({
    grant_type:"refresh_token",
    refresh_token,
    client_id: need("SPOTIFY_CLIENT_ID"),
    client_secret: need("SPOTIFY_CLIENT_SECRET")
  });
  const r = await fetch("https://accounts.spotify.com/api/token", {
    method:"POST", headers:{ "Content-Type":"application/x-www-form-urlencoded" }, body
  });
  const { json, text } = await parseJsonSafe(r);
  if (!r.ok || !json?.access_token) {
    throw new Error(`spotify refresh failed: ${r.status} ${json ? JSON.stringify(json) : text}`);
  }
  return json; // { access_token, expires_in, ... }
}

async function getAccessTokenFromConnection(connection_id) {
  const r = await sb(`/rest/v1/spotify_connections?select=refresh_token_enc&limit=1&id=eq.${encodeURIComponent(connection_id)}`);
  const arr = await r.json();
  const enc = arr?.[0]?.refresh_token_enc;
  if (!enc) throw new Error("no refresh token on connection");
  const refresh_token = decryptToken(enc);
  const t = await refreshAccessToken(refresh_token);
  return t.access_token;
}

/* ==============================
   Route Handlers (map)
============================== */
const routes = {
  /* ---------- connections/list (GET) ---------- */
  "connections/list": async (req, res) => {
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SRK = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SRK) {
      return json(res, 500, {
        error: "missing_env",
        have: { SUPABASE_URL: !!SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: !!SRK }
      });
    }
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const bubble_user_id = req.query.bubble_user_id;
    if (!bubble_user_id) return bad(res, 400, "missing_bubble_user_id");

    const path =
      `/rest/v1/spotify_connections` +
      `?select=id,display_name,avatar_url,spotify_user_id,created_at` +
      `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
      `&order=created_at.desc`;

    const r = await fetch(SUPABASE_URL + path, {
      headers: { apikey: SRK, Authorization: `Bearer ${SRK}` },
      cache: "no-store"
    });
    const txt = await r.text();
    if (!r.ok) return json(res, 500, { error:"supabase_error", status:r.status, body:txt, url: SUPABASE_URL+path });
    return json(res, 200, txt ? JSON.parse(txt) : []);
  },

  /* ---------- debug/env (GET) ---------- */
  "debug/env": async (_req, res) => {
    return json(res, 200, {
      SUPABASE_URL: !!process.env.SUPABASE_URL,
      SUPABASE_SERVICE_ROLE_KEY: !!process.env.SUPABASE_SERVICE_ROLE_KEY
    });
  },

  /* ---------- oauth/spotify/start (GET) ---------- */
  "oauth/spotify/start": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    if (!process.env.SPOTIFY_CLIENT_ID || !process.env.SPOTIFY_REDIRECT_URI) {
      return res.status(500).send("Server misconfigured: missing SPOTIFY_CLIENT_ID or SPOTIFY_REDIRECT_URI");
    }
    const { bubble_user_id, label = "", return_to = "" } = req.query;
    if (!bubble_user_id) return res.status(400).send("Missing query param: bubble_user_id");

    const stateObj = { bubble_user_id, label, return_to, nonce: Math.random().toString(36).slice(2) };
    const state = Buffer.from(JSON.stringify(stateObj)).toString("base64url");

    const scope = [
      "playlist-read-private",
      "playlist-modify-private",
      "playlist-modify-public"
    ].join(" ");

    const url =
      "https://accounts.spotify.com/authorize" +
      `?client_id=${encodeURIComponent(process.env.SPOTIFY_CLIENT_ID)}` +
      `&response_type=code` +
      `&redirect_uri=${encodeURIComponent(process.env.SPOTIFY_REDIRECT_URI)}` +
      `&scope=${encodeURIComponent(scope)}` +
      `&state=${encodeURIComponent(state)}` +
      `&show_dialog=true`;

    return res.redirect(url);
  },

  /* ---------- oauth/spotify/callback (GET) ---------- */
  "oauth/spotify/callback": async (req, res) => {
    try {
      const assertEnv = (n) => need(n);
      assertEnv("SPOTIFY_CLIENT_ID");
      assertEnv("SPOTIFY_CLIENT_SECRET");
      assertEnv("SPOTIFY_REDIRECT_URI");
      assertEnv("SUPABASE_URL");
      assertEnv("SUPABASE_SERVICE_ROLE_KEY");
      assertEnv("ENC_SECRET");

      const code = req.query.code;
      const state = req.query.state;
      if (!code || !state) return res.status(400).send("Missing code/state");

      let parsed;
      try { parsed = JSON.parse(Buffer.from(state, "base64url").toString("utf8")); }
      catch { return res.status(400).send("Invalid state"); }
      const bubble_user_id = parsed.bubble_user_id;
      const label = parsed.label || "";
      const return_to = parsed.return_to || "/";
      if (!bubble_user_id) return res.status(400).send("Missing bubble_user_id in state");

      // exchange
      const tokenRes = await fetch("https://accounts.spotify.com/api/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: "Basic " + Buffer.from(
            `${process.env.SPOTIFY_CLIENT_ID}:${process.env.SPOTIFY_CLIENT_SECRET}`
          ).toString("base64"),
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: process.env.SPOTIFY_REDIRECT_URI,
        }),
      }).then(r => r.json());

      if (!tokenRes || !tokenRes.access_token) {
        console.error("Token exchange failed:", tokenRes);
        return res.status(400).send("Failed to get access token from Spotify");
      }

      const meResp = await fetch("https://api.spotify.com/v1/me", {
        headers: { Authorization: `Bearer ${tokenRes.access_token}` },
      });
      if (!meResp.ok) {
        const t = await meResp.text();
        console.error("Spotify /me failed:", meResp.status, t);
        return res.status(400).send(`Spotify /me failed: ${meResp.status}\n\n${t}`);
      }
      const me = await meResp.json();
      const spotify_user_id = me.id;
      const display_name = me.display_name || label || "";
      const avatar_url = (me.images && me.images[0]?.url) || null;

      // ensure app_user exists (ignore dup)
      await fetch(`${process.env.SUPABASE_URL}/rest/v1/app_users?on_conflict=bubble_user_id`, {
        method: "POST",
        headers: {
          apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
          "Content-Type": "application/json",
          Prefer: "resolution=ignore-duplicates,return=minimal"
        },
        body: JSON.stringify({ bubble_user_id }),
      });

      // existing connection?
      const existing = await fetch(
        `${process.env.SUPABASE_URL}/rest/v1/spotify_connections?` +
        `select=id,refresh_token_enc&` +
        `bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}&` +
        `spotify_user_id=eq.${encodeURIComponent(spotify_user_id)}&limit=1`,
        {
          headers: {
            apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
            Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
          }
        }
      ).then(r => r.json()).then(a => (Array.isArray(a) && a[0]) ? a[0] : null);

      let refresh_token_enc = null;
      if (tokenRes.refresh_token) refresh_token_enc = encToken(tokenRes.refresh_token);
      else if (existing?.refresh_token_enc) refresh_token_enc = existing.refresh_token_enc;
      else return res.status(400).send("No refresh_token received. Please retry (consent required).");

      const access_token_enc = encToken(tokenRes.access_token);
      const access_expires_at = new Date(Date.now() + (tokenRes.expires_in || 3600) * 1000).toISOString();

      const payload = {
        bubble_user_id,
        spotify_user_id,
        display_name,
        avatar_url,
        scope: "playlist-read-private playlist-modify-private playlist-modify-public",
        refresh_token_enc,
        access_token_enc,
        access_expires_at
      };

      if (existing) {
        await fetch(
          `${process.env.SUPABASE_URL}/rest/v1/spotify_connections?` +
          `bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}&` +
          `spotify_user_id=eq.${encodeURIComponent(spotify_user_id)}`,
          {
            method: "PATCH",
            headers: {
              apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
              Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
              "Content-Type": "application/json",
              Prefer: "return=representation"
            },
            body: JSON.stringify(payload),
          }
        );
      } else {
        await fetch(`${process.env.SUPABASE_URL}/rest/v1/spotify_connections`, {
          method: "POST",
          headers: {
            apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
            Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
            "Content-Type": "application/json",
            Prefer: "return=representation"
          },
          body: JSON.stringify(payload),
        });
      }

      const qs = `?spotify_linked=1&spotify_user=${encodeURIComponent(spotify_user_id)}`;
      const back = (return_to || "/") + qs;
      return res.redirect(back);
    } catch (e) {
      console.error("callback error:", e);
      const msg = e && e.stack ? e.stack : String(e);
      return res.status(500).send("callback error – " + msg);
    }
  },

  /* ---------- playlist-items/list (GET) ---------- */
  "playlist-items/list": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
    if (!SUPABASE_URL || !SRK) return bad(res, 500, "missing_env");

    const playlist_row_id = req.query.playlist_row_id;
    if (!playlist_row_id) return bad(res, 400, "missing_playlist_row_id");

    const path =
     `/rest/v1/playlist_items_ui` +
     `?select=playlist_id,position,track_id,track_name,artist_names,album_name,` +
     `duration_ms,duration_formatted,added_at,age_days,age_label,track_uri,` +
     `popularity,preview_url,cover_url,is_locked,locked_position,locked_at` +
     `&playlist_id=eq.${encodeURIComponent(playlist_row_id)}` +
     `&order=position.asc`;


    const r = await fetch(SUPABASE_URL + path, {
      headers: { apikey: SRK, Authorization: `Bearer ${SRK}` },
      cache: "no-store"
    });
    const txt = await r.text();
    if (!r.ok) return json(res, 500, { error: "supabase_error", status: r.status, body: txt });
    return json(res, 200, txt ? JSON.parse(txt) : []);
  },

  /* ---------- playlists/list (GET) ---------- */
  "playlists/list": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
    if (!SUPABASE_URL || !SRK) return bad(res, 500, "missing_env");

    const bubble_user_id = req.query.bubble_user_id;
    if (!bubble_user_id) return bad(res, 400, "missing_bubble_user_id");

    const path =
      `/rest/v1/playlists` +
      `?select=id,playlist_id,name,image,tracks_total,followers,updated_at` +
      `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
      `&is_owner=is.true&is_public=is.true` +
      `&order=updated_at.desc`;

    const r = await fetch(SUPABASE_URL + path, {
      headers: { apikey: SRK, Authorization: `Bearer ${SRK}` },
      cache: "no-store",
    });
    const txt = await r.text();
    if (!r.ok) return json(res, 500, { error: "supabase_error", status: r.status, body: txt, url: SUPABASE_URL+path });
    return json(res, 200, txt ? JSON.parse(txt) : []);
  },

  /* ---------- playlists/refresh-followers (POST, secret) ---------- */
  "playlists/refresh-followers": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    if (process.env.APP_WEBHOOK_SECRET) {
      const got = req.headers["x-app-secret"];
      if (got !== process.env.APP_WEBHOOK_SECRET) return bad(res, 401, "unauthorized");
    }

    const body = await readBody(req);
    const connection_id = body.connection_id;
    if (!connection_id) return bad(res, 400, "missing_connection_id");

    const staleHours = Number(req.query.stale_hours || "24");
    const maxTotal   = Number(req.query.max || "1000");
    const conc       = Number(req.query.concurrency || "4");
    const perWrite   = Number(req.query.batch || "100");

    const connR = await sb(`/rest/v1/spotify_connections?select=id,bubble_user_id,spotify_user_id&limit=1&id=eq.${encodeURIComponent(connection_id)}`);
    const conn = (await connR.json())?.[0];
    if (!conn) return bad(res, 404, "connection_not_found");

    const sinceIso = new Date(Date.now() - staleHours * 3600 * 1000).toISOString();
    const order = encodeURIComponent("followers_checked_at.asc.nullsfirst");
    const path =
      `/rest/v1/playlists?select=playlist_id` +
      `&connection_id=eq.${encodeURIComponent(connection_id)}` +
      `&is_owner=is.true&is_public=is.true` +
      `&or=(followers.is.null,followers_checked_at.lt.${encodeURIComponent(sinceIso)})` +
      `&order=${order}&limit=${maxTotal}`;
    const ids = (await sb(path).then(r => r.json())).map(x => x.playlist_id);

    if (ids.length === 0) return json(res, 200, { ok:true, attempted:0, updated:0, failed:[], reason:"up_to_date" });

    const access_token = await getAccessTokenFromConnection(connection_id);

    const results = await (async () => {
      const out = [];
      let i = 0, running = 0;
      await new Promise((resolve, reject) => {
        const kick = () => {
          while (running < conc && i < ids.length) {
            const id = ids[i++]; running++;
            (async () => {
              try {
                const url = `https://api.spotify.com/v1/playlists/${id}?fields=followers(total)`;
                let resFollowers = { ok:false, status:0, id, followers:null };
                while (true) {
                  const r = await fetch(url, { headers: { Authorization: `Bearer ${access_token}` } });
                  if (r.status === 429) {
                    const retry = Number(r.headers.get("retry-after") || "1");
                    await sleep((retry + 0.2)*1000);
                    continue;
                  }
                  const j = await r.json().catch(()=> ({}));
                  if (!r.ok) { resFollowers = { id, followers:null, ok:false, status:r.status }; }
                  else { resFollowers = { id, followers: j?.followers?.total ?? null, ok:true, status:200 }; }
                  break;
                }
                out.push(resFollowers);
                await sleep(50);
              } catch (e) {
                out.push({ id, followers:null, ok:false, status:500 });
              } finally {
                running--; kick();
              }
            })();
          }
          if (running === 0 && i >= ids.length) resolve();
        };
        kick();
      });
      return out;
    })();

    const nowIso = new Date().toISOString();
    const rows = results.filter(x => x.ok).map(x => ({
      playlist_id: x.id,
      connection_id,
      bubble_user_id: conn.bubble_user_id,
      followers: x.followers,
      followers_checked_at: nowIso,
      updated_at: nowIso,
    }));

    for (let i = 0; i < rows.length; i += perWrite) {
      const r = await sb(`/rest/v1/playlists?on_conflict=playlist_id`, {
        method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify(rows.slice(i, i + perWrite)),
      });
      if (!r.ok) return bad(res, 500, `supabase upsert failed: ${await r.text()}`);
    }

    const failed = results.filter(x => !x.ok).map(x => ({ id: x.id, status: x.status }));
    return json(res, 200, { ok:true, attempted: ids.length, updated: rows.length, failed });
  },

  /* ---------- playlists/sync-items (POST, secret) ---------- */
  "playlists/sync-items": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    if (process.env.APP_WEBHOOK_SECRET) {
      const got = req.headers["x-app-secret"];
      if (got !== process.env.APP_WEBHOOK_SECRET) return bad(res, 401, "unauthorized");
    }
    const body = await readBody(req);
    let { playlist_row_id, spotify_playlist_id } = body;
    if (!playlist_row_id && !spotify_playlist_id) return bad(res, 400, "missing_playlist_identifier");

    if (!playlist_row_id && spotify_playlist_id) {
      const r = await sb(`/rest/v1/playlists?select=id,playlist_id,connection_id,bubble_user_id&limit=1&playlist_id=eq.${encodeURIComponent(spotify_playlist_id)}`);
      if (!r.ok) return bad(res, 500, `supabase_select_failed: ${await r.text()}`);
      const arr = await r.json();
      if (!arr[0]) return bad(res, 404, "playlist_not_found_by_spotify_id");
      playlist_row_id = arr[0].id;
    }

    const pr = await sb(`/rest/v1/playlists?select=id,playlist_id,connection_id,bubble_user_id&limit=1&id=eq.${encodeURIComponent(playlist_row_id)}`);
    if (!pr.ok) return bad(res, 500, `supabase select playlist failed: ${await pr.text()}`);
    const p = (await pr.json())[0];
    if (!p) return bad(res, 404, "playlist_not_found");

    const cr = await sb(`/rest/v1/spotify_connections?select=id,refresh_token_enc&limit=1&id=eq.${encodeURIComponent(p.connection_id)}`);
    if (!cr.ok) return bad(res, 500, `supabase select connection failed: ${await cr.text()}`);
    const conn = (await cr.json())[0];
    if (!conn) return bad(res, 404, "connection_not_found");

    const refresh_token = decryptToken(conn.refresh_token_enc);
    const access_token = (await refreshAccessToken(refresh_token)).access_token;

    // fetch tracks
    const items = [];
    let url = `https://api.spotify.com/v1/playlists/${encodeURIComponent(p.playlist_id)}/tracks?limit=100&offset=0&fields=items(added_at,track(id,name,uri,popularity,duration_ms,preview_url,album(name,images),artists(name))),total,next,offset`;
    while (url) {
      const r = await fetch(url, { headers: { Authorization: `Bearer ${access_token}` } });
      if (r.status === 429) {
        const retry = Number(r.headers.get("retry-after") || "1");
        await sleep((retry + 0.2) * 1000);
        continue; // nochmal versuchen
      }
      const { json, text } = await parseJsonSafe(r);
      if (!r.ok) {
        return bad(res, r.status, `spotify playlist tracks failed: ${r.status} ${json ? JSON.stringify(json) : text}`);
      }
      items.push(...(json?.items || []));
      url = json?.next || null;
    }

    const rows = [];
    for (let i = 0; i < items.length; i++) {
      const it = items[i] || {};
      const t  = it.track || {};
      const album = t.album || {};
      const artists = Array.isArray(t.artists) ? t.artists : [];
      rows.push({
        playlist_id: playlist_row_id, // FK -> playlists.id (uuid)
        position: i, // 0-based
        track_id: t.id || null,
        track_name: t.name || null,
        track_uri: t.uri || null,
        artist_names: artists.map(a=>a?.name).filter(Boolean).join(", "),
        album_name: album.name || null,
        duration_ms: Number.isFinite(t.duration_ms) ? t.duration_ms : null,
        popularity: Number.isFinite(t.popularity) ? t.popularity : null,
        preview_url: t.preview_url || null,
        cover_url: (album.images && album.images[0]?.url) || null,
        added_at: it.added_at || null
      });
    }

    // UPSERT in Batches
    const chunk = (arr,n)=>{const out=[]; for(let i=0;i<arr.length;i+=n) out.push(arr.slice(i,i+n)); return out;};
    const batches = chunk(rows, 500);
    for (const b of batches) {
      const up = await sb(`/rest/v1/playlist_items?on_conflict=playlist_id,position`, {
        method: "POST", headers: { Prefer: "resolution=merge-duplicates,return=minimal" }, body: JSON.stringify(b)
      });
      if (!up.ok) return bad(res, 500, `upsert_items_failed: ${await up.text()}`);
    }

    // cleanup tail
    const maxKeep = Math.max(0, rows.length - 1);
    const delUrl = `/rest/v1/playlist_items?playlist_id=eq.${encodeURIComponent(playlist_row_id)}&position=gt.${maxKeep}`;
    const del = await sb(delUrl, { method: "DELETE", headers: { Prefer: "return=minimal" } });
    if (!del.ok) {
      const dtxt = await del.text();
      return json(res, 200, { ok:true, inserted_or_updated: rows.length, total_spotify: items.length, cleanup_warning: dtxt });
    }
    return json(res, 200, { ok:true, inserted_or_updated: rows.length, total_spotify: items.length });
  },

  /* ---------- playlists/sync (POST, secret) ---------- */
  "playlists/sync": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    if (process.env.APP_WEBHOOK_SECRET) {
      const got = req.headers["x-app-secret"];
      if (got !== process.env.APP_WEBHOOK_SECRET) return bad(res, 401, "unauthorized");
    }
    const body = await readBody(req);
    const connection_id = body.connection_id;
    if (!connection_id) return bad(res, 400, "missing_connection_id");

    // 1) connection
    const cr = await sb(`/rest/v1/spotify_connections?select=id,bubble_user_id,spotify_user_id,refresh_token_enc&limit=1&id=eq.${encodeURIComponent(connection_id)}`);
    if (!cr.ok) return bad(res, 500, `supabase select connection failed: ${await cr.text()}`);
    const conn = (await cr.json())[0];
    if (!conn) return bad(res, 404, "connection_not_found");

    const refresh_token = decryptToken(conn.refresh_token_enc);
    const token = await refreshAccessToken(refresh_token);
    const access_token = token.access_token;

    // 3) /me/playlists
    let url = "https://api.spotify.com/v1/me/playlists?limit=50";
    const all = [];
    while (url) {
      const r = await fetch(url, { headers: { Authorization: `Bearer ${access_token}` } });
      if (r.status === 429) {
        const retry = Number(r.headers.get("retry-after") || "1");
        await sleep((retry + 0.2) * 1000);
        continue; // nochmal versuchen
      }
      const { json, text } = await parseJsonSafe(r);
      if (!r.ok) {
        return bad(res, r.status, `spotify /me/playlists failed: ${r.status} ${json ? JSON.stringify(json) : text}`);
      }
      all.push(...(json?.items || []));
      url = json?.next || null;
    }

    const includePrivate = req.query.include_private === "1";
    const withFollowers = req.query.with_followers === "1";
    const filtered = all.filter(
      (p) => p?.owner?.id === conn.spotify_user_id && (includePrivate ? true : p?.public === true)
    );

    let followersMap = new Map();
    let followersFetched = 0;
    if (withFollowers) {
      const ids = filtered.slice(0, 50).map((p) => p.id);
      for (const id of ids) {
        const r = await fetch(
          `https://api.spotify.com/v1/playlists/${id}?fields=followers(total)`,
          { headers: { Authorization: `Bearer ${access_token}` } }
        );
        if (r.status === 429) {
          const retry = Number(r.headers.get("retry-after") || "1");
          await sleep((retry + 0.2) * 1000);
          continue; // nochmal versuchen
        }
        const { json, text } = await parseJsonSafe(r);
        if (r.ok) followersMap.set(id, json?.followers?.total ?? null);
      }
      followersFetched = followersMap.size;
    }

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
        followers: followersMap.has(p.id)
          ? followersMap.get(p.id)
          : (p.followers?.total ?? null),
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
      return json(res, 200, { ok:true, upserts:0, filtered:0, followers_fetched: followersFetched, reason:"no_owned_public_playlists" });
    }

    // batch upsert
    const chunk = (arr,n)=>{const out=[]; for(let i=0;i<arr.length;i+=n) out.push(arr.slice(i,i+n)); return out;};
    let upserts = 0;
    for (const batch of chunk(rows, 100)) {
      const up = await sb(`/rest/v1/playlists?on_conflict=playlist_id`, {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify(batch),
      });
      if (!up.ok) return bad(res, 500, `supabase_upsert_failed: ${await up.text()}`);
      upserts += batch.length;
    }

    return json(res, 200, { ok:true, upserts, filtered: filtered.length, followers_fetched: followersFetched });
  },

  /* ---------- watch/check-updates (POST, internal) ---------- */
  "watch/check-updates": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    if (!checkAppSecret(req)) return bad(res, 401, "unauthorized");

    const url = new URL(req.url, `http://${req.headers.host}`);
    const qs  = Object.fromEntries(url.searchParams.entries());
    const body = await readBody(req);
    if (!body.connection_id) return bad(res, 400, "missing_connection_id");

    // cooldown?
    const cdR = await sb(`/rest/v1/connection_rl_state?select=cooldown_until&connection_id=eq.${encodeURIComponent(body.connection_id)}&limit=1`);
    const cdA = await cdR.json();
    const cd = cdA?.[0]?.cooldown_until ? new Date(cdA[0].cooldown_until) : null;
    if (cd && cd > new Date()) return json(res, 200, { ok:true, skipped:true, reason:"cooldown", until: cd.toISOString() });

    const order = encodeURIComponent("next_check_at.asc.nullsfirst");
    const sel = await sb(
      `/rest/v1/playlists?select=id,playlist_id,snapshot_id,next_check_at,last_snapshot_checked_at,error_count` +
      `&connection_id=eq.${encodeURIComponent(body.connection_id)}` +
      `&is_owner=is.true&is_public=is.true` +
      `&or=(next_check_at.is.null,next_check_at.lte.${encodeURIComponent(new Date().toISOString())})` +
      `&order=${order}&limit=${encodeURIComponent(qs.limit || "200")}`
    );
    if (!sel.ok) return bad(res, 500, `supabase_select_failed: ${await sel.text()}`);
    const rows = await sel.json();
    if (rows.length === 0) return json(res, 200, { ok:true, checked:0, updated:0, marked:0 });

    const token = await getAccessTokenFromConnection(body.connection_id);
    let marked = 0, updated = 0, checked = 0, got429 = false, retryAfter = 1;

    let i = 0, running = 0, conc = Number(qs.concurrency || "4");
    await new Promise((resolve) => {
      const kick = () => {
        while (running < conc && i < rows.length && !got429) {
          const row = rows[i++]; running++;
          (async () => {
            try {
              const r = await fetch(
                `https://api.spotify.com/v1/playlists/${encodeURIComponent(row.playlist_id)}?fields=snapshot_id`,
                { headers: { Authorization: `Bearer ${token}` } }
              );
              if (r.status === 429) {
                got429 = true; retryAfter = Number(r.headers.get("retry-after") || "5");
              } else {
                const j = await r.json().catch(() => ({}));
                if (r.ok) {
                  const current = j?.snapshot_id || null;
                  const changed = current && row.snapshot_id && current !== row.snapshot_id;
                  const nowIso = new Date().toISOString();
                  const nextIso = new Date(Date.now() + (changed ? 5*60*1000 : 15*60*1000)).toISOString();
                  const patch = { last_snapshot_checked_at: nowIso, next_check_at: nextIso };
                  if (current && current !== row.snapshot_id) { patch.needs_sync = true; marked++; }
                  const up = await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(row.id)}`, {
                    method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify(patch)
                  });
                  if (up.ok) updated++; checked++;
                } else {
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
      await sb(`/rest/v1/connection_rl_state`, {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates" },
        body: JSON.stringify({ connection_id: body.connection_id, cooldown_until: until })
      });
      return json(res, 200, { ok:true, hit_429:true, retry_after: retryAfter, set_cooldown_until: until, checked, marked, updated });
    }
    return json(res, 200, { ok:true, checked, marked, updated });
  },

  /* ---------- watch/sync-needed (POST, internal) ---------- */
  "watch/sync-needed": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    if (!checkAppSecret(req)) return bad(res, 401, "unauthorized");

    const url = new URL(req.url, `http://${req.headers.host}`);
    const qs  = Object.fromEntries(url.searchParams.entries());
    const body = await readBody(req);
    if (!body.connection_id) return bad(res, 400, "missing_connection_id");

    const r = await sb(`/rest/v1/playlists?select=id&connection_id=eq.${encodeURIComponent(body.connection_id)}&needs_sync=is.true&limit=${encodeURIComponent(qs.limit || "50")}`);
    if (!r.ok) return bad(res, 500, `supabase_select_failed: ${await r.text()}`);
    const rows = await r.json();
    if (rows.length === 0) return json(res, 200, { ok:true, synced:0 });

    const base = process.env.PUBLIC_BASE_URL || `https://${process.env.VERCEL_URL}`;
    if (!base) return bad(res, 500, "missing PUBLIC_BASE_URL/VERCEL_URL");
    const syncUrl = `${base}/api/playlists/sync-items`;

    let i=0, running=0, conc=Number(qs.concurrency || "3"), synced=0, failed=0;
    await new Promise((resolve) => {
      const kick = () => {
        while (running < conc && i < rows.length) {
          const row = rows[i++]; running++;
          (async () => {
            try {
              const resp = await fetch(syncUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json", "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
                body: JSON.stringify({ playlist_row_id: row.id })
              });
              if (resp.ok) {
                await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(row.id)}`, {
                  method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ needs_sync: false })
                });
                synced++;
              } else { failed++; }
              await sleep(80);
            } catch { failed++; }
            finally { running--; kick(); }
          })();
        }
        if (running === 0 && i >= rows.length) resolve();
      };
      kick();
    });

    return json(res, 200, { ok:true, synced, failed });
  },

  /* ---------- watch/cron-check-all (GET/POST) ---------- */
  "watch/cron-check-all": async (req, res) => {
    if (!checkCronAuth(req)) return bad(res, 401, "unauthorized_cron");
    const url = new URL(req.url, `http://${req.headers.host}`);
    const qs  = Object.fromEntries(url.searchParams.entries());

    const conns = await sb(`/rest/v1/spotify_connections?select=id`).then(r=>r.json());
    let ok=0, fail=0;
    for (const c of conns) {
      const resp = await routes["watch/check-updates"](
        { ...req, method:"POST", headers: { ...req.headers, "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" }, url: req.url, query: req.query, body: { connection_id: c.id } },
        { status: ()=>({ json: ()=>{} }) } // dummy, we won't use
      ).catch(()=>({ ok:false }));
      resp?.ok ? ok++ : fail++;
      await sleep(80);
    }
    return json(res, 200, { ok:true, connections: conns.length, dispatched_ok: ok, dispatched_fail: fail });
  },

  /* ---------- watch/cron-sync-all (GET/POST) ---------- */
  "watch/cron-sync-all": async (req, res) => {
    if (!checkCronAuth(req)) return bad(res, 401, "unauthorized_cron");
    const url = new URL(req.url, `http://${req.headers.host}`);
    const qs  = Object.fromEntries(url.searchParams.entries());

    const conns = await sb(`/rest/v1/spotify_connections?select=id`).then(r=>r.json());
    let ok=0, fail=0;
    for (const c of conns) {
      const resp = await routes["watch/sync-needed"](
        { ...req, method:"POST", headers: { ...req.headers, "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" }, url: req.url, query: req.query, body: { connection_id: c.id } },
        { status: ()=>({ json: ()=>{} }) }
      ).catch(()=>({ ok:false }));
      resp?.ok ? ok++ : fail++;
      await sleep(80);
    }
    return json(res, 200, { ok:true, connections: conns.length, dispatched_ok: ok, dispatched_fail: fail });
  },

  /* ---------- watch/cron-all (GET/POST) ---------- */
  "watch/cron-all": async (req, res) => {
    const valid = checkAppSecret(req) || checkCronAuth(req);
    if (!valid) return bad(res, 401, "unauthorized_cron");

    const out1 = await routes["watch/cron-check-all"](req, { status: ()=>({ json: ()=>{} }) }).catch(e=>({ error:String(e) }));
    const out2 = await routes["watch/cron-sync-all"](req, { status: ()=>({ json: ()=>{} }) }).catch(e=>({ error:String(e) }));
    if (out1?.error || out2?.error) return bad(res, 500, "cron_error");
    return json(res, 200, { ok:true, check: out1, sync: out2 });
  },

  /* ---------- locks/set (POST, Bubble) ---------- */
  "locks/set": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "Method not allowed");
    const bubbleUserId = req.headers["x-bubble-user-id"];
    if (!bubbleUserId) return bad(res, 401, "Missing X-Bubble-User-Id");

    // user exists?
    const usr = await sb(`/rest/v1/app_users?select=bubble_user_id&limit=1&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`).then(r=>r.json());
    if (!usr?.[0]) return bad(res, 401, "Unknown bubble_user_id");

    const { playlist_id, track_id, locked_position, is_locked = true } = await readBody(req);
    if (!playlist_id || !track_id || !locked_position) return bad(res, 400, "Missing playlist_id, track_id or locked_position");

    // ownership
    const own = await sb(`/rest/v1/playlists?select=id&limit=1&id=eq.${encodeURIComponent(String(playlist_id))}&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`).then(r=>r.json());
    if (!own?.[0]) return bad(res, 403, "Playlist not owned by user");

    // upsert lock
    const up = await sb(`/rest/v1/playlist_item_locks?on_conflict=playlist_id,track_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=representation" },
      body: JSON.stringify([{
        playlist_id,
        track_id,
        locked_position: Number(locked_position),
        is_locked: !!is_locked,
        locked_at: new Date().toISOString()
      }]),
    });
    if (!up.ok) return bad(res, 500, `supabase_upsert_failed: ${await up.text()}`);
    const data = await up.json();
    return json(res, 200, { ok:true, lock: Array.isArray(data) ? data[0] : data });
  },

  /* ---------- locks/unset (POST, Bubble) ---------- */
  "locks/unset": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "Method not allowed");
    const bubbleUserId = req.headers["x-bubble-user-id"];
    if (!bubbleUserId) return bad(res, 401, "Missing X-Bubble-User-Id");

    const usr = await sb(`/rest/v1/app_users?select=bubble_user_id&limit=1&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`).then(r=>r.json());
    if (!usr?.[0]) return bad(res, 401, "Unknown bubble_user_id");

    const { playlist_id, track_id } = await readBody(req);
    if (!playlist_id || !track_id) return bad(res, 400, "Missing playlist_id or track_id");

    const own = await sb(`/rest/v1/playlists?select=id&limit=1&id=eq.${encodeURIComponent(String(playlist_id))}&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`).then(r=>r.json());
    if (!own?.[0]) return bad(res, 403, "Playlist not owned by user");

    const del = await sb(`/rest/v1/playlist_item_locks?playlist_id=eq.${encodeURIComponent(playlist_id)}&track_id=eq.${encodeURIComponent(track_id)}`, {
      method: "DELETE", headers: { Prefer: "return=minimal" }
    });
    if (!del.ok) return bad(res, 500, `supabase_delete_failed: ${await del.text()}`);
    return json(res, 200, { ok:true });
  },

  /* ---------- playlists/enforce (POST, server/cron) ---------- */
  "playlists/enforce": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "Method not allowed");
    // Optional: Secret-Gate
    // if (req.headers["x-service-key"] !== process.env.INTERNAL_SERVICE_KEY) return bad(res, 401, "Unauthorized");
    const { playlist_id } = await readBody(req);
    if (!playlist_id) return bad(res, 400, "Missing playlist_id");

    // Cleanup Missing Locks (SQL Funktion) – via RPC oder einfache DELETE (wie zuvor)
    // Hier: nutzt eure DB-Funktion, falls vorhanden:
    await fetch(`${process.env.SUPABASE_URL}/rest/v1/rpc/locks_cleanup_missing_tracks`, {
      method: "POST",
      headers: {
        apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ p_playlist_id: playlist_id }),
    }).catch(()=>{ /* ignorierbar, wenn RPC nicht existiert */ });

    // Deine bestehende serverseitige Enforce-Logik (Node) kann hier aufgerufen werden.
    // Falls ihr sie (noch) in lib/enforce.js habt, könnt ihr sie leicht nach REST portieren.
    // Placeholder: Erfolg zurückgeben (ersetzbar durch echte Logik)
    return json(res, 200, { ok:true, enforced: true, playlist_id });
  },

  /* ---------- playlists/mark-sync-needed (POST, secret) ---------- */
  "playlists/mark-sync-needed": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    if (process.env.APP_WEBHOOK_SECRET) {
      const got = req.headers["x-app-secret"];
      if (got !== process.env.APP_WEBHOOK_SECRET) return bad(res, 401, "unauthorized");
    }
    const body = await readBody(req);
    const { playlist_id } = body;
    if (!playlist_id) return bad(res, 400, "missing_playlist_id");

    const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
    const r = await fetch(`${SUPABASE_URL}/rest/v1/playlists?id=eq.${encodeURIComponent(playlist_id)}`, {
      method: 'PATCH',
      headers: {
        apikey: SRK, 
        Authorization: `Bearer ${SRK}`,
        'Content-Type': 'application/json', 
        Prefer: 'return=minimal'
      },
      body: JSON.stringify({ needs_sync: true })
    });
    if (!r.ok) return bad(res, 500, `supabase_patch_failed: ${await r.text()}`);
    return json(res, 200, { ok: true });
  },

  /* ---------- playlists/dispatch-sync (POST, secret) ---------- */
  "playlists/dispatch-sync": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    if (process.env.APP_WEBHOOK_SECRET) {
      const got = req.headers["x-app-secret"];
      if (got !== process.env.APP_WEBHOOK_SECRET) return bad(res, 401, "unauthorized");
    }
    const body = await readBody(req);
    const { playlist_id } = body;
    if (!playlist_id) return bad(res, 400, "missing_playlist_id");

    // pg_net-Aufruf an Supabase: ruft asynchron deinen /api/playlists/sync-items Endpoint auf
    const base = process.env.PUBLIC_BASE_URL || `https://${process.env.VERCEL_URL}`;
    const targetUrl = `${base}/api/playlists/sync-items`;
    const syncBody = JSON.stringify({ playlist_row_id: playlist_id });

    const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK, APP_WEBHOOK_SECRET } = process.env;
    // net.http_post einmalig starten – nicht darauf warten, dass der Sync fertig ist
    const r = await fetch(`${SUPABASE_URL}/rest/v1/rpc/net_http_post`, {
      method: 'POST',
      headers: { 
        apikey: SRK, 
        Authorization: `Bearer ${SRK}`, 
        'Content-Type': 'application/json' 
      },
      body: JSON.stringify({
        url: targetUrl,
        headers: JSON.stringify({ 
          'Content-Type': 'application/json', 
          'x-app-secret': APP_WEBHOOK_SECRET 
        }),
        body: syncBody
      })
    });

    // Wir erwarten 200 von rpc-Aufruf; selbst wenn der spätere Sync 10–60s läuft, ist dieser Call sofort fertig
    if (!r.ok) return bad(res, 500, `pg_net_http_post_failed: ${await r.text()}`);

    return json(res, 202, { ok: true, dispatched: true });
  },

  /* ---------- ping ---------- */
  "watch/ping": async (_req, res) => json(res, 200, { ok: true }),
};

/* ==============================
   Dispatcher
============================== */
export default withCORS(async function handler(req, res) {
  try {
    const path = Array.isArray(req.query.task) ? req.query.task : [];
    const key = path.join("/"); // e.g., 'locks/set'
    const handler = routes[key];
    if (!handler) return bad(res, 404, `Unknown route: /api/${key}`);
    return await handler(req, res);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: String(e?.message || e) });
  }
});
