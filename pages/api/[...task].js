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
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,X-Bubble-User-Id,x-app-secret,x-service-key,x-bubble-user-id");
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


function parseSpotifyTrack(input) {
  const v = String(input || "").trim();
  if (!v) return null;

  const BASE62_22 = /^[A-Za-z0-9]{22}$/;

  // spotify:track:<id>
  if (v.startsWith("spotify:")) {
    const parts = v.split(":");
    if (parts[1] === "track" && BASE62_22.test(parts[2])) {
      return { id: parts[2], uri: `spotify:track:${parts[2]}` };
    }
    return null;
  }

  // reine ID erlauben
  if (BASE62_22.test(v)) {
    return { id: v, uri: `spotify:track:${v}` };
  }

  // URL-Formate (inkl. /intl-xx/, /embed/, Query-Params)
  let u;
  try { u = new URL(v); }
  catch {
    try { u = new URL("https://" + v); }
    catch { return null; }
  }

  const hostOk = /(^|\.)spotify\.com$/i.test(u.hostname);
  if (!hostOk) return null;

  const parts = u.pathname.split("/").filter(Boolean);
  // Locale-Prefixe wie intl-de, intl-en, intl-de-de entfernen
  if (parts[0] && /^intl-/i.test(parts[0])) parts.shift();
  // /embed/track/<id> unterstützen
  if (parts[0] === "embed") parts.shift();

  if (parts[0] !== "track") return null;
  const id = parts[1];
  if (!BASE62_22.test(id)) return null;

  return { id, uri: `spotify:track:${id}` };
}


function parseTrackId(input) {
  const s = String(input || "").trim();
  if (!s) return null;
  let m;
  if ((m = s.match(/spotify:track:([A-Za-z0-9]{22})/))) return m[1];
  if ((m = s.match(/open\.spotify\.com\/(?:intl-[a-z]+\/)?track\/([A-Za-z0-9]{22})/))) return m[1];
  if (/^[A-Za-z0-9]{22}$/.test(s)) return s;
  return null;
}
const trackUri = (id) => `spotify:track:${id}`;

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
  const { r, json, text } = await fetchJSON("https://accounts.spotify.com/api/token", {
    method:"POST",
    headers:{ "Content-Type":"application/x-www-form-urlencoded" },
    body
  }, 20000); // 20s Timeout

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


// --- resilient fetch helpers ---
function withTimeout(ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  return { signal: ctrl.signal, clear: () => clearTimeout(t) };
}

async function fetchJSON(url, init={}, timeoutMs=20000) {
  const { signal, clear } = withTimeout(timeoutMs);
  try {
    const r = await fetch(url, { ...init, signal });
    const { json, text } = await parseJsonSafe(r);
    return { r, json, text };
  } finally { clear(); }
}

async function fetchText(url, init={}, timeoutMs=20000) {
  const { signal, clear } = withTimeout(timeoutMs);
  try {
    const r = await fetch(url, { ...init, signal });
    const t = await r.text();
    return { r, text: t };
  } finally { clear(); }
}

async function setConnectionCooldown(connection_id, seconds) {
  const until = new Date(Date.now() + Math.max(1, seconds) * 1000).toISOString();
  await sb(`/rest/v1/connection_rl_state`, {
    method: "POST",
    headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify({ connection_id, cooldown_until: until })
  }).catch(()=>{});
  return until;
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


   /* ---------- dashboard/expiring-next (GET) ---------- */
   "dashboard/expiring-next": async (req, res) => {
     if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
     const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
     if (!SUPABASE_URL || !SRK) return bad(res, 500, "missing_env");
   
     const bubble_user_id = req.query.bubble_user_id;
     if (!bubble_user_id) return bad(res, 400, "missing_bubble_user_id");
   
     const limit = Math.max(1, Math.min(100, Number(req.query.limit || "10")));
     const connection_id = req.query.connection_id || null; // optional: Filter auf einen Account
   
     // RPC aufrufen
     const r = await fetch(`${SUPABASE_URL}/rest/v1/rpc/dashboard_expiring_next`, {
       method: "POST",
       headers: {
         apikey: SRK,
         Authorization: `Bearer ${SRK}`,
         "Content-Type": "application/json",
         Prefer: "return=representation"
       },
       body: JSON.stringify({
         p_bubble_user_id: String(bubble_user_id),
         p_limit: limit,
         p_connection_id: connection_id
       })
     });
   
     const txt = await r.text();
     if (!r.ok) return json(res, 500, { error: "rpc_failed", status: r.status, body: txt });
     const rows = txt ? JSON.parse(txt) : [];
   
     // kleine Sicherung: niemals negative Tage anzeigen
     for (const row of rows) {
       if (typeof row.days_until_remove === "number" && row.days_until_remove < 0) {
         row.days_until_remove = 0;
       }
     }
   
     return json(res, 200, rows);
   },
   
   
      
   /* ---------- dashboard/cards (GET) ----------
   Query:
     bubble_user_id (required)
     range: 'd'|'w'|'m'|'y'  -> 1/7/30/365 Tage
     scope (optional): 'all' | 'public' | 'owned'  (default: 'all')
   */
   "dashboard/cards": async (req, res) => {
     if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
   
     const bubble_user_id = req.query.bubble_user_id;
     const range = String(req.query.range || "d").toLowerCase();
     const scope = String(req.query.scope || "all").toLowerCase();
   
     if (!bubble_user_id) return bad(res, 400, "missing_bubble_user_id");
   
     const days =
       range === "y" ? 365 :
       range === "m" ? 30  :
       range === "w" ? 7   : 1;
   
     // Baseline-Schwelle (YYYY-MM-DD) = "heute minus days"
     const threshold = new Date(Date.now() - days * 86400 * 1000)
       .toISOString()
       .slice(0, 10);
   
     // --- 1) aktuelle Playlists des Users (robust; scope steuerbar) ---
     const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
   
     let filt =
       `?select=id,name,followers` +
       `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}`;
   
     if (scope === "public") {
       filt += `&is_public=is.true`;
     } else if (scope === "owned") {
       filt += `&is_owner=is.true`; // owned (egal ob public/private)
     } // 'all' = nur bubble_user_id
   
     const pathNow = `/rest/v1/playlists${filt}&order=updated_at.desc`;
   
     const nowR = await fetch(SUPABASE_URL + pathNow, {
       headers: { apikey: SRK, Authorization: `Bearer ${SRK}` }
     });
     const nowArr = await nowR.json().catch(() => []);
     if (!nowR.ok) return bad(res, 500, `supabase_now_failed: ${JSON.stringify(nowArr)}`);
   
     const ids = nowArr.map(x => x.id).filter(Boolean);
     let baselineById = new Map();
   
     // --- 2) Baseline je Playlist = letzter Wert <= threshold ---
     if (ids.length > 0) {
       // PostgREST IN()-Syntax: in.(uuid1,uuid2,...) ohne Anführungszeichen
       const inList = `(${ids.join(",")})`;
   
       // 2a) Primär: aus playlist_followers_history
       const pathHist =
         `/rest/v1/playlist_followers_history` +
         `?select=playlist_id,day,followers` +
         `&playlist_id=in.${encodeURIComponent(inList)}` +
         `&day=lte.${encodeURIComponent(threshold)}` +
         `&order=playlist_id.asc,day.desc`;
   
       const histR = await fetch(SUPABASE_URL + pathHist, {
         headers: { apikey: SRK, Authorization: `Bearer ${SRK}` }
       });
       const histArr = await histR.json().catch(() => []);
       if (!histR.ok) return bad(res, 500, `supabase_hist_failed: ${JSON.stringify(histArr)}`);
   
       for (const row of histArr) {
         // aufgrund der Sortierung ist das erste Auftreten pro playlist_id der jüngste Wert <= threshold
         if (!baselineById.has(row.playlist_id)) {
           baselineById.set(row.playlist_id, row.followers ?? 0);
         }
       }
   
       // 2b) Fallback: falls History leer → versuche playlist_followers_daily
       if (baselineById.size === 0) {
         const pathDaily =
           `/rest/v1/playlist_followers_daily` +
           `?select=playlist_id,day,followers` +
           `&playlist_id=in.${encodeURIComponent(inList)}` +
           `&day=lte.${encodeURIComponent(threshold)}` +
           `&order=playlist_id.asc,day.desc`;
   
         const dailyR = await fetch(SUPABASE_URL + pathDaily, {
           headers: { apikey: SRK, Authorization: `Bearer ${SRK}` }
         });
         const dailyArr = await dailyR.json().catch(() => []);
         if (!dailyR.ok) return bad(res, 500, `supabase_daily_failed: ${JSON.stringify(dailyArr)}`);
   
         for (const row of dailyArr) {
           if (!baselineById.has(row.playlist_id)) {
             baselineById.set(row.playlist_id, row.followers ?? 0);
           }
         }
       }
     }
   
     // --- 3) KPIs berechnen ---
     let totalCurrent = 0;
     let totalBaseline = 0;
     const playlistsCount = nowArr.length;
   
     let topFollower = null; // {id,name,current,delta}
     let topNew = null;      // {id,name,current,delta}
   
     for (const p of nowArr) {
       const current = Number(p.followers || 0);
       const baseline = Number(baselineById.get(p.id) ?? current); // kein Baseline-Wert → delta 0
       const delta = current - baseline;
   
       totalCurrent += current;
       totalBaseline += baseline;
   
       if (!topFollower || current > topFollower.current) {
         topFollower = { id: p.id, name: p.name, current, delta };
       }
       if (!topNew || delta > topNew.delta) {
         topNew = { id: p.id, name: p.name, current, delta };
       }
     }
   
     const pctChange =
       totalBaseline > 0
         ? ((totalCurrent - totalBaseline) * 100.0) / totalBaseline
         : null;
   
     // kleine Debug-Hilfe zurückgeben, um zu verifizieren, dass "now" überhaupt Zeilen sieht
     const debug_counts = {
       playlists_seen: Array.isArray(nowArr) ? nowArr.length : 0,
       scope
     };
   
     return json(res, 200, {
       ok: true,
       range: { key: range, days },
       totals: {
         total_followers: totalCurrent,
         pct_change: pctChange,                 // z. B. 3.5 (%)
         total_new_followers: totalCurrent - totalBaseline,
         playlists_count: playlistsCount
       },
       top_playlist_follower: topFollower,      // {id,name,current,delta} oder null
       top_playlist_new_followers: topNew,      // {id,name,current,delta} oder null
       debug_counts                                // hilft beim Troubleshooting
     });
   },

   
   
      
   /* ---------- dashboard/series (GET) ---------- */
   // Query:
   //   bubble_user_id=...          (required)
   //   days=30                     (optional)
   //   granularity=daily|weekly|monthly  (optional; default daily)
   //   scope=total|by_playlist     (optional; default total)
   "dashboard/series": async (req, res) => {
     if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
     const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
     if (!SUPABASE_URL || !SRK) return bad(res, 500, "missing_env");
   
     const bubble_user_id = req.query.bubble_user_id;
     if (!bubble_user_id) return bad(res, 400, "missing_bubble_user_id");
   
     const days = Math.max(1, Math.min(365, Number(req.query.days || "30")));
     const gran = (req.query.granularity || "daily").toLowerCase(); // daily|weekly|monthly
     const scope = (req.query.scope || "total").toLowerCase();       // total|by_playlist
   
     const fromDay = new Date(Date.now() - days*24*3600*1000);
     const fromStr = fromDay.toISOString().slice(0,10);
   
     const snapPath =
       `/rest/v1/playlist_followers_daily` +
       `?select=playlist_id,day,followers` +
       `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
       `&day=gte.${encodeURIComponent(fromStr)}` +
       `&order=day.asc`;
     const sResp = await fetch(SUPABASE_URL + snapPath, { headers: { apikey: SRK, Authorization: `Bearer ${SRK}` }, cache: "no-store" });
     if (!sResp.ok) return bad(res, 500, `supabase_error: ${await sResp.text()}`);
     const rows = JSON.parse(await sResp.text() || "[]");
   
     // Helper: bucket nach granularity
     const bucketKey = (isoDay) => {
       // isoDay = "YYYY-MM-DD"
       if (gran === "weekly") {
         // ISO week Montag: wir normalisieren auf die Montag-Datum
         const d = new Date(isoDay + "T00:00:00Z");
         const day = d.getUTCDay(); // So=0..Sa=6
         const diffToMon = (day === 0 ? -6 : 1 - day);
         const monday = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + diffToMon));
         return monday.toISOString().slice(0,10);
       }
       if (gran === "monthly") {
         return isoDay.slice(0,7) + "-01"; // erster des Monats
       }
       return isoDay;
     };
   
     // Aggregiere Followers TOTAL pro Bucket (Summe über Playlists),
     // danach in Growth (Delta zum vorherigen Bucket) umrechnen
     const agg = new Map(); // key -> { followersTotalByPlaylist?:Map, followersTotal }
     for (const r of rows) {
       const k = bucketKey(r.day);
       let o = agg.get(k);
       if (!o) { o = { followersTotal: 0, byPl: new Map() }; agg.set(k, o); }
       // wir nehmen den letzten Wert pro playlist_id im Bucket als "Stand"
       o.byPl.set(r.playlist_id, r.followers);
     }
     // jetzt pro Bucket Summen bilden
     for (const [, o] of agg) {
       let sum = 0;
       for (const v of o.byPl.values()) sum += v || 0;
       o.followersTotal = sum;
     }
   
     // sortierte Buckets
     const labels = Array.from(agg.keys()).sort();
     // Growth total:
     const growth = [];
     for (let i = 0; i < labels.length; i++) {
       const curr = agg.get(labels[i]).followersTotal;
       const prev = i ? agg.get(labels[i-1]).followersTotal : curr;
       growth.push(curr - prev);
     }
   
     if (scope === "total") {
       return json(res, 200, {
         ok: true,
         granularity: gran,
         labels,               // z.B. Tage/Wochen/Monate
         growth,               // Delta followers pro Bucket (gesamt)
       });
     }
   
     // by_playlist: Growth je Playlist (für z.B. gestapelte Graphen)
     // Wir berechnen je Playlist die Buckets (letzter Followers-Wert je Bucket), dann Delta
     const byPlMap = new Map(); // playlist_id -> array followersByBucket
     const plIds = new Set(rows.map(r => r.playlist_id));
     for (const pid of plIds) {
       const series = [];
       for (const k of labels) {
         const o = agg.get(k);
         const v = o.byPl.get(pid);
         // falls im Bucket kein Wert, nimm letzten bekannten (carry-forward)
         const last = series.length ? series[series.length-1] : (v ?? 0);
         series.push(v ?? last ?? 0);
       }
       byPlMap.set(pid, series);
     }
     const by_playlist = [];
     for (const [pid, series] of byPlMap) {
       const deltas = series.map((v, i) => i ? (v - series[i-1]) : 0);
       by_playlist.push({ playlist_id: pid, growth: deltas });
     }
   
     return json(res, 200, { ok: true, granularity: gran, labels, by_playlist });
   },
   
      
/* ---------- dashboard/summary (GET) ---------- */
// Query:
//   bubble_user_id=...            (required)
//   days=7                        (optional; für Growth-Spanne)
//   removals_limit=50             (optional)
"dashboard/summary": async (req, res) => {
  if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
  if (!SUPABASE_URL || !SRK) return bad(res, 500, "missing_env");

  const bubble_user_id = req.query.bubble_user_id;
  if (!bubble_user_id) return bad(res, 400, "missing_bubble_user_id");

  const days = Math.max(1, Math.min(365, Number(req.query.days || "7")));
  const removals_limit = Math.max(1, Math.min(500, Number(req.query.removals_limit || "50")));

  // 1) aktuelle Playlists ziehen (für total followers + Namen)
  const plistPath =
    `/rest/v1/playlists?select=id,name,followers,image,tracks_total,connection_id` +
    `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
    `&is_owner=is.true&is_public=is.true`;
  const pResp = await fetch(SUPABASE_URL + plistPath, { headers: { apikey: SRK, Authorization: `Bearer ${SRK}` }, cache: "no-store" });
  const playlists = pResp.ok ? JSON.parse(await pResp.text() || "[]") : [];
  const total_followers = playlists.reduce((a, p) => a + (p.followers || 0), 0);

  // 2) Growth über N Tage: minimaler/ maximaler Snapshot pro Playlist vergleichen
  const fromDay = new Date(Date.now() - days*24*3600*1000);
  const fromStr = fromDay.toISOString().slice(0,10); // YYYY-MM-DD

  const snapPath =
    `/rest/v1/playlist_followers_daily` +
    `?select=playlist_id,day,followers` +
    `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
    `&day=gte.${encodeURIComponent(fromStr)}` +
    `&order=day.asc`;
  const sResp = await fetch(SUPABASE_URL + snapPath, { headers: { apikey: SRK, Authorization: `Bearer ${SRK}` }, cache: "no-store" });
  const snaps = sResp.ok ? JSON.parse(await sResp.text() || "[]") : [];

  // map: playlist_id -> {firstFollowers, lastFollowers}
  const snapMap = new Map();
  for (const r of snaps) {
    let o = snapMap.get(r.playlist_id);
    if (!o) { o = { first: r.followers, last: r.followers }; snapMap.set(r.playlist_id, o); }
    o.last = r.followers; // wegen day.asc ist die letzte Zeile am Ende
  }

  let top_growing = null;
  let net_growth = 0;
  for (const p of playlists) {
    const s = snapMap.get(p.id);
    const delta = s ? (s.last - s.first) : 0;
    net_growth += delta;
    if (!top_growing || delta > top_growing.delta) {
      top_growing = { playlist_id: p.id, name: p.name, image: p.image, delta, followers_now: p.followers || 0 };
    }
  }

  // 3) Morgen entfernte Tracks (UTC)
  const tomorrow = new Date(Date.now() + 24*3600*1000);
  const tomStr = tomorrow.toISOString().slice(0,10);
  const upcPath =
    `/rest/v1/upcoming_removals_ui` +
    `?select=playlist_id,playlist_name,position,track_id,track_name,artist_names,added_at,auto_remove_weeks,removes_on` +
    `&removes_on=eq.${encodeURIComponent(tomStr)}` +
    `&playlist_id=in.(${playlists.map(p => `"${p.id}"`).join(",")})` +
    `&limit=${removals_limit}`;
  const uResp = await fetch(SUPABASE_URL + upcPath, { headers: { apikey: SRK, Authorization: `Bearer ${SRK}` }, cache: "no-store" });
  const next_day_removals = uResp.ok ? JSON.parse(await uResp.text() || "[]") : [];

  return json(res, 200, {
    ok: true,
    totals: {
      playlists_count: playlists.length,
      total_followers,
      net_growth_last_days: net_growth
    },
    top_growing: top_growing || null,
    next_day_removals: next_day_removals
  });
},



  /* ---------- search (GET) ---------- */

   "tracks/search": async (req, res) => {
     if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
     const q = req.query.q || "";
     const connection_id = req.query.connection_id || "";
     const limit = Math.min(25, Number(req.query.limit || "10"));
   
     if (!q || !connection_id) return bad(res, 400, "missing_q_or_connection_id");
   
     try {
       const token = await getAccessTokenFromConnection(connection_id);
       const url = `https://api.spotify.com/v1/search?type=track&market=from_token&limit=${encodeURIComponent(
         String(limit)
       )}&q=${encodeURIComponent(q)}`;
   
       const { r, json, text } = await fetchJSON(url, {
         headers: { Authorization: `Bearer ${token}` },
       }, 20000);
   
       if (!r.ok) {
         return bad(res, r.status, `spotify_search_failed: ${json ? JSON.stringify(json) : text}`);
       }
   
       const items = (json?.tracks?.items || []).map((t) => ({
         id: t.id,
         uri: t.uri,
         name: t.name,
         artists: (t.artists || []).map((a) => a.name).join(", "),
         album: t.album?.name || null,
         duration_ms: t.duration_ms ?? null,
         preview_url: t.preview_url || null,
         cover_url: t.album?.images?.[0]?.url || null,
       }));
   
       return json(res, 200, { items });
     } catch (e) {
       return bad(res, 500, `tracks_search_exception: ${String(e?.message || e)}`);
     }
   },

  /* ---------- resolve (GET) ---------- */
   
   "tracks/resolve": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     const body = await readBody(req);
     const input = body.input || "";
     const connection_id = body.connection_id || "";
     const wantCandidates = Math.max(0, Math.min(25, Number(body.candidates ?? req.query.candidates ?? 8)));
   
     let id = parseTrackId(input);
   
     try {
       // Wenn id erkennbar: hol Meta (wenn connection da) + parallele Kandidaten-Suche optional
       if (id) {
         let meta = null, candidates = [];
         if (connection_id) {
           const token = await getAccessTokenFromConnection(connection_id);
   
           // Track-Meta
           const metaReq = fetchJSON(
             `https://api.spotify.com/v1/tracks/${encodeURIComponent(id)}`,
             { headers: { Authorization: `Bearer ${token}` } },
             20000
           );
   
           // Kandidaten (freie Suche nach demselben Input) – optional
           let candReq = null;
           if (wantCandidates > 0) {
             candReq = fetchJSON(
               `https://api.spotify.com/v1/search?type=track&market=from_token&limit=${encodeURIComponent(String(wantCandidates))}&q=${encodeURIComponent(input)}`,
               { headers: { Authorization: `Bearer ${token}` } },
               20000
             );
           }
   
           const metaRes = await metaReq;
           if (metaRes.r.ok) meta = metaRes.json;
   
           if (candReq) {
             const candRes = await candReq;
             if (candRes.r.ok) {
               candidates = (candRes.json?.tracks?.items || []).map((t) => ({
                 id: t.id, uri: t.uri, name: t.name,
                 artists: (t.artists||[]).map(a=>a.name).join(", "),
                 album: t.album?.name || null,
                 cover_url: t.album?.images?.[0]?.url || null,
                 duration_ms: t.duration_ms ?? null
               }));
             }
           }
         }
   
         return json(res, 200, {
           track_id: id,
           track_uri: trackUri(id),
           ...(meta ? {
             name: meta.name,
             artists: (meta.artists||[]).map(a=>a.name).join(", "),
             album: meta.album?.name || null,
             cover_url: meta.album?.images?.[0]?.url || null,
             duration_ms: meta.duration_ms ?? null
           } : {}),
           candidates
         });
       }
   
       // Keine ID => Fallback Suche (liefert best + candidates)
       if (!connection_id) return bad(res, 400, "unrecognized_input_and_no_connection");
   
       const token = await getAccessTokenFromConnection(connection_id);
       const url = `https://api.spotify.com/v1/search?type=track&market=from_token&limit=${encodeURIComponent(String(Math.max(1, wantCandidates)))}&q=${encodeURIComponent(input)}`;
       const { r, json, text } = await fetchJSON(url, { headers: { Authorization: `Bearer ${token}` } }, 20000);
       if (!r.ok) return bad(res, r.status, `search_failed: ${json ? JSON.stringify(json) : text}`);
   
       const all = (json?.tracks?.items || []).map((t) => ({
         id: t.id, uri: t.uri, name: t.name,
         artists: (t.artists||[]).map(a=>a.name).join(", "),
         album: t.album?.name || null,
         cover_url: t.album?.images?.[0]?.url || null,
         duration_ms: t.duration_ms ?? null
       }));
       if (all.length === 0) return bad(res, 404, "no_match");
   
       return json(res, 200, {
         track_id: all[0].id,
         track_uri: trackUri(all[0].id),
         name: all[0].name,
         artists: all[0].artists,
         album: all[0].album,
         cover_url: all[0].cover_url,
         duration_ms: all[0].duration_ms ?? null,
         candidates: all
       });
     } catch (e) {
       return bad(res, 500, `tracks_resolve_exception: ${String(e?.message || e)}`);
     }
   },


  /* ---------- playlist-items/add (POST, Bubble) ---------- */
   "playlist-items/add": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
   
     const bubbleUserId = req.headers["x-bubble-user-id"];
     if (!bubbleUserId) return bad(res, 401, "Missing X-Bubble-User-Id");
   
     try {
       const { playlist_id, link_or_uri, position } = await readBody(req);
       if (!playlist_id || !link_or_uri) {
         return bad(res, 400, "missing_playlist_id_or_link");
       }
   
       // Playlist holen + Ownership prüfen
       const pr = await sb(
         `/rest/v1/playlists?select=id,playlist_id,connection_id,bubble_user_id&limit=1&id=eq.${encodeURIComponent(playlist_id)}`
       );
       if (!pr.ok) return bad(res, 500, `supabase_select_playlist_failed: ${await pr.text()}`);
       const row = (await pr.json())?.[0];
       if (!row) return bad(res, 404, "playlist_not_found");
       if (row.bubble_user_id !== bubbleUserId) return bad(res, 403, "playlist_not_owned_by_user");
   
       // Link/URI/ID -> Track-URI parsen (unterstützt /intl-xx/, /embed/, Query, reine ID, spotify:track:…)
       const parsed = parseSpotifyTrack(link_or_uri);
       if (!parsed) return bad(res, 400, "invalid_spotify_track_link_or_uri");
       const trackUri = parsed.uri;
   
       // Access Token für die Connection ziehen
       const access_token = await getAccessTokenFromConnection(row.connection_id);
   
       // Position aus UI ist 1-basiert – Spotify erwartet 0-basiert.
       // Wenn leer/0/ungültig -> append.
       let wantPosition = null;
       if (position !== undefined && position !== null && String(position).trim() !== "") {
         const p = Number(position);
         if (Number.isFinite(p) && p > 0) wantPosition = Math.floor(p - 1);
       }
   
       const doAdd = async (posOrNull) => {
         const payload = posOrNull !== null && posOrNull !== undefined
           ? { uris: [trackUri], position: posOrNull }
           : { uris: [trackUri] };
   
         const r = await fetch(
           `https://api.spotify.com/v1/playlists/${encodeURIComponent(row.playlist_id)}/tracks`,
           {
             method: "POST",
             headers: {
               Authorization: `Bearer ${access_token}`,
               "Content-Type": "application/json"
             },
             body: JSON.stringify(payload)
           }
         );
         const { json, text } = await parseJsonSafe(r);
         return { r, json, text };
       };
   
       // 1. Versuch: mit gewünschter Position (falls angegeben)
       let addRes = await doAdd(wantPosition);
   
       // Falls 400 "Index out of bounds" -> erneut ohne position (append)
       if (addRes.r.status === 400 && String(addRes.text || "").toLowerCase().includes("index out of bounds")) {
         addRes = await doAdd(null);
       }
   
       // Minimales 429-Handling: einmal kurz warten und nochmal ohne Position probieren
       if (addRes.r.status === 429) {
         const ra = Number(addRes.r.headers.get("retry-after") || "1");
         await sleep((Math.max(1, ra) + 0.5) * 1000);
         addRes = await doAdd(null);
       }
   
       if (addRes.r.status === 404) {
         return bad(res, 404, "spotify_playlist_not_found");
       }
       if (!addRes.r.ok) {
         return bad(res, addRes.r.status, `spotify_add_failed: ${addRes.text || JSON.stringify(addRes.json)}`);
       }
   
       // Nach Erfolg: DB-Sync markieren und asynchronen Sync anstoßen
       await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(row.id)}`, {
         method: "PATCH",
         headers: { Prefer: "return=minimal" },
         body: JSON.stringify({ needs_sync: true })
       }).catch(() => {});
   
       const base = process.env.PUBLIC_BASE_URL || `https://${process.env.VERCEL_URL}`;
       await fetch(`${base}/api/playlists/dispatch-sync`, {
         method: "POST",
         headers: { "Content-Type": "application/json", "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
         body: JSON.stringify({ playlist_id: row.id })
       }).catch(() => {});
   
       return json(res, 200, {
         ok: true,
         added: trackUri,
         position_used: (wantPosition !== null && wantPosition !== undefined) ? wantPosition : "append",
         snapshot_id: addRes.json?.snapshot_id || null
       });
     } catch (e) {
       return bad(res, 500, `add_track_exception: ${e && e.stack ? e.stack : String(e)}`);
     }
   },


   
  /* ---------- playlists/get (GET) ---------- */
   
   "playlists/get": async (req, res) => {
  if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
  if (!SUPABASE_URL || !SRK) return bad(res, 500, "missing_env");

  const playlist_id = req.query.playlist_id;
  if (!playlist_id) return bad(res, 400, "missing_playlist_id");

  const path =
    `/rest/v1/playlists` +
    `?select=id,playlist_id,name,image,tracks_total,followers,updated_at,` +
    `auto_remove_enabled,auto_remove_weeks` +
    `&id=eq.${encodeURIComponent(playlist_id)}` +
    `&limit=1`;

  const r = await fetch(SUPABASE_URL + path, {
    headers: { apikey: SRK, Authorization: `Bearer ${SRK}` },
    cache: "no-store",
  });
  const txt = await r.text();
  if (!r.ok) return json(res, 500, { error:"supabase_error", status:r.status, body:txt, url: SUPABASE_URL+path });
  const arr = txt ? JSON.parse(txt) : [];
  return json(res, 200, arr[0] || null);
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
        `select=id,refresh_token_enc,cron_bucket&` +   // <-- NEU
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

      // stabilen Bucket bestimmen: vorhandenen behalten, sonst neu würfeln (0..59)
      const cron_bucket =
        Number.isInteger(existing?.cron_bucket) ? existing.cron_bucket : Math.floor(Math.random() * 60);
      
      const payload = {
        bubble_user_id,
        spotify_user_id,
        display_name,
        avatar_url,
        scope: "playlist-read-private playlist-modify-private playlist-modify-public",
        refresh_token_enc,
        access_token_enc,
        access_expires_at,
        cron_bucket, // <-- NEU
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

   /* ---------- playlists/settings/save (POST, Bubble) ---------- */
   "playlists/settings/save": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     const bubbleUserId = req.headers["x-bubble-user-id"];
     if (!bubbleUserId) return bad(res, 401, "Missing X-Bubble-User-Id");
   
     const { playlist_id, auto_remove_enabled, auto_remove_weeks } = await readBody(req);
     if (!playlist_id) return bad(res, 400, "missing_playlist_id");
   
     // Ownership prüfen
     const own = await sb(`/rest/v1/playlists?select=id&limit=1&id=eq.${encodeURIComponent(String(playlist_id))}&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`).then(r=>r.json());
     if (!own?.[0]) return bad(res, 403, "Playlist not owned by user");
   
     // Werte validieren
     const enabled = !!auto_remove_enabled;
     const weeks = (auto_remove_weeks == null || auto_remove_weeks === "") ? null : Number(auto_remove_weeks);
     if (enabled && (!Number.isInteger(weeks) || weeks < 1 || weeks > 104)) {
       return bad(res, 400, "invalid_weeks_range_1_104");
     }
   
     const patch = {
       auto_remove_enabled: enabled,
       auto_remove_weeks: weeks
     };
   
     const r = await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(playlist_id)}`, {
       method: "PATCH",
       headers: { Prefer: "return=representation" },
       body: JSON.stringify(patch),
     });
     if (!r.ok) return bad(res, 500, `supabase_patch_failed: ${await r.text()}`);
     const data = await r.json();
     return json(res, 200, { ok:true, playlist: Array.isArray(data) ? data[0] : data });
   },
   

   /* ---------- playlists/maintenance (POST, Bubble ODER Cron) ---------- */
   "playlists/maintenance": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
   
     const body = await readBody(req);
     const { playlist_id } = body;
     if (!playlist_id) return bad(res, 400, "missing_playlist_id");
   
     // Entweder Bubble-User prüft Ownership ODER interner Secret-Call:
     const bubbleUserId = req.headers["x-bubble-user-id"];
     const isInternal = checkAppSecret(req) || checkCronAuth(req);
   
     if (!isInternal) {
       if (!bubbleUserId) return bad(res, 401, "Missing X-Bubble-User-Id");
       const own = await sb(`/rest/v1/playlists?select=id&limit=1&id=eq.${encodeURIComponent(String(playlist_id))}&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`).then(r=>r.json());
       if (!own?.[0]) return bad(res, 403, "Playlist not owned by user");
     }
   
     const r = await sb(`/rest/v1/rpc/playlist_maintenance`, {
       method: "POST",
       body: JSON.stringify({ p_playlist_id: playlist_id })
     });
     const t = await r.text();
     if (!r.ok) return bad(res, 500, `rpc_playlist_maintenance_failed: ${t}`);
   
     const out = t ? JSON.parse(t) : [{ removed:0, total_after:0 }];
     return json(res, 200, { ok:true, result: out[0] || out });
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
   
     // optionales Filter fürs Dropdown (nur Playlists einer Connection anzeigen)
     const connection_id = req.query.connection_id; // optional
   
     // Felder erweitert: connection_id, auto_remove_enabled, auto_remove_weeks
     let path =
       `/rest/v1/playlists` +
       `?select=` +
         [
           "id",
           "playlist_id",
           "connection_id",
           "name",
           "image",
           "tracks_total",
           "followers",
           "updated_at",
           "auto_remove_enabled",
           "auto_remove_weeks"
         ].join(",") +
       `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
       `&is_owner=is.true&is_public=is.true` +
       `&order=updated_at.desc`;
   
     if (connection_id) {
       path += `&connection_id=eq.${encodeURIComponent(connection_id)}`;
     }
   
     const r = await fetch(SUPABASE_URL + path, {
       headers: { apikey: SRK, Authorization: `Bearer ${SRK}` },
       cache: "no-store",
     });
     const txt = await r.text();
     if (!r.ok) {
       return json(res, 500, { error: "supabase_error", status: r.status, body: txt, url: SUPABASE_URL + path });
     }
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
       `/rest/v1/playlists?select=id,playlist_id` +                           // <-- NEU: auch UUID ziehen
       `&connection_id=eq.${encodeURIComponent(connection_id)}` +
       `&is_owner=is.true&is_public=is.true` +
       `&or=(followers.is.null,followers_checked_at.lt.${encodeURIComponent(sinceIso)})` +
       `&order=${order}&limit=${maxTotal}`;
   
     const targets = await sb(path).then(r => r.json()); // [{ id: <uuid>, playlist_id: <spotify_id> }, ...]
     if (!Array.isArray(targets) || targets.length === 0) {
       return json(res, 200, { ok:true, attempted:0, updated:0, failed:[], reason:"up_to_date" });
     }
   
     const access_token = await getAccessTokenFromConnection(connection_id);
   
     // parallel Followers laden
     const results = await (async () => {
       const out = [];
       let i = 0, running = 0;
       await new Promise((resolve) => {
         const kick = () => {
           while (running < conc && i < targets.length) {
             const t = targets[i++]; running++;
             (async () => {
               const row_id = t.id;              // UUID in unserer DB
               const sp_id  = t.playlist_id;     // Spotify ID
               try {
                 const url = `https://api.spotify.com/v1/playlists/${encodeURIComponent(sp_id)}?fields=followers(total)`;
                 let resFollowers = { ok:false, status:0, row_id, sp_id, followers:null };
                 while (true) {
                   const r = await fetch(url, { headers: { Authorization: `Bearer ${access_token}` } });
                   if (r.status === 429) {
                     const retry = Number(r.headers.get("retry-after") || "1");
                     await sleep((retry + 0.2)*1000);
                     continue;
                   }
                   const j = await r.json().catch(()=> ({}));
                   if (!r.ok) { resFollowers = { row_id, sp_id, followers:null, ok:false, status:r.status }; }
                   else { resFollowers = { row_id, sp_id, followers: j?.followers?.total ?? null, ok:true, status:200 }; }
                   break;
                 }
                 out.push(resFollowers);
                 await sleep(50);
               } catch {
                 out.push({ row_id, sp_id, followers:null, ok:false, status:500 });
               } finally {
                 running--; kick();
               }
             })();
           }
           if (running === 0 && i >= targets.length) resolve();
         };
         kick();
       });
       return out;
     })();
   
     // Upsert in playlists (aktuelle Follower + checked_at)
     const nowIso = new Date().toISOString();
     const rows = results.filter(x => x.ok).map(x => ({
       playlist_id: x.sp_id,                // Spotify-ID, on_conflict=playlist_id
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
   
     // --- NEU: Tages-Snapshot in playlist_followers_history (UUID-Referenz) ---
     const sample_date = new Date().toISOString().slice(0,10); // 'YYYY-MM-DD' UTC
     const histRows = results
       .filter(x => x.ok && Number.isFinite(x.followers))
       .map(x => ({
         playlist_id: x.row_id,              // UUID (playlists.id)
         bubble_user_id: conn.bubble_user_id,
         sample_date,                        // DATE-Spalte
         followers: x.followers
       }));
   
     for (let i = 0; i < histRows.length; i += perWrite) {
       const rHist = await sb(`/rest/v1/playlist_followers_history?on_conflict=playlist_id,sample_date`, {
         method: "POST",
         headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
         body: JSON.stringify(histRows.slice(i, i + perWrite))
       });
       if (!rHist.ok) {
         return bad(res, 500, `supabase history upsert failed: ${await rHist.text()}`);
       }
     }
   
     const failed = results.filter(x => !x.ok).map(x => ({ spotify_id: x.sp_id, status: x.status }));
     return json(res, 200, { ok:true, attempted: targets.length, updated: rows.length, history: histRows.length, failed });
   },


  /* ---------- playlists/sync-items (POST, secret) ---------- */
   "playlists/sync-items": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     if (process.env.APP_WEBHOOK_SECRET) {
       const got = req.headers["x-app-secret"];
       if (got !== process.env.APP_WEBHOOK_SECRET) return bad(res, 401, "unauthorized");
     }
   
     const bodyRaw = await readBody(req);
     let { playlist_row_id, spotify_playlist_id } = bodyRaw;
   
     const timeLabel = `sync-items:${playlist_row_id || spotify_playlist_id || 'unknown'}`;
     console.time(timeLabel);
     console.log("sync-items:start", {
       by: playlist_row_id ? "row_id" : (spotify_playlist_id ? "spotify_id" : "missing"),
       playlist_row_id,
       spotify_playlist_id,
       ts: new Date().toISOString(),
       vercel_url: process.env.VERCEL_URL || null
     });
   
     const chunk = (arr, n) => { const out=[]; for (let i=0;i<arr.length;i+=n) out.push(arr.slice(i, i+n)); return out; };
   
     try {
       if (!playlist_row_id && !spotify_playlist_id) {
         console.timeEnd(timeLabel);
         return bad(res, 400, "missing_playlist_identifier");
       }
   
       // Falls nur Spotify-ID kam → Row-ID auflösen
       if (!playlist_row_id && spotify_playlist_id) {
         console.log("sync-items:resolve_row_id_from_spotify_id", { spotify_playlist_id });
         const r = await sb(`/rest/v1/playlists?select=id,playlist_id,connection_id,bubble_user_id,auto_remove_enabled,auto_remove_weeks&limit=1&playlist_id=eq.${encodeURIComponent(spotify_playlist_id)}`);
         if (!r.ok) { console.timeEnd(timeLabel); return bad(res, 500, `supabase_select_failed: ${await r.text()}`); }
         const arr = await r.json();
         if (!arr[0]) { console.timeEnd(timeLabel); return bad(res, 404, "playlist_not_found_by_spotify_id"); }
         playlist_row_id = arr[0].id;
         console.log("sync-items:resolved_row_id", { playlist_row_id });
       }
   
       // Playlist-Metadaten (+Settings)
       const pr = await sb(`/rest/v1/playlists?select=id,playlist_id,connection_id,bubble_user_id,auto_remove_enabled,auto_remove_weeks&limit=1&id=eq.${encodeURIComponent(playlist_row_id)}`);
       if (!pr.ok) { console.timeEnd(timeLabel); return bad(res, 500, `supabase select playlist failed: ${await pr.text()}`); }
       const p = (await pr.json())[0];
       if (!p) { console.timeEnd(timeLabel); return bad(res, 404, "playlist_not_found"); }
       console.log("sync-items:playlist_meta", {
         playlist_row_id: p.id,
         spotify_playlist_id: p.playlist_id,
         connection_id: p.connection_id,
         bubble_user_id: p.bubble_user_id,
         auto_remove_enabled: !!p.auto_remove_enabled,
         auto_remove_weeks: p.auto_remove_weeks
       });
   
       // Reentrancy-Guard (Claim)
       const claim = await fetch(
         `${process.env.SUPABASE_URL}/rest/v1/playlists` +
         `?id=eq.${encodeURIComponent(p.id)}&sync_started_at=is.null`,
         {
           method: "PATCH",
           headers: {
             apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
             Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
             "Content-Type": "application/json",
             Prefer: "return=representation"
           },
           body: JSON.stringify({ sync_started_at: new Date().toISOString() })
         }
       );
       if (!claim.ok) {
         console.timeEnd(timeLabel);
         return bad(res, 500, `supabase_claim_failed: ${await claim.text()}`);
       }
       const claimed = await claim.json();
       if (!Array.isArray(claimed) || claimed.length === 0) {
         console.warn("sync-items:already_in_progress", { playlist_row_id: p.id });
         console.timeEnd(timeLabel);
         return json(res, 202, { ok:true, already_in_progress:true });
       }
   
       // Connection & Token
       const cr = await sb(`/rest/v1/spotify_connections?select=id,refresh_token_enc&limit=1&id=eq.${encodeURIComponent(p.connection_id)}`);
       if (!cr.ok) { console.timeEnd(timeLabel); return bad(res, 500, `supabase select connection failed: ${await cr.text()}`); }
       const conn = (await cr.json())[0];
       if (!conn) { console.timeEnd(timeLabel); return bad(res, 404, "connection_not_found"); }
   
       const refresh_token = decryptToken(conn.refresh_token_enc);
       const t0 = Date.now();
       const tokenRef = await refreshAccessToken(refresh_token);
       const access_token = tokenRef.access_token;
       console.log("sync-items:token_refreshed", { took_ms: Date.now() - t0, expires_in: tokenRef.expires_in });
   
       // Snapshot-ID (für positionsgenaue Delete/Reorder)
       let snapshot_id = null;
       {
         const meta = await fetchJSON(
           `https://api.spotify.com/v1/playlists/${encodeURIComponent(p.playlist_id)}?fields=snapshot_id`,
           { headers: { Authorization: `Bearer ${access_token}` } },
           20000
         );
         if (meta.r.ok) snapshot_id = meta.json?.snapshot_id || null;
       }
   
       // Locks laden
       const locksR = await sb(`/rest/v1/playlist_item_locks?select=track_id,is_locked,locked_position&playlist_id=eq.${encodeURIComponent(p.id)}`);
       const locksArr = locksR.ok ? await locksR.json() : [];
       const lockedSet = new Set(locksArr.filter(x => x.is_locked).map(x => x.track_id));
   
       // Spotify Tracks robust holen
       const items = [];
       let url = `https://api.spotify.com/v1/playlists/${encodeURIComponent(p.playlist_id)}/tracks?limit=100&offset=0&fields=items(added_at,track(id,name,uri,popularity,duration_ms,preview_url,album(name,images),artists(name))),total,next,offset`;
   
       const startedAt = Date.now();
       const MAX_WALL_MS = 240000;
       const MAX_PAGES = 100;
       const MAX_429_RETRIES_PER_PAGE = 12;
   
       let pageCount = 0;
       while (url) {
         if (Date.now() - startedAt > MAX_WALL_MS) {
           console.warn("sync-items:wall_timeout", { elapsed_ms: Date.now() - startedAt });
           // Guard abbauen + reschedule
           await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
             method: "PATCH", headers: { Prefer: "return=minimal" },
             body: JSON.stringify({ sync_started_at: null, next_check_at: new Date(Date.now()+300000).toISOString(), needs_sync: true })
           }).catch(()=>{});
           console.timeEnd(timeLabel);
           return json(res, 202, { ok:false, rescheduled:true, reason:"wall_timeout" });
         }
         if (++pageCount > MAX_PAGES) {
           console.warn("sync-items:pagination_safety_tripped", { pageCount });
           await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
             method: "PATCH", headers: { Prefer: "return=minimal" },
             body: JSON.stringify({ sync_started_at: null, next_check_at: new Date(Date.now()+300000).toISOString(), needs_sync: true })
           }).catch(()=>{});
           console.timeEnd(timeLabel);
           return json(res, 202, { ok:false, rescheduled:true, reason:"too_many_pages" });
         }
   
         let attempt = 0;
         while (true) {
           const tPage = Date.now();
           const { r, json, text } = await fetchJSON(
             url,
             { headers: { Authorization: `Bearer ${access_token}` } },
             20000
           );
   
           if (r.status === 429) {
             // Exponentieller Backoff + Jitter + Cooldown (falls zu oft)
             const ra = Number(r.headers.get("retry-after") || "1");
             const base = Math.max(ra, 1);
             const waitSec = Math.min(60, base * Math.pow(2, attempt)) + (Math.random() * 0.8);
             console.warn("sync-items:429", { page: pageCount, attempt, retry_after_s: ra, wait_s: waitSec.toFixed(1) });
   
             if (attempt++ >= MAX_429_RETRIES_PER_PAGE) {
               // Verbindung in Cooldown + später neu versuchen
               const untilIso = new Date(Date.now() + (base + 5) * 1000).toISOString();
               await sb(`/rest/v1/connection_rl_state`, {
                 method: "POST",
                 headers: { Prefer: "resolution=merge-duplicates" },
                 body: JSON.stringify({ connection_id: p.connection_id, cooldown_until: untilIso })
               }).catch(()=>{});
               await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
                 method: "PATCH",
                 headers: { Prefer: "return=minimal" },
                 body: JSON.stringify({
                   sync_started_at: null,
                   next_check_at: untilIso,
                   needs_sync: true
                 })
               }).catch(()=>{});
               console.timeEnd(timeLabel);
               return json(res, 202, { ok:false, rescheduled:true, reason:"rate_limited" });
             }
   
             await sleep(waitSec * 1000);
             continue;
           }
   
           if (!r.ok) {
             console.error("sync-items:spotify_tracks_failed", { status: r.status, body: json || text });
             // Guard abbauen, aber Fehler zurückgeben (hier sinnvoll)
             await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
               method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ sync_started_at: null })
             }).catch(()=>{});
             console.timeEnd(timeLabel);
             return bad(res, r.status, `spotify playlist tracks failed: ${r.status} ${json ? JSON.stringify(json) : text}`);
           }
   
           const len = Array.isArray(json?.items) ? json.items.length : 0;
           items.push(...(json?.items || []));
           console.log("sync-items:page_ok", {
             page: pageCount,
             items_in_page: len,
             total_items_so_far: items.length,
             took_ms: Date.now() - tPage,
             next: !!json?.next
           });
   
           url = json?.next || null;
           break; // next page
         }
       }
   
       console.log("sync-items:spotify_fetched", { total_items: items.length });
   
       /* === (A) Expiry: alte, UNGElOCKTE Items löschen (positionsgenau) === */
       let removedPositionsSet = new Set();
       if (p.auto_remove_enabled && Number(p.auto_remove_weeks) > 0) {
         const cutoffMs = Date.now() - Number(p.auto_remove_weeks) * 7 * 24 * 3600 * 1000;
         const toRemoveMap = new Map(); // uri -> positions[]
   
         for (let i = 0; i < items.length; i++) {
           const it = items[i] || {};
           const t = it.track || {};
           if (!t?.id || !t?.uri) continue;
           if (lockedSet.has(t.id)) continue; // gelockte nie löschen
           const addedAt = it.added_at ? Date.parse(it.added_at) : NaN;
           if (!Number.isFinite(addedAt)) continue;
           if (addedAt <= cutoffMs) {
             if (!toRemoveMap.has(t.uri)) toRemoveMap.set(t.uri, []);
             toRemoveMap.get(t.uri).push(i);
             removedPositionsSet.add(i);
           }
         }
   
         const toRemovePayload = Array.from(toRemoveMap.entries()).map(([uri, positions]) => ({ uri, positions }));
         if (toRemovePayload.length > 0 && snapshot_id) {
           for (const batch of chunk(toRemovePayload, 100)) {
             let attempt = 0;
             while (true) {
               const del = await fetchJSON(
                 `https://api.spotify.com/v1/playlists/${encodeURIComponent(p.playlist_id)}/tracks`,
                 {
                   method: "DELETE",
                   headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
                   body: JSON.stringify({ tracks: batch, snapshot_id })
                 },
                 20000
               );
               if (del.r.status === 429) {
                 const ra = Number(del.r.headers.get("retry-after") || "1");
                 const waitSec = Math.min(60, Math.max(1, ra) * Math.pow(2, attempt)) + (Math.random() * 0.8);
                 if (attempt++ >= 6) {
                   // Guard abbauen + später neu versuchen
                   await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
                     method: "PATCH", headers: { Prefer: "return=minimal" },
                     body: JSON.stringify({ sync_started_at: null, needs_sync: true, next_check_at: new Date(Date.now()+ (Math.max(1,ra)+5)*1000).toISOString() })
                   }).catch(()=>{});
                   console.timeEnd(timeLabel);
                   return json(res, 202, { ok:false, rescheduled:true, reason:"rate_limited_delete" });
                 }
                 await sleep(waitSec * 1000);
                 continue;
               }
               if (!del.r.ok) {
                 // harte Fehler → Guard abbauen & Fehler
                 await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
                   method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ sync_started_at: null })
                 }).catch(()=>{});
                 console.timeEnd(timeLabel);
                 return bad(res, del.r.status, `spotify delete failed: ${del.r.status} ${del.text || ""}`);
               }
               // neue snapshot_id übernehmen
               snapshot_id = del.json?.snapshot_id || snapshot_id;
               break;
             }
             await sleep(80);
           }
   
           // Lokalen Items-Array kompaktieren (gelöschte Positionen entfernen)
           const keep = [];
           for (let i = 0; i < items.length; i++) {
             if (!removedPositionsSet.has(i)) keep.push(items[i]);
           }
           items.length = 0;
           items.push(...keep);
         }
       }
   
       /* === (B) Locks enforce (Reorder) – auf Basis des (ggf. bereinigten) items-Arrays === */
       if (locksArr.some(x => x.is_locked) && snapshot_id) {
         // Arbeitsliste: nur tracks mit id/uri
         const order = items
           .map((it) => it?.track ? { id: it.track.id, uri: it.track.uri } : null)
           .filter(Boolean);
   
         // Hilfsfunktion: local reorder anwenden
         const localMove = (arr, from, to) => {
           if (from === to) return;
           const el = arr.splice(from, 1)[0];
           arr.splice(to, 0, el);
         };
   
         // IndexMap
         const indexOf = (id) => order.findIndex(x => x.id === id);
   
         // sortiere Locks nach Zielposition ASC
         const desiredLocks = locksArr
           .filter(l => l.is_locked && Number.isFinite(l.locked_position))
           .sort((a,b) => a.locked_position - b.locked_position);
   
         for (const l of desiredLocks) {
           const desired = Math.max(0, Math.min(order.length - 1, Number(l.locked_position)));
           const cur = indexOf(l.track_id);
           if (cur < 0) continue;      // Track aktuell nicht in Playlist
           if (cur === desired) continue;
   
           // Spotify-Reorder: insert_before ist "Zielindex" nach Entfernung des Elements.
           const insert_before = desired > cur ? desired + 1 : desired;
   
           let attempt = 0;
           while (true) {
             const re = await fetchJSON(
               `https://api.spotify.com/v1/playlists/${encodeURIComponent(p.playlist_id)}/tracks`,
               {
                 method: "PUT",
                 headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
                 body: JSON.stringify({
                   range_start: cur,
                   insert_before,
                   range_length: 1,
                   snapshot_id
                 })
               },
               20000
             );
             if (re.r.status === 429) {
               const ra = Number(re.r.headers.get("retry-after") || "1");
               const waitSec = Math.min(60, Math.max(1, ra) * Math.pow(2, attempt)) + (Math.random() * 0.8);
               if (attempt++ >= 6) {
                 await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
                   method: "PATCH", headers: { Prefer: "return=minimal" },
                   body: JSON.stringify({ sync_started_at: null, needs_sync: true, next_check_at: new Date(Date.now() + (Math.max(1,ra)+5)*1000).toISOString() })
                 }).catch(()=>{});
                 console.timeEnd(timeLabel);
                 return json(res, 202, { ok:false, rescheduled:true, reason:"rate_limited_reorder" });
               }
               await sleep(waitSec * 1000);
               continue;
             }
             if (!re.r.ok) {
               await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
                 method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ sync_started_at: null })
               }).catch(()=>{});
               console.timeEnd(timeLabel);
               return bad(res, re.r.status, `spotify reorder failed: ${re.r.status} ${re.text || ""}`);
             }
             // lokale Liste & snapshot aktualisieren
             localMove(order, cur, desired);
             snapshot_id = re.json?.snapshot_id || snapshot_id;
             break;
           }
   
           // kleine Pause
           await sleep(60);
         }
   
         // items an neue Reihenfolge anpassen (damit Upsert-Positionen stimmen)
         // Wir mappen schnell id -> erstes Item
         const byId = new Map();
         for (const it of items) {
           const t = it?.track;
           if (t?.id && !byId.has(t.id)) byId.set(t.id, it);
         }
         const remapped = order.map(o => byId.get(o.id)).filter(Boolean);
         items.length = 0;
         items.push(...remapped);
       }
   
       /* === (C) Map → DB Rows === */
       const rows = [];
       for (let i = 0; i < items.length; i++) {
         const it = items[i] || {};
         const t = it.track || {};
         const album = t.album || {};
         const artists = Array.isArray(t.artists) ? t.artists : [];
         rows.push({
           playlist_id: p.id,          // FK -> playlists.id (uuid)
           position: i,                // 0-based
           track_id: t.id || null,
           track_name: t.name || null,
           track_uri: t.uri || null,
           artist_names: artists.map((a) => a?.name).filter(Boolean).join(", "),
           album_name: album.name || null,
           duration_ms: Number.isFinite(t.duration_ms) ? t.duration_ms : null,
           popularity: Number.isFinite(t.popularity) ? t.popularity : null,
           preview_url: t.preview_url || null,
           cover_url: (album.images && album.images[0]?.url) || null,
           added_at: it.added_at || null
         });
       }
       console.log("sync-items:mapped_rows", { rows: rows.length });
   
       /* === (D) UPSERT in Batches (robust, kein harter return bei Teilausfällen) === */
       const batches = chunk(rows, 500);
       let batchIdx = 0, upsertErrors = 0;
       for (const b of batches) {
         const tUp = Date.now();
         const { r, text } = await fetchText(
           `${process.env.SUPABASE_URL}/rest/v1/playlist_items?on_conflict=playlist_id,position`,
           {
             method: "POST",
             headers: {
               apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
               Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
               Prefer: "resolution=merge-duplicates,return=minimal",
               "Content-Type": "application/json"
             },
             body: JSON.stringify(b)
           },
           20000
         );
         if (!r.ok) {
           upsertErrors++;
           console.error("sync-items:upsert_failed", { batch: batchIdx, size: b.length, text });
         } else {
           console.log("sync-items:upsert_ok", { batch: batchIdx, size: b.length, took_ms: Date.now() - tUp });
         }
         batchIdx++;
       }
   
       // Tail-Cleanup (löscht alte Positionen > maxKeep)
       const maxKeep = Math.max(0, rows.length - 1);
       const delUrl = `${process.env.SUPABASE_URL}/rest/v1/playlist_items?playlist_id=eq.${encodeURIComponent(
         p.id
       )}&position=gt.${maxKeep}`;
       const tDel = Date.now();
       const { r: delR, text: dtxt } = await fetchText(
         delUrl,
         {
           method: "DELETE",
           headers: {
             apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
             Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
             Prefer: "return=minimal"
           }
         },
         20000
       );
       if (!delR.ok) console.warn("sync-items:cleanup_warning", { text: dtxt, took_ms: Date.now() - tDel });
       else console.log("sync-items:cleanup_ok", { took_ms: Date.now() - tDel });
   
       // Erfolgs-Finale: Flags setzen & Guard abbauen
       await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
         method: "PATCH",
         headers: { Prefer: "return=minimal" },
         body: JSON.stringify({
           needs_sync: false,
           sync_started_at: null,
           last_synced_at: new Date().toISOString()
         })
       }).catch(()=>{});
   
       console.timeEnd(timeLabel);
       return json(res, 200, {
         ok: upsertErrors === 0,
         inserted_or_updated: rows.length,
         total_spotify: items.length,
         upsert_errors: upsertErrors
       });
     } catch (e) {
       const msg = e && e.stack ? e.stack : String(e);
       console.error("sync-items:error", msg);
       console.timeEnd(timeLabel);
       return bad(res, 500, "sync_items_exception: " + msg);
     } finally {
       // Guard sicher abbauen, falls noch gesetzt
       try {
         if (playlist_row_id) {
           await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(playlist_row_id)}`, {
             method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ sync_started_at: null })
           });
         }
       } catch {}
     }
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
        `&sync_started_at=is.null` + // <— NEU: niemals poll’en, wenn gerade gesynct wird
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
   
     let i=0, running=0, conc=1, synced=0, failed=0; // conc=1, um Herdeneffekt zu vermeiden
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
   
     const inUrl = new URL(req.url, `http://${req.headers.host}`);
     const qp = inUrl.searchParams;
   
     // Shard/ Bucket bestimmen (0..59). Optional Override via ?bucket=NN
     const bucketOverride = qp.get("bucket");
     const nowUtcMin = new Date().getUTCMinutes();
     const bucket = bucketOverride !== null ? Number(bucketOverride) : nowUtcMin;
   
     // Per-Subroute Budgets aus Query (global fallback)
     const limitCheck = qp.get("limit_check") ?? qp.get("limit") ?? "5";
     const concCheck  = qp.get("conc_check")  ?? qp.get("concurrency") ?? "2";
     const limitSync  = qp.get("limit_sync")  ?? qp.get("limit") ?? "2";
     const concSync   = qp.get("conc_sync")   ?? qp.get("concurrency") ?? "1";
   
     // Nur Connections in diesem Bucket laden
     const conns = await sb(`/rest/v1/spotify_connections?select=id&cron_bucket=eq.${encodeURIComponent(bucket)}`)
                         .then(r => r.json());
   
     let ok=0, fail=0;
     for (const c of conns) {
       // CHECK-Updates für diese Connection
       const reqCheck = {
         ...req,
         method: "POST",
         headers: { ...req.headers, "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
         url: `/api/watch/check-updates?limit=${encodeURIComponent(limitCheck)}&concurrency=${encodeURIComponent(concCheck)}`,
         query: { limit: String(limitCheck), concurrency: String(concCheck) },
         body: { connection_id: c.id }
       };
       const r1 = await routes["watch/check-updates"](reqCheck, { status:()=>({ json:()=>{} }) }).catch(()=>({ ok:false }));
       r1?.ok ? ok++ : fail++;
   
       // SYNC-needed für diese Connection
       const reqSync = {
         ...req,
         method: "POST",
         headers: { ...req.headers, "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
         url: `/api/watch/sync-needed?limit=${encodeURIComponent(limitSync)}&concurrency=${encodeURIComponent(concSync)}`,
         query: { limit: String(limitSync), concurrency: String(concSync) },
         body: { connection_id: c.id }
       };
       const r2 = await routes["watch/sync-needed"](reqSync, { status:()=>({ json:()=>{} }) }).catch(()=>({ ok:false }));
       r2?.ok ? ok++ : fail++;
   
       await sleep(60); // mini-jitter zwischen Connections
     }
   
     return json(res, 200, { ok:true, bucket, connections: conns.length, dispatched_ok: ok, dispatched_fail: fail });
   },



   /* ---------- watch/cron-maintenance-all (GET/POST) ---------- */
   "watch/cron-maintenance-all": async (req, res) => {
     if (!checkCronAuth(req) && !checkAppSecret(req)) return bad(res, 401, "unauthorized_cron");
     const qs = Object.fromEntries(new URL(req.url, `http://${req.headers.host}`).searchParams.entries());
   
     // Zielmenge: alle, die Auto-Remove aktiv haben (und Wochen gesetzt)
     const sel = await sb(`/rest/v1/playlists?select=id&auto_remove_enabled=is.true&auto_remove_weeks=not.is.null`);
     if (!sel.ok) return bad(res, 500, `supabase_select_failed: ${await sel.text()}`);
     const rows = await sel.json();
     if (!rows.length) return json(res, 200, { ok:true, processed:0 });
   
     let i=0, running=0, conc = Number(qs.concurrency || "3");
     let ok=0, fail=0;
     await new Promise(resolve => {
       const kick = () => {
         while (running < conc && i < rows.length) {
           const id = rows[i++].id; running++;
           (async () => {
             try {
               const r = await sb(`/rest/v1/rpc/playlist_maintenance`, {
                 method: "POST",
                 body: JSON.stringify({ p_playlist_id: id })
               });
               r.ok ? ok++ : fail++;
             } catch { fail++; }
             finally { running--; kick(); }
           })();
         }
         if (running === 0 && i >= rows.length) resolve();
       };
       kick();
     });
   
     return json(res, 200, { ok:true, processed: rows.length, ok_count: ok, failed: fail });
   },




   /* ---------- playlist-items/move (POST) ---------- */
   "playlist-items/move": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     const bubbleUserId = req.headers["x-bubble-user-id"];
     if (!bubbleUserId) return bad(res, 401, "Missing X-Bubble-User-Id");
   
     const { playlist_id, track_id, dir, steps = 1 } = await readBody(req);
     if (!playlist_id || !track_id || !dir) return bad(res, 400, "Missing playlist_id, track_id or dir");
   
     // Ownership
     const own = await sb(`/rest/v1/playlists?select=id&limit=1&id=eq.${encodeURIComponent(String(playlist_id))}&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`).then(r=>r.json());
     if (!own?.[0]) return bad(res, 403, "Playlist not owned by user");
   
     // RPC call
     const r = await sb(`/rest/v1/rpc/playlist_move_one`, {
       method: "POST",
       body: JSON.stringify({
         p_playlist_id: playlist_id,
         p_track_id: track_id,
         p_dir: String(dir || "").toLowerCase(),
         p_steps: Number(steps) || 1
       })
     });
     const txt = await r.text();
     let j = null; try { j = txt ? JSON.parse(txt) : null; } catch {}
     if (!r.ok) return bad(res, r.status, `rpc_move_failed: ${txt}`);
   
     // optional: Spotify Enforce anstoßen (asynchron)
     // await routes["playlists/dispatch-sync"]({ ...req, body: { playlist_id } }, { status: ()=>({ json: ()=>{} }) });
   
     return json(res, 200, { ok: true, result: j?.[0] || null });
   },
   
  /* ---------- playlist-items/remove (POST, Bubble) ---------- */
   "playlist-items/remove": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
   
     // Auth per Bubble
     const bubbleUserId = req.headers["x-bubble-user-id"];
     if (!bubbleUserId) return bad(res, 401, "missing_x_bubble_user_id");
   
     const body = await readBody(req);
     const playlist_id = String(body.playlist_id || "").trim(); // interne UUID (playlists.id)
     const track_id    = String(body.track_id || "").trim();    // z.B. "6dpaekNzHZDhwd9QDayrbB"
     let   position0   = body.position0;                        // 0-basiert erwartet
   
     // position0 sauber parsen
     if (position0 === "" || position0 === null || position0 === undefined) {
       return bad(res, 400, "missing_or_invalid_position0");
     }
     position0 = Number(position0);
     if (!Number.isFinite(position0) || position0 < 0) {
       return bad(res, 400, "missing_or_invalid_position0");
     }
     if (!playlist_id || !track_id) return bad(res, 400, "missing_playlist_id_or_track_id");
   
     try {
       // Playlist + Ownership prüfen
       const pr = await sb(`/rest/v1/playlists?select=id,playlist_id,connection_id,bubble_user_id&limit=1&id=eq.${encodeURIComponent(playlist_id)}`);
       if (!pr.ok) return bad(res, 500, `supabase_select_playlist_failed: ${await pr.text()}`);
       const p = (await pr.json())?.[0];
       if (!p) return bad(res, 404, "playlist_not_found");
       if (p.bubble_user_id !== bubbleUserId) return bad(res, 403, "forbidden");
   
       // Token
       const access_token = await getAccessTokenFromConnection(p.connection_id);
   
       // Aktuellen Snapshot
       const metaR = await fetch(`https://api.spotify.com/v1/playlists/${encodeURIComponent(p.playlist_id)}?fields=snapshot_id`, {
         headers: { Authorization: `Bearer ${access_token}` }
       });
       const metaJ = await metaR.json().catch(()=> ({}));
       if (!metaR.ok || !metaJ?.snapshot_id) {
         return bad(res, metaR.status || 500, `spotify_meta_failed`);
       }
       let snapshot_id = metaJ.snapshot_id;
   
       // Helper: Item an Position prüfen
       const checkAt = async (pos) => {
         if (pos < 0) return null;
         const url = `https://api.spotify.com/v1/playlists/${encodeURIComponent(p.playlist_id)}/tracks?fields=items(track(id,uri)),total,limit,offset&limit=1&offset=${pos}`;
         const { r, json } = await fetchJSON(url, { headers:{ Authorization:`Bearer ${access_token}` } }, 20000);
         if (!r.ok) return null;
         const it = Array.isArray(json?.items) ? json.items[0] : null;
         if (!it?.track?.id) return { ok:true, match:false, total: json?.total ?? null };
         const match = it.track.id === track_id;
         return { ok:true, match, total: json?.total ?? null, uri: it.track.uri, pos };
       };
   
       // Kandidatenliste an Positionen aufbauen:
       //  - die vom Client gelieferte position0 (und ±1)
       //  - die "kanonische" DB-Position des Tracks (und ±1/±2) als Fallback
       const candidateSet = new Set([position0, position0 - 1, position0 + 1]);
   
       // DB-Position für diesen Track ermitteln (erste Instanz)
       const dbPosR = await sb(
         `/rest/v1/playlist_items?select=position` +
         `&playlist_id=eq.${encodeURIComponent(playlist_id)}` +
         `&track_id=eq.${encodeURIComponent(track_id)}` +
         `&order=position.asc&limit=1`
       );
       if (dbPosR.ok) {
         const dbRow = (await dbPosR.json())?.[0];
         const dbPos = Number.isFinite(dbRow?.position) ? dbRow.position : null;
         if (dbPos !== null) {
           // Enge Fenster um dbPos hinzufügen
           candidateSet.add(dbPos);
           candidateSet.add(dbPos - 1);
           candidateSet.add(dbPos + 1);
           candidateSet.add(dbPos - 2);
           candidateSet.add(dbPos + 2);
         }
       }
   
       // Kandidaten sortieren (näheste zuerst zur initialen position0)
       const candidates = Array.from(candidateSet).filter(n => Number.isFinite(n) && n >= 0)
         .sort((a,b) => Math.abs(a - position0) - Math.abs(b - position0));
   
       // Durchprobieren bis ein Match steht
       let posToRemove = null;
       for (const pos of candidates) {
         const probe = await checkAt(pos);
         if (probe?.match) { posToRemove = pos; break; }
       }
       if (posToRemove === null) {
         return bad(res, 409, "position_mismatch_refresh_needed");
       }
   
       const uri = `spotify:track:${track_id}`;
       const delBody = { tracks: [{ uri, positions: [posToRemove] }], snapshot_id };
   
       // Retry-Loop für 409/429/5xx
       let attempt = 0;
       const MAX_ATTEMPTS = 3;
       while (true) {
         const r = await fetch(`https://api.spotify.com/v1/playlists/${encodeURIComponent(p.playlist_id)}/tracks`, {
           method: "DELETE",
           headers: {
             Authorization: `Bearer ${access_token}`,
             "Content-Type": "application/json"
           },
           body: JSON.stringify(delBody)
         });
   
         if (r.status === 429) {
           const ra = Number(r.headers.get("retry-after") || "1");
           const wait = Math.min(30, ra + 0.5 + Math.random()*0.8);
           await sleep(wait * 1000);
           if (++attempt >= MAX_ATTEMPTS) return bad(res, 429, "spotify_remove_rate_limited");
           continue;
         }
   
         if (r.status === 409) {
           // Snapshot alt → aktualisieren & Position gegenchecken
           if (++attempt >= MAX_ATTEMPTS) return bad(res, 409, "snapshot_conflict_gave_up");
   
           const metaR2 = await fetch(`https://api.spotify.com/v1/playlists/${encodeURIComponent(p.playlist_id)}?fields=snapshot_id`, {
             headers: { Authorization: `Bearer ${access_token}` }
           });
           const metaJ2 = await metaR2.json().catch(()=> ({}));
           if (!metaR2.ok || !metaJ2?.snapshot_id) return bad(res, 500, "refresh_snapshot_failed");
           snapshot_id = metaJ2.snapshot_id;
           delBody.snapshot_id = snapshot_id;
   
           // Prüfe erneut an posToRemove und ggf. Nachbarn
           const recheck = await checkAt(posToRemove);
           if (!recheck?.match) {
             const left  = await checkAt(posToRemove - 1);
             const right = await checkAt(posToRemove + 1);
             if (left?.match)  delBody.tracks[0].positions = [left.pos];
             else if (right?.match) delBody.tracks[0].positions = [right.pos];
             else return bad(res, 409, "position_mismatch_after_snapshot");
           }
           continue;
         }
   
         const j = await r.json().catch(()=> ({}));
         if (!r.ok) {
           if (r.status >= 500 && attempt++ < 2) {
             await sleep((2 + Math.random()*3) * 1000);
             continue;
           }
           return bad(res, r.status, `spotify_remove_failed: ${JSON.stringify(j)}`);
         }
   
         const newSnap = j?.snapshot_id || null;
   
         // Supabase sync triggern
         await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
           method: "PATCH",
           headers: { Prefer: "return=minimal" },
           body: JSON.stringify({ needs_sync: true, last_snapshot_checked_at: new Date().toISOString() })
         }).catch(()=>{});
   
         const base = process.env.PUBLIC_BASE_URL || `https://${process.env.VERCEL_URL}`;
         if (base) {
           fetch(`${base}/api/playlists/dispatch-sync`, {
             method: "POST",
             headers: { "Content-Type": "application/json", "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
             body: JSON.stringify({ playlist_id: p.id })
           }).catch(()=>{});
         }
   
         return json(res, 200, { ok: true, removed_at_position0: delBody.tracks[0].positions[0], new_snapshot_id: newSnap });
       }
     } catch (e) {
       return bad(res, 500, `remove_exception: ${e?.message || e}`);
     }
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
   
     // Wichtig: 0 ist ein gültiger Wert → nicht mit !locked_position prüfen
     if (!playlist_id || !track_id || locked_position === undefined || locked_position === null) {
       return bad(res, 400, "Missing playlist_id, track_id or locked_position");
     }
   
     // ownership
     const own = await sb(`/rest/v1/playlists?select=id&limit=1&id=eq.${encodeURIComponent(String(playlist_id))}&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`).then(r=>r.json());
     if (!own?.[0]) return bad(res, 403, "Playlist not owned by user");
   
     // UI liefert i.d.R. 1-basiert → auf 0-basiert normalisieren (nie negativ)
     const rawPos = Number(locked_position);
     if (!Number.isFinite(rawPos)) return bad(res, 400, "invalid locked_position");
     const lockedPosZero = rawPos >= 1 ? rawPos - 1 : Math.max(0, rawPos);
   
     // upsert lock (jetzt 0-basiert speichern)
     const up = await sb(`/rest/v1/playlist_item_locks?on_conflict=playlist_id,track_id`, {
       method: "POST",
       headers: { Prefer: "resolution=merge-duplicates,return=representation" },
       body: JSON.stringify([{
         playlist_id,
         track_id,
         locked_position: lockedPosZero,
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
        body: syncBody,
        headers: {
          'Content-Type': 'application/json',
          'x-app-secret': APP_WEBHOOK_SECRET
        },
        url: targetUrl
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
