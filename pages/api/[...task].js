// pages/api/[...task].js
export const config = { api: { bodyParser: false } };

import Stripe from "stripe";

/* ==============================
   Shared Utils (Server-only)
============================== */
// hi!

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
    const origin = req.headers?.origin || "";
    const allowedOrigins = new Set([
      "https://playlist-pilot.com",
      process.env.PUBLIC_BASE_URL || "",
      process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "",
      process.env.NODE_ENV !== "production" ? "http://localhost:3000" : "",
      process.env.NODE_ENV !== "production" ? "http://127.0.0.1:3000" : "",
    ].filter(Boolean));
    if (origin && !allowedOrigins.has(origin)) return res.status(403).json({ error: "origin_not_allowed" });
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
    }
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,x-app-secret");
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

async function scopedPlaylistUpsert(batch) {
  const rows = Array.isArray(batch) ? batch : [batch];
  const scoped = await sb(`/rest/v1/playlists?on_conflict=connection_id,playlist_id`, {
    method: "POST",
    headers: { Prefer: "resolution=merge-duplicates,return=representation" },
    body: JSON.stringify(rows),
  });
  if (scoped.ok) return scoped;

  const scopedText = await scoped.text().catch(() => "");
  const missingScopedConstraint =
    scoped.status === 400 &&
    /connection_id|playlist_id|constraint|schema cache|unique/i.test(scopedText);
  if (!missingScopedConstraint) {
    return new Response(scopedText, { status: scoped.status, statusText: scoped.statusText });
  }

  // Compatibility path until the DB migration adding unique(connection_id, playlist_id) is applied.
  return sb(`/rest/v1/playlists?on_conflict=playlist_id`, {
    method: "POST",
    headers: {
      Prefer: "resolution=merge-duplicates,return=representation",
      "x-playlistpilot-fallback": "global-playlist-id",
    },
    body: JSON.stringify(rows),
  });
}

function checkCronAuth(req) {
  const want = process.env.CRON_SECRET || "";
  const gotAuth = req.headers?.authorization || "";
  const url = new URL(req.url, `http://${req.headers.host}`);
  const qpKey = url.searchParams.get("key") || url.searchParams.get("cron_secret");
  const isVercelCron = (req.headers["x-vercel-cron"] === "1") && (process.env.VERCEL === "1");

  if (want && (gotAuth === `Bearer ${want}` || qpKey === want)) return true;
  if (isVercelCron) return true;
  return !want;  // falls ohne Secret explizit offen gewünscht
}

function checkAppSecret(req) {
  const want = process.env.APP_WEBHOOK_SECRET;
  const got = req.headers["x-app-secret"];
  if (want && got !== want) return false;
  return true;
}

function hasValidAppSecret(req) {
  const want = process.env.APP_WEBHOOK_SECRET || "";
  const got = req.headers["x-app-secret"] || "";
  return !!want && got === want;
}

function getBearerToken(req) {
  const auth = req.headers?.authorization || "";
  const match = String(auth).match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : "";
}

function getPublicSupabaseKey() {
  return process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY || "";
}

async function getSupabaseAuthUser(req) {
  const token = getBearerToken(req);
  const publicKey = getPublicSupabaseKey();
  if (!token || !publicKey) return null;

  const r = await fetch(`${need("SUPABASE_URL")}/auth/v1/user`, {
    headers: {
      apikey: publicKey,
      Authorization: `Bearer ${token}`,
    },
    cache: "no-store",
  });

  if (!r.ok) return null;
  return await r.json().catch(() => null);
}

async function getUserContext(req) {
  const authUser = await getSupabaseAuthUser(req);
  if (!authUser?.id || !authUser?.email) return null;

  const email = String(authUser.email).trim().toLowerCase();
  const byAuth = await sb(
    `/rest/v1/user_identity_links?select=auth_user_id,email,bubble_user_id,role&limit=1&auth_user_id=eq.${encodeURIComponent(authUser.id)}`
  );
  const authRows = byAuth.ok ? await byAuth.json().catch(() => []) : [];
  let link = authRows?.[0] || null;

  if (!link) {
    const byEmail = await sb(
      `/rest/v1/user_identity_links?select=id,auth_user_id,email,bubble_user_id,role&limit=1&email=eq.${encodeURIComponent(email)}`
    );
    const emailRows = byEmail.ok ? await byEmail.json().catch(() => []) : [];
    link = emailRows?.[0] || null;

    if (link && !link.auth_user_id) {
      await sb(`/rest/v1/user_identity_links?id=eq.${encodeURIComponent(link.id)}`, {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ auth_user_id: authUser.id, updated_at: new Date().toISOString() }),
      }).catch(() => {});
      link.auth_user_id = authUser.id;
    }
  }

  if (!link) {
    const bubble_user_id = `auth:${authUser.id}`;
    const userUpsert = await sb(`/rest/v1/app_users?on_conflict=bubble_user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=ignore-duplicates,return=minimal" },
      body: JSON.stringify([{
        bubble_user_id,
        subscription_status: "none",
        sub_status: "none",
        is_active: false,
        seats_limit: 0,
        seats_used: 0,
      }])
    });
    if (userUpsert.ok) {
      const linkInsert = await sb(`/rest/v1/user_identity_links`, {
        method: "POST",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify([{
          auth_user_id: authUser.id,
          email,
          bubble_user_id,
          role: "user",
        }])
      });
      const inserted = linkInsert.ok ? await linkInsert.json().catch(() => []) : [];
      link = inserted?.[0] || null;
    }
  }

  if (!link?.bubble_user_id) return { authUser, email, linked: false };
  return {
    authUser,
    email,
    linked: true,
    bubble_user_id: link.bubble_user_id,
    role: link.role || "user",
  };
}

async function bubbleUserIdFromRequest(req, explicitValue = "") {
  const ctx = await getUserContext(req);
  if (ctx?.bubble_user_id) return ctx.bubble_user_id;

  const legacyValue = String(explicitValue || req.headers?.["x-bubble-user-id"] || "").trim();
  if (legacyValue && hasValidAppSecret(req)) return legacyValue;

  return "";
}

function getStripeClient() {
  const key = need("STRIPE_SECRET_KEY");
  return new Stripe(key);
}

function publicBaseUrl(req = null) {
  return process.env.PUBLIC_BASE_URL || (req?.headers?.host ? `https://${req.headers.host}` : "https://playlist-pilot.com");
}

function internalBaseUrl() {
  return process.env.PUBLIC_BASE_URL || "https://playlist-pilot.com";
}

function stripePlanCatalog() {
  return {
    economy_monthly: {
      price: process.env.STRIPE_PRICE_ECONOMY_MONTHLY || process.env.STRIPE_PRICE_PRO || "",
      plan_code: "economy",
      plan_name: "Economy Class",
      interval: "month",
      seats_limit: 1,
      features: { playlist_tools: true, rotator: true, automations: true },
    },
    economy_yearly: {
      price: process.env.STRIPE_PRICE_ECONOMY_YEARLY || "",
      plan_code: "economy",
      plan_name: "Economy Class",
      interval: "year",
      seats_limit: 1,
      features: { playlist_tools: true, rotator: true, automations: true },
    },
    business_monthly: {
      price: process.env.STRIPE_PRICE_BUSINESS_MONTHLY || "",
      plan_code: "business",
      plan_name: "Business Class",
      interval: "month",
      seats_limit: 5,
      features: { playlist_tools: true, rotator: true, automations: true, multi_account: true },
    },
    business_yearly: {
      price: process.env.STRIPE_PRICE_BUSINESS_YEARLY || "",
      plan_code: "business",
      plan_name: "Business Class",
      interval: "year",
      seats_limit: 5,
      features: { playlist_tools: true, rotator: true, automations: true, multi_account: true },
    },
  };
}

function mapStripePlan(priceId) {
  for (const plan of Object.values(stripePlanCatalog())) {
    if (plan.price && priceId === plan.price) {
      return { plan_code: plan.plan_code, seats_limit: plan.seats_limit, features: plan.features };
    }
  }
  return { plan_code: "economy", seats_limit: 1, features: { playlist_tools: true, rotator: true, automations: true } };
}

function isAppSubscriptionActive(row = {}, bubble_user_id = "") {
  const hasProviderSubscription = !!(
    row.provider_subscription_id ||
    row.stripe_subscription_id
  );
  // Fresh Supabase-auth workspaces must not inherit legacy app_users defaults.
  if (String(bubble_user_id || row.bubble_user_id || "").startsWith("auth:") && !hasProviderSubscription) return false;
  if (row.is_active === true) return true;
  const status = String(row.sub_status || row.subscription_status || "").toLowerCase();
  if (["active", "trialing"].includes(status)) return true;
  if (status === "canceled" && row.current_period_end) {
    return new Date(row.current_period_end).getTime() > Date.now();
  }
  if (row.subscription_expires_at) {
    return new Date(row.subscription_expires_at).getTime() > Date.now();
  }
  return false;
}

async function getBillingState(bubble_user_id) {
  const r = await sb(
    `/rest/v1/app_users?select=bubble_user_id,provider,provider_subscription_id,stripe_customer_id,stripe_subscription_id,stripe_price_id,subscription_status,subscription_expires_at,plan_code,sub_status,is_active,seats_limit,seats_used,features,current_period_end,cancel_at_period_end,last_synced_at` +
    `&limit=1&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}`
  );
  const row = r.ok ? (await r.json().catch(() => []))?.[0] : null;
  return {
    row,
    is_active: isAppSubscriptionActive(row || {}, bubble_user_id),
    status: row?.sub_status || row?.subscription_status || "none",
  };
}

async function findActiveSpotifyOwner(spotify_user_id, bubble_user_id) {
  if (!spotify_user_id) return null;
  const r = await sb(
    `/rest/v1/spotify_connections?select=id,bubble_user_id,spotify_user_id,display_name` +
      `&limit=1&is_active=is.true` +
      `&spotify_user_id=eq.${encodeURIComponent(spotify_user_id)}` +
      `&bubble_user_id=neq.${encodeURIComponent(bubble_user_id)}`
  );
  const rows = r.ok ? await r.json().catch(() => []) : [];
  return rows?.[0] || null;
}

async function upsertStripeSubscriptionState({ bubble_user_id, customer_id, subscription }) {
  const item = subscription?.items?.data?.[0] || null;
  const priceId = item?.price?.id || null;
  const mapped = mapStripePlan(priceId);
  const status = String(subscription?.status || "unknown");
  const currentPeriodEnd = subscription?.current_period_end
    ? new Date(subscription.current_period_end * 1000).toISOString()
    : null;
  const active = ["active", "trialing"].includes(status) || (status === "canceled" && currentPeriodEnd && new Date(currentPeriodEnd) > new Date());

  const payload = {
    bubble_user_id,
    provider: "stripe",
    provider_subscription_id: subscription?.id || null,
    stripe_customer_id: customer_id || subscription?.customer || null,
    stripe_subscription_id: subscription?.id || null,
    stripe_price_id: priceId,
    subscription_status: status,
    subscription_expires_at: currentPeriodEnd,
    plan_code: mapped.plan_code,
    subscription_plan_code: mapped.plan_code,
    sub_status: status,
    is_active: active,
    seats_limit: mapped.seats_limit,
    features: mapped.features,
    current_period_end: currentPeriodEnd,
    cancel_at_period_end: !!subscription?.cancel_at_period_end,
    last_synced_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const up = await sb(`/rest/v1/app_users?on_conflict=bubble_user_id`, {
    method: "POST",
    headers: { Prefer: "resolution=merge-duplicates,return=representation" },
    body: JSON.stringify([payload]),
  });
  const txt = await up.text();
  if (!up.ok) throw new Error(`stripe_subscription_upsert_failed: ${txt}`);
  const data = txt ? JSON.parse(txt) : [];
  return Array.isArray(data) ? data[0] : data;
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

function parseSpotifyPlaylistId(input) {
  const s = String(input || "").trim();
  if (!s) return null;
  let m;
  if ((m = s.match(/spotify:playlist:([A-Za-z0-9]{22})/))) return m[1];
  if ((m = s.match(/open\.spotify\.com\/(?:intl-[a-z-]+\/)?playlist\/([A-Za-z0-9]{22})/))) return m[1];
  if (/^[A-Za-z0-9]{22}$/.test(s)) return s;
  try {
    const u = new URL(s.startsWith("http") ? s : `https://${s}`);
    if (!/(^|\.)spotify\.com$/i.test(u.hostname)) return null;
    const parts = u.pathname.split("/").filter(Boolean);
    if (parts[0] && /^intl-/i.test(parts[0])) parts.shift();
    if (parts[0] === "playlist" && /^[A-Za-z0-9]{22}$/.test(parts[1])) return parts[1];
  } catch {}
  return null;
}

function nextFlexRotationAt(interval, from = new Date()) {
  const d = new Date(from);
  const mode = String(interval || "weekly").toLowerCase();
  if (mode === "daily") d.setUTCDate(d.getUTCDate() + 1);
  else if (mode === "monthly") d.setUTCMonth(d.getUTCMonth() + 1);
  else d.setUTCDate(d.getUTCDate() + 7);
  return d.toISOString();
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

function fallbackSpotifyCredentials({ requireRedirect = false } = {}) {
  const client_id = process.env.SPOTIFY_CLIENT_ID || "";
  const client_secret = process.env.SPOTIFY_CLIENT_SECRET || "";
  const redirect_uri = process.env.SPOTIFY_REDIRECT_URI || "";
  if (!client_id || !client_secret || (requireRedirect && !redirect_uri)) return null;
  return { id: null, client_id, client_secret, redirect_uri, source: "global" };
}

async function getSpotifyAppCredentialsForUser(bubble_user_id, { allowFallback = true } = {}) {
  if (bubble_user_id) {
    const r = await sb(
      `/rest/v1/spotify_app_credentials?select=id,client_id,client_secret_enc,redirect_uri,app_name` +
      `&limit=1&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}`
    );
    const row = r.ok ? (await r.json().catch(() => []))?.[0] : null;
    if (row?.client_id && row?.client_secret_enc && row?.redirect_uri) {
      return {
        id: row.id,
        client_id: row.client_id,
        client_secret: decryptToken(row.client_secret_enc),
        redirect_uri: row.redirect_uri,
        app_name: row.app_name || "",
        source: "user",
      };
    }
  }

  if (!allowFallback) return null;
  return fallbackSpotifyCredentials({ requireRedirect: true });
}

async function getSpotifyAppCredentialsForConnection(connection_id) {
  const r = await sb(
    `/rest/v1/spotify_connections?select=bubble_user_id,credential_id` +
    `&limit=1&id=eq.${encodeURIComponent(connection_id)}`
  );
  const row = r.ok ? (await r.json().catch(() => []))?.[0] : null;
  if (row?.credential_id) {
    const cr = await sb(
      `/rest/v1/spotify_app_credentials?select=id,client_id,client_secret_enc,redirect_uri,app_name` +
      `&limit=1&id=eq.${encodeURIComponent(row.credential_id)}`
    );
    const cred = cr.ok ? (await cr.json().catch(() => []))?.[0] : null;
    if (cred?.client_id && cred?.client_secret_enc && cred?.redirect_uri) {
      return {
        id: cred.id,
        client_id: cred.client_id,
        client_secret: decryptToken(cred.client_secret_enc),
        redirect_uri: cred.redirect_uri,
        app_name: cred.app_name || "",
        source: "connection",
      };
    }
  }
  return fallbackSpotifyCredentials();
}

async function refreshAccessToken(refresh_token, credentials = null) {
  const creds = credentials || fallbackSpotifyCredentials();
  if (!creds?.client_id || !creds?.client_secret) throw new Error("missing_spotify_app_credentials");
  const body = new URLSearchParams({
    grant_type:"refresh_token",
    refresh_token,
    client_id: creds.client_id,
    client_secret: creds.client_secret
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
  const creds = await getSpotifyAppCredentialsForConnection(connection_id);
  const t = await refreshAccessToken(refresh_token, creds);
  return t.access_token;
}

async function fetchSpotifyPlaylistSnapshot(playlist, access_token, knownMeta = null) {
  let meta = knownMeta;
  if (!meta) {
    const metaR = await fetchJSON(
      `https://api.spotify.com/v1/playlists/${encodeURIComponent(playlist.playlist_id)}?fields=name,description,images,snapshot_id,followers(total),tracks(total)`,
      { headers: { Authorization: `Bearer ${access_token}` } },
      20000
    );
    if (!metaR.r.ok) throw new Error(`spotify_backup_meta_failed:${metaR.r.status}:${metaR.text || JSON.stringify(metaR.json)}`);
    meta = metaR.json || {};
  }
  const tracks = [];
  let offset = 0;
  let guard = 0;
  while (guard++ < 100) {
    const pageR = await fetchJSON(
      `https://api.spotify.com/v1/playlists/${encodeURIComponent(playlist.playlist_id)}/tracks?limit=100&offset=${offset}&fields=items(added_at,track(id,uri,name,album(name,images),artists(name))),next`,
      { headers: { Authorization: `Bearer ${access_token}` } },
      30000
    );
    if (!pageR.r.ok) throw new Error(`spotify_backup_tracks_failed:${pageR.r.status}:${pageR.text || JSON.stringify(pageR.json)}`);
    const items = Array.isArray(pageR.json?.items) ? pageR.json.items : [];
    items.forEach((it, index) => {
      const t = it?.track || {};
      const album = t?.album || {};
      const artists = Array.isArray(t?.artists) ? t.artists : [];
      tracks.push({
        position: offset + index,
        track_id: t.id || null,
        track_uri: t.uri || null,
        track_name: t.name || null,
        artist_names: artists.map(a => a?.name).filter(Boolean).join(", "),
        album_name: album?.name || null,
        added_at: it?.added_at || null
      });
    });
    if (!pageR.json?.next || !items.length) break;
    offset += items.length;
    await sleep(40);
  }
  return { meta, tracks };
}

async function enrichBackupTracksWithAutomationState(playlist_id, tracks) {
  const [locksR, slotsR] = await Promise.all([
    sb(`/rest/v1/playlist_item_locks?select=track_id,is_locked,locked_position,expiry_weeks&playlist_id=eq.${encodeURIComponent(playlist_id)}`).catch(() => null),
    sb(`/rest/v1/playlist_flex_slots?select=position,current_track_id,last_rotated_at&playlist_id=eq.${encodeURIComponent(playlist_id)}`).catch(() => null)
  ]);
  const lockRows = locksR?.ok ? await locksR.json().catch(() => []) : [];
  const slotRows = slotsR?.ok ? await slotsR.json().catch(() => []) : [];
  const locksByTrack = new Map((Array.isArray(lockRows) ? lockRows : []).filter(x => x?.track_id).map(x => [x.track_id, x]));
  const flexByTrack = new Map((Array.isArray(slotRows) ? slotRows : []).filter(x => x?.current_track_id).map(x => [x.current_track_id, x]));
  return (Array.isArray(tracks) ? tracks : []).map((track) => {
    const lock = locksByTrack.get(track.track_id);
    const flex = flexByTrack.get(track.track_id);
    return {
      ...track,
      is_locked: !!lock?.is_locked,
      locked_position: lock?.locked_position ?? null,
      expiry_weeks: lock?.expiry_weeks ?? null,
      is_rotator: !!flex,
      rotator_position: flex?.position ?? null,
      rotator_last_rotated_at: flex?.last_rotated_at ?? null
    };
  });
}

async function createPlaylistBackup(playlist, { reason = "manual", onlyIfChanged = false } = {}) {
  const access_token = await getAccessTokenFromConnection(playlist.connection_id);
  const metaR = await fetchJSON(
    `https://api.spotify.com/v1/playlists/${encodeURIComponent(playlist.playlist_id)}?fields=name,description,images,snapshot_id,followers(total),tracks(total)`,
    { headers: { Authorization: `Bearer ${access_token}` } },
    20000
  );
  if (!metaR.r.ok) throw new Error(`spotify_backup_meta_failed:${metaR.r.status}:${metaR.text || JSON.stringify(metaR.json)}`);
  const meta = metaR.json || {};
  const snapshot_id = meta?.snapshot_id || null;
  if (onlyIfChanged && snapshot_id) {
    const lastR = await sb(
      `/rest/v1/playlist_backups?select=id,snapshot_id` +
      `&playlist_id=eq.${encodeURIComponent(playlist.id)}` +
      `&order=taken_at.desc&limit=1`
    );
    const last = lastR.ok ? (await lastR.json())?.[0] : null;
    if (last?.snapshot_id === snapshot_id) return { skipped: true, reason: "unchanged_snapshot", snapshot_id };
  }
  const { tracks } = await fetchSpotifyPlaylistSnapshot(playlist, access_token, meta);
  const enrichedTracks = await enrichBackupTracksWithAutomationState(playlist.id, tracks);
  const payload = {
    playlist_id: playlist.id,
    spotify_playlist_id: playlist.playlist_id,
    snapshot_id,
    taken_at: new Date().toISOString(),
    name: meta?.name || playlist.name || null,
    description: meta?.description || null,
    image: meta?.images?.[0]?.url || playlist.image || null,
    followers: meta?.followers?.total ?? playlist.followers ?? null,
    tracks_total: enrichedTracks.length,
    tracks: enrichedTracks,
    bubble_user_id: playlist.bubble_user_id,
    reason
  };
  let insert = await sb(`/rest/v1/playlist_backups`, {
    method: "POST",
    headers: { Prefer: "return=representation" },
    body: JSON.stringify([payload])
  });
  if (!insert.ok) {
    const text = await insert.text();
    if (text.includes("reason")) {
      const { reason: _reason, ...fallbackPayload } = payload;
      insert = await sb(`/rest/v1/playlist_backups`, {
        method: "POST",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify([fallbackPayload])
      });
    } else {
      throw new Error(`backup_insert_failed:${text}`);
    }
  }
  if (!insert.ok) throw new Error(`backup_insert_failed:${await insert.text()}`);
  const rows = await insert.json();
  return { skipped: false, backup: rows?.[0] || null, snapshot_id };
}

async function replaceSpotifyPlaylistTracks(spotify_playlist_id, access_token, uris) {
  const cleanUris = (Array.isArray(uris) ? uris : []).filter(Boolean);
  if (!cleanUris.length) throw new Error("backup_has_no_tracks");

  const first = cleanUris.slice(0, 100);
  const replace = await fetchJSON(
    `https://api.spotify.com/v1/playlists/${encodeURIComponent(spotify_playlist_id)}/tracks`,
    {
      method: "PUT",
      headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ uris: first })
    },
    30000
  );
  if (!replace.r.ok) {
    throw new Error(`spotify_restore_replace_failed:${replace.r.status}:${replace.text || JSON.stringify(replace.json)}`);
  }

  let snapshot_id = replace.json?.snapshot_id || null;
  for (const batch of chunkArray(cleanUris.slice(100), 100)) {
    const append = await fetchJSON(
      `https://api.spotify.com/v1/playlists/${encodeURIComponent(spotify_playlist_id)}/tracks`,
      {
        method: "POST",
        headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ uris: batch })
      },
      30000
    );
    if (!append.r.ok) {
      throw new Error(`spotify_restore_append_failed:${append.r.status}:${append.text || JSON.stringify(append.json)}`);
    }
    snapshot_id = append.json?.snapshot_id || snapshot_id;
    await sleep(120);
  }
  return { snapshot_id, tracks_total: cleanUris.length };
}

function summarizeBackupTracks(tracks = []) {
  const rows = Array.isArray(tracks) ? tracks : [];
  return {
    tracks_total: rows.length,
    locked_total: rows.filter((track) => track?.is_locked).length,
    expiry_total: rows.filter((track) => track?.expiry_weeks !== null && track?.expiry_weeks !== undefined).length,
    rotator_total: rows.filter((track) => track?.is_rotator).length,
  };
}

async function getBackupForPlaylist(playlist_id, backup_id) {
  const r = await sb(
    `/rest/v1/playlist_backups?select=*` +
    `&id=eq.${encodeURIComponent(String(backup_id))}` +
    `&playlist_id=eq.${encodeURIComponent(String(playlist_id))}` +
    `&limit=1`
  );
  if (!r.ok) throw new Error(`backup_select_failed:${await r.text()}`);
  return (await r.json())?.[0] || null;
}

function backupTrackKey(track) {
  return track?.track_uri || (track?.track_id ? trackUri(track.track_id) : "");
}

function diffBackupAgainstCurrent(backupTracks = [], currentTracks = []) {
  const backup = Array.isArray(backupTracks) ? backupTracks : [];
  const current = Array.isArray(currentTracks) ? currentTracks : [];
  const currentByUri = new Map(current.map((track, index) => [backupTrackKey(track), { track, index }]).filter(([key]) => key));
  const backupByUri = new Map(backup.map((track, index) => [backupTrackKey(track), { track, index }]).filter(([key]) => key));
  let moved = 0, added = 0, removed = 0, lock_changes = 0, expiry_changes = 0, rotator_changes = 0;
  const preview = [];

  for (let i = 0; i < backup.length; i++) {
    const target = backup[i];
    const key = backupTrackKey(target);
    const currentMatch = key ? currentByUri.get(key) : null;
    if (!currentMatch) {
      added++;
      if (preview.length < 12) preview.push({ type: "restore_add", track_name: target.track_name, to_position: i });
      continue;
    }
    if (currentMatch.index !== i) {
      moved++;
      if (preview.length < 12) preview.push({ type: "move", track_name: target.track_name, from_position: currentMatch.index, to_position: i });
    }
    const source = currentMatch.track || {};
    if (!!source.is_locked !== !!target.is_locked || Number(source.locked_position ?? -1) !== Number(target.locked_position ?? -1)) lock_changes++;
    if (String(source.expiry_weeks ?? "") !== String(target.expiry_weeks ?? "")) expiry_changes++;
    if (!!source.is_rotator !== !!target.is_rotator || Number(source.rotator_position ?? -1) !== Number(target.rotator_position ?? -1)) rotator_changes++;
  }
  for (let i = 0; i < current.length; i++) {
    const source = current[i];
    const key = backupTrackKey(source);
    if (key && !backupByUri.has(key)) {
      removed++;
      if (preview.length < 12) preview.push({ type: "remove_current", track_name: source.track_name, from_position: i });
    }
  }
  return { moved, added, removed, lock_changes, expiry_changes, rotator_changes, preview };
}

async function fetchCurrentPlaylistItemsForBackupDiff(playlist_id) {
  const r = await sb(
    `/rest/v1/playlist_items?select=position,track_id,track_name,artist_names,album_name,added_at,is_locked,locked_position,expiry_weeks` +
    `&playlist_id=eq.${encodeURIComponent(String(playlist_id))}` +
    `&order=position.asc&limit=2000`
  );
  const items = r.ok ? await r.json().catch(() => []) : [];
  const slotsR = await sb(
    `/rest/v1/playlist_flex_slots?select=position,current_track_id,last_rotated_at&playlist_id=eq.${encodeURIComponent(String(playlist_id))}`
  ).catch(() => null);
  const slots = slotsR?.ok ? await slotsR.json().catch(() => []) : [];
  const flexByTrack = new Map((Array.isArray(slots) ? slots : []).filter(x => x?.current_track_id).map(x => [x.current_track_id, x]));
  return (Array.isArray(items) ? items : []).map((item) => {
    const flex = flexByTrack.get(item.track_id);
    return {
      ...item,
      track_uri: item.track_id ? trackUri(item.track_id) : null,
      is_rotator: !!flex,
      rotator_position: flex?.position ?? null,
      rotator_last_rotated_at: flex?.last_rotated_at ?? null
    };
  });
}

async function restoreBackupAutomationState(playlist, tracks, options = {}) {
  const rows = Array.isArray(tracks) ? tracks : [];
  const nowIso = new Date().toISOString();
  let locks_restored = 0;
  let rotator_slots_restored = 0;

  if (options.restore_locks) {
    const lockRows = rows
      .filter((track) => track?.track_id && (track.is_locked || track.expiry_weeks !== null && track.expiry_weeks !== undefined))
      .map((track, index) => ({
        playlist_id: playlist.id,
        track_id: track.track_id,
        locked_position: track.is_locked ? Number(track.locked_position ?? index) : null,
        is_locked: !!track.is_locked,
        locked_at: track.is_locked ? nowIso : null,
        expiry_weeks: track.expiry_weeks ?? null,
      }));
    if (lockRows.length) {
      const r = await sb(`/rest/v1/playlist_item_locks?on_conflict=playlist_id,track_id`, {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify(lockRows),
      });
      if (!r.ok) throw new Error(`lock_restore_failed:${await r.text()}`);
      locks_restored = lockRows.length;
    }
  }

  if (options.restore_rotator) {
    const del = await sb(`/rest/v1/playlist_flex_slots?playlist_id=eq.${encodeURIComponent(playlist.id)}`, { method: "DELETE" });
    if (!del.ok) throw new Error(`rotator_clear_failed:${await del.text()}`);
    const slotRows = rows
      .filter((track) => track?.is_rotator && track?.track_id)
      .map((track, index) => ({
        playlist_id: playlist.id,
        bubble_user_id: playlist.bubble_user_id,
        connection_id: playlist.connection_id,
        position: Number(track.rotator_position ?? track.locked_position ?? index),
        current_track_id: track.track_id,
        current_track_name: track.track_name || null,
        source_track_id: track.track_id,
        last_rotated_at: track.rotator_last_rotated_at || null,
        updated_at: nowIso,
      }));
    if (slotRows.length) {
      const r = await sb(`/rest/v1/playlist_flex_slots`, {
        method: "POST",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify(slotRows),
      });
      if (!r.ok) throw new Error(`rotator_restore_failed:${await r.text()}`);
      rotator_slots_restored = slotRows.length;
    }
  }
  return { locks_restored, rotator_slots_restored };
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

async function refreshAccessTokenDirect(refresh_token, credentials) {
  const response = await fetch("https://accounts.spotify.com/api/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token,
      client_id: credentials.client_id,
      client_secret: credentials.client_secret,
    }),
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok || !payload?.access_token) {
    throw new Error(`spotify_refresh_failed_${response.status}`);
  }
  return payload.access_token;
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

async function setPlaylistUpdateCooldown(playlist_id, seconds = 90) {
  const until = new Date(Date.now() + Math.max(1, seconds) * 1000).toISOString();
  await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(String(playlist_id))}`, {
    method: "PATCH",
    headers: { Prefer: "return=minimal" },
    body: JSON.stringify({ next_check_at: until, needs_sync: true })
  }).catch(() => {});
  return until;
}

async function getOwnedPlaylist(playlist_id, bubble_user_id) {
  const r = await sb(
    `/rest/v1/playlists?select=id,playlist_id,connection_id,bubble_user_id,name,image,tracks_total` +
    `&limit=1&id=eq.${encodeURIComponent(String(playlist_id))}` +
    `&bubble_user_id=eq.${encodeURIComponent(String(bubble_user_id))}`
  );
  const rows = r.ok ? await r.json().catch(() => []) : [];
  return rows?.[0] || null;
}

function normalizeFlexRules(settings = {}) {
  const minPopularity = Number(settings.min_popularity);
  const maxPopularity = Number(settings.max_popularity);
  const maxReleaseAgeWeeks = Number(settings.max_release_age_weeks);
  const repeatCooldownWeeks = Number(settings.repeat_cooldown_weeks);
  return {
    repeat_cooldown_weeks: Number.isFinite(repeatCooldownWeeks) ? Math.max(0, Math.min(260, repeatCooldownWeeks)) : 8,
    avoid_target_duplicates: settings.avoid_target_duplicates !== false,
    min_popularity: Number.isFinite(minPopularity) ? Math.max(0, Math.min(100, minPopularity)) : null,
    max_popularity: Number.isFinite(maxPopularity) ? Math.max(0, Math.min(100, maxPopularity)) : null,
    max_release_age_weeks: Number.isFinite(maxReleaseAgeWeeks) ? Math.max(1, Math.min(520, maxReleaseAgeWeeks)) : null,
  };
}

function releaseDateToTime(value) {
  if (!value) return NaN;
  const text = String(value);
  const normalized = text.length === 4 ? `${text}-01-01` : text.length === 7 ? `${text}-01` : text;
  return Date.parse(`${normalized}T00:00:00Z`);
}

function chunkArray(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

async function fetchReferencePlaylistTracks(reference_playlist_id, access_token) {
  const tracks = [];
  let url = `https://api.spotify.com/v1/playlists/${encodeURIComponent(reference_playlist_id)}/tracks?limit=100&offset=0&fields=items(track(id,uri,name,is_local,type,popularity,album(release_date,release_date_precision))),next`;
  let guard = 0;
  while (url && guard++ < 20) {
    const { r, json, text } = await fetchJSON(url, { headers: { Authorization: `Bearer ${access_token}` } }, 20000);
    if (!r.ok) throw new Error(`reference_playlist_fetch_failed:${r.status}:${text || JSON.stringify(json)}`);
    for (const item of (json?.items || [])) {
      const t = item?.track;
      if (t?.id && t?.uri && t.type === "track" && !t.is_local) tracks.push(t);
    }
    url = json?.next || "";
  }
  return tracks;
}

async function getPlaylistTrackIds(playlist_id) {
  const ids = new Set();
  const r = await sb(
    `/rest/v1/playlist_items?select=track_id&playlist_id=eq.${encodeURIComponent(playlist_id)}&limit=2000`
  );
  if (!r.ok) return ids;
  const rows = await r.json().catch(() => []);
  for (const row of rows || []) {
    if (row.track_id) ids.add(row.track_id);
  }
  return ids;
}

async function getFlexRecentTrackIds(playlist_id, cooldownWeeks) {
  const ids = new Set();
  if (!cooldownWeeks) return ids;
  const since = new Date(Date.now() - cooldownWeeks * 7 * 24 * 3600 * 1000).toISOString();
  const r = await sb(
    `/rest/v1/playlist_flex_history?select=track_id` +
    `&playlist_id=eq.${encodeURIComponent(playlist_id)}` +
    `&rotated_at=gte.${encodeURIComponent(since)}` +
    `&limit=1000`
  );
  if (!r.ok) return ids;
  const rows = await r.json().catch(() => []);
  for (const row of rows || []) {
    if (row.track_id) ids.add(row.track_id);
  }
  return ids;
}

async function fetchSpotifyPlaylistMeta(playlist_id, access_token) {
  if (!playlist_id || !access_token) return null;
  const { r, json } = await fetchJSON(
    `https://api.spotify.com/v1/playlists/${encodeURIComponent(playlist_id)}?fields=id,name,description,images,owner(display_name),followers(total),tracks(total),external_urls`,
    { headers: { Authorization: `Bearer ${access_token}` } },
    20000
  );
  if (!r.ok || !json?.id) return null;
  return {
    id: json.id,
    name: json.name || null,
    description: json.description || null,
    image: json.images?.[0]?.url || null,
    owner_name: json.owner?.display_name || null,
    followers: json.followers?.total ?? null,
    tracks_total: json.tracks?.total ?? null,
    url: json.external_urls?.spotify || null
  };
}

async function findPlaylistTrackPosition(spotify_playlist_id, track_id, access_token, preferred_position = 0) {
  const matches = [];
  let offset = 0;
  let guard = 0;
  while (guard++ < 25) {
    const { r, json, text } = await fetchJSON(
      `https://api.spotify.com/v1/playlists/${encodeURIComponent(spotify_playlist_id)}/tracks?fields=items(track(id,uri)),total,next&limit=100&offset=${offset}`,
      { headers: { Authorization: `Bearer ${access_token}` } },
      20000
    );
    if (!r.ok) throw new Error(`spotify_position_probe_failed:${r.status}:${text || JSON.stringify(json)}`);
    const items = Array.isArray(json?.items) ? json.items : [];
    items.forEach((item, index) => {
      if (item?.track?.id === track_id) matches.push(offset + index);
    });
    if (!json?.next || !items.length) break;
    offset += items.length;
  }
  if (!matches.length) return -1;
  const preferred = Math.max(0, Number(preferred_position) || 0);
  return matches.sort((a, b) => Math.abs(a - preferred) - Math.abs(b - preferred))[0];
}

async function rotateFlexSlot(slot, settings) {
  const access_token = await getAccessTokenFromConnection(slot.connection_id);
  const playlistRows = await sb(`/rest/v1/playlists?select=id,playlist_id&limit=1&id=eq.${encodeURIComponent(slot.playlist_id)}`).then(r => r.json());
  const playlist = playlistRows?.[0];
  if (!playlist?.playlist_id) throw new Error("playlist_not_found");

  const refPlaylistId = settings?.reference_playlist_id || slot.source_playlist_id;
  if (!refPlaylistId) throw new Error("missing_reference_playlist");

  const rules = normalizeFlexRules(settings);
  const candidates = await fetchReferencePlaylistTracks(refPlaylistId, access_token);
  const targetTrackIds = rules.avoid_target_duplicates ? await getPlaylistTrackIds(slot.playlist_id) : new Set();
  const recentTrackIds = await getFlexRecentTrackIds(slot.playlist_id, rules.repeat_cooldown_weeks);
  const releaseCutoff = rules.max_release_age_weeks
    ? Date.now() - rules.max_release_age_weeks * 7 * 24 * 3600 * 1000
    : null;
  const usable = candidates.filter((t) => {
    if (!t?.id || t.id === slot.current_track_id) return false;
    if (rules.avoid_target_duplicates && targetTrackIds.has(t.id)) return false;
    if (recentTrackIds.has(t.id)) return false;
    const popularity = Number(t.popularity);
    if (rules.min_popularity !== null && Number.isFinite(popularity) && popularity < rules.min_popularity) return false;
    if (rules.max_popularity !== null && Number.isFinite(popularity) && popularity > rules.max_popularity) return false;
    if (releaseCutoff) {
      const releaseTime = releaseDateToTime(t.album?.release_date);
      if (!Number.isFinite(releaseTime) || releaseTime < releaseCutoff) return false;
    }
    return true;
  });
  if (!usable.length) throw new Error("reference_playlist_has_no_usable_tracks");
  const picked = usable[Math.floor(Math.random() * usable.length)];
  const desired = Math.max(0, Number(slot.position) || 0);

  const oldPosition = await findPlaylistTrackPosition(playlist.playlist_id, slot.current_track_id, access_token, desired);
  const insertPosition = oldPosition >= 0 && oldPosition < desired ? desired + 1 : desired;

  const addR = await fetch(`https://api.spotify.com/v1/playlists/${encodeURIComponent(playlist.playlist_id)}/tracks`, {
    method: "POST",
    headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ uris: [picked.uri], position: insertPosition })
  });
  if (!addR.ok) throw new Error(`spotify_add_failed:${addR.status}:${await addR.text()}`);
  const addJson = await addR.json().catch(() => ({}));

  if (oldPosition >= 0) {
    const removePosition = oldPosition >= insertPosition ? oldPosition + 1 : oldPosition;
    const delR = await fetch(`https://api.spotify.com/v1/playlists/${encodeURIComponent(playlist.playlist_id)}/tracks`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        tracks: [{ uri: trackUri(slot.current_track_id), positions: [removePosition] }],
        ...(addJson?.snapshot_id ? { snapshot_id: addJson.snapshot_id } : {})
      })
    });
    if (!delR.ok) throw new Error(`spotify_remove_failed:${delR.status}:${await delR.text()}`);
  }

  const nowIso = new Date().toISOString();
  await sb(`/rest/v1/playlist_item_locks?playlist_id=eq.${encodeURIComponent(slot.playlist_id)}&track_id=eq.${encodeURIComponent(slot.current_track_id)}`, {
    method: "DELETE",
    headers: { Prefer: "return=minimal" }
  }).catch(() => {});
  await sb(`/rest/v1/playlist_item_locks?on_conflict=playlist_id,track_id`, {
    method: "POST",
    headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify([{
      playlist_id: slot.playlist_id,
      track_id: picked.id,
      locked_position: desired,
      is_locked: true,
      locked_at: nowIso
    }])
  });
  await sb(`/rest/v1/playlist_flex_slots?id=eq.${encodeURIComponent(slot.id)}`, {
    method: "PATCH",
    headers: { Prefer: "return=representation" },
    body: JSON.stringify({
      current_track_id: picked.id,
      current_track_name: picked.name || null,
      source_playlist_id: refPlaylistId,
      source_track_id: picked.id,
      last_rotated_at: nowIso,
      updated_at: nowIso
    })
  });
  await sb(`/rest/v1/playlist_flex_history`, {
    method: "POST",
    headers: { Prefer: "return=minimal" },
    body: JSON.stringify([{
      playlist_id: slot.playlist_id,
      slot_id: slot.id,
      bubble_user_id: slot.bubble_user_id,
      connection_id: slot.connection_id,
      track_id: picked.id,
      track_name: picked.name || null,
      source_playlist_id: refPlaylistId,
      rotated_at: nowIso
    }])
  }).catch(() => {});
  await sb(`/rest/v1/playlist_flex_settings?playlist_id=eq.${encodeURIComponent(slot.playlist_id)}`, {
    method: "PATCH",
    headers: { Prefer: "return=minimal" },
    body: JSON.stringify({
      last_rotated_at: nowIso,
      next_rotation_at: nextFlexRotationAt(settings?.interval || "weekly"),
      updated_at: nowIso
    })
  }).catch(() => {});

  const cooldownUntil = await setPlaylistUpdateCooldown(slot.playlist_id, 300);
  await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(slot.playlist_id)}`, {
    method: "PATCH",
    headers: { Prefer: "return=minimal" },
    body: JSON.stringify({ needs_sync: true, next_check_at: cooldownUntil })
  }).catch(() => {});

  const base = internalBaseUrl();
  if (base) {
    fetch(`${base}/api/playlists/dispatch-sync`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
      body: JSON.stringify({ playlist_id: slot.playlist_id })
    }).catch(() => {});
  }

  return { picked_track_id: picked.id, picked_track_name: picked.name || null, position: desired, cooldown_until: cooldownUntil };
}


/* ==============================
   PayPal helpers
============================== */

// Maps PayPal plan_id -> your internal plan info
export const PLAN_MAP = {
  // monthly
  "P-37R54649L5313890NNCUH6UQ": { plan_code: "economy",  term: "m", seats: 1,  features: { playlist_tools:true, feedback:true } },
  "P-8W102166E7155104WNDNNXLA": { plan_code: "business", term: "m", seats: 3,  features: { playlist_tools:true, feedback:true } },
  "P-12L562319L893910WNDNNYUQ": { plan_code: "first",    term: "m", seats: 10, features: { playlist_tools:true, feedback:true } },
  "P-3VM522122Y492971MNDOASFY": { plan_code: "luggage",  term: "m", seats: 0,  features: { playlist_tools:false, feedback:true } },

  // yearly
  "P-64J2759572685030ANDOAVVI": { plan_code: "economy_y",  term: "y", seats: 1,  features: { playlist_tools:true, feedback:true } },
  "P-0AY14242ML673252HNDOAVEQ": { plan_code: "business_y", term: "y", seats: 3,  features: { playlist_tools:true, feedback:true } },
  "P-76U26120YA480793KNDOAULQ": { plan_code: "first_y",    term: "y", seats: 10, features: { playlist_tools:true, feedback:true } },
  "P-0AF75583E6596344TNDOAWDQ": { plan_code: "luggage_y",  term: "y", seats: 0,  features: { playlist_tools:false, feedback:true } },
};

function paypalBase(env) {
  return env === "live" ? "https://api.paypal.com" : "https://api.sandbox.paypal.com";
}
function getPaypalCreds(env) {
  if (env === "live") {
    return {
      id: need("PAYPAL_CLIENT_ID_LIVE"),
      secret: need("PAYPAL_CLIENT_SECRET_LIVE"),
      webhookId: need("PAYPAL_WEBHOOK_ID_LIVE"),
    };
  }
  return {
    id: need("PAYPAL_CLIENT_ID_SANDBOX"),
    secret: need("PAYPAL_CLIENT_SECRET_SANDBOX"),
    webhookId: need("PAYPAL_WEBHOOK_ID_SANDBOX"),
  };
}
async function paypalAccessToken(env) {
  const { id, secret } = getPaypalCreds(env);
  const r = await fetch(`${paypalBase(env)}/v1/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: "Basic " + Buffer.from(`${id}:${secret}`).toString("base64") },
    body: "grant_type=client_credentials"
  });
  const j = await r.json();
  if (!r.ok || !j.access_token) throw new Error("paypal_token_failed");
  return j.access_token;
}
/** Heuristik: aus Headern Sandbox/Live ableiten; optional ?env= override */
function inferPaypalEnv(req) {
  const qpEnv = new URL(req.url, `http://${req.headers.host}`).searchParams.get("env");
  if (qpEnv === "live" || qpEnv === "sandbox") return qpEnv;
  const certUrl = String(req.headers["paypal-cert-url"] || "");
  return /sandbox/.test(certUrl) ? "sandbox" : "live";
}
async function readRawBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
  });
}
async function verifyPaypalWebhook(req, rawBody, env) {
  const { webhookId } = getPaypalCreds(env);
  const token = await paypalAccessToken(env);
  const payload = {
    transmission_id: req.headers["paypal-transmission-id"],
    transmission_time: req.headers["paypal-transmission-time"],
    cert_url: req.headers["paypal-cert-url"],
    auth_algo: req.headers["paypal-auth-algo"],
    transmission_sig: req.headers["paypal-transmission-sig"],
    webhook_id: webhookId,
    webhook_event: JSON.parse(rawBody || "{}"),
  };
  const r = await fetch(`${paypalBase(env)}/v1/notifications/verify-webhook-signature`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(payload),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.verification_status !== "SUCCESS") {
    throw new Error(`paypal_webhook_verify_failed: ${r.status} ${JSON.stringify(j)}`);
  }
  return j; // enthält u.a. verification_status
}
function mapPaypalStatus(s) {
  // PayPal liefert z.B. APPROVAL_PENDING, ACTIVE, SUSPENDED, CANCELLED, EXPIRED
  const up = String(s || "").toUpperCase();
  if (["ACTIVE","SUSPENDED","CANCELLED","EXPIRED","APPROVAL_PENDING"].includes(up)) return up;
  return up || "UNKNOWN";
}
/** Normalisiert wichtige Felder aus GET /v1/billing/subscriptions/{id} */
function normalizePaypalSubscription(json) {
  const status = mapPaypalStatus(json?.status);
  const plan_id = json?.plan_id || null;
  const create_time = json?.create_time || null;
  const billing = json?.billing_info || {};
  const lastPaymentTime = billing?.last_payment?.time || null;
  const nextBillingTime  = billing?.next_billing_time || null;

  // Grobe Heuristik für Start: letzte Zahlung oder create_time
  const current_period_start = lastPaymentTime || create_time || null;
  const current_period_end   = nextBillingTime || null;

  // cancel_at_period_end kennt PayPal so nicht direkt; wir setzen false und leiten realen Status über 'status' ab
  const cancel_at_period_end = false;

  const custom_id = json?.custom_id || json?.subscriber?.payer_id || null;
  return { status, plan_id, current_period_start, current_period_end, cancel_at_period_end, custom_id };
}




/* ==============================
   Route Handlers (map)
============================== */
const routes = {

  /* ---------- image-proxy (GET) ---------- */
  "image-proxy": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const raw = String(req.query.url || "");
    let target;
    try {
      target = new URL(raw);
    } catch {
      return bad(res, 400, "invalid_image_url");
    }
    const allowed = target.hostname === "i.scdn.co" || target.hostname.endsWith(".spotifycdn.com");
    if (!allowed) return bad(res, 400, "image_host_not_allowed");
    const proxied = await fetch(target.toString(), {
      headers: {
        Accept: "image/avif,image/webp,image/png,image/jpeg,image/*,*/*;q=0.8",
        "User-Agent": "PlaylistPilot/1.0"
      }
    });
    if (!proxied.ok) return bad(res, proxied.status, "image_fetch_failed");
    const contentType = proxied.headers.get("content-type") || "image/jpeg";
    if (!contentType.startsWith("image/")) return bad(res, 415, "unsupported_image_type");
    const buffer = Buffer.from(await proxied.arrayBuffer());
    res.setHeader("Content-Type", contentType);
    res.setHeader("Cache-Control", "public, max-age=86400, s-maxage=604800, stale-while-revalidate=604800");
    return res.status(200).send(buffer);
  },


  /* ---------- auth/me (GET) ---------- */
  "auth/me": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const ctx = await getUserContext(req);
    if (!ctx?.authUser) return bad(res, 401, "not_authenticated");
    if (!ctx.linked) {
      return json(res, 403, {
        ok: false,
        linked: false,
        email: ctx.email,
        error: "user_not_linked",
      });
    }

    const credentials = await getSpotifyAppCredentialsForUser(ctx.bubble_user_id, { allowFallback: false }).catch(() => null);
    const billing = await getBillingState(ctx.bubble_user_id).catch(() => ({ row: null, is_active: false, status: "unknown" }));

    return json(res, 200, {
      ok: true,
      linked: true,
      email: ctx.email,
      bubble_user_id: ctx.bubble_user_id,
      role: ctx.role,
      has_spotify_credentials: !!credentials,
      spotify_redirect_uri: `${process.env.PUBLIC_BASE_URL || "https://playlist-pilot.com"}/api/oauth/spotify/callback`,
      billing: {
        is_active: billing.is_active,
        status: billing.status,
        plan_code: billing.row?.plan_code || billing.row?.subscription_plan_code || null,
        current_period_end: billing.row?.current_period_end || billing.row?.subscription_expires_at || null,
        cancel_at_period_end: !!billing.row?.cancel_at_period_end,
        seats_limit: billing.row?.seats_limit ?? 0,
        seats_used: billing.row?.seats_used ?? 0,
        provider: billing.row?.provider || null,
      },
    });
  },

  /* ---------- health/status (GET) ---------- */
  "health/status": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req, req.query.bubble_user_id);
    if (!bubbleUserId) return bad(res, 401, "missing_user");
    const now = new Date();
    const [connR, playlistR, flexR] = await Promise.all([
      sb(`/rest/v1/spotify_connections?select=id,is_active&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`),
      sb(
        `/rest/v1/playlists?select=id,next_check_at,needs_sync,sync_started_at,last_checked_at,error_count` +
        `&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}&is_owner=is.true&is_public=is.true`
      ),
      sb(`/rest/v1/playlist_flex_settings?select=playlist_id,enabled,next_rotation_at&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`).catch(() => null),
    ]);
    const connections = connR.ok ? await connR.json() : [];
    const playlists = playlistR.ok ? await playlistR.json() : [];
    const flex = flexR?.ok ? await flexR.json() : [];
    return json(res, 200, {
      ok: true,
      checked_at: now.toISOString(),
      spotify_connections: {
        total: connections.length,
        active: connections.filter((c) => c.is_active !== false).length,
      },
      playlists: {
        total: playlists.length,
        on_cooldown: playlists.filter((p) => p.next_check_at && new Date(p.next_check_at) > now).length,
        needs_sync: playlists.filter((p) => p.needs_sync).length,
        syncing: playlists.filter((p) => p.sync_started_at).length,
        stale: playlists.filter((p) => !p.last_checked_at || new Date(p.last_checked_at) < new Date(Date.now() - 24 * 3600 * 1000)).length,
        failed: playlists.filter((p) => Number(p.error_count || 0) > 0).length,
      },
      rotator: {
        enabled: flex.filter((f) => f.enabled).length,
        due: flex.filter((f) => f.enabled && (!f.next_rotation_at || new Date(f.next_rotation_at) <= now)).length,
      },
    });
  },

  /* ---------- stripe/checkout (POST) ---------- */
  "stripe/checkout": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    const ctx = await getUserContext(req);
    if (!ctx?.linked) return bad(res, 401, "not_authenticated");
    const body = await readBody(req);
    const requestedPlan = String(body.plan || "economy").toLowerCase();
    const requestedInterval = String(body.interval || "monthly").toLowerCase();
    const planKey = `${requestedPlan}_${requestedInterval === "year" || requestedInterval === "yearly" ? "yearly" : "monthly"}`;
    const selectedPlan = stripePlanCatalog()[planKey] || stripePlanCatalog().economy_monthly;
    const price = selectedPlan.price;
    if (!price) return bad(res, 500, "missing_stripe_price");

    const stripe = getStripeClient();
    const billing = await getBillingState(ctx.bubble_user_id);
    let customerId = billing.row?.stripe_customer_id || null;

    if (!customerId) {
      const customer = await stripe.customers.create({
        email: ctx.email,
        metadata: { bubble_user_id: ctx.bubble_user_id },
      });
      customerId = customer.id;
      await sb(`/rest/v1/app_users?on_conflict=bubble_user_id`, {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify([{ bubble_user_id: ctx.bubble_user_id, stripe_customer_id: customerId, updated_at: new Date().toISOString() }]),
      });
    }

    const base = publicBaseUrl(req);
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: customerId,
      line_items: [{ price, quantity: 1 }],
      success_url: `${base}/app?billing=success`,
      cancel_url: `${base}/app?billing=cancelled`,
      metadata: { bubble_user_id: ctx.bubble_user_id, plan: selectedPlan.plan_code, interval: selectedPlan.interval },
      subscription_data: {
        trial_period_days: 30,
        metadata: { bubble_user_id: ctx.bubble_user_id, plan: selectedPlan.plan_code, interval: selectedPlan.interval },
      },
      allow_promotion_codes: true,
    });
    return json(res, 200, { ok: true, url: session.url });
  },

  /* ---------- stripe/portal (POST) ---------- */
  "stripe/portal": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    const ctx = await getUserContext(req);
    if (!ctx?.linked) return bad(res, 401, "not_authenticated");
    const billing = await getBillingState(ctx.bubble_user_id);
    let customerId = billing.row?.stripe_customer_id || null;
    const stripe = getStripeClient();
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: ctx.email,
        metadata: { bubble_user_id: ctx.bubble_user_id },
      });
      customerId = customer.id;
      await sb(`/rest/v1/app_users?on_conflict=bubble_user_id`, {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify([{ bubble_user_id: ctx.bubble_user_id, stripe_customer_id: customerId, updated_at: new Date().toISOString() }]),
      });
    }
    let portal;
    try {
      portal = await stripe.billingPortal.sessions.create({
        customer: customerId,
        return_url: publicBaseUrl(req),
      });
    } catch (e) {
      const message = String(e?.message || e);
      if (!/configuration|No configuration/i.test(message)) throw e;
      const config = await stripe.billingPortal.configurations.create({
        business_profile: {
          headline: "Manage your PlaylistPilot subscription",
        },
        features: {
          customer_update: { enabled: true, allowed_updates: ["email", "tax_id"] },
          invoice_history: { enabled: true },
          payment_method_update: { enabled: true },
          subscription_cancel: { enabled: true, mode: "at_period_end" },
        },
      });
      portal = await stripe.billingPortal.sessions.create({
        customer: customerId,
        configuration: config.id,
        return_url: publicBaseUrl(req),
      });
    }
    return json(res, 200, { ok: true, url: portal.url });
  },

  /* ---------- stripe/webhook (POST) ---------- */
  "stripe/webhook": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    const stripe = getStripeClient();
    const secret = need("STRIPE_WEBHOOK_SECRET");
    const sig = req.headers["stripe-signature"];
    const raw = await readRawBody(req);
    let event;
    try {
      event = stripe.webhooks.constructEvent(raw, sig, secret);
    } catch (e) {
      return bad(res, 400, `stripe_webhook_invalid: ${e.message}`);
    }

    try {
      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        if (session.mode === "subscription" && session.subscription) {
          const subscription = await stripe.subscriptions.retrieve(session.subscription);
          const bubble_user_id = session.metadata?.bubble_user_id || subscription.metadata?.bubble_user_id;
          if (bubble_user_id) {
            await upsertStripeSubscriptionState({
              bubble_user_id,
              customer_id: session.customer,
              subscription,
            });
          }
        }
      }

      if (event.type === "customer.subscription.created" || event.type === "customer.subscription.updated" || event.type === "customer.subscription.deleted") {
        const subscription = event.data.object;
        let bubble_user_id = subscription.metadata?.bubble_user_id || null;
        if (!bubble_user_id && subscription.customer) {
          const r = await sb(`/rest/v1/app_users?select=bubble_user_id&limit=1&stripe_customer_id=eq.${encodeURIComponent(subscription.customer)}`);
          bubble_user_id = r.ok ? (await r.json().catch(() => []))?.[0]?.bubble_user_id : null;
        }
        if (bubble_user_id) {
          await upsertStripeSubscriptionState({
            bubble_user_id,
            customer_id: subscription.customer,
            subscription,
          });
        }
      }

      if (event.type === "invoice.payment_failed" || event.type === "invoice.payment_succeeded") {
        const invoice = event.data.object;
        if (invoice.subscription) {
          const subscription = await stripe.subscriptions.retrieve(invoice.subscription);
          let bubble_user_id = subscription.metadata?.bubble_user_id || null;
          if (!bubble_user_id && subscription.customer) {
            const r = await sb(`/rest/v1/app_users?select=bubble_user_id&limit=1&stripe_customer_id=eq.${encodeURIComponent(subscription.customer)}`);
            bubble_user_id = r.ok ? (await r.json().catch(() => []))?.[0]?.bubble_user_id : null;
          }
          if (bubble_user_id) await upsertStripeSubscriptionState({ bubble_user_id, customer_id: subscription.customer, subscription });
        }
      }
    } catch (e) {
      console.error("stripe_webhook_handler_failed", { type: event.type, error: String(e?.message || e) });
      return bad(res, 500, "stripe_webhook_handler_failed");
    }

    return json(res, 200, { received: true });
  },

  /* ---------- spotify/credentials/get (GET) ---------- */
  "spotify/credentials/get": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req);
    if (!bubbleUserId) return bad(res, 401, "missing_user");

    const r = await sb(
      `/rest/v1/spotify_app_credentials?select=id,client_id,redirect_uri,app_name,created_at,updated_at` +
      `&limit=1&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`
    );
    const rows = r.ok ? await r.json().catch(() => []) : [];
    if (!r.ok) return bad(res, 500, `spotify_credentials_select_failed: ${await r.text().catch(() => "")}`);
    const row = rows?.[0] || null;
    return json(res, 200, {
      configured: !!row,
      credentials: row,
      required_redirect_uri: `${process.env.PUBLIC_BASE_URL || "https://playlist-pilot.com"}/api/oauth/spotify/callback`,
      fallback_available: !!fallbackSpotifyCredentials(),
    });
  },

  /* ---------- spotify/credentials/save (POST) ---------- */
  "spotify/credentials/save": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req);
    if (!bubbleUserId) return bad(res, 401, "missing_user");
    const body = await readBody(req);
    const client_id = String(body.client_id || "").trim();
    const client_secret = String(body.client_secret || "").trim();
    const redirect_uri = String(body.redirect_uri || `${process.env.PUBLIC_BASE_URL || "https://playlist-pilot.com"}/api/oauth/spotify/callback`).trim();
    const app_name = String(body.app_name || "").trim();

    if (!/^[A-Za-z0-9]{20,80}$/.test(client_id)) return bad(res, 400, "invalid_client_id");
    if (client_secret.length < 20) return bad(res, 400, "invalid_client_secret");
    let parsedRedirect;
    try { parsedRedirect = new URL(redirect_uri); } catch { return bad(res, 400, "invalid_redirect_uri"); }
    if (!/^https?:$/.test(parsedRedirect.protocol)) return bad(res, 400, "invalid_redirect_uri_protocol");

    const payload = {
      bubble_user_id: bubbleUserId,
      client_id,
      client_secret_enc: encToken(client_secret),
      redirect_uri,
      app_name: app_name || null,
      updated_at: new Date().toISOString(),
    };

    const up = await sb(`/rest/v1/spotify_app_credentials?on_conflict=bubble_user_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=representation" },
      body: JSON.stringify([payload]),
    });
    const txt = await up.text();
    let data = null; try { data = txt ? JSON.parse(txt) : null; } catch {}
    if (!up.ok) return bad(res, up.status, `spotify_credentials_save_failed: ${txt}`);
    const row = Array.isArray(data) ? data[0] : data;
    return json(res, 200, {
      ok: true,
      credentials: row ? {
        id: row.id,
        client_id: row.client_id,
        redirect_uri: row.redirect_uri,
        app_name: row.app_name,
        updated_at: row.updated_at,
      } : null,
    });
  },

  /* ---------- spotify/credentials/delete (POST) ---------- */
  "spotify/credentials/delete": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req);
    if (!bubbleUserId) return bad(res, 401, "missing_user");
    const del = await sb(`/rest/v1/spotify_app_credentials?bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`, {
      method: "DELETE",
      headers: { Prefer: "return=minimal" },
    });
    if (!del.ok) return bad(res, del.status, `spotify_credentials_delete_failed: ${await del.text().catch(() => "")}`);
    return json(res, 200, { ok: true });
  },



   /* ---------- users/settings/get (GET) ---------- */
   "users/settings/get": async (req, res) => {
     if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
     const bubbleUserId = await bubbleUserIdFromRequest(req);
     if (!bubbleUserId) return bad(res, 401, "missing_x_bubble_user_id");
   
     // HINWEIS: Wenn du die View-Variante nutzt, ersetze /app_users durch /app_users_with_seats
     const r = await sb(
       `/rest/v1/app_users` +
         `?select=` +
         [
           "bubble_user_id",
           "sync_paused",
           "auto_remove_enabled",
           "position_lock_enabled",
           "subscription_status",
           "subscription_expires_at",
           "subscription_plan_code",
           "seats_limit",
           "seats_used",       // <- NEU: kommt aus Spalte + Trigger ODER aus View
         ].join(",") +
         `&limit=1&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`
     );
   
     const arr = await r.json().catch(() => []);
     if (!r.ok) return bad(res, 500, `supabase_select_failed: ${JSON.stringify(arr)}`);
   
     // Defaults, falls User-Zeile noch nicht existiert
     const defaults = {
       bubble_user_id: bubbleUserId,
       sync_paused: false,
       auto_remove_enabled: true,
       position_lock_enabled: true,
       subscription_status: "active",
       subscription_expires_at: null,
       subscription_plan_code: null,
       seats_limit: 1,  // Default (z.B. für Free/Luggage 0, wenn du willst)
       seats_used: 0,   // Default
     };
   
     const rowInDb = arr?.[0];
     const row = rowInDb
       ? {
           ...defaults,
           ...rowInDb,
           // Numerik-Absicherung
           seats_limit: Number.isFinite(Number(rowInDb.seats_limit))
             ? Number(rowInDb.seats_limit)
             : defaults.seats_limit,
           seats_used: Number.isFinite(Number(rowInDb.seats_used))
             ? Number(rowInDb.seats_used)
             : defaults.seats_used,
         }
       : defaults;
   
     return json(res, 200, { ok: true, settings: row });
   },



   /* ---------- users/settings/save (POST) ---------- */
   "users/settings/save": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     const bubbleUserId = await bubbleUserIdFromRequest(req);
     if (!bubbleUserId) return bad(res, 401, "missing_x_bubble_user_id");
   
     const b = await readBody(req);
     // Nur whitelisten, was wir erlauben:
     const payload = {
       bubble_user_id: bubbleUserId,
       ...(typeof b.sync_paused === "boolean" ? { sync_paused: b.sync_paused } : {}),
       ...(typeof b.auto_remove_enabled === "boolean" ? { auto_remove_enabled: b.auto_remove_enabled } : {}),
       ...(typeof b.position_lock_enabled === "boolean" ? { position_lock_enabled: b.position_lock_enabled } : {}),
   
       // optional adminish: nur setzen, wenn übergeben (z. B. Stripe-Webhook):
       ...(typeof b.subscription_status === "string" ? { subscription_status: b.subscription_status } : {}),
       ...(b.subscription_expires_at ? { subscription_expires_at: b.subscription_expires_at } : {})
     };
   
     // ensure app_user exists
     await sb(`/rest/v1/app_users?on_conflict=bubble_user_id`, {
       method: "POST",
       headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
       body: JSON.stringify([payload])
     });
   
     return json(res, 200, { ok:true });
   },

         /* ---------- paypal/subscriptions/link (POST) ----------
   Body: { subscriptionId: "I-...", bubble_user_id: "<id>", environment: "live"|"sandbox" }
   Header (optional Admin-Override): x-app-secret: <APP_WEBHOOK_SECRET>
   */
   "paypal/subscriptions/link": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     try {
       const body = await readBody(req);
       const subscriptionId = String(body.subscriptionId || body.subscription_id || "").trim();
       const bubble_user_id = String(body.bubble_user_id || "").trim();
       const environment = (String(body.environment || "").toLowerCase() === "live") ? "live" : "sandbox";
       if (!subscriptionId || !bubble_user_id) return bad(res, 400, "missing_subscription_id_or_user");
   
       // Nutzer sicherstellen (idempotent)
       await sb(`/rest/v1/app_users?on_conflict=bubble_user_id`, {
         method: "POST",
         headers: { Prefer: "resolution=ignore-duplicates,return=minimal" },
         body: JSON.stringify([{ bubble_user_id }])
       }).catch(()=>{});
   
       // PayPal token + subscription holen
       const isLive = environment === "live";
       const base    = isLive ? "https://api.paypal.com" : "https://api.sandbox.paypal.com";
       const cid     = need(isLive ? "PAYPAL_CLIENT_ID_LIVE"    : "PAYPAL_CLIENT_ID_SANDBOX");
       const secret  = need(isLive ? "PAYPAL_CLIENT_SECRET_LIVE" : "PAYPAL_CLIENT_SECRET_SANDBOX");
       const tokenRes = await fetch(`${base}/v1/oauth2/token`, {
         method: "POST",
         headers: { "Authorization": "Basic " + Buffer.from(`${cid}:${secret}`).toString("base64"),
                    "Content-Type": "application/x-www-form-urlencoded" },
         body: "grant_type=client_credentials"
       });
       const tok = await tokenRes.json().catch(()=> ({}));
       if (!tokenRes.ok || !tok?.access_token) {
         return bad(res, 502, `paypal_auth_failed: ${tokenRes.status}`);
       }
   
       const subRes = await fetch(`${base}/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}`, {
         headers: { "Authorization": `Bearer ${tok.access_token}` }
       });
       const sub = await subRes.json().catch(()=> ({}));
       if (!subRes.ok) {
         return bad(res, subRes.status, `paypal_get_failed: ${JSON.stringify(sub)}`);
       }
   
       // Normalize einige Kernfelder
       const norm = {
         id: sub?.id || subscriptionId,
         status: sub?.status || "UNKNOWN",
         plan_id: sub?.plan_id || null,
         custom_id: sub?.custom_id || null,
         next_billing_time: sub?.billing_info?.next_billing_time || null
       };
   
       // --- EXISTING LOOKUP: beide Spalten + Environment berücksichtigen
       const q1 = `/rest/v1/subscriptions?select=id,bubble_user_id&limit=1`
                + `&environment=eq.${encodeURIComponent(environment)}`
                + `&provider=eq.paypal`
                + `&provider_subscription_id=eq.${encodeURIComponent(subscriptionId)}`;
       const r1 = await sb(q1); const e1 = r1.ok ? (await r1.json())?.[0] : null;
   
       let existing = e1 || null;
       if (!existing) {
         const q2 = `/rest/v1/subscriptions?select=id,bubble_user_id&limit=1`
                  + `&environment=eq.${encodeURIComponent(environment)}`
                  + `&paypal_subscription_id=eq.${encodeURIComponent(subscriptionId)}`;
         const r2 = await sb(q2); existing = r2.ok ? (await r2.json())?.[0] : null;
       }
   
       // --- CUSTOM_ID MISMATCH HANDLING (tolerant für Alt-Abos):
       const hasSecret = checkAppSecret(req);
       if (norm.custom_id && norm.custom_id !== bubble_user_id) {
         const sameUserAlready = !!existing && existing.bubble_user_id === bubble_user_id;
         if (!sameUserAlready && !hasSecret) {
           // Wer mag, kann zum Debuggen folgende Zeile temporär aktivieren:
           // return bad(res, 409, `custom_id_mismatch (pp=${norm.custom_id}, ui=${bubble_user_id})`);
           return bad(res, 409, "custom_id_mismatch");
         }
       }
   
       // --- UPSERT (provider-agnostisch + Legacy-Spalte füllen)
       const up = await sb(`/rest/v1/subscriptions?on_conflict=provider,provider_subscription_id`, {
         method: "POST",
         headers: { Prefer: "resolution=merge-duplicates,return=representation",
                    "Content-Type": "application/json" },
         body: JSON.stringify([{
           bubble_user_id,
           provider: "paypal",
           provider_subscription_id: norm.id,
           paypal_subscription_id: norm.id,  // für Alt-Schema
           plan_id: norm.plan_id,
           status: norm.status,
           environment,
           current_period_end: norm.next_billing_time ? new Date(norm.next_billing_time).toISOString() : null,
           updated_at: new Date().toISOString()
         }])
       });
       const data = await up.json().catch(()=>[]);
       if (!up.ok) return bad(res, 500, `supabase_upsert_failed: ${JSON.stringify(data)}`);
   
       return json(res, 200, { ok:true, linked:true, subscription: Array.isArray(data) ? data[0] : data });
     } catch (e) {
       return bad(res, 500, `paypal_link_exception: ${e?.message || e}`);
     }
   },



   
   /* ---------- paypal/webhook (POST) ---------- */
   "paypal/webhook": async (req, res) => {
     // CORS preflight
     if (req.method === "OPTIONS") return res.status(204).end();
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
   
     // --- helper: extract a clean Bubble UID from custom_id formats
     function normalizeBubbleUID(raw) {
       if (!raw) return null;
       // JSON string? e.g. {"uid":"...","code":"first","term":"m"}
       try {
         if (typeof raw === "string" && raw.trim().startsWith("{")) {
           const j = JSON.parse(raw);
           if (j && typeof j.uid === "string" && j.uid.trim()) return j.uid.trim();
         }
       } catch (_) {}
       const s = String(raw).trim();
       // key-pipe format: uid:...|code:...|term:...
       const m = s.match(/(?:^|\|)uid:([^|]+)(?:\||$)/i);
       if (m && m[1]) return m[1].trim();
       // fallback: treat full string as uid
       return s || null;
     }
   
     // --- read JSON body (already parsed by our readBody)
     const headers = req.headers;
     const event = await readBody(req); // already JSON
     const transmission_id   = headers["paypal-transmission-id"];
     const transmission_time = headers["paypal-transmission-time"];
     const cert_url          = headers["paypal-cert-url"];
     const auth_algo         = headers["paypal-auth-algo"];
     const transmission_sig  = headers["paypal-transmission-sig"];
     if (!transmission_id || !transmission_time || !cert_url || !auth_algo || !transmission_sig) {
       return bad(res, 400, "missing_signature_headers");
     }
   
     // --- verify helper (live, fallback sandbox)
     const tryVerify = async (env) => {
       const isLive = env === "live";
       const base   = isLive ? "https://api.paypal.com" : "https://api.sandbox.paypal.com";
       const cid    = need(isLive ? "PAYPAL_CLIENT_ID_LIVE"     : "PAYPAL_CLIENT_ID_SANDBOX");
       const secret = need(isLive ? "PAYPAL_CLIENT_SECRET_LIVE" : "PAYPAL_CLIENT_SECRET_SANDBOX");
       const webhook_id = need(isLive ? "PAYPAL_WEBHOOK_ID_LIVE" : "PAYPAL_WEBHOOK_ID_SANDBOX");
   
       // OAuth
       const tokRes = await fetch(`${base}/v1/oauth2/token`, {
         method: "POST",
         headers: { "Authorization":"Basic "+Buffer.from(`${cid}:${secret}`).toString("base64"), "Content-Type":"application/x-www-form-urlencoded" },
         body: "grant_type=client_credentials"
       });
       const tok = await tokRes.json().catch(()=> ({}));
       if (!tokRes.ok || !tok?.access_token) return { ok:false, status:502 };
   
       // verify signature
       const vRes = await fetch(`${base}/v1/notifications/verify-webhook-signature`, {
         method: "POST",
         headers: { "Authorization": `Bearer ${tok.access_token}`, "Content-Type":"application/json" },
         body: JSON.stringify({
           transmission_id, transmission_time, cert_url, auth_algo, transmission_sig,
           webhook_id, webhook_event: event
         })
       });
       const v = await vRes.json().catch(()=> ({}));
       return { ok: v?.verification_status === "SUCCESS", env, token: tok.access_token, base, webhook_id };
     };
   
     let ver = await tryVerify("live");
     if (!ver.ok) ver = await tryVerify("sandbox");
     if (!ver.ok) {
       console.error("PP webhook verify FAILED", {
         event_type: event?.event_type, sub: event?.resource?.id
       });
       return bad(res, 400, "webhook_verify_failed");
     }
   
     // --- Event fields
     const env  = ver.env;
     const name = String(event?.event_type || "");
     const subId = event?.resource?.id || event?.resource?.subscription_id || null;
     let bubble_user_id = normalizeBubbleUID(event?.resource?.custom_id || null); // <— normalize here
     const status = event?.resource?.status || null;
     const plan_id = event?.resource?.plan_id || null;
     const nextBilling = event?.resource?.billing_info?.next_billing_time || null;
     const createdAt = event?.create_time || null;
   
     console.info("PP webhook verify OK", { env, event_type: name, sub: subId });
   
     // --- Upsert into subscriptions (RLS bypass via Service Role in sb())
     if (subId) {
       const payload = [{
         // identity
         provider: "paypal",
         provider_subscription_id: subId,
         paypal_subscription_id: subId,
   
         // linking
         bubble_user_id: bubble_user_id || null, // normalized UID (or null if absent)
   
         // metadata
         environment: env,
         plan_id,
         status: status || "UNKNOWN",
         current_period_end: nextBilling ? new Date(nextBilling).toISOString() : null,
         last_event_at: createdAt || new Date().toISOString(),
         updated_at: new Date().toISOString()
       }];
   
       const up = await sb(`/rest/v1/subscriptions?on_conflict=provider,provider_subscription_id`, {
         method: "POST",
         headers: { Prefer: "resolution=merge-duplicates,return=minimal", "Content-Type": "application/json" },
         body: JSON.stringify(payload)
       });
   
       if (!up.ok) {
         const body = await up.text().catch(()=>"?");
         console.error("PP webhook upsert FAILED", { status: up.status, body });
         return bad(res, 400, "upsert_failed");
       }
   
       console.info("PP webhook upsert OK", {
         env, event_type: name, subId, status: status || "UNKNOWN", plan_id, nextBilling
       });
     }
   
     // optional: event log table
     // await sb(`/rest/v1/billing_events`, { ... }).catch(()=>{})
   
     return json(res, 200, { ok: true });
   },





   


   // POST /api/paypal/subscriptions/cancel
   "paypal/subscriptions/cancel": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     const { subscriptionId, environment = "live", reason = "user_cancelled" } = await readBody(req);
     if (!subscriptionId) return bad(res, 400, "missing_subscription_id");
     const isLive = String(environment).toLowerCase() === "live";
     const base = isLive ? "https://api.paypal.com" : "https://api.sandbox.paypal.com";
     const cid    = need(isLive ? "PAYPAL_CLIENT_ID_LIVE"     : "PAYPAL_CLIENT_ID_SANDBOX");
     const secret = need(isLive ? "PAYPAL_CLIENT_SECRET_LIVE" : "PAYPAL_CLIENT_SECRET_SANDBOX");
   
     // auth
     const tokRes = await fetch(`${base}/v1/oauth2/token`, {
       method: "POST",
       headers: { "Authorization": "Basic " + Buffer.from(`${cid}:${secret}`).toString("base64"), "Content-Type":"application/x-www-form-urlencoded" },
       body: "grant_type=client_credentials"
     });
     const tok = await tokRes.json().catch(()=> ({}));
     if (!tokRes.ok || !tok?.access_token) return bad(res, 502, "paypal_auth_failed");
   
     // cancel
     const cancelRes = await fetch(`${base}/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}/cancel`, {
       method: "POST",
       headers: { "Authorization": `Bearer ${tok.access_token}`, "Content-Type":"application/json" },
       body: JSON.stringify({ reason })
     });
     if (cancelRes.status !== 204) {
       const t = await cancelRes.text();
       return bad(res, cancelRes.status, `paypal_cancel_failed: ${t}`);
     }
   
     // status nachziehen (optional: Detail-GET)
     await sb(`/rest/v1/subscriptions?provider=eq.paypal&provider_subscription_id=eq.${encodeURIComponent(subscriptionId)}&environment=eq.${encodeURIComponent(isLive ? "live":"sandbox")}`, {
       method: "PATCH",
       headers: { Prefer: "return=minimal" },
       body: JSON.stringify({ status: "CANCELLED", updated_at: new Date().toISOString() })
     }).catch(()=>{});
   
     return json(res, 200, { ok: true, cancelled: true });
   },



   
   // GET subscriptions/status
   "subscriptions/status": async (req, res) => {
     if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
     const bubble_user_id = await bubbleUserIdFromRequest(req, req.query.bubble_user_id);
     if (!bubble_user_id) return bad(res, 400, "missing_bubble_user_id");
   
     const r = await sb(
       `/rest/v1/app_users` +
       `?select=provider,provider_subscription_id,environment,plan_code,term,sub_status,is_active,seats_limit,features,current_period_end,last_synced_at` +
       `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}&limit=1`
     );
     if (!r.ok) return bad(res, 500, `supabase_select_failed: ${await r.text()}`);
     const row = (await r.json())?.[0] || null;
   
     if (!row || !row.provider_subscription_id) {
       return json(res, 200, { ok:true, status:"NONE", is_active:false });
     }
   
     return json(res, 200, {
       ok: true,
       provider: row.provider || "paypal",
       environment: row.environment || "live",
       status: row.sub_status || "UNKNOWN",
       is_active: !!row.is_active,
       plan_code: row.plan_code || null,
       term: row.term || null,                          // 'm' | 'y'
       seats_limit: typeof row.seats_limit === "number" ? row.seats_limit : 0,
       features: row.features || {},
       current_period_end: row.current_period_end || null,
       subscription_id: row.provider_subscription_id || null,
       last_synced_at: row.last_synced_at || null
     });
   },



   /* ---------- subscriptions/refresh (POST) ----------
   Body:
   {
     "subscription_id": "I-…",           // or "subscriptionId"
     "bubble_user_id": "<Bubble UID>",   // optional, recommended
     "environment": "live" | "sandbox"   // default: "live"
   }
   Header (optional admin override if sub belongs to another user):
     x-app-secret: <APP_WEBHOOK_SECRET>
   */
   "subscriptions/refresh": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     try {
       const body = await readBody(req);
       const subscriptionId = String(body.subscription_id || body.subscriptionId || "").trim();
       const bubble_user_id = String(body.bubble_user_id || "").trim();
       const environment = (String(body.environment || "live").toLowerCase() === "sandbox") ? "sandbox" : "live";
       if (!subscriptionId) return bad(res, 400, "missing_subscription_id");
   
       // Ensure user row exists (idempotent)
       if (bubble_user_id) {
         await sb(`/rest/v1/app_users?on_conflict=bubble_user_id`, {
           method: "POST",
           headers: { Prefer: "resolution=ignore-duplicates,return=minimal", "Content-Type": "application/json" },
           body: JSON.stringify([{ bubble_user_id }])
         }).catch(()=>{});
       }
   
       // PayPal auth
       const isLive = environment === "live";
       const base   = isLive ? "https://api.paypal.com" : "https://api.sandbox.paypal.com";
       const cid    = need(isLive ? "PAYPAL_CLIENT_ID_LIVE"     : "PAYPAL_CLIENT_ID_SANDBOX");
       const secret = need(isLive ? "PAYPAL_CLIENT_SECRET_LIVE" : "PAYPAL_CLIENT_SECRET_SANDBOX");
   
       const tokRes = await fetch(`${base}/v1/oauth2/token`, {
         method: "POST",
         headers: {
           "Authorization": "Basic " + Buffer.from(`${cid}:${secret}`).toString("base64"),
           "Content-Type": "application/x-www-form-urlencoded"
         },
         body: "grant_type=client_credentials"
       });
       const tok = await tokRes.json().catch(()=> ({}));
       if (!tokRes.ok || !tok?.access_token) {
         return bad(res, 502, `paypal_auth_failed: ${tokRes.status}`);
       }
   
       // Pull subscription
       const subRes = await fetch(`${base}/v1/billing/subscriptions/${encodeURIComponent(subscriptionId)}`, {
         headers: { "Authorization": `Bearer ${tok.access_token}` }
       });
       const sub = await subRes.json().catch(()=> ({}));
       if (!subRes.ok) {
         return bad(res, subRes.status, `paypal_get_failed: ${JSON.stringify(sub)}`);
       }
   
       const paypal_status = String(sub?.status || "UNKNOWN").toUpperCase();
       const plan_id       = sub?.plan_id || null;
       const next_time     = sub?.billing_info?.next_billing_time || null;
       const meta          = plan_id ? PLAN_MAP[plan_id] : null;
   
       // active if ACTIVE, or CANCELLED but still within paid period
       const active = (() => {
         if (paypal_status === "ACTIVE") return true;
         if (paypal_status === "CANCELLED" && next_time) {
           try { return new Date(next_time).getTime() > Date.now(); } catch {}
         }
         return false;
       })();
   
       // Update user row (single source of truth)
       if (bubble_user_id) {
         const patch = await sb(`/rest/v1/app_users?bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}`, {
           method: "PATCH",
           headers: { "Content-Type":"application/json", Prefer:"return=representation" },
           body: JSON.stringify({
             provider: "paypal",
             provider_subscription_id: sub?.id || subscriptionId,
             environment,
             plan_code: meta?.plan_code || null,
             term: meta?.term || null,
             sub_status: paypal_status,
             is_active: active,
             seats_limit: meta?.seats ?? 0,
             features: meta?.features ?? {},
             current_period_end: next_time ? new Date(next_time).toISOString() : null,
             last_synced_at: new Date().toISOString()
           })
         });
         if (!patch.ok) {
           const err = await patch.text().catch(()=>"?");
           return bad(res, 500, `supabase_update_failed: ${err}`);
         }
         const data = await patch.json().catch(()=>[]);
         return json(res, 200, { ok:true, refreshed:true, user: Array.isArray(data) ? data[0] : data });
       }
   
       // If no user id provided (e.g. webhook test), return raw info
       return json(res, 200, {
         ok:true, refreshed:true,
         subscription: { id: sub?.id || subscriptionId, status: paypal_status, plan_id }
       });
     } catch (e) {
       return bad(res, 500, `subscriptions_refresh_exception: ${e?.message || e}`);
     }
   },




   
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
   
     const bubble_user_id = await bubbleUserIdFromRequest(req, req.query.bubble_user_id);
     if (!bubble_user_id) return bad(res, 400, "missing_bubble_user_id");
   
     // Default: nur aktive. Mit ?include_inactive=1 bekommst du alle.
     const includeInactive = String(req.query.include_inactive || "0") === "1";
   
     let path =
       `/rest/v1/spotify_connections` +
       `?select=id,display_name,avatar_url,spotify_user_id,created_at,is_active,disconnected_at` +
       `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
       `&order=created_at.desc`;
   
     if (!includeInactive) {
       path += `&is_active=is.true`;
     }
   
     const r = await fetch(SUPABASE_URL + path, {
       headers: { apikey: SRK, Authorization: `Bearer ${SRK}` },
       cache: "no-store"
     });
   
     const txt = await r.text();
     if (!r.ok) {
       return json(res, 500, { error:"supabase_error", status:r.status, body:txt, url: SUPABASE_URL+path });
     }
   
     return json(res, 200, txt ? JSON.parse(txt) : []);
   },




   /* ---------- connections/activate (POST) ----------
   Body:
     { connection_id?: uuid, spotify_user_id?: string }
   Header:
     X-Bubble-User-Id: <required, außer Admin ruft’s intern>
   */
   "connections/activate": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     const bubbleUserId = await bubbleUserIdFromRequest(req);
     if (!bubbleUserId) return bad(res, 401, "missing_x_bubble_user_id");
   
     const b = await readBody(req);
     const connection_id = String(b.connection_id || "").trim();
     if (!connection_id) return bad(res, 400, "missing_connection_id");
   
     // Ownership prüfen
     const sel = await sb(
       `/rest/v1/spotify_connections?select=id,bubble_user_id,spotify_user_id,is_active&limit=1&id=eq.${encodeURIComponent(connection_id)}`
     );
     const arr = await sel.json().catch(()=>[]);
     if (!sel.ok) return bad(res, 500, `supabase_select_failed: ${JSON.stringify(arr)}`);
     const row = arr[0];
     if (!row) return bad(res, 404, "connection_not_found");
     if (row.bubble_user_id !== bubbleUserId) return bad(res, 403, "forbidden");

     const activeOwner = await findActiveSpotifyOwner(row.spotify_user_id, bubbleUserId);
     if (activeOwner) return bad(res, 409, "spotify_account_already_connected");
   
     // Aktivieren
     const patch = await sb(`/rest/v1/spotify_connections?id=eq.${encodeURIComponent(connection_id)}`, {
       method: "PATCH",
       headers: { Prefer: "return=representation" },
       body: JSON.stringify({
         is_active: true,
         disabled_at: null,
         updated_at: new Date().toISOString()
       })
     });
     const patched = await patch.json().catch(()=>[]);
     if (!patch.ok) return bad(res, 500, `supabase_patch_failed: ${JSON.stringify(patched)}`);
     const conn = Array.isArray(patched) ? patched[0] : patched;
   
     // seats_used neu zählen (nur aktive)
     try {
       const cr = await sb(
         `/rest/v1/spotify_connections?select=id&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}&is_active=is.true`
       );
       const used = cr.ok ? (await cr.json()).length : null;
       if (used != null) {
         await sb(`/rest/v1/app_users?bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`, {
           method: "PATCH",
           headers: { Prefer: "return=minimal" },
           body: JSON.stringify({ seats_used: used, updated_at: new Date().toISOString() })
         }).catch(()=>{});
       }
     } catch {}
   
     return json(res, 200, { ok: true, connection: { id: conn.id, is_active: conn.is_active } });
   },

   
      
   /* ---------- connections/disconnect (POST) ---------- */
   "connections/disconnect": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
   
     const bubbleUserId = await bubbleUserIdFromRequest(req);
     if (!bubbleUserId) return bad(res, 401, "missing_x_bubble_user_id");
   
     const body = await readBody(req);
     const connection_id = String(
       body.connection_id || body.id || body.connectionId || req.query.connection_id || req.query.id || ""
     ).trim();
     if (!connection_id) return bad(res, 400, "missing_connection_id");
   
     // Ownership prüfen
     const sel = await sb(
       `/rest/v1/spotify_connections?select=id,bubble_user_id,is_active&limit=1&id=eq.${encodeURIComponent(connection_id)}`
     );
     if (!sel.ok) return bad(res, 500, `supabase_select_failed: ${await sel.text()}`);
     const row = (await sel.json())?.[0];
     if (!row) return bad(res, 404, "connection_not_found");
     if (row.bubble_user_id !== bubbleUserId) return bad(res, 403, "forbidden");
   
     // **Soft disconnect**: nur Flags setzen (KEINE Token-Felder anfassen)
     const patch = await sb(`/rest/v1/spotify_connections?id=eq.${encodeURIComponent(connection_id)}`, {
       method: "PATCH",
       headers: { Prefer: "return=representation" },
       body: JSON.stringify({
         is_active: false,
         disconnected_at: new Date().toISOString()
       })
     });
     if (!patch.ok) {
       const t = await patch.text().catch(()=>"?");
       return bad(res, 500, `supabase_disconnect_failed: ${t}`);
     }
   
     // seats_used neu zählen (nur aktive Verbindungen)
     let seats_used = 0;
     try {
       const cr = await sb(
         `/rest/v1/spotify_connections?select=id&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}&is_active=is.true`
       );
       const arr = cr.ok ? await cr.json() : [];
       seats_used = Array.isArray(arr) ? arr.length : 0;
   
       await sb(`/rest/v1/app_users?bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`, {
         method: "PATCH",
         headers: { Prefer: "return=minimal" },
         body: JSON.stringify({ seats_used })
       }).catch(()=>{});
     } catch {}
   
     return json(res, 200, { ok: true, disconnected: true, connection_id, seats_used });
   },

   
      
   /* ---------- dashboard/expiring-next (GET) ---------- */
   "dashboard/expiring-next": async (req, res) => {
     if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
     const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
     if (!SUPABASE_URL || !SRK) return bad(res, 500, "missing_env");
   
     const bubble_user_id = await bubbleUserIdFromRequest(req, req.query.bubble_user_id);
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
   
   
      /* ---------- dashboard/growth (GET) ----------
   Query:
     bubble_user_id (required)
     playlist_id   (required, UUID der playlists.id)
     days          (optional, int; default 30)
   Returns rows: [{day, followers, delta, note}]
   */
   "dashboard/growth": async (req, res) => {
     if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
     const bubble_user_id = String(req.query.bubble_user_id || "");
     const playlist_id    = String(req.query.playlist_id || "");
     const days           = Math.max(1, parseInt(req.query.days || "30", 10) || 30);
   
     if (!bubble_user_id) return bad(res, 400, "missing_bubble_user_id");
     if (!playlist_id)    return bad(res, 400, "missing_playlist_id");
   
     try {
       const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
   
       // 1) Eigentum prüfen & Playlist-Infos ziehen
       const pR = await fetch(
         `${SUPABASE_URL}/rest/v1/playlists?select=id,name,followers,bubble_user_id&limit=1&id=eq.${encodeURIComponent(playlist_id)}&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}`,
         { headers: { apikey: SRK, Authorization: `Bearer ${SRK}` } }
       );
       const pArr = await pR.json().catch(()=>[]);
       if (!pR.ok) return bad(res, 500, `supabase_playlist_failed: ${JSON.stringify(pArr)}`);
       const playlist = pArr[0];
       if (!playlist) return bad(res, 403, "playlist_not_owned_or_not_found");
   
       // 2) Zeitraum berechnen (UTC)
       const cutoff = new Date(Date.now() - days * 86400 * 1000).toISOString().slice(0,10); // YYYY-MM-DD
       const today  = new Date().toISOString().slice(0,10);
   
       // 3) Daily-Folgs holen (ASC für Delta-Berechnung)
       const dR = await fetch(
         `${SUPABASE_URL}/rest/v1/playlist_followers_daily` +
         `?select=day,followers` +
         `&playlist_id=eq.${encodeURIComponent(playlist_id)}` +
         `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
         `&day=gte.${encodeURIComponent(cutoff)}` +
         `&order=day.asc`,
         { headers: { apikey: SRK, Authorization: `Bearer ${SRK}` } }
       );
       const dArr = await dR.json().catch(()=>[]);
       if (!dR.ok) return bad(res, 500, `supabase_daily_failed: ${JSON.stringify(dArr)}`);
   
       // 4) Notizen für diesen Zeitraum ziehen
       const nR = await fetch(
         `${SUPABASE_URL}/rest/v1/playlist_growth_notes` +
         `?select=day,note` +
         `&playlist_id=eq.${encodeURIComponent(playlist_id)}` +
         `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
         `&day=gte.${encodeURIComponent(cutoff)}`,
         { headers: { apikey: SRK, Authorization: `Bearer ${SRK}` } }
       );
       const nArr = await nR.json().catch(()=>[]);
       if (!nR.ok) return bad(res, 500, `supabase_notes_failed: ${JSON.stringify(nArr)}`);
       const noteByDay = new Map(nArr.map(r => [String(r.day), r.note || ""]));
   
       // 5) Delta vs. Vortag berechnen
       const rowsAsc = [];
       for (let i=0; i<dArr.length; i++) {
         const cur = dArr[i];
         const prev = dArr[i-1];
         const delta = prev ? Number(cur.followers || 0) - Number(prev.followers || 0) : null;
         rowsAsc.push({
           day: String(cur.day),
           followers: Number(cur.followers || 0),
           delta,
           note: noteByDay.get(String(cur.day)) || ""
         });
       }
   
       // 6) Optional "heute" anhängen, wenn es keinen Daily-Eintrag gibt (zeigt aktuellen Stand)
       if (rowsAsc.length === 0 || rowsAsc[rowsAsc.length-1].day !== today) {
         const prevFollowers = rowsAsc.length ? rowsAsc[rowsAsc.length-1].followers : null;
         const curFollowers  = Number(playlist.followers || 0);
         rowsAsc.push({
           day: today,
           followers: curFollowers,
           delta: prevFollowers == null ? null : curFollowers - prevFollowers,
           note: noteByDay.get(today) || ""
         });
       }
   
       // Neueste oben
       const rows = rowsAsc.slice().reverse();
   
       return json(res, 200, {
         ok: true,
         playlist: { id: playlist.id, name: playlist.name, current_followers: Number(playlist.followers || 0) },
         range: { days, cutoff, today },
         rows
       });
     } catch (e) {
       return bad(res, 500, `growth_exception: ${e?.message || e}`);
     }
   },



   
   /* ---------- dashboard/cards (GET) ----------
   Query:
     bubble_user_id (required)
     range: 'd'|'w'|'m'|'y'  -> 1/7/30/365 Tage
   */
   "dashboard/cards": async (req, res) => {
     if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
   
     const bubble_user_id = req.query.bubble_user_id;
     const range = String(req.query.range || "d").toLowerCase();
     if (!bubble_user_id) return bad(res, 400, "missing_bubble_user_id");
   
     const days = range === "y" ? 365 : range === "m" ? 30 : range === "w" ? 7 : 1;
     // Schwelle = inkl. Datum (UTC) – wir vergleichen gegen DATE-Spalte
     const threshold = new Date(Date.now() - days * 86400 * 1000)
       .toISOString()
       .slice(0, 10); // 'YYYY-MM-DD'
   
     const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
   
     // 1) Aktuelle Playlists des Users (Owner + public)
     const pathNow =
       `/rest/v1/playlists` +
       `?select=id,name,followers` +
       `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
       `&is_owner=is.true&is_public=is.true` +
       `&order=followers.desc.nullslast,name.asc`;
   
     const nowR = await fetch(SUPABASE_URL + pathNow, {
       headers: { apikey: SRK, Authorization: `Bearer ${SRK}` },
     });
     const nowArr = await nowR.json().catch(() => []);
     if (!nowR.ok) return bad(res, 500, `supabase_now_failed: ${JSON.stringify(nowArr)}`);
   
     const playlistsCount = nowArr.length;
     if (playlistsCount === 0) {
       return json(res, 200, {
         ok: true,
         range: { key: range, days },
         totals: {
           total_followers: 0,
           pct_change: null,
           total_new_followers: 0,
           playlists_count: 0,
         },
         top_playlist_follower: null,
         top_playlist_new_followers: null,
         debug_counts: {
           playlists_seen: 0,
           baseline_daily_rows: 0,
           baseline_history_rows: 0,
           threshold,
           scope: "all",
         },
       });
     }
   
     const ids = nowArr.map((x) => x.id).filter(Boolean);
     const inList = `(${ids.join(",")})`; // PostgREST IN() für UUIDs ok ohne Quotes
   
     // 2) Baseline primär aus playlist_followers_daily (<= threshold), pro Playlist jüngster Eintrag
     const pathDaily =
       `/rest/v1/playlist_followers_daily` +
       `?select=playlist_id,day,followers` +
       `&playlist_id=in.${encodeURIComponent(inList)}` +
       `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
       `&day=lte.${encodeURIComponent(threshold)}` +
       `&order=playlist_id.asc,day.desc`;
   
     const dailyR = await fetch(SUPABASE_URL + pathDaily, {
       headers: { apikey: SRK, Authorization: `Bearer ${SRK}` },
     });
     const dailyArr = await dailyR.json().catch(() => []);
     if (!dailyR.ok) return bad(res, 500, `supabase_daily_failed: ${JSON.stringify(dailyArr)}`);
   
     const baselineById = new Map(); // playlist_id -> followers
     for (const row of dailyArr) {
       if (!baselineById.has(row.playlist_id)) {
         baselineById.set(row.playlist_id, Number(row.followers ?? 0));
       }
     }
     const baselineDailyCount = baselineById.size;
   
     // 2b) Optionaler Fallback: fehlende Baselines aus playlist_followers_history
     if (baselineById.size < ids.length) {
       const missing = ids.filter((id) => !baselineById.has(id));
       if (missing.length > 0) {
         const inMissing = `(${missing.join(",")})`;
         const pathHist =
           `/rest/v1/playlist_followers_history` +
           `?select=playlist_id,day,followers` +
           `&playlist_id=in.${encodeURIComponent(inMissing)}` +
           `&day=lte.${encodeURIComponent(threshold)}` +
           `&order=playlist_id.asc,day.desc`;
         const histR = await fetch(SUPABASE_URL + pathHist, {
           headers: { apikey: SRK, Authorization: `Bearer ${SRK}` },
         });
         const histArr = await histR.json().catch(() => []);
         if (!histR.ok) return bad(res, 500, `supabase_hist_failed: ${JSON.stringify(histArr)}`);
         for (const row of histArr) {
           if (!baselineById.has(row.playlist_id)) {
             baselineById.set(row.playlist_id, Number(row.followers ?? 0));
           }
         }
       }
     }
     const baselineHistAdded = baselineById.size - baselineDailyCount;
   
     // 3) KPIs berechnen
     let totalCurrent = 0;
     let totalBaseline = 0;
     let topFollower = null; // { id, name, current, delta }
     let topNew = null; // { id, name, current, delta }
   
     for (const p of nowArr) {
       const current = Number(p.followers || 0);
       const baseline = baselineById.has(p.id)
         ? Number(baselineById.get(p.id))
         : current; // wenn keine Baseline bekannt → delta 0
   
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
   
     const totalNew = totalCurrent - totalBaseline;
     const pctChange = totalBaseline > 0 ? (totalNew * 100.0) / totalBaseline : null;
   
     return json(res, 200, {
       ok: true,
       range: { key: range, days },
       totals: {
         total_followers: totalCurrent,
         pct_change: pctChange, // z.B. 3.5 (%)
         total_new_followers: totalNew,
         playlists_count: playlistsCount,
       },
       top_playlist_follower: topFollower, // {id,name,current,delta}
       top_playlist_new_followers: topNew, // {id,name,current,delta}
       debug_counts: {
         playlists_seen: playlistsCount,
         baseline_daily_rows: baselineDailyCount,
         baseline_history_rows: baselineHistAdded,
         threshold,
         scope: "all",
       },
     });
   },


   
   
      /* ---------- dashboard/growth/note/save (POST) ----------
   Header: X-Bubble-User-Id (required)
   Body: { playlist_id: uuid, day: 'YYYY-MM-DD', note: string }
   Leere note => delete
   */
   "dashboard/growth/note/save": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     const bubbleUserId = await bubbleUserIdFromRequest(req);
     if (!bubbleUserId) return bad(res, 401, "missing_x_bubble_user_id");
   
     const body = await readBody(req);
     const playlist_id = String(body.playlist_id || "");
     const day = String(body.day || "").slice(0,10);
     const note = typeof body.note === "string" ? body.note : "";
   
     if (!playlist_id) return bad(res, 400, "missing_playlist_id");
     if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return bad(res, 400, "invalid_day");
   
     try {
       const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
   
       // Ownership check
       const pR = await fetch(
         `${SUPABASE_URL}/rest/v1/playlists?select=id&limit=1&id=eq.${encodeURIComponent(playlist_id)}&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`,
         { headers: { apikey: SRK, Authorization: `Bearer ${SRK}` } }
       );
       const pArr = await pR.json().catch(()=>[]);
       if (!pR.ok) return bad(res, 500, `supabase_playlist_check_failed: ${JSON.stringify(pArr)}`);
       if (!pArr[0]) return bad(res, 403, "playlist_not_owned_or_not_found");
   
       if (!note.trim()) {
         // Delete
         const del = await fetch(
           `${SUPABASE_URL}/rest/v1/playlist_growth_notes?playlist_id=eq.${encodeURIComponent(playlist_id)}&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}&day=eq.${encodeURIComponent(day)}`,
           { method: "DELETE", headers: { apikey: SRK, Authorization: `Bearer ${SRK}`, Prefer: "return=minimal" } }
         );
         if (!del.ok) return bad(res, 500, `note_delete_failed: ${await del.text()}`);
         return json(res, 200, { ok: true, deleted: true });
       }
   
       // Upsert
       const up = await fetch(
         `${SUPABASE_URL}/rest/v1/playlist_growth_notes?on_conflict=playlist_id,bubble_user_id,day`,
         {
           method: "POST",
           headers: {
             apikey: SRK,
             Authorization: `Bearer ${SRK}`,
             "Content-Type": "application/json",
             Prefer: "resolution=merge-duplicates,return=representation"
           },
           body: JSON.stringify([{ playlist_id, bubble_user_id: bubbleUserId, day, note }])
         }
       );
       const data = await up.json().catch(()=>[]);
       if (!up.ok) return bad(res, 500, `note_upsert_failed: ${JSON.stringify(data)}`);
   
       return json(res, 200, { ok: true, note: Array.isArray(data) ? data[0] : data });
     } catch (e) {
       return bad(res, 500, `note_save_exception: ${e?.message || e}`);
     }
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
   
     const bubble_user_id = await bubbleUserIdFromRequest(req, req.query.bubble_user_id);
     if (!bubble_user_id) return bad(res, 400, "missing_bubble_user_id");
   
     const days = Math.max(1, Math.min(365, Number(req.query.days || "30")));
     const gran = (req.query.granularity || "daily").toLowerCase(); // daily|weekly|monthly
     const scope = (req.query.scope || "total").toLowerCase();       // total|by_playlist
     const connection_id = String(req.query.connection_id || "");
     const playlist_id = String(req.query.playlist_id || "");
   
     const fromParam = String(req.query.from || "").slice(0, 10);
     const toParam = String(req.query.to || "").slice(0, 10);
     const fromDay = new Date(Date.now() - days*24*3600*1000);
     const fromStr = /^\d{4}-\d{2}-\d{2}$/.test(fromParam) ? fromParam : fromDay.toISOString().slice(0,10);
     const toFilter = /^\d{4}-\d{2}-\d{2}$/.test(toParam) ? `&day=lte.${encodeURIComponent(toParam)}` : "";
   
     let playlistFilter = "";
     if (playlist_id) {
       playlistFilter = `&playlist_id=eq.${encodeURIComponent(playlist_id)}`;
     } else if (connection_id) {
       const plR = await fetch(
         SUPABASE_URL +
           `/rest/v1/playlists?select=id&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
           `&connection_id=eq.${encodeURIComponent(connection_id)}&is_owner=is.true&is_public=is.true`,
         { headers: { apikey: SRK, Authorization: `Bearer ${SRK}` }, cache: "no-store" }
       );
       const accountPlaylists = plR.ok ? JSON.parse(await plR.text() || "[]") : [];
       const ids = accountPlaylists.map((p) => p.id).filter(Boolean);
       if (!ids.length) return json(res, 200, { ok: true, granularity: gran, labels: [], followers: [], growth: [] });
       playlistFilter = `&playlist_id=in.(${ids.map((id) => `"${id}"`).join(",")})`;
     }

     const snapPath =
       `/rest/v1/playlist_followers_daily` +
       `?select=playlist_id,day,followers` +
       `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
       `&day=gte.${encodeURIComponent(fromStr)}` +
       toFilter +
       playlistFilter +
       `&order=day.asc`;
     const sResp = await fetch(SUPABASE_URL + snapPath, { headers: { apikey: SRK, Authorization: `Bearer ${SRK}` }, cache: "no-store" });
     if (!sResp.ok) return bad(res, 500, `supabase_error: ${await sResp.text()}`);
     const rows = JSON.parse(await sResp.text() || "[]");
     const uniqueDays = new Set(rows.map((row) => row.day).filter(Boolean));
   
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
     const followers = [];
     for (let i = 0; i < labels.length; i++) {
       const curr = agg.get(labels[i]).followersTotal;
       const prev = i ? agg.get(labels[i-1]).followersTotal : curr;
       followers.push(curr);
       growth.push(curr - prev);
     }
   
     if (scope === "total") {
       return json(res, 200, {
         ok: true,
         granularity: gran,
         labels,               // z.B. Tage/Wochen/Monate
         followers,
         growth,               // Delta followers pro Bucket (gesamt)
         data_points: rows.length,
         history_days: uniqueDays.size,
         ready: labels.length >= 2 && uniqueDays.size >= 2,
         warmup: labels.length < 2 || uniqueDays.size < 2,
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
   
     return json(res, 200, { ok: true, granularity: gran, labels, by_playlist, data_points: rows.length, history_days: uniqueDays.size, ready: labels.length >= 2 && uniqueDays.size >= 2, warmup: labels.length < 2 || uniqueDays.size < 2 });
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

  const bubble_user_id = await bubbleUserIdFromRequest(req, req.query.bubble_user_id);
  if (!bubble_user_id) return bad(res, 400, "missing_bubble_user_id");

  const days = Math.max(1, Math.min(365, Number(req.query.days || "7")));
  const removals_limit = Math.max(1, Math.min(500, Number(req.query.removals_limit || "50")));

  // 1) aktuelle Playlists ziehen (für total followers + Namen)
  const plistPath =
    `/rest/v1/playlists?select=id,name,followers,image,tracks_total,connection_id,auto_remove_enabled,auto_remove_weeks,updated_at,last_checked_at,next_check_at` +
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
  const snapshotDays = new Set(snaps.map((row) => row.day).filter(Boolean));

  // map: playlist_id -> {firstFollowers, lastFollowers}
  const snapMap = new Map();
  for (const r of snaps) {
    let o = snapMap.get(r.playlist_id);
    if (!o) { o = { first: r.followers, last: r.followers }; snapMap.set(r.playlist_id, o); }
    o.last = r.followers; // wegen day.asc ist die letzte Zeile am Ende
  }

  let top_growing = null;
  let net_growth = 0;
  const growth_rank = [];
  for (const p of playlists) {
    const s = snapMap.get(p.id);
    const delta = s ? (s.last - s.first) : 0;
    net_growth += delta;
    if (!top_growing || delta > top_growing.delta) {
      top_growing = { playlist_id: p.id, name: p.name, image: p.image, delta, followers_now: p.followers || 0 };
    }
    growth_rank.push({
      playlist_id: p.id,
      name: p.name,
      image: p.image,
      delta,
      followers_now: p.followers || 0,
      tracks_total: p.tracks_total || 0,
    });
  }
  growth_rank.sort((a, b) => b.delta - a.delta || b.followers_now - a.followers_now);
  const top_playlists = [...playlists]
    .sort((a, b) => (b.followers || 0) - (a.followers || 0))
    .slice(0, 8)
    .map((p) => ({
      playlist_id: p.id,
      name: p.name,
      image: p.image,
      followers: p.followers || 0,
      tracks_total: p.tracks_total || 0,
      auto_remove_enabled: !!p.auto_remove_enabled,
      auto_remove_weeks: p.auto_remove_weeks ?? null,
    }));

	  // 3) kommende Auto-Removals
	  const playlistIds = playlists.map((p) => p.id).filter(Boolean);
	  const todayStr = new Date().toISOString().slice(0,10);
	  const horizonStr = new Date(Date.now() + 14*24*3600*1000).toISOString().slice(0,10);
	  let upcoming_removals = [];
	  if (playlistIds.length) {
	    const rpcResp = await fetch(`${SUPABASE_URL}/rest/v1/rpc/dashboard_expiring_next`, {
	      method: "POST",
	      headers: { apikey: SRK, Authorization: `Bearer ${SRK}`, "Content-Type": "application/json" },
	      body: JSON.stringify({ p_bubble_user_id: String(bubble_user_id), p_limit: removals_limit, p_connection_id: null })
	    });
	    if (rpcResp.ok) {
	      const rpcRows = JSON.parse(await rpcResp.text() || "[]");
	      upcoming_removals = rpcRows.map((row) => {
	        const daysUntil = Number(row.days_until_remove ?? row.days_until_removal);
	        const removesOn = row.removes_on || row.remove_on || (Number.isFinite(daysUntil)
	          ? new Date(Date.now() + Math.max(0, daysUntil) * 24*3600*1000).toISOString().slice(0,10)
	          : null);
	        return {
	          playlist_id: row.playlist_id,
	          playlist_name: row.playlist_name || row.name,
	          position: row.position,
	          track_id: row.track_id,
	          track_name: row.track_name || row.title,
	          artist_names: row.artist_names || row.artist,
	          added_at: row.added_at,
	          auto_remove_weeks: row.auto_remove_weeks || row.expiry_weeks,
	          removes_on: removesOn,
	          days_until_remove: Number.isFinite(daysUntil) ? Math.max(0, daysUntil) : null,
	        };
	      }).filter((row) => !row.removes_on || row.removes_on <= horizonStr);
	    }
	    if (!upcoming_removals.length) {
	      const upcPath =
	        `/rest/v1/upcoming_removals_ui` +
	        `?select=playlist_id,playlist_name,position,track_id,track_name,artist_names,added_at,auto_remove_weeks,removes_on` +
	        `&removes_on=gte.${encodeURIComponent(todayStr)}` +
	        `&removes_on=lte.${encodeURIComponent(horizonStr)}` +
	        `&playlist_id=in.(${playlistIds.map((id) => `"${id}"`).join(",")})` +
	        `&order=removes_on.asc,playlist_name.asc,position.asc` +
	        `&limit=${removals_limit}`;
	      const uResp = await fetch(SUPABASE_URL + upcPath, { headers: { apikey: SRK, Authorization: `Bearer ${SRK}` }, cache: "no-store" });
	      upcoming_removals = uResp.ok ? JSON.parse(await uResp.text() || "[]") : [];
	    }
	    if (upcoming_removals.length) {
	      const removalTrackIds = [...new Set(upcoming_removals.map((row) => row.track_id).filter(Boolean))];
	      if (removalTrackIds.length) {
	        const quotedTrackIds = removalTrackIds.map((id) => `"${encodeURIComponent(String(id))}"`).join(",");
	        const itemsResp = await fetch(
	          SUPABASE_URL +
	            `/rest/v1/playlist_items?select=playlist_id,track_id,cover_url` +
	            `&playlist_id=in.(${playlistIds.map((id) => `"${id}"`).join(",")})` +
	            `&track_id=in.(${quotedTrackIds})`,
	          { headers: { apikey: SRK, Authorization: `Bearer ${SRK}` }, cache: "no-store" }
	        );
	        const itemRows = itemsResp.ok ? JSON.parse(await itemsResp.text() || "[]") : [];
	        const coverByKey = new Map(itemRows.map((row) => [`${row.playlist_id}:${row.track_id}`, row.cover_url]));
	        const playlistImageById = new Map(playlists.map((p) => [p.id, p.image]));
	        upcoming_removals = upcoming_removals.map((row) => ({
	          ...row,
	          cover_url: row.cover_url || coverByKey.get(`${row.playlist_id}:${row.track_id}`) || null,
	          playlist_image: playlistImageById.get(row.playlist_id) || null,
	        }));
	      }
	    }
	  }

  let flex_enabled_count = 0;
  let flex_due_count = 0;
  if (playlistIds.length) {
    const flexPath =
      `/rest/v1/playlist_flex_settings?select=playlist_id,enabled,next_rotation_at` +
      `&playlist_id=in.(${playlistIds.map((id) => `"${id}"`).join(",")})`;
    const fResp = await fetch(SUPABASE_URL + flexPath, { headers: { apikey: SRK, Authorization: `Bearer ${SRK}` }, cache: "no-store" });
    const flexRows = fResp.ok ? JSON.parse(await fResp.text() || "[]") : [];
    flex_enabled_count = flexRows.filter((r) => r.enabled).length;
    flex_due_count = flexRows.filter((r) => r.enabled && r.next_rotation_at && new Date(r.next_rotation_at) <= new Date(Date.now() + 24*3600*1000)).length;
  }

  const automation_enabled_count = playlists.filter((p) => p.auto_remove_enabled && Number(p.auto_remove_weeks) > 0).length;
  const cooldown_count = playlists.filter((p) => p.next_check_at && new Date(p.next_check_at) > new Date()).length;
  const stale_count = playlists.filter((p) => {
    const checked = p.last_checked_at || p.updated_at;
    return !checked || new Date(checked) < new Date(Date.now() - 24*3600*1000);
  }).length;

  return json(res, 200, {
    ok: true,
    totals: {
      playlists_count: playlists.length,
      total_followers,
      total_tracks: playlists.reduce((a, p) => a + (p.tracks_total || 0), 0),
      net_growth_last_days: net_growth,
      automation_enabled_count,
      flex_enabled_count,
      flex_due_count,
      cooldown_count,
      stale_count,
      growth_snapshot_days: snapshotDays.size,
      growth_data_points: snaps.length,
      growth_ready: snapshotDays.size >= 2,
    },
    top_growing: top_growing || null,
    top_playlists,
    growth_rank: growth_rank.slice(0, 8),
    upcoming_removals,
    next_day_removals: upcoming_removals.filter((r) => r.removes_on === new Date(Date.now() + 24*3600*1000).toISOString().slice(0,10))
  });
},

  /* ---------- backups/list (GET) ---------- */
  "backups/list": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req, req.query.bubble_user_id);
    if (!bubbleUserId) return bad(res, 401, "missing_user");
    const playlist_id = String(req.query.playlist_id || "");
    if (!playlist_id) return bad(res, 400, "missing_playlist_id");
    const owned = await getOwnedPlaylist(playlist_id, bubbleUserId);
    if (!owned) return bad(res, 403, "playlist_not_owned");
    const limit = Math.max(1, Math.min(50, Number(req.query.limit || "10")));
    let r = await sb(
      `/rest/v1/playlist_backups?select=id,taken_at,snapshot_id,name,image,followers,tracks_total,reason` +
      `&playlist_id=eq.${encodeURIComponent(playlist_id)}` +
      `&order=taken_at.desc&limit=${encodeURIComponent(limit)}`
    );
    if (!r.ok) {
      const text = await r.text();
      if (text.includes("reason")) {
        r = await sb(
          `/rest/v1/playlist_backups?select=id,taken_at,snapshot_id,name,image,followers,tracks_total` +
          `&playlist_id=eq.${encodeURIComponent(playlist_id)}` +
          `&order=taken_at.desc&limit=${encodeURIComponent(limit)}`
        );
      } else {
        return bad(res, 500, `backups_select_failed: ${text}`);
      }
    }
    if (!r.ok) return bad(res, 500, `backups_select_failed: ${await r.text()}`);
    return json(res, 200, await r.json());
  },

  /* ---------- backups/create (POST) ---------- */
  "backups/create": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req);
    if (!bubbleUserId) return bad(res, 401, "missing_user");
    const { playlist_id, only_if_changed = false } = await readBody(req);
    if (!playlist_id) return bad(res, 400, "missing_playlist_id");
    const playlist = await getOwnedPlaylist(playlist_id, bubbleUserId);
    if (!playlist) return bad(res, 403, "playlist_not_owned");
    try {
      const result = await createPlaylistBackup(playlist, { reason: "manual", onlyIfChanged: !!only_if_changed });
      return json(res, 200, { ok: true, ...result });
    } catch (e) {
      return bad(res, 500, `backup_create_failed: ${String(e?.message || e)}`);
    }
  },

  /* ---------- backups/detail (GET) ---------- */
  "backups/detail": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req, req.query.bubble_user_id);
    if (!bubbleUserId) return bad(res, 401, "missing_user");
    const playlist_id = String(req.query.playlist_id || "");
    const backup_id = String(req.query.backup_id || "");
    if (!playlist_id || !backup_id) return bad(res, 400, "missing_playlist_or_backup_id");
    const owned = await getOwnedPlaylist(playlist_id, bubbleUserId);
    if (!owned) return bad(res, 403, "playlist_not_owned");
    try {
      const backup = await getBackupForPlaylist(playlist_id, backup_id);
      if (!backup) return bad(res, 404, "backup_not_found");
      const tracks = Array.isArray(backup.tracks) ? backup.tracks : [];
      return json(res, 200, { ...backup, summary: summarizeBackupTracks(tracks), tracks });
    } catch (e) {
      return bad(res, 500, String(e?.message || e));
    }
  },

  /* ---------- backups/diff (GET) ---------- */
  "backups/diff": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req, req.query.bubble_user_id);
    if (!bubbleUserId) return bad(res, 401, "missing_user");
    const playlist_id = String(req.query.playlist_id || "");
    const backup_id = String(req.query.backup_id || "");
    if (!playlist_id || !backup_id) return bad(res, 400, "missing_playlist_or_backup_id");
    const owned = await getOwnedPlaylist(playlist_id, bubbleUserId);
    if (!owned) return bad(res, 403, "playlist_not_owned");
    try {
      const backup = await getBackupForPlaylist(playlist_id, backup_id);
      if (!backup) return bad(res, 404, "backup_not_found");
      const current = await fetchCurrentPlaylistItemsForBackupDiff(playlist_id);
      const backupTracks = Array.isArray(backup.tracks) ? backup.tracks : [];
      return json(res, 200, {
        backup_id,
        backup_summary: summarizeBackupTracks(backupTracks),
        current_summary: summarizeBackupTracks(current),
        diff: diffBackupAgainstCurrent(backupTracks, current),
      });
    } catch (e) {
      return bad(res, 500, String(e?.message || e));
    }
  },

  /* ---------- backups/restore (POST) ---------- */
  "backups/restore": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req);
    if (!bubbleUserId) return bad(res, 401, "missing_user");
    const { playlist_id, backup_id, restore_locks = false, restore_rotator = false } = await readBody(req);
    if (!playlist_id || !backup_id) return bad(res, 400, "missing_playlist_or_backup_id");
    const playlist = await getOwnedPlaylist(playlist_id, bubbleUserId);
    if (!playlist) return bad(res, 403, "playlist_not_owned");

    const backup = await getBackupForPlaylist(playlist_id, backup_id).catch((e) => ({ _error: e }));
    if (backup?._error) return bad(res, 500, String(backup._error?.message || backup._error));
    if (!backup) return bad(res, 404, "backup_not_found");

    const tracks = Array.isArray(backup.tracks) ? backup.tracks : [];
    const uris = tracks
      .sort((a, b) => Number(a?.position || 0) - Number(b?.position || 0))
      .map((track) => track?.track_uri)
      .filter(Boolean);
    if (!uris.length) return bad(res, 400, "backup_has_no_restorable_tracks");

    try {
      const before = await createPlaylistBackup(playlist, { reason: "pre_restore", onlyIfChanged: false }).catch((e) => ({ skipped: true, error: String(e?.message || e) }));
      const access_token = await getAccessTokenFromConnection(playlist.connection_id);
      const restored = await replaceSpotifyPlaylistTracks(playlist.playlist_id, access_token, uris);
      const automation = await restoreBackupAutomationState(playlist, tracks, { restore_locks: !!restore_locks || !!restore_rotator, restore_rotator: !!restore_rotator });
      const cooldownUntil = await setPlaylistUpdateCooldown(playlist.id, 300);
      await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(String(playlist.id))}`, {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify({
          snapshot_id: restored.snapshot_id,
          tracks_total: restored.tracks_total,
          needs_sync: true,
          next_check_at: cooldownUntil
        })
      }).catch(() => {});

      const base = internalBaseUrl();
      if (base) {
        fetch(`${base}/api/playlists/dispatch-sync`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
          body: JSON.stringify({ playlist_id: playlist.id })
        }).catch(() => {});
      }

      return json(res, 200, { ok: true, restored, automation, pre_restore_backup: before, cooldown_until: cooldownUntil });
    } catch (e) {
      return bad(res, 500, `backup_restore_failed: ${String(e?.message || e)}`);
    }
  },

  /* ---------- backups/cleanup-duplicates (POST) ---------- */
  "backups/cleanup-duplicates": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req);
    if (!bubbleUserId) return bad(res, 401, "missing_user");
    const { playlist_id } = await readBody(req);
    if (!playlist_id) return bad(res, 400, "missing_playlist_id");
    const owned = await getOwnedPlaylist(playlist_id, bubbleUserId);
    if (!owned) return bad(res, 403, "playlist_not_owned");
    const r = await sb(
      `/rest/v1/playlist_backups?select=id,snapshot_id,taken_at` +
      `&playlist_id=eq.${encodeURIComponent(String(playlist_id))}` +
      `&snapshot_id=not.is.null&order=taken_at.desc`
    );
    if (!r.ok) return bad(res, 500, `backup_select_failed:${await r.text()}`);
    const rows = await r.json();
    const seen = new Set();
    const deleteIds = [];
    for (const row of rows || []) {
      if (!row.snapshot_id) continue;
      if (seen.has(row.snapshot_id)) deleteIds.push(row.id);
      else seen.add(row.snapshot_id);
    }
    if (deleteIds.length) {
      const idList = deleteIds.map((id) => encodeURIComponent(String(id))).join(",");
      const del = await sb(`/rest/v1/playlist_backups?id=in.(${idList})`, { method: "DELETE" });
      if (!del.ok) return bad(res, 500, `backup_delete_failed:${await del.text()}`);
    }
    return json(res, 200, { ok: true, deleted: deleteIds.length, kept_snapshots: seen.size });
  },

  /* ---------- backups/apply-retention (POST) ---------- */
  "backups/apply-retention": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req);
    if (!bubbleUserId) return bad(res, 401, "missing_user");
    const { playlist_id, keep_daily_days = 30, keep_weekly_months = 6 } = await readBody(req);
    if (!playlist_id) return bad(res, 400, "missing_playlist_id");
    const owned = await getOwnedPlaylist(playlist_id, bubbleUserId);
    if (!owned) return bad(res, 403, "playlist_not_owned");
    const r = await sb(
      `/rest/v1/playlist_backups?select=id,taken_at` +
      `&playlist_id=eq.${encodeURIComponent(String(playlist_id))}` +
      `&order=taken_at.desc&limit=2000`
    );
    if (!r.ok) return bad(res, 500, `backup_select_failed:${await r.text()}`);
    const rows = await r.json();
    const dailyCutoff = Date.now() - Math.max(1, Number(keep_daily_days) || 30) * 24 * 3600 * 1000;
    const weeklyCutoff = Date.now() - Math.max(1, Number(keep_weekly_months) || 6) * 31 * 24 * 3600 * 1000;
    const keptWeeks = new Set();
    const deleteIds = [];
    for (const row of rows || []) {
      const ts = Date.parse(row.taken_at || "");
      if (!Number.isFinite(ts) || ts >= dailyCutoff) continue;
      if (ts < weeklyCutoff) {
        deleteIds.push(row.id);
        continue;
      }
      const d = new Date(ts);
      const weekKey = `${d.getUTCFullYear()}-${Math.floor((Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) - Date.UTC(d.getUTCFullYear(), 0, 1)) / (7 * 24 * 3600 * 1000))}`;
      if (keptWeeks.has(weekKey)) deleteIds.push(row.id);
      else keptWeeks.add(weekKey);
    }
    if (deleteIds.length) {
      const idList = deleteIds.map((id) => encodeURIComponent(String(id))).join(",");
      const del = await sb(`/rest/v1/playlist_backups?id=in.(${idList})`, { method: "DELETE" });
      if (!del.ok) return bad(res, 500, `backup_delete_failed:${await del.text()}`);
    }
    return json(res, 200, { ok: true, deleted: deleteIds.length, weekly_kept: keptWeeks.size });
  },

  /* ---------- backups/cron-weekly (GET/POST) ---------- */
  "backups/cron-weekly": async (req, res) => {
    if (!checkCronAuth(req) && !checkAppSecret(req)) return bad(res, 401, "unauthorized_cron");
    const qs = Object.fromEntries(new URL(req.url, `http://${req.headers.host}`).searchParams.entries());
    const limit = Math.max(1, Math.min(20, Number(qs.limit || "10")));
    const r = await sb(
      `/rest/v1/playlists?select=id,playlist_id,connection_id,bubble_user_id,name,image,followers,tracks_total,last_checked_at` +
      `&is_owner=is.true&is_public=is.true&connection_id=not.is.null` +
      `&order=last_checked_at.asc.nullsfirst&limit=${encodeURIComponent(limit)}`
    );
    if (!r.ok) return bad(res, 500, `playlist_select_failed: ${await r.text()}`);
    const playlists = await r.json();
    let created = 0, unchanged = 0, failed = 0;
    for (const playlist of playlists) {
      try {
        const result = await createPlaylistBackup(playlist, { reason: "weekly", onlyIfChanged: true });
        if (result.skipped) unchanged++;
        else created++;
      } catch {
        failed++;
      }
      await sleep(120);
    }
    return json(res, 200, { ok: true, processed: playlists.length, created, unchanged, failed });
  },



  /* ---------- search (GET) ---------- */

   "tracks/search": async (req, res) => {
     if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
     const q = req.query.q || "";
     const connection_id = req.query.connection_id || "";
     const limit = Math.min(25, Number(req.query.limit || "10"));
   
     if (!q || !connection_id) return bad(res, 400, "missing_q_or_connection_id");
   
     try {
       const connR = await sb(`/rest/v1/spotify_connections?select=id,refresh_token_enc&limit=1&id=eq.${encodeURIComponent(connection_id)}`);
       const conn = connR.ok ? (await connR.json().catch(() => []))?.[0] : null;
       if (!conn?.refresh_token_enc) return bad(res, 404, "connection_not_found");
       const credentials = await getSpotifyAppCredentialsForConnection(connection_id);
       const token = await refreshAccessTokenDirect(decryptToken(conn.refresh_token_enc), credentials);
       const url = `https://api.spotify.com/v1/search?type=track&market=from_token&limit=${encodeURIComponent(
         String(limit)
       )}&q=${encodeURIComponent(q)}`;
   
       const searchResponse = await fetch(url, {
         headers: { Authorization: `Bearer ${token}` },
       });
       const parsed = await parseJsonSafe(searchResponse);
   
       if (!searchResponse.ok) {
         return bad(res, searchResponse.status, `spotify_search_failed: ${parsed.json ? JSON.stringify(parsed.json) : parsed.text}`);
       }
   
       const items = (parsed.json?.tracks?.items || []).map((t) => ({
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

  /* ---------- tracks/resolve (GET|POST) ---------- */
   "tracks/resolve": async (req, res) => {
     // GET → Body spiegeln, damit die bestehende Logik weiter unten unverändert greifen kann
     if (req.method === "GET") {
       req.body = {
         input: req.query.input || req.query.q || "",
         connection_id: req.query.connection_id || "",
         candidates: req.query.candidates || undefined,
       };
     } else if (req.method !== "POST") {
       return bad(res, 405, "method_not_allowed");
     }
   
     const body = await readBody(req);
     const input = body.input || "";
     const connection_id = body.connection_id || "";
     const wantCandidates = Math.max(0, Math.min(25, Number(body.candidates ?? req.query?.candidates ?? 8)));
   
     let id = parseTrackId(input);
   
     try {
       // Fall A: Eine gültige Track-ID/URI/URL wurde erkannt
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
   
           // Kandidaten (frei nach dem Original-Input suchen)
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
   
       // Fall B: Keine ID erkannt → suche (verlangt connection_id)
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
   
     const bubbleUserId = await bubbleUserIdFromRequest(req);
     if (!bubbleUserId) return bad(res, 401, "Missing X-Bubble-User-Id");
   
     try {
       const { playlist_id, link_or_uri, position, expiry_weeks, exp_weeks } = await readBody(req);
       if (!playlist_id || !link_or_uri) {
         return bad(res, 400, "missing_playlist_id_or_link");
       }
       
       // Unterstütze sowohl expiry_weeks als auch exp_weeks (exp_weeks hat Priorität)
       const expiryWeeksParam = exp_weeks !== undefined ? exp_weeks : expiry_weeks;
   
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
       const trackId = parsed.id;
   
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
       const cooldownUntil = await setPlaylistUpdateCooldown(row.id, 300);
       await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(row.id)}`, {
         method: "PATCH",
         headers: { Prefer: "return=minimal" },
         body: JSON.stringify({ needs_sync: true, next_check_at: cooldownUntil })
       }).catch(() => {});

       // Wenn expiry_weeks angegeben wurde, in playlist_item_locks speichern
       if (expiryWeeksParam !== undefined && expiryWeeksParam !== null && String(expiryWeeksParam).trim() !== "") {
         const expiryWeeksNum = Number(expiryWeeksParam);
         if (Number.isFinite(expiryWeeksNum) && expiryWeeksNum > 0) {
           const finalPosition = wantPosition !== null && wantPosition !== undefined ? wantPosition : 0;
           await sb(`/rest/v1/playlist_item_locks?on_conflict=playlist_id,track_id`, {
             method: "POST",
             headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
             body: JSON.stringify([{
               playlist_id: row.id,
               track_id: trackId,
               locked_position: finalPosition,
               is_locked: false, // Nicht gelockt, nur Expiry gesetzt
               expiry_weeks: expiryWeeksNum,
               locked_at: new Date().toISOString()
             }])
           }).catch((err) => {
             console.warn("Failed to save expiry_weeks for track", { playlist_id: row.id, track_id: trackId, error: err });
           });
         }
       }

       const base = internalBaseUrl();
       await fetch(`${base}/api/playlists/dispatch-sync`, {
         method: "POST",
         headers: { "Content-Type": "application/json", "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
         body: JSON.stringify({ playlist_id: row.id })
       }).catch(() => {});

       return json(res, 200, {
         ok: true,
         added: trackUri,
         position_used: (wantPosition !== null && wantPosition !== undefined) ? wantPosition : "append",
         snapshot_id: addRes.json?.snapshot_id || null,
         cooldown_until: cooldownUntil
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
  const bubbleUserId = await bubbleUserIdFromRequest(req);
  if (!bubbleUserId) return bad(res, 401, "not_authenticated");

  const playlist_id = req.query.playlist_id;
  if (!playlist_id) return bad(res, 400, "missing_playlist_id");

  const path =
    `/rest/v1/playlists` +
    `?select=id,playlist_id,name,image,tracks_total,followers,updated_at,` +
    `auto_remove_enabled,auto_remove_weeks` +
    `&id=eq.${encodeURIComponent(playlist_id)}` +
    `&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}` +
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
   
  /* ===========================
      oauth/spotify/start (POST)
      =========================== */
   "oauth/spotify/start": async (req, res) => {
     try {
       const body = req.method === "POST" ? await readBody(req) : {};
       const return_to = String(body.return_to || req.query.return_to || "/").trim();
       const label = String(body.label || req.query.label || "").trim();
       let bubble_user_id = "";

       if (req.method === "POST") {
         const ctx = await getUserContext(req);
         if (!ctx?.linked || !ctx.bubble_user_id) return bad(res, 401, "not_authenticated");
         bubble_user_id = ctx.bubble_user_id;
       } else if (hasValidAppSecret(req)) {
         bubble_user_id = String(req.query.bubble_user_id || "").trim();
       } else {
         const base = return_to || "/";
         const sep = base.includes("?") ? "&" : "?";
         return res.redirect(`${base}${sep}spotify_error=auth_required`);
       }
   
       if (!bubble_user_id) {
         const base = return_to || "/";
         const sep  = base.includes("?") ? "&" : "?";
         return res.redirect(`${base}${sep}spotify_error=missing_bubble_user_id`);
       }

       const billing = await getBillingState(bubble_user_id).catch(() => null);
       if (!billing?.is_active) {
         const base = return_to || "/";
         const sep  = base.includes("?") ? "&" : "?";
         return res.redirect(`${base}${sep}spotify_error=subscription_required`);
       }

       const credentials = await getSpotifyAppCredentialsForUser(bubble_user_id, { allowFallback: true });
       if (!credentials?.client_id || !credentials?.redirect_uri) {
         const base = return_to || "/";
         const sep  = base.includes("?") ? "&" : "?";
         return res.redirect(`${base}${sep}spotify_error=missing_spotify_app_credentials`);
       }
   
       // Scopes – je nach Feature erweitern
       const SCOPES = [
         "playlist-read-private",
         "playlist-modify-private",
         "playlist-modify-public",
       ];
   
       // state sicher verpacken (base64url, ohne Padding)
       const stateObj = {
         bubble_user_id,
         return_to,
         label,
         credential_id: credentials.id || null,
         nonce: Math.random().toString(36).slice(2),
         issued_at: Date.now()
       };
       const state = Buffer.from(JSON.stringify(stateObj)).toString("base64url");
   
       // WICHTIG: show_dialog=true erzwingt den Consent-Dialog,
       // prompt=consent ist ein zusätzliches Hint (von vielen Libs verwendet)
       const params = new URLSearchParams({
         response_type: "code",
         client_id: credentials.client_id,
         redirect_uri: credentials.redirect_uri,
         scope: SCOPES.join(" "),
         state,
         show_dialog: "true",
         prompt: "consent"
       });
   
       const url = `https://accounts.spotify.com/authorize?${params.toString()}`;
       if (req.method === "POST") return json(res, 200, { ok: true, url });
       return res.redirect(url);
     } catch (e) {
       const msg = encodeURIComponent(e?.message || String(e));
       if (req.method === "POST") return bad(res, 500, `spotify_oauth_start_exception_${msg}`);
       const back = String(req.query.return_to || "/app");
       const sep = back.includes("?") ? "&" : "?";
       return res.redirect(`${back}${sep}spotify_error=start_exception_${msg}`);
     }
   },
   
   /* ===============================
         oauth/spotify/callback (GET)
      =============================== */
   "oauth/spotify/callback": async (req, res) => {
     // Redirect-Helfer
     const backWithError = (return_to, code) => {
       const base = return_to || "/";
       const sep  = base.includes("?") ? "&" : "?";
       return res.redirect(`${base}${sep}spotify_error=${encodeURIComponent(code)}`);
     };
   
     try {
       const assertEnv = (n) => need(n);
       const SB_URL        = assertEnv("SUPABASE_URL");
       const SB_KEY        = assertEnv("SUPABASE_SERVICE_ROLE_KEY");
       assertEnv("ENC_SECRET");
   
       // Query
       const code  = req.query.code;
       const state = req.query.state;
       if (!code || !state) return backWithError("/", "missing_code_or_state");
   
       // state decodieren
       let parsed;
       try {
         parsed = JSON.parse(Buffer.from(state, "base64url").toString("utf8"));
       } catch {
         return backWithError("/", "invalid_state");
       }
       const bubble_user_id = parsed.bubble_user_id;
       const label          = parsed.label || "";
       const return_to      = parsed.return_to || "/";
       const credential_id  = parsed.credential_id || null;
       if (!bubble_user_id) return backWithError(return_to, "missing_user_in_state");

       let credentials = null;
       if (credential_id) {
         const cr = await sb(
           `/rest/v1/spotify_app_credentials?select=id,client_id,client_secret_enc,redirect_uri,app_name` +
           `&limit=1&id=eq.${encodeURIComponent(credential_id)}&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}`
         );
         const row = cr.ok ? (await cr.json().catch(() => []))?.[0] : null;
         if (row?.client_id && row?.client_secret_enc && row?.redirect_uri) {
           credentials = {
             id: row.id,
             client_id: row.client_id,
             client_secret: decryptToken(row.client_secret_enc),
             redirect_uri: row.redirect_uri,
             source: "user",
           };
         }
       }
       if (!credentials) credentials = await getSpotifyAppCredentialsForUser(bubble_user_id, { allowFallback: true });
       if (!credentials?.client_id || !credentials?.client_secret || !credentials?.redirect_uri) {
         return backWithError(return_to, "missing_spotify_app_credentials");
       }
   
       // Token-Exchange
       const tokenResRaw = await fetch("https://accounts.spotify.com/api/token", {
         method: "POST",
         headers: {
           "Content-Type": "application/x-www-form-urlencoded",
           Authorization: "Basic " + Buffer.from(`${credentials.client_id}:${credentials.client_secret}`).toString("base64"),
         },
         body: new URLSearchParams({
           grant_type: "authorization_code",
           code,
           redirect_uri: credentials.redirect_uri,
         }),
       });
   
       const tokenRes = await tokenResRaw.json().catch(() => ({}));
       if (!tokenRes || !tokenRes.access_token) {
         console.error("oauth/spotify/callback: token exchange failed", {
           status: tokenResRaw.status,
           body: tokenRes
         });
         return backWithError(return_to, "token_exchange_failed");
       }
   
       // /me holen
       const meResp = await fetch("https://api.spotify.com/v1/me", {
         headers: { Authorization: `Bearer ${tokenRes.access_token}` },
       });
       if (!meResp.ok) {
         const t = await meResp.text().catch(() => "");
         console.error("oauth/spotify/callback: GET /v1/me failed", { status: meResp.status, body: t.slice(0,1000) });
         return backWithError(return_to, `spotify_me_failed_${meResp.status}`);
       }
       const me = await meResp.json();
       const spotify_user_id = me.id;
       const display_name    = me.display_name || label || "";
       const avatar_url      = (me.images && me.images[0]?.url) || null;

       const activeOwner = await findActiveSpotifyOwner(spotify_user_id, bubble_user_id);
       if (activeOwner) return backWithError(return_to, "spotify_account_already_connected");
   
       // app_user idempotent anlegen
       await fetch(`${SB_URL}/rest/v1/app_users?on_conflict=bubble_user_id`, {
         method: "POST",
         headers: {
           apikey: SB_KEY,
           Authorization: `Bearer ${SB_KEY}`,
           "Content-Type": "application/json",
           Prefer: "resolution=ignore-duplicates,return=minimal",
         },
         body: JSON.stringify({ bubble_user_id }),
       }).catch(() => {});
   
       // Seats/Sub-Gate (nicht blockend falls DB-Reads fehlschlagen)
       let seats_limit = 1;
       let seats_used  = 0;
       let sub_status  = "active";
       let sub_expires = null;
       try {
         const uR = await sb(
           `/rest/v1/app_users?select=seats_limit,seats_used,subscription_status,subscription_expires_at` +
           `&limit=1&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}`
         );
         const u = uR.ok ? (await uR.json())?.[0] : null;
         if (u) {
           if (Number.isFinite(Number(u.seats_limit))) seats_limit = Number(u.seats_limit);
           if (Number.isFinite(Number(u.seats_used)))  seats_used  = Number(u.seats_used);
           sub_status  = String(u.subscription_status || "active");
           sub_expires = u.subscription_expires_at || null;
         }
         if (!Number.isFinite(seats_used)) {
           const cR = await sb(
             `/rest/v1/spotify_connections?select=id` +
             `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
             `&is_active=is.true`
           );
           const arr = cR.ok ? await cR.json() : [];
           seats_used = Array.isArray(arr) ? arr.length : 0;
         }
       } catch (e) {
         console.error("oauth/spotify/callback: seats/sub fetch failed", { error: String(e) });
       }
   
       const billing = await getBillingState(bubble_user_id).catch(() => null);
       const subActive = billing ? billing.is_active : (sub_status !== "canceled" && (!sub_expires || new Date(sub_expires) > new Date()));
       if (!subActive) return backWithError(return_to, "subscription_required");
       if (seats_used >= seats_limit) return backWithError(return_to, "seat_limit_reached");
   
       // Vorhandene Verbindung suchen
       const existing = await fetch(
         `${SB_URL}/rest/v1/spotify_connections?` +
           `select=id,refresh_token_enc,cron_bucket,is_active,disabled_at,disconnected_at,created_at&` +
           `bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}&` +
           `spotify_user_id=eq.${encodeURIComponent(spotify_user_id)}&` +
           `order=created_at.desc&limit=1`,
         { headers: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}` } }
       )
         .then((r) => r.json())
         .then((a) => (Array.isArray(a) && a[0] ? a[0] : null))
         .catch((e) => {
           console.error("oauth/spotify/callback: existing lookup failed", { error: String(e) });
           return null;
         });
   
       // Tokens verschlüsseln
       let refresh_token_enc = null;
       if (tokenRes.refresh_token) {
         refresh_token_enc = encToken(tokenRes.refresh_token);
       } else if (existing?.refresh_token_enc) {
         // Reuse bei Re-Consent gleicher Spotify-User
         refresh_token_enc = existing.refresh_token_enc;
       } else {
         // Kein Refresh-Token – Consent fehlt
         return backWithError(return_to, "no_refresh_token_consent_required");
       }
   
       const access_token_enc  = encToken(tokenRes.access_token);
       const access_expires_at = new Date(Date.now() + (tokenRes.expires_in || 3600) * 1000).toISOString();
   
       // stabiler Cron-Bucket
       const cron_bucket = Number.isInteger(existing?.cron_bucket)
         ? existing.cron_bucket
         : Math.floor(Math.random() * 60);
   
       const payload = {
         bubble_user_id,
         spotify_user_id,
         display_name,
         avatar_url,
         scope: "playlist-read-private playlist-modify-private playlist-modify-public",
         refresh_token_enc,
         access_token_enc,
         access_expires_at,
         cron_bucket,
         credential_id: credentials.id || null,
       };
   
       // Upsert
       if (existing) {
         const up = await fetch(
           `${SB_URL}/rest/v1/spotify_connections?id=eq.${encodeURIComponent(existing.id)}`,
           {
             method: "PATCH",
             headers: {
               apikey: SB_KEY,
               Authorization: `Bearer ${SB_KEY}`,
               "Content-Type": "application/json",
               Prefer: "return=representation",
             },
             body: JSON.stringify({
               ...payload,
               is_active: true,
               disabled_at: null,
               disconnected_at: null,
               updated_at: new Date().toISOString(),
             }),
           }
         );
         if (!up.ok) {
           const errTxt = (await up.text().catch(() => "")) || "";
           console.error("oauth/spotify/callback: spotify_connections PATCH failed", {
             status: up.status,
             body: errTxt.slice(0, 1000)
           });
           const msg = `supabase_patch_failed_${up.status}:${encodeURIComponent(errTxt.slice(0, 280))}`;
           return backWithError(return_to, msg);
         }
   
         // Sicherheits-Reenable falls Dubletten
         await sb(
           `/rest/v1/spotify_connections?bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
           `&spotify_user_id=eq.${encodeURIComponent(spotify_user_id)}`,
           {
             method: "PATCH",
             headers: { Prefer: "return=minimal" },
             body: JSON.stringify({
               is_active: true,
               disabled_at: null,
               disconnected_at: null,
               updated_at: new Date().toISOString()
             })
           }
         ).catch((e) => {
           console.error("oauth/spotify/callback: re-enable duplicates failed", { error: String(e) });
         });
       } else {
         // INSERT mit on_conflict (merge-duplicates)
         const ins = await fetch(
           `${SB_URL}/rest/v1/spotify_connections?on_conflict=bubble_user_id,spotify_user_id`,
           {
             method: "POST",
             headers: {
               apikey: SB_KEY,
               Authorization: `Bearer ${SB_KEY}`,
               "Content-Type": "application/json",
               Prefer: "resolution=merge-duplicates,return=representation",
             },
             body: JSON.stringify({
               ...payload,
               is_active: true,
               disabled_at: null,
               disconnected_at: null,
               created_at: new Date().toISOString(),
               updated_at: new Date().toISOString(),
             }),
           }
         );
   
         if (!ins.ok) {
           const errTxt = (await ins.text().catch(() => "")) || "";
           console.error("oauth/spotify/callback: spotify_connections INSERT failed", {
             status: ins.status,
             body: errTxt.slice(0, 1000)
           });
           const msg = `supabase_insert_failed_${ins.status}:${encodeURIComponent(errTxt.slice(0, 280))}`;
           return backWithError(return_to, msg);
         }
       }
   
       // Verifizieren
       try {
         const vr = await fetch(
           `${SB_URL}/rest/v1/spotify_connections?` +
             `select=id,is_active,disabled_at,disconnected_at&limit=1&` +
             `bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}&` +
             `spotify_user_id=eq.${encodeURIComponent(spotify_user_id)}`,
           { headers: { apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}` } }
         );
         const vj = vr.ok ? await vr.json() : [];
         if (!vj?.[0]?.is_active) {
           console.error("oauth/spotify/callback: verify is_active failed", { got: vj });
           return backWithError(return_to, "is_active_update_failed");
         }
       } catch (e) {
         console.error("oauth/spotify/callback: verify fetch failed", { error: String(e) });
         // nicht blockend
       }
   
       // seats_used refreshen
       try {
         const cR = await sb(
           `/rest/v1/spotify_connections?select=id&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}&is_active=is.true`
         );
         const arr  = cR.ok ? await cR.json() : [];
         const used = Array.isArray(arr) ? arr.length : 0;
   
         await sb(`/rest/v1/app_users?bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}`, {
           method: "PATCH",
           headers: { Prefer: "return=minimal" },
           body: JSON.stringify({ seats_used: used, updated_at: new Date().toISOString() })
         }).catch((e) => {
           console.error("oauth/spotify/callback: seats_used patch failed", { error: String(e) });
         });
       } catch (e) {
         console.error("oauth/spotify/callback: seats_used refresh failed", { error: String(e) });
       }
   
       // zurück ins UI
       const qs   = `?spotify_linked=1&spotify_user=${encodeURIComponent(spotify_user_id)}`;
       const back = (return_to || "/") + qs;
       return res.redirect(back);
     } catch (e) {
       const msg = e?.message || String(e);
       console.error("oauth/spotify/callback: exception", { error: msg });
       return backWithError("/", `callback_exception_${encodeURIComponent(msg)}`);
     }
   },








   /* ---------- playlists/settings/save (POST, Bubble) ---------- */
   "playlists/settings/save": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     const bubbleUserId = await bubbleUserIdFromRequest(req);
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
     const cooldownUntil = await setPlaylistUpdateCooldown(playlist_id, 300);
   
     const patch = {
       auto_remove_enabled: enabled,
       auto_remove_weeks: weeks,
       next_check_at: cooldownUntil
     };
   
     const r = await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(playlist_id)}`, {
       method: "PATCH",
       headers: { Prefer: "return=representation" },
       body: JSON.stringify(patch),
     });
     if (!r.ok) return bad(res, 500, `supabase_patch_failed: ${await r.text()}`);
     const data = await r.json();

     return json(res, 200, { ok:true, playlist: Array.isArray(data) ? data[0] : data, cooldown_until: cooldownUntil });
   },
   


   /* ---------- cron/spotify/snapshot-daily (GET) ----------
      Snapshot der Followerzahlen für alle Playlists je aktiver Connection
      im angegebenen cron_bucket; schreibt in playlist_followers_daily (Upsert).
      Abhängigkeiten: need(), sb(), encToken(), decToken(), fetch, process.env.*
   -------------------------------------------------------- */
   "cron/spotify/snapshot-daily": async (req, res) => {
     try {
       // --- Env-Guards
       const assertEnv = (n) => need(n);
       assertEnv("SUPABASE_URL");
       assertEnv("SUPABASE_SERVICE_ROLE_KEY");
       assertEnv("ENC_SECRET");
       assertEnv("SPOTIFY_CLIENT_ID");
       assertEnv("SPOTIFY_CLIENT_SECRET");
   
       // --- Input
       const bucket = Number(req.query.bucket ?? "");
       if (!Number.isInteger(bucket) || bucket < 0 || bucket > 59) {
         return res.status(400).json({ ok:false, error:"invalid_bucket", hint:"use ?bucket=0..59" });
       }
   
       // --- Aktive Connections für den Bucket ziehen
       const conResp = await sb(
         `/rest/v1/spotify_connections?` +
         [
           `select=id,bubble_user_id,spotify_user_id,refresh_token_enc,access_token_enc,access_expires_at,cron_bucket,is_active,disabled_at`,
           `cron_bucket=eq.${encodeURIComponent(bucket)}`,
           `is_active=is.true`,
           `disabled_at=is.null`
         ].join("&")
       );
       if (!conResp.ok) {
         const t = await conResp.text().catch(()=> "");
         return res.status(502).json({ ok:false, error:"supabase_connections_failed", detail:t });
       }
       const connections = await conResp.json();
       if (!Array.isArray(connections) || connections.length === 0) {
         return res.json({ ok:true, bucket, processed:0, note:"no active connections in this bucket" });
       }
   
       // --- Helper: Token sicherstellen (refresh bei Bedarf)
       async function ensureAccessToken(conn) {
         const now = Date.now();
         const expMs = conn.access_expires_at ? new Date(conn.access_expires_at).getTime() : 0;
         const stillValid = expMs - now > 5 * 60 * 1000; // ≥5 Min Puffer
   
         if (stillValid && conn.access_token_enc) {
           try { return { token: decryptToken(conn.access_token_enc), refreshed:false }; }
           catch { /* fallthrough to refresh */ }
         }
         // Refresh
         if (!conn.refresh_token_enc) throw new Error("missing_refresh_token");
         const refresh_token = decryptToken(conn.refresh_token_enc);
         const credentials = await getSpotifyAppCredentialsForConnection(conn.id);
         const j = await refreshAccessToken(refresh_token, credentials);
         const newAccess = j.access_token;
         const newExpiresAt = new Date(Date.now() + (j.expires_in || 3600) * 1000).toISOString();
         const newAccessEnc = encToken(newAccess);
   
         // ggf. neues Refresh-Token von Spotify (selten) – dann persistieren
         const newRefreshEnc = j.refresh_token ? encToken(j.refresh_token) : conn.refresh_token_enc;
   
         // Connection updaten
         await sb(`/rest/v1/spotify_connections?id=eq.${encodeURIComponent(conn.id)}`, {
           method: "PATCH",
           headers: { Prefer: "return=minimal" },
           body: JSON.stringify({
             access_token_enc: newAccessEnc,
             access_expires_at: newExpiresAt,
             // nur ersetzen, wenn Spotify eins liefert:
             ...(j.refresh_token ? { refresh_token_enc: newRefreshEnc } : {}),
             updated_at: new Date().toISOString()
           })
         });
   
         return { token:newAccess, refreshed:true };
       }
   
       // --- Helper: Spotify /me/playlists paginiert lesen
       async function* iterateUserPlaylists(accessToken) {
         let url = "https://api.spotify.com/v1/me/playlists?limit=50";
         while (url) {
           const r = await fetch(url, { headers: { Authorization:`Bearer ${accessToken}` } });
           if (!r.ok) throw new Error(`spotify_me_playlists_${r.status}`);
           const j = await r.json();
           const items = Array.isArray(j.items) ? j.items : [];
           for (const p of items) yield p;
           url = j.next || null;
         }
       }
   
       // --- Helper: lokale Playlist-Zeile sichern/holen (UUID) für (connection_id + Spotify playlist_id)
       async function ensureLocalPlaylistRow(conn, spPlaylist, accessToken) {
         const spotify_playlist_id = spPlaylist.id;
         const name = spPlaylist.name || null;
   
         const resp = await scopedPlaylistUpsert([{
               connection_id: conn.id,
               bubble_user_id: conn.bubble_user_id,
               playlist_id: spotify_playlist_id,
               name,
               description: spPlaylist.description || null,
               image: spPlaylist.images?.[0]?.url || null,
               is_public: !!spPlaylist.public,
               tracks_total: spPlaylist.tracks?.total ?? 0,
               snapshot_id: spPlaylist.snapshot_id || null,
               updated_at: new Date().toISOString(),
             }]);
   
         if (!resp.ok) {
           const alt = await sb(
             `/rest/v1/playlists?select=id&connection_id=eq.${encodeURIComponent(conn.id)}&playlist_id=eq.${encodeURIComponent(spotify_playlist_id)}&limit=1`
           );
           if (!alt.ok) throw new Error(`ensureLocalPlaylistRow_failed_${resp.status}`);
           const jj = await alt.json();
           const row = Array.isArray(jj) && jj[0];
           if (!row?.id) throw new Error("playlist_row_missing");
           return row.id;
         } else {
           const jj = await resp.json().catch(()=> []);
           const row = Array.isArray(jj) && jj[0];
           if (!row?.id) {
             const alt = await sb(
               `/rest/v1/playlists?select=id&connection_id=eq.${encodeURIComponent(conn.id)}&playlist_id=eq.${encodeURIComponent(spotify_playlist_id)}&limit=1`
             );
             const a = alt.ok ? await alt.json() : [];
             if (!a?.[0]?.id) throw new Error("playlist_row_missing_after_upsert");
             return a[0].id;
           }
           return row.id;
         }
       }
   
       // --- Helper: Follower-Snapshot (UPSERT) schreiben
       async function upsertFollowersDaily(localPlaylistUUID, conn, followersInt) {
         const day = new Date().toISOString().slice(0,10); // YYYY-MM-DD
         const payload = {
           playlist_id: localPlaylistUUID,      // uuid in deiner Tabelle!
           bubble_user_id: conn.bubble_user_id, // text
           connection_id: conn.id,              // uuid, nullable – wir füllen sie
           day,
           followers: Number.isFinite(+followersInt) ? +followersInt : 0
         };
         const r = await fetch(`${process.env.SUPABASE_URL}/rest/v1/playlist_followers_daily`, {
           method: "POST",
           headers: {
             apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
             Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
             "Content-Type": "application/json",
             // funktioniert mit deinem Unique-Index (playlist_id, day)
             Prefer: "resolution=merge-duplicates,return=minimal",
           },
           body: JSON.stringify(payload)
         });
         if (!r.ok) {
           const t = await r.text().catch(()=> "");
           throw new Error(`followers_upsert_failed_${r.status}:${t.slice(0,200)}`);
         }
       }
   
       // --- Verarbeitung
       const results = [];
       for (const conn of connections) {
         const out = { connection_id: conn.id, bubble_user_id: conn.bubble_user_id, refreshed:false, playlists:0, snapshots:0, errors:[] };
         try {
           // Token sichern
           const { token, refreshed } = await ensureAccessToken(conn);
           out.refreshed = refreshed;
   
           // Eigene Playlists iterieren (du kannst hier filtern, z.B. nur owner==me)
           for await (const sp of iterateUserPlaylists(token)) {
             out.playlists += 1;
   
             // Followers.total zuverlässig holen (manche /me/playlists liefern es nicht konsistent → ggf. Detail-Call)
             let followers = sp.followers?.total;
             if (typeof followers !== "number") {
               const pr = await fetch(`https://api.spotify.com/v1/playlists/${encodeURIComponent(sp.id)}?fields=followers.total`, {
                 headers: { Authorization:`Bearer ${token}` }
               });
               if (pr.ok) {
                 const pj = await pr.json();
                 followers = pj?.followers?.total ?? 0;
               } else {
                 followers = 0;
               }
             }
   
             // Lokale Playlist-UUID sicherstellen
             let localUUID;
             try {
               localUUID = await ensureLocalPlaylistRow(conn, sp, token);
             } catch (e) {
               out.errors.push(`ensureLocalPlaylistRow:${sp.id}:${e.message}`);
               continue;
             }
   
             // followers_daily upserten
             try {
               await upsertFollowersDaily(localUUID, conn, followers);
               out.snapshots += 1;
             } catch (e) {
               out.errors.push(`upsert_daily:${sp.id}:${e.message}`);
             }
           }
         } catch (e) {
           out.errors.push(e.message || String(e));
         }
         results.push(out);
       }
   
       return res.json({ ok:true, bucket, processed: results.length, results });
     } catch (e) {
       return res.status(500).json({ ok:false, error:"snapshot_exception", message: e?.message || String(e) });
     }
   },





   
   /* ---------- playlists/maintenance (POST, Bubble ODER Cron) ---------- */
   "playlists/maintenance": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
   
     const body = await readBody(req);
     const { playlist_id } = body;
     if (!playlist_id) return bad(res, 400, "missing_playlist_id");
   
     // Entweder Bubble-User prüft Ownership ODER interner Secret-Call:
     const bubbleUserId = await bubbleUserIdFromRequest(req);
     const isInternal = checkAppSecret(req) || checkCronAuth(req);
   
     if (!isInternal) {
       if (!bubbleUserId) return bad(res, 401, "Missing X-Bubble-User-Id");
       const own = await sb(`/rest/v1/playlists?select=id&limit=1&id=eq.${encodeURIComponent(String(playlist_id))}&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`).then(r=>r.json());
       if (!own?.[0]) return bad(res, 403, "Playlist not owned by user");
     } else {
       const cdRows = await sb(`/rest/v1/playlists?select=next_check_at&limit=1&id=eq.${encodeURIComponent(String(playlist_id))}`).then(r => r.json()).catch(() => []);
       const cooldownUntil = cdRows?.[0]?.next_check_at ? new Date(cdRows[0].next_check_at) : null;
       if (cooldownUntil && cooldownUntil > new Date()) {
         return json(res, 200, { ok: true, skipped: true, reason: "playlist_cooldown", until: cooldownUntil.toISOString() });
       }
     }
   
     const r = await sb(`/rest/v1/rpc/playlist_maintenance`, {
       method: "POST",
       body: JSON.stringify({ p_playlist_id: playlist_id })
     });
     const t = await r.text();
     if (!r.ok) return bad(res, 500, `rpc_playlist_maintenance_failed: ${t}`);
   
     const out = t ? JSON.parse(t) : [{ removed:0, total_after:0 }];
     const cooldownUntil = !isInternal ? await setPlaylistUpdateCooldown(playlist_id, 300) : null;
     return json(res, 200, { ok:true, result: out[0] || out, ...(cooldownUntil ? { cooldown_until: cooldownUntil } : {}) });
   },

  /* ---------- playlist-items/list (GET) ---------- */
  "playlist-items/list": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
    if (!SUPABASE_URL || !SRK) return bad(res, 500, "missing_env");

    const playlist_row_id = req.query.playlist_row_id;
    if (!playlist_row_id) return bad(res, 400, "missing_playlist_row_id");
    const bubbleUserId = await bubbleUserIdFromRequest(req);
    if (!bubbleUserId) return bad(res, 401, "not_authenticated");

    const owner = await sb(
      `/rest/v1/playlists?select=id&limit=1` +
      `&id=eq.${encodeURIComponent(playlist_row_id)}` +
      `&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`
    );
    const ownerRows = owner.ok ? await owner.json().catch(() => []) : [];
    if (!ownerRows?.[0]) return bad(res, 403, "playlist_not_owned");

    const path =
       `/rest/v1/playlist_items_ui` +
       `?select=playlist_id,position,track_id,track_name,artist_names,album_name,` +
       `duration_ms,duration_formatted,added_at,age_days,age_label,track_uri,` +
       `popularity,preview_url,cover_url,is_locked,locked_position,locked_at,expiry_weeks` +
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
   
     const bubble_user_id = await bubbleUserIdFromRequest(req, req.query.bubble_user_id);
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
       `&order=followers.desc.nullslast,name.asc`;
   
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



  /* ---------- playlists/refresh-followers (POST, secret) ----------
          Body: { connection_id: uuid }
          Query (optional):
            stale_hours=23
            max=600
            concurrency=3      // wir nutzen sie intern moderat (2-4)
            batch=100
            only_playlist_id=<uuid>  // Single-Playlist Test
         */
   "playlists/refresh-followers": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     if (process.env.APP_WEBHOOK_SECRET) {
       const got = req.headers["x-app-secret"];
       if (got !== process.env.APP_WEBHOOK_SECRET) return bad(res, 401, "unauthorized");
     }
   
     try {
       const body = await readBody(req);
       const connection_id = body.connection_id;
       if (!connection_id) return bad(res, 400, "missing_connection_id");
   
       const staleHours = Math.max(1, Number(req.query.stale_hours || "23"));
       const maxTotal   = Math.max(1, Number(req.query.max || "600"));
       const perWrite   = Math.max(10, Number(req.query.batch || "100"));
       const onlyPid    = req.query.only_playlist_id ? String(req.query.only_playlist_id) : null;
   
       // 1) Connection holen (für Token, Ownership etc.)
       const connR = await sb(`/rest/v1/spotify_connections?select=id,bubble_user_id,spotify_user_id,is_active&limit=1&id=eq.${encodeURIComponent(connection_id)}`);
       if (!connR.ok) return bad(res, 500, `supabase_select_connection_failed: ${await connR.text()}`);
       const conn = (await connR.json())?.[0];
       if (!conn) return bad(res, 404, "connection_not_found");
       if (conn.is_active === false) return json(res, 200, { ok:true, skipped:true, reason:"connection_inactive" });
   
       // 2) Kandidaten-Playlists bestimmen (stale window)
       let playlistsToUpdate = [];
       if (onlyPid) {
         const oneR = await sb(
           `/rest/v1/playlists?select=id,playlist_id,bubble_user_id,is_owner,is_public,followers,followers_checked_at` +
           `&limit=1&id=eq.${encodeURIComponent(onlyPid)}`
         );
         if (!oneR.ok) return bad(res, 500, `supabase_select_one_failed: ${await oneR.text()}`);
         const one = (await oneR.json())?.[0];
         if (!one || !one.is_owner || !one.is_public) {
           return bad(res, 404, "playlist_not_found_or_not_allowed");
         }
         playlistsToUpdate = [one];
       } else {
         const sinceIso = new Date(Date.now() - staleHours * 3600 * 1000).toISOString();
         const order = encodeURIComponent("followers_checked_at.asc.nullsfirst");
         const selPath =
           `/rest/v1/playlists?select=id,playlist_id,bubble_user_id,is_owner,is_public,followers,followers_checked_at` +
           `&connection_id=eq.${encodeURIComponent(connection_id)}` +
           `&is_owner=is.true&is_public=is.true` +
           `&or=(followers.is.null,followers_checked_at.lt.${encodeURIComponent(sinceIso)})` +
           `&order=${order}&limit=${encodeURIComponent(maxTotal)}`;
         const selR = await sb(selPath);
         if (!selR.ok) return bad(res, 500, `supabase_select_failed: ${await selR.text()}`);
         playlistsToUpdate = await selR.json();
       }
   
       // 2b) SAFETY: Heute-Row garantieren → alle Owned/Public ziehen & fehlende „heute“-Rows ergänzen
       const today  = new Date().toISOString().slice(0,10); // UTC YYYY-MM-DD
       const allR = await sb(
         `/rest/v1/playlists?select=id,playlist_id,bubble_user_id,followers` +
         `&connection_id=eq.${encodeURIComponent(connection_id)}` +
         `&is_owner=is.true&is_public=is.true`
       );
       const allOwned = allR.ok ? await allR.json() : [];
       if (allOwned.length) {
         const inList = `(${allOwned.map(p => p.id).join(",")})`; // UUIDs ohne Quotes ok
         const dR = await sb(
           `/rest/v1/playlist_followers_daily?select=playlist_id` +
           `&playlist_id=in.${encodeURIComponent(inList)}` +
           `&day=eq.${encodeURIComponent(today)}`
         );
         const haveToday = new Set((dR.ok ? await dR.json() : []).map(r => r.playlist_id));
         const seen = new Set(playlistsToUpdate.map(p => p.id));
         for (const p of allOwned) {
           if (!haveToday.has(p.id) && !seen.has(p.id)) {
             playlistsToUpdate.push(p); // heute noch keine Row → heute zwingend versuchen
             seen.add(p.id);
           }
         }
       }
   
       if (!Array.isArray(playlistsToUpdate) || playlistsToUpdate.length === 0) {
         // Nichts zu tun, aber evtl. gab es bereits Today-Rows; melden wir sauber zurück.
         return json(res, 200, { ok:true, attempted:0, updated:0, daily_upserts:0, fallback_upserts:0, reason:"up_to_date" });
       }
   
       // 3) Spotify Token
       const access_token = await getAccessTokenFromConnection(connection_id);
   
       // 4) Pro Playlist frischen Wert holen (sequentiell + Backoff, robust)
       const nowIso = new Date().toISOString();
       const freshResults = []; // { row, followers }
   
       for (const row of playlistsToUpdate) {
         const id = row.playlist_id;
         let followers = null, ok = false, attempt = 0;
   
         while (attempt < 8) {
           const r = await fetch(
             `https://api.spotify.com/v1/playlists/${encodeURIComponent(id)}?fields=followers(total)`,
             { headers: { Authorization: `Bearer ${access_token}` } }
           );
           if (r.status === 429) {
             const ra = Number(r.headers.get("retry-after") || "1");
             const wait = Math.min(60, Math.max(1, ra) * Math.pow(2, attempt)) + Math.random()*0.5;
             await sleep(wait * 1000);
             attempt++;
             continue;
           }
           const { json, text } = await parseJsonSafe(r);
           if (!r.ok) {
             // WICHTIG: Bei Fehlern NICHT followers_checked_at hochzählen, damit sie bald erneut versucht wird
             await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(row.id)}`, {
               method: "PATCH",
               headers: { Prefer: "return=minimal" },
               body: JSON.stringify({ updated_at: nowIso })
             }).catch(()=>{});
             break;
           }
           followers = json?.followers?.total ?? null;
           ok = typeof followers === "number";
           break;
         }
   
         if (ok) {
           console.log("followers:fresh", {
             playlist_row_id: row.id,
             spotify_playlist_id: row.playlist_id,
             followers
           });
   
           // Erfolgreich → playlists patchen (SOURCE OF TRUTH im UI)
           const patch = await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(row.id)}`, {
             method: "PATCH",
             headers: { Prefer: "return=minimal" },
             body: JSON.stringify({
               followers,
               followers_checked_at: nowIso,
               updated_at: nowIso
             })
           });
           if (!patch.ok) return bad(res, 500, `supabase playlists patch failed: ${await patch.text()}`);
   
           freshResults.push({ row, followers });
         }
   
         // kleiner Jitter
         await sleep(40);
       }
   
       // 5) Daily upserten – direkt die frisch geholten Spotify-Werte verwenden
       let dailyUpserts = 0;
       if (freshResults.length > 0) {
         const dailyRows = freshResults.map(fr => ({
           playlist_id: fr.row.id,
           bubble_user_id: fr.row.bubble_user_id || null,
           day: today,
           followers: Number(fr.followers || 0)
         }));
   
         for (let i = 0; i < dailyRows.length; i += perWrite) {
           const chunk = dailyRows.slice(i, i + perWrite);
           const up = await sb(`/rest/v1/playlist_followers_daily?on_conflict=playlist_id,day`, {
             method: "POST",
             headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
             body: JSON.stringify(chunk)
           });
           if (!up.ok) return bad(res, 500, `supabase daily upsert failed: ${await up.text()}`);
           dailyUpserts += chunk.length;
           await sleep(20);
         }
       }
   
       // 6) SAFETY NET: Falls es Playlists ohne „heute“-Row gibt (und kein frischer Wert),
       // schreibe einen Today-Row mit dem aktuell bekannten playlists.followers.
       let fallbackUpserts = 0;
       if (allOwned.length) {
         // Neu laden, welche heute bereits existieren (inkl. gerade frisch upserteter)
         const inList2 = `(${allOwned.map(p => p.id).join(",")})`;
         const dR2 = await sb(
           `/rest/v1/playlist_followers_daily?select=playlist_id` +
           `&playlist_id=in.${encodeURIComponent(inList2)}` +
           `&day=eq.${encodeURIComponent(today)}`
         );
         const haveTodayNow = new Set((dR2.ok ? await dR2.json() : []).map(r => r.playlist_id));
         const dailyFallbackRows = [];
         const freshSet = new Set(freshResults.map(fr => fr.row.id));
   
         for (const p of allOwned) {
           if (!haveTodayNow.has(p.id)) {
             // Noch kein Today-Row → Fallback mit letztem bekannten Stand
             dailyFallbackRows.push({
               playlist_id: p.id,
               bubble_user_id: p.bubble_user_id || null,
               day: today,
               followers: Number(p.followers ?? 0)
             });
           }
         }
   
         if (dailyFallbackRows.length) {
           for (let i = 0; i < dailyFallbackRows.length; i += perWrite) {
             const chunk = dailyFallbackRows.slice(i, i + perWrite);
             const up = await sb(`/rest/v1/playlist_followers_daily?on_conflict=playlist_id,day`, {
               method: "POST",
               headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
               body: JSON.stringify(chunk)
             });
             if (!up.ok) return bad(res, 500, `supabase daily fallback upsert failed: ${await up.text()}`);
             fallbackUpserts += chunk.length;
             await sleep(20);
           }
         }
       }
   
       return json(res, 200, {
         ok: true,
         attempted: playlistsToUpdate.length,
         updated: freshResults.length,
         daily_upserts: dailyUpserts,
         fallback_upserts: fallbackUpserts
       });
     } catch (e) {
       return bad(res, 500, `refresh_followers_exception: ${e?.message || e}`);
     }
   },









  /* ---------- playlists/sync-items (POST, secret) ---------- */
   "playlists/sync-items": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     const isInternal = hasValidAppSecret(req);
   
     const bodyRaw = await readBody(req);
     let { playlist_row_id, spotify_playlist_id, connection_id } = bodyRaw;
   
     const timeLabel = `sync-items:${playlist_row_id || spotify_playlist_id || "unknown"}`;
     console.time(timeLabel);
     console.log("sync-items:start", {
       by: playlist_row_id ? "row_id" : (spotify_playlist_id ? "spotify_id" : "missing"),
       playlist_row_id,
       spotify_playlist_id,
       ts: new Date().toISOString(),
       vercel_url: process.env.VERCEL_URL || null,
     });
   
     const chunk = (arr, n) => { const out=[]; for (let i=0;i<arr.length;i+=n) out.push(arr.slice(i,i+n)); return out; };
   
     try {
       if (!playlist_row_id && !spotify_playlist_id) {
         console.timeEnd(timeLabel);
         return bad(res, 400, "missing_playlist_identifier");
       }
   
       // Falls nur Spotify-ID kam → Row-ID auflösen
       if (!playlist_row_id && spotify_playlist_id) {
         console.log("sync-items:resolve_row_id_from_spotify_id", { spotify_playlist_id });
         const requesterBubbleUserId = !isInternal ? await bubbleUserIdFromRequest(req) : "";
         const scopedFilters = [
           `playlist_id=eq.${encodeURIComponent(spotify_playlist_id)}`,
           connection_id ? `connection_id=eq.${encodeURIComponent(connection_id)}` : "",
           requesterBubbleUserId ? `bubble_user_id=eq.${encodeURIComponent(requesterBubbleUserId)}` : "",
         ].filter(Boolean).join("&");
         const r = await sb(`/rest/v1/playlists?select=id,playlist_id,connection_id,bubble_user_id,auto_remove_enabled,auto_remove_weeks,next_check_at&limit=1&${scopedFilters}`);
         if (!r.ok) { console.timeEnd(timeLabel); return bad(res, 500, `supabase_select_failed: ${await r.text()}`); }
         const arr = await r.json();
         if (!arr[0]) { console.timeEnd(timeLabel); return bad(res, 404, "playlist_not_found_by_spotify_id"); }
         playlist_row_id = arr[0].id;
         console.log("sync-items:resolved_row_id", { playlist_row_id });
       }
   
       // Playlist-Metadaten (+Settings)
       const pr = await sb(`/rest/v1/playlists?select=id,playlist_id,connection_id,bubble_user_id,auto_remove_enabled,auto_remove_weeks,next_check_at&limit=1&id=eq.${encodeURIComponent(playlist_row_id)}`);
       if (!pr.ok) { console.timeEnd(timeLabel); return bad(res, 500, `supabase select playlist failed: ${await pr.text()}`); }
       const p = (await pr.json())[0];
       if (!p) { console.timeEnd(timeLabel); return bad(res, 404, "playlist_not_found"); }
       if (!isInternal) {
         const bubbleUserId = await bubbleUserIdFromRequest(req);
         if (!bubbleUserId) { console.timeEnd(timeLabel); return bad(res, 401, "not_authenticated"); }
         if (p.bubble_user_id !== bubbleUserId) { console.timeEnd(timeLabel); return bad(res, 403, "playlist_not_owned"); }
       }
       console.log("sync-items:playlist_meta", {
         playlist_row_id: p.id,
         spotify_playlist_id: p.playlist_id,
         connection_id: p.connection_id,
         bubble_user_id: p.bubble_user_id,
         auto_remove_enabled: !!p.auto_remove_enabled,
         auto_remove_weeks: p.auto_remove_weeks,
       });
   
       // --- USER MASTER SWITCHES / SUBSCRIPTION GATE ---
       const ufR = await sb(`/rest/v1/app_users?select=sync_paused,auto_remove_enabled,position_lock_enabled,subscription_status,subscription_expires_at&limit=1&bubble_user_id=eq.${encodeURIComponent(p.bubble_user_id)}`);
       const uf = (await ufR.json())[0] || {};
       const subActive = !uf.subscription_expires_at || new Date(uf.subscription_expires_at) > new Date();
       const subOk = (uf.subscription_status || "active") !== "canceled" && subActive;
   
       if (uf.sync_paused || !subOk) {
         await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
           method: "PATCH", headers: { Prefer: "return=minimal" },
           body: JSON.stringify({ sync_started_at: null, needs_sync: true })
         }).catch(()=>{});
         console.timeEnd(timeLabel);
         return json(res, 202, { ok:true, paused:true, reason: uf.sync_paused ? "user_paused" : "subscription_inactive" });
       }
   
       const playlistCooldownUntil = p.next_check_at ? new Date(p.next_check_at) : null;
       const playlistOnCooldown = playlistCooldownUntil && playlistCooldownUntil > new Date();
       const USER_ALLOW_AUTO  = !playlistOnCooldown && uf.auto_remove_enabled !== false;     // default true
       const USER_ALLOW_LOCKS = !playlistOnCooldown && uf.position_lock_enabled !== false;   // default true
       if (playlistOnCooldown) {
         console.log("sync-items:automation_skipped_playlist_cooldown", {
           playlist_row_id: p.id,
           next_check_at: p.next_check_at
         });
       }
   
       // Reentrancy-Guard (Claim)
       const claim = await fetch(
         `${process.env.SUPABASE_URL}/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}&sync_started_at=is.null`,
         {
           method: "PATCH",
           headers: {
             apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
             Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
             "Content-Type": "application/json",
             Prefer: "return=representation",
           },
           body: JSON.stringify({ sync_started_at: new Date().toISOString() }),
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
       const credentials = await getSpotifyAppCredentialsForConnection(conn.id);
       const tokenRef = await refreshAccessToken(refresh_token, credentials);
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
   
       // Locks laden (inkl. expiry_weeks für per-Song Expiry)
       const locksR = await sb(`/rest/v1/playlist_item_locks?select=track_id,is_locked,locked_position,expiry_weeks&playlist_id=eq.${encodeURIComponent(p.id)}`);
       const locksArr = locksR.ok ? await locksR.json() : [];
       const lockedSet = new Set(locksArr.filter(x => x.is_locked).map(x => x.track_id));
       // Map für per-Song Expiry: track_id -> expiry_weeks (nur wenn gesetzt)
       const expiryWeeksMap = new Map();
       for (const lock of locksArr) {
         if (lock.track_id && lock.expiry_weeks !== null && lock.expiry_weeks !== undefined && Number(lock.expiry_weeks) > 0) {
           expiryWeeksMap.set(lock.track_id, Number(lock.expiry_weeks));
         }
       }
   
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
             const ra = Number(r.headers.get("retry-after") || "1");
             const base = Math.max(ra, 1);
             const waitSec = Math.min(60, base * Math.pow(2, attempt)) + (Math.random() * 0.8);
             console.warn("sync-items:429", { page: pageCount, attempt, retry_after_s: ra, wait_s: waitSec.toFixed(1) });
   
             if (attempt++ >= MAX_429_RETRIES_PER_PAGE) {
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
           break;
         }
       }
   
       console.log("sync-items:spotify_fetched", { total_items: items.length });
   
       /* === (Backup) Zustands-Snapshot speichern – vor Expiry/Locks/Reorder === */
       try {
         let meta = null;
         try {
           const mr = await fetch(
             `https://api.spotify.com/v1/playlists/${encodeURIComponent(p.playlist_id)}?fields=name,description,images,snapshot_id,followers(total),tracks(total)`,
             { headers: { Authorization: `Bearer ${access_token}` } }
           );
           meta = await mr.json().catch(() => ({}));
         } catch {/* ignore */}
   
         const backupSnapshot = (meta && meta.snapshot_id) || snapshot_id || null;
         if (backupSnapshot) {
           const lastBackupR = await sb(
             `/rest/v1/playlist_backups?select=id` +
             `&playlist_id=eq.${encodeURIComponent(p.id)}` +
             `&snapshot_id=eq.${encodeURIComponent(backupSnapshot)}` +
             `&limit=1`
           ).catch(() => null);
           const lastBackups = lastBackupR?.ok ? await lastBackupR.json().catch(() => []) : [];
           const alreadyBackedUp = Array.isArray(lastBackups) && lastBackups.length > 0;
           if (alreadyBackedUp) throw new Error("backup_skipped_duplicate_snapshot");
         }

         const tracksForBackupBase = items.map((it, i) => {
           const t = it?.track || {};
           const album = t?.album || {};
           const artists = Array.isArray(t?.artists) ? t.artists : [];
           return {
             position: i,
             track_id: t.id || null,
             track_uri: t.uri || null,
             track_name: t.name || null,
             artist_names: artists.map(a => a?.name).filter(Boolean).join(", "),
             album_name: album?.name || null,
             added_at: it?.added_at || null
           };
         });
         const tracksForBackup = await enrichBackupTracksWithAutomationState(p.id, tracksForBackupBase);
   
         const backupPayload = {
             playlist_id: p.id,
             spotify_playlist_id: p.playlist_id,
             snapshot_id: backupSnapshot,
             taken_at: new Date().toISOString(),
             name: meta?.name || null,
             description: meta?.description || null,
             image: (meta?.images && meta.images[0]?.url) || null,
             followers: (meta?.followers && meta.followers.total) ?? null,
             tracks_total: items.length,
             tracks: tracksForBackup,
             bubble_user_id: p.bubble_user_id,
             reason: "sync"
           };
         let backupInsert = await sb(`/rest/v1/playlist_backups`, {
           method: "POST",
           headers: { Prefer: "return=minimal" },
           body: JSON.stringify([backupPayload])
         });
         if (!backupInsert.ok) {
           const text = await backupInsert.text();
           if (text.includes("reason")) {
             const { reason: _reason, ...fallbackPayload } = backupPayload;
             backupInsert = await sb(`/rest/v1/playlist_backups`, {
               method: "POST",
               headers: { Prefer: "return=minimal" },
               body: JSON.stringify([fallbackPayload])
             });
           } else {
             console.warn("backup_insert_failed", text);
           }
         }
       } catch (e) {
         if (String(e?.message || e) !== "backup_skipped_duplicate_snapshot") {
           console.warn("backup_block_failed", e?.message || e);
         }
       }
   
       /* === (A) Expiry: alte, UNGElOCKTE Items löschen (positionsgenau) === */
       let removedPositionsSet = new Set();
       if (USER_ALLOW_AUTO && p.auto_remove_enabled && Number(p.auto_remove_weeks) > 0) {
         const masterExpiryWeeks = Number(p.auto_remove_weeks);
         const masterCutoffMs = Date.now() - masterExpiryWeeks * 7 * 24 * 3600 * 1000;
         const toRemoveMap = new Map(); // uri -> positions[]
   
         for (let i = 0; i < items.length; i++) {
           const it = items[i] || {};
           const t = it.track || {};
           if (!t?.id || !t?.uri) continue;
           if (lockedSet.has(t.id)) continue; // gelockte nie löschen
           const addedAt = it.added_at ? Date.parse(it.added_at) : NaN;
           if (!Number.isFinite(addedAt)) continue;
           
           // Prüfe per-Song Expiry (falls vorhanden), sonst Master Expiry
           const songExpiryWeeks = expiryWeeksMap.get(t.id);
           let cutoffMs = masterCutoffMs;
           if (songExpiryWeeks && songExpiryWeeks > 0) {
             // Per-Song Expiry: kann länger sein als Master Expiry
             cutoffMs = Date.now() - songExpiryWeeks * 7 * 24 * 3600 * 1000;
           }
           
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
                 await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
                   method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ sync_started_at: null })
                 }).catch(()=>{});
                 console.timeEnd(timeLabel);
                 return bad(res, del.r.status, `spotify delete failed: ${del.r.status} ${del.text || ""}`);
               }
               snapshot_id = del.json?.snapshot_id || snapshot_id;
               break;
             }
             await sleep(80);
           }
   
           // lokales Array kompaktieren
           const keep = [];
           for (let i = 0; i < items.length; i++) {
             if (!removedPositionsSet.has(i)) keep.push(items[i]);
           }
           items.length = 0;
           items.push(...keep);
         }
       }
   
       /* === (B) Locks enforce (Reorder) === */
       if (USER_ALLOW_LOCKS && locksArr.some(x => x.is_locked) && snapshot_id) {
        let order = items
          .map(it => it?.track ? { id: it.track.id, uri: it.track.uri } : null)
          .filter(Boolean);
   
        const localMove = (arr, from, to) => { if (from===to) return; const el = arr.splice(from,1)[0]; arr.splice(to,0,el); };
   
        const desiredLocks = locksArr
          .filter(l => l.is_locked && Number.isFinite(Number(l.locked_position)))
          .sort((a,b) => Number(a.locked_position) - Number(b.locked_position));

        const lockedByPosition = new Map();
        const lockedIds = new Set();
        for (const l of desiredLocks) {
          const current = order.find(x => x.id === l.track_id);
          if (!current) continue;
          const desired = Math.max(0, Math.min(order.length - 1, Number(l.locked_position)));
          if (lockedByPosition.has(desired)) continue;
          lockedByPosition.set(desired, current);
          lockedIds.add(l.track_id);
        }

        const floating = order.filter(x => !lockedIds.has(x.id));
        const targetOrder = [];
        let floatingIndex = 0;
        for (let i = 0; i < order.length; i++) {
          if (lockedByPosition.has(i)) {
            targetOrder.push(lockedByPosition.get(i));
          } else {
            const next = floating[floatingIndex++];
            if (next) targetOrder.push(next);
          }
        }
        while (floatingIndex < floating.length) targetOrder.push(floating[floatingIndex++]);

        for (let desired = 0; desired < targetOrder.length; desired++) {
          const target = targetOrder[desired];
          const cur = order.findIndex(x => x.id === target.id);
          if (cur < 0 || cur === desired) { await sleep(30); continue; }

          const insert_before = desired > cur ? desired + 1 : desired;
   
          let attempt = 0;
          while (true) {
             const re = await fetchJSON(
               `https://api.spotify.com/v1/playlists/${encodeURIComponent(p.playlist_id)}/tracks`,
               {
                 method: "PUT",
                 headers: { Authorization: `Bearer ${access_token}`, "Content-Type": "application/json" },
                 body: JSON.stringify({ range_start: cur, insert_before, range_length: 1, snapshot_id })
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
             localMove(order, cur, desired);
             snapshot_id = re.json?.snapshot_id || snapshot_id;
             break;
           }
   
           await sleep(60);
         }
   
         // items an neue Reihenfolge anpassen
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
           playlist_id: p.id,
           position: i, // 0-based
           track_id: t.id || null,
           track_name: t.name || null,
           track_uri: t.uri || null,
           artist_names: artists.map(a => a?.name).filter(Boolean).join(", "),
           album_name: album.name || null,
           duration_ms: Number.isFinite(t.duration_ms) ? t.duration_ms : null,
           popularity: Number.isFinite(t.popularity) ? t.popularity : null,
           preview_url: t.preview_url || null,
           cover_url: (album.images && album.images[0]?.url) || null,
           added_at: it.added_at || null,
         });
       }
       console.log("sync-items:mapped_rows", { rows: rows.length });
   
       /* === (D) UPSERT in Batches (robust) === */
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
               "Content-Type": "application/json",
             },
             body: JSON.stringify(b),
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
       const delUrl = `${process.env.SUPABASE_URL}/rest/v1/playlist_items?playlist_id=eq.${encodeURIComponent(p.id)}&position=gt.${maxKeep}`;
       const tDel = Date.now();
       const { r: delR, text: dtxt } = await fetchText(
         delUrl,
         {
           method: "DELETE",
           headers: {
             apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
             Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
             Prefer: "return=minimal",
           },
         },
         20000
       );
       if (!delR.ok) console.warn("sync-items:cleanup_warning", { text: dtxt, took_ms: Date.now() - tDel });
       else console.log("sync-items:cleanup_ok", { took_ms: Date.now() - tDel });
   
       // Erfolgs-Finale
       await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
         method: "PATCH",
         headers: { Prefer: "return=minimal" },
         body: JSON.stringify({
           needs_sync: false,
           sync_started_at: null,
           last_synced_at: new Date().toISOString(),
         }),
       }).catch(()=>{});
   
       console.timeEnd(timeLabel);
       return json(res, 200, {
         ok: upsertErrors === 0,
         inserted_or_updated: rows.length,
         total_spotify: items.length,
         upsert_errors: upsertErrors,
       });
     } catch (e) {
       const msg = e && e.stack ? e.stack : String(e);
       console.error("sync-items:error", msg);
       console.timeEnd(timeLabel);
       return bad(res, 500, "sync_items_exception: " + msg);
     } finally {
       // Guard sicher abbauen
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
    const body = await readBody(req);
    const connection_id = body.connection_id;
    if (!connection_id) return bad(res, 400, "missing_connection_id");

    // 1) connection
    const cr = await sb(`/rest/v1/spotify_connections?select=id,bubble_user_id,spotify_user_id,refresh_token_enc&limit=1&id=eq.${encodeURIComponent(connection_id)}`);
    if (!cr.ok) return bad(res, 500, `supabase select connection failed: ${await cr.text()}`);
    const conn = (await cr.json())[0];
    if (!conn) return bad(res, 404, "connection_not_found");

    if (process.env.APP_WEBHOOK_SECRET) {
      const got = req.headers["x-app-secret"];
      const bubbleUserId = await bubbleUserIdFromRequest(req);
      const isOwner = bubbleUserId && bubbleUserId === conn.bubble_user_id;
      if (got !== process.env.APP_WEBHOOK_SECRET && !isOwner) return bad(res, 401, "unauthorized");
    }

    const refresh_token = decryptToken(conn.refresh_token_enc);
    const credentials = await getSpotifyAppCredentialsForConnection(conn.id);
    const token = await refreshAccessToken(refresh_token, credentials);
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
    const syncedRows = [];
    for (const batch of chunk(rows, 100)) {
      const up = await scopedPlaylistUpsert(batch);
      if (!up.ok) return bad(res, 500, `supabase_upsert_failed: ${await up.text()}`);
      const returnedRows = await up.json().catch(() => []);
      if (Array.isArray(returnedRows)) syncedRows.push(...returnedRows);
      upserts += batch.length;
    }

    const initialItems = String(req.query.with_items || "0") === "1";
    let itemSyncDispatched = 0;
    if (initialItems && syncedRows.length) {
      const base = internalBaseUrl();
      const syncCandidates = syncedRows
        .filter((p) => p?.id && Number(p.tracks_total || 0) > 0)
        .sort((a, b) => Number(b.followers ?? -1) - Number(a.followers ?? -1));
      const limit = Math.max(1, Math.min(50, Number(req.query.items_limit || 12) || 12));
      for (const playlist of syncCandidates.slice(0, limit)) {
        await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(playlist.id)}`, {
          method: "PATCH",
          headers: { Prefer: "return=minimal" },
          body: JSON.stringify({ needs_sync: true, next_check_at: null }),
        }).catch(() => {});
        const dispatch = await fetch(`${base}/api/playlists/dispatch-sync`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
          body: JSON.stringify({ playlist_id: playlist.id }),
        }).catch((error) => ({ ok: false, status: 0, text: async () => String(error?.message || error) }));
        if (dispatch.ok) {
          itemSyncDispatched++;
        } else {
          console.warn("playlists_sync_item_dispatch_failed", {
            playlist_id: playlist.id,
            status: dispatch.status,
            body: await dispatch.text().catch(() => ""),
          });
        }
      }
    }

    return json(res, 200, { ok:true, upserts, filtered: filtered.length, followers_fetched: followersFetched, item_sync_dispatched: itemSyncDispatched });
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
   
     // --- USER MASTER SWITCHES / SUB GATE ---
     const cR = await sb(`/rest/v1/spotify_connections?select=bubble_user_id&limit=1&id=eq.${encodeURIComponent(body.connection_id)}`);
     const cJ = await cR.json();
     const bubble_user_id = cJ?.[0]?.bubble_user_id || null;
     if (!bubble_user_id) return bad(res, 404, "connection_not_found");
   
     const uR = await sb(`/rest/v1/app_users?select=sync_paused,subscription_status,subscription_expires_at&limit=1&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}`);
     const u = (await uR.json())[0] || {};
     const subActive = !u.subscription_expires_at || new Date(u.subscription_expires_at) > new Date();
     const subOk = (u.subscription_status || "active") !== "canceled" && subActive;
     if (u.sync_paused || !subOk) {
       return json(res, 200, { ok:true, skipped:true, reason: u.sync_paused ? "user_paused" : "subscription_inactive" });
     }
   
     const order = encodeURIComponent("next_check_at.asc.nullsfirst");
     const sel = await sb(
       `/rest/v1/playlists?select=id,playlist_id,snapshot_id,next_check_at,last_snapshot_checked_at,error_count` +
       `&connection_id=eq.${encodeURIComponent(body.connection_id)}` +
       `&is_owner=is.true&is_public=is.true` +
       `&sync_started_at=is.null` +
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
   
     // --- USER MASTER SWITCHES / SUB GATE ---
     const cR = await sb(`/rest/v1/spotify_connections?select=bubble_user_id&limit=1&id=eq.${encodeURIComponent(body.connection_id)}`);
     const cJ = await cR.json();
     const bubble_user_id = cJ?.[0]?.bubble_user_id || null;
     if (!bubble_user_id) return bad(res, 404, "connection_not_found");
   
     const uR = await sb(`/rest/v1/app_users?select=sync_paused,subscription_status,subscription_expires_at&limit=1&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}`);
     const u = (await uR.json())[0] || {};
     const subActive = !u.subscription_expires_at || new Date(u.subscription_expires_at) > new Date();
     const subOk = (u.subscription_status || "active") !== "canceled" && subActive;
     if (u.sync_paused || !subOk) {
       return json(res, 200, { ok:true, synced:0, failed:0, skipped:true, reason: u.sync_paused ? "user_paused" : "subscription_inactive" });
     }
   
     const r = await sb(
       `/rest/v1/playlists?select=id,next_check_at` +
       `&connection_id=eq.${encodeURIComponent(body.connection_id)}` +
       `&needs_sync=is.true` +
       `&or=(next_check_at.is.null,next_check_at.lte.${encodeURIComponent(new Date().toISOString())})` +
       `&limit=${encodeURIComponent(qs.limit || "50")}`
     );
     if (!r.ok) return bad(res, 500, `supabase_select_failed: ${await r.text()}`);
     const rows = await r.json();
     if (rows.length === 0) return json(res, 200, { ok:true, synced:0 });
   
     const base = internalBaseUrl();
     if (!base) return bad(res, 500, "missing PUBLIC_BASE_URL/VERCEL_URL");
     const syncUrl = `${base}/api/playlists/sync-items`;
   
     let i=0, running=0, conc=1, synced=0, failed=0; // conc=1: vermeidet Herd-Effekte
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
   
     return json(res, 200, { ok:true, synced, failed });
   },



  /* ---------- watch/cron-check-all (GET/POST) ---------- */
  "watch/cron-check-all": async (req, res) => {
     if (!checkCronAuth(req)) return bad(res, 401, "unauthorized_cron");
   
     const conns = await sb(
       `/rest/v1/spotify_connections?select=id&is_active=is.true`
     ).then(r => r.json());
   
     let ok=0, fail=0;
     for (const c of conns) {
       const resp = await routes["watch/check-updates"](
         { ...req, method:"POST", headers: { ...req.headers, "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" }, url: req.url, query: req.query, body: { connection_id: c.id } },
         { status: ()=>({ json: ()=>{} }) }
       ).catch(()=>({ ok:false }));
       resp?.ok ? ok++ : fail++;
       await sleep(80);
     }
     return json(res, 200, { ok:true, connections: conns.length, dispatched_ok: ok, dispatched_fail: fail });
   },


  /* ---------- watch/cron-sync-all (GET/POST) ---------- */
  "watch/cron-sync-all": async (req, res) => {
     if (!checkCronAuth(req)) return bad(res, 401, "unauthorized_cron");
   
     const conns = await sb(
       `/rest/v1/spotify_connections?select=id&is_active=is.true`
     ).then(r=>r.json());
   
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
     const bucketOverride = qp.get("bucket");
     const nowUtcMin = new Date().getUTCMinutes();
     const bucket = bucketOverride !== null ? Number(bucketOverride) : nowUtcMin;
   
     const limitCheck = qp.get("limit_check") ?? qp.get("limit") ?? "5";
     const concCheck  = qp.get("conc_check")  ?? qp.get("concurrency") ?? "2";
     const limitSync  = qp.get("limit_sync")  ?? qp.get("limit") ?? "2";
     const concSync   = qp.get("conc_sync")   ?? qp.get("concurrency") ?? "1";
   
     const conns = await sb(
       `/rest/v1/spotify_connections?select=id&is_active=is.true&cron_bucket=eq.${encodeURIComponent(bucket)}`
     ).then(r => r.json());
   
     let ok=0, fail=0;
     for (const c of conns) {
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
   
       await sleep(60);
     }
   
     return json(res, 200, { ok:true, bucket, connections: conns.length, dispatched_ok: ok, dispatched_fail: fail });
   },




   /* ---------- watch/cron-maintenance-all (GET/POST) ---------- */
   "watch/cron-maintenance-all": async (req, res) => {
     if (!checkCronAuth(req) && !checkAppSecret(req)) return bad(res, 401, "unauthorized_cron");
     const qs = Object.fromEntries(new URL(req.url, `http://${req.headers.host}`).searchParams.entries());
   
     // Zielmenge: alle, die Auto-Remove aktiv haben (und Wochen gesetzt)
     const sel = await sb(
       `/rest/v1/playlists?select=id` +
       `&auto_remove_enabled=is.true&auto_remove_weeks=not.is.null` +
       `&or=(next_check_at.is.null,next_check_at.lte.${encodeURIComponent(new Date().toISOString())})`
     );
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




   /* ---------- followers/cron-refresh-all (GET/POST) ---------- XXX
   Läuft idealerweise jede Minute.
   - verteilt Last über 60 "buckets" (cron_bucket pro Connection)
   - ruft intern playlists/refresh-followers für jede aktive Connection im Bucket
   Query-Params (optional):
     stale_hours=23   -> nur Playlists updaten, deren Stand älter ist
     max=600          -> max Playlists pro Connection pro Lauf
     concurrency=3    -> parallele Spotify-GETs pro Connection (wird an Sub-Route gereicht)
     batch=100        -> Batch-Größe fürs Upsert der Daily-Tabelle
     bucket=NN        -> manuelles Bucket-Override (0..59), sonst UTC Minute
   */
   "followers/cron-refresh-all": async (req, res) => {
     if (!checkCronAuth(req)) return bad(res, 401, "unauthorized_cron");
   
     const inUrl = new URL(req.url, `http://${req.headers.host}`);
     const qp = inUrl.searchParams;
   
     const staleHours = Number(qp.get("stale_hours") || "23");
     const maxTotal   = Number(qp.get("max") || "600");
     const conc       = Number(qp.get("concurrency") || "3");
     const perWrite   = Number(qp.get("batch") || "100");
   
     const bucketOverride = qp.get("bucket");
     const nowUtcMin = new Date().getUTCMinutes();
     const bucket = bucketOverride !== null ? Number(bucketOverride) : nowUtcMin;
   
     // Nur aktive Connections im aktuellen Bucket
     const conns = await sb(
       `/rest/v1/spotify_connections?select=id&is_active=is.true&cron_bucket=eq.${encodeURIComponent(bucket)}`
     ).then(r => r.json());
   
     let ok=0, fail=0;
     for (const c of conns) {
       // interner Aufruf deiner bestehenden Subroute (mit Secret-Header)
       const reqOne = {
         ...req,
         method: "POST",
         headers: { ...req.headers, "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
         // Query-Params an Subroute durchreichen
         url: `/api/playlists/refresh-followers?stale_hours=${encodeURIComponent(String(staleHours))}` +
              `&max=${encodeURIComponent(String(maxTotal))}` +
              `&concurrency=${encodeURIComponent(String(conc))}` +
              `&batch=${encodeURIComponent(String(perWrite))}`,
         query: {
           stale_hours: String(staleHours),
           max: String(maxTotal),
           concurrency: String(conc),
           batch: String(perWrite)
         },
         body: { connection_id: c.id }
       };
   
       const dummyRes = { status: () => ({ json: () => {} }) };
       try {
         const r = await routes["playlists/refresh-followers"](reqOne, dummyRes);
         r?.ok ? ok++ : fail++;
       } catch {
         fail++;
       }
       await sleep(60); // leichter Jitter zwischen Connections
     }
   
     return json(res, 200, { ok:true, bucket, connections: conns.length, dispatched_ok: ok, dispatched_fail: fail });
   },

   /* ---------- followers/cron-refresh-6h (GET/POST) ---------- */
   "followers/cron-refresh-6h": async (req, res) => {
     const reqSixHourly = {
       ...req,
       url: `/api/followers/cron-refresh-all?stale_hours=6&max=120&batch=100`,
       query: { ...(req.query || {}), stale_hours: "6", max: "120", batch: "100" }
     };
     return routes["followers/cron-refresh-all"](reqSixHourly, res);
   },
   
      
   /* ---------- playlist-items/move (POST) ---------- */
   "playlist-items/move": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
     const bubbleUserId = await bubbleUserIdFromRequest(req);
     if (!bubbleUserId) return bad(res, 401, "Missing X-Bubble-User-Id");
   
     const { playlist_id, track_id, dir, steps = 1 } = await readBody(req);
     if (!playlist_id || !track_id || !dir) return bad(res, 400, "Missing playlist_id, track_id or dir");
   
     // Ownership + Spotify target. Moves must hit Spotify immediately, otherwise
     // the next sync can read the old Spotify order back and make locked tracks jump.
     const own = await sb(
       `/rest/v1/playlists?select=id,playlist_id,connection_id,tracks_total&limit=1` +
       `&id=eq.${encodeURIComponent(String(playlist_id))}` +
       `&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`
     ).then(r=>r.json());
     const playlistRow = own?.[0];
     if (!playlistRow) return bad(res, 403, "Playlist not owned by user");

     const beforePosR = await sb(
       `/rest/v1/playlist_items?select=position` +
       `&playlist_id=eq.${encodeURIComponent(playlist_id)}` +
       `&track_id=eq.${encodeURIComponent(track_id)}` +
       `&order=position.asc&limit=1`
     );
     const beforeRow = beforePosR.ok ? (await beforePosR.json())?.[0] : null;
     const beforePosition = Number.isFinite(Number(beforeRow?.position)) ? Number(beforeRow.position) : null;
     const stepCount = Math.max(1, Number(steps) || 1);
     const direction = String(dir || "").toLowerCase();
     const estimatedTarget = beforePosition === null
       ? null
       : Math.max(0, beforePosition + (direction === "up" ? -stepCount : stepCount));

     let spotifyMoved = false;
     let spotifySnapshotId = null;
     if (playlistRow.playlist_id && playlistRow.connection_id && estimatedTarget !== null) {
       try {
         const accessToken = await getAccessTokenFromConnection(playlistRow.connection_id);
         const spotifyFrom = await findPlaylistTrackPosition(playlistRow.playlist_id, track_id, accessToken, beforePosition);
         if (spotifyFrom >= 0) {
           const meta = await fetchJSON(
             `https://api.spotify.com/v1/playlists/${encodeURIComponent(playlistRow.playlist_id)}?fields=snapshot_id,tracks(total)`,
             { headers: { Authorization: `Bearer ${accessToken}` } },
             20000
           );
           if (!meta.r.ok) return bad(res, meta.r.status, `spotify_meta_failed: ${meta.text || JSON.stringify(meta.json)}`);
           const spotifyTotal = Number(meta.json?.tracks?.total);
           const maxTarget = Number.isFinite(spotifyTotal) && spotifyTotal > 0 ? spotifyTotal - 1 : Math.max(0, Number(playlistRow.tracks_total || 1) - 1);
           const spotifyTo = Math.max(0, Math.min(maxTarget, estimatedTarget));
           if (spotifyFrom !== spotifyTo) {
             const reorder = await fetchJSON(
               `https://api.spotify.com/v1/playlists/${encodeURIComponent(playlistRow.playlist_id)}/tracks`,
               {
                 method: "PUT",
                 headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
                 body: JSON.stringify({
                   range_start: spotifyFrom,
                   insert_before: spotifyTo > spotifyFrom ? spotifyTo + 1 : spotifyTo,
                   range_length: 1,
                   ...(meta.json?.snapshot_id ? { snapshot_id: meta.json.snapshot_id } : {})
                 })
               },
               20000
             );
             if (!reorder.r.ok) return bad(res, reorder.r.status, `spotify_reorder_failed: ${reorder.r.status} ${reorder.text || JSON.stringify(reorder.json)}`);
             spotifyMoved = true;
             spotifySnapshotId = reorder.json?.snapshot_id || meta.json?.snapshot_id || null;
           }
         }
       } catch (e) {
         return bad(res, 500, `spotify_reorder_exception: ${String(e?.message || e)}`);
       }
     }
   
     // RPC call
     const r = await sb(`/rest/v1/rpc/playlist_move_one`, {
       method: "POST",
       body: JSON.stringify({
         p_playlist_id: playlist_id,
         p_track_id: track_id,
         p_dir: direction,
         p_steps: stepCount
       })
     });
     const txt = await r.text();
     let j = null; try { j = txt ? JSON.parse(txt) : null; } catch {}
    if (!r.ok) return bad(res, r.status, `rpc_move_failed: ${txt}`);

    const movedPosR = await sb(
      `/rest/v1/playlist_items?select=position` +
      `&playlist_id=eq.${encodeURIComponent(playlist_id)}` +
      `&track_id=eq.${encodeURIComponent(track_id)}` +
      `&order=position.asc&limit=1`
    );
    let movedPosition = null;
    if (movedPosR.ok) {
      const movedRow = (await movedPosR.json())?.[0];
      if (Number.isFinite(Number(movedRow?.position))) movedPosition = Number(movedRow.position);
    }

    try {
      const locksR = await sb(
        `/rest/v1/playlist_item_locks?select=track_id&playlist_id=eq.${encodeURIComponent(playlist_id)}&is_locked=is.true`
      );
      const locks = locksR.ok ? await locksR.json() : [];
      const lockedIds = Array.isArray(locks) ? locks.map((x) => x.track_id).filter(Boolean) : [];
      if (lockedIds.length) {
        const quotedIds = lockedIds.map((id) => `"${encodeURIComponent(String(id))}"`).join(",");
        const posR = await sb(
          `/rest/v1/playlist_items?select=track_id,position` +
          `&playlist_id=eq.${encodeURIComponent(playlist_id)}` +
          `&track_id=in.(${quotedIds})`
        );
        const positions = posR.ok ? await posR.json() : [];
        const nowIso = new Date().toISOString();
        const lockUpdates = (Array.isArray(positions) ? positions : [])
          .filter((row) => Number.isFinite(Number(row.position)))
          .map((row) => ({
            playlist_id,
            track_id: row.track_id,
            locked_position: Number(row.position),
            is_locked: true,
            locked_at: nowIso,
          }));
        if (lockUpdates.length) {
          await sb(`/rest/v1/playlist_item_locks?on_conflict=playlist_id,track_id`, {
            method: "POST",
            headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
            body: JSON.stringify(lockUpdates),
          });
        }
      }
    } catch (e) {
      console.warn("playlist-items/move:lock_position_resync_failed", String(e?.message || e));
    }

    const cooldownUntil = await setPlaylistUpdateCooldown(playlist_id, 300);
   
     const base = internalBaseUrl();
     if (base) {
       fetch(`${base}/api/playlists/dispatch-sync`, {
         method: "POST",
         headers: { "Content-Type": "application/json", "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
         body: JSON.stringify({ playlist_id })
       }).catch(() => {});
     }
   
    return json(res, 200, {
      ok: true,
      result: j?.[0] || null,
      moved_position: movedPosition,
      spotify_moved: spotifyMoved,
      spotify_snapshot_id: spotifySnapshotId,
      cooldown_until: cooldownUntil
    });
  },
   
  /* ---------- playlist-items/remove (POST, Bubble) ---------- */
   "playlist-items/remove": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
   
     // Auth per Bubble
     const bubbleUserId = await bubbleUserIdFromRequest(req);
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
         const cooldownUntil = await setPlaylistUpdateCooldown(p.id, 300);
   
         // Supabase sync triggern
         await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(p.id)}`, {
           method: "PATCH",
           headers: { Prefer: "return=minimal" },
           body: JSON.stringify({ needs_sync: true, last_snapshot_checked_at: new Date().toISOString(), next_check_at: cooldownUntil })
         }).catch(()=>{});
   
         const base = internalBaseUrl();
         if (base) {
           fetch(`${base}/api/playlists/dispatch-sync`, {
             method: "POST",
             headers: { "Content-Type": "application/json", "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
             body: JSON.stringify({ playlist_id: p.id })
           }).catch(()=>{});
         }
   
         return json(res, 200, { ok: true, removed_at_position0: delBody.tracks[0].positions[0], new_snapshot_id: newSnap, cooldown_until: cooldownUntil });
       }
     } catch (e) {
       return bad(res, 500, `remove_exception: ${e?.message || e}`);
     }
   },










   
  /* ---------- locks/set (POST, Bubble) ---------- */
  "locks/set": async (req, res) => {
     if (req.method !== "POST") return bad(res, 405, "Method not allowed");
     const bubbleUserId = await bubbleUserIdFromRequest(req);
     if (!bubbleUserId) return bad(res, 401, "Missing X-Bubble-User-Id");
   
     // user exists?
     const usr = await sb(`/rest/v1/app_users?select=bubble_user_id&limit=1&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`).then(r=>r.json());
     if (!usr?.[0]) return bad(res, 401, "Unknown bubble_user_id");
   
     const { playlist_id, track_id, locked_position, is_locked = true, expiry_weeks, exp_weeks } = await readBody(req);
     
     // Unterstütze sowohl expiry_weeks als auch exp_weeks (exp_weeks hat Priorität)
     const expiryWeeksParam = exp_weeks !== undefined ? exp_weeks : expiry_weeks;
   
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
   
     // expiry_weeks validieren und normalisieren
     // Wenn expiry_weeks explizit auf null gesetzt wird, soll es entfernt werden
     // Wenn es nicht gesetzt ist (undefined), bleibt der alte Wert erhalten
     let expiryWeeksValue = undefined;
     if (expiryWeeksParam !== undefined) {
       if (expiryWeeksParam === null || expiryWeeksParam === "") {
         expiryWeeksValue = null; // Explizit entfernen
       } else {
         const expiryWeeksNum = Number(expiryWeeksParam);
         if (Number.isFinite(expiryWeeksNum) && expiryWeeksNum > 0) {
           expiryWeeksValue = expiryWeeksNum;
         } else {
           expiryWeeksValue = null; // Ungültiger Wert -> entfernen
         }
       }
     }
   
     // upsert lock (jetzt 0-basiert speichern, mit optionalem expiry_weeks)
     const lockData = {
       playlist_id,
       track_id,
       locked_position: lockedPosZero,
       is_locked: !!is_locked,
       locked_at: new Date().toISOString()
     };
     if (expiryWeeksValue !== undefined) {
       lockData.expiry_weeks = expiryWeeksValue;
     }
     
     const up = await sb(`/rest/v1/playlist_item_locks?on_conflict=playlist_id,track_id`, {
       method: "POST",
       headers: { Prefer: "resolution=merge-duplicates,return=representation" },
       body: JSON.stringify([lockData]),
     });
     if (!up.ok) return bad(res, 500, `supabase_upsert_failed: ${await up.text()}`);
     const data = await up.json();

     const cooldownUntil = await setPlaylistUpdateCooldown(playlist_id, 300);

     return json(res, 200, { ok:true, lock: Array.isArray(data) ? data[0] : data, cooldown_until: cooldownUntil });
   },


  /* ---------- locks/unset (POST, Bubble) ---------- */
  "locks/unset": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "Method not allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req);
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

    const cooldownUntil = await setPlaylistUpdateCooldown(playlist_id, 300);

    return json(res, 200, { ok:true, cooldown_until: cooldownUntil });
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

  /* ---------- flex/settings/get (GET) ---------- */
  "flex/settings/get": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req, req.query.bubble_user_id);
    if (!bubbleUserId) return bad(res, 401, "missing_bubble_user_id");
    const playlist_id = String(req.query.playlist_id || "").trim();
    if (!playlist_id) return bad(res, 400, "missing_playlist_id");
    const owned = await getOwnedPlaylist(playlist_id, bubbleUserId);
    if (!owned) return bad(res, 403, "playlist_not_owned");

    const r = await sb(`/rest/v1/playlist_flex_settings?select=*&limit=1&playlist_id=eq.${encodeURIComponent(playlist_id)}`);
    if (!r.ok) return bad(res, 500, `flex_settings_select_failed: ${await r.text()}`);
    const row = (await r.json())?.[0] || null;
    const base = row || {
      playlist_id,
      bubble_user_id: bubbleUserId,
      connection_id: owned.connection_id,
      reference_playlist_id: null,
      reference_playlist_url: "",
      interval: "weekly",
      enabled: false,
      next_rotation_at: null,
      last_rotated_at: null,
      ...normalizeFlexRules({})
    };
    Object.assign(base, normalizeFlexRules(base));
    let reference_playlist = null;
    if (base.reference_playlist_id) {
      const token = await getAccessTokenFromConnection(base.connection_id).catch(() => "");
      reference_playlist = await fetchSpotifyPlaylistMeta(base.reference_playlist_id, token).catch(() => null);
    }
    return json(res, 200, { ...base, reference_playlist });
  },

  /* ---------- flex/settings/save (POST) ---------- */
  "flex/settings/save": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req);
    if (!bubbleUserId) return bad(res, 401, "missing_bubble_user_id");
    const body = await readBody(req);
    const playlist_id = String(body.playlist_id || "").trim();
    if (!playlist_id) return bad(res, 400, "missing_playlist_id");
    const owned = await getOwnedPlaylist(playlist_id, bubbleUserId);
    if (!owned) return bad(res, 403, "playlist_not_owned");

    const interval = String(body.interval || "weekly").toLowerCase();
    if (!["daily", "weekly", "monthly"].includes(interval)) return bad(res, 400, "invalid_interval");
    const referenceRaw = String(body.reference_playlist || body.reference_playlist_url || body.reference_playlist_id || "").trim();
    const reference_playlist_id = referenceRaw ? parseSpotifyPlaylistId(referenceRaw) : null;
    if (referenceRaw && !reference_playlist_id) return bad(res, 400, "invalid_reference_playlist");
    let reference_playlist = null;
    if (reference_playlist_id) {
      const token = await getAccessTokenFromConnection(owned.connection_id);
      const probe = await fetchJSON(
        `https://api.spotify.com/v1/playlists/${encodeURIComponent(reference_playlist_id)}/tracks?limit=1&fields=total,items(track(id))`,
        { headers: { Authorization: `Bearer ${token}` } },
        20000
      );
      reference_playlist = await fetchSpotifyPlaylistMeta(reference_playlist_id, token).catch(() => null);
      if (!probe.r.ok) {
        return json(res, 422, {
          error: "reference_playlist_blocked",
          status: probe.r.status,
          spotify_error: probe.json?.error || null,
          reference_playlist_id,
          reference_playlist_url: referenceRaw,
          reference_playlist,
        });
      }
    }
    const enabled = !!body.enabled && !!reference_playlist_id;
    const nowIso = new Date().toISOString();
    const next_rotation_at = enabled
      ? (body.next_rotation_at || nextFlexRotationAt(interval))
      : null;

    const payload = {
      playlist_id,
      bubble_user_id: bubbleUserId,
      connection_id: owned.connection_id,
      reference_playlist_id,
      reference_playlist_url: referenceRaw || null,
      interval,
      enabled,
      next_rotation_at,
      updated_at: nowIso,
      repeat_cooldown_weeks: normalizeFlexRules(body).repeat_cooldown_weeks,
      avoid_target_duplicates: normalizeFlexRules(body).avoid_target_duplicates,
      min_popularity: normalizeFlexRules(body).min_popularity,
      max_popularity: normalizeFlexRules(body).max_popularity,
      max_release_age_weeks: normalizeFlexRules(body).max_release_age_weeks
    };

    let r = await sb(`/rest/v1/playlist_flex_settings?on_conflict=playlist_id`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=representation" },
      body: JSON.stringify([payload])
    });
    if (!r.ok) {
      const text = await r.text();
      if (text.includes("repeat_cooldown_weeks") || text.includes("avoid_target_duplicates") || text.includes("min_popularity") || text.includes("max_popularity") || text.includes("max_release_age_weeks")) {
        const {
          repeat_cooldown_weeks,
          avoid_target_duplicates,
          min_popularity,
          max_popularity,
          max_release_age_weeks,
          ...fallbackPayload
        } = payload;
        r = await sb(`/rest/v1/playlist_flex_settings?on_conflict=playlist_id`, {
          method: "POST",
          headers: { Prefer: "resolution=merge-duplicates,return=representation" },
          body: JSON.stringify([fallbackPayload])
        });
      } else {
        return bad(res, 500, `flex_settings_upsert_failed: ${text}`);
      }
    }
    if (!r.ok) return bad(res, 500, `flex_settings_upsert_failed: ${await r.text()}`);
    const rows = await r.json();
    await setPlaylistUpdateCooldown(playlist_id, 300);
    const saved = rows?.[0] || payload;
    return json(res, 200, { ok: true, settings: { ...normalizeFlexRules(payload), ...saved, reference_playlist } });
  },

  /* ---------- flex/history (GET) ---------- */
  "flex/history": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req, req.query.bubble_user_id);
    if (!bubbleUserId) return bad(res, 401, "missing_bubble_user_id");
    const playlist_id = String(req.query.playlist_id || "").trim();
    if (!playlist_id) return bad(res, 400, "missing_playlist_id");
    const owned = await getOwnedPlaylist(playlist_id, bubbleUserId);
    if (!owned) return bad(res, 403, "playlist_not_owned");
    const limit = Math.max(1, Math.min(50, Number(req.query.limit || "10")));
    const r = await sb(
      `/rest/v1/playlist_flex_history?select=id,slot_id,track_id,track_name,source_playlist_id,rotated_at` +
      `&playlist_id=eq.${encodeURIComponent(playlist_id)}` +
      `&order=rotated_at.desc&limit=${encodeURIComponent(limit)}`
    );
    if (!r.ok) return json(res, 200, []);
    return json(res, 200, await r.json());
  },

  /* ---------- flex/slots/list (GET) ---------- */
  "flex/slots/list": async (req, res) => {
    if (req.method !== "GET") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req, req.query.bubble_user_id);
    if (!bubbleUserId) return bad(res, 401, "missing_bubble_user_id");
    const playlist_id = String(req.query.playlist_id || "").trim();
    if (!playlist_id) return bad(res, 400, "missing_playlist_id");
    const owned = await getOwnedPlaylist(playlist_id, bubbleUserId);
    if (!owned) return bad(res, 403, "playlist_not_owned");

    const r = await sb(`/rest/v1/playlist_flex_slots?select=*&playlist_id=eq.${encodeURIComponent(playlist_id)}&order=position.asc`);
    if (!r.ok) return bad(res, 500, `flex_slots_select_failed: ${await r.text()}`);
    return json(res, 200, await r.json());
  },

  /* ---------- flex/slots/add (POST) ---------- */
  "flex/slots/add": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req);
    if (!bubbleUserId) return bad(res, 401, "missing_bubble_user_id");
    const body = await readBody(req);
    const playlist_id = String(body.playlist_id || "").trim();
    const track_id = String(body.track_id || "").trim();
    if (!playlist_id || !track_id) return bad(res, 400, "missing_playlist_id_or_track_id");
    const owned = await getOwnedPlaylist(playlist_id, bubbleUserId);
    if (!owned) return bad(res, 403, "playlist_not_owned");

    const lockRows = await sb(
      `/rest/v1/playlist_item_locks?select=track_id,locked_position,is_locked` +
      `&limit=1&playlist_id=eq.${encodeURIComponent(playlist_id)}&track_id=eq.${encodeURIComponent(track_id)}`
    ).then(r => r.json()).catch(() => []);
    const lock = lockRows?.[0];

    const itemRows = await sb(
      `/rest/v1/playlist_items?select=track_name,position` +
      `&limit=1&playlist_id=eq.${encodeURIComponent(playlist_id)}&track_id=eq.${encodeURIComponent(track_id)}`
    ).then(r => r.json()).catch(() => []);
    const item = itemRows?.[0] || {};
    const position = Number.isFinite(Number(lock.locked_position)) ? Number(lock.locked_position) : Number(item.position || 0);

    if (!lock?.is_locked) {
      const lockUp = await sb(`/rest/v1/playlist_item_locks?on_conflict=playlist_id,track_id`, {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify([{
          playlist_id,
          track_id,
          locked_position: Math.max(0, position),
          is_locked: true,
          locked_at: new Date().toISOString()
        }])
      });
      if (!lockUp.ok) return bad(res, 500, `flex_auto_lock_failed: ${await lockUp.text()}`);
    }

    const payload = {
      playlist_id,
      bubble_user_id: bubbleUserId,
      connection_id: owned.connection_id,
      position,
      current_track_id: track_id,
      current_track_name: item.track_name || null,
      updated_at: new Date().toISOString()
    };
    const r = await sb(`/rest/v1/playlist_flex_slots?on_conflict=playlist_id,position`, {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates,return=representation" },
      body: JSON.stringify([payload])
    });
    if (!r.ok) return bad(res, 500, `flex_slot_upsert_failed: ${await r.text()}`);
    await setPlaylistUpdateCooldown(playlist_id, 300);
    const rows = await r.json();
    return json(res, 200, { ok: true, slot: rows?.[0] || payload });
  },

  /* ---------- flex/slots/remove (POST) ---------- */
  "flex/slots/remove": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req);
    if (!bubbleUserId) return bad(res, 401, "missing_bubble_user_id");
    const body = await readBody(req);
    const slot_id = String(body.slot_id || "").trim();
    if (!slot_id) return bad(res, 400, "missing_slot_id");
    const slotRows = await sb(
      `/rest/v1/playlist_flex_slots?select=id,playlist_id,current_track_id,position` +
      `&limit=1&id=eq.${encodeURIComponent(slot_id)}&bubble_user_id=eq.${encodeURIComponent(bubbleUserId)}`
    ).then(r => r.json()).catch(() => []);
    const slot = slotRows?.[0];
    if (!slot) return bad(res, 404, "slot_not_found");
    const r = await sb(`/rest/v1/playlist_flex_slots?id=eq.${encodeURIComponent(slot_id)}`, {
      method: "DELETE",
      headers: { Prefer: "return=minimal" }
    });
    if (!r.ok) return bad(res, 500, `flex_slot_delete_failed: ${await r.text()}`);
    if (slot.current_track_id) {
      await sb(
        `/rest/v1/playlist_item_locks?playlist_id=eq.${encodeURIComponent(slot.playlist_id)}` +
        `&track_id=eq.${encodeURIComponent(slot.current_track_id)}`,
        {
          method: "PATCH",
          headers: { Prefer: "return=minimal" },
          body: JSON.stringify({
            is_locked: false,
            locked_position: null,
            locked_at: new Date().toISOString()
          })
        }
      ).catch(() => {});
    }
    await setPlaylistUpdateCooldown(slot.playlist_id, 300);
    return json(res, 200, { ok: true });
  },

  /* ---------- flex/rotate (POST) ---------- */
  "flex/rotate": async (req, res) => {
    if (req.method !== "POST") return bad(res, 405, "method_not_allowed");
    const bubbleUserId = await bubbleUserIdFromRequest(req);
    const isInternal = checkAppSecret(req) || checkCronAuth(req);
    if (!isInternal && !bubbleUserId) return bad(res, 401, "missing_bubble_user_id");
    const body = await readBody(req);
    const playlist_id = String(body.playlist_id || "").trim();
    const slot_id = String(body.slot_id || "").trim();
    if (!playlist_id && !slot_id) return bad(res, 400, "missing_playlist_id_or_slot_id");

    let settings = null;
    let slots = [];
    if (slot_id) {
      const slotRows = await sb(`/rest/v1/playlist_flex_slots?select=*&limit=1&id=eq.${encodeURIComponent(slot_id)}`).then(r => r.json()).catch(() => []);
      const slot = slotRows?.[0];
      if (!slot) return bad(res, 404, "slot_not_found");
      if (!isInternal && slot.bubble_user_id !== bubbleUserId) return bad(res, 403, "forbidden");
      slots = [slot];
      const stRows = await sb(`/rest/v1/playlist_flex_settings?select=*&limit=1&playlist_id=eq.${encodeURIComponent(slot.playlist_id)}`).then(r => r.json()).catch(() => []);
      settings = stRows?.[0] || null;
    } else {
      const owned = !isInternal ? await getOwnedPlaylist(playlist_id, bubbleUserId) : { id: playlist_id };
      if (!owned) return bad(res, 403, "playlist_not_owned");
      const stRows = await sb(`/rest/v1/playlist_flex_settings?select=*&limit=1&playlist_id=eq.${encodeURIComponent(playlist_id)}`).then(r => r.json()).catch(() => []);
      settings = stRows?.[0] || null;
      const slotRows = await sb(`/rest/v1/playlist_flex_slots?select=*&playlist_id=eq.${encodeURIComponent(playlist_id)}&order=position.asc`).then(r => r.json()).catch(() => []);
      slots = slotRows || [];
    }
    if (!settings?.reference_playlist_id) return bad(res, 400, "missing_reference_playlist");
    if (!slots.length) return bad(res, 400, "no_flex_slots");

    const results = [];
    for (const slot of slots) {
      try {
        results.push({ slot_id: slot.id, ok: true, ...(await rotateFlexSlot(slot, settings)) });
      } catch (e) {
        results.push({ slot_id: slot.id, ok: false, error: e?.message || String(e) });
      }
      await sleep(250);
    }
    const okCount = results.filter(r => r.ok).length;
    return json(res, okCount ? 200 : 500, { ok: !!okCount, rotated: okCount, failed: results.length - okCount, results });
  },

  /* ---------- flex/cron-rotate-due (GET/POST) ---------- */
  "flex/cron-rotate-due": async (req, res) => {
    if (!checkCronAuth(req) && !checkAppSecret(req)) return bad(res, 401, "unauthorized_cron");
    const qs = Object.fromEntries(new URL(req.url, `http://${req.headers.host}`).searchParams.entries());
    const limit = Math.max(1, Math.min(25, Number(qs.limit || "10")));
    const nowIso = new Date().toISOString();
    const dueR = await sb(
      `/rest/v1/playlist_flex_settings?select=*` +
      `&enabled=is.true&reference_playlist_id=not.is.null` +
      `&or=(next_rotation_at.is.null,next_rotation_at.lte.${encodeURIComponent(nowIso)})` +
      `&order=next_rotation_at.asc.nullsfirst&limit=${limit}`
    );
    if (!dueR.ok) return bad(res, 500, `flex_due_select_failed: ${await dueR.text()}`);
    const due = await dueR.json();
    const results = [];
    for (const settings of due) {
      const slotRows = await sb(`/rest/v1/playlist_flex_slots?select=*&playlist_id=eq.${encodeURIComponent(settings.playlist_id)}&order=position.asc`).then(r => r.json()).catch(() => []);
      let rotated = 0, failed = 0;
      for (const slot of (slotRows || [])) {
        try { await rotateFlexSlot(slot, settings); rotated++; }
        catch { failed++; }
        await sleep(250);
      }
      if (!slotRows?.length) {
        await sb(`/rest/v1/playlist_flex_settings?playlist_id=eq.${encodeURIComponent(settings.playlist_id)}`, {
          method: "PATCH",
          headers: { Prefer: "return=minimal" },
          body: JSON.stringify({ next_rotation_at: nextFlexRotationAt(settings.interval), updated_at: new Date().toISOString() })
        }).catch(() => {});
      }
      results.push({ playlist_id: settings.playlist_id, rotated, failed });
    }
    return json(res, 200, { ok: true, playlists: due.length, results });
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
    const base = internalBaseUrl();
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

// ---- Alias, damit /api/resolve ebenfalls funktioniert:
   
// nach dem routes = { ... } Block, aber noch vor export default:
routes["resolve"] = routes["tracks/resolve"];



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
