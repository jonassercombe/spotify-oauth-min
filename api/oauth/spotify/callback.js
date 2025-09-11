// Node 18+ (Vercel default) hat global fetch.
// Minimaler AES-256-GCM Verschlüsselungs-Helper (Tokens nicht im Klartext speichern).
import crypto from "crypto";

function assertEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

function enc(plain) {
  // ENC_SECRET: 32-Byte Hex (64 Zeichen). Beispiel erzeugen: `openssl rand -hex 32`
  const hex = assertEnv("ENC_SECRET");
  if (hex.length < 64) throw new Error("ENC_SECRET must be 32-byte hex (64 hex chars)");
  const key = Buffer.from(hex, "hex");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString("base64");
}

// kleine Helper für Supabase REST
async function sbSelect(path) {
  const url = `${assertEnv("SUPABASE_URL")}${path}`;
  const r = await fetch(url, {
    headers: {
      apikey: assertEnv("SUPABASE_SERVICE_ROLE_KEY"),
      Authorization: `Bearer ${assertEnv("SUPABASE_SERVICE_ROLE_KEY")}`,
    },
  });
  if (!r.ok) throw new Error(`Supabase SELECT ${path} failed: ${r.status} ${await r.text()}`);
  return r.json();
}

async function sbInsert(path, body) {
  const url = `${assertEnv("SUPABASE_URL")}${path}`;
  const r = await fetch(url, {
    method: "POST",
    headers: {
      apikey: assertEnv("SUPABASE_SERVICE_ROLE_KEY"),
      Authorization: `Bearer ${assertEnv("SUPABASE_SERVICE_ROLE_KEY")}`,
      "Content-Type": "application/json",
      Prefer: "return=representation"
    },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`Supabase INSERT ${path} failed: ${r.status} ${await r.text()}`);
  return r.json();
}

async function sbPatch(path, body) {
  const url = `${assertEnv("SUPABASE_URL")}${path}`;
  const r = await fetch(url, {
    method: "PATCH",
    headers: {
      apikey: assertEnv("SUPABASE_SERVICE_ROLE_KEY"),
      Authorization: `Bearer ${assertEnv("SUPABASE_SERVICE_ROLE_KEY")}`,
      "Content-Type": "application/json",
      Prefer: "return=representation"
    },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`Supabase PATCH ${path} failed: ${r.status} ${await r.text()}`);
  return r.json();
}

export default async function handler(req, res) {
  try {
    // --- sanity env ---
    assertEnv("SPOTIFY_CLIENT_ID");
    assertEnv("SPOTIFY_CLIENT_SECRET");
    assertEnv("SPOTIFY_REDIRECT_URI");
    assertEnv("SUPABASE_URL");
    assertEnv("SUPABASE_SERVICE_ROLE_KEY");
    assertEnv("ENC_SECRET");

    // --- parse query ---
    const code = req.query.code;
    const state = req.query.state;
    if (!code || !state) {
      return res.status(400).send("Missing code/state");
    }

    let parsed;
    try {
      parsed = JSON.parse(Buffer.from(state, "base64url").toString("utf8"));
    } catch {
      return res.status(400).send("Invalid state");
    }
    const bubble_user_id = parsed.bubble_user_id;
    const label = parsed.label || "";
    const return_to = parsed.return_to || "/";
    if (!bubble_user_id) {
      return res.status(400).send("Missing bubble_user_id in state");
    }

    // --- Exchange code -> tokens ---
    const tokenRes = await fetch("https://accounts.spotify.com/api/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization:
          "Basic " +
          Buffer.from(
            `${process.env.SPOTIFY_CLIENT_ID}:${process.env.SPOTIFY_CLIENT_SECRET}`
          ).toString("base64"),
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: process.env.SPOTIFY_REDIRECT_URI,
      }),
    }).then((r) => r.json());

    if (!tokenRes || !tokenRes.access_token) {
      console.error("Token exchange failed:", tokenRes);
      return res.status(400).send("Failed to get access token from Spotify");
    }

    // --- Get profile ---
    const meResp = await fetch("https://api.spotify.com/v1/me", {
      headers: { Authorization: `Bearer ${tokenRes.access_token}` },
    });
    
    // DEBUG: zeige genaue Fehlermeldung
    if (!meResp.ok) {
      const t = await meResp.text();
      console.error("Spotify /me failed:", meResp.status, t);
      return res
        .status(400)
        .send(`Spotify /me failed: ${meResp.status}\n\n${t}`);
    }
    
    const me = await meResp.json();

    const spotify_user_id = me.id;
    const display_name = me.display_name || label || "";
    const avatar_url = (me.images && me.images[0]?.url) || null;

    // --- Ensure app_user exists (idempotent via merge duplicates pattern) ---
    // Falls Policy strikt ist, reicht hier einfacher Insert (mehrfache Inserts sind OK).
    await sbInsert("/rest/v1/app_users", { bubble_user_id });

    // --- Check if connection already exists for this (bubble_user_id, spotify_user_id) ---
    const existing = await sbSelect(
      `/rest/v1/spotify_connections?select=id,refresh_token_enc&bubble_user_id=eq.${encodeURIComponent(
        bubble_user_id
      )}&spotify_user_id=eq.${encodeURIComponent(spotify_user_id)}&limit=1`
    );
    const existingRow = Array.isArray(existing) && existing[0] ? existing[0] : null;

    // --- Decide refresh_token_enc ---
    // Falls Spotify KEIN refresh_token liefert (häufig beim erneuten Consent), behalten wir das vorhandene.
    let refresh_token_enc = null;
    if (tokenRes.refresh_token) {
      refresh_token_enc = enc(tokenRes.refresh_token);
    } else if (existingRow?.refresh_token_enc) {
      refresh_token_enc = existingRow.refresh_token_enc; // reuse stored encrypted token
    } else {
      // Kein altes & kein neues Refresh-Token -> bitte Consent erneut erzwingen.
      // (sollte mit show_dialog=true sehr selten sein)
      return res
        .status(400)
        .send("No refresh_token received. Please retry (consent required).");
    }

    const access_token_enc = enc(tokenRes.access_token);
    const access_expires_at = new Date(Date.now() + (tokenRes.expires_in || 3600) * 1000).toISOString();

    // --- Upsert ohne DB-Constraint: PATCH wenn vorhanden, sonst POST ---
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

    if (existingRow) {
      await sbPatch(
        `/rest/v1/spotify_connections?bubble_user_id=eq.${encodeURIComponent(
          bubble_user_id
        )}&spotify_user_id=eq.${encodeURIComponent(spotify_user_id)}`,
        payload
      );
    } else {
      await sbInsert("/rest/v1/spotify_connections", payload);
    }

    // --- Redirect back to Bubble ---
    const qs =
      `?spotify_linked=1&spotify_user=${encodeURIComponent(spotify_user_id)}`;
    const back = (return_to || "/") + qs;
    return res.redirect(back);
  } catch (e) {
    console.error("callback error:", e);
    const msg = (e && e.stack) ? e.stack : String(e);
    return res
      .status(500)
      .send("callback error – " + msg);
  }
}
