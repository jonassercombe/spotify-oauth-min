import crypto from "crypto";
function enc(plain) {
  const key = Buffer.from(process.env.ENC_SECRET, "hex"); // 32 bytes hex
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString("base64");
}

export default async function handler(req, res) {
  try {
    const code = req.query.code;
    const state = req.query.state;
    if (!code || !state) return res.status(400).send("Missing code/state");
    const { bubble_user_id, label, return_to } = JSON.parse(
      Buffer.from(state, "base64url").toString("utf8")
    );

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

    if (!tokenRes.access_token || !tokenRes.refresh_token) {
      console.error("Token response:", tokenRes);
      return res.status(400).send("Failed to get tokens");
    }

    const me = await fetch("https://api.spotify.com/v1/me", {
      headers: { Authorization: `Bearer ${tokenRes.access_token}` },
    }).then((r) => r.json());

    // Supabase: User ggf. anlegen
    await fetch(`${process.env.SUPABASE_URL}/rest/v1/app_users`, {
      method: "POST",
      headers: {
        apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
        "Content-Type": "application/json",
        Prefer: "resolution=merge-duplicates"
      },
      body: JSON.stringify({ bubble_user_id })
    });

    const expiresAt = new Date(Date.now() + tokenRes.expires_in * 1000).toISOString();
    await fetch(`${process.env.SUPABASE_URL}/rest/v1/spotify_connections`, {
      method: "POST",
      headers: {
        apikey: process.env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
        "Content-Type": "application/json",
        Prefer: "return=representation"
      },
      body: JSON.stringify({
        bubble_user_id,
        spotify_user_id: me.id,
        display_name: me.display_name || label || "",
        avatar_url: (me.images && me.images[0]?.url) || null,
        scope: "playlist-read-private playlist-modify-private playlist-modify-public",
        refresh_token_enc: enc(tokenRes.refresh_token),
        access_token_enc: enc(tokenRes.access_token),
        access_expires_at: expiresAt
      })
    });

    const back = (return_to || "/") + `?spotify_linked=1&spotify_user=${encodeURIComponent(me.id)}`;
    res.redirect(back);
  } catch (e) {
    console.error(e);
    res.status(500).send("callback error");
  }
}
