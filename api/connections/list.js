export const config = { runtime: "nodejs18.x" };

export default async function handler(req, res) {
  try {
    // CORS (hilft im Bubble-Editor)
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    if (req.method === "OPTIONS") return res.status(204).end();

    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SRK = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!SUPABASE_URL || !SRK) {
      return res.status(500).json({
        error: "missing_env",
        have: {
          SUPABASE_URL: !!SUPABASE_URL,
          SUPABASE_SERVICE_ROLE_KEY: !!SRK
        }
      });
    }

    const bubble_user_id = req.query.bubble_user_id;
    if (!bubble_user_id) {
      return res.status(400).json({ error: "missing_bubble_user_id" });
    }

    const path =
      `/rest/v1/spotify_connections` +
      `?select=id,display_name,avatar_url,spotify_user_id,created_at` +
      `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
      `&order=created_at.desc`;

    const url = SUPABASE_URL + path;

    const r = await fetch(url, {
      headers: {
        apikey: SRK,
        Authorization: `Bearer ${SRK}`
      },
      cache: "no-store"
    });

    const txt = await r.text();
    if (!r.ok) {
      return res.status(500).json({
        error: "supabase_error",
        status: r.status,
        body: txt,
        url
      });
    }

    let data = [];
    if (txt) {
      try { data = JSON.parse(txt); }
      catch (e) { return res.status(500).json({ error: "json_parse_error", body: txt }); }
    }

    return res.status(200).json(data);
  } catch (e) {
    return res.status(500).json({
      error: "server_error",
      message: String(e),
      stack: e?.stack
    });
  }
}
