// api/playlists/list.js
export const config = { runtime: "nodejs" };

export default async function handler(req, res) {
  try {
    // CORS (hilft im Bubble-Editor)
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    if (req.method === "OPTIONS") return res.status(204).end();
    if (req.method !== "GET") return res.status(405).json({ error: "method_not_allowed" });

    const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
    if (!SUPABASE_URL || !SRK) {
      return res.status(500).json({
        error: "missing_env",
        have: { SUPABASE_URL: !!SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: !!SRK }
      });
    }

    const bubble_user_id = req.query.bubble_user_id;
    if (!bubble_user_id) return res.status(400).json({ error: "missing_bubble_user_id" });

    // Nur öffentliche Felder zurückgeben + Filter: eigene, public, owner
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
    if (!r.ok) {
      return res.status(500).json({
        error: "supabase_error",
        status: r.status,
        body: txt,
        url: SUPABASE_URL + path
      });
    }

    let data = [];
    if (txt) {
      try { data = JSON.parse(txt); }
      catch { return res.status(500).json({ error: "json_parse_error", body: txt }); }
    }

    return res.status(200).json(data);
  } catch (e) {
    return res.status(500).json({ error: "server_error", message: String(e) });
  }
}
