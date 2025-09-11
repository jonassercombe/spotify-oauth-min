// api/connections/list.js
export default async function handler(req, res) {
  try {
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SRK = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SRK) return res.status(500).json({ error: "server_misconfigured" });

    const { bubble_user_id } = req.query;
    if (!bubble_user_id) return res.status(400).json({ error: "missing_bubble_user_id" });

    // Nur öffentliche Felder selektieren!
    const path =
      `/rest/v1/spotify_connections` +
      `?select=id,display_name,avatar_url,spotify_user_id,created_at` +
      `&bubble_user_id=eq.${encodeURIComponent(bubble_user_id)}` +
      `&order=created_at.desc`;

    const r = await fetch(SUPABASE_URL + path, {
      headers: {
        apikey: SRK,
        Authorization: `Bearer ${SRK}`,
      },
    });
    if (!r.ok) {
      const t = await r.text();
      return res.status(500).json({ error: "supabase_error", status: r.status, body: t });
    }

    co
