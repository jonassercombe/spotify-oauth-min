// api/playlist-items/list.js
export const config = { runtime: "nodejs" };

export default async function handler(req,res){
  try{
    // CORS
    res.setHeader("Access-Control-Allow-Origin","*");
    res.setHeader("Access-Control-Allow-Methods","GET,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers","Content-Type");
    if(req.method==="OPTIONS") return res.status(204).end();
    if(req.method!=="GET") return res.status(405).json({ error:"method_not_allowed" });

    const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY: SRK } = process.env;
    if(!SUPABASE_URL || !SRK) return res.status(500).json({ error:"missing_env" });

    const playlist_row_id = req.query.playlist_row_id;
    if(!playlist_row_id) return res.status(400).json({ error:"missing_playlist_row_id" });

    const path =
      `/rest/v1/playlist_items_with_age` +
      `?select=position,track_id,track_name,artist_names,album_name,duration_ms,popularity,preview_url,cover_url,added_at,age_days,age_label` +
      `&playlist_id=eq.${encodeURIComponent(playlist_row_id)}` +
      `&order=position.asc`;

    const r = await fetch(SUPABASE_URL + path, {
      headers: { apikey: SRK, Authorization: `Bearer ${SRK}` },
      cache: "no-store"
    });
    const txt = await r.text();
    if(!r.ok) return res.status(500).json({ error:"supabase_error", status:r.status, body:txt });

    const data = txt ? JSON.parse(txt) : [];
    return res.status(200).json(data);
  }catch(e){
    return res.status(500).json({ error:"server_error", message:String(e) });
  }
}
