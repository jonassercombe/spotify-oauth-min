// api/playlists/sync-items.js
export const config = { runtime: "nodejs" };

import crypto from "crypto";

/* ---------- utils ---------- */
function need(n){const v=process.env[n]; if(!v) throw new Error(`missing env: ${n}`); return v;}
async function readBody(req){ if(req.body && typeof req.body==="object") return req.body;
  return new Promise(res=>{ let d=""; req.on("data",c=>d+=c); req.on("end",()=>{ try{res(JSON.parse(d||"{}"))}catch{res({})} }); });
}
async function sb(path, init={}) {
  const url = need("SUPABASE_URL") + path;
  const headers = {
    apikey: need("SUPABASE_SERVICE_ROLE_KEY"),
    Authorization: `Bearer ${need("SUPABASE_SERVICE_ROLE_KEY")}`,
    "Content-Type": "application/json",
    ...(init.headers||{})
  };
  return fetch(url, {...init, headers});
}
function decryptToken(b64){
  const hex = need("ENC_SECRET");
  if(hex.length<64) throw new Error("ENC_SECRET must be 32-byte hex (64 chars)");
  const key = Buffer.from(hex,"hex");
  const raw = Buffer.from(String(b64),"base64");
  const iv = raw.subarray(0,12), tag = raw.subarray(12,28), ct = raw.subarray(28);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}
async function refreshAccessToken(refresh_token){
  const body = new URLSearchParams({
    grant_type:"refresh_token",
    refresh_token,
    client_id: need("SPOTIFY_CLIENT_ID"),
    client_secret: need("SPOTIFY_CLIENT_SECRET")
  });
  const r = await fetch("https://accounts.spotify.com/api/token", {
    method:"POST", headers:{ "Content-Type":"application/x-www-form-urlencoded" }, body
  });
  const j = await r.json();
  if(!r.ok || !j.access_token) throw new Error(`spotify refresh failed: ${r.status} ${JSON.stringify(j)}`);
  return j.access_token;
}

/* ---------- fetch playlist + tracks ---------- */
async function getPlaylistRow(playlist_row_id){
  const r = await sb(`/rest/v1/playlists?select=id,playlist_id,connection_id,bubble_user_id&limit=1&id=eq.${encodeURIComponent(playlist_row_id)}`);
  if(!r.ok) throw new Error(`supabase select playlist failed: ${r.status} ${await r.text()}`);
  const arr = await r.json(); return arr[0];
}
async function getConnectionById(connection_id){
  const r = await sb(`/rest/v1/spotify_connections?select=id,refresh_token_enc&limit=1&id=eq.${encodeURIComponent(connection_id)}`);
  if(!r.ok) throw new Error(`supabase select connection failed: ${r.status} ${await r.text()}`);
  const arr = await r.json(); return arr[0];
}
async function fetchAllTracks(spotify_playlist_id, access_token){
  const out = [];
  let url = `https://api.spotify.com/v1/playlists/${encodeURIComponent(spotify_playlist_id)}/tracks?limit=100&offset=0&fields=items(added_at,track(id,name,uri,popularity,duration_ms,preview_url,album(name,images),artists(name))),total,next,offset`;
  while(url){
    const r = await fetch(url, { headers:{ Authorization:`Bearer ${access_token}` }});
    const j = await r.json();
    if(!r.ok) throw new Error(`spotify playlist tracks failed: ${r.status} ${JSON.stringify(j)}`);
    out.push(...(j.items || []));
    url = j.next;
  }
  return out;
}

function chunk(arr,n){ const out=[]; for(let i=0;i<arr.length;i+=n) out.push(arr.slice(i,i+n)); return out; }

/* ---------- handler ---------- */
export default async function handler(req,res){
  try{
    // CORS + method
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,x-app-secret");
    if(req.method==="OPTIONS") return res.status(204).end();
    if(req.method!=="POST") return res.status(405).json({ error:"method_not_allowed" });

    // optionaler Secret-Header
    const expected = process.env.APP_WEBHOOK_SECRET;
    if(expected){
      const got = req.headers["x-app-secret"];
      if(got!==expected) return res.status(401).json({ error:"unauthorized" });
    }

    // body
    const body = await readBody(req);
    let { playlist_row_id, spotify_playlist_id } = body;
    if(!playlist_row_id && !spotify_playlist_id) return res.status(400).json({ error:"missing_playlist_identifier" });

    // Falls nur Spotify-ID kam → Zeile nachschlagen
    if (!playlist_row_id && spotify_playlist_id) {
      const r = await sb(`/rest/v1/playlists?select=id,playlist_id,connection_id,bubble_user_id&limit=1&playlist_id=eq.${encodeURIComponent(spotify_playlist_id)}`);
      if(!r.ok) return res.status(500).json({ error:"supabase_select_failed", body: await r.text() });
      const arr = await r.json();
      if(!arr[0]) return res.status(404).json({ error:"playlist_not_found_by_spotify_id" });
      playlist_row_id = arr[0].id;
    }

    // lookup playlist + connection
    const p = await getPlaylistRow(playlist_row_id);
    if(!p) return res.status(404).json({ error:"playlist_not_found" });

    const conn = await getConnectionById(p.connection_id);
    if(!conn) return res.status(404).json({ error:"connection_not_found" });

    // access token
    const refresh_token = decryptToken(conn.refresh_token_enc);
    const access_token = await refreshAccessToken(refresh_token);

    // fetch tracks
    const items = await fetchAllTracks(p.playlist_id, access_token);

    // transform -> rows (eine Zeile je (playlist_id, position))
    const rows = [];
    for(let i=0;i<items.length;i++){
      const it = items[i] || {};
      const t  = it.track || {};
      const album = t.album || {};
      const artists = Array.isArray(t.artists) ? t.artists : [];
      rows.push({
        playlist_id: playlist_row_id,            // FK (uuid) -> playlists.id
        position: i,                             // 0-basiert
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

    // UPSERT in Batches: on_conflict=(playlist_id,position)
    const batches = chunk(rows, 500);
    let upserts = 0;
    for (const b of batches) {
      const up = await sb(`/rest/v1/playlist_items?on_conflict=playlist_id,position`, {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify(b),
      });
      if (!up.ok) {
        const txt = await up.text();
        return res.status(500).json({ error: "upsert_items_failed", body: txt });
      }
      upserts += b.length;
    }

    // CLEANUP: entferne Zeilen mit Position >= neuer Länge (falls Playlist kürzer wurde)
    // (PostgREST: position=gt.X)
    const maxKeep = Math.max(0, rows.length - 1);
    const delUrl = `/rest/v1/playlist_items?playlist_id=eq.${encodeURIComponent(playlist_row_id)}&position=gt.${maxKeep}`;
    const del = await sb(delUrl, { method: "DELETE", headers: { Prefer: "return=minimal" } });
    if (!del.ok) {
      // Kein harter Abbruch, nur als Hinweis zurückgeben
      const dtxt = await del.text();
      return res.status(200).json({ ok: true, inserted_or_updated: upserts, total_spotify: items.length, cleanup_warning: dtxt });
    }

    return res.status(200).json({ ok:true, inserted_or_updated: upserts, total_spotify: items.length });
  }catch(e){
    return res.status(500).json({ error:"server_error", message:String(e) });
  }
}
