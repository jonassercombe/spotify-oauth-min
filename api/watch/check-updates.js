export const config = { runtime: "nodejs" };

function need(n){const v=process.env[n]; if(!v) throw new Error(`missing env: ${n}`); return v;}
async function sb(path, init={}) {
  const url = need("SUPABASE_URL") + path;
  const headers = {
    apikey: need("SUPABASE_SERVICE_ROLE_KEY"),
    Authorization: `Bearer ${need("SUPABASE_SERVICE_ROLE_KEY")}`,
    "Content-Type": "application/json",
    ...(init.headers||{}),
  };
  return fetch(url, { ...init, headers });
}
import crypto from "crypto";
function decryptToken(b64){
  const key = Buffer.from(need("ENC_SECRET"), "hex");
  const raw = Buffer.from(String(b64), "base64");
  const iv=raw.subarray(0,12), tag=raw.subarray(12,28), ct=raw.subarray(28);
  const d=crypto.createDecipheriv("aes-256-gcm", key, iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}
async function getAccessToken(connection_id){
  const r = await sb(`/rest/v1/spotify_connections?select=refresh_token_enc&limit=1&id=eq.${encodeURIComponent(connection_id)}`);
  const arr = await r.json();
  if(!arr[0]) throw new Error("connection_not_found");
  const refresh_token = decryptToken(arr[0].refresh_token_enc);
  const body = new URLSearchParams({
    grant_type:"refresh_token",
    refresh_token,
    client_id: need("SPOTIFY_CLIENT_ID"),
    client_secret: need("SPOTIFY_CLIENT_SECRET"),
  });
  const t = await fetch("https://accounts.spotify.com/api/token", {
    method:"POST", headers:{ "Content-Type":"application/x-www-form-urlencoded" }, body
  });
  const j = await t.json();
  if(!t.ok || !j.access_token) throw new Error(`refresh_failed ${t.status} ${JSON.stringify(j)}`);
  return j.access_token;
}
async function getCooldown(connection_id){
  const r = await sb(`/rest/v1/connection_rl_state?select=cooldown_until&connection_id=eq.${encodeURIComponent(connection_id)}&limit=1`);
  const a = await r.json();
  return a[0]?.cooldown_until ? new Date(a[0].cooldown_until) : null;
}
async function setCooldown(connection_id, untilIso){
  await sb(`/rest/v1/connection_rl_state`, {
    method:"POST",
    headers:{ Prefer:"resolution=merge-duplicates" },
    body: JSON.stringify({ connection_id, cooldown_until: untilIso })
  });
}
const sleep = (ms)=>new Promise(r=>setTimeout(r, ms));
async function mapLimited(items, limit, mapper){
  const out = []; let i=0, running=0;
  return await new Promise((resolve,reject)=>{
    const kick=()=>{
      while(running<limit && i<items.length){
        const idx=i++; running++;
        Promise.resolve(mapper(items[idx], idx)).then(v=>{ out[idx]=v; running--; kick(); }).catch(reject);
      }
      if(running===0 && i>=items.length) resolve(out);
    };
    kick();
  });
}
function backoffNext(prevChanged, prevCheckedAt){
  // adaptiv: bei Änderung → 5–15 min; bei stabil → exponentiell bis 6h
  if (prevChanged) return 5 * 60 * 1000; // 5min
  // einfache Heuristik: 15min, 30min, 60min, 2h, 4h, 6h
  return 15 * 60 * 1000;
}

export default async function handler(req,res){
  try{
    // CORS
    res.setHeader("Access-Control-Allow-Origin","*");
    res.setHeader("Access-Control-Allow-Methods","POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers","Content-Type,x-app-secret");
    if(req.method==="OPTIONS") return res.status(204).end();
    if(req.method!=="POST") return res.status(405).json({ error:"method_not_allowed" });

    const expected=process.env.APP_WEBHOOK_SECRET;
    if(expected && req.headers["x-app-secret"]!==expected) return res.status(401).json({ error:"unauthorized" });

    const { connection_id } = await (async()=> {
      if (req.body && typeof req.body==="object") return req.body;
      return await new Promise(r=>{ let d=""; req.on("data",c=>d+=c); req.on("end",()=>{ try{r(JSON.parse(d||"{}"))}catch{r({})} }); });
    })();
    if(!connection_id) return res.status(400).json({ error:"missing_connection_id" });

    // globaler cooldown?
    const cd = await getCooldown(connection_id);
    if (cd && cd > new Date()) {
      return res.status(200).json({ ok:true, skipped:true, reason:"cooldown", until: cd.toISOString() });
    }

    // fällige Playlists ziehen
    const limit = Number(req.query.limit || "200");   // pro Run
    const order = encodeURIComponent("next_check_at.asc.nullsfirst");
    const q =
      `/rest/v1/playlists?select=id,playlist_id,snapshot_id,next_check_at,last_snapshot_checked_at` +
      `&connection_id=eq.${encodeURIComponent(connection_id)}` +
      `&is_owner=is.true&is_public=is.true` +
      `&or=(next_check_at.is.null,next_check_at.lte.${encodeURIComponent(new Date().toISOString())})` +
      `&order=${order}&limit=${limit}`;
    const sel = await sb(q);
    if(!sel.ok) return res.status(500).json({ error:"supabase_select_failed", body: await sel.text() });
    const rows = await sel.json();
    if(rows.length===0) return res.status(200).json({ ok:true, checked:0, updated:0, marked:0 });

    const token = await getAccessToken(connection_id);

    let marked=0, updated=0, checked=0, got429=false, retryAfter=1;

    await mapLimited(rows, Number(req.query.concurrency || "4"), async (row) => {
      if (got429) return; // soft stop
      // HEAD-light: snapshot_id only
      const r = await fetch(
        `https://api.spotify.com/v1/playlists/${encodeURIComponent(row.playlist_id)}?fields=snapshot_id`,
        { headers:{ Authorization:`Bearer ${token}` } }
      );
      if (r.status === 429) {
        got429 = true;
        retryAfter = Number(r.headers.get("retry-after") || "5");
        return;
      }
      const j = await r.json().catch(()=>({}));
      if (!r.ok) {
        // softer Fehler: schiebe next_check um 30min
        const next = new Date(Date.now() + 30*60*1000).toISOString();
        await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(row.id)}`, {
          method:"PATCH", headers:{ Prefer:"return=minimal" },
          body: JSON.stringify({ next_check_at: next, last_snapshot_checked_at: new Date().toISOString(), error_count: (row.error_count||0)+1 })
        });
        return;
      }
      const current = j?.snapshot_id || null;
      const changed = current && row.snapshot_id && current !== row.snapshot_id;
      const nowIso = new Date().toISOString();
      const nextMs = backoffNext(changed, row.last_snapshot_checked_at);
      const nextIso = new Date(Date.now() + nextMs).toISOString();

      // wenn neu/anders → needs_sync markieren (Tracks später ziehen)
      const patch = {
        last_snapshot_checked_at: nowIso,
        next_check_at: nextIso
      };
      if (current && current !== row.snapshot_id) {
        patch.needs_sync = true;
        patch.snapshot_id = current; // optional: schon vorab aktualisieren
        marked++;
      }
      const up = await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(row.id)}`, {
        method:"PATCH", headers:{ Prefer:"return=minimal" }, body: JSON.stringify(patch)
      });
      if (up.ok) updated++;
      checked++;
      // kleine Pause zwischen Calls (sanfter)
      await sleep(40);
    });

    if (got429) {
      const until = new Date(Date.now() + (retryAfter + 0.5) * 1000).toISOString();
      await setCooldown(connection_id, until);
      return res.status(200).json({ ok:true, hit_429:true, retry_after: retryAfter, set_cooldown_until: until, checked, marked, updated });
    }

    return res.status(200).json({ ok:true, checked, marked, updated });
  }catch(e){
    return res.status(500).json({ error:"server_error", message:String(e) });
  }
}
