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
const sleep = (ms)=>new Promise(r=>setTimeout(r, ms));
async function mapLimited(items, limit, mapper){
  const out=[]; let i=0, running=0;
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

export default async function handler(req,res){
  try{
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

    // fällige "needs_sync" Playlists holen
    const limit = Number(req.query.limit || "50"); // pro Run
    const q =
      `/rest/v1/playlists?select=id&connection_id=eq.${encodeURIComponent(connection_id)}&needs_sync=is.true&limit=${limit}`;
    const r = await sb(q);
    if(!r.ok) return res.status(500).json({ error:"supabase_select_failed", body: await r.text() });
    const rows = await r.json();
    if(rows.length===0) return res.status(200).json({ ok:true, synced:0 });

    const base = process.env.PUBLIC_BASE_URL || ""; // z.B. https://spotify-oauth-min.vercel.app
    const syncUrl = `${base}/api/playlists/sync-items`; // deine existierende Route

    let synced=0, failed=0;
    await mapLimited(rows, Number(req.query.concurrency || "3"), async (row)=>{
      const r = await fetch(syncUrl, {
        method:"POST",
        headers:{ "Content-Type":"application/json", "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
        body: JSON.stringify({ playlist_row_id: row.id })
      });
      const ok = r.ok;
      if (ok) {
        // needs_sync zurücksetzen
        await sb(`/rest/v1/playlists?id=eq.${encodeURIComponent(row.id)}`, {
          method:"PATCH", headers:{ Prefer:"return=minimal" }, body: JSON.stringify({ needs_sync: false })
        });
        synced++;
      } else {
        failed++;
      }
      await sleep(80);
    });

    return res.status(200).json({ ok:true, synced, failed });
  }catch(e){
    return res.status(500).json({ error:"server_error", message:String(e) });
  }
}
