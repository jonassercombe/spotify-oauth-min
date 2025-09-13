export const config = { runtime: "nodejs" };
function need(n){const v=process.env[n]; if(!v) throw new Error(`missing env: ${n}`); return v;}
async function sb(path, init={}) {
  const url = need("SUPABASE_URL") + path;
  const headers = { apikey: need("SUPABASE_SERVICE_ROLE_KEY"), Authorization: `Bearer ${need("SUPABASE_SERVICE_ROLE_KEY")}`, "Content-Type":"application/json", ...(init.headers||{}) };
  return fetch(url, { ...init, headers });
}
export default async function handler(req,res){
  try {
    const limit = req.query.limit || "200";
    const concurrency = req.query.concurrency || "4";
    // alle Connections (du kannst pro Run limitieren/paginate’n)
    const r = await sb(`/rest/v1/spotify_connections?select=id`);
    const conns = await r.json();
    let ok=0, fail=0;
    for (const c of conns) {
      const resp = await fetch(`${process.env.PUBLIC_BASE_URL}/api/watch/check-updates?limit=${limit}&concurrency=${concurrency}`,{
        method:"POST",
        headers:{ "Content-Type":"application/json", "x-app-secret": process.env.APP_WEBHOOK_SECRET || "" },
        body: JSON.stringify({ connection_id: c.id })
      });
      resp.ok ? ok++ : fail++;
      // kleine Pause, schont Rate Limit & Vercel
      await new Promise(r=>setTimeout(r, 80));
    }
    res.status(200).json({ ok:true, connections: conns.length, dispatched_ok:ok, dispatched_fail:fail });
  } catch(e){ res.status(500).json({ error:"server_error", message:String(e) }); }
}
