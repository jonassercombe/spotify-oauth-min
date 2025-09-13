// lib/spotify.ts
type TokenBundle = { access_token: string; expires_at: string | null; refresh_token?: string | null; connection_id?: string };

async function refreshSpotifyToken(connection_id: string) {
  // Hole refresh_token etc. aus eurer "connections"-Tabelle
  // Annahme: connections(id uuid, provider text, access_token text, refresh_token text, expires_at timestamptz, spotify_user_id text)
  // und provider='spotify'
  const { supabaseAsService } = await import('./supabase');
  const sb = supabaseAsService();

  const { data: conn, error } = await sb
    .from('connections')
    .select('id, access_token, refresh_token, expires_at')
    .eq('id', connection_id)
    .eq('provider', 'spotify')
    .maybeSingle();

  if (error || !conn) throw error ?? new Error('Connection not found');

  // Falls noch gültig, einfach zurück
  if (conn.expires_at && new Date(conn.expires_at).getTime() - Date.now() > 60_000) {
    return { access_token: conn.access_token as string };
  }

  // Refresh beim Spotify Token Endpoint
  const basic = Buffer.from(`${process.env.SPOTIFY_CLIENT_ID}:${process.env.SPOTIFY_CLIENT_SECRET}`).toString('base64');
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: conn.refresh_token,
  });

  const res = await fetch('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: { 'Authorization': `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Spotify refresh failed: ${res.status} ${text}`);
  }

  const json = await res.json();
  const newAccess = json.access_token as string;
  const expiresIn = json.expires_in as number | undefined;

  // Persistieren
  await sb.from('connections').update({
    access_token: newAccess,
    // Spotify liefert beim Refresh nicht immer ein neues refresh_token:
    refresh_token: json.refresh_token ?? conn.refresh_token,
    expires_at: expiresIn ? new Date(Date.now() + expiresIn * 1000).toISOString() : null
  }).eq('id', connection_id);

  return { access_token: newAccess };
}

export async function getSpotifyTokenForPlaylist(playlist_id: string) {
  // Hole connection_id über playlists.connection_id (Annahme)
  const { supabaseAsService } = await import('./supabase');
  const sb = supabaseAsService();
  const { data, error } = await sb
    .from('playlists')
    .select('connection_id')
    .eq('id', playlist_id)
    .maybeSingle();
  if (error || !data) throw error ?? new Error('Playlist not found');
  return refreshSpotifyToken(data.connection_id);
}

export type PlaylistItems = { items: string[]; snapshot_id: string };

export async function fetchPlaylistState(playlist_id: string, access_token: string): Promise<PlaylistItems> {
  // Wir ziehen snapshot_id + alle Track-IDs
  // Tipp: Felder einschränken spart Rate Limit
  const base = `https://api.spotify.com/v1/playlists/${playlist_id}`;
  // Erst Seite 1
  const first = await fetch(`${base}?fields=snapshot_id,tracks(items(track(id)),total,limit,next)`, {
    headers: { Authorization: `Bearer ${access_token}` }
  });
  if (first.status === 429) await backoffFrom429(first);
  if (!first.ok) throw new Error(`Spotify playlist fetch failed: ${first.status} ${await first.text()}`);
  const j = await first.json();

  const out: string[] = [];
  let next = j.tracks?.next ?? null;
  for (const it of (j.tracks?.items ?? [])) {
    if (it?.track?.id) out.push(it.track.id as string);
  }
  while (next) {
    const r = await fetch(next, { headers: { Authorization: `Bearer ${access_token}` }});
    if (r.status === 429) await backoffFrom429(r);
    if (!r.ok) throw new Error(`Spotify playlist page failed: ${r.status} ${await r.text()}`);
    const jj = await r.json();
    for (const it of (jj.items ?? [])) {
      if (it?.track?.id) out.push(it.track.id as string);
    }
    next = jj.next ?? null;
  }
  return { items: out, snapshot_id: j.snapshot_id as string };
}

export async function reorderTrack({
  playlist_id, access_token, range_start, insert_before, snapshot_id
}: { playlist_id: string; access_token: string; range_start: number; insert_before: number; snapshot_id?: string }): Promise<string> {
  const url = `https://api.spotify.com/v1/playlists/${playlist_id}/tracks`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${access_token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ range_start, insert_before, snapshot_id }),
  });
  if (res.status === 429) await backoffFrom429(res);
  if (!res.ok) {
    const text = await res.text();
    const err = new Error(`Spotify reorder failed: ${res.status} ${text}`) as any;
    // Mark conflict for caller
    if (res.status === 409) err.code = 409;
    throw err;
  }
  const json = await res.json();
  return json.snapshot_id as string;
}

export async function reorderWithRetry(args: Parameters<typeof reorderTrack>[0] & { maxRetries?: number }) {
  const maxRetries = Number(process.env.ENFORCE_MAX_RETRIES ?? 3);
  let attempt = 0;
  while (true) {
    try {
      return await reorderTrack(args);
    } catch (e: any) {
      if (e.code === 409 && attempt < maxRetries) {
        // Snapshot conflict: frisches snapshot holen und einmal neu probieren
        const { fetchPlaylistState } = await import('./spotify');
        const state = await fetchPlaylistState(args.playlist_id, args.access_token);
        args.snapshot_id = state.snapshot_id;
        attempt++;
        continue;
      }
      throw e;
    }
  }
}

async function backoffFrom429(res: Response) {
  const ra = Number(res.headers.get('Retry-After') ?? '1');
  await new Promise(r => setTimeout(r, Math.min(ra, 10) * 1000));
}
