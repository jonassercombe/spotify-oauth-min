// lib/enforce.ts
import { getSpotifyTokenForPlaylist, fetchPlaylistState, reorderWithRetry } from './spotify';
import { supabaseAsService } from './supabase';

export async function cleanupMissingLocks(playlist_id: string) {
  const sb = supabaseAsService();
  // nutzt eure SQL-Funktion aus der Migration
  const { error } = await sb.rpc('locks_cleanup_missing_tracks', { p_playlist_id: playlist_id });
  if (error) throw error;
}

export async function enforcePlaylistLocks(playlist_id: string) {
  const sb = supabaseAsService();
  const { access_token } = await getSpotifyTokenForPlaylist(playlist_id);

  // 1) Aktuellen Zustand + Locks laden
  const state = await fetchPlaylistState(playlist_id, access_token);
  const trackIds = state.items;
  const len = trackIds.length;

  const { data: locks, error } = await sb
    .from('playlist_item_locks')
    .select('track_id, locked_position, is_locked')
    .eq('playlist_id', playlist_id)
    .eq('is_locked', true);

  if (error) throw error;
  if (!locks?.length) return { moved: 0 };

  // 2) Nicht vorhandene (gelöschte) Locks entfernen
  const set = new Set(trackIds);
  const missing = locks.filter(l => !set.has(l.track_id));
  if (missing.length) {
    await sb.from('playlist_item_locks')
      .delete()
      .eq('playlist_id', playlist_id)
      .in('track_id', missing.map(m => m.track_id));
  }

  const active = locks.filter(l => set.has(l.track_id));
  if (!active.length) return { moved: 0 };

  // 3) Zielpositionen normalisieren, sortieren (1-basiert)
  const targets = active.map(l => ({ track_id: l.track_id, target: Math.min(Math.max(1, l.locked_position), Math.max(1, len)) }));
  targets.sort((a, b) => a.target - b.target);

  // Lokale Liste (0-basiert)
  let items = [...trackIds];
  let movedCount = 0;
  let snapshot_id: string | undefined = state.snapshot_id;
  const cooldown = Number(process.env.ENFORCE_MOVE_COOLDOWN_MS ?? 300);

  for (const t of targets) {
    const idxCurrent = items.indexOf(t.track_id); // 0-basiert
    if (idxCurrent < 0) continue;
    const posCurrent = idxCurrent + 1;
    const posTarget = t.target;
    if (posCurrent === posTarget) continue;

    let range_start = idxCurrent;
    let insert_before = posTarget - 1;
    if (insert_before > range_start) insert_before += 1;

    snapshot_id = await reorderWithRetry({
      playlist_id,
      access_token,
      range_start,
      insert_before,
      snapshot_id
    });

    // Lokale Liste updaten
    const [moved] = items.splice(range_start, 1);
    const ib = Math.min(insert_before, items.length);
    items.splice(ib, 0, moved);

    movedCount++;
    await sb.from('playlist_item_locks')
      .update({ last_enforced_at: new Date().toISOString() })
      .eq('playlist_id', playlist_id)
      .eq('track_id', t.track_id);

    if (cooldown > 0) await new Promise(r => setTimeout(r, cooldown));
  }

  // Nach dem Enforce: Items neu syncen (nutze euren bestehenden Endpoint via pg_net oder HTTP)
  // Beispiel: per pg_net rpc triggern (falls vorhanden) oder ignorieren, wenn euer Cron es eh gleich macht.

  return { moved: movedCount };
}
