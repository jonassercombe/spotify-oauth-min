// pages/api/[...task].ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { sbService, assertBubbleUserExists, assertPlaylistOwnership } from '../../lib/supabase';

function bad(res: NextApiResponse, status: number, msg: string) {
  return res.status(status).json({ error: msg });
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    const path = (req.query.task as string[] | undefined) ?? [];
    const [ns, action] = [path[0], path[1]]; // e.g. locks/set
    const sb = sbService();

    // Bubble schickt nur diese Header:
    const bubbleUserId = (req.headers['x-bubble-user-id'] || req.headers['x-bubble-user-id'.toLowerCase()]) as string | undefined;

    // ---------- LOCKS / SET ----------
    if (ns === 'locks' && action === 'set' && req.method === 'POST') {
      if (!bubbleUserId) return bad(res, 401, 'Missing X-Bubble-User-Id');

      await assertBubbleUserExists(sb, bubbleUserId);

      const { playlist_id, track_id, locked_position, is_locked = true } = req.body ?? {};
      if (!playlist_id || !track_id || !locked_position) {
        return bad(res, 400, 'Missing playlist_id, track_id or locked_position');
      }

      await assertPlaylistOwnership(sb, String(playlist_id), bubbleUserId);

      const { data, error } = await sb
        .from('playlist_item_locks')
        .upsert({
          playlist_id,
          track_id,
          locked_position: Number(locked_position),
          is_locked: !!is_locked,
          locked_at: new Date().toISOString()
        }, { onConflict: 'playlist_id,track_id' })
        .select()
        .maybeSingle();

      if (error) throw error;
      return res.status(200).json({ ok: true, lock: data });
    }

    // ---------- LOCKS / UNSET ----------
    if (ns === 'locks' && action === 'unset' && req.method === 'POST') {
      if (!bubbleUserId) return bad(res, 401, 'Missing X-Bubble-User-Id');

      await assertBubbleUserExists(sb, bubbleUserId);

      const { playlist_id, track_id } = req.body ?? {};
      if (!playlist_id || !track_id) return bad(res, 400, 'Missing playlist_id or track_id');

      await assertPlaylistOwnership(sb, String(playlist_id), bubbleUserId);

      const { error } = await sb
        .from('playlist_item_locks')
        .delete()
        .eq('playlist_id', playlist_id)
        .eq('track_id', track_id);

      if (error) throw error;
      return res.status(200).json({ ok: true });
    }

    // ---------- PLAYLISTS / ENFORCE (Cron/Server) ----------
    if (ns === 'playlists' && action === 'enforce' && req.method === 'POST') {
      const { playlist_id } = req.body ?? {};
      if (!playlist_id) return bad(res, 400, 'Missing playlist_id');

      // Optional: Secret Header prüfen (damit nur Cron/Server callen kann)
      // if (req.headers['x-service-key'] !== process.env.INTERNAL_SERVICE_KEY) return bad(res, 401, 'Unauthorized');

      // Cleanup + Enforce aus deiner bestehenden Logik, z.B.:
      const { cleanupMissingLocks } = await import('../../lib/enforce');
      const { enforcePlaylistLocks } = await import('../../lib/enforce');

      await cleanupMissingLocks(playlist_id);
      const result = await enforcePlaylistLocks(playlist_id);
      return res.status(200).json({ ok: true, ...result });
    }

    // ---------- Fallback ----------
    return bad(res, 404, 'Unknown route');
  } catch (e: any) {
    console.error(e);
    return res.status(e?.status ?? 500).json({ error: e?.message ?? 'Internal error' });
  }
}
