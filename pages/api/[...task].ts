// pages/api/[...task].ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { supabaseWithBearer, supabaseAsService, supabaseAsAnon, assertUserAccessToPlaylist } from '../../lib/supabase';
import { enforcePlaylistLocks, cleanupMissingLocks } from '../../lib/enforce';

function bad(res: NextApiResponse, status: number, message: string) {
  return res.status(status).json({ error: message });
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    const path = (req.query.task as string[] | undefined) ?? [];
    const [ns, action] = [path[0], path[1]]; // e.g. locks/set

    if (ns === 'locks' && action === 'set' && req.method === 'POST') {
      /**
       * Body: { playlist_id: string(uuid), track_id: string, locked_position: number, is_locked?: boolean }
       * Auth: Authorization: Bearer <Supabase User JWT>  (aus Bubble)
       */
      const auth = req.headers.authorization?.split(' ')[1];
      if (!auth) return bad(res, 401, 'Missing Authorization Bearer');
      const sb = supabaseWithBearer(auth);

      const { playlist_id, track_id, locked_position, is_locked = true } = req.body ?? {};
      if (!playlist_id || !track_id || !locked_position) return bad(res, 400, 'Missing required fields');

      await assertUserAccessToPlaylist(sb, playlist_id);

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

    if (ns === 'locks' && action === 'unset' && req.method === 'POST') {
      /**
       * Body: { playlist_id: string, track_id: string }
       * Auth: Authorization: Bearer <Supabase User JWT>
       */
      const auth = req.headers.authorization?.split(' ')[1];
      if (!auth) return bad(res, 401, 'Missing Authorization Bearer');
      const sb = supabaseWithBearer(auth);

      const { playlist_id, track_id } = req.body ?? {};
      if (!playlist_id || !track_id) return bad(res, 400, 'Missing required fields');

      await assertUserAccessToPlaylist(sb, playlist_id);

      const { error } = await sb
        .from('playlist_item_locks')
        .delete()
        .eq('playlist_id', playlist_id)
        .eq('track_id', track_id);

      if (error) throw error;
      return res.status(200).json({ ok: true });
    }

    if (ns === 'playlists' && action === 'enforce' && req.method === 'POST') {
      /**
       * Body: { playlist_id: string }
       * Auth: Service-only (von Cron) → optional Header X-Service-Key oder Vercel Cron secret
       * Hier nutzen wir Supabase Service Role intern, kein User-JWT nötig.
       */
      const { playlist_id } = req.body ?? {};
      if (!playlist_id) return bad(res, 400, 'Missing playlist_id');

      // Optional: simples Secret-Gate
      // if (req.headers['x-service-key'] !== process.env.INTERNAL_SERVICE_KEY) return bad(res, 401, 'Unauthorized');

      // Cleanup und Enforce
      await cleanupMissingLocks(playlist_id);
      const result = await enforcePlaylistLocks(playlist_id);
      return res.status(200).json({ ok: true, ...result });
    }

    return bad(res, 404, 'Unknown route');
  } catch (e: any) {
    console.error(e);
    const status = e?.status ?? 500;
    return res.status(status).json({ error: e?.message ?? 'Internal error' });
  }
}
