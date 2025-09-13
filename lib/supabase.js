// lib/supabase.ts
import { createClient } from '@supabase/supabase-js';

const url = process.env.SUPABASE_URL!;
const service = process.env.SUPABASE_SERVICE_ROLE_KEY!;

export const sbService = () => createClient(url, service, { auth: { persistSession: false } });

export async function assertBubbleUserExists(sb: ReturnType<typeof sbService>, bubbleUserId: string) {
  const { data, error } = await sb
    .from('app_users')                // <- Name eurer User-Tabelle (ggf. anpassen)
    .select('id')
    .eq('id', bubbleUserId)
    .limit(1)
    .maybeSingle();
  if (error) throw error;
  if (!data) {
    const e: any = new Error('Unknown bubble_user_id');
    e.status = 401;
    throw e;
  }
}

export async function assertPlaylistOwnership(
  sb: ReturnType<typeof sbService>,
  playlist_id: string,
  bubbleUserId: string
) {
  const { data, error } = await sb
    .from('playlists')
    .select('id')
    .eq('id', playlist_id)
    .eq('bubble_user_id', bubbleUserId)  // <- Feldname ggf. anpassen
    .limit(1)
    .maybeSingle();
  if (error) throw error;
  if (!data) {
    const e: any = new Error('Playlist not owned by user');
    e.status = 403;
    throw e;
  }
}
