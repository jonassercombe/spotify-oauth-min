// lib/supabase.ts
import { createClient } from '@supabase/supabase-js';

const url = process.env.SUPABASE_URL!;
const anon = process.env.SUPABASE_ANON_KEY!;
const service = process.env.SUPABASE_SERVICE_ROLE_KEY!;

export const supabaseAsAnon = () => createClient(url, anon, { auth: { persistSession: false }});
export const supabaseAsService = () => createClient(url, service, { auth: { persistSession: false }});

// Für UI-Calls mit User-JWT (kommt von Bubble)
export const supabaseWithBearer = (jwt: string) => {
  const c = createClient(url, anon, { auth: { persistSession: false } });
  // @ts-ignore
  c.auth.setAuth(jwt);
  return c;
};

// Hilfsfunktion: prüft, ob caller Zugriff auf playlist_id hat (RLS schützt zusätzlich)
export async function assertUserAccessToPlaylist(sb: ReturnType<typeof supabaseWithBearer>, playlist_id: string) {
  const { data, error } = await sb
    .from('playlists')
    .select('id')
    .eq('id', playlist_id)
    .limit(1)
    .maybeSingle();
  if (error) throw error;
  if (!data) {
    const e: any = new Error('Playlist not found or not accessible');
    e.status = 404;
    throw e;
  }
}
