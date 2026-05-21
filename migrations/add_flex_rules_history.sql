alter table public.playlist_flex_settings
  add column if not exists repeat_cooldown_weeks integer not null default 8,
  add column if not exists avoid_target_duplicates boolean not null default true,
  add column if not exists min_popularity integer,
  add column if not exists max_popularity integer,
  add column if not exists max_release_age_weeks integer;

create table if not exists public.playlist_flex_history (
  id uuid primary key default gen_random_uuid(),
  playlist_id uuid not null references public.playlists(id) on delete cascade,
  slot_id uuid references public.playlist_flex_slots(id) on delete set null,
  bubble_user_id text not null references public.app_users(bubble_user_id) on delete cascade,
  connection_id uuid not null references public.spotify_connections(id) on delete cascade,
  track_id text not null,
  track_name text,
  source_playlist_id text,
  rotated_at timestamptz not null default now()
);

create index if not exists idx_playlist_flex_history_playlist_track
  on public.playlist_flex_history(playlist_id, track_id, rotated_at desc);

create index if not exists idx_playlist_flex_history_slot
  on public.playlist_flex_history(slot_id, rotated_at desc);
