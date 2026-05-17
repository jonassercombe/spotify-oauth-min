create table if not exists public.playlist_flex_settings (
  playlist_id uuid primary key references public.playlists(id) on delete cascade,
  bubble_user_id text not null references public.app_users(bubble_user_id) on delete cascade,
  connection_id uuid not null references public.spotify_connections(id) on delete cascade,
  reference_playlist_id text,
  reference_playlist_url text,
  interval text not null default 'weekly',
  enabled boolean not null default false,
  next_rotation_at timestamptz,
  last_rotated_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint playlist_flex_settings_interval_check check (interval in ('daily', 'weekly', 'monthly'))
);

create table if not exists public.playlist_flex_slots (
  id uuid primary key default gen_random_uuid(),
  playlist_id uuid not null references public.playlists(id) on delete cascade,
  bubble_user_id text not null references public.app_users(bubble_user_id) on delete cascade,
  connection_id uuid not null references public.spotify_connections(id) on delete cascade,
  position integer not null,
  current_track_id text not null,
  current_track_name text,
  source_playlist_id text,
  source_track_id text,
  last_rotated_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint playlist_flex_slots_position_check check (position >= 0),
  constraint playlist_flex_slots_unique_position unique (playlist_id, position),
  constraint playlist_flex_slots_unique_track unique (playlist_id, current_track_id)
);

create index if not exists idx_playlist_flex_settings_due
  on public.playlist_flex_settings(enabled, next_rotation_at)
  where enabled = true;

create index if not exists idx_playlist_flex_slots_playlist
  on public.playlist_flex_slots(playlist_id, position);

