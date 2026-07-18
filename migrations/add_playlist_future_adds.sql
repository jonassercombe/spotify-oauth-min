create table if not exists public.playlist_future_adds (
  id uuid primary key default gen_random_uuid(),
  bubble_user_id text not null,
  playlist_id uuid not null references public.playlists(id) on delete cascade,
  connection_id uuid,
  release_date date not null,
  artist_name text not null,
  track_title text not null,
  target_position integer,
  status text not null default 'pending',
  attempts integer not null default 0,
  spotify_track_id text,
  spotify_track_uri text,
  spotify_track_name text,
  spotify_artist_names text,
  last_error text,
  processed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint playlist_future_adds_status_check check (status in ('pending', 'added', 'not_found', 'failed', 'cancelled')),
  constraint playlist_future_adds_position_check check (target_position is null or target_position >= 1)
);

create index if not exists playlist_future_adds_due_idx
  on public.playlist_future_adds (status, release_date, created_at);

create index if not exists playlist_future_adds_playlist_idx
  on public.playlist_future_adds (playlist_id, release_date);

alter table public.playlist_future_adds enable row level security;
