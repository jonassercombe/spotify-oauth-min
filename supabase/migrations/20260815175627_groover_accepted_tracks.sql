create table if not exists public.curator_accepted_tracks (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid not null references auth.users(id) on delete cascade,
  bubble_user_id text not null,
  platform text not null check (platform in ('groover')),
  platform_profile text not null default '',
  platform_submission_id text not null,
  spotify_track_id text not null check (spotify_track_id ~ '^[A-Za-z0-9]{22}$'),
  spotify_track_url text not null,
  track_title text not null,
  artist_names text[] not null default '{}',
  platform_playlists text[] not null default '{}',
  accepted_at timestamptz not null default now(),
  manual_expiry_weeks integer check (manual_expiry_weeks between 1 and 104),
  expiry_status text not null default 'pending'
    check (expiry_status in ('pending', 'assigned', 'applied', 'ignored')),
  metadata jsonb not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (auth_user_id, platform, platform_submission_id)
);

create index if not exists curator_accepted_tracks_user_status_idx
  on public.curator_accepted_tracks (auth_user_id, expiry_status, accepted_at desc);

alter table public.curator_accepted_tracks enable row level security;

revoke all on table public.curator_accepted_tracks from anon, authenticated;
grant all on table public.curator_accepted_tracks to service_role;
