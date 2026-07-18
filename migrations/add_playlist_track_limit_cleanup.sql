alter table public.playlists
  add column if not exists track_limit_enabled boolean not null default false,
  add column if not exists track_limit_count integer,
  add column if not exists track_limit_strategy text not null default 'back';

alter table public.playlists
  drop constraint if exists playlists_track_limit_count_check;

alter table public.playlists
  add constraint playlists_track_limit_count_check
  check (track_limit_count is null or (track_limit_count >= 1 and track_limit_count <= 10000));

alter table public.playlists
  drop constraint if exists playlists_track_limit_strategy_check;

alter table public.playlists
  add constraint playlists_track_limit_strategy_check
  check (track_limit_strategy in ('back', 'oldest'));
