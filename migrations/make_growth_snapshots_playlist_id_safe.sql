-- Keep growth snapshots recoverable when a local playlist row is recreated.
-- Historical follower data must be keyed by the stable Spotify playlist id,
-- not only by public.playlists.id, because local rows can be deleted/recreated
-- during account reconnect or ownership cleanup.

alter table public.playlist_followers_daily
  add column if not exists spotify_playlist_id text;

alter table public.playlist_followers_history
  add column if not exists spotify_playlist_id text,
  add column if not exists bubble_user_id text,
  add column if not exists connection_id uuid;

alter table public.playlist_growth_notes
  add column if not exists spotify_playlist_id text;

update public.playlist_followers_daily d
   set spotify_playlist_id = p.playlist_id
  from public.playlists p
 where d.playlist_id = p.id
   and d.spotify_playlist_id is null;

update public.playlist_followers_history h
   set spotify_playlist_id = p.playlist_id,
       bubble_user_id = p.bubble_user_id,
       connection_id = p.connection_id
  from public.playlists p
 where h.playlist_id = p.id
   and (h.spotify_playlist_id is null or h.bubble_user_id is null or h.connection_id is null);

update public.playlist_growth_notes n
   set spotify_playlist_id = p.playlist_id
  from public.playlists p
 where n.playlist_id = p.id
   and n.spotify_playlist_id is null;

create index if not exists pfd_stable_playlist_day_idx
  on public.playlist_followers_daily (bubble_user_id, spotify_playlist_id, day);

create index if not exists pfh_stable_playlist_day_idx
  on public.playlist_followers_history (bubble_user_id, spotify_playlist_id, day);

create index if not exists pgn_stable_playlist_day_idx
  on public.playlist_growth_notes (bubble_user_id, spotify_playlist_id, day);

drop index if exists public.playlist_followers_daily_stable_uq;
drop index if exists public.playlist_followers_history_stable_uq;

do $$
begin
  if exists (
    select 1 from pg_constraint
    where conrelid = 'public.playlist_followers_daily'::regclass
      and conname = 'playlist_followers_daily_playlist_id_fkey'
  ) then
    alter table public.playlist_followers_daily
      drop constraint playlist_followers_daily_playlist_id_fkey;
  end if;

  if exists (
    select 1 from pg_constraint
    where conrelid = 'public.playlist_followers_history'::regclass
      and conname = 'playlist_followers_history_playlist_id_fkey'
  ) then
    alter table public.playlist_followers_history
      drop constraint playlist_followers_history_playlist_id_fkey;
  end if;

  if exists (
    select 1 from pg_constraint
    where conrelid = 'public.playlist_growth_notes'::regclass
      and conname = 'playlist_growth_notes_playlist_id_fkey'
  ) then
    alter table public.playlist_growth_notes
      drop constraint playlist_growth_notes_playlist_id_fkey;
  end if;

  if exists (
    select 1 from pg_constraint
    where conrelid = 'public.playlist_followers_daily'::regclass
      and conname = 'fk_pfd_connection'
  ) then
    alter table public.playlist_followers_daily
      drop constraint fk_pfd_connection;
  end if;
end $$;

alter table public.playlist_followers_daily
  add constraint playlist_followers_daily_playlist_id_fkey
  foreign key (playlist_id) references public.playlists(id) on delete no action
  deferrable initially immediate;

alter table public.playlist_followers_history
  add constraint playlist_followers_history_playlist_id_fkey
  foreign key (playlist_id) references public.playlists(id) on delete no action
  deferrable initially immediate;

alter table public.playlist_growth_notes
  add constraint playlist_growth_notes_playlist_id_fkey
  foreign key (playlist_id) references public.playlists(id) on delete no action
  deferrable initially immediate;

alter table public.playlist_followers_daily
  add constraint fk_pfd_connection
  foreign key (connection_id) references public.spotify_connections(id) on delete no action
  deferrable initially immediate;
