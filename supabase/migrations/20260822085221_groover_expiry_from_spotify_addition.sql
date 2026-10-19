alter table public.curator_accepted_tracks
  add column if not exists playlist_id uuid references public.playlists(id) on delete set null,
  add column if not exists playlist_added_at timestamptz,
  add column if not exists expires_at timestamptz,
  add column if not exists matched_at timestamptz;

comment on column public.curator_accepted_tracks.playlist_added_at is
  'Immutable Spotify playlist added_at value that starts the placement expiry timer.';

update public.curator_accepted_tracks
set manual_expiry_weeks = 4,
    expiry_status = 'assigned',
    updated_at = now()
where platform = 'groover'
  and manual_expiry_weeks is null
  and expiry_status in ('pending', 'assigned');

-- Resolve an unambiguous PlaylistPilot playlist from Groover's selected playlist
-- label. A mismatch deliberately remains pending instead of risking the wrong list.
with candidates as (
  select accepted.id as accepted_track_id, min(playlist.id::text)::uuid as playlist_id
  from public.curator_accepted_tracks accepted
  join public.playlists playlist
    on playlist.bubble_user_id = accepted.bubble_user_id
   and exists (
     select 1
     from unnest(accepted.platform_playlists) platform_playlist(name)
     where lower(trim(platform_playlist.name)) = lower(trim(playlist.name))
   )
  where accepted.platform = 'groover'
    and accepted.playlist_id is null
  group by accepted.id
  having count(*) = 1
)
update public.curator_accepted_tracks accepted
set playlist_id = candidate.playlist_id,
    updated_at = now()
from candidates candidate
where accepted.platform = 'groover'
  and accepted.id = candidate.accepted_track_id;

create index if not exists curator_accepted_tracks_waiting_playlist_track_idx
  on public.curator_accepted_tracks (playlist_id, spotify_track_id)
  where playlist_added_at is null and expiry_status in ('pending', 'assigned');

create index if not exists curator_accepted_tracks_active_expiry_idx
  on public.curator_accepted_tracks (playlist_id, expires_at)
  where expiry_status = 'applied';

create or replace function public.reconcile_groover_placements(p_playlist_id uuid)
returns table (activated_count integer, waiting_count integer)
language plpgsql
security invoker
set search_path = public, pg_temp
as $$
declare
  v_activated integer := 0;
  v_waiting integer := 0;
begin
  -- Late playlist imports and pre-releases are resolved here. playlist_added_at
  -- and expires_at are written only once, so retries and concurrent syncs cannot
  -- move an already-started timer.
  with spotify_presence as (
    select
      item.track_id,
      min(item.added_at) as added_at,
      min(item.position) as position
    from public.playlist_items item
    where item.playlist_id = p_playlist_id
      and item.added_at is not null
    group by item.track_id
  ), activated as (
    update public.curator_accepted_tracks accepted
    set playlist_added_at = presence.added_at,
        expires_at = presence.added_at
          + make_interval(weeks => coalesce(accepted.manual_expiry_weeks, 4)),
        matched_at = now(),
        manual_expiry_weeks = coalesce(accepted.manual_expiry_weeks, 4),
        expiry_status = 'applied',
        updated_at = now()
    from spotify_presence presence
    where accepted.playlist_id = p_playlist_id
      and accepted.spotify_track_id = presence.track_id
      and accepted.playlist_added_at is null
      and accepted.expiry_status in ('pending', 'assigned')
    returning accepted.spotify_track_id, accepted.manual_expiry_weeks
  )
  insert into public.playlist_item_locks (
    playlist_id, track_id, locked_position, is_locked, lock_source, expiry_weeks
  )
  select
    p_playlist_id,
    activated.spotify_track_id,
    presence.position,
    false,
    'groover_expiry',
    activated.manual_expiry_weeks
  from activated
  join spotify_presence presence on presence.track_id = activated.spotify_track_id
  on conflict (playlist_id, track_id) do update
    set expiry_weeks = excluded.expiry_weeks;

  get diagnostics v_activated = row_count;

  select count(*)::integer into v_waiting
  from public.curator_accepted_tracks accepted
  where accepted.playlist_id = p_playlist_id
    and accepted.playlist_added_at is null
    and accepted.expiry_status in ('pending', 'assigned');

  return query select v_activated, v_waiting;
end;
$$;

revoke all on function public.reconcile_groover_placements(uuid) from public, anon, authenticated;
grant execute on function public.reconcile_groover_placements(uuid) to service_role;
