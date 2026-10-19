alter table public.curator_accepted_tracks
  drop constraint if exists curator_accepted_tracks_platform_check;

alter table public.curator_accepted_tracks
  add constraint curator_accepted_tracks_platform_check
  check (platform in ('groover', 'playlistpush', 'submithub')) not valid;

alter table public.curator_accepted_tracks
  validate constraint curator_accepted_tracks_platform_check;

create or replace function public.reconcile_curator_placements(p_playlist_id uuid)
returns table (activated_count integer, waiting_count integer)
language plpgsql
security invoker
set search_path = public, pg_temp
as $$
declare
  v_activated integer := 0;
  v_waiting integer := 0;
begin
  with spotify_presence as (
    select item.track_id, min(item.added_at) as added_at, min(item.position) as position
    from public.playlist_items item
    where item.playlist_id = p_playlist_id and item.added_at is not null
    group by item.track_id
  ), activated as (
    update public.curator_accepted_tracks accepted
    set playlist_added_at = presence.added_at,
        expires_at = presence.added_at + make_interval(weeks => coalesce(accepted.manual_expiry_weeks, case when accepted.platform = 'groover' then 4 else 8 end)),
        matched_at = now(),
        manual_expiry_weeks = coalesce(accepted.manual_expiry_weeks, case when accepted.platform = 'groover' then 4 else 8 end),
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
  select p_playlist_id, activated.spotify_track_id, presence.position, false, 'platform_acceptance_expiry', activated.manual_expiry_weeks
  from activated
  join spotify_presence presence on presence.track_id = activated.spotify_track_id
  on conflict (playlist_id, track_id) do update set expiry_weeks = excluded.expiry_weeks;

  get diagnostics v_activated = row_count;

  select count(*)::integer into v_waiting
  from public.curator_accepted_tracks accepted
  where accepted.playlist_id = p_playlist_id
    and accepted.playlist_added_at is null
    and accepted.expiry_status in ('pending', 'assigned');

  return query select v_activated, v_waiting;
end;
$$;

revoke all on function public.reconcile_curator_placements(uuid) from public, anon, authenticated;
grant execute on function public.reconcile_curator_placements(uuid) to service_role;
