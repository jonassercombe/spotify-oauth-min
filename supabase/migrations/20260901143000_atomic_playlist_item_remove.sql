create or replace function public.playlist_remove_at_position(
  p_playlist_id uuid,
  p_position integer,
  p_track_id text
)
returns table(ok boolean, removed_position integer, remaining integer)
language plpgsql
as $function$
declare
  v_removed integer := 0;
  v_remaining integer := 0;
begin
  perform 1 from public.playlist_items
    where playlist_id = p_playlist_id
    for update;
  perform 1 from public.playlist_item_locks
    where playlist_id = p_playlist_id
    for update;
  perform 1 from public.playlist_flex_slots
    where playlist_id = p_playlist_id
    for update;

  delete from public.playlist_items
   where playlist_id = p_playlist_id
     and position = p_position
     and track_id = p_track_id;
  get diagnostics v_removed = row_count;

  if v_removed = 0 then
    return query select false, p_position, count(*)::integer
      from public.playlist_items where playlist_id = p_playlist_id;
    return;
  end if;

  delete from public.playlist_flex_slots
   where playlist_id = p_playlist_id
     and (position = p_position or current_track_id = p_track_id);

  update public.playlist_items
     set position = -(position + 1)
   where playlist_id = p_playlist_id
     and position > p_position;

  update public.playlist_items
     set position = -position - 2
   where playlist_id = p_playlist_id
     and position < -(p_position + 1);

  update public.playlist_flex_slots
     set position = 1000000 + position,
         updated_at = now()
   where playlist_id = p_playlist_id
     and position > p_position;

  update public.playlist_flex_slots
     set position = position - 1000001,
         updated_at = now()
   where playlist_id = p_playlist_id
     and position > 1000000 + p_position;

  delete from public.playlist_item_locks lock
   where lock.playlist_id = p_playlist_id
     and lock.track_id = p_track_id
     and not exists (
       select 1 from public.playlist_items item
        where item.playlist_id = p_playlist_id
          and item.track_id = p_track_id
     );

  with current_positions as (
    select track_id, min(position) as position
      from public.playlist_items
     where playlist_id = p_playlist_id
     group by track_id
  )
  update public.playlist_item_locks lock
     set locked_position = current_positions.position
    from current_positions
   where lock.playlist_id = p_playlist_id
     and lock.is_locked
     and lock.track_id = current_positions.track_id;

  select count(*)::integer into v_remaining
    from public.playlist_items
   where playlist_id = p_playlist_id;

  return query select true, p_position, v_remaining;
end
$function$;

revoke execute on function public.playlist_remove_at_position(uuid, integer, text) from public;
revoke execute on function public.playlist_remove_at_position(uuid, integer, text) from anon;
revoke execute on function public.playlist_remove_at_position(uuid, integer, text) from authenticated;
grant execute on function public.playlist_remove_at_position(uuid, integer, text) to service_role;
