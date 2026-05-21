-- Move playlist rows by concrete source position. Spotify playlists may contain
-- the same track_id more than once, so track_id cannot identify a row during a
-- positional reorder.

create or replace function public.playlist_move_at_position(
  p_playlist_id uuid,
  p_from_position integer,
  p_dir text,
  p_steps integer default 1
)
returns table(ok boolean, from_pos integer, to_pos integer)
language plpgsql
as $function$
declare
  ord integer[];
  n integer;
  src_idx integer;
  dst_idx integer;
begin
  perform 1 from public.playlist_items
    where playlist_id = p_playlist_id
    for update;
  perform 1 from public.playlist_item_locks
    where playlist_id = p_playlist_id
    for update;

  select array_agg(position order by position)
    into ord
  from public.playlist_items
  where playlist_id = p_playlist_id;

  if ord is null then
    return query select false, null::int, null::int;
    return;
  end if;

  n := array_length(ord, 1);
  src_idx := array_position(ord, p_from_position);
  if src_idx is null then
    return query select false, null::int, null::int;
    return;
  end if;

  if lower(p_dir) = 'up' then
    dst_idx := src_idx - greatest(1, coalesce(p_steps, 1));
  elsif lower(p_dir) = 'down' then
    dst_idx := src_idx + greatest(1, coalesce(p_steps, 1));
  else
    raise exception 'invalid direction (use up|down)';
  end if;

  if dst_idx < 1 then dst_idx := 1; end if;
  if dst_idx > n then dst_idx := n; end if;
  if dst_idx = src_idx then
    return query select true, src_idx - 1, dst_idx - 1;
    return;
  end if;

  if dst_idx < src_idx then
    ord := array_cat(
      array_cat(ord[1:dst_idx - 1], array[ord[src_idx]]),
      array_cat(ord[dst_idx:src_idx - 1], ord[src_idx + 1:n])
    );
  else
    ord := array_cat(
      array_cat(ord[1:src_idx - 1], ord[src_idx + 1:dst_idx]),
      array_cat(array[ord[src_idx]], ord[dst_idx + 1:n])
    );
  end if;

  update public.playlist_items
     set position = -(position + 1)
   where playlist_id = p_playlist_id;

  with newmap as (
    select unnest(ord) as old_position,
           generate_subscripts(ord, 1) as idx
  )
  update public.playlist_items pi
     set position = newmap.idx - 1
    from newmap
   where pi.playlist_id = p_playlist_id
     and pi.position = -(newmap.old_position + 1);

  with current_positions as (
    select track_id, min(position) as position
    from public.playlist_items
    where playlist_id = p_playlist_id
    group by track_id
  )
  update public.playlist_item_locks l
     set locked_position = current_positions.position
    from current_positions
   where l.playlist_id = p_playlist_id
     and l.is_locked
     and l.track_id = current_positions.track_id;

  return query select true, src_idx - 1, dst_idx - 1;
end
$function$;

revoke execute on function public.playlist_move_at_position(uuid, integer, text, integer) from public;
revoke execute on function public.playlist_move_at_position(uuid, integer, text, integer) from anon;
revoke execute on function public.playlist_move_at_position(uuid, integer, text, integer) from authenticated;
grant execute on function public.playlist_move_at_position(uuid, integer, text, integer) to service_role;
