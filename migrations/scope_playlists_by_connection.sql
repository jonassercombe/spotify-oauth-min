-- Scope Spotify playlist rows by connection.
--
-- Before this migration, public.playlists was treated as globally unique by
-- Spotify playlist_id. That is unsafe once multiple PlaylistPilot workspaces
-- can connect different Spotify accounts that may expose the same playlist.
--
-- Apply this before relying on scoped playlist upserts in the app.

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conrelid = 'public.playlists'::regclass
      and conname = 'playlists_connection_id_playlist_id_key'
  ) then
    alter table public.playlists
      add constraint playlists_connection_id_playlist_id_key
      unique (connection_id, playlist_id);
  end if;
end $$;

do $$
declare
  constraint_record record;
begin
  for constraint_record in
    select c.conname
    from pg_constraint c
    join pg_class t on t.oid = c.conrelid
    join pg_namespace n on n.oid = t.relnamespace
    where n.nspname = 'public'
      and t.relname = 'playlists'
      and c.contype = 'u'
      and array_length(c.conkey, 1) = 1
      and exists (
        select 1
        from unnest(c.conkey) key(attnum)
        join pg_attribute a on a.attrelid = c.conrelid and a.attnum = key.attnum
        where a.attname = 'playlist_id'
      )
  loop
    execute format('alter table public.playlists drop constraint %I', constraint_record.conname);
  end loop;
end $$;

create index if not exists idx_playlists_connection_playlist
  on public.playlists(connection_id, playlist_id);

create index if not exists idx_playlists_bubble_connection
  on public.playlists(bubble_user_id, connection_id);
