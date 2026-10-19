alter table public.playlists
  add column if not exists items_snapshot_id text;

comment on column public.playlists.items_snapshot_id is
  'Spotify snapshot_id represented by the currently persisted playlist_items rows.';

update public.playlists
set needs_sync = true
where is_owner is true
  and is_public is true
  and coalesce(tracks_total, 0) > 0
  and items_snapshot_id is null;
