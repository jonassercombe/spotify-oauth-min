alter table public.playlist_backups
  add column if not exists reason text;

create index if not exists playlist_backups_playlist_reason_taken_idx
  on public.playlist_backups (playlist_id, reason, taken_at desc);
