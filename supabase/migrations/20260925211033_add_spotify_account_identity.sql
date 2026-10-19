-- Spotify introduced account_id as the stable account identifier in May 2026.
-- Keep spotify_user_id because playlist owner.id still uses that public user id.
alter table public.spotify_connections
  add column if not exists spotify_account_id text;

create index if not exists spotify_connections_account_id_idx
  on public.spotify_connections (spotify_account_id)
  where spotify_account_id is not null;

create unique index if not exists spotify_connections_active_account_id_key
  on public.spotify_connections (spotify_account_id)
  where spotify_account_id is not null and is_active = true;
