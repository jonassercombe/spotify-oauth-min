create unique index if not exists spotify_connections_active_spotify_user_owner_idx
  on public.spotify_connections (spotify_user_id)
  where is_active is true;
