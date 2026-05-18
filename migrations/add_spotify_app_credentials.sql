create table if not exists public.spotify_app_credentials (
  id uuid primary key default gen_random_uuid(),
  bubble_user_id text not null references public.app_users(bubble_user_id) on delete cascade,
  client_id text not null,
  client_secret_enc text not null,
  redirect_uri text not null,
  app_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (bubble_user_id)
);

alter table public.spotify_connections
  add column if not exists credential_id uuid references public.spotify_app_credentials(id) on delete set null;

create index if not exists spotify_app_credentials_bubble_user_id_idx
  on public.spotify_app_credentials(bubble_user_id);

create index if not exists spotify_connections_credential_id_idx
  on public.spotify_connections(credential_id);
