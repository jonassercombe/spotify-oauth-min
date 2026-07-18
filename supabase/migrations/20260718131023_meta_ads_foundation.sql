create table if not exists public.meta_ads_connections (
  id uuid primary key default gen_random_uuid(),
  bubble_user_id text not null references public.app_users(bubble_user_id) on delete cascade,
  app_id text not null,
  business_id text not null,
  access_token_enc text not null,
  app_secret_enc text,
  graph_version text not null default 'v25.0',
  status text not null default 'unverified' check (status in ('unverified', 'ready', 'error', 'disabled')),
  token_expires_at timestamptz,
  last_audit_at timestamptz,
  last_error text,
  audit_summary jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (bubble_user_id)
);

create table if not exists public.meta_ads_assets (
  id uuid primary key default gen_random_uuid(),
  connection_id uuid not null references public.meta_ads_connections(id) on delete cascade,
  asset_type text not null check (asset_type in ('ad_account', 'page', 'instagram_account')),
  meta_id text not null,
  name text,
  is_selected boolean not null default false,
  metadata jsonb not null default '{}'::jsonb,
  discovered_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (connection_id, asset_type, meta_id)
);

create table if not exists public.meta_ads_audit_events (
  id bigint generated always as identity primary key,
  connection_id uuid not null references public.meta_ads_connections(id) on delete cascade,
  status text not null check (status in ('success', 'warning', 'error')),
  summary jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists meta_ads_assets_connection_type_idx
  on public.meta_ads_assets (connection_id, asset_type, is_selected);

create index if not exists meta_ads_audit_events_connection_created_idx
  on public.meta_ads_audit_events (connection_id, created_at desc);

alter table public.meta_ads_connections enable row level security;
alter table public.meta_ads_assets enable row level security;
alter table public.meta_ads_audit_events enable row level security;

revoke all on table public.meta_ads_connections from anon, authenticated;
revoke all on table public.meta_ads_assets from anon, authenticated;
revoke all on table public.meta_ads_audit_events from anon, authenticated;
revoke all on sequence public.meta_ads_audit_events_id_seq from anon, authenticated;
