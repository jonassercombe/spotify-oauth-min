create table if not exists public.extension_adapter_releases (
  id uuid primary key default gen_random_uuid(),
  platform text not null check (platform ~ '^[a-z][a-z0-9_-]{1,48}$'),
  page_kind text not null default 'any' check (page_kind ~ '^[a-z][a-z0-9_-]{1,48}$'),
  version integer not null check (version > 0),
  status text not null default 'draft' check (status in ('draft', 'canary', 'stable', 'disabled')),
  minimum_extension_version text not null default '0.0.0',
  rules jsonb not null default '[]'::jsonb check (jsonb_typeof(rules) = 'array'),
  checksum text not null default '',
  created_at timestamptz not null default now(),
  published_at timestamptz,
  unique (platform, page_kind, version)
);

create unique index if not exists extension_adapter_one_stable
  on public.extension_adapter_releases (platform, page_kind)
  where status = 'stable';

create table if not exists public.extension_adapter_health_daily (
  day date not null default current_date,
  platform text not null check (platform ~ '^[a-z][a-z0-9_-]{1,48}$'),
  page_kind text not null default 'unknown',
  adapter_version text not null default 'legacy',
  extension_version text not null default 'unknown',
  status text not null check (status in ('healthy', 'degraded', 'broken')),
  warning_key text not null default 'none',
  checks bigint not null default 0 check (checks >= 0),
  last_seen_at timestamptz not null default now(),
  primary key (day, platform, page_kind, adapter_version, extension_version, status, warning_key)
);

alter table public.extension_adapter_releases enable row level security;
alter table public.extension_adapter_health_daily enable row level security;
revoke all on public.extension_adapter_releases from anon, authenticated;
revoke all on public.extension_adapter_health_daily from anon, authenticated;

insert into public.extension_adapter_releases (platform, page_kind, version, status, minimum_extension_version, rules, checksum, published_at)
select platform, 'any', 1, 'stable', '0.33.0', '[]'::jsonb, 'initial-empty-rescue-v1', now()
from unnest(array['submithub','groover','playlistpush','unhurd']) platform
on conflict (platform, page_kind, version) do nothing;

create or replace function public.increment_extension_adapter_health(
  p_platform text, p_page_kind text, p_adapter_version text,
  p_extension_version text, p_status text, p_warning_key text
) returns void
language sql
security definer
set search_path = public, pg_temp
as $$
  insert into public.extension_adapter_health_daily
    (day, platform, page_kind, adapter_version, extension_version, status, warning_key, checks, last_seen_at)
  values
    (current_date, p_platform, p_page_kind, p_adapter_version, p_extension_version, p_status, p_warning_key, 1, now())
  on conflict (day, platform, page_kind, adapter_version, extension_version, status, warning_key)
  do update set checks = extension_adapter_health_daily.checks + 1, last_seen_at = now();
$$;
revoke all on function public.increment_extension_adapter_health(text,text,text,text,text,text) from public, anon, authenticated;
grant execute on function public.increment_extension_adapter_health(text,text,text,text,text,text) to service_role;
