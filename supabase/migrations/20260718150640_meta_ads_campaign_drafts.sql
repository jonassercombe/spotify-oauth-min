create table public.meta_ads_campaign_drafts (
  id uuid primary key default gen_random_uuid(),
  connection_id uuid not null references public.meta_ads_connections(id) on delete cascade,
  bubble_user_id text not null references public.app_users(bubble_user_id) on delete cascade,
  name text not null,
  objective text not null default 'OUTCOME_TRAFFIC',
  daily_budget_minor integer not null check (daily_budget_minor between 100 and 100000000),
  destination_url text not null,
  primary_text text not null,
  headline text not null,
  image_url text not null,
  countries text[] not null default array['DE']::text[],
  age_min smallint not null default 18 check (age_min between 13 and 65),
  age_max smallint not null default 45 check (age_max between 13 and 65 and age_max >= age_min),
  status text not null default 'draft' check (status in ('draft', 'review_ready', 'creating', 'created_paused', 'error')),
  review_confirmed_at timestamptz,
  meta_campaign_id text,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index meta_ads_campaign_drafts_connection_created_idx
  on public.meta_ads_campaign_drafts (connection_id, created_at desc);

alter table public.meta_ads_campaign_drafts enable row level security;
revoke all on table public.meta_ads_campaign_drafts from public, anon, authenticated;
grant select, insert, update, delete on table public.meta_ads_campaign_drafts to service_role;
