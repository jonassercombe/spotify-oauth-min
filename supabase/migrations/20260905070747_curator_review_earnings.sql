create table public.curator_review_earning_rates (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid not null references auth.users(id) on delete cascade,
  bubble_user_id text not null,
  account_profile_id text not null,
  platform text not null check (platform in ('groover', 'playlistpush', 'submithub')),
  amount numeric(12,4) not null default 0 check (amount >= 0 and amount <= 10000),
  currency text not null default 'EUR' check (currency ~ '^[A-Z]{3}$'),
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (auth_user_id, platform, account_profile_id)
);

alter table public.curator_review_earning_rates enable row level security;
revoke all on table public.curator_review_earning_rates from anon, authenticated;
grant all on table public.curator_review_earning_rates to service_role;

create table public.curator_review_earnings (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid not null references auth.users(id) on delete cascade,
  bubble_user_id text not null,
  account_profile_id text not null,
  platform text not null check (platform in ('groover', 'playlistpush', 'submithub')),
  platform_profile text not null default '',
  platform_submission_id text not null,
  decision text not null check (decision in ('accept', 'decline')),
  track_title text not null default '',
  artist_names text[] not null default '{}',
  spotify_track_id text,
  amount numeric(12,4) not null check (amount >= 0 and amount <= 10000),
  currency text not null check (currency ~ '^[A-Z]{3}$'),
  reviewed_at timestamptz not null,
  metadata jsonb not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (auth_user_id, platform, account_profile_id, platform_submission_id)
);

create index curator_review_earnings_user_reviewed_idx
  on public.curator_review_earnings (auth_user_id, reviewed_at desc);

alter table public.curator_review_earnings enable row level security;

revoke all on table public.curator_review_earnings from anon, authenticated;
grant all on table public.curator_review_earnings to service_role;
