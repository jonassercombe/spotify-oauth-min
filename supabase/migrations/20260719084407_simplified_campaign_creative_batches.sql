create table public.meta_campaign_creative_batches (
  id uuid primary key default gen_random_uuid(),
  playlist_id uuid not null references public.playlists(id) on delete cascade,
  project_id uuid not null unique references public.meta_creative_projects(id) on delete cascade,
  campaign_draft_id uuid references public.meta_ads_campaign_drafts(id) on delete set null,
  connection_id uuid not null references public.meta_ads_connections(id) on delete cascade,
  bubble_user_id text not null references public.app_users(bubble_user_id) on delete cascade,
  name text not null check (char_length(name) between 3 and 160),
  creative_notes text not null default '',
  audio_snippet_ids uuid[] not null default '{}'::uuid[],
  requested_count smallint not null default 8 check (requested_count = 8),
  status text not null default 'created'
    check (status in ('created', 'concepts', 'media', 'rendering', 'review', 'failed')),
  progress jsonb not null default '{}'::jsonb,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index meta_campaign_creative_batches_owner_idx
  on public.meta_campaign_creative_batches (bubble_user_id, created_at desc);
create index meta_campaign_creative_batches_playlist_idx
  on public.meta_campaign_creative_batches (playlist_id, created_at desc);
create index meta_campaign_creative_batches_draft_idx
  on public.meta_campaign_creative_batches (campaign_draft_id, created_at desc)
  where campaign_draft_id is not null;

create table public.meta_campaign_creative_reviews (
  id uuid primary key default gen_random_uuid(),
  batch_id uuid not null references public.meta_campaign_creative_batches(id) on delete cascade,
  concept_id uuid not null references public.meta_creative_concepts(id) on delete cascade,
  decision text not null default 'pending'
    check (decision in ('pending', 'approved', 'rejected')),
  note text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (batch_id, concept_id)
);

create index meta_campaign_creative_reviews_batch_idx
  on public.meta_campaign_creative_reviews (batch_id, decision, created_at);

alter table public.meta_campaign_creative_batches enable row level security;
alter table public.meta_campaign_creative_reviews enable row level security;

revoke all on table public.meta_campaign_creative_batches from public, anon, authenticated;
revoke all on table public.meta_campaign_creative_reviews from public, anon, authenticated;

grant select, insert, update, delete on table public.meta_campaign_creative_batches to service_role;
grant select, insert, update, delete on table public.meta_campaign_creative_reviews to service_role;

comment on table public.meta_campaign_creative_batches is
  'One-click Generate 8 runs. Each batch owns an isolated internal creative project.';
comment on table public.meta_campaign_creative_reviews is
  'Simple user-facing decisions over generated batch concepts and renders.';
