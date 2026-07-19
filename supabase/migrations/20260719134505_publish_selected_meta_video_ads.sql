alter table public.meta_ads_campaign_drafts
  add column selected_render_asset_ids uuid[] not null default '{}'::uuid[],
  add column experiment_id uuid references public.meta_creative_experiments(id) on delete set null;

create table public.meta_ads_campaign_video_items (
  id uuid primary key default gen_random_uuid(),
  draft_id uuid not null references public.meta_ads_campaign_drafts(id) on delete cascade,
  asset_id uuid not null references public.meta_creative_assets(id) on delete restrict,
  concept_id uuid not null references public.meta_creative_concepts(id) on delete restrict,
  variant_id uuid references public.meta_creative_variants(id) on delete set null,
  position smallint not null check (position between 1 and 50),
  status text not null default 'selected'
    check (status in ('selected', 'uploading', 'uploaded', 'creative_created', 'complete', 'error')),
  meta_video_id text,
  meta_creative_id text,
  meta_ad_id text,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (draft_id, asset_id),
  unique (draft_id, position)
);

create index meta_ads_campaign_video_items_draft_idx
  on public.meta_ads_campaign_video_items (draft_id, position);

create index meta_ads_campaign_video_items_variant_idx
  on public.meta_ads_campaign_video_items (variant_id)
  where variant_id is not null;

alter table public.meta_ads_campaign_video_items enable row level security;
revoke all on table public.meta_ads_campaign_video_items from public, anon, authenticated;
grant select, insert, update, delete on table public.meta_ads_campaign_video_items to service_role;

comment on column public.meta_ads_campaign_drafts.selected_render_asset_ids is
  'Approved rendered MP4 assets selected for the paused Meta creative test.';
comment on table public.meta_ads_campaign_video_items is
  'Resumable one-to-one mapping from a selected rendered asset to its Meta video, creative, ad and experiment variant.';
