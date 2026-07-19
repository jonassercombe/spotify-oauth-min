create table public.meta_creative_experiments (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.meta_creative_projects(id) on delete cascade,
  connection_id uuid not null references public.meta_ads_connections(id) on delete cascade,
  bubble_user_id text not null references public.app_users(bubble_user_id) on delete cascade,
  name text not null check (char_length(name) between 3 and 160),
  objective text not null default 'spotify_open'
    check (objective in ('outbound_click', 'spotify_open', 'playlist_follow')),
  primary_metric text not null default 'cost_per_spotify_open'
    check (primary_metric in ('hook_rate', 'hold_rate', 'outbound_ctr', 'cost_per_outbound_click', 'spotify_open_rate', 'cost_per_spotify_open')),
  status text not null default 'draft'
    check (status in ('draft', 'active', 'paused', 'completed', 'archived')),
  current_phase smallint not null default 1 check (current_phase between 1 and 20),
  settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index meta_creative_experiments_owner_idx
  on public.meta_creative_experiments (bubble_user_id, status, created_at desc);
create index meta_creative_experiments_project_idx
  on public.meta_creative_experiments (project_id, created_at desc);

create table public.meta_creative_experiment_phases (
  id uuid primary key default gen_random_uuid(),
  experiment_id uuid not null references public.meta_creative_experiments(id) on delete cascade,
  phase_number smallint not null check (phase_number between 1 and 20),
  phase_type text not null
    check (phase_type in ('explore', 'audio_match', 'expand', 'optimize')),
  name text not null check (char_length(name) between 3 and 160),
  status text not null default 'draft'
    check (status in ('draft', 'rendering', 'ready', 'active', 'evaluating', 'completed', 'cancelled')),
  hypothesis text not null default '',
  primary_metric text not null default 'cost_per_spotify_open',
  minimum_impressions integer not null default 1000 check (minimum_impressions between 100 and 10000000),
  minimum_spend_minor integer not null default 0 check (minimum_spend_minor between 0 and 1000000000),
  config jsonb not null default '{}'::jsonb,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (experiment_id, phase_number)
);

create index meta_creative_experiment_phases_status_idx
  on public.meta_creative_experiment_phases (experiment_id, status, phase_number);

create table public.meta_creative_audio_tracks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.meta_creative_projects(id) on delete cascade,
  bubble_user_id text not null references public.app_users(bubble_user_id) on delete cascade,
  asset_id uuid not null references public.meta_creative_assets(id) on delete cascade,
  title text not null check (char_length(title) between 1 and 200),
  artist text not null default '',
  rights_status text not null default 'owned'
    check (rights_status in ('owned', 'licensed', 'test_only', 'unknown')),
  default_start_seconds numeric(8, 3) not null default 0 check (default_start_seconds >= 0),
  energy text not null default 'unknown'
    check (energy in ('low', 'medium', 'high', 'unknown')),
  mood_tags text[] not null default '{}'::text[],
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (asset_id)
);

create index meta_creative_audio_tracks_project_idx
  on public.meta_creative_audio_tracks (project_id, created_at desc);

create table public.meta_creative_variants (
  id uuid primary key default gen_random_uuid(),
  experiment_id uuid not null references public.meta_creative_experiments(id) on delete cascade,
  phase_id uuid not null references public.meta_creative_experiment_phases(id) on delete cascade,
  parent_variant_id uuid references public.meta_creative_variants(id) on delete set null,
  concept_id uuid not null references public.meta_creative_concepts(id) on delete restrict,
  video_asset_id uuid not null references public.meta_creative_assets(id) on delete restrict,
  audio_track_id uuid references public.meta_creative_audio_tracks(id) on delete restrict,
  render_job_id uuid references public.meta_creative_render_jobs(id) on delete set null,
  output_asset_id uuid references public.meta_creative_assets(id) on delete set null,
  generation smallint not null default 1 check (generation between 1 and 100),
  label text not null check (char_length(label) between 1 and 200),
  status text not null default 'draft'
    check (status in ('draft', 'queued', 'rendering', 'ready', 'active', 'paused', 'winner', 'rejected', 'failed')),
  template_id text not null default 'bold_center'
    check (template_id in ('bold_center', 'editorial_top', 'minimal_bottom')),
  format text not null default '9:16' check (format in ('9:16', '1:1', '4:5')),
  hook_text text not null default '',
  cta_text text not null default 'Listen on Spotify',
  video_start_seconds numeric(8, 3) not null default 0 check (video_start_seconds >= 0),
  video_end_seconds numeric(8, 3),
  song_start_seconds numeric(8, 3) not null default 0 check (song_start_seconds >= 0),
  duration_seconds numeric(8, 3) not null default 15 check (duration_seconds between 1 and 60),
  dna jsonb not null default '{}'::jsonb,
  dna_hash text not null check (dna_hash ~ '^[0-9a-f]{64}$'),
  meta_campaign_id text,
  meta_adset_id text,
  meta_creative_id text,
  meta_ad_id text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (phase_id, dna_hash)
);

create index meta_creative_variants_phase_status_idx
  on public.meta_creative_variants (phase_id, status, created_at);
create index meta_creative_variants_lineage_idx
  on public.meta_creative_variants (parent_variant_id, generation);
create index meta_creative_variants_meta_ad_idx
  on public.meta_creative_variants (meta_ad_id)
  where meta_ad_id is not null;

create table public.meta_creative_variant_metrics (
  id uuid primary key default gen_random_uuid(),
  variant_id uuid not null references public.meta_creative_variants(id) on delete cascade,
  metric_date date not null,
  impressions bigint not null default 0 check (impressions >= 0),
  reach bigint not null default 0 check (reach >= 0),
  spend_minor bigint not null default 0 check (spend_minor >= 0),
  three_second_views bigint not null default 0 check (three_second_views >= 0),
  video_plays_25 bigint not null default 0 check (video_plays_25 >= 0),
  video_plays_50 bigint not null default 0 check (video_plays_50 >= 0),
  video_plays_75 bigint not null default 0 check (video_plays_75 >= 0),
  video_completions bigint not null default 0 check (video_completions >= 0),
  outbound_clicks bigint not null default 0 check (outbound_clicks >= 0),
  landing_page_views bigint not null default 0 check (landing_page_views >= 0),
  spotify_opens bigint not null default 0 check (spotify_opens >= 0),
  playlist_follows bigint not null default 0 check (playlist_follows >= 0),
  raw_metrics jsonb not null default '{}'::jsonb,
  imported_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (variant_id, metric_date)
);

create index meta_creative_variant_metrics_date_idx
  on public.meta_creative_variant_metrics (variant_id, metric_date desc);

alter table public.meta_creative_experiments enable row level security;
alter table public.meta_creative_experiment_phases enable row level security;
alter table public.meta_creative_audio_tracks enable row level security;
alter table public.meta_creative_variants enable row level security;
alter table public.meta_creative_variant_metrics enable row level security;

revoke all on table public.meta_creative_experiments from public, anon, authenticated;
revoke all on table public.meta_creative_experiment_phases from public, anon, authenticated;
revoke all on table public.meta_creative_audio_tracks from public, anon, authenticated;
revoke all on table public.meta_creative_variants from public, anon, authenticated;
revoke all on table public.meta_creative_variant_metrics from public, anon, authenticated;

grant select, insert, update, delete on table public.meta_creative_experiments to service_role;
grant select, insert, update, delete on table public.meta_creative_experiment_phases to service_role;
grant select, insert, update, delete on table public.meta_creative_audio_tracks to service_role;
grant select, insert, update, delete on table public.meta_creative_variants to service_role;
grant select, insert, update, delete on table public.meta_creative_variant_metrics to service_role;
