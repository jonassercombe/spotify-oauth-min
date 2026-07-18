create table public.meta_creative_projects (
  id uuid primary key default gen_random_uuid(),
  connection_id uuid not null references public.meta_ads_connections(id) on delete cascade,
  bubble_user_id text not null references public.app_users(bubble_user_id) on delete cascade,
  playlist_id uuid not null references public.playlists(id) on delete cascade,
  name text not null check (char_length(name) between 3 and 120),
  language text not null default 'en' check (language in ('en', 'de')),
  format text not null default '9:16' check (format in ('9:16', '1:1', '4:5')),
  status text not null default 'brief_pending'
    check (status in ('brief_pending', 'concepts_pending', 'media_pending', 'render_ready', 'rendering', 'review', 'complete', 'error')),
  current_step smallint not null default 1 check (current_step between 1 and 6),
  brief jsonb not null default '{}'::jsonb,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index meta_creative_projects_user_created_idx
  on public.meta_creative_projects (bubble_user_id, created_at desc);
create index meta_creative_projects_playlist_idx
  on public.meta_creative_projects (playlist_id, created_at desc);

create table public.meta_creative_concepts (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.meta_creative_projects(id) on delete cascade,
  position smallint not null default 1 check (position between 1 and 100),
  title text not null default '',
  hook text not null default '',
  angle text not null default '',
  story text not null default '',
  primary_emotion text not null default '',
  visual_direction text not null default '',
  visual_search_terms text[] not null default '{}'::text[],
  text_design_direction text not null default '',
  audio_direction text not null default '',
  cta text not null default '',
  hypothesis text not null default '',
  status text not null default 'concept'
    check (status in ('concept', 'selected', 'media_ready', 'render_queued', 'rendered', 'winner', 'rejected')),
  render_spec jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (project_id, position)
);

create index meta_creative_concepts_project_status_idx
  on public.meta_creative_concepts (project_id, status, position);

create table public.meta_creative_assets (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.meta_creative_projects(id) on delete cascade,
  concept_id uuid references public.meta_creative_concepts(id) on delete cascade,
  asset_type text not null check (asset_type in ('video', 'audio', 'image', 'render')),
  source text not null check (source in ('pexels', 'spotify', 'upload', 'render_worker')),
  provider_id text,
  source_url text,
  storage_path text,
  mime_type text,
  duration_seconds numeric(8, 3),
  width integer,
  height integer,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (source_url is not null or storage_path is not null)
);

create index meta_creative_assets_project_type_idx
  on public.meta_creative_assets (project_id, asset_type, created_at desc);
create index meta_creative_assets_concept_idx
  on public.meta_creative_assets (concept_id, created_at desc)
  where concept_id is not null;

create table public.meta_creative_render_jobs (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.meta_creative_projects(id) on delete cascade,
  concept_id uuid not null references public.meta_creative_concepts(id) on delete cascade,
  status text not null default 'queued'
    check (status in ('queued', 'processing', 'completed', 'failed', 'cancelled')),
  priority smallint not null default 100,
  attempts smallint not null default 0 check (attempts between 0 and 20),
  max_attempts smallint not null default 3 check (max_attempts between 1 and 20),
  render_spec jsonb not null default '{}'::jsonb,
  output_asset_id uuid references public.meta_creative_assets(id) on delete set null,
  worker_id text,
  error_code text,
  error_message text,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index meta_creative_render_jobs_queue_idx
  on public.meta_creative_render_jobs (status, priority, created_at)
  where status in ('queued', 'processing');
create index meta_creative_render_jobs_project_idx
  on public.meta_creative_render_jobs (project_id, created_at desc);

alter table public.meta_creative_projects enable row level security;
alter table public.meta_creative_concepts enable row level security;
alter table public.meta_creative_assets enable row level security;
alter table public.meta_creative_render_jobs enable row level security;

revoke all on table public.meta_creative_projects from public, anon, authenticated;
revoke all on table public.meta_creative_concepts from public, anon, authenticated;
revoke all on table public.meta_creative_assets from public, anon, authenticated;
revoke all on table public.meta_creative_render_jobs from public, anon, authenticated;

grant select, insert, update, delete on table public.meta_creative_projects to service_role;
grant select, insert, update, delete on table public.meta_creative_concepts to service_role;
grant select, insert, update, delete on table public.meta_creative_assets to service_role;
grant select, insert, update, delete on table public.meta_creative_render_jobs to service_role;
