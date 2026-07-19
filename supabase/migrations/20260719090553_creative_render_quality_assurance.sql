alter table public.meta_creative_concepts
  add column creative_dna jsonb not null default '{}'::jsonb;

comment on column public.meta_creative_concepts.creative_dna is
  'Structured, reusable creative attributes used to compare concepts and generate later experiment phases.';

create table public.meta_creative_render_quality_reports (
  id uuid primary key default gen_random_uuid(),
  render_job_id uuid not null references public.meta_creative_render_jobs(id) on delete cascade,
  output_asset_id uuid not null references public.meta_creative_assets(id) on delete cascade,
  project_id uuid not null references public.meta_creative_projects(id) on delete cascade,
  concept_id uuid not null references public.meta_creative_concepts(id) on delete cascade,
  status text not null default 'pending'
    check (status in ('pending', 'passed', 'warning', 'failed', 'error')),
  overall_score smallint check (overall_score between 0 and 100),
  technical_pass boolean,
  creative_pass boolean,
  auto_fixable boolean not null default false,
  checks jsonb not null default '[]'::jsonb,
  summary text not null default '',
  suggested_fixes jsonb not null default '[]'::jsonb,
  frame_urls jsonb not null default '[]'::jsonb,
  model text,
  error_message text,
  analyzed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (render_job_id)
);

create index meta_creative_render_quality_project_idx
  on public.meta_creative_render_quality_reports (project_id, created_at desc);
create index meta_creative_render_quality_status_idx
  on public.meta_creative_render_quality_reports (status, created_at desc);

alter table public.meta_creative_render_quality_reports enable row level security;
revoke all on table public.meta_creative_render_quality_reports from public, anon, authenticated;
grant select, insert, update, delete on table public.meta_creative_render_quality_reports to service_role;
