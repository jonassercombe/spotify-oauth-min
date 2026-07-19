create table public.meta_openai_usage_events (
  id uuid primary key default gen_random_uuid(),
  bubble_user_id text not null,
  project_id uuid references public.meta_creative_projects(id) on delete set null,
  concept_id uuid references public.meta_creative_concepts(id) on delete set null,
  render_job_id uuid references public.meta_creative_render_jobs(id) on delete set null,
  operation text not null,
  model text not null,
  input_tokens bigint not null default 0,
  cached_input_tokens bigint not null default 0,
  cache_write_tokens bigint not null default 0,
  output_tokens bigint not null default 0,
  reasoning_tokens bigint not null default 0,
  image_count integer not null default 0,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index meta_openai_usage_user_created_idx
  on public.meta_openai_usage_events (bubble_user_id, created_at desc);
create index meta_openai_usage_project_created_idx
  on public.meta_openai_usage_events (project_id, created_at desc);

alter table public.meta_openai_usage_events enable row level security;
revoke all on table public.meta_openai_usage_events from public, anon, authenticated;
grant select, insert, update, delete on table public.meta_openai_usage_events to service_role;
