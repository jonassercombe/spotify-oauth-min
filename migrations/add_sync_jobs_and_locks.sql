create extension if not exists pgcrypto;

create table if not exists public.sync_jobs (
  id uuid primary key default gen_random_uuid(),
  job_type text not null,
  scope_type text not null default 'global',
  scope_id text not null default '',
  playlist_id uuid null references public.playlists(id) on delete cascade,
  connection_id uuid null references public.spotify_connections(id) on delete cascade,
  bubble_user_id text null,
  priority integer not null default 50,
  payload jsonb not null default '{}'::jsonb,
  status text not null default 'pending',
  run_after timestamptz not null default now(),
  attempts integer not null default 0,
  max_attempts integer not null default 5,
  locked_at timestamptz null,
  locked_by text null,
  completed_at timestamptz null,
  last_error text null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint sync_jobs_status_check check (status in ('pending','running','done','failed','cancelled'))
);

create unique index if not exists sync_jobs_active_dedupe_idx
  on public.sync_jobs (job_type, scope_type, scope_id)
  where status in ('pending','running');

create index if not exists sync_jobs_queue_idx
  on public.sync_jobs (status, run_after, priority desc, created_at asc);

create index if not exists sync_jobs_playlist_idx
  on public.sync_jobs (playlist_id, status, run_after);

create index if not exists sync_jobs_connection_idx
  on public.sync_jobs (connection_id, status, run_after);

create table if not exists public.sync_locks (
  lock_key text primary key,
  scope_type text not null,
  scope_id text not null,
  owner text not null,
  expires_at timestamptz not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists sync_locks_expires_idx
  on public.sync_locks (expires_at);

alter table public.sync_jobs enable row level security;
alter table public.sync_locks enable row level security;

drop policy if exists "sync_jobs_service_only" on public.sync_jobs;
create policy "sync_jobs_service_only"
  on public.sync_jobs
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

drop policy if exists "sync_locks_service_only" on public.sync_locks;
create policy "sync_locks_service_only"
  on public.sync_locks
  for all
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');
