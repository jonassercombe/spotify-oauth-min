update storage.buckets
set
  file_size_limit = 104857600,
  allowed_mime_types = array[
    'image/jpeg',
    'image/png',
    'image/webp',
    'video/mp4',
    'audio/mpeg',
    'audio/mp4',
    'audio/x-m4a',
    'audio/wav',
    'audio/x-wav'
  ]::text[]
where id = 'meta-ad-creatives';

create table public.meta_audio_masters (
  id uuid primary key default gen_random_uuid(),
  playlist_id uuid not null references public.playlists(id) on delete cascade,
  project_id uuid references public.meta_creative_projects(id) on delete set null,
  bubble_user_id text not null references public.app_users(bubble_user_id) on delete cascade,
  title text not null check (char_length(title) between 1 and 200),
  artist text not null default '',
  file_name text not null check (char_length(file_name) between 1 and 240),
  mime_type text not null check (mime_type in ('audio/mpeg', 'audio/mp4', 'audio/x-m4a', 'audio/wav', 'audio/x-wav')),
  bytes bigint not null check (bytes between 1 and 104857600),
  storage_path text not null unique,
  source_url text not null default '',
  duration_seconds numeric(10, 3) check (duration_seconds is null or duration_seconds > 0),
  rights_status text not null default 'test_only'
    check (rights_status in ('owned', 'licensed', 'test_only', 'unknown')),
  status text not null default 'uploading'
    check (status in ('uploading', 'ready', 'failed')),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index meta_audio_masters_playlist_idx
  on public.meta_audio_masters (playlist_id, created_at desc);
create index meta_audio_masters_owner_idx
  on public.meta_audio_masters (bubble_user_id, status, created_at desc);

create table public.meta_audio_snippets (
  id uuid primary key default gen_random_uuid(),
  master_id uuid not null references public.meta_audio_masters(id) on delete cascade,
  playlist_id uuid not null references public.playlists(id) on delete cascade,
  project_id uuid references public.meta_creative_projects(id) on delete set null,
  bubble_user_id text not null references public.app_users(bubble_user_id) on delete cascade,
  title text not null check (char_length(title) between 1 and 200),
  start_seconds numeric(10, 3) not null check (start_seconds >= 0),
  end_seconds numeric(10, 3) not null,
  fade_in_seconds numeric(6, 3) not null default 0.2 check (fade_in_seconds between 0 and 3),
  fade_out_seconds numeric(6, 3) not null default 0.2 check (fade_out_seconds between 0 and 3),
  gain_db numeric(6, 2) not null default 0 check (gain_db between -24 and 12),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (end_seconds > start_seconds),
  check (end_seconds - start_seconds between 5 and 30),
  check (fade_in_seconds + fade_out_seconds < end_seconds - start_seconds)
);

create index meta_audio_snippets_playlist_idx
  on public.meta_audio_snippets (playlist_id, created_at desc);
create index meta_audio_snippets_master_idx
  on public.meta_audio_snippets (master_id, start_seconds);

alter table public.meta_creative_variants
  add column audio_snippet_id uuid references public.meta_audio_snippets(id) on delete restrict;

create index meta_creative_variants_audio_snippet_idx
  on public.meta_creative_variants (audio_snippet_id)
  where audio_snippet_id is not null;

alter table public.meta_ads_campaign_drafts
  add column creative_notes text not null default '',
  add column audio_snippet_ids uuid[] not null default '{}'::uuid[];

alter table public.meta_audio_masters enable row level security;
alter table public.meta_audio_snippets enable row level security;

revoke all on table public.meta_audio_masters from public, anon, authenticated;
revoke all on table public.meta_audio_snippets from public, anon, authenticated;

grant select, insert, update, delete on table public.meta_audio_masters to service_role;
grant select, insert, update, delete on table public.meta_audio_snippets to service_role;

comment on table public.meta_audio_masters is
  'Original campaign audio uploads. Files are immutable; edits are represented by snippets.';
comment on table public.meta_audio_snippets is
  'Non-destructive playlist-ad audio regions with stable timing and fade DNA.';
