create table if not exists public.feedback_profiles (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid not null references auth.users(id) on delete cascade,
  bubble_user_id text not null,
  name text not null check (char_length(name) between 1 and 80),
  scope text not null default 'global' check (
    scope = 'global'
    or scope in ('platform:groover', 'platform:submithub', 'platform:playlistpush')
    or scope ~ '^account:[A-Za-z0-9._:-]{1,160}$'
  ),
  language text not null default 'auto' check (language in ('auto', 'en', 'de')),
  tone text not null default 'matched' check (tone in ('matched', 'warm', 'direct', 'casual')),
  length text not null default 'matched' check (length in ('matched', 'short', 'medium', 'long')),
  imperfections text not null default 'matched' check (imperfections in ('matched', 'none', 'subtle', 'natural')),
  grammar text not null default 'matched' check (grammar in ('matched', 'clean', 'casual', 'rough')),
  custom_rules text not null default '',
  reference_feedback text not null default '',
  sort_order integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (auth_user_id, name)
);

create index if not exists feedback_profiles_auth_user_sort_idx
  on public.feedback_profiles (auth_user_id, sort_order, created_at);

create index if not exists feedback_profiles_bubble_user_idx
  on public.feedback_profiles (bubble_user_id);

alter table public.feedback_profiles enable row level security;

drop policy if exists "feedback_profiles_select_own" on public.feedback_profiles;
create policy "feedback_profiles_select_own"
  on public.feedback_profiles for select
  to authenticated
  using ((select auth.uid()) = auth_user_id);

drop policy if exists "feedback_profiles_insert_own" on public.feedback_profiles;
create policy "feedback_profiles_insert_own"
  on public.feedback_profiles for insert
  to authenticated
  with check ((select auth.uid()) = auth_user_id);

drop policy if exists "feedback_profiles_update_own" on public.feedback_profiles;
create policy "feedback_profiles_update_own"
  on public.feedback_profiles for update
  to authenticated
  using ((select auth.uid()) = auth_user_id)
  with check ((select auth.uid()) = auth_user_id);

drop policy if exists "feedback_profiles_delete_own" on public.feedback_profiles;
create policy "feedback_profiles_delete_own"
  on public.feedback_profiles for delete
  to authenticated
  using ((select auth.uid()) = auth_user_id);

grant select, insert, update, delete on public.feedback_profiles to authenticated;
