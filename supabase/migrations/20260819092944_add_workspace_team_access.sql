create table if not exists public.workspace_members (
  id uuid primary key default gen_random_uuid(),
  workspace_bubble_user_id text not null references public.app_users(bubble_user_id) on delete cascade,
  member_auth_user_id uuid references auth.users(id) on delete set null,
  member_email text not null,
  role text not null default 'member',
  status text not null default 'pending',
  invited_by_auth_user_id uuid references auth.users(id) on delete set null,
  invited_at timestamptz not null default now(),
  accepted_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint workspace_members_email_normalized check (member_email = lower(trim(member_email))),
  constraint workspace_members_role_check check (role in ('member')),
  constraint workspace_members_status_check check (status in ('pending', 'active', 'revoked')),
  unique (workspace_bubble_user_id, member_email)
);

create unique index if not exists workspace_members_active_auth_workspace_idx
  on public.workspace_members (workspace_bubble_user_id, member_auth_user_id)
  where member_auth_user_id is not null and status <> 'revoked';

create index if not exists workspace_members_auth_user_idx
  on public.workspace_members (member_auth_user_id, status);

create index if not exists workspace_members_email_idx
  on public.workspace_members (member_email, status);

create table if not exists public.workspace_connection_access (
  workspace_member_id uuid not null references public.workspace_members(id) on delete cascade,
  connection_id uuid not null references public.spotify_connections(id) on delete cascade,
  granted_by_auth_user_id uuid references auth.users(id) on delete set null,
  granted_at timestamptz not null default now(),
  primary key (workspace_member_id, connection_id)
);

create index if not exists workspace_connection_access_connection_idx
  on public.workspace_connection_access (connection_id);

alter table public.workspace_members enable row level security;
alter table public.workspace_connection_access enable row level security;

-- Team membership is resolved only by authenticated PlaylistPilot API routes.
-- Browser clients intentionally receive no direct table policies.
revoke all on table public.workspace_members from anon, authenticated;
revoke all on table public.workspace_connection_access from anon, authenticated;
