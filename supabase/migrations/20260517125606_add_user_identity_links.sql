create table if not exists public.user_identity_links (
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid unique references auth.users(id) on delete cascade,
  email text not null unique,
  bubble_user_id text not null references public.app_users(bubble_user_id) on delete restrict,
  role text not null default 'user',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint user_identity_links_role_check check (role in ('user', 'admin'))
);

create index if not exists user_identity_links_bubble_user_id_idx
  on public.user_identity_links(bubble_user_id);

insert into public.user_identity_links (email, bubble_user_id, role)
values ('jonassercombe@googlemail.com', '1767994526101x684258361600929900', 'admin')
on conflict (email) do update set
  bubble_user_id = excluded.bubble_user_id,
  role = excluded.role,
  updated_at = now();;
