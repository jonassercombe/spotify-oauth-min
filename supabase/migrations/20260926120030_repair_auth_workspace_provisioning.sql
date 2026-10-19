-- A freshly authenticated user has no subscription yet. The application has
-- always represented that state as `none`, but the production constraint did
-- not allow it, causing workspace provisioning to fail after successful auth.
alter table public.app_users
  drop constraint if exists app_users_subscription_status_check;

alter table public.app_users
  add constraint app_users_subscription_status_check
  check (subscription_status = any (array[
    'none'::text,
    'active'::text,
    'trialing'::text,
    'past_due'::text,
    'canceled'::text
  ]));

-- Repair auth users left without a PlaylistPilot identity link by the failed
-- provisioning attempt. These workspaces stay inactive and receive no paid
-- features until billing is completed.
insert into public.app_users (
  bubble_user_id,
  subscription_status,
  sub_status,
  is_active,
  seats_limit,
  seats_used
)
select
  'auth:' || u.id::text,
  'none',
  'none',
  false,
  0,
  0
from auth.users u
left join public.user_identity_links l on l.auth_user_id = u.id
where l.id is null
on conflict (bubble_user_id) do nothing;

insert into public.user_identity_links (
  auth_user_id,
  email,
  bubble_user_id,
  role
)
select
  u.id,
  lower(u.email),
  'auth:' || u.id::text,
  'user'
from auth.users u
left join public.user_identity_links by_auth on by_auth.auth_user_id = u.id
left join public.user_identity_links by_email on lower(by_email.email) = lower(u.email)
where by_auth.id is null
  and by_email.id is null
  and u.email is not null
on conflict do nothing;
