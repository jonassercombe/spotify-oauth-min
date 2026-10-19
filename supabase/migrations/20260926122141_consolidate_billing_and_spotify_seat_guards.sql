-- Spotify connection changes must never rewrite subscription state from the
-- retired PayPal-era subscriptions table. Billing is owned by provider
-- webhooks and app_users.
drop trigger if exists t_connections_recompute_ad on public.spotify_connections;
drop trigger if exists t_connections_recompute_ai on public.spotify_connections;

-- Accept every subscription status Stripe can send. Restricting this column
-- to only the happy-path statuses made a legitimate `incomplete`, `unpaid` or
-- `paused` webhook fail and left the previous entitlement cached.
alter table public.app_users
  drop constraint if exists app_users_subscription_status_check;

alter table public.app_users
  add constraint app_users_subscription_status_check
  check (subscription_status = any (array[
    'none'::text,
    'active'::text,
    'trialing'::text,
    'past_due'::text,
    'canceled'::text,
    'incomplete'::text,
    'incomplete_expired'::text,
    'unpaid'::text,
    'paused'::text,
    'unknown'::text
  ]));

-- Normalize stale cached entitlements left by legacy/test providers. Manual
-- lifetime grants intentionally remain active without requiring an end date.
update public.app_users
set is_active = false,
    updated_at = now()
where provider is distinct from 'manual'
  and coalesce(current_period_end, subscription_expires_at) < now()
  and is_active is true;

-- Keep exactly one seat counter trigger instead of four overlapping variants.
drop trigger if exists trg_sc_recalc_seats_used_del on public.spotify_connections;
drop trigger if exists trg_sc_recalc_seats_used_ins on public.spotify_connections;
drop trigger if exists trg_sc_recalc_seats_used_upd on public.spotify_connections;
drop trigger if exists trg_spotify_connections_seats on public.spotify_connections;

create or replace function public.recalc_seats_for_user(p_uid text)
returns void
language plpgsql
set search_path = public, pg_temp
as $$
begin
  update public.app_users u
     set seats_used = (
       select count(*)::integer
       from public.spotify_connections s
       where s.bubble_user_id = p_uid
         and s.is_active is true
         and s.disabled_at is null
         and s.disconnected_at is null
     ),
     updated_at = now()
   where u.bubble_user_id = p_uid;
end
$$;

create or replace function public.trg_sc_recalc_seats()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
declare
  uid text;
begin
  uid := coalesce(new.bubble_user_id, old.bubble_user_id);
  if uid is not null then
    perform public.recalc_seats_for_user(uid);
  end if;
  if tg_op = 'UPDATE' and old.bubble_user_id is distinct from new.bubble_user_id then
    perform public.recalc_seats_for_user(old.bubble_user_id);
  end if;
  return null;
end
$$;

drop trigger if exists sc_after_iud on public.spotify_connections;
create trigger sc_after_iud
after insert or delete or update on public.spotify_connections
for each row execute function public.trg_sc_recalc_seats();

-- Serialize seat checks on the workspace row. This covers both new inserts and
-- reactivating an existing disabled connection, closing the old update bypass.
create or replace function public.trg_block_connection_over_seat()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_limit integer;
  v_used integer;
begin
  if new.is_active is not true or new.disabled_at is not null or new.disconnected_at is not null then
    return new;
  end if;

  select greatest(coalesce(u.seats_limit, 0), 0)
    into v_limit
  from public.app_users u
  where u.bubble_user_id = new.bubble_user_id
  for update;

  if v_limit is null then
    raise exception 'Workspace not found.' using errcode = 'P0001';
  end if;

  select count(*)::integer
    into v_used
  from public.spotify_connections c
  where c.bubble_user_id = new.bubble_user_id
    and c.is_active is true
    and c.disabled_at is null
    and c.disconnected_at is null
    and c.id is distinct from new.id;

  if v_used >= v_limit then
    raise exception 'Seat limit reached (% used of %).', v_used, v_limit
      using errcode = 'P0001';
  end if;

  return new;
end
$$;

revoke all on function public.trg_block_connection_over_seat() from public;

drop trigger if exists t_block_connection_over_seat on public.spotify_connections;
drop trigger if exists t_block_connection_over_seat_update on public.spotify_connections;

create trigger t_block_connection_over_seat
before insert on public.spotify_connections
for each row execute function public.trg_block_connection_over_seat();

create trigger t_block_connection_over_seat_update
before update of is_active, bubble_user_id, disabled_at, disconnected_at
on public.spotify_connections
for each row execute function public.trg_block_connection_over_seat();

-- Repair cached seat counts after consolidating the triggers.
update public.app_users u
set seats_used = (
  select count(*)::integer
  from public.spotify_connections c
  where c.bubble_user_id = u.bubble_user_id
    and c.is_active is true
    and c.disabled_at is null
    and c.disconnected_at is null
),
updated_at = now();
