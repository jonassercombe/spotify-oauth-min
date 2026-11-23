-- Ensure all public schema functions (including seat-guard functions added in
-- 20260926122141_consolidate_billing_and_spotify_seat_guards.sql) are restricted
-- to service_role and not executable by browser roles (public, anon, authenticated).
-- Idempotent: safe to apply on both existing production and fresh staging databases.

revoke all on function public.recalc_seats_for_user(text) from public, anon, authenticated;
grant execute on function public.recalc_seats_for_user(text) to service_role;

revoke all on function public.trg_sc_recalc_seats() from public, anon, authenticated;
grant execute on function public.trg_sc_recalc_seats() to service_role;

revoke all on function public.trg_block_connection_over_seat() from public, anon, authenticated;
grant execute on function public.trg_block_connection_over_seat() to service_role;

do $$
declare
  fn record;
begin
  for fn in
    select p.oid::regprocedure as signature
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
  loop
    execute format('revoke execute on function %s from public', fn.signature);
    execute format('revoke execute on function %s from anon', fn.signature);
    execute format('revoke execute on function %s from authenticated', fn.signature);
    execute format('grant execute on function %s to service_role', fn.signature);
  end loop;
end $$;
