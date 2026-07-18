-- Meta Ads tables are server-only, but current Supabase projects require
-- explicit Data API grants for every role that should reach new tables.
grant select, insert, update, delete on table public.meta_ads_connections to service_role;
grant select, insert, update, delete on table public.meta_ads_assets to service_role;
grant select, insert, update, delete on table public.meta_ads_audit_events to service_role;
grant usage, select on sequence public.meta_ads_audit_events_id_seq to service_role;

-- At most one default asset of each type can be selected per connection.
create unique index if not exists meta_ads_assets_one_selected_per_type_idx
  on public.meta_ads_assets (connection_id, asset_type)
  where is_selected;

-- Select the default asset atomically. This remains inaccessible to browser
-- roles and executes with the caller's privileges (the server's service role).
create or replace function public.select_meta_ads_asset(
  p_connection_id uuid,
  p_asset_id uuid
)
returns public.meta_ads_assets
language plpgsql
security invoker
set search_path = ''
as $$
declare
  selected_asset public.meta_ads_assets;
begin
  select *
    into selected_asset
    from public.meta_ads_assets
   where id = p_asset_id
     and connection_id = p_connection_id
   for update;

  if not found then
    raise exception 'meta_asset_not_found';
  end if;

  update public.meta_ads_assets
     set is_selected = false,
         updated_at = now()
   where connection_id = p_connection_id
     and asset_type = selected_asset.asset_type
     and id <> p_asset_id
     and is_selected;

  update public.meta_ads_assets
     set is_selected = true,
         updated_at = now()
   where id = p_asset_id
  returning * into selected_asset;

  return selected_asset;
end;
$$;

revoke all on function public.select_meta_ads_asset(uuid, uuid) from public, anon, authenticated;
grant execute on function public.select_meta_ads_asset(uuid, uuid) to service_role;
