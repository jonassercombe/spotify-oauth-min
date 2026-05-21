-- PlaylistPilot data is served through authenticated API routes using the
-- Supabase service role. Direct anon/authenticated Data API table reads are not
-- part of the web app contract, so keep the exposed public schema closed.

alter table public.app_users enable row level security;
alter table public.connection_rl_state enable row level security;
alter table public.plan_seats enable row level security;
alter table public.playlist_backups enable row level security;
alter table public.playlist_flex_settings enable row level security;
alter table public.playlist_flex_slots enable row level security;
alter table public.playlist_followers_daily enable row level security;
alter table public.playlist_followers_history enable row level security;
alter table public.playlist_growth_notes enable row level security;
alter table public.playlist_item_locks enable row level security;
alter table public.playlist_items enable row level security;
alter table public.playlist_items_feed enable row level security;
alter table public.playlists enable row level security;
alter table public.position_locks enable row level security;
alter table public.spotify_app_credentials enable row level security;
alter table public.spotify_connections enable row level security;
alter table public.subscription_events enable row level security;
alter table public.subscription_plans enable row level security;
alter table public.subscriptions enable row level security;
alter table public.user_identity_links enable row level security;

-- Retire policies from the Bubble-era direct Data API experiment. The current
-- app resolves ownership in API routes and accesses Supabase with service role.
drop policy if exists "admin_full_access_app_users" on public.app_users;
drop policy if exists "admin_full_access_playlist_items" on public.playlist_items;
drop policy if exists "debug select playlist_items" on public.playlist_items;
drop policy if exists "items_no_write_for_anon" on public.playlist_items;
drop policy if exists "items_select_via_parent" on public.playlist_items;
drop policy if exists "debug select playlists" on public.playlists;
drop policy if exists "playlists_no_delete_for_anon" on public.playlists;
drop policy if exists "playlists_no_insert_for_anon" on public.playlists;
drop policy if exists "playlists_no_update_for_anon" on public.playlists;
drop policy if exists "playlists_select_own" on public.playlists;
drop policy if exists "public read" on public.playlists;
drop policy if exists "public read test" on public.playlists;
drop policy if exists "admin_full_access_position_locks" on public.position_locks;
drop policy if exists "locks_no_write_for_anon" on public.position_locks;
drop policy if exists "locks_select_via_parent" on public.position_locks;
drop policy if exists "admin_full_access_spotify_connections" on public.spotify_connections;

-- Public views are security-definer by default. Make these invoke table access
-- as the caller, so RLS stays effective through REST view endpoints.
alter view public.playlist_items_ui set (security_invoker = true);
alter view public.playlist_items_with_age set (security_invoker = true);
alter view public.playlist_items_with_age_and_lock set (security_invoker = true);
alter view public.playlist_items_with_lock set (security_invoker = true);
alter view public.playlist_items_with_lock_fmt set (security_invoker = true);
