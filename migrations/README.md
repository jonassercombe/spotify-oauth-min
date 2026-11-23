# Legacy SQL Migrations (Historical Reference)

New database migrations must be added under `supabase/migrations/` using timestamped filenames so they are tracked and applied consistently via the Supabase CLI.

The files in this `migrations/` directory are retained for historical reference only. Security lock-downs originally applied from here (`restrict_public_rpc_execute.sql`) have been folded into `supabase/migrations/20261123102500_restrict_remaining_public_rpcs.sql`.
