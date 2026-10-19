alter table public.playlist_flex_settings
  add column if not exists repeat_cooldown_weeks integer not null default 8,
  add column if not exists avoid_target_duplicates boolean not null default true,
  add column if not exists min_popularity integer,
  add column if not exists max_popularity integer,
  add column if not exists max_release_age_weeks integer;
