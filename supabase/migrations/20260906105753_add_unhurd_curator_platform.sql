alter table public.curator_accepted_tracks
  drop constraint if exists curator_accepted_tracks_platform_check;
alter table public.curator_accepted_tracks
  add constraint curator_accepted_tracks_platform_check
  check (platform in ('groover', 'playlistpush', 'submithub', 'unhurd')) not valid;
alter table public.curator_accepted_tracks
  validate constraint curator_accepted_tracks_platform_check;

alter table public.curator_review_earning_rates
  drop constraint if exists curator_review_earning_rates_platform_check;
alter table public.curator_review_earning_rates
  add constraint curator_review_earning_rates_platform_check
  check (platform in ('groover', 'playlistpush', 'submithub', 'unhurd')) not valid;
alter table public.curator_review_earning_rates
  validate constraint curator_review_earning_rates_platform_check;

alter table public.curator_review_earnings
  drop constraint if exists curator_review_earnings_platform_check;
alter table public.curator_review_earnings
  add constraint curator_review_earnings_platform_check
  check (platform in ('groover', 'playlistpush', 'submithub', 'unhurd')) not valid;
alter table public.curator_review_earnings
  validate constraint curator_review_earnings_platform_check;

alter table public.feedback_profiles
  drop constraint if exists feedback_profiles_scope_check;
alter table public.feedback_profiles
  add constraint feedback_profiles_scope_check check (
    scope = 'global'
    or scope in ('platform:groover', 'platform:submithub', 'platform:playlistpush', 'platform:unhurd')
    or scope ~ '^account:[A-Za-z0-9._:-]{1,160}$'
  ) not valid;
alter table public.feedback_profiles
  validate constraint feedback_profiles_scope_check;
