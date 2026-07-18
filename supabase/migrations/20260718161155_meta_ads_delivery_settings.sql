alter table public.meta_ads_campaign_drafts
  add column start_date date,
  add column end_date date,
  add column placement_mode text not null default 'automatic'
    check (placement_mode in ('automatic', 'feeds', 'stories_reels')),
  add constraint meta_ads_campaign_drafts_delivery_dates_check
    check (end_date is null or start_date is null or end_date > start_date);
