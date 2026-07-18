alter table public.meta_ads_campaign_drafts
  add column meta_adset_id text,
  add column meta_creative_id text,
  add column meta_ad_id text,
  add column creation_stage text not null default 'local'
    check (creation_stage in ('local', 'campaign', 'adset', 'creative', 'ad', 'complete'));
