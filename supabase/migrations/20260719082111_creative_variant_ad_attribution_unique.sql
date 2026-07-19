create unique index meta_creative_variants_meta_ad_unique_idx
  on public.meta_creative_variants (meta_ad_id)
  where meta_ad_id is not null;

comment on index public.meta_creative_variants_meta_ad_unique_idx is
  'Prevents one Meta ad from being attributed to multiple experiment variants.';
