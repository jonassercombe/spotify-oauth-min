alter table public.meta_creative_concepts
  add column production_type text not null default 'stock_simple'
    check (production_type in ('stock_simple', 'stock_montage', 'experimental_wildcard')),
  add column footage_criteria text[] not null default '{}'::text[],
  add column north_star_story text not null default '';

comment on column public.meta_creative_concepts.visual_direction is
  'One-sentence executable stock-footage treatment, not an aspirational storyboard.';
comment on column public.meta_creative_concepts.footage_criteria is
  'Five to seven visible, frame-verifiable requirements used for Pexels Vision ranking.';
comment on column public.meta_creative_concepts.north_star_story is
  'Optional ambitious creative direction; explicitly excluded from literal stock-footage matching.';
