alter table public.meta_ads_campaign_drafts
  add column playlist_id uuid references public.playlists(id) on delete set null;

create index meta_ads_campaign_drafts_playlist_idx
  on public.meta_ads_campaign_drafts (playlist_id)
  where playlist_id is not null;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'meta-ad-creatives',
  'meta-ad-creatives',
  true,
  3145728,
  array['image/jpeg', 'image/png', 'image/webp']::text[]
)
on conflict (id) do update set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;
