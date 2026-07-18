create table if not exists public.playlist_ad_events (
  id uuid primary key default gen_random_uuid(),
  bubble_user_id text not null,
  playlist_id uuid not null references public.playlists(id) on delete cascade,
  event_date date not null,
  daily_spend numeric(12,2) not null default 0,
  currency text not null default 'EUR',
  label text,
  note text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists playlist_ad_events_user_date_idx on public.playlist_ad_events (bubble_user_id, event_date desc);
create index if not exists playlist_ad_events_playlist_date_idx on public.playlist_ad_events (playlist_id, event_date desc);

alter table public.playlist_ad_events enable row level security;

grant select, insert, update, delete on public.playlist_ad_events to service_role;

create or replace function public.set_playlist_ad_events_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists playlist_ad_events_set_updated_at on public.playlist_ad_events;
create trigger playlist_ad_events_set_updated_at
before update on public.playlist_ad_events
for each row execute function public.set_playlist_ad_events_updated_at();
