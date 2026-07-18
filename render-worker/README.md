# PlaylistPilot render worker

Runs one low-priority FFmpeg render at a time. The worker only receives a PlaylistPilot worker secret and a two-hour signed upload URL scoped to the current MP4 path; it does not receive the Supabase service key.

Required environment:

- `RENDER_WORKER_SECRET`
- `PLAYLISTPILOT_API_BASE` (defaults to production)

Optional limits:

- `RENDER_MAX_LOAD=3.6`
- `RENDER_POLL_SECONDS=5`
- `RENDER_HTTP_TIMEOUT=180`
