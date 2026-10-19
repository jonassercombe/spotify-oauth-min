# PlaylistPilot Firefox Extension

Firefox-first curator sidebar for Groover, SubmitHub and PlaylistPush.

## Current MVP

- reads the active curator page without modifying it
- detects the active track, Spotify ID, account, deadline and inbox counters
- signs in through a dedicated PlaylistPilot extension-auth page
- keeps working without an open PlaylistPilot web-app tab
- lists the user's PlaylistPilot playlists
- adds or updates a track with position, expiry and lock
- exposes a compact playlist manager with auto-expiry rules, backups and per-track move, lock, expiry and remove actions
- generates accept or decline feedback from curator notes and locally stored personal writing samples
- keeps a local account cockpit for Groover, SubmitHub and PlaylistPush profiles
- maps every platform profile to its own Firefox Container without storing platform passwords
- scans curator accounts and aggregates open and due-within-24-hours counters
- reports active, stale, closed and unreadable adapter/session states
- stores account-specific preferred playlist, expiry and slot-lock rules
- automatically prepares—but never submits—playlist placement settings for detected submissions
- counts visible submission deadlines when a platform exposes them reliably
- inserts a generated draft into the currently visible platform feedback field after an explicit click
- shows a compact round-avatar account switcher at the top of the sidebar
- focuses an existing account tab with one click instead of opening duplicates
- can keep configured platform/container sessions ready across Firefox starts
- surfaces cross-platform due-within-24-hours badges directly on account thumbnails
- shows adapter confidence, detected fields and page-structure warnings for every supported tab
- copies an anonymized adapter diagnostic without track, artist or account values
- requires a Review & Apply confirmation before every PlaylistPilot/Spotify playlist mutation
- organizes the sidebar into Focus, Queue and Tools views with a persistent bottom navigation
- lazy-loads full playlist-manager data only when Tools is opened
- hides zero-value secondary counters and keeps adapter details behind a compact status light

The extension never submits feedback or platform decisions to curator platforms. Generated drafts must be reviewed and submitted by the curator. “Insert into page” only fills the visible textarea and refuses a draft when the platform or detected submission changed.

The complete feedback style library stays in Firefox storage. Up to 24 selected reference samples are sent to the PlaylistPilot backend and OpenAI only when the curator explicitly generates a draft.

## Local installation

1. Start PlaylistPilot locally or deploy the companion API/app changes.
2. Open `about:debugging#/runtime/this-firefox`.
3. Choose **Load Temporary Add-on**.
4. Select `extension/manifest.json`.
5. Open the PlaylistPilot sidebar from Firefox.

For a packaged build:

```bash
npm run extension:validate
npm run extension:lint
npm run extension:package
```

The archive is written to `extension/dist/playlistpilot-firefox.zip`.

## Release candidate and Mozilla signing

Run the complete reproducible preflight from the repository root:

```bash
npm ci
npm run extension:release-check
```

The release package contains only the manifest, runtime scripts, icons, content adapters and sidebar assets. It does not include tests, build scripts, local files or credentials.

Create AMO API credentials in the Mozilla Add-ons Developer Hub and export them without committing them:

```bash
export WEB_EXT_API_KEY="user:…"
export WEB_EXT_API_SECRET="…"
```

For a limited signed test release:

```bash
npm run extension:sign:unlisted
```

For the public AMO listing and subsequent listed updates:

```bash
npm run extension:sign:listed
```

Signed artifacts are written below `extension/dist/<channel>/`. Increment `manifest.json` before every submitted update. AMO listing copy and reviewer notes live in `extension/amo/`. The published privacy policy is `https://playlist-pilot.com/privacy`.

## Architecture

- `background.js`: auth, API calls, multi-tab aggregation, account mappings and Firefox Containers
- `content/content-script.js`: read-only platform adapters and nonce-protected PlaylistPilot auth handoff
- `sidebar/`: persistent curator UI

Content adapters use visible DOM only. They do not read cookies, intercept private APIs or submit decisions.
Account names, Firefox Container IDs and session snapshots stay in local Firefox extension storage. The container ID is browser-local, so these mappings are intentionally not synced through Supabase.
