# PlaylistPilot Curator — AMO listing copy

## Summary

A focused multi-account workspace for Spotify playlist curators.

## Description

PlaylistPilot Curator brings SubmitHub, Groover and PlaylistPush sessions into one quiet Firefox sidebar.

- Switch between curator accounts using Firefox Containers.
- Scan open submissions and items due within 24 hours on demand.
- Create account-specific feedback profiles and generate drafts from your own notes.
- Track confirmed playlist acceptances and apply platform-specific expiry rules in PlaylistPilot.
- Preview a focused Spotify track without changing tracks while you scroll.

The extension does not submit feedback or accept or decline submissions automatically. Final platform actions remain under the curator’s control.

PlaylistPilot account required. Some Spotify functionality requires a Spotify account and may require Spotify Premium.

Privacy policy: https://playlist-pilot.com/privacy

## Reviewer notes

PlaylistPilot Curator is a sidebar extension for authenticated curator workflows on SubmitHub, Groover and PlaylistPush.

1. Install the extension and open the sidebar from the toolbar button.
2. Choose “Connect” and authenticate on `https://playlist-pilot.com/extension-auth`.
3. Open a supported curator website. Content scripts read visible DOM only; they do not call private platform APIs.
4. “Scan all” is a user-triggered action that visits configured sessions and reads visible counters.
5. Feedback generation transmits the user’s notes and selected writing examples only after an explicit generation action.
6. Acceptance tracking observes a user-confirmed final platform action and records track metadata; the extension itself never performs the final submission.

Required permissions:

- `tabs`: locate, focus, open and scan explicitly configured curator sessions.
- `contextualIdentities`: assign separate platform accounts to Firefox Containers.
- `storage`: retain settings, feedback profiles, authentication and scan snapshots.
- `menus`: provide the explicit selection-to-feedback context menu.
- `alarms`: refresh the PlaylistPilot authentication session.
- Host access is limited to PlaylistPilot and the three supported curator platforms.

No remote JavaScript is executed in an extension page. The Spotify embed is an isolated HTTPS iframe hosted by PlaylistPilot and uses Spotify’s official IFrame API on that web origin.
