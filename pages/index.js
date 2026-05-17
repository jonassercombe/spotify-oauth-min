import { useEffect, useMemo, useState } from "react";
import { getSupabaseBrowserClient } from "../lib/supabaseBrowser";

async function api(path, { method = "GET", accessToken, body } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;

  const res = await fetch(path, {
    method,
    headers,
    ...(body ? { body: JSON.stringify(body) } : {}),
  });

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error(data?.error || `Request failed: ${res.status}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

function formatNumber(value) {
  if (value === null || value === undefined) return "0";
  return new Intl.NumberFormat("en-US").format(value);
}

function Field({ label, children }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
}

export default function PlaylistManager() {
  const [supabase, setSupabase] = useState(null);
  const [session, setSession] = useState(null);
  const [userContext, setUserContext] = useState(null);
  const [connections, setConnections] = useState([]);
  const [connectionId, setConnectionId] = useState("");
  const [playlists, setPlaylists] = useState([]);
  const [playlistId, setPlaylistId] = useState("");
  const [playlist, setPlaylist] = useState(null);
  const [tracks, setTracks] = useState([]);
  const [playlistSearch, setPlaylistSearch] = useState("");
  const [trackSearch, setTrackSearch] = useState("");
  const [trackLink, setTrackLink] = useState("");
  const [trackPosition, setTrackPosition] = useState("1");
  const [trackExpiry, setTrackExpiry] = useState("");
  const [autoWeeks, setAutoWeeks] = useState("4");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    const client = getSupabaseBrowserClient();
    setSupabase(client);

    client.auth.getSession().then(({ data }) => {
      setSession(data.session || null);
    });

    const { data: listener } = client.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession || null);
      setUserContext(null);
      setConnections([]);
      setPlaylists([]);
      setPlaylistId("");
      setPlaylist(null);
      setTracks([]);
    });

    return () => listener.subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (!session?.access_token) return;
    loadCurrentUser();
  }, [session?.access_token]);

  useEffect(() => {
    if (!userContext?.linked) return;
    loadConnections();
  }, [userContext?.linked]);

  useEffect(() => {
    if (!userContext?.linked) return;
    loadPlaylists();
  }, [userContext?.linked, connectionId]);

  useEffect(() => {
    if (!playlistId) {
      setPlaylist(null);
      setTracks([]);
      return;
    }
    loadSelectedPlaylist();
  }, [playlistId]);

  const filteredPlaylists = useMemo(() => {
    const q = playlistSearch.trim().toLowerCase();
    if (!q) return playlists;
    return playlists.filter((p) => String(p.name || "").toLowerCase().includes(q));
  }, [playlists, playlistSearch]);

  const filteredTracks = useMemo(() => {
    const q = trackSearch.trim().toLowerCase();
    if (!q) return tracks;
    return tracks.filter((t) =>
      [t.track_name, t.artist_names, t.album_name].some((v) =>
        String(v || "").toLowerCase().includes(q)
      )
    );
  }, [tracks, trackSearch]);

  async function run(label, fn) {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const result = await fn();
      setMessage(label);
      return result;
    } catch (e) {
      setError(e.message || String(e));
      return null;
    } finally {
      setBusy(false);
    }
  }

  function accessToken() {
    return session?.access_token || "";
  }

  async function signInWithGoogle() {
    setError("");
    await supabase.auth.signInWithOAuth({
      provider: "google",
      options: {
        redirectTo: window.location.origin,
      },
    });
  }

  async function signOut() {
    await supabase.auth.signOut();
  }

  async function loadCurrentUser() {
    return run("Signed in", async () => {
      let data;
      try {
        data = await api("/api/auth/me", { accessToken: accessToken() });
      } catch (e) {
        if (e.status === 403 && e.data) data = e.data;
        else throw e;
      }
      setUserContext(data);
      return data;
    });
  }

  async function loadConnections() {
    return run("Connections loaded", async () => {
      const data = await api("/api/connections/list", { accessToken: accessToken() });
      setConnections(data);
      if (!connectionId && data[0]?.id) setConnectionId(data[0].id);
      return data;
    });
  }

  async function loadPlaylists() {
    return run("Playlists loaded", async () => {
      const qs = new URLSearchParams();
      if (connectionId) qs.set("connection_id", connectionId);
      const query = qs.toString();
      const data = await api(`/api/playlists/list${query ? `?${query}` : ""}`, { accessToken: accessToken() });
      setPlaylists(data);
      if (!data.some((p) => p.id === playlistId)) {
        setPlaylistId(data[0]?.id || "");
      }
      return data;
    });
  }

  async function refreshFromSpotify() {
    if (!connectionId) return;
    await run("Spotify playlists refreshed", async () => {
      await api("/api/playlists/sync?with_followers=1", {
        method: "POST",
        accessToken: accessToken(),
        body: { connection_id: connectionId },
      });
      await loadPlaylists();
    });
  }

  async function loadSelectedPlaylist() {
    return run("Tracks loaded", async () => {
      const [detail, items] = await Promise.all([
        api(`/api/playlists/get?playlist_id=${encodeURIComponent(playlistId)}`, { accessToken: accessToken() }),
        api(`/api/playlist-items/list?playlist_row_id=${encodeURIComponent(playlistId)}`, { accessToken: accessToken() }),
      ]);
      setPlaylist(detail);
      setAutoWeeks(detail?.auto_remove_weeks ? String(detail.auto_remove_weeks) : "4");
      setTracks(items);
      return { detail, items };
    });
  }

  async function addTrack() {
    if (!playlistId || !trackLink.trim()) return;
    await run("Track added; sync dispatched", async () => {
      await api("/api/playlist-items/add", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          playlist_id: playlistId,
          link_or_uri: trackLink,
          position: trackPosition,
          exp_weeks: trackExpiry || undefined,
        },
      });
      setTrackLink("");
      await loadSelectedPlaylist();
    });
  }

  async function moveTrack(track, dir) {
    await run("Track move queued", async () => {
      await api("/api/playlist-items/move", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          playlist_id: playlistId,
          track_id: track.track_id,
          dir,
          steps: 1,
        },
      });
      await loadSelectedPlaylist();
    });
  }

  async function removeTrack(track) {
    await run("Track removed; sync dispatched", async () => {
      await api("/api/playlist-items/remove", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          playlist_id: playlistId,
          track_id: track.track_id,
          position0: track.position,
        },
      });
      await loadSelectedPlaylist();
    });
  }

  async function toggleLock(track) {
    await run(track.is_locked ? "Lock removed" : "Track locked", async () => {
      if (track.is_locked) {
        await api("/api/locks/unset", {
          method: "POST",
          accessToken: accessToken(),
          body: { playlist_id: playlistId, track_id: track.track_id },
        });
      } else {
        await api("/api/locks/set", {
          method: "POST",
          accessToken: accessToken(),
          body: {
            playlist_id: playlistId,
            track_id: track.track_id,
            locked_position: Number(track.position) + 1,
            is_locked: true,
            exp_weeks: track.expiry_weeks || undefined,
          },
        });
      }
      await loadSelectedPlaylist();
    });
  }

  async function setSongExpiry(track) {
    const value = window.prompt("Expiry in weeks. Empty clears song expiry.", track.expiry_weeks || "");
    if (value === null) return;
    await run("Song expiry updated", async () => {
      await api("/api/locks/set", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          playlist_id: playlistId,
          track_id: track.track_id,
          locked_position: Number(track.locked_position ?? track.position),
          is_locked: !!track.is_locked,
          exp_weeks: value.trim() === "" ? null : value,
        },
      });
      await loadSelectedPlaylist();
    });
  }

  async function saveAutoRemoval() {
    await run("Auto-removal settings saved", async () => {
      await api("/api/playlists/settings/save", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          playlist_id: playlistId,
          auto_remove_enabled: true,
          auto_remove_weeks: Number(autoWeeks),
        },
      });
      await loadSelectedPlaylist();
    });
  }

  async function cleanupNow() {
    await run("Cleanup queued", async () => {
      await api("/api/playlists/maintenance", {
        method: "POST",
        accessToken: accessToken(),
        body: { playlist_id: playlistId },
      });
      await loadSelectedPlaylist();
    });
  }

  return (
    <main>
      <header className="topbar">
        <div className="brand">
          <div className="logo">PP</div>
          <div>
            <h1>Playlist Pilot</h1>
            <p>Playlist Manager</p>
          </div>
        </div>
        <nav>
          <a>Dashboard</a>
          <a className="active">Playlist Manager</a>
          {session ? <button onClick={signOut}>Log Out</button> : null}
        </nav>
      </header>

      {!session ? (
        <section className="loginScreen">
          <h2>Sign in to Playlist Pilot</h2>
          <p>Use the Google account linked to your existing Playlist Pilot workspace.</p>
          <button onClick={signInWithGoogle} disabled={!supabase}>Continue with Google</button>
          {error ? <strong>{error}</strong> : null}
        </section>
      ) : userContext && !userContext.linked ? (
        <section className="loginScreen">
          <h2>Account not linked</h2>
          <p>{userContext.email} is signed in, but no Playlist Pilot workspace is linked yet.</p>
          <button onClick={signOut}>Log Out</button>
        </section>
      ) : !userContext ? (
        <section className="loginScreen">
          <h2>Loading workspace</h2>
          {error ? <strong>{error}</strong> : null}
        </section>
      ) : (
      <>

      <section className="workspace">
        <aside className="sidebar">
          <div className="accountBox">
            <span>Signed in</span>
            <strong>{userContext.email}</strong>
          </div>

          <Field label="Account">
            <select value={connectionId} onChange={(e) => setConnectionId(e.target.value)}>
              <option value="">Select account</option>
              {connections.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.display_name || c.spotify_user_id}
                </option>
              ))}
            </select>
          </Field>

          <button
            onClick={() => {
              const qs = new URLSearchParams({
                bubble_user_id: userContext.bubble_user_id,
                return_to: window.location.origin,
              });
              window.location.href = `/api/oauth/spotify/start?${qs.toString()}`;
            }}
          >
            Connect Spotify
          </button>

          <div className="sectionTitle">
            <h2>Playlists</h2>
            <button disabled={busy || !connectionId} onClick={refreshFromSpotify}>
              Refresh
            </button>
          </div>
          <input
            value={playlistSearch}
            onChange={(e) => setPlaylistSearch(e.target.value)}
            placeholder="Search playlists"
          />

          <div className="playlistList">
            {filteredPlaylists.map((p) => (
              <button
                className={`playlistCard ${p.id === playlistId ? "selected" : ""}`}
                key={p.id}
                onClick={() => setPlaylistId(p.id)}
              >
                {p.image ? <img src={p.image} alt="" /> : <div className="coverFallback" />}
                <span>
                  <strong>{p.name}</strong>
                  <small>
                    {formatNumber(p.tracks_total)} tracks · {formatNumber(p.followers)} followers
                  </small>
                </span>
              </button>
            ))}
          </div>
        </aside>

        <section className="content">
          <div className="statusLine">
            {message ? <span>{message}</span> : <span />}
            {error ? <strong>{error}</strong> : null}
          </div>

          <div className="playlistHeader">
            <div>
              <h2>Selected Playlist</h2>
              <h3>{playlist?.name || "No playlist selected"}</h3>
              <p>
                {formatNumber(playlist?.tracks_total)} Tracks · {formatNumber(playlist?.followers)} Followers
              </p>
            </div>
            <div className="headerActions">
              <Field label="Auto-removal weeks">
                <input
                  type="number"
                  min="1"
                  max="104"
                  value={autoWeeks}
                  onChange={(e) => setAutoWeeks(e.target.value)}
                />
              </Field>
              <button disabled={busy || !playlistId} onClick={saveAutoRemoval}>
                Set Auto-Removal
              </button>
              <button disabled={busy || !playlistId} onClick={cleanupNow}>
                Trigger Cleanup
              </button>
            </div>
          </div>

          <div className="addTrack">
            <strong>Add Track</strong>
            <input
              value={trackLink}
              onChange={(e) => setTrackLink(e.target.value)}
              placeholder="...paste song link"
            />
            <Field label="pos">
              <input value={trackPosition} onChange={(e) => setTrackPosition(e.target.value)} />
            </Field>
            <Field label="exp">
              <input value={trackExpiry} onChange={(e) => setTrackExpiry(e.target.value)} />
            </Field>
            <button disabled={busy || !playlistId || !trackLink.trim()} onClick={addTrack}>
              +
            </button>
          </div>

          <div className="trackPanel">
            <div className="trackPanelHeader">
              <h2>Tracks</h2>
              <input
                value={trackSearch}
                onChange={(e) => setTrackSearch(e.target.value)}
                placeholder="Search tracks"
              />
            </div>
            <div className="trackList">
              {filteredTracks.map((track) => (
                <article key={`${track.position}-${track.track_id}`} className="trackRow">
                  <div className="pos">{Number(track.position) + 1}</div>
                  <div className="age">{track.age_label || "age unknown"}</div>
                  {track.cover_url ? <img src={track.cover_url} alt="" /> : <div className="coverFallback" />}
                  <div className="trackMeta">
                    <strong>{track.track_name || track.track_id}</strong>
                    <span>{track.artist_names || "Unknown artist"} · {track.album_name || "Unknown album"}</span>
                  </div>
                  <div className="duration">{track.duration_formatted || ""}</div>
                  <div className="badges">
                    {track.is_locked ? <span className="locked">Locked</span> : null}
                    {track.expiry_weeks ? <span className="expiry">{track.expiry_weeks}w</span> : null}
                  </div>
                  <button disabled={busy} onClick={() => toggleLock(track)}>
                    {track.is_locked ? "Unlock" : "Set Lock"}
                  </button>
                  <button disabled={busy} onClick={() => setSongExpiry(track)}>
                    Exp
                  </button>
                  <button disabled={busy || track.position <= 0} onClick={() => moveTrack(track, "up")}>
                    ↑
                  </button>
                  <button disabled={busy} onClick={() => moveTrack(track, "down")}>
                    ↓
                  </button>
                  <button className="danger" disabled={busy} onClick={() => removeTrack(track)}>
                    Remove
                  </button>
                </article>
              ))}
            </div>
          </div>
        </section>
      </section>
      </>
      )}

      <style jsx>{`
        :global(body) {
          margin: 0;
          background: #12151a;
          color: #f4f6fb;
          font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }
        button, input, select {
          font: inherit;
        }
        button {
          border: 1px solid #18e06f;
          background: #1b2028;
          color: #18e06f;
          border-radius: 8px;
          padding: 10px 14px;
          cursor: pointer;
        }
        button:disabled {
          cursor: not-allowed;
          opacity: 0.45;
        }
        input, select {
          min-width: 0;
          border: 1px solid #303743;
          background: #222731;
          color: #f4f6fb;
          border-radius: 8px;
          padding: 12px 14px;
          outline: none;
        }
        input:focus, select:focus {
          border-color: #18e06f;
        }
        main {
          min-height: 100vh;
        }
        .topbar {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 28px 40px;
          gap: 24px;
        }
        .brand {
          display: flex;
          align-items: center;
          gap: 18px;
        }
        .logo {
          display: grid;
          place-items: center;
          width: 72px;
          height: 72px;
          border-radius: 14px;
          background: #082331;
          color: #18e06f;
          font-weight: 800;
        }
        h1, h2, h3, p {
          margin: 0;
        }
        h1 {
          font-size: 34px;
          line-height: 1;
        }
        .brand p, .playlistHeader p, small, .trackMeta span, .age, .duration {
          color: #a6adba;
        }
        nav {
          display: flex;
          align-items: center;
          gap: 32px;
          color: #18e06f;
          font-size: 18px;
        }
        nav button {
          min-width: 112px;
        }
        .loginScreen {
          display: grid;
          gap: 18px;
          align-content: center;
          justify-items: start;
          min-height: 58vh;
          max-width: 620px;
          padding: 40px;
        }
        .loginScreen h2 {
          font-size: 34px;
        }
        .loginScreen p {
          color: #a6adba;
          font-size: 18px;
          line-height: 1.5;
        }
        .loginScreen strong {
          color: #ff4d4d;
        }
        .accountBox {
          display: grid;
          gap: 6px;
          padding: 14px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #181c23;
        }
        .accountBox span {
          color: #a6adba;
          font-size: 13px;
        }
        .accountBox strong {
          overflow-wrap: anywhere;
        }
        nav .active {
          border: 1px solid #18e06f;
          border-radius: 8px;
          padding: 16px 22px;
        }
        .workspace {
          display: grid;
          grid-template-columns: minmax(340px, 30vw) 1fr;
          gap: 34px;
          padding: 36px 40px 52px;
        }
        .sidebar, .content {
          min-width: 0;
        }
        .field {
          display: grid;
          gap: 8px;
          color: #f4f6fb;
          font-weight: 700;
        }
        .field span {
          font-size: 14px;
          color: #a6adba;
        }
        .sidebar {
          display: grid;
          align-content: start;
          gap: 20px;
        }
        .sectionTitle, .trackPanelHeader, .playlistHeader, .addTrack, .statusLine {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
        }
        .playlistList {
          display: grid;
          gap: 18px;
          max-height: 72vh;
          overflow: auto;
          padding-right: 6px;
        }
        .playlistCard {
          display: grid;
          grid-template-columns: 76px 1fr;
          align-items: center;
          gap: 18px;
          width: 100%;
          min-height: 116px;
          padding: 20px;
          border-color: #2a303b;
          color: #f4f6fb;
          text-align: left;
        }
        .playlistCard.selected {
          border-color: #18e06f;
        }
        .playlistCard img, .coverFallback {
          width: 76px;
          height: 76px;
          border-radius: 4px;
          object-fit: cover;
          background: #303743;
        }
        .playlistCard span {
          display: grid;
          gap: 8px;
        }
        .playlistCard strong {
          font-size: 18px;
        }
        .content {
          display: grid;
          align-content: start;
          gap: 28px;
        }
        .statusLine {
          min-height: 24px;
          color: #18e06f;
        }
        .statusLine strong {
          color: #ff4d4d;
          font-weight: 700;
        }
        .playlistHeader {
          align-items: end;
        }
        .playlistHeader h2 {
          font-size: 32px;
        }
        .playlistHeader h3 {
          margin-top: 26px;
          font-size: 28px;
        }
        .playlistHeader p {
          margin-top: 18px;
          font-size: 18px;
        }
        .headerActions {
          display: flex;
          align-items: end;
          gap: 14px;
          flex-wrap: wrap;
          justify-content: flex-end;
        }
        .headerActions input, .addTrack .field input {
          width: 72px;
        }
        .addTrack {
          display: grid;
          grid-template-columns: auto minmax(220px, 1fr) auto auto 56px;
          align-items: end;
        }
        .addTrack strong {
          font-size: 24px;
          padding-bottom: 11px;
        }
        .addTrack button {
          min-height: 48px;
          font-size: 26px;
          font-weight: 800;
          padding: 4px 14px;
        }
        .trackPanel {
          border: 1px solid #2a303b;
          background: #181c23;
        }
        .trackPanelHeader {
          background: #222831;
          padding: 22px 26px;
        }
        .trackPanelHeader h2 {
          font-size: 24px;
        }
        .trackPanelHeader input {
          width: min(360px, 45%);
        }
        .trackList {
          display: grid;
        }
        .trackRow {
          display: grid;
          grid-template-columns: 52px 160px 52px minmax(220px, 1fr) 54px 110px auto auto 48px 48px auto;
          align-items: center;
          gap: 14px;
          min-height: 92px;
          padding: 16px 24px;
          border-top: 1px solid #202630;
        }
        .trackRow img, .trackRow .coverFallback {
          width: 52px;
          height: 52px;
        }
        .trackMeta {
          display: grid;
          min-width: 0;
          gap: 4px;
        }
        .trackMeta strong, .trackMeta span {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .pos {
          color: #a6adba;
          font-size: 18px;
          text-align: center;
        }
        .badges {
          display: flex;
          gap: 6px;
          min-height: 24px;
        }
        .badges span {
          border-radius: 999px;
          padding: 4px 8px;
          font-size: 12px;
          font-weight: 800;
        }
        .locked {
          color: #18e06f;
          background: rgba(24, 224, 111, 0.12);
        }
        .expiry {
          color: #ffbd4a;
          background: rgba(255, 189, 74, 0.12);
        }
        .danger {
          border-color: #ff4d4d;
          background: #ef4242;
          color: white;
        }
        @media (max-width: 1100px) {
          .topbar, nav, .playlistHeader, .sectionTitle {
            align-items: flex-start;
          }
          .topbar, .playlistHeader {
            flex-direction: column;
          }
          nav {
            flex-wrap: wrap;
            gap: 14px;
          }
          .workspace {
            grid-template-columns: 1fr;
            padding: 24px;
          }
          .trackRow {
            grid-template-columns: 42px 1fr auto auto;
          }
          .age, .duration, .badges {
            display: none;
          }
          .trackRow img, .trackRow .coverFallback {
            display: none;
          }
        }
        @media (max-width: 720px) {
          .topbar {
            padding: 22px;
          }
          .brand {
            align-items: flex-start;
          }
          .logo {
            width: 70px;
            height: 70px;
            flex: 0 0 auto;
          }
          nav {
            display: grid;
            grid-template-columns: 1fr;
            width: 100%;
          }
          nav .active {
            width: fit-content;
          }
          .workspace {
            padding: 22px;
            gap: 40px;
          }
          .sectionTitle {
            display: grid;
            grid-template-columns: 1fr auto;
            align-items: center;
          }
          .playlistHeader {
            align-items: stretch;
          }
          .headerActions {
            display: grid;
            grid-template-columns: 1fr;
            align-items: stretch;
            justify-content: stretch;
          }
          .headerActions .field {
            width: 100%;
          }
          .headerActions input,
          .headerActions button {
            width: 100%;
            box-sizing: border-box;
          }
          .addTrack {
            grid-template-columns: 1fr;
            align-items: stretch;
          }
          .addTrack strong {
            padding-bottom: 0;
          }
          .addTrack input,
          .addTrack button {
            width: 100%;
            box-sizing: border-box;
          }
          .playlistHeader h2 {
            font-size: 26px;
          }
          .playlistHeader h3 {
            font-size: 22px;
          }
        }
      `}</style>
    </main>
  );
}
