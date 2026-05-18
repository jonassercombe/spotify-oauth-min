import { useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, GripVertical, Lock, Shuffle, TimerReset, Trash2, Unlock } from "lucide-react";
import { getSupabaseBrowserClient } from "../lib/supabaseBrowser";

const ENABLE_OPTIMISTIC_PLAYLIST_UI = true;

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

function formatDelta(value) {
  const n = Number(value) || 0;
  if (n > 0) return `+${formatNumber(n)}`;
  return formatNumber(n);
}

function formatShortDate(value) {
  if (!value) return "";
  const d = new Date(`${value}T00:00:00`);
  if (Number.isNaN(d.getTime())) return value;
  return new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" }).format(d);
}

function Field({ label, children, className = "" }) {
  return (
    <label className={`field ${className}`.trim()}>
      <span>{label}</span>
      {children}
    </label>
  );
}

function IconButton({ children, className = "", tooltip, label, ...props }) {
  return (
    <button
      {...props}
      className={`actionButton tooltipButton ${className}`.trim()}
      aria-label={label || tooltip}
      title={tooltip}
      data-tooltip={tooltip}
    >
      {children}
    </button>
  );
}

function normalizeSpotifyImageUrl(url) {
  if (!url) return "";
  const value = String(url).trim();
  const match = value.match(/^https:\/\/image-cdn-[^.]+\.spotifycdn\.com\/image\/([^/?#]+)/i);
  if (match?.[1]) return `https://i.scdn.co/image/${match[1]}`;
  return value;
}

function Artwork({ src, alt = "", size = "md" }) {
  const normalized = normalizeSpotifyImageUrl(src);
  const [currentSrc, setCurrentSrc] = useState(normalized);
  const [failed, setFailed] = useState(!normalized);

  useEffect(() => {
    const next = normalizeSpotifyImageUrl(src);
    setCurrentSrc(next);
    setFailed(!next);
  }, [src]);

  if (failed || !currentSrc) {
    return <div className={`coverFallback artwork--${size}`} aria-hidden="true" />;
  }

  return (
    <img
      className={`artwork artwork--${size}`}
      src={currentSrc}
      alt={alt}
      referrerPolicy="no-referrer"
      loading="lazy"
      onError={() => {
        if (currentSrc !== src && src) setCurrentSrc(src);
        else setFailed(true);
      }}
    />
  );
}

function selectionStorageKey(userContext) {
  const id = userContext?.bubble_user_id || userContext?.email;
  return id ? `playlistpilot:selected:${id}` : "";
}

function readStoredSelection(userContext) {
  const key = selectionStorageKey(userContext);
  if (!key || typeof window === "undefined") return {};
  try {
    return JSON.parse(window.localStorage.getItem(key) || "{}") || {};
  } catch {
    return {};
  }
}

function writeStoredSelection(userContext, nextSelection) {
  const key = selectionStorageKey(userContext);
  if (!key || typeof window === "undefined") return;
  const current = readStoredSelection(userContext);
  window.localStorage.setItem(key, JSON.stringify({ ...current, ...nextSelection }));
}

function reorderTracks(list, sourceTrackId, targetPosition) {
  const fromIndex = list.findIndex((track) => track.track_id === sourceTrackId);
  const toIndex = list.findIndex((track) => Number(track.position) === Number(targetPosition));
  if (fromIndex < 0 || toIndex < 0 || fromIndex === toIndex) return list;
  const next = [...list];
  const [moved] = next.splice(fromIndex, 1);
  next.splice(toIndex, 0, moved);
  return next.map((track, index) => ({ ...track, position: index }));
}

function Sparkline({ values = [] }) {
  const points = values.map((v) => Number(v) || 0);
  if (!points.length) return <div className="sparkline empty" />;
  const min = Math.min(...points);
  const max = Math.max(...points);
  const span = max - min || 1;
  const d = points.map((v, i) => {
    const x = points.length === 1 ? 100 : (i / (points.length - 1)) * 100;
    const y = 54 - ((v - min) / span) * 46;
    return `${i ? "L" : "M"}${x.toFixed(2)},${y.toFixed(2)}`;
  }).join(" ");
  return (
    <svg className="sparkline" viewBox="0 0 100 60" preserveAspectRatio="none" aria-hidden="true">
      <path d={d} />
    </svg>
  );
}

function GrowthBars({ items = [] }) {
  const max = Math.max(1, ...items.map((item) => Math.abs(Number(item.delta) || 0)));
  return (
    <div className="growthBars">
      {items.map((item) => {
        const delta = Number(item.delta) || 0;
        const width = Math.max(4, Math.round((Math.abs(delta) / max) * 100));
        return (
          <div className="growthBar" key={item.playlist_id}>
            <Artwork src={item.image} alt="" size="sm" />
            <div>
              <strong>{item.name || "Untitled playlist"}</strong>
              <span>{formatNumber(item.followers_now)} followers</span>
            </div>
            <div className={delta < 0 ? "barTrack negative" : "barTrack"}>
              <i style={{ width: `${width}%` }} />
            </div>
            <b>{formatDelta(delta)}</b>
          </div>
        );
      })}
      {!items.length ? <p>No growth data yet.</p> : null}
    </div>
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
  const [flexSettings, setFlexSettings] = useState(null);
  const [flexSlots, setFlexSlots] = useState([]);
  const [flexReference, setFlexReference] = useState("");
  const [flexReferenceMeta, setFlexReferenceMeta] = useState(null);
  const [flexReferenceIssue, setFlexReferenceIssue] = useState(null);
  const [flexInterval, setFlexInterval] = useState("weekly");
  const [flexEnabled, setFlexEnabled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [view, setView] = useState("manager");
  const [dashboardSummary, setDashboardSummary] = useState(null);
  const [dashboardSeries, setDashboardSeries] = useState(null);
  const [toolsOpen, setToolsOpen] = useState(false);
  const [activeTool, setActiveTool] = useState("add");
  const [dragTrackId, setDragTrackId] = useState("");

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
      setConnectionId("");
      setPlaylists([]);
      setPlaylistId("");
      setPlaylist(null);
      setTracks([]);
      setFlexSettings(null);
      setFlexSlots([]);
      setFlexReferenceMeta(null);
      setFlexReferenceIssue(null);
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
    loadDashboard();
  }, [userContext?.linked]);

  useEffect(() => {
    if (!userContext?.linked || !connectionId) return;
    writeStoredSelection(userContext, { connectionId });
    loadPlaylists();
  }, [userContext?.linked, connectionId]);

  useEffect(() => {
    if (!playlistId) {
      setPlaylist(null);
      setTracks([]);
      return;
    }
    if (userContext?.linked) writeStoredSelection(userContext, { playlistId });
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

  const activeFlexTrackIds = useMemo(
    () => new Set(flexSlots.map((slot) => slot.current_track_id).filter(Boolean)),
    [flexSlots]
  );

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
      const stored = readStoredSelection(userContext);
      const storedConnectionId = stored.connectionId && data.some((c) => c.id === stored.connectionId)
        ? stored.connectionId
        : "";
      const nextConnectionId = storedConnectionId || data[0]?.id || "";
      if (connectionId !== nextConnectionId) setConnectionId(nextConnectionId);
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
      const stored = readStoredSelection(userContext);
      const storedPlaylistId = stored.playlistId && data.some((p) => p.id === stored.playlistId)
        ? stored.playlistId
        : "";
      const currentPlaylistIsValid = playlistId && data.some((p) => p.id === playlistId);
      const nextPlaylistId = currentPlaylistIsValid ? playlistId : (storedPlaylistId || data[0]?.id || "");
      if (playlistId !== nextPlaylistId) setPlaylistId(nextPlaylistId);
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
      const [settings, slots] = await Promise.all([
        api(`/api/flex/settings/get?playlist_id=${encodeURIComponent(playlistId)}`, { accessToken: accessToken() }).catch(() => null),
        api(`/api/flex/slots/list?playlist_id=${encodeURIComponent(playlistId)}`, { accessToken: accessToken() }).catch(() => []),
      ]);
      setPlaylist(detail);
      setAutoWeeks(detail?.auto_remove_weeks ? String(detail.auto_remove_weeks) : "4");
      setTracks(items);
      setFlexSettings(settings);
      setFlexSlots(Array.isArray(slots) ? slots : []);
      setFlexReference(settings?.reference_playlist_url || settings?.reference_playlist_id || "");
      setFlexReferenceMeta(settings?.reference_playlist || null);
      setFlexReferenceIssue(null);
      setFlexInterval(settings?.interval || "weekly");
      setFlexEnabled(!!settings?.enabled);
      return { detail, items };
    });
  }

  async function reconcileTracksAndFlex() {
    if (!playlistId) return;
    const [items, slots] = await Promise.all([
      api(`/api/playlist-items/list?playlist_row_id=${encodeURIComponent(playlistId)}`, { accessToken: accessToken() }),
      api(`/api/flex/slots/list?playlist_id=${encodeURIComponent(playlistId)}`, { accessToken: accessToken() }).catch(() => []),
    ]);
    setTracks(items);
    setFlexSlots(Array.isArray(slots) ? slots : []);
  }

  async function addTrack() {
    if (!playlistId || !trackLink.trim()) return;
    await run("Track added; sync dispatched", async () => {
      const previousLink = trackLink;
      if (ENABLE_OPTIMISTIC_PLAYLIST_UI) setTrackLink("");
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
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
    }).then((result) => {
      if (result === null && ENABLE_OPTIMISTIC_PLAYLIST_UI) setTrackLink(previousLink);
    });
  }

  async function moveTrack(track, dir) {
    const previousTracks = tracks;
    const targetPosition = Number(track.position) + (dir === "up" ? -1 : 1);
    if (ENABLE_OPTIMISTIC_PLAYLIST_UI) setTracks(reorderTracks(tracks, track.track_id, targetPosition));
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
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
    }).then((result) => {
      if (result === null && ENABLE_OPTIMISTIC_PLAYLIST_UI) setTracks(previousTracks);
    });
  }

  async function moveTrackTo(track, targetPosition) {
    const from = Number(track.position);
    const to = Number(targetPosition);
    if (!Number.isFinite(from) || !Number.isFinite(to) || from === to) return;
    const previousTracks = tracks;
    if (ENABLE_OPTIMISTIC_PLAYLIST_UI) setTracks(reorderTracks(tracks, track.track_id, to));
    await run("Track reordered", async () => {
      await api("/api/playlist-items/move", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          playlist_id: playlistId,
          track_id: track.track_id,
          dir: to < from ? "up" : "down",
          steps: Math.abs(to - from),
        },
      });
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
    }).then((result) => {
      if (result === null && ENABLE_OPTIMISTIC_PLAYLIST_UI) setTracks(previousTracks);
    });
  }

  async function removeTrack(track) {
    const previousTracks = tracks;
    if (ENABLE_OPTIMISTIC_PLAYLIST_UI) {
      setTracks(tracks.filter((item) => item.track_id !== track.track_id).map((item, index) => ({ ...item, position: index })));
    }
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
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
    }).then((result) => {
      if (result === null && ENABLE_OPTIMISTIC_PLAYLIST_UI) setTracks(previousTracks);
    });
  }

  async function toggleLock(track) {
    const previousTracks = tracks;
    if (ENABLE_OPTIMISTIC_PLAYLIST_UI) {
      setTracks(tracks.map((item) =>
        item.track_id === track.track_id
          ? { ...item, is_locked: !track.is_locked, locked_position: !track.is_locked ? track.position : null }
          : item
      ));
    }
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
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
    }).then((result) => {
      if (result === null && ENABLE_OPTIMISTIC_PLAYLIST_UI) setTracks(previousTracks);
    });
  }

  async function setSongExpiry(track) {
    const value = window.prompt("Expiry in weeks. Empty clears song expiry.", track.expiry_weeks || "");
    if (value === null) return;
    const previousTracks = tracks;
    const nextExpiry = value.trim() === "" ? null : value;
    if (ENABLE_OPTIMISTIC_PLAYLIST_UI) {
      setTracks(tracks.map((item) =>
        item.track_id === track.track_id ? { ...item, expiry_weeks: nextExpiry } : item
      ));
    }
    await run("Song expiry updated", async () => {
      await api("/api/locks/set", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          playlist_id: playlistId,
          track_id: track.track_id,
          locked_position: Number(track.locked_position ?? track.position),
          is_locked: !!track.is_locked,
          exp_weeks: nextExpiry,
        },
      });
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
    }).then((result) => {
      if (result === null && ENABLE_OPTIMISTIC_PLAYLIST_UI) setTracks(previousTracks);
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

  async function loadDashboard() {
    if (!session?.access_token) return;
    return run("Dashboard loaded", async () => {
      const [summary, series] = await Promise.all([
        api("/api/dashboard/summary?days=30&removals_limit=12", { accessToken: accessToken() }),
        api("/api/dashboard/series?days=30&granularity=daily&scope=total", { accessToken: accessToken() }),
      ]);
      setDashboardSummary(summary);
      setDashboardSeries(series);
      return { summary, series };
    });
  }

  async function saveFlexSettings() {
    if (!playlistId) return;
    await run("Flex settings saved", async () => {
      let result;
      setFlexReferenceIssue(null);
      try {
        result = await api("/api/flex/settings/save", {
          method: "POST",
          accessToken: accessToken(),
          body: {
            playlist_id: playlistId,
            reference_playlist: flexReference,
            interval: flexInterval,
            enabled: flexEnabled,
          },
        });
      } catch (e) {
        if (e.status === 422 && e.data?.error === "reference_playlist_blocked") {
          setFlexReferenceIssue(e.data);
          setFlexReferenceMeta(e.data.reference_playlist || null);
          throw new Error("Spotify blocks this playlist as a direct flex source.");
        }
        throw e;
      }
      if (result?.settings?.reference_playlist) {
        setFlexReferenceMeta(result.settings.reference_playlist);
      }
      await loadSelectedPlaylist();
    });
  }

  async function addFlexSlot(track) {
    const previousTracks = tracks;
    const previousSlots = flexSlots;
    if (ENABLE_OPTIMISTIC_PLAYLIST_UI) {
      setTracks(tracks.map((item) =>
        item.track_id === track.track_id
          ? { ...item, is_locked: true, locked_position: item.position }
          : item
      ));
      setFlexSlots([
        ...flexSlots,
        {
          id: `optimistic-${track.track_id}`,
          playlist_id: playlistId,
          position: track.position,
          current_track_id: track.track_id,
          current_track_name: track.track_name,
        },
      ]);
    }
    await run("Flex slot added", async () => {
      await api("/api/flex/slots/add", {
        method: "POST",
        accessToken: accessToken(),
        body: { playlist_id: playlistId, track_id: track.track_id },
      });
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
    }).then((result) => {
      if (result === null && ENABLE_OPTIMISTIC_PLAYLIST_UI) {
        setTracks(previousTracks);
        setFlexSlots(previousSlots);
      }
    });
  }

  async function removeFlexSlot(slot) {
    const previousSlots = flexSlots;
    if (ENABLE_OPTIMISTIC_PLAYLIST_UI) {
      setFlexSlots(flexSlots.filter((item) => item.id !== slot.id));
    }
    await run("Flex slot removed", async () => {
      await api("/api/flex/slots/remove", {
        method: "POST",
        accessToken: accessToken(),
        body: { slot_id: slot.id },
      });
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
    }).then((result) => {
      if (result === null && ENABLE_OPTIMISTIC_PLAYLIST_UI) setFlexSlots(previousSlots);
    });
  }

  async function rotateFlex(slotId = "") {
    await run("Flex rotation queued", async () => {
      await api("/api/flex/rotate", {
        method: "POST",
        accessToken: accessToken(),
        body: slotId ? { slot_id: slotId } : { playlist_id: playlistId },
      });
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
    });
  }

  return (
    <main>
      <header className="topbar">
        <div className="brand">
          <img className="logo" src="/playlistpilot-logo-v1.jpg" alt="Playlist Pilot" />
          <div>
            <h1>Playlist Pilot</h1>
            <p>Playlist Manager</p>
          </div>
        </div>
        <nav>
          <button className={view === "dashboard" ? "navButton active" : "navButton"} onClick={() => setView("dashboard")}>Dashboard</button>
          <button className={view === "manager" ? "navButton active" : "navButton"} onClick={() => setView("manager")}>Playlist Manager</button>
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
        <section className="loadingScreen" aria-live="polite">
          <div className="loaderMark">
            <img src="/playlistpilot-logo-v1.jpg" alt="" />
            <span />
          </div>
          <h2>Loading workspace</h2>
          <p>Syncing your accounts, playlists, and saved position.</p>
          {error ? <strong>{error}</strong> : null}
        </section>
      ) : (
      <>

      {view === "dashboard" ? (
      <section className="dashboard">
        <div className="statusLine">
          {message ? <span>{message}</span> : <span />}
          {error ? <strong>{error}</strong> : null}
        </div>
        <div className="dashboardHero">
          <div>
            <h2>Dashboard</h2>
            <p>{dashboardSummary?.totals?.playlists_count || 0} playlists · {formatNumber(dashboardSummary?.totals?.total_followers)} followers · {formatNumber(dashboardSummary?.totals?.total_tracks)} tracks</p>
          </div>
          <button disabled={busy} onClick={loadDashboard}>Refresh</button>
        </div>
        <div className="metricGrid">
          <article>
            <span>Total Followers</span>
            <strong>{formatNumber(dashboardSummary?.totals?.total_followers)}</strong>
          </article>
          <article>
            <span>30d Growth</span>
            <strong>{formatNumber(dashboardSummary?.totals?.net_growth_last_days)}</strong>
          </article>
          <article>
            <span>Playlists</span>
            <strong>{formatNumber(dashboardSummary?.totals?.playlists_count)}</strong>
          </article>
          <article>
            <span>Upcoming Removals</span>
            <strong>{formatNumber(dashboardSummary?.upcoming_removals?.length)}</strong>
            <small>next 14 days</small>
          </article>
          <article>
            <span>Auto-Remove Active</span>
            <strong>{formatNumber(dashboardSummary?.totals?.automation_enabled_count)}</strong>
            <small>{formatNumber(dashboardSummary?.totals?.cooldown_count)} on cooldown</small>
          </article>
          <article>
            <span>Flex Rotation</span>
            <strong>{formatNumber(dashboardSummary?.totals?.flex_enabled_count)}</strong>
            <small>{formatNumber(dashboardSummary?.totals?.flex_due_count)} due soon</small>
          </article>
          <article>
            <span>Needs Fresh Check</span>
            <strong>{formatNumber(dashboardSummary?.totals?.stale_count)}</strong>
            <small>older than 24h</small>
          </article>
        </div>
        <div className="dashboardGrid">
          <section className="dashboardPanel growthPanel">
            <div>
              <h2>Growth Trend</h2>
              <p>Daily follower delta over the last 30 days</p>
            </div>
            <Sparkline values={dashboardSeries?.growth || []} />
            <div className="sparkLabels">
              <span>{dashboardSeries?.labels?.[0] ? formatShortDate(dashboardSeries.labels[0]) : ""}</span>
              <span>{dashboardSeries?.labels?.at?.(-1) ? formatShortDate(dashboardSeries.labels.at(-1)) : ""}</span>
            </div>
          </section>
          <section className="dashboardPanel">
            <h2>Top Growing</h2>
            {dashboardSummary?.top_growing ? (
              <div className="topGrowing">
                <Artwork src={dashboardSummary.top_growing.image} alt="" size="lg" />
                <div>
                  <strong>{dashboardSummary.top_growing.name}</strong>
                  <span>+{formatNumber(dashboardSummary.top_growing.delta)} · {formatNumber(dashboardSummary.top_growing.followers_now)} followers</span>
                </div>
              </div>
            ) : <p>No growth data yet.</p>}
          </section>
          <section className="dashboardPanel rankPanel">
            <div>
              <h2>Growth Ranking</h2>
              <p>Best movers in the selected 30-day window</p>
            </div>
            <GrowthBars items={dashboardSummary?.growth_rank || []} />
          </section>
          <section className="dashboardPanel topPlaylistsPanel">
            <div>
              <h2>Playlist Portfolio</h2>
              <p>Largest playlists by current follower count</p>
            </div>
            <div className="playlistTable">
              {(dashboardSummary?.top_playlists || []).map((item) => (
                <div key={item.playlist_id}>
                  <Artwork src={item.image} alt="" size="sm" />
                  <strong>{item.name || "Untitled playlist"}</strong>
                  <span>{formatNumber(item.followers)} followers</span>
                  <span>{formatNumber(item.tracks_total)} tracks</span>
                  <b>{item.auto_remove_enabled ? `${item.auto_remove_weeks || "?"}w expiry` : "manual"}</b>
                </div>
              ))}
              {!dashboardSummary?.top_playlists?.length ? <p>No playlists yet.</p> : null}
            </div>
          </section>
          <section className="dashboardPanel removalsPanel">
            <div>
              <h2>Upcoming Auto-Removals</h2>
              <p>Unlocked tracks scheduled to age out in the next 14 days</p>
            </div>
            <div className="removalList">
              {(dashboardSummary?.upcoming_removals || []).map((item, index) => (
                <div key={`${item.playlist_id || index}-${item.track_id || index}`}>
                  <strong>{item.track_name || item.track_id || "Unknown track"}</strong>
                  <span>{item.artist_names || "Unknown artist"}</span>
                  <small>{item.playlist_name || "Playlist"} · {formatShortDate(item.removes_on)} · pos {Number(item.position) + 1}</small>
                </div>
              ))}
              {!dashboardSummary?.upcoming_removals?.length ? <p>No upcoming removals.</p> : null}
            </div>
          </section>
        </div>
      </section>
      ) : (
      <section className="workspace">
        <aside className="sidebar">
          <div className="accountBox">
            <span>Signed in</span>
            <strong>{userContext.email}</strong>
          </div>

          <Field label="Account" className="accountField">
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
                <Artwork src={p.image} alt="" size="lg" />
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
            <Artwork src={playlist?.image} alt="" size="xl" />
            <div>
              <h2>Selected Playlist</h2>
              <h3>{playlist?.name || "No playlist selected"}</h3>
              <p>
                {formatNumber(playlist?.tracks_total)} Tracks · {formatNumber(playlist?.followers)} Followers
              </p>
            </div>
          </div>

          <section className={`toolsPanel ${toolsOpen ? "toolsPanel--open" : ""}`}>
            <button className="toolsToggle" onClick={() => setToolsOpen(!toolsOpen)}>
              <span>Playlist Tools</span>
              <small>{toolsOpen ? "Hide" : "Show"}</small>
            </button>
            <div className="toolsBody">
              <nav className="toolsNav" aria-label="Playlist tools">
                {[
                  ["add", "Add song"],
                  ["expiry", "Expiry"],
                  ["flex", "Flex"],
                ].map(([key, label]) => (
                  <button key={key} className={activeTool === key ? "selected" : ""} onClick={() => setActiveTool(key)}>
                    {label}
                  </button>
                ))}
              </nav>
              <div className="toolCard">
                {activeTool === "add" ? (
                  <>
                    <h2>Add song</h2>
                    <p>Add a Spotify track by URL or URI, optionally at a fixed position and with a per-song expiry.</p>
                    <div className="toolGrid addToolGrid">
                      <input value={trackLink} onChange={(e) => setTrackLink(e.target.value)} placeholder="Spotify song link or URI" />
                      <Field label="Position">
                        <input value={trackPosition} onChange={(e) => setTrackPosition(e.target.value)} />
                      </Field>
                      <Field label="Expiry weeks">
                        <input value={trackExpiry} onChange={(e) => setTrackExpiry(e.target.value)} />
                      </Field>
                      <button disabled={busy || !playlistId || !trackLink.trim()} onClick={addTrack}>Add song</button>
                    </div>
                  </>
                ) : null}
                {activeTool === "expiry" ? (
                  <>
                    <h2>Expiry</h2>
                    <p>Automatically remove unlocked songs after the selected number of weeks. Manual per-song expiry still overrides this.</p>
                    <div className="toolGrid expiryToolGrid">
                      <Field label="Default expiry weeks">
                        <input type="number" min="1" max="104" value={autoWeeks} onChange={(e) => setAutoWeeks(e.target.value)} />
                      </Field>
                      <button disabled={busy || !playlistId} onClick={saveAutoRemoval}>Save expiry</button>
                      <button disabled={busy || !playlistId} onClick={cleanupNow}>Run expiry check now</button>
                    </div>
                  </>
                ) : null}
                {activeTool === "flex" ? (
                  <>
                    <div className="flexPanelHeader">
                      <div>
                        <h2>Flex</h2>
                        <p>Rotate locked flex slots from a reference playlist on your schedule. Use public/editorial playlists when Spotify allows access.</p>
                      </div>
                      <button className="tooltipButton" data-tooltip="Rotate all flex slots now using the reference playlist." disabled={busy || !playlistId || !flexSlots.length || !flexReference.trim()} onClick={() => rotateFlex()}>
                        Rotate now
                      </button>
                    </div>
                    <div className="flexSettings">
                      <input value={flexReference} onChange={(e) => { setFlexReference(e.target.value); setFlexReferenceIssue(null); }} placeholder="Reference playlist link" />
                      <select value={flexInterval} onChange={(e) => setFlexInterval(e.target.value)}>
                        <option value="daily">Daily</option>
                        <option value="weekly">Weekly</option>
                        <option value="monthly">Monthly</option>
                      </select>
                      <label className="toggleField">
                        <input type="checkbox" checked={flexEnabled} onChange={(e) => setFlexEnabled(e.target.checked)} />
                        Enabled
                      </label>
                      <button className="tooltipButton" data-tooltip="Save the reference playlist, rotation interval, and enabled state." disabled={busy || !playlistId} onClick={saveFlexSettings}>
                        Save flex
                      </button>
                    </div>
                    {flexReferenceMeta ? (
                      <div className="referencePlaylist">
                        <Artwork src={flexReferenceMeta.image} alt="" size="lg" />
                        <div>
                          <span>Reference Playlist</span>
                          <strong>{flexReferenceMeta.name || flexReferenceMeta.id}</strong>
                          <small>
                            {formatNumber(flexReferenceMeta.tracks_total)} tracks
                            {flexReferenceMeta.owner_name ? ` · by ${flexReferenceMeta.owner_name}` : ""}
                            {flexReferenceMeta.followers !== null && flexReferenceMeta.followers !== undefined ? ` · ${formatNumber(flexReferenceMeta.followers)} followers` : ""}
                          </small>
                        </div>
                      </div>
                    ) : null}
                    {flexReferenceIssue ? (
                      <div className="referenceIssue">
                        <strong>Spotify blocks this playlist as a direct source.</strong>
                        <p>Editorial and personalized Spotify playlists often cannot be read through the official API. Make your own copy, then paste that new playlist link here.</p>
                        <ol>
                          <li>Open the playlist in Spotify.</li>
                          <li>Click the three-dot menu.</li>
                          <li>Choose “Add to other playlist” and create a new playlist.</li>
                          <li>Open your new playlist, copy its link, and paste it above.</li>
                        </ol>
                      </div>
                    ) : null}
                    <div className="flexSlotList">
                      {flexSlots.map((slot) => (
                        <div className="flexSlot" key={slot.id}>
                          <span>#{Number(slot.position) + 1}</span>
                          <strong>{slot.current_track_name || slot.current_track_id}</strong>
                          <button className="tooltipButton" data-tooltip="Replace this flex song with a random track from the reference playlist." disabled={busy || !flexReference.trim()} onClick={() => rotateFlex(slot.id)}>Rotate</button>
                          <button className="danger tooltipButton" data-tooltip="Remove this flex slot. The song itself stays in the playlist unless removed separately." disabled={busy} onClick={() => removeFlexSlot(slot)}>Remove</button>
                        </div>
                      ))}
                    </div>
                  </>
                ) : null}
              </div>
            </div>
          </section>

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
              {filteredTracks.map((track) => {
                const isFlexTrack = activeFlexTrackIds.has(track.track_id);
                return (
                  <article
                    key={`${track.position}-${track.track_id}`}
                    className={`trackRow ${isFlexTrack ? "trackRow--flex" : ""} ${dragTrackId === track.track_id ? "trackRow--dragging" : ""}`}
                    draggable={!busy}
                    onDragStart={(e) => {
                      setDragTrackId(track.track_id);
                      e.dataTransfer.effectAllowed = "move";
                      e.dataTransfer.setData("text/plain", track.track_id);
                    }}
                    onDragOver={(e) => {
                      if (!busy) e.preventDefault();
                    }}
                    onDrop={(e) => {
                      e.preventDefault();
                      const sourceId = e.dataTransfer.getData("text/plain");
                      const source = tracks.find((item) => item.track_id === sourceId);
                      setDragTrackId("");
                      if (source) moveTrackTo(source, track.position);
                    }}
                    onDragEnd={() => setDragTrackId("")}
                  >
                    <div className="dragHandle" aria-hidden="true"><GripVertical /></div>
                    <div className="pos">{Number(track.position) + 1}</div>
                    <Artwork src={track.cover_url} alt="" size="sm" />
                    <div className="trackMeta">
                      <strong>{track.track_name || track.track_id}</strong>
                      <span>{track.artist_names || "Unknown artist"} · {track.album_name || "Unknown album"}</span>
                      <small>
                        {track.age_label || "age unknown"}
                        {track.duration_formatted ? ` · ${track.duration_formatted}` : ""}
                      </small>
                    </div>
                    <div className="badges">
                      {isFlexTrack ? <span className="flexBadge"><Shuffle aria-hidden="true" /> Flex</span> : null}
                      {track.is_locked ? <span className="locked">Locked</span> : null}
                      {track.expiry_weeks ? <span className="expiry">{track.expiry_weeks}w</span> : null}
                    </div>
                    <div className="rowActions">
                      <button
                        className="actionButton tooltipButton"
                        aria-label={track.is_locked ? "Unlock song" : "Lock song"}
                        title={track.is_locked ? "Unlock this song so automation can move or remove it again." : "Lock this song to its current playlist position."}
                        data-tooltip={track.is_locked ? "Unlock this song so automation can move or remove it again." : "Lock this song to its current playlist position."}
                        disabled={busy}
                        onClick={() => toggleLock(track)}
                      >
                        {track.is_locked ? <Unlock aria-hidden="true" /> : <Lock aria-hidden="true" />}
                      </button>
                      <IconButton
                        tooltip="Set or clear a custom expiry timer for this song."
                        disabled={busy}
                        onClick={() => setSongExpiry(track)}
                      >
                        <TimerReset aria-hidden="true" />
                      </IconButton>
                      <IconButton
                        tooltip={isFlexTrack ? "This song is already an active flex slot." : "Turn this song into a locked flex slot that rotates from the reference playlist."}
                        disabled={busy || isFlexTrack}
                        onClick={() => addFlexSlot(track)}
                      >
                        <Shuffle aria-hidden="true" />
                      </IconButton>
                      <IconButton tooltip="Move this song one position up." disabled={busy || track.position <= 0} onClick={() => moveTrack(track, "up")}>
                        <ArrowUp aria-hidden="true" />
                      </IconButton>
                      <IconButton tooltip="Move this song one position down." disabled={busy} onClick={() => moveTrack(track, "down")}>
                        <ArrowDown aria-hidden="true" />
                      </IconButton>
                      <IconButton className="danger" tooltip="Remove this song from the playlist." disabled={busy} onClick={() => removeTrack(track)}>
                        <Trash2 aria-hidden="true" />
                      </IconButton>
                    </div>
                  </article>
                );
              })}
            </div>
          </div>
        </section>
      </section>
      )}
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
        button svg {
          width: 18px;
          height: 18px;
          stroke: currentColor;
          stroke-width: 2;
          stroke-linecap: round;
          stroke-linejoin: round;
          fill: none;
          flex: 0 0 auto;
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
        * {
          box-sizing: border-box;
        }
        main {
          min-height: 100vh;
          width: 100%;
          overflow-x: hidden;
        }
        .topbar {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 22px clamp(20px, 3vw, 40px);
          gap: 24px;
          min-height: 116px;
        }
        .brand {
          display: flex;
          align-items: center;
          gap: 18px;
        }
        .logo {
          width: 72px;
          height: 72px;
          border-radius: 14px;
          object-fit: cover;
          background: #082331;
        }
        h1, h2, h3, p {
          margin: 0;
        }
        h1 {
          font-size: 30px;
          line-height: 1;
        }
        .brand p, .playlistHeader p, small, .trackMeta span {
          color: #a6adba;
        }
        nav {
          display: flex;
          align-items: center;
          gap: 18px;
          color: #18e06f;
          font-size: 16px;
        }
        nav button {
          min-width: 112px;
        }
        .navButton {
          border-color: transparent;
          background: transparent;
          padding: 12px 0;
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
        .loadingScreen {
          display: grid;
          align-content: center;
          justify-items: center;
          gap: 14px;
          min-height: calc(100vh - 116px);
          padding: 40px;
          text-align: center;
        }
        .loaderMark {
          position: relative;
          width: 96px;
          height: 96px;
          display: grid;
          place-items: center;
        }
        .loaderMark img {
          width: 58px;
          height: 58px;
          border-radius: 14px;
          object-fit: cover;
          background: #082331;
        }
        .loaderMark span {
          position: absolute;
          inset: 0;
          border-radius: 50%;
          border: 2px solid rgba(24, 224, 111, 0.16);
          border-top-color: #18e06f;
          border-right-color: rgba(24, 224, 111, 0.72);
          animation: spin 900ms linear infinite;
          box-shadow: 0 0 30px rgba(24, 224, 111, 0.14);
        }
        .loadingScreen h2 {
          font-size: 28px;
        }
        .loadingScreen p {
          color: #a6adba;
          font-size: 15px;
        }
        .loadingScreen strong {
          color: #ff4d4d;
        }
        @keyframes spin {
          to { transform: rotate(360deg); }
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
          padding: 12px 16px;
        }
        .dashboard {
          display: grid;
          gap: 20px;
          padding: 18px clamp(20px, 3vw, 40px) 32px;
        }
        .dashboardHero {
          display: flex;
          justify-content: space-between;
          align-items: end;
          gap: 18px;
        }
        .dashboardHero h2 {
          font-size: clamp(30px, 4vw, 48px);
          line-height: 1;
        }
        .dashboardHero p,
        .dashboardPanel p,
        .dashboardPanel span {
          color: #a6adba;
        }
        .metricGrid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
          gap: 14px;
        }
        .metricGrid article,
        .dashboardPanel {
          border: 1px solid #2a303b;
          background: #181c23;
          padding: 18px;
        }
        .metricGrid article {
          display: grid;
          gap: 10px;
          min-height: 128px;
          align-content: space-between;
        }
        .metricGrid span {
          color: #a6adba;
          font-weight: 700;
        }
        .metricGrid strong {
          font-size: 30px;
        }
        .metricGrid small {
          font-size: 13px;
        }
        .dashboardGrid {
          display: grid;
          grid-template-columns: minmax(0, 1.4fr) minmax(280px, 0.8fr);
          gap: 14px;
        }
        .growthPanel {
          min-height: 280px;
        }
        .sparkline {
          width: 100%;
          height: 210px;
          margin-top: 22px;
        }
        .sparkline path {
          fill: none;
          stroke: #18e06f;
          stroke-width: 3;
          vector-effect: non-scaling-stroke;
        }
        .sparkline.empty {
          background: #222731;
        }
        .sparkLabels {
          display: flex;
          justify-content: space-between;
          color: #a6adba;
          font-size: 13px;
          margin-top: 8px;
        }
        .topGrowing {
          display: grid;
          grid-template-columns: 64px minmax(0, 1fr);
          align-items: center;
          gap: 14px;
          margin-top: 18px;
        }
        .topGrowing div {
          display: grid;
          gap: 6px;
          min-width: 0;
        }
        .topGrowing strong,
        .topGrowing span {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .rankPanel,
        .topPlaylistsPanel {
          min-height: 360px;
        }
        .growthBars {
          display: grid;
          gap: 12px;
          margin-top: 18px;
        }
        .growthBar {
          display: grid;
          grid-template-columns: 52px minmax(140px, 1fr) minmax(90px, 0.7fr) 70px;
          align-items: center;
          gap: 12px;
          min-width: 0;
        }
        .growthBar div {
          min-width: 0;
        }
        .growthBar strong,
        .growthBar span {
          display: block;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .growthBar b {
          text-align: right;
          color: #18e06f;
        }
        .barTrack {
          height: 8px;
          border-radius: 999px;
          background: #222731;
          overflow: hidden;
        }
        .barTrack i {
          display: block;
          height: 100%;
          border-radius: inherit;
          background: #18e06f;
        }
        .barTrack.negative i {
          background: #ff4d4d;
        }
        .playlistTable {
          display: grid;
          gap: 2px;
          margin-top: 18px;
        }
        .playlistTable div {
          display: grid;
          grid-template-columns: 52px minmax(140px, 1fr) 116px 88px 92px;
          align-items: center;
          gap: 12px;
          min-height: 64px;
          padding: 6px 0;
          border-top: 1px solid #202630;
          min-width: 0;
        }
        .playlistTable strong,
        .playlistTable span,
        .playlistTable b {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .playlistTable b {
          color: #18e06f;
          font-size: 13px;
          text-align: right;
        }
        .removalsPanel {
          grid-column: 1 / -1;
        }
        .removalList {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 10px;
          margin-top: 14px;
        }
        .removalList div {
          display: grid;
          gap: 6px;
          border-top: 1px solid #202630;
          padding-top: 10px;
          min-width: 0;
        }
        .removalList strong,
        .removalList span,
        .removalList small {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .workspace {
          display: grid;
          grid-template-columns: minmax(300px, 360px) minmax(0, 1fr);
          gap: clamp(18px, 2vw, 28px);
          min-height: calc(100vh - 116px);
          padding: 18px clamp(20px, 3vw, 40px) 28px;
          align-items: start;
        }
        .sidebar, .content {
          min-width: 0;
        }
        .field {
          display: grid;
          gap: 8px;
          color: #f4f6fb;
          font-weight: 700;
          width: 100%;
        }
        .field span {
          font-size: 14px;
          color: #a6adba;
        }
        .field select,
        .field input {
          width: 100%;
        }
        .accountField {
          grid-template-columns: auto minmax(0, 1fr);
          align-items: center;
          gap: 18px;
        }
        .accountField span {
          white-space: nowrap;
        }
        .accountField select {
          justify-self: stretch;
        }
        .sidebar {
          display: grid;
          align-content: start;
          grid-template-rows: auto auto auto auto auto minmax(0, 1fr);
          gap: 14px;
          min-height: 0;
        }
        .sectionTitle, .trackPanelHeader, .playlistHeader, .addTrack, .statusLine {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 16px;
        }
        .playlistList {
          display: grid;
          align-content: start;
          gap: 12px;
          min-height: 0;
          padding-right: 6px;
        }
        .playlistCard {
          display: grid;
          grid-template-columns: 64px minmax(0, 1fr);
          align-items: center;
          gap: 14px;
          width: 100%;
          min-height: 88px;
          padding: 12px;
          border-color: #2a303b;
          color: #f4f6fb;
          text-align: left;
        }
        .playlistCard.selected {
          border-color: #18e06f;
        }
        :global(.artwork), :global(.coverFallback) {
          display: block;
          border-radius: 4px;
          object-fit: cover;
          background: #303743;
          flex: 0 0 auto;
          max-width: 100%;
        }
        :global(.artwork--sm) {
          width: 52px;
          height: 52px;
        }
        :global(.artwork--lg) {
          width: 64px;
          height: 64px;
        }
        :global(.artwork--xl) {
          width: 92px;
          height: 92px;
          border-radius: 6px;
        }
        :global(.coverFallback) {
          background:
            linear-gradient(135deg, rgba(24, 224, 111, 0.2), transparent 44%),
            #303743;
        }
        .playlistCard span {
          display: grid;
          gap: 8px;
          min-width: 0;
        }
        .playlistCard strong,
        .playlistCard small {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .playlistCard strong {
          font-size: 16px;
        }
        .content {
          display: grid;
          align-content: start;
          gap: 18px;
          min-height: 0;
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
          display: grid;
          grid-template-columns: auto minmax(0, 1fr) auto;
          align-items: end;
          padding-bottom: 2px;
        }
        .playlistHeader h2 {
          font-size: 20px;
          color: #a6adba;
        }
        .playlistHeader h3 {
          margin-top: 8px;
          font-size: clamp(24px, 3vw, 34px);
          line-height: 1.08;
        }
        .playlistHeader p {
          margin-top: 10px;
          font-size: 16px;
        }
        .toolsPanel {
          border: 1px solid #2a303b;
          background: #181c23;
        }
        .toolsToggle {
          width: 100%;
          display: flex;
          justify-content: space-between;
          align-items: center;
          border: 0;
          border-radius: 0;
          background: #222831;
          padding: 14px 18px;
          text-align: left;
        }
        .toolsToggle span {
          font-size: 18px;
          font-weight: 800;
        }
        .toolsToggle small {
          color: #a6adba;
          font-weight: 800;
        }
        .toolsBody {
          display: none;
          grid-template-columns: 148px minmax(0, 1fr);
          gap: 16px;
          padding: 16px 18px 18px;
        }
        .toolsPanel--open .toolsBody {
          display: grid;
        }
        .toolsNav {
          display: grid;
          align-content: start;
          gap: 8px;
        }
        .toolsNav button {
          border-color: #303743;
          background: transparent;
          color: #a6adba;
          text-align: left;
        }
        .toolsNav button.selected {
          border-color: #18e06f;
          color: #18e06f;
          background: rgba(24, 224, 111, 0.08);
        }
        .toolCard {
          display: grid;
          gap: 14px;
          min-width: 0;
        }
        .toolCard h2 {
          font-size: 20px;
        }
        .toolCard p {
          color: #a6adba;
          line-height: 1.45;
        }
        .toolGrid {
          display: grid;
          gap: 12px;
          align-items: end;
        }
        .addToolGrid {
          grid-template-columns: minmax(220px, 1fr) 88px 110px auto;
        }
        .expiryToolGrid {
          grid-template-columns: 150px auto auto;
        }
        .flexPanelHeader,
        .flexSettings,
        .flexSlot {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
        }
        .flexPanelHeader h2 {
          font-size: 20px;
        }
        .flexPanelHeader p {
          margin-top: 5px;
          color: #a6adba;
        }
        .flexSettings {
          display: grid;
          grid-template-columns: minmax(220px, 1fr) 132px auto auto;
        }
        .toggleField {
          display: flex;
          align-items: center;
          gap: 8px;
          color: #a6adba;
          font-weight: 700;
          white-space: nowrap;
        }
        .toggleField input {
          width: 18px;
          height: 18px;
          padding: 0;
        }
        .referencePlaylist {
          display: grid;
          grid-template-columns: 64px minmax(0, 1fr);
          align-items: center;
          gap: 14px;
          padding: 12px;
          border: 1px solid rgba(24, 224, 111, 0.28);
          border-radius: 8px;
          background: rgba(24, 224, 111, 0.06);
        }
        .referencePlaylist div {
          display: grid;
          gap: 5px;
          min-width: 0;
        }
        .referencePlaylist span {
          color: #18e06f;
          font-size: 12px;
          font-weight: 800;
          text-transform: uppercase;
        }
        .referencePlaylist strong,
        .referencePlaylist small {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .referencePlaylist small {
          color: #a6adba;
        }
        .referenceIssue {
          display: grid;
          gap: 8px;
          padding: 14px;
          border: 1px solid rgba(255, 189, 74, 0.45);
          border-radius: 8px;
          background: rgba(255, 189, 74, 0.08);
        }
        .referenceIssue strong {
          color: #ffbd4a;
        }
        .referenceIssue p,
        .referenceIssue ol {
          margin: 0;
          color: #d6dbe4;
          line-height: 1.45;
        }
        .referenceIssue ol {
          padding-left: 20px;
        }
        .flexSlotList {
          display: grid;
          gap: 8px;
        }
        .flexSlot {
          display: grid;
          grid-template-columns: 52px minmax(0, 1fr) auto auto;
          padding: 10px 0 0;
          border-top: 1px solid #202630;
        }
        .flexSlot strong {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .flexSlot span {
          color: #a6adba;
          font-weight: 800;
        }
        .trackPanel {
          border: 1px solid #2a303b;
          background: #181c23;
          min-height: 0;
          display: grid;
        }
        .trackPanelHeader {
          background: #222831;
          padding: 16px 18px;
        }
        .trackPanelHeader h2 {
          font-size: 22px;
        }
        .trackPanelHeader input {
          width: min(360px, 45%);
        }
        .trackList {
          display: grid;
          align-content: start;
          min-height: 0;
        }
        .trackRow {
          display: grid;
          grid-template-columns: 28px 44px 52px minmax(180px, 1fr) minmax(74px, auto) minmax(330px, auto);
          align-items: center;
          gap: 12px;
          min-height: 76px;
          padding: 12px 16px;
          border-top: 1px solid #202630;
        }
        .trackRow[draggable="true"] {
          cursor: grab;
        }
        .trackRow--dragging {
          opacity: 0.55;
        }
        .dragHandle {
          color: #637083;
          display: inline-flex;
          align-items: center;
          justify-content: center;
        }
        .dragHandle svg {
          width: 18px;
          height: 18px;
        }
        .trackRow--flex {
          border-left: 3px solid #18e06f;
          background:
            linear-gradient(90deg, rgba(24, 224, 111, 0.14), rgba(24, 224, 111, 0.035) 34%, transparent 72%),
            #181c23;
          box-shadow: inset 0 0 0 1px rgba(24, 224, 111, 0.12);
        }
        .trackRow--flex .pos {
          color: #18e06f;
          font-weight: 800;
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
        .trackMeta small {
          display: none;
        }
        .pos {
          color: #a6adba;
          font-size: 16px;
          text-align: center;
        }
        .badges {
          display: flex;
          gap: 6px;
          min-height: 24px;
          justify-content: flex-end;
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
        .flexBadge {
          display: inline-flex;
          align-items: center;
          gap: 5px;
          color: #18e06f;
          background: rgba(24, 224, 111, 0.18);
          border: 1px solid rgba(24, 224, 111, 0.35);
        }
        .flexBadge svg {
          width: 13px;
          height: 13px;
          stroke: currentColor;
          stroke-width: 2;
          stroke-linecap: round;
          stroke-linejoin: round;
          fill: none;
        }
        .danger {
          border-color: #ff4d4d;
          background: #ef4242;
          color: white;
        }
        .rowActions {
          display: grid;
          grid-template-columns: repeat(6, 38px);
          align-items: center;
          gap: 6px;
          justify-content: end;
        }
        .actionButton {
          position: relative;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 38px;
          height: 38px;
          min-height: 38px;
          padding: 0;
          border-color: #18e06f;
          background: transparent;
          color: #18e06f;
          border-radius: 7px;
          line-height: 1;
          box-shadow: none;
          transition: background 120ms ease, border-color 120ms ease, color 120ms ease, transform 120ms ease;
        }
        .actionButton:hover:not(:disabled),
        .actionButton:focus-visible:not(:disabled) {
          background: rgba(24, 224, 111, 0.1);
          border-color: #18e06f;
          color: #f4fff8;
          transform: translateY(-1px);
        }
        .actionButton svg {
          width: 17px;
          height: 17px;
          stroke-width: 2.15;
        }
        .actionButton.danger {
          border-color: #ff4d4d;
          background: transparent;
          color: #ff4d4d;
          box-shadow: none;
        }
        .actionButton.danger:hover:not(:disabled),
        .actionButton.danger:focus-visible:not(:disabled) {
          background: rgba(255, 77, 77, 0.18);
          border-color: #ff4d4d;
          color: #fff4f4;
        }
        .tooltipButton {
          position: relative;
        }
        .tooltipButton::after {
          content: attr(data-tooltip);
          position: absolute;
          right: 0;
          bottom: calc(100% + 10px);
          z-index: 20;
          width: max-content;
          max-width: 260px;
          padding: 8px 10px;
          border: 1px solid #303743;
          border-radius: 6px;
          background: #0f1217;
          color: #f4f6fb;
          font-size: 12px;
          line-height: 1.35;
          font-weight: 700;
          text-align: left;
          white-space: normal;
          box-shadow: 0 10px 28px rgba(0, 0, 0, 0.35);
          opacity: 0;
          pointer-events: none;
          transform: translateY(4px);
          transition: opacity 140ms ease, transform 140ms ease;
        }
        .tooltipButton:hover::after,
        .tooltipButton:focus-visible::after {
          opacity: 1;
          transform: translateY(0);
          transition-delay: 420ms;
        }
        .trackRow:first-child .tooltipButton::after,
        .toolsPanel .tooltipButton::after {
          bottom: auto;
          top: calc(100% + 10px);
        }
        @media (max-width: 1320px) {
          .workspace {
            grid-template-columns: minmax(280px, 330px) minmax(0, 1fr);
          }
          .trackRow {
            grid-template-columns: 28px 42px 52px minmax(160px, 1fr) minmax(70px, auto);
          }
          .rowActions {
            grid-column: 4 / -1;
            grid-row: 2;
            justify-content: start;
          }
          .badges {
            grid-column: 5 / -1;
            justify-content: flex-end;
          }
          .trackMeta small {
            display: block;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
          }
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
          .metricGrid,
          .dashboardGrid,
          .removalList {
            grid-template-columns: 1fr;
          }
          .playlistTable div {
            grid-template-columns: 52px minmax(0, 1fr) 100px;
          }
          .playlistTable span:nth-of-type(2),
          .playlistTable b {
            display: none;
          }
          .workspace {
            grid-template-columns: 1fr;
            height: auto;
            overflow: visible;
            padding: 24px;
          }
          .content {
            overflow: visible;
          }
          .playlistList {
            max-height: 42vh;
          }
          .playlistHeader {
            grid-template-columns: auto minmax(0, 1fr);
          }
          .trackRow {
            grid-template-columns: 28px 42px 52px minmax(0, 1fr);
          }
          .badges {
            grid-column: 4;
            justify-content: flex-start;
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
          .dashboardHero {
            display: grid;
            align-items: stretch;
          }
          .growthBar {
            grid-template-columns: 42px minmax(0, 1fr) 58px;
          }
          .growthBar .barTrack {
            grid-column: 2 / -1;
          }
          .playlistTable div {
            grid-template-columns: 42px minmax(0, 1fr);
          }
          .playlistTable span {
            grid-column: 2;
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
            grid-template-columns: 72px minmax(0, 1fr);
            align-items: center;
          }
          .playlistHeader :global(.artwork--xl) {
            width: 72px;
            height: 72px;
          }
          .toolsBody,
          .addToolGrid,
          .expiryToolGrid {
            grid-template-columns: 1fr;
          }
          .flexSettings,
          .flexSlot {
            grid-template-columns: 1fr;
            align-items: stretch;
          }
          .flexPanelHeader {
            display: grid;
            align-items: stretch;
          }
          .playlistHeader h2 {
            font-size: 14px;
          }
          .playlistHeader h3 {
            font-size: 21px;
            overflow-wrap: anywhere;
          }
          .trackPanelHeader {
            display: grid;
            align-items: stretch;
          }
          .trackPanelHeader input {
            width: 100%;
          }
          .trackRow {
            grid-template-columns: 24px 34px minmax(0, 1fr);
            gap: 10px;
            padding: 12px;
          }
          .trackRow :global(.artwork--sm) {
            display: none;
          }
          .trackMeta {
            grid-column: 3;
          }
          .badges {
            grid-column: 3;
          }
          .rowActions {
            grid-column: 3;
            grid-template-columns: repeat(6, 40px);
            justify-content: stretch;
          }
          .actionButton {
            width: 40px;
            height: 40px;
          }
        }
      `}</style>
    </main>
  );
}
