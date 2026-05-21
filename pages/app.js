import { useEffect, useMemo, useState } from "react";
import Head from "next/head";
import { ArrowDown, ArrowUp, GripVertical, Lock, Settings, Shuffle, TimerReset, Trash2, Unlock, X } from "lucide-react";
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

function spotifySetupErrorMessage(code = "") {
  if (!code) return "";
  if (code === "subscription_required") return "Start a plan before connecting Spotify accounts.";
  if (code === "auth_required") return "Sign in again before connecting Spotify.";
  if (code === "seat_limit_reached") return "This plan has no free Spotify account seats left.";
  if (code === "spotify_account_already_connected") return "This Spotify account is already connected to another PlaylistPilot workspace.";
  if (code === "missing_spotify_app_credentials") return "Save your Spotify API app credentials before connecting Spotify.";
  if (code === "token_exchange_failed") return "Spotify authorization failed. Check Client ID, Client Secret, and the saved Redirect URI in Spotify.";
  if (code === "spotify_me_failed_403") return "Spotify rejected this account. Add the Spotify account name and email under Users and Access in your Spotify Developer app, then connect again.";
  if (code === "no_refresh_token_consent_required") return "Spotify did not return a refresh token. Retry Connect Spotify and approve access.";
  return `Spotify connection failed: ${code.replaceAll("_", " ")}`;
}

function sortPlaylistsByFollowers(items = []) {
  return [...items].sort((a, b) => {
    const aFollowers = Number(a.followers);
    const bFollowers = Number(b.followers);
    const aRank = Number.isFinite(aFollowers) ? aFollowers : -1;
    const bRank = Number.isFinite(bFollowers) ? bFollowers : -1;
    if (aRank !== bRank) return bRank - aRank;
    return String(a.name || "").localeCompare(String(b.name || ""));
  });
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

function proxiedArtworkUrl(url) {
  const normalized = normalizeSpotifyImageUrl(url);
  if (!normalized) return "";
  try {
    const parsed = new URL(normalized);
    if (parsed.hostname === "i.scdn.co" || parsed.hostname.endsWith(".spotifycdn.com")) {
      return `/api/image-proxy?url=${encodeURIComponent(normalized)}`;
    }
  } catch {
    return normalized;
  }
  return normalized;
}

function Artwork({ src, alt = "", size = "md" }) {
  const normalized = proxiedArtworkUrl(src);
  const [currentSrc, setCurrentSrc] = useState(normalized);
  const [failed, setFailed] = useState(!normalized);

  useEffect(() => {
    const next = proxiedArtworkUrl(src);
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
        const direct = normalizeSpotifyImageUrl(src);
        if (currentSrc !== direct && direct) setCurrentSrc(direct);
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
  const toIndex = Math.max(0, Math.min(list.length - 1, Number(targetPosition)));
  if (fromIndex < 0 || toIndex < 0 || fromIndex === toIndex) return list;
  const next = [...list];
  const [moved] = next.splice(fromIndex, 1);
  next.splice(toIndex, 0, moved);
  return next.map((track, index) => ({
    ...track,
    position: index,
    locked_position: track.is_locked ? index : track.locked_position,
  }));
}

function dropTargetPosition(source, target, placement = "before") {
  const from = Number(source?.position);
  const targetPos = Number(target?.position);
  if (!Number.isFinite(from) || !Number.isFinite(targetPos)) return targetPos;
  if (placement === "after") return from < targetPos ? targetPos : targetPos + 1;
  return from < targetPos ? targetPos - 1 : targetPos;
}

function GrowthChart({ values = [], labels = [], growth = [], granularity = "daily" }) {
  const [hoverIndex, setHoverIndex] = useState(null);
  const points = values.map((v) => Number(v) || 0);
  if (!points.length) return <div className="growthChart growthChart--empty"><span>No growth data yet</span></div>;
  const min = Math.min(...points);
  const max = Math.max(...points);
  const span = max - min || 1;
  const padX = 8;
  const padTop = 10;
  const padBottom = 18;
  const width = 100;
  const height = 64;
  const chartHeight = height - padTop - padBottom;
  const d = points.map((v, i) => {
    const x = points.length === 1 ? 50 : padX + (i / (points.length - 1)) * (width - padX * 2);
    const y = padTop + chartHeight - ((v - min) / span) * chartHeight;
    return `${i ? "L" : "M"}${x.toFixed(2)},${y.toFixed(2)}`;
  }).join(" ");
  const firstX = points.length === 1 ? 50 : padX;
  const lastX = points.length === 1 ? 50 : width - padX;
  const area = `${d} L${lastX},${height - padBottom} L${firstX},${height - padBottom} Z`;
  const gridLines = [padTop, padTop + chartHeight / 2, padTop + chartHeight];
  const activeIndex = hoverIndex === null ? points.length - 1 : hoverIndex;
  const activeX = points.length === 1 ? 50 : padX + (activeIndex / (points.length - 1)) * (width - padX * 2);
  const activeY = padTop + chartHeight - ((points[activeIndex] - min) / span) * chartHeight;
  const tooltipTitle = labels?.[activeIndex] ? formatShortDate(labels[activeIndex]) : `${granularity} ${activeIndex + 1}`;
  const tooltipGrowth = Number(growth?.[activeIndex] || 0);
  const growthLabel = granularity === "monthly" ? "monthly growth" : granularity === "weekly" ? "weekly growth" : "daily growth";
  return (
    <div
      className="growthChart"
      onMouseLeave={() => setHoverIndex(null)}
      onMouseMove={(event) => {
        const rect = event.currentTarget.getBoundingClientRect();
        const ratio = Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width));
        setHoverIndex(Math.round(ratio * (points.length - 1)));
      }}
    >
      <svg viewBox={`0 0 ${width} ${height}`} aria-hidden="true">
        {gridLines.map((y) => <line key={y} className="chartGridLine" x1="0" x2="100" y1={y} y2={y} />)}
        <line className="chartHoverLine" x1={activeX} x2={activeX} y1={padTop} y2={height - padBottom} />
        <path className="chartArea" d={area} />
        <path className="chartLine" d={d} />
        {points.map((v, i) => {
          if (points.length > 12 && i !== 0 && i !== points.length - 1) return null;
          const x = points.length === 1 ? 50 : padX + (i / (points.length - 1)) * (width - padX * 2);
          const y = padTop + chartHeight - ((v - min) / span) * chartHeight;
          return <circle key={i} className="chartPoint" cx={x} cy={y} r="1.3" />;
        })}
        <circle className="chartActivePoint" cx={activeX} cy={activeY} r="2" />
      </svg>
      <div className="chartTooltip" style={{ left: `${activeX}%` }}>
        <strong>{tooltipTitle}</strong>
        <span>{formatNumber(points[activeIndex])} followers</span>
        <em>{formatDelta(tooltipGrowth)} {growthLabel}</em>
      </div>
    </div>
  );
}

function DashboardWarmup({ summary, series, onRefresh, busy }) {
  const playlistCount = summary?.totals?.playlists_count || 0;
  const historyDays = Math.max(summary?.totals?.growth_snapshot_days || 0, series?.history_days || 0);
  const dataPoints = Math.max(summary?.totals?.growth_data_points || 0, series?.data_points || 0);
  return (
    <div className="dashboardWarmup">
      <div>
        <span>Growth monitor warming up</span>
        <h3>Current playlist stats are ready. Trend data needs at least two snapshot days.</h3>
        <p>Spotify does not expose historical follower data, so PlaylistPilot starts tracking from the moment playlists are connected. The growth chart becomes meaningful after a few days and reliable after about one week.</p>
      </div>
      <div className="warmupStats">
        <article><strong>{formatNumber(playlistCount)}</strong><span>playlists tracked</span></article>
        <article><strong>{formatNumber(historyDays)}</strong><span>snapshot days</span></article>
        <article><strong>{formatNumber(dataPoints)}</strong><span>data points</span></article>
      </div>
      <button disabled={busy} onClick={onRefresh}>Refresh baseline now</button>
    </div>
  );
}

function GrowthBars({ items = [], selectedId = "", onSelect }) {
  const max = Math.max(1, ...items.map((item) => Math.abs(Number(item.delta) || 0)));
  return (
    <div className="growthBars">
      {items.map((item, index) => {
        const delta = Number(item.delta) || 0;
        const width = Math.max(4, Math.round((Math.abs(delta) / max) * 100));
        return (
          <button
            type="button"
            className={`growthBar ${selectedId === item.playlist_id ? "selected" : ""}`}
            key={item.playlist_id}
            onClick={() => onSelect?.(item.playlist_id)}
          >
            <span className="growthRank">{index + 1}</span>
            <Artwork src={item.image} alt="" size="sm" />
            <div>
              <strong>{item.name || "Untitled playlist"}</strong>
              <span>{formatNumber(item.followers_now)} followers</span>
            </div>
            <div className="growthSignal">
              <b>{formatDelta(delta)}</b>
              <div className={delta < 0 ? "barTrack negative" : "barTrack"}>
                <i style={{ width: `${width}%` }} />
              </div>
            </div>
          </button>
        );
      })}
      {!items.length ? <p>No growth data yet.</p> : null}
    </div>
  );
}

export default function PlaylistManager() {
  const [supabase, setSupabase] = useState(null);
  const [session, setSession] = useState(null);
  const [authRefreshTick, setAuthRefreshTick] = useState(0);
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
  const [selectedTrackCandidate, setSelectedTrackCandidate] = useState(null);
  const [trackCandidates, setTrackCandidates] = useState([]);
  const [trackSearchLoading, setTrackSearchLoading] = useState(false);
  const [trackSearchNotice, setTrackSearchNotice] = useState("");
  const [trackPosition, setTrackPosition] = useState("");
  const [trackExpiry, setTrackExpiry] = useState("");
  const [autoWeeks, setAutoWeeks] = useState("4");
  const [flexSettings, setFlexSettings] = useState(null);
  const [flexSlots, setFlexSlots] = useState([]);
  const [flexReference, setFlexReference] = useState("");
  const [flexReferenceMeta, setFlexReferenceMeta] = useState(null);
  const [flexReferenceIssue, setFlexReferenceIssue] = useState(null);
  const [flexInterval, setFlexInterval] = useState("weekly");
  const [flexEnabled, setFlexEnabled] = useState(false);
  const [flexRepeatWeeks, setFlexRepeatWeeks] = useState("8");
  const [flexAvoidDuplicates, setFlexAvoidDuplicates] = useState(true);
  const [flexMinPopularity, setFlexMinPopularity] = useState("");
  const [flexMaxPopularity, setFlexMaxPopularity] = useState("");
  const [flexMaxReleaseAgeWeeks, setFlexMaxReleaseAgeWeeks] = useState("");
  const [flexHistory, setFlexHistory] = useState([]);
  const [backups, setBackups] = useState([]);
  const [restoringBackupId, setRestoringBackupId] = useState("");
  const [selectedBackupId, setSelectedBackupId] = useState("");
  const [backupDetail, setBackupDetail] = useState(null);
  const [backupDiff, setBackupDiff] = useState(null);
  const [backupRestoreMode, setBackupRestoreMode] = useState("order");
  const [busy, setBusy] = useState(false);
  const [busyLabel, setBusyLabel] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [view, setView] = useState("manager");
  const [dashboardSummary, setDashboardSummary] = useState(null);
  const [dashboardSeries, setDashboardSeries] = useState(null);
  const [dashboardRange, setDashboardRange] = useState("month");
  const [dashboardGranularity, setDashboardGranularity] = useState("daily");
  const [dashboardStartDate, setDashboardStartDate] = useState("");
  const [dashboardEndDate, setDashboardEndDate] = useState("");
  const [dashboardConnectionId, setDashboardConnectionId] = useState("");
  const [dashboardPlaylistId, setDashboardPlaylistId] = useState("");
  const [moversPage, setMoversPage] = useState(0);
  const [toolsOpen, setToolsOpen] = useState(false);
  const [activeTool, setActiveTool] = useState("add");
  const [dragTrackId, setDragTrackId] = useState("");
  const [dragTarget, setDragTarget] = useState(null);
  const [spotifyCredentials, setSpotifyCredentials] = useState(null);
  const [spotifyCredsOpen, setSpotifyCredsOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [onboardingOpen, setOnboardingOpen] = useState(false);
  const [onboardingDismissed, setOnboardingDismissed] = useState(false);
  const [connectionsLoaded, setConnectionsLoaded] = useState(false);
  const [playlistsLoaded, setPlaylistsLoaded] = useState(false);
  const [healthStatus, setHealthStatus] = useState(null);
  const [spotifyClientId, setSpotifyClientId] = useState("");
  const [spotifyClientSecret, setSpotifyClientSecret] = useState("");
  const [spotifyAppName, setSpotifyAppName] = useState("");
  const [spotifyRedirectUri, setSpotifyRedirectUri] = useState("https://playlist-pilot.com/api/oauth/spotify/callback");
  const [initialSpotifySyncPending, setInitialSpotifySyncPending] = useState(false);
  const [initialSpotifySyncUser, setInitialSpotifySyncUser] = useState("");

  const billing = userContext?.billing || {};
  const billingActive = !!billing.is_active;
  const movers = dashboardSummary?.growth_rank || [];
  const moversPageSize = 5;
  const moversPageCount = Math.max(1, Math.ceil(movers.length / moversPageSize));
  const safeMoversPage = Math.min(moversPage, moversPageCount - 1);
  const visibleMovers = movers.slice(safeMoversPage * moversPageSize, safeMoversPage * moversPageSize + moversPageSize);
  const growthReady = !!(dashboardSeries?.ready || dashboardSummary?.totals?.growth_ready);
  const onboardingBillingReady = billingActive;
  const onboardingCredentialsReady = !!spotifyCredentials?.configured;
  const onboardingConnectionsReady = connections.length > 0;
  const onboardingPlaylistsReady = playlists.length > 0;
  const onboardingNeedsBilling = !onboardingBillingReady && !onboardingCredentialsReady && !onboardingConnectionsReady && !onboardingPlaylistsReady;
  const onboardingMustConnect = billingActive && !onboardingConnectionsReady;
  const onboardingStep = onboardingNeedsBilling ? 1 : !onboardingCredentialsReady ? 2 : !onboardingConnectionsReady ? 3 : !onboardingPlaylistsReady ? 4 : 5;
  const [isMobileViewport, setIsMobileViewport] = useState(false);

  useEffect(() => {
    const client = getSupabaseBrowserClient();
    setSupabase(client);

    client.auth.getSession().then(({ data }) => {
      setSession(data.session || null);
    });

    const { data: listener } = client.auth.onAuthStateChange((event, nextSession) => {
      setSession(nextSession || null);
      if (!nextSession || event === "SIGNED_OUT" || event === "USER_DELETED") {
        setUserContext(null);
        setConnections([]);
        setConnectionsLoaded(false);
        setConnectionId("");
        setPlaylists([]);
        setPlaylistsLoaded(false);
        setPlaylistId("");
        setPlaylist(null);
        setTracks([]);
        setFlexSettings(null);
        setFlexSlots([]);
        setFlexReferenceMeta(null);
        setFlexReferenceIssue(null);
        return;
      }
      if (event === "SIGNED_IN" || event === "TOKEN_REFRESHED" || event === "INITIAL_SESSION") {
        setAuthRefreshTick((value) => value + 1);
      }
    });

    return () => listener.subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const media = window.matchMedia("(max-width: 720px)");
    const update = () => setIsMobileViewport(media.matches);
    update();
    media.addEventListener?.("change", update);
    return () => media.removeEventListener?.("change", update);
  }, []);

  useEffect(() => {
    if (!session?.access_token) return;
    loadCurrentUser();
  }, [session?.access_token, authRefreshTick]);

  useEffect(() => {
    if (!userContext?.linked) return;
    setConnectionsLoaded(false);
    setPlaylistsLoaded(false);
    loadConnections();
    loadDashboard();
    loadSpotifyCredentials();
    loadHealthStatus();
  }, [userContext?.linked]);

  useEffect(() => {
    if (!userContext?.linked || spotifyCredentials === null || !connectionsLoaded || (connectionId && !playlistsLoaded)) return;
    const key = `playlistpilot:onboarding-dismissed:${userContext.bubble_user_id || userContext.email}`;
    const dismissed = !onboardingMustConnect && typeof window !== "undefined" && window.localStorage.getItem(key) === "1";
    setOnboardingDismissed(dismissed);
    if (onboardingMustConnect || (!dismissed && (onboardingNeedsBilling || !onboardingCredentialsReady || !onboardingConnectionsReady || !onboardingPlaylistsReady))) {
      setOnboardingOpen(true);
    }
  }, [userContext?.linked, userContext?.bubble_user_id, userContext?.email, spotifyCredentials, connectionsLoaded, playlistsLoaded, connectionId, onboardingNeedsBilling, onboardingMustConnect, onboardingCredentialsReady, onboardingConnectionsReady, onboardingPlaylistsReady]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const spotifyError = params.get("spotify_error");
    const spotifyLinked = params.get("spotify_linked");
    if (spotifyError) {
      setError(spotifySetupErrorMessage(spotifyError));
      setOnboardingOpen(true);
      params.delete("spotify_error");
    }
    if (spotifyLinked) {
      setMessage("Spotify account connected");
      setInitialSpotifySyncPending(true);
      setInitialSpotifySyncUser(params.get("spotify_user") || "");
      params.delete("spotify_linked");
      params.delete("spotify_user");
    }
    if (spotifyError || spotifyLinked) {
      const next = params.toString();
      window.history.replaceState({}, "", `${window.location.pathname}${next ? `?${next}` : ""}${window.location.hash}`);
    }
  }, []);

  useEffect(() => {
    if (!initialSpotifySyncPending || !billingActive || !connectionId || !session?.access_token) return;
    setInitialSpotifySyncPending(false);
    setInitialSpotifySyncUser("");
    importOnboardingPlaylists("New Spotify account connected. Syncing playlists and follower baselines");
  }, [initialSpotifySyncPending, billingActive, connectionId, session?.access_token]);

  useEffect(() => {
    if (!userContext?.linked || view !== "dashboard") return;
    loadDashboard();
  }, [dashboardRange, dashboardGranularity, dashboardStartDate, dashboardEndDate, dashboardConnectionId, dashboardPlaylistId, view]);

  useEffect(() => {
    setMoversPage(0);
  }, [dashboardRange, dashboardConnectionId, dashboardSummary?.growth_rank?.length]);

  useEffect(() => {
    if (!userContext?.linked || !connectionId) return;
    setPlaylistsLoaded(false);
    writeStoredSelection(userContext, { connectionId });
    loadPlaylists();
  }, [userContext?.linked, connectionId]);

  useEffect(() => {
    if (!dashboardPlaylistId) return;
    const stillAvailable = playlists.some((p) => p.id === dashboardPlaylistId);
    if (!stillAvailable) setDashboardPlaylistId("");
  }, [playlists, dashboardPlaylistId]);

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

  useEffect(() => {
    const query = trackLink.trim();
    if (!connectionId || query.length < 3 || query.includes("spotify.com/track/") || query.startsWith("spotify:track:")) {
      setTrackCandidates([]);
      setTrackSearchLoading(false);
      setTrackSearchNotice("");
      return;
    }

    let cancelled = false;
    const timeout = setTimeout(async () => {
      setTrackSearchLoading(true);
      setTrackSearchNotice("");
      try {
        const data = await api(
          `/api/tracks/search?connection_id=${encodeURIComponent(connectionId)}&q=${encodeURIComponent(query)}&limit=6`,
          { accessToken: accessToken() }
        );
        if (!cancelled) {
          const items = Array.isArray(data?.items) ? data.items : [];
          setTrackCandidates(items);
          setTrackSearchNotice(items.length ? "" : "No tracks found.");
        }
      } catch (e) {
        if (!cancelled) {
          setTrackCandidates([]);
          setTrackSearchNotice(e.message || "Spotify search failed.");
        }
      } finally {
        if (!cancelled) setTrackSearchLoading(false);
      }
    }, 350);

    return () => {
      cancelled = true;
      clearTimeout(timeout);
    };
  }, [trackLink, connectionId, session?.access_token]);

  const activeFlexTrackIds = useMemo(
    () => new Set(flexSlots.map((slot) => slot.current_track_id).filter(Boolean)),
    [flexSlots]
  );

  async function run(label, fn) {
    setBusy(true);
    setBusyLabel(label);
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
      setBusyLabel("");
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
        redirectTo: `${window.location.origin}/app`,
      },
    });
  }

  async function signOut() {
    await supabase.auth.signOut();
  }

  function dismissOnboarding() {
    if (onboardingMustConnect) return;
    const key = userContext?.bubble_user_id || userContext?.email
      ? `playlistpilot:onboarding-dismissed:${userContext.bubble_user_id || userContext.email}`
      : "";
    if (key && typeof window !== "undefined") window.localStorage.setItem(key, "1");
    setOnboardingDismissed(true);
    setOnboardingOpen(false);
  }

  function reopenOnboarding() {
    const key = userContext?.bubble_user_id || userContext?.email
      ? `playlistpilot:onboarding-dismissed:${userContext.bubble_user_id || userContext.email}`
      : "";
    if (key && typeof window !== "undefined") window.localStorage.removeItem(key);
    setOnboardingDismissed(false);
    setOnboardingOpen(true);
  }

  function startSpotifyConnect() {
    if (!userContext?.bubble_user_id) return;
    run("Opening Spotify authorization", async () => {
      const data = await api("/api/oauth/spotify/start", {
        method: "POST",
        accessToken: accessToken(),
        body: { return_to: `${window.location.origin}/app` },
      });
      if (data?.url) window.location.href = data.url;
      return data;
    });
  }

  async function disconnectSpotifyConnection(id) {
    if (!id) return;
    const currentId = connectionId;
    await run("Spotify account removed", async () => {
      await api("/api/connections/disconnect", {
        method: "POST",
        accessToken: accessToken(),
        body: { connection_id: id },
      });
      const nextConnections = await api("/api/connections/list", { accessToken: accessToken() });
      setConnections(nextConnections);
      if (currentId === id) {
        setConnectionId(nextConnections[0]?.id || "");
        setPlaylistId("");
        setPlaylist(null);
        setTracks([]);
      }
      return nextConnections;
    });
  }

  async function startCheckout(plan = "economy", interval = "monthly") {
    await run("Opening checkout", async () => {
      const data = await api("/api/stripe/checkout", {
        method: "POST",
        accessToken: accessToken(),
        body: { plan, interval },
      });
      if (data?.url) window.location.href = data.url;
      return data;
    });
  }

  async function openBillingPortal() {
    await run("Opening billing portal", async () => {
      const data = await api("/api/stripe/portal", { method: "POST", accessToken: accessToken() });
      if (data?.url) window.location.href = data.url;
      return data;
    });
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
      const connectedConnectionId = initialSpotifySyncUser
        ? data.find((c) => c.spotify_user_id === initialSpotifySyncUser)?.id || ""
        : "";
      const storedConnectionId = stored.connectionId && data.some((c) => c.id === stored.connectionId)
        ? stored.connectionId
        : "";
      const nextConnectionId = connectedConnectionId || storedConnectionId || data[0]?.id || "";
      if (connectionId !== nextConnectionId) setConnectionId(nextConnectionId);
      setConnectionsLoaded(true);
      return data;
    });
  }

  async function loadPlaylists() {
    return run("Playlists loaded", async () => {
      const qs = new URLSearchParams();
      if (connectionId) qs.set("connection_id", connectionId);
      const query = qs.toString();
      const data = sortPlaylistsByFollowers(
        await api(`/api/playlists/list${query ? `?${query}` : ""}`, { accessToken: accessToken() })
      );
      setPlaylists(data);
      const stored = readStoredSelection(userContext);
      const storedPlaylistId = stored.playlistId && data.some((p) => p.id === stored.playlistId)
        ? stored.playlistId
        : "";
      const currentPlaylistIsValid = playlistId && data.some((p) => p.id === playlistId);
      const nextPlaylistId = currentPlaylistIsValid ? playlistId : (storedPlaylistId || data[0]?.id || "");
      if (playlistId !== nextPlaylistId) {
        setPlaylistId(nextPlaylistId);
        if (userContext?.linked) writeStoredSelection(userContext, { playlistId: nextPlaylistId });
      }
      setPlaylistsLoaded(true);
      return data;
    });
  }

  async function refreshFromSpotify() {
    if (!connectionId) return;
    await run("Spotify playlists refreshed", async () => {
      await api("/api/playlists/sync?with_followers=1&with_items=1&items_limit=12", {
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
      setFlexRepeatWeeks(String(settings?.repeat_cooldown_weeks ?? "8"));
      setFlexAvoidDuplicates(settings?.avoid_target_duplicates !== false);
      setFlexMinPopularity(settings?.min_popularity ?? "");
      setFlexMaxPopularity(settings?.max_popularity ?? "");
      setFlexMaxReleaseAgeWeeks(settings?.max_release_age_weeks ?? "");
      await Promise.all([loadBackups(), loadFlexHistory()]);
      if (!items.length && Number(detail?.tracks_total || 0) > 0) {
        api("/api/playlists/sync-items", {
          method: "POST",
          accessToken: accessToken(),
          body: { playlist_row_id: playlistId },
        }).then(() => loadSelectedPlaylist()).catch(() => {});
      }
      return { detail, items };
    });
  }

  async function loadFlexHistory() {
    if (!playlistId) return [];
    const rows = await api(`/api/flex/history?playlist_id=${encodeURIComponent(playlistId)}&limit=8`, { accessToken: accessToken() }).catch(() => []);
    setFlexHistory(Array.isArray(rows) ? rows : []);
    return rows;
  }

  async function loadBackups() {
    if (!playlistId) return [];
    const rows = await api(`/api/backups/list?playlist_id=${encodeURIComponent(playlistId)}&limit=8`, { accessToken: accessToken() });
    setBackups(Array.isArray(rows) ? rows : []);
    return rows;
  }

  async function openBackupDetails(backup) {
    if (!playlistId || !backup?.id) return;
    setSelectedBackupId(backup.id);
    await run("Backup loaded", async () => {
      const [detail, diff] = await Promise.all([
        api(`/api/backups/detail?playlist_id=${encodeURIComponent(playlistId)}&backup_id=${encodeURIComponent(backup.id)}`, { accessToken: accessToken() }),
        api(`/api/backups/diff?playlist_id=${encodeURIComponent(playlistId)}&backup_id=${encodeURIComponent(backup.id)}`, { accessToken: accessToken() }),
      ]);
      setBackupDetail(detail);
      setBackupDiff(diff);
      return detail;
    });
  }

  async function createBackupNow() {
    if (!playlistId) return;
    await run("Backup created", async () => {
      await api("/api/backups/create", {
        method: "POST",
        accessToken: accessToken(),
        body: { playlist_id: playlistId },
      });
      await loadBackups();
    });
  }

  async function restoreBackup(backup) {
    if (!playlistId || !backup?.id) return;
    const label = formatShortDate(String(backup.taken_at || "").slice(0, 10)) || "this backup";
    const modeText = backupRestoreMode === "order_rotator"
      ? "playlist order, locks and rotator slots"
      : backupRestoreMode === "order_locks"
        ? "playlist order and locks"
        : "playlist order only";
    const typed = window.prompt(
      `WARNING: Restore ${label}?\n\nPlaylistPilot will create a safety backup first, then restore ${modeText} from this backup.\n\nType ARE YOU SURE to continue.`
    );
    if (typed !== "ARE YOU SURE") return;
    setRestoringBackupId(backup.id);
    try {
      await run("Backup restored", async () => {
        await api("/api/backups/restore", {
          method: "POST",
          accessToken: accessToken(),
          body: {
            playlist_id: playlistId,
            backup_id: backup.id,
            restore_locks: backupRestoreMode === "order_locks" || backupRestoreMode === "order_rotator",
            restore_rotator: backupRestoreMode === "order_rotator",
          },
        });
        await Promise.all([loadBackups(), loadSelectedPlaylist()]);
      });
    } finally {
      setRestoringBackupId("");
    }
  }

  async function cleanupDuplicateBackups() {
    if (!playlistId) return;
    await run("Duplicate backups cleaned", async () => {
      const result = await api("/api/backups/cleanup-duplicates", {
        method: "POST",
        accessToken: accessToken(),
        body: { playlist_id: playlistId },
      });
      await loadBackups();
      setMessage(`Deleted ${formatNumber(result.deleted)} duplicate backups`);
      return result;
    });
  }

  async function applyBackupRetention() {
    if (!playlistId) return;
    await run("Backup retention applied", async () => {
      const result = await api("/api/backups/apply-retention", {
        method: "POST",
        accessToken: accessToken(),
        body: { playlist_id: playlistId, keep_daily_days: 30, keep_weekly_months: 6 },
      });
      await loadBackups();
      setMessage(`Deleted ${formatNumber(result.deleted)} old backups`);
      return result;
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
    const previousLink = trackLink;
    const previousSelectedTrack = selectedTrackCandidate;
    await run("Track added; sync dispatched", async () => {
      if (ENABLE_OPTIMISTIC_PLAYLIST_UI) {
        setTrackLink("");
        setSelectedTrackCandidate(null);
      }
      await api("/api/playlist-items/add", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          playlist_id: playlistId,
          link_or_uri: trackLink,
          position: trackPosition.trim() || "1",
          exp_weeks: trackExpiry || undefined,
        },
      });
      setTrackLink("");
      setSelectedTrackCandidate(null);
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
    }).then((result) => {
      if (result === null && ENABLE_OPTIMISTIC_PLAYLIST_UI) {
        setTrackLink(previousLink);
        setSelectedTrackCandidate(previousSelectedTrack);
      }
    });
  }

  function selectTrackCandidate(candidate) {
    setTrackLink(candidate.uri || candidate.id || "");
    setSelectedTrackCandidate(candidate);
    setTrackCandidates([]);
    setTrackSearchNotice("");
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
    const to = Math.max(0, Math.min(tracks.length - 1, Number(targetPosition)));
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
      const customStart = dashboardRange === "custom" && dashboardStartDate ? new Date(`${dashboardStartDate}T00:00:00`) : null;
      const customEnd = dashboardRange === "custom" && dashboardEndDate ? new Date(`${dashboardEndDate}T00:00:00`) : new Date();
      const customDays = customStart && !Number.isNaN(customStart.getTime())
        ? Math.max(1, Math.ceil((customEnd.getTime() - customStart.getTime()) / (24 * 3600 * 1000)))
        : null;
      const rangeDays = customDays || (dashboardRange === "year" ? 365 : dashboardRange === "week" ? 7 : 30);
      const granularity = dashboardGranularity || (dashboardRange === "year" ? "monthly" : "daily");
      const seriesQs = new URLSearchParams({
        days: String(rangeDays),
        granularity,
        scope: "total",
      });
      if (dashboardRange === "custom") {
        if (dashboardStartDate) seriesQs.set("from", dashboardStartDate);
        if (dashboardEndDate) seriesQs.set("to", dashboardEndDate);
      }
      if (dashboardConnectionId) seriesQs.set("connection_id", dashboardConnectionId);
      if (dashboardPlaylistId) seriesQs.set("playlist_id", dashboardPlaylistId);
      const [summary, series] = await Promise.all([
        api(`/api/dashboard/summary?days=${rangeDays}&removals_limit=12`, { accessToken: accessToken() }),
        api(`/api/dashboard/series?${seriesQs.toString()}`, { accessToken: accessToken() }),
      ]);
      setDashboardSummary(summary);
      setDashboardSeries(series);
      return { summary, series };
    });
  }

  async function refreshDashboardBaseline() {
    if (!connectionId) return;
    await run("Follower baseline refreshed", async () => {
      await api("/api/playlists/sync?with_followers=1", {
        method: "POST",
        accessToken: accessToken(),
        body: { connection_id: connectionId },
      });
      return loadDashboard();
    });
  }

  async function importOnboardingPlaylists(label = "Playlists imported") {
    if (!connectionId) return;
    await run(label, async () => {
      await api("/api/playlists/sync?with_followers=1", {
        method: "POST",
        accessToken: accessToken(),
        body: { connection_id: connectionId },
      });
      await loadPlaylists();
      await loadDashboard();
    });
  }

  async function loadSpotifyCredentials() {
    if (!session?.access_token) return;
    return run("Spotify app settings loaded", async () => {
      const data = await api("/api/spotify/credentials/get", { accessToken: accessToken() });
      setSpotifyCredentials(data);
      setSpotifyClientId(data.credentials?.client_id || "");
      setSpotifyAppName(data.credentials?.app_name || "");
      setSpotifyRedirectUri(data.credentials?.redirect_uri || data.required_redirect_uri || "https://playlist-pilot.com/api/oauth/spotify/callback");
      setSpotifyCredsOpen(!data.configured);
      return data;
    });
  }

  async function loadHealthStatus() {
    if (!session?.access_token) return null;
    const data = await api("/api/health/status", { accessToken: accessToken() }).catch(() => null);
    setHealthStatus(data);
    return data;
  }

  async function saveSpotifyCredentials() {
    await run("Spotify app settings saved", async () => {
      const data = await api("/api/spotify/credentials/save", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          client_id: spotifyClientId,
          client_secret: spotifyClientSecret,
          redirect_uri: spotifyRedirectUri,
          app_name: spotifyAppName,
        },
      });
      setSpotifyClientSecret("");
      await loadSpotifyCredentials();
      return data;
    });
  }

  async function saveFlexSettings() {
    if (!playlistId) return;
    await run("Rotator settings saved", async () => {
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
            repeat_cooldown_weeks: flexRepeatWeeks,
            avoid_target_duplicates: flexAvoidDuplicates,
            min_popularity: flexMinPopularity || null,
            max_popularity: flexMaxPopularity || null,
            max_release_age_weeks: flexMaxReleaseAgeWeeks || null,
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
    await run("Rotation slot added", async () => {
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
    if (!slot?.id) return;
    const previousTracks = tracks;
    const previousSlots = flexSlots;
    if (ENABLE_OPTIMISTIC_PLAYLIST_UI) {
      setFlexSlots(flexSlots.filter((item) => item.id !== slot.id));
      setTracks(tracks.map((item) =>
        item.track_id === slot.current_track_id
          ? { ...item, is_locked: false, locked_position: null }
          : item
      ));
    }
    await run("Rotation slot removed", async () => {
      await api("/api/flex/slots/remove", {
        method: "POST",
        accessToken: accessToken(),
        body: { slot_id: slot.id },
      });
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
    }).then((result) => {
      if (result === null && ENABLE_OPTIMISTIC_PLAYLIST_UI) {
        setTracks(previousTracks);
        setFlexSlots(previousSlots);
      }
    });
  }

  async function rotateFlex(slotId = "") {
    await run("Rotation queued", async () => {
      await api("/api/flex/rotate", {
        method: "POST",
        accessToken: accessToken(),
        body: slotId ? { slot_id: slotId } : { playlist_id: playlistId },
      });
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
      await loadFlexHistory();
    });
  }

  return (
    <main>
      <Head>
        <title>PlaylistPilot | Smart Spotify Playlist Manager</title>
        <meta name="description" content="Manage Spotify playlists with position locks, expiry timers, track rotation, multi-account workflows, and growth analytics." />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta property="og:title" content="PlaylistPilot" />
        <meta property="og:description" content="Smart Spotify playlist management for curators." />
        <meta property="og:type" content="website" />
        <meta property="og:url" content="https://playlist-pilot.com" />
        <meta property="og:image" content="https://playlist-pilot.com/playlistpilot-logo-v1.jpg" />
        <meta name="twitter:card" content="summary" />
        <link rel="icon" href="/playlistpilot-logo-v1.jpg" />
        <link rel="apple-touch-icon" href="/playlistpilot-logo-v1.jpg" />
        <link rel="canonical" href="https://playlist-pilot.com/app" />
      </Head>
      <header className="topbar">
        <div className="brand">
          <img className="logo" src="/playlistpilot-logo-v1.jpg" alt="Playlist Pilot" />
          <div>
            <h1>Playlist Pilot</h1>
            <p>Playlist Manager</p>
          </div>
        </div>
        <nav className="mainNav" aria-label="Main navigation">
          {session && userContext?.linked && billingActive && onboardingConnectionsReady ? (
            <div className="navTabs">
              <button className={view === "dashboard" ? "navButton active" : "navButton"} onClick={() => setView("dashboard")}>Dashboard</button>
              <button className={view === "manager" ? "navButton active" : "navButton"} onClick={() => setView("manager")}>Playlist Manager</button>
            </div>
          ) : null}
          {session && userContext?.linked && billingActive && onboardingConnectionsReady ? (
            <button className="settingsButton topSettingsButton" onClick={() => setSettingsOpen(true)} aria-label="Open settings">
              <Settings aria-hidden="true" />
            </button>
          ) : null}
        </nav>
      </header>
      {busy ? (
        <div className="operationToast" role="status" aria-live="polite">
          <span className="miniSpinner" aria-hidden="true" />
          <strong>{busyLabel || "Working with Spotify"}</strong>
        </div>
      ) : null}

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
      ) : !billingActive ? (
        <section className="subscriptionGate" aria-label="PlaylistPilot subscription required">
          <div className="subscriptionGateCopy">
            <span>Start</span>
            <h2>Choose a plan before opening your workspace</h2>
            <p>PlaylistPilot starts with a 30-day Stripe trial. Your plan controls how many Spotify accounts you can connect and keeps playlist tools behind an active workspace.</p>
            {error ? <strong>{error}</strong> : null}
            <button className="secondaryOutline" onClick={signOut}>Log out</button>
          </div>
          <div className="subscriptionGatePlans">
            <article>
              <span>Economy Class</span>
              <strong>1 Spotify account seat</strong>
              <small>Playlist tools, rotation, automations, dashboard.</small>
              <div>
                <button disabled={busy} onClick={() => startCheckout("economy", "monthly")}>8 EUR / month</button>
                <button className="secondaryOutline" disabled={busy} onClick={() => startCheckout("economy", "yearly")}>79 EUR / year</button>
              </div>
            </article>
            <article>
              <span>Business Class</span>
              <strong>5 Spotify account seats</strong>
              <small>For multi-account curator workflows.</small>
              <div>
                <button disabled={busy} onClick={() => startCheckout("business", "monthly")}>15 EUR / month</button>
                <button className="secondaryOutline" disabled={busy} onClick={() => startCheckout("business", "yearly")}>149 EUR / year</button>
              </div>
            </article>
          </div>
        </section>
      ) : (
      <>
      {onboardingOpen && !onboardingDismissed ? (
        <div className="onboardingOverlay" role="dialog" aria-modal="true" aria-label="PlaylistPilot onboarding">
          <section className="onboardingPanel">
            <div className="onboardingHeader">
              <div>
                <span>Setup</span>
                <h2>Get your first playlist into PlaylistPilot</h2>
                <p>Start your plan, connect the Spotify app credentials you control, authorize Spotify, then import your playlists and baseline stats.</p>
              </div>
              {!onboardingMustConnect ? (
                <button className="iconOnlyButton" onClick={dismissOnboarding} aria-label="Close onboarding">
                  <X aria-hidden="true" />
                </button>
              ) : null}
            </div>
            <ol className="onboardingSteps">
              <li className={onboardingStep === 1 ? "active" : onboardingBillingReady ? "done" : ""}>
                <b>1</b>
                <span><strong>Plan</strong><small>{onboardingBillingReady ? "Subscription active" : "Start your trial and choose seats"}</small></span>
              </li>
              <li className={onboardingStep === 2 ? "active" : onboardingCredentialsReady ? "done" : ""}>
                <b>2</b>
                <span><strong>Spotify API App</strong><small>{onboardingCredentialsReady ? "Credentials saved" : "Create credentials once for your account"}</small></span>
              </li>
              <li className={onboardingStep === 3 ? "active" : onboardingConnectionsReady ? "done" : ""}>
                <b>3</b>
                <span><strong>Connect Spotify</strong><small>{onboardingConnectionsReady ? `${connections.length} account connected` : "Authorize the account to manage"}</small></span>
              </li>
              <li className={onboardingStep === 4 ? "active" : onboardingPlaylistsReady ? "done" : ""}>
                <b>4</b>
                <span><strong>Import Playlists</strong><small>{onboardingPlaylistsReady ? `${playlists.length} playlists available` : "Load playlists and start follower baselines"}</small></span>
              </li>
            </ol>

            {onboardingStep === 1 ? (
              <div className="onboardingStage">
                <div className="onboardingCopy">
                  <h3>Choose the account capacity you need</h3>
                  <p>PlaylistPilot starts with a 30-day Stripe trial. Billing comes first so Spotify accounts are only connected to active workspaces.</p>
                </div>
                <div className="onboardingPlanGrid">
                  <article>
                    <span>Economy Class</span>
                    <strong>1 Spotify account seat</strong>
                    <div>
                      <button disabled={busy} onClick={() => startCheckout("economy", "monthly")}>8 EUR / month</button>
                      <button className="secondaryOutline" disabled={busy} onClick={() => startCheckout("economy", "yearly")}>79 EUR / year</button>
                    </div>
                  </article>
                  <article>
                    <span>Business Class</span>
                    <strong>5 Spotify account seats</strong>
                    <div>
                      <button disabled={busy} onClick={() => startCheckout("business", "monthly")}>15 EUR / month</button>
                      <button className="secondaryOutline" disabled={busy} onClick={() => startCheckout("business", "yearly")}>149 EUR / year</button>
                    </div>
                  </article>
                </div>
              </div>
            ) : null}

            {onboardingStep === 2 ? (
              <div className="onboardingStage">
                <div className="onboardingCopy">
                  <h3>Create your Spotify Developer app</h3>
                  <ol>
                    <li>Open the Spotify Developer Dashboard and create an app.</li>
                    <li>Add this Redirect URI in Spotify app settings.</li>
                    <li>Click Spotify's Save button after adding the Redirect URI.</li>
                    <li>Add every Spotify account you want to connect under Users and Access.</li>
                    <li>Paste Client ID and Client Secret below.</li>
                  </ol>
                </div>
                <div className="onboardingForm">
                  <label><span>Redirect URI</span><input value={spotifyRedirectUri} onChange={(e) => setSpotifyRedirectUri(e.target.value)} /></label>
                  <input value={spotifyAppName} onChange={(e) => setSpotifyAppName(e.target.value)} placeholder="App name" />
                  <input value={spotifyClientId} onChange={(e) => setSpotifyClientId(e.target.value)} placeholder="Client ID" />
                  <input type="password" value={spotifyClientSecret} onChange={(e) => setSpotifyClientSecret(e.target.value)} placeholder="Client Secret" />
                  <button disabled={busy || !spotifyClientId.trim() || !spotifyClientSecret.trim()} onClick={saveSpotifyCredentials}>Save Spotify App</button>
                </div>
              </div>
            ) : null}

            {onboardingStep === 3 ? (
              <div className="onboardingStage">
                <div className="onboardingCopy">
                  <h3>Authorize a Spotify account</h3>
                  <p>The connected Spotify account determines which playlists PlaylistPilot can import and edit.</p>
                  <div className="setupNotice">
                    <strong>Before connecting</strong>
                    <p>Spotify must have this exact Redirect URI saved: <code>{spotifyRedirectUri}</code>. If Spotify shows "redirect_uri: Not matching configuration", reopen your Spotify Developer app, add the URI, and press Save.</p>
                    <p>If Spotify returns a 403 after login, add this Spotify account with its name and email under Users and Access in the same Developer app first.</p>
                  </div>
                </div>
                <div className="onboardingActions">
                  <button disabled={busy} onClick={startSpotifyConnect}>Connect Spotify</button>
                  <button className="secondaryOutline" onClick={() => setSettingsOpen(true)}>Open settings</button>
                </div>
              </div>
            ) : null}

            {onboardingStep === 4 ? (
              <div className="onboardingStage">
                <div className="onboardingCopy">
                  <h3>Import playlists and start tracking</h3>
                  <p>This loads playlists from Spotify and captures the first follower baseline. Growth history builds from this point forward.</p>
                </div>
                <div className="onboardingActions">
                  <button disabled={busy || !connectionId} onClick={importOnboardingPlaylists}>Import playlists</button>
                  <button className="secondaryOutline" disabled={busy} onClick={loadPlaylists}>Check imported playlists</button>
                </div>
              </div>
            ) : null}

            {onboardingStep === 5 ? (
              <div className="onboardingStage onboardingReady">
                <div>
                  <h3>Your workspace is ready</h3>
                  <p>Select a playlist in the manager. Dashboard growth starts as soon as PlaylistPilot has multiple follower snapshot days.</p>
                </div>
                <button onClick={() => { setOnboardingOpen(false); setView("manager"); }}>Open Playlist Manager</button>
              </div>
            ) : null}
          </section>
        </div>
      ) : null}
      {settingsOpen ? (
        <div className="settingsOverlay" role="dialog" aria-modal="true" aria-label="Settings">
          <div className="settingsPanel">
            <div className="settingsHeader">
              <div>
                <h2>Settings</h2>
                <p>Account, billing, and Spotify API setup.</p>
              </div>
              <button className="iconOnlyButton" onClick={() => setSettingsOpen(false)} aria-label="Close settings">
                <X aria-hidden="true" />
              </button>
            </div>

            <section className="settingsSection">
              <span>Signed in</span>
              <strong>{userContext.email}</strong>
              <div className="accountActions">
                <button disabled={busy} onClick={reopenOnboarding}>Open onboarding</button>
                <button className="dangerOutline settingsLogout" onClick={signOut}>Log out</button>
              </div>
            </section>

            <section className="settingsSection">
              <div className="settingsSectionHeader">
                <div>
                  <h3>Spotify Accounts</h3>
                  <p>Connect the Spotify accounts you want to manage in Playlist Pilot.</p>
                </div>
                <button
                  disabled={busy || (!spotifyCredentials?.configured && !spotifyCredentials?.fallback_available)}
                  onClick={startSpotifyConnect}
                >
                  Connect Spotify
                </button>
              </div>
              <div className="connectionList">
                {connections.map((c) => (
                  <div key={c.id} className="connectionItem">
                    <Artwork src={c.avatar_url} alt="" size="sm" />
                    <div>
                      <strong>{c.display_name || c.spotify_user_id || "Spotify Account"}</strong>
                      <span>{c.spotify_user_id || "Connected account"}</span>
                    </div>
                    <button
                      className="dangerOutline"
                      disabled={busy}
                      onClick={() => disconnectSpotifyConnection(c.id)}
                    >
                      Remove
                    </button>
                  </div>
                ))}
                {!connections.length ? <p>No Spotify account connected yet.</p> : null}
              </div>
            </section>

            <section className={billingActive ? "billingBox billingBox--active" : "billingBox"}>
              <div className="settingsSectionHeader">
                <div>
                  <h3>Billing</h3>
                  <p>{billingActive ? "Your current PlaylistPilot plan and renewal." : "Choose a plan to unlock Spotify playlist operations."}</p>
                </div>
                {billingActive ? <button disabled={busy} onClick={openBillingPortal}>Manage billing</button> : null}
              </div>
              <div className="billingSummary">
                <span>{billingActive ? "Subscription active" : "Subscription required"}</span>
                <strong>{billing.plan_code ? `${billing.plan_code} plan` : (billingActive ? "Active plan" : "Choose a plan")}</strong>
                {billing.current_period_end ? <small>Renews through {formatShortDate(String(billing.current_period_end).slice(0, 10))}</small> : null}
              </div>
              {!billingActive ? (
                <div className="pricingGrid">
                  <article>
                    <span>Economy Class</span>
                    <strong>8 EUR <small>/ month</small></strong>
                    <p>1 Spotify account seat</p>
                    <button disabled={busy} onClick={() => startCheckout("economy", "monthly")}>Monthly</button>
                    <button disabled={busy} onClick={() => startCheckout("economy", "yearly")}>79 EUR yearly</button>
                  </article>
                  <article>
                    <span>Business Class</span>
                    <strong>15 EUR <small>/ month</small></strong>
                    <p>5 Spotify account seats</p>
                    <button disabled={busy} onClick={() => startCheckout("business", "monthly")}>Monthly</button>
                    <button disabled={busy} onClick={() => startCheckout("business", "yearly")}>149 EUR yearly</button>
                  </article>
                </div>
              ) : null}
            </section>

            <section className="settingsSection">
              <div className="settingsSectionHeader">
                <div>
                  <h3>Spotify API App</h3>
                  <p>{spotifyCredentials?.configured ? "Credentials configured for your Spotify OAuth flow." : "Create a Spotify Developer app before connecting Spotify accounts."}</p>
                </div>
                {spotifyCredentials?.configured ? (
                  <button onClick={() => setSpotifyCredsOpen(!spotifyCredsOpen)}>{spotifyCredsOpen ? "Hide" : "Edit"}</button>
                ) : null}
              </div>
              {spotifyCredentials?.configured && !spotifyCredsOpen ? (
                <div className="spotifyApiSummary">
                  <span>Configured</span>
                  <strong>{spotifyCredentials?.credentials?.app_name || "Spotify app saved"}</strong>
                  <small>{spotifyCredentials?.credentials?.client_id || "Client ID stored"}</small>
                </div>
              ) : (
                <>
                  <ol>
                    <li>Open developer.spotify.com/dashboard and create an app.</li>
                    <li>Add the Redirect URI below in the app settings.</li>
                    <li>Copy Client ID and Client Secret into Playlist Pilot.</li>
                  </ol>
                  <label>
                    <span>Redirect URI</span>
                    <input value={spotifyRedirectUri} onChange={(e) => setSpotifyRedirectUri(e.target.value)} />
                  </label>
                  <input value={spotifyAppName} onChange={(e) => setSpotifyAppName(e.target.value)} placeholder="App name" />
                  <input value={spotifyClientId} onChange={(e) => setSpotifyClientId(e.target.value)} placeholder="Client ID" />
                  <input
                    type="password"
                    value={spotifyClientSecret}
                    onChange={(e) => setSpotifyClientSecret(e.target.value)}
                    placeholder={spotifyCredentials?.configured ? "New Client Secret to replace" : "Client Secret"}
                  />
                  <button disabled={busy || !spotifyClientId.trim() || !spotifyClientSecret.trim()} onClick={saveSpotifyCredentials}>
                    Save Spotify App
                  </button>
                </>
              )}
            </section>

            <section className="settingsSection">
              <div className="settingsSectionHeader">
                <div>
                  <h3>System Status</h3>
                  <p>Current sync, cooldown, and rotator health.</p>
                </div>
                <button disabled={busy} onClick={loadHealthStatus}>Refresh</button>
              </div>
              <div className="healthGrid">
                <article><span>Spotify</span><strong>{formatNumber(healthStatus?.spotify_connections?.active)}</strong><small>{formatNumber(healthStatus?.spotify_connections?.total)} connected</small></article>
                <article><span>Needs Sync</span><strong>{formatNumber(healthStatus?.playlists?.needs_sync)}</strong><small>{formatNumber(healthStatus?.playlists?.on_cooldown)} in safe edit</small></article>
                <article><span>Stale</span><strong>{formatNumber(healthStatus?.playlists?.stale)}</strong><small>{formatNumber(healthStatus?.playlists?.syncing)} syncing now</small></article>
                <article><span>Rotator</span><strong>{formatNumber(healthStatus?.rotator?.enabled)}</strong><small>{formatNumber(healthStatus?.rotator?.due)} due</small></article>
              </div>
            </section>
          </div>
        </div>
      ) : null}

      {!onboardingConnectionsReady ? (
        <section className="setupHold" aria-live="polite">
          <span>Setup required</span>
          <h2>Connect your first Spotify account</h2>
          <p>The Playlist Manager opens after a Spotify account is authorized. Finish the setup guide above or open Settings to edit your Spotify API app details.</p>
          <button disabled={busy} onClick={() => setOnboardingOpen(true)}>Continue setup</button>
        </section>
      ) : view === "dashboard" ? (
      <section className="dashboard">
        <div className="statusLine">
          {busy ? <span><i className="miniSpinner" aria-hidden="true" />{busyLabel || "Working with Spotify"}</span> : message ? <span>{message}</span> : <span />}
          {error ? <strong>{error}</strong> : null}
        </div>
        <div className="dashboardHero">
          <div>
            <h2>Dashboard</h2>
            <p>{dashboardSummary?.totals?.playlists_count || 0} playlists · {formatNumber(dashboardSummary?.totals?.total_followers)} followers · {formatNumber(dashboardSummary?.totals?.total_tracks)} tracks</p>
          </div>
          <div className="dashboardActions">
            <select value={dashboardRange} onChange={(e) => setDashboardRange(e.target.value)} aria-label="Dashboard range">
              <option value="week">Week</option>
              <option value="month">Month</option>
              <option value="year">Year</option>
              <option value="custom">Custom</option>
            </select>
            <select value={dashboardGranularity} onChange={(e) => setDashboardGranularity(e.target.value)} aria-label="Growth scale">
              <option value="daily">Day</option>
              <option value="weekly">Week</option>
              <option value="monthly">Month</option>
            </select>
            {dashboardRange === "custom" ? (
              <>
                <input type="date" value={dashboardStartDate} onChange={(e) => setDashboardStartDate(e.target.value)} aria-label="Start date" />
                <input type="date" value={dashboardEndDate} onChange={(e) => setDashboardEndDate(e.target.value)} aria-label="End date" />
              </>
            ) : null}
            <button disabled={busy} onClick={loadDashboard}>Refresh</button>
          </div>
        </div>
        <div className="metricGrid">
          <article>
            <span>Total Followers</span>
            <strong>{formatNumber(dashboardSummary?.totals?.total_followers)}</strong>
          </article>
          <article>
            <span>Selected Growth</span>
            <strong>{growthReady ? formatNumber(dashboardSummary?.totals?.net_growth_last_days) : "Warming up"}</strong>
            <small>{growthReady ? `${formatNumber(dashboardSummary?.totals?.growth_snapshot_days)} snapshot days` : "needs 2+ days"}</small>
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
            <span>Track Rotator</span>
            <strong>{formatNumber(dashboardSummary?.totals?.flex_enabled_count)}</strong>
            <small>{formatNumber(dashboardSummary?.totals?.flex_due_count)} due soon</small>
          </article>
          <article>
            <span>Needs Fresh Check</span>
            <strong>{formatNumber(dashboardSummary?.totals?.stale_count)}</strong>
            <small>older than 24h</small>
          </article>
        </div>
        <div className="dashboardFocusGrid">
          <section className="dashboardPanel growthPanel">
            <div className="panelHeader">
              <div>
                <h2>Growth Trend</h2>
                <p>Total follower development for the selected scope</p>
              </div>
              <div className="chartFilters">
                <select value={dashboardConnectionId} onChange={(e) => {
                  setDashboardConnectionId(e.target.value);
                  setDashboardPlaylistId("");
                }} aria-label="Dashboard account">
                  <option value="">All accounts</option>
                  {connections.map((c) => (
                    <option key={c.id} value={c.id}>{c.display_name || c.spotify_user_id}</option>
                  ))}
                </select>
                <select value={dashboardPlaylistId} onChange={(e) => setDashboardPlaylistId(e.target.value)} aria-label="Dashboard playlist">
                  <option value="">All playlists</option>
                  {playlists.map((p) => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
              </div>
            </div>
            {growthReady ? (
              <>
                <GrowthChart
                  values={dashboardSeries?.followers || dashboardSeries?.growth || []}
                  labels={dashboardSeries?.labels || []}
                  growth={dashboardSeries?.growth || []}
                  granularity={dashboardSeries?.granularity || dashboardGranularity}
                />
                <div className="sparkLabels">
                  <span>{dashboardSeries?.labels?.[0] ? formatShortDate(dashboardSeries.labels[0]) : ""}</span>
                  <strong>{formatDelta((dashboardSeries?.growth || []).reduce((sum, value) => sum + (Number(value) || 0), 0))}</strong>
                  <span>{dashboardSeries?.labels?.at?.(-1) ? formatShortDate(dashboardSeries.labels.at(-1)) : ""}</span>
                </div>
              </>
            ) : (
              <DashboardWarmup summary={dashboardSummary} series={dashboardSeries} onRefresh={refreshDashboardBaseline} busy={busy} />
            )}
          </section>
          <section className="dashboardPanel rankPanel">
            <div>
              <h2>Top Movers</h2>
              <p>Click a playlist to show it in the graph</p>
            </div>
            <GrowthBars
              items={visibleMovers}
              selectedId={dashboardPlaylistId}
              onSelect={(id) => setDashboardPlaylistId(id)}
            />
            {movers.length > moversPageSize ? (
              <div className="moversPager">
                <button disabled={safeMoversPage === 0} onClick={() => setMoversPage((page) => Math.max(0, page - 1))}>Prev</button>
                <span>{safeMoversPage + 1} / {moversPageCount}</span>
                <button disabled={safeMoversPage >= moversPageCount - 1} onClick={() => setMoversPage((page) => Math.min(moversPageCount - 1, page + 1))}>Next</button>
              </div>
            ) : null}
          </section>
        </div>
        <div className="dashboardSplitGrid">
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
                  <Artwork src={item.cover_url || item.playlist_image} alt="" size="sm" />
                  <span>
                    <strong>{item.track_name || item.track_id || "Unknown track"}</strong>
                    <em>{item.artist_names || "Unknown artist"}</em>
                    <small>{item.playlist_name || "Playlist"} · {formatShortDate(item.removes_on)} · pos {Number(item.position) + 1}</small>
                  </span>
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
          <label className="accountField">
            <span>Account</span>
            <select value={connectionId} onChange={(e) => setConnectionId(e.target.value)}>
              <option value="">Select account</option>
              {connections.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.display_name || c.spotify_user_id}
                </option>
              ))}
            </select>
          </label>

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
            {busy ? <span><i className="miniSpinner" aria-hidden="true" />{busyLabel || "Working with Spotify"}</span> : message ? <span>{message}</span> : <span />}
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
                  ["flex", "Rotator"],
                  ["backups", "Backups"],
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
                    <p>Search Spotify or paste a track URL. Pick a candidate, then add it at an optional position with optional expiry.</p>
                    <div className="toolGrid addToolGrid">
                      <div className="trackSearchBox">
                        <input
                          value={trackLink}
                          onChange={(e) => {
                            setTrackLink(e.target.value);
                            setSelectedTrackCandidate(null);
                          }}
                          placeholder="Search artist - song or paste Spotify track link"
                        />
                        {selectedTrackCandidate ? (
                          <div className="selectedTrackCard">
                            <Artwork src={selectedTrackCandidate.cover_url} alt="" size="sm" />
                            <span>
                              <strong>{selectedTrackCandidate.name}</strong>
                              <small>{selectedTrackCandidate.artists}{selectedTrackCandidate.album ? ` · ${selectedTrackCandidate.album}` : ""}</small>
                            </span>
                            <button
                              className="iconOnlyButton selectedTrackClear"
                              aria-label="Clear selected song"
                              onClick={() => {
                                setTrackLink("");
                                setSelectedTrackCandidate(null);
                              }}
                            >
                              <X aria-hidden="true" />
                            </button>
                          </div>
                        ) : null}
                        {(trackSearchLoading || trackCandidates.length || trackSearchNotice) ? (
                          <div className="trackCandidates">
                            {trackSearchLoading ? <span>Searching...</span> : null}
                            {!trackSearchLoading && trackSearchNotice ? <span>{trackSearchNotice}</span> : null}
                            {trackCandidates.map((candidate) => (
                              <button key={candidate.id} onClick={() => selectTrackCandidate(candidate)}>
                                <Artwork src={candidate.cover_url} alt="" size="sm" />
                                <span>
                                  <strong>{candidate.name}</strong>
                                  <small>{candidate.artists}{candidate.album ? ` · ${candidate.album}` : ""}</small>
                                </span>
                              </button>
                            ))}
                          </div>
                        ) : null}
                      </div>
                      <input value={trackPosition} onChange={(e) => setTrackPosition(e.target.value)} placeholder="Position" inputMode="numeric" />
                      <input value={trackExpiry} onChange={(e) => setTrackExpiry(e.target.value)} placeholder="Expiry weeks" inputMode="numeric" />
                      <button disabled={busy || !playlistId || !trackLink.trim()} onClick={addTrack}>Add song</button>
                    </div>
                  </>
                ) : null}
                {activeTool === "expiry" ? (
                  <>
                    <h2>Expiry</h2>
                    <p>Automatically remove unlocked songs after the selected number of weeks. Manual per-song expiry still overrides this.</p>
                    <div className="toolGrid expiryToolGrid">
                      <label className="compactField">
                        <span>Default expiry weeks</span>
                        <input type="number" min="1" max="104" value={autoWeeks} onChange={(e) => setAutoWeeks(e.target.value)} />
                      </label>
                      <button disabled={busy || !playlistId} onClick={saveAutoRemoval}>Save expiry</button>
                      <button disabled={busy || !playlistId} onClick={cleanupNow}>Run expiry check now</button>
                    </div>
                  </>
                ) : null}
                {activeTool === "flex" ? (
                  <>
                    <div className="flexPanelHeader">
                      <div>
                        <h2>Track Rotator</h2>
                        <p>Set rotation slots that automatically swap songs from a reference playlist on your schedule.</p>
                      </div>
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
                        Save rotator
                      </button>
                    </div>
                    <div className="rotatorRules">
                      <label className="toggleField">
                        <input type="checkbox" checked={flexAvoidDuplicates} onChange={(e) => setFlexAvoidDuplicates(e.target.checked)} />
                        Skip songs already in target playlist
                      </label>
                      <input value={flexRepeatWeeks} onChange={(e) => setFlexRepeatWeeks(e.target.value)} placeholder="No repeat weeks" inputMode="numeric" />
                      <input value={flexMaxReleaseAgeWeeks} onChange={(e) => setFlexMaxReleaseAgeWeeks(e.target.value)} placeholder="Max release age weeks" inputMode="numeric" />
                      <input value={flexMinPopularity} onChange={(e) => setFlexMinPopularity(e.target.value)} placeholder="Min popularity" inputMode="numeric" />
                      <input value={flexMaxPopularity} onChange={(e) => setFlexMaxPopularity(e.target.value)} placeholder="Max popularity" inputMode="numeric" />
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
                        <button className="tooltipButton" data-tooltip="Rotate all rotation slots now using the reference playlist." disabled={busy || !playlistId || !flexEnabled || !flexSlots.length || !flexReference.trim()} onClick={() => rotateFlex()}>
                          Rotate now
                        </button>
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
                          <button className="tooltipButton" data-tooltip="Replace this rotation slot with a random track from the reference playlist." disabled={busy || !flexReference.trim()} onClick={() => rotateFlex(slot.id)}>Rotate</button>
                          <button className="danger tooltipButton" data-tooltip="Remove this rotation slot. The song becomes a normal playlist item." disabled={busy} onClick={() => removeFlexSlot(slot)}>Remove</button>
                        </div>
                      ))}
                    </div>
                    <div className="rotationHistory">
                      <h3>Recent rotations</h3>
                      {flexHistory.map((item) => (
                        <div key={item.id || `${item.track_id}-${item.rotated_at}`}>
                          <span>{formatShortDate(String(item.rotated_at || "").slice(0, 10))}</span>
                          <strong>{item.track_name || item.track_id}</strong>
                        </div>
                      ))}
                      {!flexHistory.length ? <p>No rotation history yet.</p> : null}
                    </div>
                  </>
                ) : null}
                {activeTool === "backups" ? (
                  <>
                    <div className="flexPanelHeader">
                      <div>
                        <h2>Backups</h2>
                        <p>Create a playlist snapshot before bigger edits. Automatic backups already happen during sync; manual backups are useful before risky reorder sessions.</p>
                      </div>
                      <button className="tooltipButton" data-tooltip="Fetch the current Spotify order and store it as a restorable snapshot." disabled={busy || !playlistId} onClick={createBackupNow}>
                        Create backup
                      </button>
                    </div>
                    <div className="backupActions">
                      <button className="smallOutlineButton" disabled={busy || !playlistId} onClick={cleanupDuplicateBackups}>Clean duplicates</button>
                      <button className="smallOutlineButton" disabled={busy || !playlistId} onClick={applyBackupRetention}>Apply retention</button>
                    </div>
                    <div className="backupList">
                      {backups.map((backup) => (
                        <button
                          className={selectedBackupId === backup.id ? "backupItem selected" : "backupItem"}
                          key={backup.id}
                          onClick={() => openBackupDetails(backup)}
                          type="button"
                        >
                          <Artwork src={backup.image || playlist?.image} alt="" size="sm" />
                          <span>
                            <strong>{formatShortDate(String(backup.taken_at || "").slice(0, 10)) || "Backup"}</strong>
                            <small>{backup.reason ? `${backup.reason} · ` : ""}{formatNumber(backup.tracks_total)} tracks · {backup.snapshot_id ? `snapshot ${String(backup.snapshot_id).slice(0, 8)}` : "no snapshot"}</small>
                          </span>
                        </button>
                      ))}
                      {!backups.length ? <p>No backups stored for this playlist yet.</p> : null}
                    </div>
                    {backupDetail ? (
                      <div className="backupDetail">
                        <div className="backupDetailHeader">
                          <div>
                            <h3>{formatShortDate(String(backupDetail.taken_at || "").slice(0, 10)) || "Backup details"}</h3>
                            <p>{backupDetail.reason || "backup"} · {formatNumber(backupDetail.summary?.tracks_total)} tracks · {formatNumber(backupDetail.summary?.locked_total)} locks · {formatNumber(backupDetail.summary?.rotator_total)} rotator slots</p>
                          </div>
                          <select value={backupRestoreMode} onChange={(event) => setBackupRestoreMode(event.target.value)}>
                            <option value="order">Restore order only</option>
                            <option value="order_locks">Restore order + locks</option>
                            <option value="order_rotator">Restore order + locks + rotator</option>
                          </select>
                          <button
                            className="smallOutlineButton"
                            disabled={busy || restoringBackupId === backupDetail.id}
                            onClick={() => restoreBackup(backupDetail)}
                          >
                            {restoringBackupId === backupDetail.id ? "Restoring" : "Restore selected"}
                          </button>
                        </div>
                        {backupDiff?.diff ? (
                          <div className="backupDiffGrid">
                            <article><span>Moved</span><strong>{formatNumber(backupDiff.diff.moved)}</strong></article>
                            <article><span>Added back</span><strong>{formatNumber(backupDiff.diff.added)}</strong></article>
                            <article><span>Removed now</span><strong>{formatNumber(backupDiff.diff.removed)}</strong></article>
                            <article><span>Lock changes</span><strong>{formatNumber(backupDiff.diff.lock_changes)}</strong></article>
                            <article><span>Expiry changes</span><strong>{formatNumber(backupDiff.diff.expiry_changes)}</strong></article>
                            <article><span>Rotator changes</span><strong>{formatNumber(backupDiff.diff.rotator_changes)}</strong></article>
                          </div>
                        ) : null}
                        {backupDiff?.diff?.preview?.length ? (
                          <div className="backupPreview">
                            <h3>Restore preview</h3>
                            {backupDiff.diff.preview.map((item, index) => (
                              <div key={`${item.type}-${index}`}>
                                <strong>{item.track_name || "Unknown track"}</strong>
                                <span>{item.type.replaceAll("_", " ")}{Number.isFinite(item.from_position) ? ` · from ${item.from_position + 1}` : ""}{Number.isFinite(item.to_position) ? ` · to ${item.to_position + 1}` : ""}</span>
                              </div>
                            ))}
                          </div>
                        ) : null}
                        <div className="backupTracks">
                          {(backupDetail.tracks || []).slice(0, 12).map((track) => (
                            <div key={`${track.position}-${track.track_id}`}>
                              <b>{Number(track.position) + 1}</b>
                              <span>
                                <strong>{track.track_name || "Unknown track"}</strong>
                                <small>{track.artist_names || "Unknown artist"}</small>
                              </span>
                              <em>{track.is_rotator ? "rotator" : track.is_locked ? "lock" : track.expiry_weeks ? "expiry" : "track"}</em>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : null}
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
	                    className={`trackRow ${isFlexTrack ? "trackRow--flex" : ""} ${dragTrackId === track.track_id ? "trackRow--dragging" : ""} ${dragTarget?.trackId === track.track_id ? `trackRow--drop-${dragTarget.placement}` : ""}`}
	                    draggable={!busy && !isMobileViewport}
	                    onDragStart={(e) => {
	                      setDragTrackId(track.track_id);
	                      setDragTarget(null);
	                      e.dataTransfer.effectAllowed = "move";
	                      e.dataTransfer.setData("text/plain", track.track_id);
	                    }}
	                    onDragOver={(e) => {
	                      if (busy || dragTrackId === track.track_id) return;
	                      e.preventDefault();
	                      const rect = e.currentTarget.getBoundingClientRect();
	                      const placement = e.clientY > rect.top + rect.height / 2 ? "after" : "before";
	                      setDragTarget({ trackId: track.track_id, placement });
	                    }}
	                    onDragLeave={() => {
	                      setDragTarget((current) => current?.trackId === track.track_id ? null : current);
	                    }}
	                    onDrop={(e) => {
	                      e.preventDefault();
	                      const sourceId = e.dataTransfer.getData("text/plain");
	                      const source = tracks.find((item) => item.track_id === sourceId);
	                      const placement = dragTarget?.trackId === track.track_id ? dragTarget.placement : "before";
	                      setDragTrackId("");
	                      setDragTarget(null);
	                      if (source) moveTrackTo(source, dropTargetPosition(source, track, placement));
	                    }}
	                    onDragEnd={() => {
	                      setDragTrackId("");
	                      setDragTarget(null);
	                    }}
	                  >
                    {!isMobileViewport ? <div className="dragHandle" aria-hidden="true"><GripVertical /></div> : null}
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
                      {isFlexTrack ? <span className="flexBadge"><Shuffle aria-hidden="true" /> Rotator</span> : null}
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
                      {(flexEnabled || isFlexTrack) ? (
                        <IconButton
                          tooltip={isFlexTrack ? "Convert this rotation slot back into a normal song." : "Turn this song into a locked rotation slot."}
                          disabled={busy}
                          onClick={() => isFlexTrack
                            ? removeFlexSlot(flexSlots.find((slot) => slot.current_track_id === track.track_id))
                            : addFlexSlot(track)
                          }
                        >
                          <Shuffle aria-hidden="true" />
                        </IconButton>
                      ) : null}
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

      <footer className="siteFooter">
        <div>
          <strong>Playlist Pilot</strong>
          <span>Smart Spotify playlist management for curators.</span>
        </div>
        <nav aria-label="Legal links">
          <a href="/legal/imprint">Imprint</a>
          <a href="/legal/privacy">Privacy</a>
          <a href="/legal/terms">Terms</a>
          <a href="mailto:hello@playlist-pilot.com">Contact</a>
        </nav>
      </footer>

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
          display: grid;
          grid-template-rows: auto 1fr auto;
        }
        .topbar {
          position: sticky;
          top: 0;
          z-index: 30;
          display: grid;
          grid-template-columns: auto minmax(0, 1fr);
          align-items: center;
          padding: 22px clamp(20px, 3vw, 40px);
          gap: 24px;
          min-height: 108px;
          border-bottom: 1px solid #202630;
          background: rgba(18, 21, 26, 0.94);
          backdrop-filter: blur(10px);
        }
        .operationToast {
          position: fixed;
          top: 118px;
          right: clamp(16px, 3vw, 36px);
          z-index: 60;
          display: inline-flex;
          align-items: center;
          gap: 10px;
          max-width: min(360px, calc(100vw - 32px));
          padding: 11px 14px;
          border: 1px solid rgba(24, 224, 111, 0.34);
          border-radius: 999px;
          background: rgba(15, 18, 23, 0.94);
          color: #f4f6fb;
          box-shadow: 0 18px 46px rgba(0, 0, 0, 0.36), 0 0 34px rgba(24, 224, 111, 0.1);
          backdrop-filter: blur(12px);
        }
        .operationToast strong {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          font-size: 13px;
        }
        .miniSpinner {
          display: inline-block;
          width: 16px;
          height: 16px;
          flex: 0 0 auto;
          border-radius: 50%;
          border: 2px solid rgba(24, 224, 111, 0.18);
          border-top-color: #18e06f;
          border-right-color: rgba(24, 224, 111, 0.72);
          animation: spin 800ms linear infinite;
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
        .mainNav {
          display: flex;
          align-items: center;
          justify-content: flex-end;
          gap: 12px;
          color: #18e06f;
          font-size: 16px;
        }
        .navTabs {
          display: inline-flex;
          align-items: center;
          gap: 4px;
          padding: 4px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #181c23;
        }
        .navButton {
          border-color: transparent;
          background: transparent;
          min-width: 128px;
          padding: 10px 14px;
          color: #a6adba;
        }
        .topSettingsButton {
          min-width: 40px;
          flex: 0 0 auto;
        }
        .navButton.active {
          border-color: rgba(24, 224, 111, 0.5);
          background: rgba(24, 224, 111, 0.1);
          color: #18e06f;
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
        .subscriptionGate {
          width: min(1180px, 100%);
          margin: auto;
          display: grid;
          grid-template-columns: minmax(300px, 0.9fr) minmax(420px, 1fr);
          align-items: center;
          gap: clamp(18px, 3vw, 42px);
          padding: clamp(28px, 5vw, 64px);
        }
        .subscriptionGateCopy,
        .subscriptionGatePlans,
        .subscriptionGatePlans article,
        .subscriptionGatePlans article div {
          display: grid;
          gap: 12px;
        }
        .subscriptionGateCopy > span,
        .subscriptionGatePlans article > span {
          color: #18e06f;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .subscriptionGateCopy h2 {
          font-size: clamp(30px, 4vw, 52px);
          line-height: 1;
        }
        .subscriptionGateCopy p,
        .subscriptionGatePlans small {
          color: #a6adba;
          line-height: 1.5;
        }
        .subscriptionGateCopy strong {
          color: #ff6b6b;
        }
        .subscriptionGateCopy button {
          width: fit-content;
        }
        .subscriptionGatePlans {
          grid-template-columns: repeat(2, minmax(0, 1fr));
        }
        .subscriptionGatePlans article {
          min-width: 0;
          min-height: 276px;
          align-content: start;
          padding: 20px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #181c23;
        }
        .subscriptionGatePlans article strong {
          min-height: 52px;
          color: #f4f6fb;
          font-size: 24px;
          line-height: 1.15;
        }
        .subscriptionGatePlans article div {
          align-self: end;
          margin-top: auto;
        }
        .setupHold {
          display: grid;
          align-content: center;
          justify-items: start;
          gap: 14px;
          min-height: calc(100vh - 210px);
          width: min(760px, 100%);
          padding: clamp(28px, 5vw, 64px);
        }
        .setupHold span {
          color: #18e06f;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .setupHold h2 {
          font-size: clamp(30px, 4vw, 48px);
          line-height: 1;
        }
        .setupHold p {
          color: #a6adba;
          font-size: 18px;
          line-height: 1.5;
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
        .onboardingOverlay {
          position: fixed;
          inset: 0;
          z-index: 75;
          display: grid;
          place-items: center;
          padding: 24px;
          background: rgba(7, 9, 12, 0.78);
          backdrop-filter: blur(10px);
        }
        .onboardingPanel {
          width: min(980px, 100%);
          max-height: calc(100vh - 48px);
          overflow: auto;
          display: grid;
          gap: 18px;
          padding: clamp(18px, 3vw, 30px);
          border: 1px solid #303743;
          border-radius: 8px;
          background: #181c23;
          box-shadow: 0 28px 100px rgba(0, 0, 0, 0.58);
        }
        .onboardingHeader {
          display: flex;
          justify-content: space-between;
          align-items: start;
          gap: 20px;
        }
        .onboardingHeader div {
          display: grid;
          gap: 8px;
          max-width: 720px;
        }
        .onboardingHeader span {
          color: #18e06f;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .onboardingHeader h2 {
          font-size: clamp(28px, 4vw, 46px);
          line-height: 1;
        }
        .onboardingHeader p,
        .onboardingCopy p,
        .onboardingCopy li,
        .onboardingSteps small {
          color: #a6adba;
          line-height: 1.5;
        }
        .onboardingSteps {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 10px;
          margin: 0;
          padding: 0;
          list-style: none;
        }
        .onboardingSteps li {
          display: grid;
          grid-template-columns: 38px minmax(0, 1fr);
          align-items: center;
          gap: 10px;
          min-width: 0;
          padding: 12px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #12161d;
        }
        .onboardingSteps li.active {
          border-color: rgba(24, 224, 111, 0.58);
          background: rgba(24, 224, 111, 0.08);
        }
        .onboardingSteps li.done b {
          background: #18e06f;
          color: #08110c;
        }
        .onboardingSteps b {
          display: grid;
          place-items: center;
          width: 34px;
          height: 34px;
          border-radius: 50%;
          background: #252c37;
          color: #f4f6fb;
        }
        .onboardingSteps span,
        .onboardingForm label {
          display: grid;
          gap: 3px;
          min-width: 0;
        }
        .onboardingSteps strong {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .onboardingStage {
          display: grid;
          grid-template-columns: minmax(240px, 0.8fr) minmax(320px, 1fr);
          gap: 18px;
          align-items: start;
          padding: 18px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #12161d;
        }
        .onboardingCopy {
          display: grid;
          gap: 12px;
        }
        .onboardingCopy h3,
        .onboardingReady h3 {
          font-size: 22px;
        }
        .onboardingCopy ol {
          display: grid;
          gap: 8px;
          margin: 0;
          padding-left: 18px;
        }
        .onboardingForm {
          display: grid;
          gap: 10px;
        }
        .onboardingPlanGrid {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 10px;
        }
        .onboardingPlanGrid article,
        .setupNotice {
          display: grid;
          gap: 8px;
          min-width: 0;
          padding: 12px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #181c23;
        }
        .onboardingPlanGrid span,
        .setupNotice strong {
          color: #18e06f;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .onboardingPlanGrid strong {
          color: #f4f6fb;
        }
        .onboardingPlanGrid div {
          display: grid;
          gap: 8px;
        }
        .setupNotice {
          border-color: rgba(24, 224, 111, 0.28);
          background: rgba(24, 224, 111, 0.07);
        }
        .setupNotice p {
          margin: 0;
        }
        .setupNotice code {
          color: #f4f6fb;
          overflow-wrap: anywhere;
        }
        .onboardingForm label span {
          color: #a6adba;
          font-size: 12px;
          font-weight: 850;
        }
        .onboardingActions {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          align-self: center;
        }
        .secondaryOutline {
          border-color: #303743;
          color: #f4f6fb;
          background: transparent;
        }
        .onboardingReady {
          grid-template-columns: minmax(0, 1fr) auto;
          align-items: center;
        }
        .onboardingReady div {
          display: grid;
          gap: 6px;
        }
        .onboardingReady p {
          color: #a6adba;
        }
        .settingsOverlay {
          position: fixed;
          inset: 0;
          z-index: 80;
          display: grid;
          place-items: center;
          padding: 24px;
          background: rgba(7, 9, 12, 0.72);
          backdrop-filter: blur(8px);
        }
        .settingsPanel {
          width: min(680px, 100%);
          max-height: min(760px, calc(100vh - 48px));
          overflow: auto;
          display: grid;
          gap: 14px;
          padding: 18px;
          border: 1px solid #303743;
          border-radius: 8px;
          background: #181c23;
          box-shadow: 0 24px 80px rgba(0, 0, 0, 0.52);
        }
        .settingsHeader {
          display: flex;
          align-items: start;
          justify-content: space-between;
          gap: 18px;
          padding-bottom: 4px;
        }
        .settingsHeader h2 {
          font-size: 24px;
        }
        .settingsHeader p,
        .settingsSection p,
        .settingsSection ol {
          margin: 0;
          color: #a6adba;
          line-height: 1.45;
        }
        .settingsSection {
          display: grid;
          gap: 10px;
          padding: 14px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #12161d;
        }
        .settingsSection h3 {
          font-size: 18px;
        }
        .healthGrid {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 8px;
        }
        .healthGrid article {
          display: grid;
          gap: 5px;
          padding: 10px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: #181c23;
        }
        .healthGrid span,
        .healthGrid small {
          color: #a6adba;
          font-size: 12px;
        }
        .healthGrid strong {
          color: #18e06f;
          font-size: 22px;
        }
        .settingsSection > span,
        .settingsSection label span {
          color: #a6adba;
          font-size: 13px;
          font-weight: 800;
        }
        .settingsSection strong {
          overflow-wrap: anywhere;
        }
        .accountActions {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
        }
        .settingsSection ol {
          padding-left: 18px;
        }
        .settingsSection label {
          display: grid;
          gap: 6px;
        }
        .settingsSection input {
          width: 100%;
        }
        .settingsSectionHeader {
          display: grid;
          grid-template-columns: minmax(0, 1fr) auto;
          align-items: start;
          gap: 14px;
        }
        .connectionList {
          display: grid;
          gap: 8px;
        }
        .connectionItem {
          display: grid;
          grid-template-columns: 42px minmax(0, 1fr) auto;
          align-items: center;
          gap: 12px;
          padding: 10px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #181c23;
        }
        .connectionItem div {
          display: grid;
          gap: 3px;
          min-width: 0;
        }
        .connectionItem strong,
        .connectionItem span {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .connectionItem span {
          color: #a6adba;
          font-size: 13px;
        }
        .dangerOutline {
          border-color: #ff4d4d;
          background: transparent;
          color: #ff4d4d;
        }
        .dangerOutline:hover:not(:disabled),
        .dangerOutline:focus-visible:not(:disabled) {
          background: rgba(255, 77, 77, 0.14);
        }
        .settingsLogout {
          width: fit-content;
          margin-top: 4px;
        }
        .iconOnlyButton,
        .settingsButton {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 40px;
          height: 40px;
          min-height: 40px;
          padding: 0;
          border: 1px solid #18e06f;
          background: transparent;
          color: #18e06f;
          border-radius: 8px;
        }
        .iconOnlyButton svg,
        .settingsButton svg {
          width: 18px;
          height: 18px;
        }
        .sidebarHeader {
          display: grid;
          grid-template-columns: minmax(0, 1fr) auto;
          align-items: center;
          gap: 12px;
          padding: 14px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #181c23;
        }
        .sidebarHeader div {
          display: grid;
          gap: 5px;
          min-width: 0;
        }
        .sidebarHeader span {
          color: #a6adba;
          font-size: 13px;
          font-weight: 800;
        }
        .sidebarHeader strong {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
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
        .billingBox {
          display: grid;
          gap: 8px;
          padding: 14px;
          border: 1px solid rgba(255, 189, 74, 0.38);
          border-radius: 8px;
          background: rgba(255, 189, 74, 0.08);
        }
        .billingBox--active {
          border-color: rgba(24, 224, 111, 0.34);
          background: rgba(24, 224, 111, 0.07);
        }
        .billingBox span {
          color: #a6adba;
          font-size: 13px;
          font-weight: 800;
        }
        .billingBox h3 {
          font-size: 18px;
        }
        .billingBox p {
          color: #a6adba;
          line-height: 1.45;
        }
        .billingSummary {
          display: grid;
          gap: 5px;
          padding: 12px;
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 8px;
          background: rgba(18, 22, 29, 0.7);
        }
        .billingBox strong {
          color: #f4f6fb;
          overflow-wrap: anywhere;
        }
        .billingBox small {
          color: #a6adba;
        }
        .billingBox button {
          width: fit-content;
          margin-top: 4px;
        }
        .pricingGrid button {
          width: 100%;
        }
        .spotifyApiSummary {
          display: grid;
          gap: 5px;
          padding: 12px;
          border: 1px solid rgba(24, 224, 111, 0.22);
          border-radius: 8px;
          background: rgba(24, 224, 111, 0.06);
        }
        .spotifyApiSummary span {
          color: #18e06f;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .spotifyApiSummary small {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .pricingGrid {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 10px;
        }
        .pricingGrid article {
          display: grid;
          gap: 8px;
          padding: 12px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #181c23;
        }
        .pricingGrid article span {
          color: #18e06f;
          font-size: 13px;
          font-weight: 800;
        }
        .pricingGrid article strong {
          font-size: 20px;
        }
        .pricingGrid article small,
        .pricingGrid article p {
          color: #a6adba;
          font-size: 13px;
        }
        .spotifySetup {
          border: 1px solid #2a303b;
          background: #181c23;
        }
        .spotifySetupToggle {
          width: 100%;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 14px;
          border: 0;
          border-radius: 0;
          background: #222831;
          padding: 12px 14px;
          text-align: left;
        }
        .spotifySetupToggle span {
          font-weight: 800;
        }
        .spotifySetupToggle small {
          color: #18e06f;
          font-weight: 800;
        }
        .spotifySetupBody {
          display: grid;
          gap: 10px;
          padding: 14px;
        }
        .spotifySetupBody p,
        .spotifySetupBody ol {
          margin: 0;
          color: #a6adba;
          font-size: 13px;
          line-height: 1.45;
        }
        .spotifySetupBody ol {
          padding-left: 18px;
        }
        .spotifySetupBody label {
          display: grid;
          gap: 6px;
        }
        .spotifySetupBody label span {
          color: #a6adba;
          font-size: 13px;
          font-weight: 800;
        }
        .spotifySetupBody input {
          width: 100%;
          min-width: 0;
        }
        .siteFooter {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 18px;
          padding: 22px clamp(20px, 3vw, 40px);
          border-top: 1px solid #202630;
          color: #a6adba;
          background: #101318;
        }
        .siteFooter div {
          display: grid;
          gap: 4px;
        }
        .siteFooter strong {
          color: #f4f6fb;
        }
        .siteFooter nav {
          display: flex;
          align-items: center;
          gap: 16px;
          flex-wrap: wrap;
        }
        .siteFooter a {
          color: #a6adba;
          text-decoration: none;
          font-size: 14px;
        }
        .siteFooter a:hover,
        .siteFooter a:focus-visible {
          color: #18e06f;
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
        .dashboardActions,
        .chartFilters {
          display: flex;
          align-items: center;
          gap: 10px;
          flex-wrap: wrap;
        }
        .dashboardActions select,
        .chartFilters select {
          min-width: 132px;
          height: 42px;
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
          border-radius: 8px;
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
        .dashboardFocusGrid {
          display: grid;
          grid-template-columns: minmax(0, 1.65fr) minmax(330px, 0.75fr);
          gap: 14px;
          align-items: start;
        }
        .dashboardSplitGrid {
          display: grid;
          grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
          gap: 14px;
        }
        .growthPanel {
          min-height: 430px;
          display: grid;
          align-content: start;
          overflow: visible;
        }
        .panelHeader {
          display: flex;
          justify-content: space-between;
          align-items: start;
          gap: 16px;
        }
        .chartFilters {
          justify-content: flex-end;
        }
        .chartFilters select:last-child {
          min-width: 220px;
          max-width: 320px;
        }
        :global(.growthChart) {
          position: relative;
          width: 100%;
          height: 310px;
          margin-top: 18px;
          padding: 2px 0 0;
          overflow: visible;
        }
        :global(.growthChart) svg {
          display: block;
          width: 100%;
          height: 100%;
          overflow: visible;
        }
        :global(.chartGridLine) {
          stroke: rgba(166, 173, 186, 0.18);
          stroke-width: 0.45;
          vector-effect: non-scaling-stroke;
        }
        :global(.chartLine) {
          fill: none;
          stroke: #18e06f;
          stroke-width: 2.5;
          vector-effect: non-scaling-stroke;
          stroke-linecap: round;
          stroke-linejoin: round;
        }
        :global(.chartArea) {
          fill: rgba(24, 224, 111, 0.1);
          stroke: none;
        }
        :global(.chartHoverLine) {
          stroke: rgba(244, 246, 251, 0.26);
          stroke-width: 0.6;
          stroke-dasharray: 2 2;
          vector-effect: non-scaling-stroke;
        }
        :global(.chartPoint) {
          fill: #18e06f;
          stroke: #11161d;
          stroke-width: 0.6;
          vector-effect: non-scaling-stroke;
        }
        :global(.chartActivePoint) {
          fill: #f4fff8;
          stroke: #18e06f;
          stroke-width: 1.2;
          vector-effect: non-scaling-stroke;
        }
        :global(.chartTooltip) {
          position: absolute;
          top: 8px;
          z-index: 8;
          min-width: 150px;
          padding: 9px 10px;
          border: 1px solid rgba(24, 224, 111, 0.28);
          border-radius: 8px;
          background: rgba(15, 18, 23, 0.96);
          color: #f4f6fb;
          box-shadow: 0 16px 40px rgba(0, 0, 0, 0.34);
          pointer-events: none;
          transform: translateX(-50%);
          backdrop-filter: blur(8px);
        }
        :global(.chartTooltip) strong,
        :global(.chartTooltip) span,
        :global(.chartTooltip) em {
          display: block;
          line-height: 1.25;
          white-space: nowrap;
        }
        :global(.chartTooltip) strong {
          font-size: 12px;
          color: #f4f6fb;
        }
        :global(.chartTooltip) span {
          margin-top: 4px;
          color: #a6adba;
          font-size: 12px;
        }
        :global(.chartTooltip) em {
          margin-top: 4px;
          color: #18e06f;
          font-size: 13px;
          font-style: normal;
          font-weight: 900;
        }
        :global(.growthChart--empty) {
          display: grid;
          place-items: center;
          color: #a6adba;
          border: 1px dashed #303743;
          border-radius: 8px;
        }
        .dashboardWarmup {
          display: grid;
          gap: 18px;
          min-height: 310px;
          margin-top: 18px;
          padding: 22px;
          border: 1px dashed rgba(36, 211, 102, 0.34);
          border-radius: 8px;
          background: linear-gradient(135deg, rgba(36, 211, 102, 0.08), rgba(255, 255, 255, 0.025));
          align-content: center;
        }
        .dashboardWarmup div:first-child {
          display: grid;
          gap: 10px;
          max-width: 760px;
        }
        .dashboardWarmup span {
          color: #18e06f;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .dashboardWarmup h3 {
          font-size: clamp(22px, 3vw, 34px);
          line-height: 1.08;
        }
        .dashboardWarmup p {
          max-width: 680px;
          line-height: 1.55;
        }
        .warmupStats {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 10px;
        }
        .warmupStats article {
          display: grid;
          gap: 4px;
          padding: 12px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: rgba(18, 22, 29, 0.76);
        }
        .warmupStats strong {
          font-size: 24px;
        }
        .dashboardWarmup button {
          justify-self: start;
        }
        .sparkLabels {
          display: grid;
          grid-template-columns: 1fr auto 1fr;
          align-items: center;
          justify-content: space-between;
          color: #a6adba;
          font-size: 13px;
          margin-top: 8px;
        }
        .sparkLabels strong {
          color: #18e06f;
          font-size: 14px;
        }
        .sparkLabels span:last-child {
          text-align: right;
        }
        .rankPanel {
          min-height: 0;
          align-self: start;
        }
        .topPlaylistsPanel,
        .removalsPanel {
          min-height: 360px;
        }
        :global(.growthBars) {
          display: grid;
          gap: 10px;
          margin-top: 14px;
        }
        :global(.growthBar) {
          display: grid;
          grid-template-columns: 24px 44px minmax(0, 1fr);
          align-items: center;
          gap: 11px;
          width: 100%;
          min-height: 70px;
          padding: 10px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: #12161d;
          color: #f4f6fb;
          text-align: left;
          min-width: 0;
        }
        :global(.growthBar):hover,
        :global(.growthBar):focus-visible,
        :global(.growthBar).selected {
          background: rgba(24, 224, 111, 0.06);
          border-color: rgba(24, 224, 111, 0.5);
        }
        :global(.growthRank) {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 24px;
          height: 24px;
          border-radius: 999px;
          background: #202630;
          color: #a6adba;
          font-size: 12px;
          font-weight: 900;
        }
        :global(.growthBar) .artwork--sm,
        :global(.growthBar) .coverFallback.artwork--sm {
          width: 44px;
          height: 44px;
        }
        :global(.growthBar) div {
          min-width: 0;
        }
        :global(.growthBar) strong,
        :global(.growthBar) span {
          display: block;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        :global(.growthBar) b {
          color: #18e06f;
          font-size: 14px;
        }
        :global(.growthSignal) {
          grid-column: 3;
          display: grid;
          grid-template-columns: auto minmax(0, 1fr);
          align-items: center;
          gap: 10px;
          min-width: 0;
        }
        :global(.barTrack) {
          height: 6px;
          border-radius: 999px;
          background: #252c37;
          overflow: hidden;
        }
        :global(.barTrack) i {
          display: block;
          height: 100%;
          border-radius: inherit;
          background: #18e06f;
        }
        :global(.barTrack).negative i {
          background: #ff4d4d;
        }
        .moversPager {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
          margin-top: 12px;
          padding-top: 12px;
          border-top: 1px solid #202630;
        }
        .moversPager button {
          min-width: 72px;
          padding: 8px 10px;
          background: transparent;
        }
        .moversPager span {
          color: #a6adba;
          font-size: 13px;
          font-weight: 800;
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
        .removalList {
          display: grid;
          gap: 2px;
          margin-top: 14px;
        }
        .removalList div {
          display: grid;
          grid-template-columns: 42px minmax(0, 1fr);
          align-items: center;
          gap: 10px;
          border-top: 1px solid #202630;
          padding: 9px 0;
          min-width: 0;
        }
        .removalList div:first-child {
          border-top: 0;
        }
        .removalList span {
          display: grid;
          gap: 3px;
          min-width: 0;
        }
        .removalList strong,
        .removalList em,
        .removalList small {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .removalList em {
          color: #a6adba;
          font-size: 13px;
          font-style: normal;
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
          display: grid;
          grid-template-columns: auto minmax(0, 1fr);
          align-items: center;
          gap: 18px;
          width: 100%;
          color: #f4f6fb;
          font-weight: 700;
        }
        .accountField span {
          color: #a6adba;
          font-size: 14px;
          white-space: nowrap;
        }
        .accountField select {
          width: 100%;
          justify-self: stretch;
        }
        .sidebar {
          display: grid;
          align-content: start;
          grid-template-rows: auto auto auto minmax(0, 1fr);
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
        .statusLine span {
          display: inline-flex;
          align-items: center;
          gap: 8px;
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
          grid-template-columns: minmax(420px, 2.4fr) 96px 120px auto;
          align-items: start;
        }
        .trackSearchBox {
          position: relative;
          min-width: 0;
          width: 100%;
        }
        .trackSearchBox input {
          width: 100%;
        }
        .selectedTrackCard {
          display: grid;
          grid-template-columns: 42px minmax(0, 1fr) 34px;
          align-items: center;
          gap: 10px;
          margin-top: 8px;
          padding: 8px;
          border: 1px solid rgba(24, 224, 111, 0.36);
          border-radius: 8px;
          background: rgba(24, 224, 111, 0.07);
        }
        .selectedTrackCard .artwork--sm,
        .selectedTrackCard .coverFallback.artwork--sm {
          width: 42px;
          height: 42px;
        }
        .selectedTrackCard span,
        .selectedTrackCard strong,
        .selectedTrackCard small {
          min-width: 0;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .selectedTrackCard small {
          display: block;
          margin-top: 3px;
          color: #a6adba;
        }
        .selectedTrackClear {
          width: 34px;
          height: 34px;
          min-height: 34px;
          border-color: rgba(24, 224, 111, 0.42);
        }
        .selectedTrackClear svg {
          width: 15px;
          height: 15px;
        }
        .trackCandidates {
          position: absolute;
          top: calc(100% + 8px);
          left: 0;
          right: 0;
          z-index: 30;
          display: grid;
          gap: 4px;
          padding: 8px;
          border: 1px solid #303743;
          border-radius: 8px;
          background: #0f1217;
          box-shadow: 0 18px 40px rgba(0, 0, 0, 0.38);
        }
        .trackCandidates > span {
          padding: 8px;
          color: #a6adba;
          font-size: 13px;
          font-weight: 700;
        }
        .trackCandidates button {
          display: grid;
          grid-template-columns: 42px minmax(0, 1fr);
          align-items: center;
          gap: 10px;
          width: 100%;
          min-height: 54px;
          padding: 6px;
          border-color: transparent;
          background: transparent;
          color: #f4f6fb;
          text-align: left;
        }
        .trackCandidates button:hover,
        .trackCandidates button:focus-visible {
          border-color: rgba(24, 224, 111, 0.45);
          background: rgba(24, 224, 111, 0.08);
        }
        .trackCandidates .artwork--sm,
        .trackCandidates .coverFallback.artwork--sm {
          width: 42px;
          height: 42px;
        }
        .trackCandidates span,
        .trackCandidates strong,
        .trackCandidates small {
          min-width: 0;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .trackCandidates small {
          display: block;
          margin-top: 3px;
          color: #a6adba;
        }
        .addToolGrid > input {
          width: 100%;
        }
        .expiryToolGrid {
          grid-template-columns: minmax(190px, 240px) auto auto;
          align-items: end;
        }
        .compactField {
          display: grid;
          gap: 8px;
          min-width: 0;
          color: #f4f6fb;
          font-weight: 700;
        }
        .compactField span {
          color: #a6adba;
          font-size: 13px;
          white-space: nowrap;
        }
        .compactField input {
          width: 100%;
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
        .rotatorRules {
          display: grid;
          grid-template-columns: minmax(220px, 1.4fr) repeat(4, minmax(120px, 1fr));
          gap: 10px;
          align-items: center;
          padding: 12px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: #12161d;
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
          grid-template-columns: 64px minmax(0, 1fr) auto;
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
        .referencePlaylist button {
          align-self: start;
          white-space: nowrap;
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
        .rotationHistory {
          display: grid;
          gap: 8px;
          padding-top: 4px;
        }
        .rotationHistory h3 {
          font-size: 15px;
        }
        .rotationHistory div {
          display: grid;
          grid-template-columns: 86px minmax(0, 1fr);
          gap: 10px;
          padding: 8px 0;
          border-top: 1px solid #202630;
        }
        .rotationHistory span {
          color: #a6adba;
          font-size: 12px;
          font-weight: 800;
        }
        .rotationHistory strong {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .backupList {
          display: grid;
          gap: 8px;
        }
        .backupActions {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }
        .backupItem {
          display: grid;
          grid-template-columns: 42px minmax(0, 1fr) auto;
          align-items: center;
          width: 100%;
          text-align: left;
          gap: 10px;
          padding: 10px;
          border: 1px solid #252c37;
          border-radius: 8px;
          color: #f4f6fb;
          background: #12161d;
        }
        .backupItem:hover,
        .backupItem.selected {
          border-color: rgba(36, 211, 102, 0.55);
          background: rgba(36, 211, 102, 0.07);
        }
        .backupItem span {
          display: grid;
          gap: 3px;
          min-width: 0;
        }
        .backupItem strong,
        .backupItem small {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .backupItem small {
          color: #a6adba;
        }
        .smallOutlineButton {
          min-height: 34px;
          padding: 0 12px;
          border: 1px solid rgba(36, 211, 102, 0.72);
          border-radius: 8px;
          background: rgba(36, 211, 102, 0.05);
          color: #24d366;
          font-size: 12px;
          font-weight: 850;
          cursor: pointer;
        }
        .smallOutlineButton:hover:not(:disabled) {
          background: rgba(36, 211, 102, 0.12);
        }
        .smallOutlineButton:disabled {
          cursor: not-allowed;
          opacity: 0.55;
        }
        .backupDetail {
          display: grid;
          gap: 12px;
          padding: 14px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: #12161d;
        }
        .backupDetailHeader {
          display: grid;
          grid-template-columns: minmax(0, 1fr) minmax(180px, auto) auto;
          align-items: center;
          gap: 10px;
        }
        .backupDetailHeader div {
          display: grid;
          gap: 3px;
          min-width: 0;
        }
        .backupDetailHeader h3,
        .backupPreview h3 {
          font-size: 15px;
        }
        .backupDetailHeader p,
        .backupPreview span {
          color: #a6adba;
          font-size: 12px;
          font-weight: 800;
        }
        .backupDiffGrid {
          display: grid;
          grid-template-columns: repeat(6, minmax(0, 1fr));
          gap: 8px;
        }
        .backupDiffGrid article {
          display: grid;
          gap: 4px;
          padding: 10px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: #181d25;
        }
        .backupDiffGrid span {
          color: #a6adba;
          font-size: 11px;
          font-weight: 850;
          text-transform: uppercase;
        }
        .backupDiffGrid strong {
          font-size: 18px;
        }
        .backupPreview,
        .backupTracks {
          display: grid;
          gap: 8px;
        }
        .backupPreview div,
        .backupTracks div {
          display: grid;
          grid-template-columns: minmax(0, 1fr) auto;
          gap: 8px;
          align-items: center;
          padding: 8px 0;
          border-top: 1px solid #202630;
        }
        .backupTracks div {
          grid-template-columns: 34px minmax(0, 1fr) auto;
        }
        .backupTracks b,
        .backupTracks em {
          color: #24d366;
          font-style: normal;
          font-weight: 900;
        }
        .backupTracks span {
          display: grid;
          gap: 2px;
          min-width: 0;
        }
        .backupTracks strong,
        .backupTracks small {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .backupTracks small {
          color: #a6adba;
        }
        .backupTracks em {
          border: 1px solid rgba(36, 211, 102, 0.35);
          border-radius: 999px;
          padding: 4px 8px;
          font-size: 11px;
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
          position: relative;
          display: grid;
          grid-template-columns: 28px 44px 52px minmax(180px, 1fr) minmax(74px, auto) minmax(330px, auto);
          align-items: center;
          gap: 12px;
          min-height: 76px;
          padding: 12px 16px;
          border-top: 1px solid #202630;
          transition: background 120ms ease, opacity 120ms ease, box-shadow 120ms ease;
        }
        .trackRow[draggable="true"] {
          cursor: grab;
        }
        .trackRow--dragging {
          opacity: 0.48;
          background: rgba(24, 224, 111, 0.06);
        }
        .trackRow--drop-before,
        .trackRow--drop-after {
          background: rgba(24, 224, 111, 0.075);
          box-shadow: inset 0 0 0 1px rgba(24, 224, 111, 0.16);
        }
        .trackRow--drop-before::before,
        .trackRow--drop-after::after {
          content: "";
          position: absolute;
          left: 14px;
          right: 14px;
          z-index: 4;
          height: 3px;
          border-radius: 999px;
          background: #18e06f;
          box-shadow: 0 0 0 3px rgba(24, 224, 111, 0.14), 0 8px 20px rgba(24, 224, 111, 0.28);
          pointer-events: none;
        }
        .trackRow--drop-before::before {
          top: -2px;
        }
        .trackRow--drop-after::after {
          bottom: -2px;
        }
        .dragHandle {
          color: #637083;
          display: inline-flex;
          align-items: center;
          justify-content: center;
        }
        .trackRow[draggable="true"]:hover .dragHandle,
        .trackRow--dragging .dragHandle {
          color: #18e06f;
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
          width: 7px;
          height: 7px;
          stroke: currentColor;
          stroke-width: 2;
          stroke-linecap: round;
          stroke-linejoin: round;
          fill: none;
        }
        :global(.flexBadge svg) {
          width: 7px;
          height: 7px;
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
          border: 1px solid #18e06f;
          background: transparent;
          color: #18e06f !important;
          border-radius: 7px;
          line-height: 1;
          box-shadow: none;
          transition: background 120ms ease, border-color 120ms ease, color 120ms ease, transform 120ms ease;
        }
        .actionButton:hover:not(:disabled),
        .actionButton:focus-visible:not(:disabled) {
          background: rgba(24, 224, 111, 0.1);
          border-color: #18e06f;
          color: #f4fff8 !important;
          transform: translateY(-1px);
        }
        .actionButton svg {
          width: 17px;
          height: 17px;
          color: currentColor;
          stroke: currentColor;
          fill: none;
          stroke-width: 2.15;
        }
        .actionButton.danger {
          border-color: #ff4d4d;
          background: transparent;
          color: #ff4d4d !important;
          box-shadow: none;
        }
        .actionButton.danger:hover:not(:disabled),
        .actionButton.danger:focus-visible:not(:disabled) {
          background: rgba(255, 77, 77, 0.18);
          border-color: #ff4d4d;
          color: #fff4f4;
        }
        :global(.actionButton) {
          position: relative;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 38px;
          height: 38px;
          min-height: 38px;
          padding: 0;
          border: 1px solid #18e06f;
          background: transparent;
          color: #18e06f !important;
          border-radius: 7px;
          line-height: 1;
          box-shadow: none;
          transition: background 120ms ease, border-color 120ms ease, color 120ms ease, transform 120ms ease;
        }
        :global(.actionButton:hover:not(:disabled)),
        :global(.actionButton:focus-visible:not(:disabled)) {
          background: rgba(24, 224, 111, 0.1);
          border-color: #18e06f;
          color: #f4fff8 !important;
          transform: translateY(-1px);
        }
        :global(.actionButton svg) {
          width: 17px;
          height: 17px;
          color: currentColor;
          stroke: currentColor;
          fill: none;
          stroke-width: 2.15;
        }
        :global(.actionButton.danger) {
          border-color: #ff4d4d;
          background: transparent;
          color: #ff4d4d !important;
          box-shadow: none;
        }
        :global(.actionButton.danger:hover:not(:disabled)),
        :global(.actionButton.danger:focus-visible:not(:disabled)) {
          background: rgba(255, 77, 77, 0.18);
          border-color: #ff4d4d;
          color: #fff4f4 !important;
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
          .topbar, .mainNav, .playlistHeader, .sectionTitle {
            align-items: flex-start;
          }
          .topbar, .playlistHeader {
            grid-template-columns: 1fr;
          }
          .mainNav {
            flex-wrap: wrap;
            gap: 14px;
            justify-content: flex-start;
          }
          .metricGrid,
          .dashboardFocusGrid,
          .dashboardSplitGrid,
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
            position: relative;
            grid-template-columns: minmax(0, 1fr);
            padding: 22px;
          }
          .onboardingSteps,
          .onboardingStage,
          .onboardingReady,
          .onboardingPlanGrid,
          .subscriptionGate,
          .subscriptionGatePlans {
            grid-template-columns: 1fr;
          }
          .onboardingHeader {
            align-items: start;
          }
          .brand {
            align-items: flex-start;
            padding-right: 52px;
          }
          .logo {
            width: 70px;
            height: 70px;
            flex: 0 0 auto;
          }
          .mainNav,
          .navTabs {
            display: grid;
            grid-template-columns: 1fr;
            width: 100%;
          }
          .topSettingsButton {
            position: absolute;
            top: 22px;
            right: 22px;
            justify-self: auto;
            z-index: 2;
          }
          .dashboardHero {
            display: grid;
            align-items: stretch;
          }
          .panelHeader {
            display: grid;
          }
          .chartFilters {
            justify-content: stretch;
          }
          .chartFilters select {
            width: 100%;
            max-width: none;
          }
          :global(.growthBar) {
            grid-template-columns: 24px 44px minmax(0, 1fr);
          }
          :global(.growthSignal) {
            grid-column: 3;
            grid-template-columns: 1fr;
            gap: 6px;
          }
          .playlistTable div {
            grid-template-columns: 42px minmax(0, 1fr);
          }
          .playlistTable span {
            grid-column: 2;
          }
          .siteFooter {
            display: grid;
            align-items: start;
          }
          .siteFooter nav {
            justify-content: flex-start;
          }
          .workspace {
            padding: 22px;
            gap: 40px;
          }
          .sidebar {
            gap: 18px;
          }
          .accountField {
            grid-template-columns: 1fr;
            gap: 8px;
          }
          .accountField select {
            min-height: 48px;
          }
          .accountActions {
            flex-wrap: wrap;
          }
          .sectionTitle {
            display: grid;
            grid-template-columns: 1fr auto;
            align-items: center;
            margin-top: 4px;
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
          .rotatorRules,
          .healthGrid,
          .backupItem,
          .backupDetailHeader,
          .backupDiffGrid,
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
            grid-template-columns: 34px 52px minmax(0, 1fr);
            gap: 10px;
            min-height: 0;
            margin: 0 0 10px;
            padding: 12px;
            border: 1px solid #252c37;
            border-radius: 8px;
            background: #151a22;
          }
          .trackRow[draggable="true"] {
            cursor: default;
          }
          .trackMeta {
            grid-column: 3;
            gap: 3px;
          }
          .trackMeta strong {
            font-size: 15px;
          }
          .trackMeta span,
          .trackMeta small {
            white-space: normal;
            overflow-wrap: anywhere;
          }
          .badges {
            grid-column: 3;
            justify-content: flex-start;
          }
          .rowActions {
            grid-column: 2 / -1;
            grid-template-columns: repeat(6, 40px);
            justify-content: start;
          }
          .actionButton {
            width: 40px;
            height: 40px;
          }
          .trackRow--drop-before::before,
          .trackRow--drop-after::after {
            display: none;
          }
          .dragHandle {
            display: none;
          }
        }
      `}</style>
    </main>
  );
}
