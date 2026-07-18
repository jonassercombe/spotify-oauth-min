import { useEffect, useMemo, useRef, useState } from "react";
import Head from "next/head";
import { useRouter } from "next/router";
import { ArrowDown, ArrowUp, GripVertical, ListEnd, Lock, Settings, Shuffle, TimerReset, Trash2, Unlock, X } from "lucide-react";
import { Turnstile } from "@marsidev/react-turnstile";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getSupabaseBrowserClient } from "../lib/supabaseBrowser";

const ENABLE_OPTIMISTIC_PLAYLIST_UI = true;
const ENABLE_FAST_PLAYLIST_MOVES = true;
const ENABLE_FAST_PLAYLIST_MUTATIONS = true;
const USE_RECHARTS_GROWTH_CHART = true;

const CREATIVE_RENDER_TEMPLATES = [
  { id: "bold_center", name: "Bold Center", description: "Large centered hook with a strong cover reveal.", hook_position: "center", text_align: "center" },
  { id: "editorial_top", name: "Editorial Top", description: "Left-aligned headline in the upper safe zone.", hook_position: "top", text_align: "left" },
  { id: "minimal_bottom", name: "Minimal Bottom", description: "Compact lower-third hook with a restrained CTA.", hook_position: "bottom", text_align: "left" },
];

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

function formatPercent(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "n/a";
  return `${n > 0 ? "+" : ""}${n.toFixed(Math.abs(n) >= 10 ? 0 : 1)}%`;
}

function formatShortDate(value) {
  if (!value) return "";
  const d = new Date(`${value}T00:00:00`);
  if (Number.isNaN(d.getTime())) return value;
  return new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric" }).format(d);
}

function buildBackupSlots(backups = []) {
  const rows = [...(Array.isArray(backups) ? backups : [])]
    .filter((row) => row?.id && Number.isFinite(Date.parse(row.taken_at || "")))
    .sort((a, b) => Date.parse(b.taken_at) - Date.parse(a.taken_at));
  const used = new Set();
  const manual = rows.find((row) => String(row.reason || "") === "manual") || null;
  if (manual) used.add(manual.id);
  const pickAtLeastDaysOld = (days) => {
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const match = rows.find((row) => !used.has(row.id) && Date.parse(row.taken_at) <= cutoff) || null;
    if (match) used.add(match.id);
    return match;
  };
  return [
    { key: "manual", label: "Latest manual", backup: manual, empty: "Create a manual backup to fill this slot." },
    { key: "daily", label: "Daily", backup: pickAtLeastDaysOld(1), empty: "Available after one day of backup history." },
    { key: "weekly", label: "Weekly", backup: pickAtLeastDaysOld(7), empty: "Available after one week of backup history." },
    { key: "monthly", label: "Monthly", backup: pickAtLeastDaysOld(30), empty: "Available after one month of backup history." },
    { key: "six_month", label: "Six-month", backup: pickAtLeastDaysOld(180), empty: "Available after six months of backup history." },
  ];
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

function reorderTracks(list, sourceTrack, targetPosition) {
  const sourcePosition = Number(sourceTrack?.position);
  const fromIndex = list.findIndex((track) => (
    Number.isFinite(sourcePosition)
      ? Number(track.position) === sourcePosition
      : track.track_id === sourceTrack?.track_id
  ));
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

function LegacyGrowthChart({ values = [], labels = [], growth = [], granularity = "daily", valueLabel = "followers" }) {
  const [hoverIndex, setHoverIndex] = useState(null);
  const points = values.map((v) => Number(v) || 0);
  if (!points.length) return <div className="growthChart growthChart--empty"><span>No growth data yet</span></div>;
  const min = Math.min(...points);
  const max = Math.max(...points);
  const span = max - min || 1;
  const width = 720;
  const height = 260;
  const padX = 38;
  const padTop = 28;
  const padBottom = 34;
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
  const activePercent = points.length === 1 ? 50 : (activeX / width) * 100;
  const tooltipX = Math.max(16, Math.min(84, activePercent));
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
      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="xMidYMid meet" aria-hidden="true">
        {gridLines.map((y) => <line key={y} className="chartGridLine" x1={padX} x2={width - padX} y1={y} y2={y} />)}
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
      <div className="chartTooltip" style={{ left: `${tooltipX}%` }}>
        <strong>{tooltipTitle}</strong>
        <span>{formatNumber(points[activeIndex])} {valueLabel}</span>
        <em><b>{formatDelta(tooltipGrowth)}</b> {growthLabel}</em>
      </div>
    </div>
  );
}

function GrowthChartTooltip({ active, payload, label, granularity, valueLabel }) {
  if (!active || !payload?.length) return null;
  const point = payload[0]?.payload || {};
  const growthLabel = granularity === "monthly" ? "monthly growth" : granularity === "weekly" ? "weekly growth" : "daily growth";
  return (
    <div className="rechartsTooltip">
      <strong>{label ? formatShortDate(label) : ""}</strong>
      <span>{formatNumber(point.value)} {valueLabel}</span>
      <em><b>{formatDelta(point.growth)}</b> {growthLabel}</em>
    </div>
  );
}

function RechartsGrowthChart({ values = [], labels = [], growth = [], granularity = "daily", valueLabel = "followers" }) {
  const points = values.map((value, index) => ({
    label: labels?.[index] || String(index + 1),
    value: Number(value) || 0,
    growth: Number(growth?.[index] || 0),
  }));
  if (!points.length) return <div className="growthChart growthChart--empty"><span>No growth data yet</span></div>;
  const min = Math.min(...points.map((point) => point.value));
  const max = Math.max(...points.map((point) => point.value));
  const span = max - min || 1;
  const domainPad = Math.max(1, Math.ceil(span * 0.08));
  const tickFormatter = (value) => {
    if (Math.abs(Number(value)) >= 1000000) return `${Math.round(Number(value) / 100000) / 10}M`;
    if (Math.abs(Number(value)) >= 1000) return `${Math.round(Number(value) / 100) / 10}k`;
    return formatNumber(value);
  };
  return (
    <div className="growthChart growthChart--recharts">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={points} margin={{ top: 18, right: 18, bottom: 6, left: 4 }}>
          <defs>
            <linearGradient id="growthAreaGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#18e06f" stopOpacity={0.28} />
              <stop offset="72%" stopColor="#18e06f" stopOpacity={0.035} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="rgba(166, 173, 186, 0.16)" strokeDasharray="3 7" vertical={false} />
          <XAxis
            dataKey="label"
            axisLine={false}
            tickLine={false}
            minTickGap={26}
            tickMargin={10}
            tick={{ fill: "#7f8794", fontSize: 11, fontWeight: 700 }}
            tickFormatter={formatShortDate}
          />
          <YAxis
            axisLine={false}
            tickLine={false}
            width={54}
            domain={[Math.max(0, min - domainPad), max + domainPad]}
            tick={{ fill: "#7f8794", fontSize: 11, fontWeight: 700 }}
            tickFormatter={tickFormatter}
          />
          <Tooltip
            cursor={{ stroke: "rgba(244, 246, 251, 0.28)", strokeDasharray: "3 4" }}
            content={<GrowthChartTooltip granularity={granularity} valueLabel={valueLabel} />}
          />
          <Area
            type="monotone"
            dataKey="value"
            stroke="#18e06f"
            strokeWidth={2.4}
            fill="url(#growthAreaGradient)"
            activeDot={{ r: 4, fill: "#f4fff8", stroke: "#18e06f", strokeWidth: 2 }}
            dot={points.length <= 14 ? { r: 2, fill: "#18e06f", stroke: "#11161d", strokeWidth: 1 } : false}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function GrowthChart(props) {
  return USE_RECHARTS_GROWTH_CHART ? <RechartsGrowthChart {...props} /> : <LegacyGrowthChart {...props} />;
}

function AdChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  const point = payload[0]?.payload || {};
  return (
    <div className="rechartsTooltip">
      <strong>{label ? formatShortDate(label) : ""}</strong>
      <span>{formatNumber(point.followers)} followers total</span>
      <em><b>{formatDelta(point.growth)}</b> follower delta</em>
      <span>Ad spend: EUR {formatNumber(point.ad_spend || 0)}</span>
    </div>
  );
}

function AdPlaylistChart({ playlist }) {
  const data = (playlist?.labels || []).map((label, index) => ({
    label,
    followers: Number(playlist.followers?.[index] || 0),
    growth: Number(playlist.growth?.[index] || 0),
    ad_spend: Number(playlist.ad_spend?.[index] || 0),
    has_spend: Number(playlist.ad_spend?.[index] || 0) > 0,
  }));
  if (!data.length) return <div className="adChart adChart--empty"><span>No growth snapshots yet</span></div>;
  const hasFollowerData = data.some((point) => Number(point.followers) > 0);
  if (!hasFollowerData) return <div className="adChart adChart--empty"><span>Waiting for follower snapshots</span></div>;
  const events = (playlist.events || []).filter((event) => event.bucket_label && data.some((point) => point.label === event.bucket_label));
  const maxAbsGrowth = Math.max(1, ...data.map((point) => Math.abs(Number(point.growth || 0))));
  const domainPad = Math.max(1, Math.ceil(maxAbsGrowth * 0.12));
  return (
    <div className="adChart">
      <ResponsiveContainer width="100%" height={240} minWidth={240}>
        <BarChart data={data} margin={{ top: 22, right: 18, bottom: 8, left: 0 }} className="adChartSvg">
          <CartesianGrid stroke="rgba(166, 173, 186, 0.14)" strokeDasharray="3 7" vertical={false} />
          <XAxis
            dataKey="label"
            axisLine={false}
            tickLine={false}
            minTickGap={22}
            tick={{ fill: "#7f8794", fontSize: 10, fontWeight: 700 }}
            tickFormatter={formatShortDate}
          />
          <YAxis axisLine={false} tickLine={false} width={54} domain={[-maxAbsGrowth - domainPad, maxAbsGrowth + domainPad]} tick={{ fill: "#7f8794", fontSize: 10, fontWeight: 700 }} tickFormatter={(value) => formatDelta(value)} />
          <Tooltip content={<AdChartTooltip />} cursor={{ fill: "rgba(244, 246, 251, 0.04)" }} />
          <ReferenceLine y={0} stroke="rgba(244, 246, 251, 0.52)" strokeWidth={1.2} />
          <Bar dataKey="growth" radius={[4, 4, 4, 4]} fill="#18e06f" isAnimationActive={false} />
          {events.map((event) => (
            <ReferenceLine
              key={event.id}
              x={event.bucket_label}
              stroke={Number(event.daily_spend || 0) > 0 ? "#7cc7ff" : "#ffd066"}
              strokeDasharray="4 4"
              label={{ value: event.label || (Number(event.daily_spend || 0) > 0 ? `EUR ${event.daily_spend}` : "note"), fill: "#a6adba", fontSize: 10, position: "top" }}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function AdPlaylistFollowerChart({ playlist }) {
  return (
    <div className="adMiniGrowthChart">
      <GrowthChart
        values={playlist?.followers || []}
        labels={playlist?.labels || []}
        growth={playlist?.growth || []}
        granularity="daily"
        valueLabel="followers"
      />
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
  const paddedItems = [...items];
  while (paddedItems.length < 5) paddedItems.push(null);
  return (
    <div className="growthBars">
      {paddedItems.map((item, index) => {
        if (!item) return <div className="growthBar growthBar--empty" key={`empty-${index}`} aria-hidden="true" />;
        const delta = Number(item.delta) || 0;
        return (
          <button
            type="button"
            className={`growthBar ${selectedId === item.playlist_id ? "selected" : ""}`}
            key={item.playlist_id}
            onClick={() => onSelect?.(item.playlist_id)}
          >
            <span className="growthRank">{index + 1}</span>
            <Artwork src={item.image} alt="" size="sm" />
            <div className="growthBarCopy">
              <strong>{item.name || "Untitled playlist"}</strong>
              <span>{formatNumber(item.followers_now)} followers · {formatPercent(item.percent_delta)}</span>
            </div>
            <b
              className={`${delta < 0 ? "growthDelta negative" : "growthDelta"} ${!item.has_growth_data ? "muted" : ""}`}
              title={item.has_growth_data ? `${formatNumber(item.snapshot_days)} snapshot days in this range` : "Not enough snapshots in this range"}
            >
              {item.has_growth_data ? formatDelta(delta) : "warming"}
            </b>
          </button>
        );
      })}
      {!items.length ? <p>No growth data yet.</p> : null}
    </div>
  );
}

export default function PlaylistManager() {
  const router = useRouter();
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
  const [playlistLoading, setPlaylistLoading] = useState(false);
  const [playlistSearch, setPlaylistSearch] = useState("");
  const [trackSearch, setTrackSearch] = useState("");
  const [trackLink, setTrackLink] = useState("");
  const [selectedTrackCandidate, setSelectedTrackCandidate] = useState(null);
  const [trackCandidates, setTrackCandidates] = useState([]);
  const [trackSearchLoading, setTrackSearchLoading] = useState(false);
  const [trackSearchNotice, setTrackSearchNotice] = useState("");
  const [trackPosition, setTrackPosition] = useState("");
  const [trackExpiry, setTrackExpiry] = useState("");
  const [futureAddEnabled, setFutureAddEnabled] = useState(false);
  const [autoExpiryEnabled, setAutoExpiryEnabled] = useState(true);
  const [autoWeeks, setAutoWeeks] = useState("4");
  const [trackLimitEnabled, setTrackLimitEnabled] = useState(false);
  const [trackLimitCount, setTrackLimitCount] = useState("");
  const [trackLimitStrategy, setTrackLimitStrategy] = useState("back");
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
  const [futureAdds, setFutureAdds] = useState([]);
  const [futureAddForm, setFutureAddForm] = useState({
    release_date: "",
    artist_name: "",
    track_title: "",
    position: "",
  });
  const [backups, setBackups] = useState([]);
  const [restoringBackupId, setRestoringBackupId] = useState("");
  const [selectedBackupId, setSelectedBackupId] = useState("");
  const [backupDetail, setBackupDetail] = useState(null);
  const [backupDiff, setBackupDiff] = useState(null);
  const [backupRestoreMode, setBackupRestoreMode] = useState("order");
  const [busy, setBusy] = useState(false);
  const moveInFlightRef = useRef(false);
  const moveQueueRef = useRef(Promise.resolve());
  const moveReconcileTimerRef = useRef(null);
  const [pendingPlaylistEdits, setPendingPlaylistEdits] = useState(0);
  const connectionsLoadSeqRef = useRef(0);
  const lastAutoSetupStepRef = useRef(0);
  const spotifyAccountsSectionRef = useRef(null);
  const spotifyApiSectionRef = useRef(null);
  const playlistLoadSeqRef = useRef(0);
  const selectedPlaylistIdRef = useRef("");
  const [busyLabel, setBusyLabel] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [spotifySetupAlert, setSpotifySetupAlert] = useState("");
  const [authMode, setAuthMode] = useState("login");
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authCaptchaToken, setAuthCaptchaToken] = useState("");
  const [authCaptchaKey, setAuthCaptchaKey] = useState(0);
  const [authSubmitting, setAuthSubmitting] = useState(false);
  const [authNotice, setAuthNotice] = useState("");
  const [passwordRecoveryOpen, setPasswordRecoveryOpen] = useState(false);
  const [recoveryPassword, setRecoveryPassword] = useState("");
  const [view, setView] = useState("manager");
  const [dashboardSummary, setDashboardSummary] = useState(null);
  const [dashboardSeries, setDashboardSeries] = useState(null);
  const [dashboardRange, setDashboardRange] = useState("month");
  const [dashboardGranularity, setDashboardGranularity] = useState("daily");
  const [dashboardStartDate, setDashboardStartDate] = useState("");
  const [dashboardEndDate, setDashboardEndDate] = useState("");
  const [dashboardConnectionId, setDashboardConnectionId] = useState("");
  const [dashboardPlaylistId, setDashboardPlaylistId] = useState("");
  const [dashboardGrowthMode, setDashboardGrowthMode] = useState("followers");
  const [dashboardTab, setDashboardTab] = useState("stats");
  const [adPerformance, setAdPerformance] = useState(null);
  const [adForm, setAdForm] = useState({
    playlist_id: "",
    event_date: new Date().toISOString().slice(0, 10),
    daily_spend: "",
    label: "",
    note: "",
  });
  const [adPlaylistView, setAdPlaylistView] = useState("chart");
  const [adMobileChartMode, setAdMobileChartMode] = useState("delta");
  const [moversPage, setMoversPage] = useState(0);
  const [portfolioPage, setPortfolioPage] = useState(0);
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
  const [adminStatus, setAdminStatus] = useState(null);
  const [metaWorkspace, setMetaWorkspace] = useState(null);
  const [metaForm, setMetaForm] = useState({
    app_id: "2767342386948629",
    business_id: "1442789502837476",
    graph_version: "v25.0",
    access_token: "",
    app_secret: "",
    dsa_beneficiary: "",
    dsa_payor: "",
  });
  const [metaDrafts, setMetaDrafts] = useState([]);
  const [creativeProjects, setCreativeProjects] = useState([]);
  const [creativeProjectForm, setCreativeProjectForm] = useState({ playlist_id: "", name: "", language: "en", format: "9:16" });
  const [openCreativeProjectId, setOpenCreativeProjectId] = useState("");
  const [creativeMediaSearches, setCreativeMediaSearches] = useState({});
  const [openCreativeEditorId, setOpenCreativeEditorId] = useState("");
  const [creativeEditorDrafts, setCreativeEditorDrafts] = useState({});
  const [creativeRenderPolling, setCreativeRenderPolling] = useState({});
  const [creativeBatchTemplates, setCreativeBatchTemplates] = useState({});
  const [creativeBatchRuns, setCreativeBatchRuns] = useState({});
  const [creativeProjectMediaRuns, setCreativeProjectMediaRuns] = useState({});
  const [adsSection, setAdsSection] = useState("overview");
  const [adsWizardStep, setAdsWizardStep] = useState(1);
  const [metaDraftForm, setMetaDraftForm] = useState({
    playlist_id: "",
    name: "Bored Indie Kid — Spotify traffic",
    daily_budget_eur: "10",
    destination_url: "",
    primary_text: "Discover independent music worth saving. Listen now on Spotify.",
    headline: "Discover Bored Indie Kid",
    image_url: "",
    countries: "DE",
    age_min: "18",
    age_max: "45",
    start_date: new Date(Date.now() + 86400000).toISOString().slice(0, 10),
    end_date: new Date(Date.now() + 15 * 86400000).toISOString().slice(0, 10),
    placement_mode: "automatic",
  });
  const [spotifyClientId, setSpotifyClientId] = useState("");
  const [spotifyClientSecret, setSpotifyClientSecret] = useState("");
  const [spotifyAppName, setSpotifyAppName] = useState("");
  const [spotifyRedirectUri, setSpotifyRedirectUri] = useState("https://playlist-pilot.com/api/oauth/spotify/callback");
  const [initialSpotifySyncPending, setInitialSpotifySyncPending] = useState(false);
  const [initialSpotifySyncUser, setInitialSpotifySyncUser] = useState("");

  const adsDraftCounts = {
    total: metaDrafts.length,
    local: metaDrafts.filter((draft) => draft.status === "draft").length,
    ready: metaDrafts.filter((draft) => draft.status === "review_ready").length,
    created: metaDrafts.filter((draft) => draft.status === "created_paused").length,
    errors: metaDrafts.filter((draft) => draft.status === "error").length,
  };

  useEffect(() => {
    if (typeof window === "undefined") return undefined;
    const syncAdsHash = () => {
      const match = window.location.hash.match(/^#ads\/(overview|campaigns|creatives|library|new|settings)$/);
      if (match) {
        setView("ads");
        setAdsSection(match[1]);
      }
    };
    syncAdsHash();
    window.addEventListener("hashchange", syncAdsHash);
    window.addEventListener("popstate", syncAdsHash);
    return () => {
      window.removeEventListener("hashchange", syncAdsHash);
      window.removeEventListener("popstate", syncAdsHash);
    };
  }, []);

  const billing = userContext?.billing || {};
  const billingActive = !!billing.is_active;
  const isAdmin = !!userContext?.is_admin;
  const movers = dashboardSummary?.growth_rank || [];
  const moversPageSize = 5;
  const moversPageCount = Math.max(1, Math.ceil(movers.length / moversPageSize));
  const safeMoversPage = Math.min(moversPage, moversPageCount - 1);
  const visibleMovers = movers.slice(safeMoversPage * moversPageSize, safeMoversPage * moversPageSize + moversPageSize);
  const portfolioItems = dashboardSummary?.top_playlists || [];
  const portfolioPageSize = 12;
  const portfolioPageCount = Math.max(1, Math.ceil(portfolioItems.length / portfolioPageSize));
  const safePortfolioPage = Math.max(0, Math.min(portfolioPage, portfolioPageCount - 1));
  const visiblePortfolioItems = portfolioItems.length > portfolioPageSize
    ? portfolioItems.slice(safePortfolioPage * portfolioPageSize, safePortfolioPage * portfolioPageSize + portfolioPageSize)
    : portfolioItems;
  const performanceRanked = (dashboardSummary?.growth_rank || []).filter((item) => item?.has_growth_data);
  const performanceCards = dashboardSummary?.performance_cards || {};
  const performanceHighlights = {
    bestMonth: performanceCards.best_month || performanceRanked[0] || null,
    bestToday: performanceCards.best_today || null,
    needsAttention: performanceCards.needs_attention || null,
    worstMonth: performanceCards.worst_month || (performanceRanked.length
      ? [...performanceRanked].sort((a, b) => Number(a.delta || 0) - Number(b.delta || 0))[0]
      : null),
  };
  const dashboardPlaylistOptions = useMemo(() => {
    const byId = new Map();
    const addOption = (item) => {
      const id = item?.id || item?.playlist_id;
      if (!id || byId.has(id)) return;
      byId.set(id, {
        id,
        name: item.name || item.playlist_name || "Untitled playlist",
      });
    };
    (dashboardSummary?.playlist_options || []).forEach(addOption);
    playlists.forEach(addOption);
    (dashboardSummary?.top_playlists || []).forEach(addOption);
    (dashboardSummary?.growth_rank || []).forEach(addOption);
    return Array.from(byId.values()).sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
  }, [playlists, dashboardSummary?.playlist_options, dashboardSummary?.top_playlists, dashboardSummary?.growth_rank]);
  const growthReady = !!(dashboardSeries?.ready && (dashboardSeries?.labels || []).length >= 2);
  const growthQuality = dashboardSeries?.quality || {};
  const dashboardChartData = useMemo(() => {
    const followers = (dashboardSeries?.followers || []).map((value) => Number(value) || 0);
    const growth = (dashboardSeries?.growth || []).map((value) => Number(value) || 0);
    if (dashboardGrowthMode === "growth") {
      return { values: growth, growth, label: "growth" };
    }
    if (dashboardGrowthMode === "cumulative") {
      let total = 0;
      return {
        values: growth.map((value) => {
          total += value;
          return total;
        }),
        growth,
        label: "cumulative growth",
      };
    }
    return { values: followers, growth, label: "followers" };
  }, [dashboardSeries?.followers, dashboardSeries?.growth, dashboardGrowthMode]);
  const selectedDashboardPlaylist = useMemo(() => {
    if (!dashboardPlaylistId) return null;
    const candidates = [
      ...(dashboardSummary?.growth_rank || []),
      ...(dashboardSummary?.top_playlists || []),
      ...(dashboardSummary?.playlist_options || []),
      ...playlists,
    ];
    return candidates.find((item) => (item?.id || item?.playlist_id) === dashboardPlaylistId) || null;
  }, [dashboardPlaylistId, dashboardSummary?.growth_rank, dashboardSummary?.top_playlists, dashboardSummary?.playlist_options, playlists]);
  const onboardingBillingReady = billingActive;
  const onboardingCredentialsReady = !!spotifyCredentials?.configured;
  const onboardingConnectionsReady = connections.length > 0;
  const onboardingPlaylistsReady = playlists.length > 0;
  const onboardingNeedsBilling = !onboardingBillingReady && !onboardingCredentialsReady && !onboardingConnectionsReady && !onboardingPlaylistsReady;
  const onboardingMustConnect = billingActive && !onboardingConnectionsReady;
  const onboardingStep = onboardingNeedsBilling ? 1 : !onboardingCredentialsReady ? 2 : !onboardingConnectionsReady ? 3 : !onboardingPlaylistsReady ? 4 : 5;
  const workspaceBootstrapped = !!userContext?.linked && spotifyCredentials !== null && connectionsLoaded && (!connectionId || playlistsLoaded);
  const showSetupProgress = !!userContext?.linked && billingActive && spotifyCredentials !== null && connectionsLoaded && onboardingStep < 5;
  const [isMobileViewport, setIsMobileViewport] = useState(false);

  useEffect(() => {
    selectedPlaylistIdRef.current = playlistId || "";
  }, [playlistId]);

  useEffect(() => {
    const client = getSupabaseBrowserClient();
    setSupabase(client);

    client.auth.getSession().then(({ data }) => {
      setSession(data.session || null);
    });

    const { data: listener } = client.auth.onAuthStateChange((event, nextSession) => {
      setSession(nextSession || null);
      if (event === "PASSWORD_RECOVERY") setPasswordRecoveryOpen(true);
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
        setFutureAdds([]);
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
    setConnectionId("");
    setPlaylists([]);
    setPlaylistId("");
    setPlaylist(null);
    setTracks([]);
    loadConnections();
    loadDashboard();
    loadSpotifyCredentials();
    loadHealthStatus();
  }, [userContext?.linked, userContext?.bubble_user_id]);

  useEffect(() => {
    if (!workspaceBootstrapped) return;
    const key = `playlistpilot:onboarding-dismissed:${userContext.bubble_user_id || userContext.email}`;
    const dismissed = !onboardingMustConnect && typeof window !== "undefined" && window.localStorage.getItem(key) === "1";
    setOnboardingDismissed(dismissed);
    if (onboardingStep < 5) {
      setOnboardingOpen(false);
      if (lastAutoSetupStepRef.current !== onboardingStep) {
        lastAutoSetupStepRef.current = onboardingStep;
        if (onboardingStep === 2) {
          setSpotifyCredsOpen(true);
          setSettingsOpen(true);
        } else if (onboardingStep === 3) {
          setSettingsOpen(true);
        }
      }
    } else {
      lastAutoSetupStepRef.current = 5;
    }
  }, [workspaceBootstrapped, userContext?.bubble_user_id, userContext?.email, onboardingMustConnect, onboardingStep]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const spotifyError = params.get("spotify_error");
    const spotifyLinked = params.get("spotify_linked");
    if (spotifyError) {
      const setupMessage = spotifySetupErrorMessage(spotifyError);
      setError(setupMessage);
      setSpotifySetupAlert(setupMessage);
      if (spotifyError === "spotify_me_failed_403") {
        setSettingsOpen(true);
      } else {
        setOnboardingOpen(true);
      }
      params.delete("spotify_error");
    }
    if (spotifyLinked) {
      setMessage("Spotify account connected");
      setInitialSpotifySyncPending(true);
      setInitialSpotifySyncUser(params.get("spotify_user") || "");
      setConnectionsLoaded(false);
      setConnectionId("");
      params.delete("spotify_linked");
      params.delete("spotify_user");
    }
    if (spotifyError || spotifyLinked) {
      const next = params.toString();
      router.replace(`${window.location.pathname}${next ? `?${next}` : ""}${window.location.hash}`, undefined, { shallow: true });
    }
  }, [router]);

  useEffect(() => {
    if (!initialSpotifySyncPending || !initialSpotifySyncUser || !userContext?.linked || !session?.access_token) return;
    loadConnections(initialSpotifySyncUser, { retryPreferred: true });
  }, [initialSpotifySyncPending, initialSpotifySyncUser, userContext?.linked, session?.access_token]);

  useEffect(() => {
    if (!initialSpotifySyncPending || !billingActive || !connectionId || !session?.access_token) return;
    const linkedConnection = connections.find((item) => item.spotify_user_id === initialSpotifySyncUser);
    if (!linkedConnection || linkedConnection.id !== connectionId) return;
    setInitialSpotifySyncPending(false);
    setInitialSpotifySyncUser("");
    importOnboardingPlaylists("New Spotify account connected. Syncing playlists and follower baselines");
  }, [initialSpotifySyncPending, initialSpotifySyncUser, billingActive, connectionId, connections, session?.access_token]);

  useEffect(() => {
    if (!userContext?.linked || view !== "dashboard") return;
    loadDashboard();
  }, [dashboardRange, dashboardGranularity, dashboardStartDate, dashboardEndDate, dashboardConnectionId, dashboardPlaylistId, view]);

  useEffect(() => {
    if (!userContext?.linked || view !== "dashboard" || dashboardTab !== "ad") return;
    loadAdPerformance();
  }, [dashboardRange, dashboardGranularity, dashboardStartDate, dashboardEndDate, dashboardConnectionId, dashboardTab, view]);

  useEffect(() => {
    if (!userContext?.linked || !isAdmin || view !== "admin") return;
    loadAdminStatus();
  }, [userContext?.linked, isAdmin, view]);

  useEffect(() => {
    if (!userContext?.linked || !isAdmin || view !== "ads") return;
    loadMetaWorkspace();
    loadMetaDrafts();
    loadCreativeProjects();
  }, [userContext?.linked, isAdmin, view]);

  useEffect(() => {
    if (dashboardRange === "year" && dashboardGranularity !== "monthly") {
      setDashboardGranularity("monthly");
    }
  }, [dashboardRange, dashboardGranularity]);

  useEffect(() => {
    setMoversPage(0);
    setPortfolioPage(0);
  }, [dashboardRange, dashboardConnectionId, dashboardSummary?.growth_rank?.length, dashboardSummary?.top_playlists?.length]);

  useEffect(() => {
    if (!userContext?.linked || !connectionId) return;
    setPlaylistsLoaded(false);
    writeStoredSelection(userContext, { connectionId });
    loadPlaylists();
  }, [userContext?.linked, connectionId]);

  useEffect(() => {
    if (!playlistId) {
      setPlaylist(null);
      setTracks([]);
      setPlaylistLoading(false);
      return;
    }
    if (!workspaceBootstrapped || !playlists.some((p) => p.id === playlistId)) return;
    if (moveReconcileTimerRef.current) clearTimeout(moveReconcileTimerRef.current);
    if (userContext?.linked) writeStoredSelection(userContext, { playlistId });
    setPlaylist(null);
    setTracks([]);
    loadSelectedPlaylist();
  }, [playlistId, workspaceBootstrapped, playlists]);

  useEffect(() => () => {
    if (moveReconcileTimerRef.current) clearTimeout(moveReconcileTimerRef.current);
  }, []);

  useEffect(() => {
    if (!settingsOpen || (onboardingStep !== 2 && onboardingStep !== 3)) return;
    const timer = setTimeout(() => {
      const target = onboardingStep === 2 ? spotifyApiSectionRef.current : spotifyAccountsSectionRef.current;
      target?.scrollIntoView?.({ behavior: "smooth", block: "center" });
    }, 80);
    return () => clearTimeout(timer);
  }, [settingsOpen, onboardingStep]);

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
  const backupSlots = useMemo(() => buildBackupSlots(backups), [backups]);

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

  function resetAuthCaptcha() {
    setAuthCaptchaToken("");
    setAuthCaptchaKey((value) => value + 1);
  }

  async function submitEmailAuth(event) {
    event.preventDefault();
    if (!supabase || authSubmitting) return;
    const email = authEmail.trim().toLowerCase();
    const turnstileSiteKey = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || "";
    setError("");
    setAuthNotice("");
    if (!email) return setError("Enter your email address.");
    if (!turnstileSiteKey) return setError("Email signup is temporarily unavailable while bot protection is being configured. Google login still works.");
    if (!authCaptchaToken) return setError("Complete the security check first.");
    if (authMode !== "reset" && authPassword.length < 10) return setError("Use a password with at least 10 characters.");

    setAuthSubmitting(true);
    try {
      if (authMode === "signup") {
        const { data, error: authError } = await supabase.auth.signUp({
          email,
          password: authPassword,
          options: {
            captchaToken: authCaptchaToken,
            emailRedirectTo: `${window.location.origin}/app`,
          },
        });
        if (authError) throw authError;
        if (!data.session) {
          setAuthNotice("Check your inbox and confirm your email before signing in.");
          setAuthMode("login");
          setAuthPassword("");
        }
      } else if (authMode === "reset") {
        const { error: authError } = await supabase.auth.resetPasswordForEmail(email, {
          captchaToken: authCaptchaToken,
          redirectTo: `${window.location.origin}/app`,
        });
        if (authError) throw authError;
        setAuthNotice("Password reset instructions have been sent if an account exists for this email.");
        setAuthMode("login");
      } else {
        const { error: authError } = await supabase.auth.signInWithPassword({
          email,
          password: authPassword,
          options: { captchaToken: authCaptchaToken },
        });
        if (authError) throw authError;
      }
    } catch (authError) {
      setError(authError?.message || "Authentication failed. Please try again.");
    } finally {
      setAuthSubmitting(false);
      resetAuthCaptcha();
    }
  }

  async function signOut() {
    await supabase.auth.signOut();
  }

  async function saveRecoveryPassword(event) {
    event.preventDefault();
    if (!supabase || recoveryPassword.length < 10) {
      setError("Use a password with at least 10 characters.");
      return;
    }
    setAuthSubmitting(true);
    setError("");
    const { error: authError } = await supabase.auth.updateUser({ password: recoveryPassword });
    setAuthSubmitting(false);
    if (authError) {
      setError(authError.message || "Could not update your password.");
      return;
    }
    setRecoveryPassword("");
    setPasswordRecoveryOpen(false);
    setMessage("Password updated");
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

  function openCurrentSetupStep() {
    setOnboardingOpen(false);
    if (onboardingStep === 2) {
      setSpotifyCredsOpen(true);
      setSettingsOpen(true);
      return;
    }
    if (onboardingStep === 3) {
      setSettingsOpen(true);
      return;
    }
    if (onboardingStep === 4) {
      importOnboardingPlaylists("Importing playlists and creating your first follower baseline");
    }
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

  async function loadConnections(preferredSpotifyUserId = "", { retryPreferred = false } = {}) {
    const loadSeq = connectionsLoadSeqRef.current + 1;
    connectionsLoadSeqRef.current = loadSeq;
    return run("Connections loaded", async () => {
      let data = await api("/api/connections/list", { accessToken: accessToken() });
      if (retryPreferred && preferredSpotifyUserId && !data.some((c) => c.spotify_user_id === preferredSpotifyUserId)) {
        await new Promise((resolve) => setTimeout(resolve, 650));
        data = await api("/api/connections/list", { accessToken: accessToken() });
      }
      if (connectionsLoadSeqRef.current !== loadSeq) return data;
      setConnections(data);
      const stored = readStoredSelection(userContext);
      const preferredId = preferredSpotifyUserId || initialSpotifySyncUser;
      const connectedConnectionId = preferredId
        ? data.find((c) => c.spotify_user_id === preferredId)?.id || ""
        : "";
      const storedConnectionId = stored.connectionId && data.some((c) => c.id === stored.connectionId)
        ? stored.connectionId
        : "";
      const nextConnectionId = connectedConnectionId || storedConnectionId || data[0]?.id || "";
      if (connectionId !== nextConnectionId) setConnectionId(nextConnectionId);
      setConnectionsLoaded(true);
      if (retryPreferred && preferredSpotifyUserId && !connectedConnectionId) {
        throw new Error("Spotify authorization completed, but the account is not active in this workspace. Refresh accounts or reconnect Spotify.");
      }
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
    const loadPlaylistId = playlistId;
    const loadSeq = playlistLoadSeqRef.current + 1;
    playlistLoadSeqRef.current = loadSeq;
    setPlaylistLoading(true);
    return run("Tracks loaded", async () => {
      let [detail, itemPayload] = await Promise.all([
        api(`/api/playlists/get?playlist_id=${encodeURIComponent(loadPlaylistId)}`, { accessToken: accessToken() }),
        api(`/api/playlist-items/list?playlist_row_id=${encodeURIComponent(loadPlaylistId)}&meta=1`, { accessToken: accessToken() }),
      ]);
      let items = normalizePlaylistItems(Array.isArray(itemPayload) ? itemPayload : (itemPayload?.items || []));
      let itemMeta = Array.isArray(itemPayload) ? null : itemPayload?.meta;
      const expectedTracks = Number(detail?.tracks_total || 0);
      const loadedTracks = Array.isArray(items) ? items.length : 0;
      const looksPartial = !!itemMeta?.partial || (expectedTracks > 0 && loadedTracks > 0 && loadedTracks < Math.max(1, Math.floor(expectedTracks * 0.8)));
      if ((!loadedTracks || looksPartial) && expectedTracks > 0) {
        await api("/api/playlists/sync-items", {
          method: "POST",
          accessToken: accessToken(),
          body: { playlist_row_id: loadPlaylistId, read_only: true },
        }).catch(() => null);
        [detail, itemPayload] = await Promise.all([
          api(`/api/playlists/get?playlist_id=${encodeURIComponent(loadPlaylistId)}`, { accessToken: accessToken() }),
          api(`/api/playlist-items/list?playlist_row_id=${encodeURIComponent(loadPlaylistId)}&meta=1&repair=0`, { accessToken: accessToken() }),
        ]);
        items = normalizePlaylistItems(Array.isArray(itemPayload) ? itemPayload : (itemPayload?.items || []));
        itemMeta = Array.isArray(itemPayload) ? null : itemPayload?.meta;
      }
      assertCompletePlaylistItems(items, itemMeta);
      const [settings, slots] = await Promise.all([
        api(`/api/flex/settings/get?playlist_id=${encodeURIComponent(loadPlaylistId)}`, { accessToken: accessToken() }).catch(() => null),
        api(`/api/flex/slots/list?playlist_id=${encodeURIComponent(loadPlaylistId)}`, { accessToken: accessToken() }).catch(() => []),
      ]);
      if (playlistLoadSeqRef.current !== loadSeq || selectedPlaylistIdRef.current !== loadPlaylistId) return { detail, items, stale: true };
      const resolvedTrackCount = Number(itemMeta?.loaded_tracks || items.length || detail?.tracks_total || 0);
      setPlaylist(detail ? { ...detail, tracks_total: resolvedTrackCount } : detail);
      setAutoExpiryEnabled(!!detail?.auto_remove_enabled);
      setAutoWeeks(detail?.auto_remove_weeks ? String(detail.auto_remove_weeks) : "4");
      setTrackLimitEnabled(!!detail?.track_limit_enabled);
      setTrackLimitCount(detail?.track_limit_count ? String(detail.track_limit_count) : "");
      setTrackLimitStrategy(detail?.track_limit_strategy || "back");
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
      await Promise.all([loadBackups(), loadFlexHistory(), loadFutureAdds()]);
      return { detail, items };
    }).finally(() => {
      if (playlistLoadSeqRef.current === loadSeq && playlistId === loadPlaylistId) setPlaylistLoading(false);
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
    const rows = await api(`/api/backups/list?playlist_id=${encodeURIComponent(playlistId)}&limit=5`, { accessToken: accessToken() });
    setBackups(Array.isArray(rows) ? rows : []);
    return rows;
  }

  async function loadFutureAdds() {
    if (!playlistId) return [];
    const rows = await api(`/api/future-adds/list?playlist_id=${encodeURIComponent(playlistId)}`, { accessToken: accessToken() }).catch(() => []);
    setFutureAdds(Array.isArray(rows) ? rows : []);
    return rows;
  }

  async function createFutureAdd() {
    if (!playlistId || !futureAddForm.release_date || !futureAddForm.artist_name.trim() || !futureAddForm.track_title.trim()) return;
    await run("Future add saved", async () => {
      await api("/api/future-adds/create", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          playlist_id: playlistId,
          release_date: futureAddForm.release_date,
          artist_name: futureAddForm.artist_name,
          track_title: futureAddForm.track_title,
          position: futureAddForm.position,
        },
      });
      setFutureAddForm({ release_date: "", artist_name: "", track_title: "", position: "" });
      await loadFutureAdds();
    });
  }

  async function deleteFutureAdd(item) {
    if (!playlistId || !item?.id) return;
    await run("Future add removed", async () => {
      await api("/api/future-adds/delete", {
        method: "POST",
        accessToken: accessToken(),
        body: { playlist_id: playlistId, id: item.id },
      });
      await loadFutureAdds();
    });
  }

  function normalizePlaylistItems(items = []) {
    return [...(Array.isArray(items) ? items : [])]
      .filter((item) => Number.isFinite(Number(item?.position)))
      .sort((a, b) => Number(a.position) - Number(b.position));
  }

  function assertCompletePlaylistItems(items, meta, playlistLabel = "Playlist") {
    const expected = Number(meta?.expected_tracks || 0);
    const loaded = Array.isArray(items) ? items.length : 0;
    const partial = !!meta?.partial || (expected > 0 && loaded > 0 && loaded < Math.max(1, Math.floor(expected * 0.8)));
    if (partial) {
      throw new Error(`${playlistLabel} sync incomplete: loaded ${formatNumber(loaded)} of ${formatNumber(expected)} tracks. Please try again in a moment.`);
    }
  }

  async function fetchPlaylistItemsSafe(targetPlaylistId, { repair = true } = {}) {
    const qs = new URLSearchParams({ playlist_row_id: targetPlaylistId, meta: "1" });
    if (!repair) qs.set("repair", "0");
    const payload = await api(`/api/playlist-items/list?${qs.toString()}`, { accessToken: accessToken() });
    const items = normalizePlaylistItems(Array.isArray(payload) ? payload : (payload?.items || []));
    const meta = Array.isArray(payload) ? null : payload?.meta;
    assertCompletePlaylistItems(items, meta);
    return { items, meta };
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
        body: { playlist_id: playlistId },
      });
      await loadBackups();
      setMessage(`Kept ${formatNumber(result.kept)} backups, deleted ${formatNumber(result.deleted)}`);
      return result;
    });
  }

  async function reconcileTracksAndFlex({ repair = true } = {}) {
    const targetPlaylistId = selectedPlaylistIdRef.current || playlistId;
    if (!targetPlaylistId) return;
    const [{ items }, slots] = await Promise.all([
      fetchPlaylistItemsSafe(targetPlaylistId, { repair }),
      api(`/api/flex/slots/list?playlist_id=${encodeURIComponent(targetPlaylistId)}`, { accessToken: accessToken() }).catch(() => []),
    ]);
    if (selectedPlaylistIdRef.current !== targetPlaylistId) return;
    setTracks(items);
    setFlexSlots(Array.isArray(slots) ? slots : []);
  }

  function scheduleMoveReconcile(targetPlaylistId, delay = 1200) {
    if (moveReconcileTimerRef.current) clearTimeout(moveReconcileTimerRef.current);
    moveReconcileTimerRef.current = setTimeout(async () => {
      await moveQueueRef.current.catch(() => null);
      if (selectedPlaylistIdRef.current !== targetPlaylistId) return;
      try {
        await reconcileTracksAndFlex({ repair: false });
        setMessage("Playlist synced");
      } catch (e) {
        setError(e.message || String(e));
      }
    }, delay);
  }

  function enqueuePlaylistMove(body) {
    const targetPlaylistId = body.playlist_id;
    setPendingPlaylistEdits((count) => count + 1);
    setError("");
    setMessage("Saving playlist changes");

    const task = moveQueueRef.current
      .catch(() => null)
      .then(() => api("/api/playlist-items/move", {
        method: "POST",
        accessToken: accessToken(),
        body,
      }));
    moveQueueRef.current = task;
    task
      .then(() => scheduleMoveReconcile(targetPlaylistId))
      .catch(async (e) => {
        setError(e.message || String(e));
        if (selectedPlaylistIdRef.current === targetPlaylistId) {
          await reconcileTracksAndFlex({ repair: false }).catch(() => null);
        }
      })
      .finally(() => setPendingPlaylistEdits((count) => Math.max(0, count - 1)));
    return task;
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
    const targetPosition = Number(track.position) + (dir === "up" ? -1 : 1);
    if (ENABLE_FAST_PLAYLIST_MOVES) {
      setTracks((current) => reorderTracks(current, track, targetPosition));
      enqueuePlaylistMove({
        playlist_id: playlistId,
        track_id: track.track_id,
        from_position: track.position,
        dir,
        steps: 1,
      });
      return;
    }
    if (moveInFlightRef.current) return;
    moveInFlightRef.current = true;
    const previousTracks = tracks;
    if (ENABLE_OPTIMISTIC_PLAYLIST_UI) setTracks(reorderTracks(tracks, track, targetPosition));
    await run("Track move queued", async () => {
      await api("/api/playlist-items/move", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          playlist_id: playlistId,
          track_id: track.track_id,
          from_position: track.position,
          dir,
          steps: 1,
        },
      });
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
    }).then((result) => {
      if (result === null && ENABLE_OPTIMISTIC_PLAYLIST_UI) setTracks(previousTracks);
    }).finally(() => {
      moveInFlightRef.current = false;
    });
  }

  async function moveTrackTo(track, targetPosition) {
    const from = Number(track.position);
    const to = Math.max(0, Math.min(tracks.length - 1, Number(targetPosition)));
    if (!Number.isFinite(from) || !Number.isFinite(to) || from === to) return;
    if (ENABLE_FAST_PLAYLIST_MOVES) {
      setTracks((current) => reorderTracks(current, track, to));
      enqueuePlaylistMove({
        playlist_id: playlistId,
        track_id: track.track_id,
        from_position: track.position,
        dir: to < from ? "up" : "down",
        steps: Math.abs(to - from),
      });
      return;
    }
    if (moveInFlightRef.current) return;
    moveInFlightRef.current = true;
    const previousTracks = tracks;
    if (ENABLE_OPTIMISTIC_PLAYLIST_UI) setTracks(reorderTracks(tracks, track, to));
    await run("Track reordered", async () => {
      await api("/api/playlist-items/move", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          playlist_id: playlistId,
          track_id: track.track_id,
          from_position: track.position,
          dir: to < from ? "up" : "down",
          steps: Math.abs(to - from),
        },
      });
      await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
    }).then((result) => {
      if (result === null && ENABLE_OPTIMISTIC_PLAYLIST_UI) setTracks(previousTracks);
    }).finally(() => {
      moveInFlightRef.current = false;
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
      if (!ENABLE_FAST_PLAYLIST_MUTATIONS) {
        await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
      }
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
      if (!ENABLE_FAST_PLAYLIST_MUTATIONS) {
        await (ENABLE_OPTIMISTIC_PLAYLIST_UI ? reconcileTracksAndFlex() : loadSelectedPlaylist());
      }
    }).then((result) => {
      if (result === null && ENABLE_OPTIMISTIC_PLAYLIST_UI) setTracks(previousTracks);
    });
  }

  async function saveAutoRemoval() {
    await run("Cleanup rules saved", async () => {
      await api("/api/playlists/settings/save", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          playlist_id: playlistId,
          auto_remove_enabled: autoExpiryEnabled,
          auto_remove_weeks: autoExpiryEnabled ? Number(autoWeeks) : null,
          track_limit_enabled: trackLimitEnabled,
          track_limit_count: trackLimitEnabled && trackLimitCount !== "" ? Number(trackLimitCount) : null,
          track_limit_strategy: trackLimitStrategy,
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
      const now = new Date();
      const yearStart = new Date(now.getFullYear(), 0, 1);
      const customDays = customStart && !Number.isNaN(customStart.getTime())
        ? Math.max(1, Math.ceil((customEnd.getTime() - customStart.getTime()) / (24 * 3600 * 1000)))
        : null;
      const yearDays = Math.max(1, Math.ceil((now.getTime() - yearStart.getTime()) / (24 * 3600 * 1000)) + 1);
      const rangeDays = customDays || (dashboardRange === "year" ? yearDays : dashboardRange === "week" ? 7 : 30);
      const granularity = dashboardRange === "year" ? "monthly" : (dashboardGranularity || "daily");
      const seriesQs = new URLSearchParams({
        days: String(rangeDays),
        granularity,
        scope: "total",
      });
      const summaryQs = new URLSearchParams({
        days: String(rangeDays),
        removals_limit: "12",
      });
      if (dashboardRange === "year") {
        seriesQs.set("from", `${now.getFullYear()}-01-01`);
        seriesQs.set("to", now.toISOString().slice(0, 10));
        summaryQs.set("from", `${now.getFullYear()}-01-01`);
        summaryQs.set("to", now.toISOString().slice(0, 10));
      }
      if (dashboardRange === "custom") {
        if (dashboardStartDate) seriesQs.set("from", dashboardStartDate);
        if (dashboardEndDate) seriesQs.set("to", dashboardEndDate);
        if (dashboardStartDate) summaryQs.set("from", dashboardStartDate);
        if (dashboardEndDate) summaryQs.set("to", dashboardEndDate);
      }
      if (dashboardConnectionId) seriesQs.set("connection_id", dashboardConnectionId);
      if (dashboardPlaylistId) seriesQs.set("playlist_id", dashboardPlaylistId);
      if (dashboardConnectionId) summaryQs.set("connection_id", dashboardConnectionId);
      const [summary, series] = await Promise.all([
        api(`/api/dashboard/summary?${summaryQs.toString()}`, { accessToken: accessToken() }),
        api(`/api/dashboard/series?${seriesQs.toString()}`, { accessToken: accessToken() }),
      ]);
      setDashboardSummary(summary);
      setDashboardSeries(series);
      return { summary, series };
    });
  }

  async function loadAdPerformance() {
    if (!session?.access_token) return;
    return run("Ad performance loaded", async () => {
      const customStart = dashboardRange === "custom" && dashboardStartDate ? new Date(`${dashboardStartDate}T00:00:00`) : null;
      const customEnd = dashboardRange === "custom" && dashboardEndDate ? new Date(`${dashboardEndDate}T00:00:00`) : new Date();
      const now = new Date();
      const yearStart = new Date(now.getFullYear(), 0, 1);
      const customDays = customStart && !Number.isNaN(customStart.getTime())
        ? Math.max(1, Math.ceil((customEnd.getTime() - customStart.getTime()) / (24 * 3600 * 1000)))
        : null;
      const yearDays = Math.max(1, Math.ceil((now.getTime() - yearStart.getTime()) / (24 * 3600 * 1000)) + 1);
      const rangeDays = customDays || (dashboardRange === "year" ? yearDays : dashboardRange === "quarter" ? 90 : dashboardRange === "week" ? 7 : 30);
      const granularity = dashboardRange === "year" ? "monthly" : dashboardRange === "week" ? "daily" : (dashboardGranularity || "weekly");
      const qs = new URLSearchParams({ days: String(rangeDays), granularity });
      if (dashboardRange === "year") {
        qs.set("from", `${now.getFullYear()}-01-01`);
        qs.set("to", now.toISOString().slice(0, 10));
      }
      if (dashboardRange === "custom") {
        if (dashboardStartDate) qs.set("from", dashboardStartDate);
        if (dashboardEndDate) qs.set("to", dashboardEndDate);
      }
      if (dashboardConnectionId) qs.set("connection_id", dashboardConnectionId);
      const data = await api(`/api/dashboard/ad-performance?${qs.toString()}`, { accessToken: accessToken() });
      setAdPerformance(data);
      if (!adForm.playlist_id && data?.playlists?.[0]?.playlist_id) {
        setAdForm((current) => ({ ...current, playlist_id: data.playlists[0].playlist_id }));
      }
      return data;
    });
  }

  async function saveAdEvent() {
    if (!adForm.playlist_id) {
      setError("Choose a playlist first.");
      return;
    }
    await run("Ad event saved", async () => {
      await api("/api/dashboard/ad-events", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          playlist_id: adForm.playlist_id,
          event_date: adForm.event_date,
          daily_spend: adForm.daily_spend || 0,
          label: adForm.label,
          note: adForm.note,
          currency: "EUR",
        },
      });
      setAdForm((current) => ({ ...current, daily_spend: "", label: "", note: "" }));
      await loadAdPerformance();
    });
  }

  async function deleteAdEvent(id) {
    if (!id) return;
    await run("Ad event removed", async () => {
      await api(`/api/dashboard/ad-events?id=${encodeURIComponent(id)}`, {
        method: "DELETE",
        accessToken: accessToken(),
      });
      await loadAdPerformance();
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

  async function loadAdminStatus() {
    if (!session?.access_token || !isAdmin) return null;
    const data = await api("/api/admin/status", { accessToken: accessToken() }).catch((e) => {
      setError(e.message || "Admin status failed.");
      return null;
    });
    setAdminStatus(data);
    return data;
  }

  async function runAdminJobs() {
    if (!isAdmin) return;
    await run("Sync worker started", async () => {
      const result = await api("/api/admin/run-jobs", {
        method: "POST",
        accessToken: accessToken(),
        body: { limit: 10, max_ms: 45000 },
      });
      await loadAdminStatus();
      return result;
    });
  }

  async function loadMetaWorkspace() {
    if (!session?.access_token || !isAdmin) return null;
    const data = await api("/api/meta/connection", { accessToken: accessToken() }).catch((e) => {
      setError(e.message || "Meta Ads workspace failed.");
      return null;
    });
    if (data) {
      setMetaWorkspace(data);
      if (data.configured) setMetaForm((current) => ({
        ...current,
        app_id: data.app_id || current.app_id,
        business_id: data.business_id || current.business_id,
        graph_version: data.graph_version || current.graph_version,
        dsa_beneficiary: data.dsa_beneficiary || "",
        dsa_payor: data.dsa_payor || "",
        access_token: "",
        app_secret: "",
      }));
    }
    return data;
  }

  function openAdsSection(section = "overview") {
    setView("ads");
    setAdsSection(section);
    if (typeof window !== "undefined" && window.location.hash !== `#ads/${section}`) window.history.pushState(null, "", `#ads/${section}`);
  }

  async function saveMetaConnection() {
    await run("Meta connection saved", async () => {
      const data = await api("/api/meta/connection/save", {
        method: "POST",
        accessToken: accessToken(),
        body: metaForm,
      });
      setMetaWorkspace(data);
      setMetaForm((current) => ({ ...current, access_token: "", app_secret: "" }));
      return data;
    });
  }

  async function auditMetaConnection() {
    await run("Meta assets audited", async () => {
      const data = await api("/api/meta/connection/audit", { method: "POST", accessToken: accessToken(), body: {} });
      setMetaWorkspace(data);
      return data;
    });
  }

  async function selectMetaAsset(assetId) {
    await run("Default Meta asset selected", async () => {
      const data = await api("/api/meta/assets/select", {
        method: "POST",
        accessToken: accessToken(),
        body: { asset_id: assetId },
      });
      setMetaWorkspace(data);
      return data;
    });
  }

  async function loadMetaDrafts() {
    if (!session?.access_token || !isAdmin) return null;
    const data = await api("/api/meta/campaign-drafts", { accessToken: accessToken() }).catch((e) => {
      if (!String(e.message || "").includes("not_configured")) setError(e.message || "Meta drafts failed.");
      return null;
    });
    if (data) setMetaDrafts(data.drafts || []);
    return data;
  }

  async function loadCreativeProjects() {
    if (!session?.access_token || !isAdmin) return null;
    const data = await api("/api/meta/creative-projects", { accessToken: accessToken() }).catch((e) => {
      if (!String(e.message || "").includes("not_configured")) setError(e.message || "Creative projects failed.");
      return null;
    });
    if (data) setCreativeProjects(data.projects || []);
    return data;
  }

  function selectCreativePlaylist(selectedId) {
    const selected = playlists.find((item) => item.id === selectedId);
    setCreativeProjectForm((current) => ({
      ...current,
      playlist_id: selectedId,
      name: selected ? `${selected.name} — Creative exploration`.slice(0, 120) : current.name,
    }));
  }

  async function createCreativeProject() {
    await run("Creative project created", async () => {
      await api("/api/meta/creative-projects", {
        method: "POST",
        accessToken: accessToken(),
        body: creativeProjectForm,
      });
      setCreativeProjectForm({ playlist_id: "", name: "", language: "en", format: "9:16" });
      return loadCreativeProjects();
    });
  }

  async function generateCreativeProject(projectId) {
    setOpenCreativeProjectId(projectId);
    await run("Creative brief and concepts generated", async () => {
      await api("/api/meta/creative-projects/generate", {
        method: "POST",
        accessToken: accessToken(),
        body: { project_id: projectId },
      });
      return loadCreativeProjects();
    });
  }

  function setCreativeMediaQuery(conceptId, query) {
    setCreativeMediaSearches((current) => ({ ...current, [conceptId]: { ...(current[conceptId] || {}), query } }));
  }

  async function searchCreativeMedia(concept) {
    const fallback = concept.visual_search_terms?.[0] || concept.visual_direction || "people listening music";
    const query = creativeMediaSearches[concept.id]?.query || fallback;
    setCreativeMediaSearches((current) => ({ ...current, [concept.id]: { ...(current[concept.id] || {}), query, loading: true } }));
    try {
      const data = await api("/api/meta/creative-media/search", {
        method: "POST",
        accessToken: accessToken(),
        body: { concept_id: concept.id, query },
      });
      setCreativeMediaSearches((current) => ({ ...current, [concept.id]: { query: data.query, videos: data.videos || [], total: data.total_results || 0, loading: false } }));
    } catch (e) {
      setCreativeMediaSearches((current) => ({ ...current, [concept.id]: { ...(current[concept.id] || {}), loading: false } }));
      setError(e.message || "Pexels search failed.");
    }
  }

  async function recommendCreativeMedia(concept) {
    const fallback = concept.visual_search_terms?.[0] || concept.visual_direction || "people listening music";
    const query = creativeMediaSearches[concept.id]?.query || fallback;
    setCreativeMediaSearches((current) => ({ ...current, [concept.id]: { ...(current[concept.id] || {}), query, recommending: true } }));
    try {
      const data = await api("/api/meta/creative-media/recommend", {
        method: "POST",
        accessToken: accessToken(),
        body: { concept_id: concept.id, query },
      });
      setCreativeMediaSearches((current) => ({
        ...current,
        [concept.id]: { query, videos: data.recommendations || [], total: data.inspected || 0, recommending: false, aiRanked: true, queries: data.queries || [] },
      }));
    } catch (e) {
      setCreativeMediaSearches((current) => ({ ...current, [concept.id]: { ...(current[concept.id] || {}), recommending: false } }));
      setError(e.message || "AI video selection failed.");
    }
  }

  async function recommendProjectMedia(project) {
    const concepts = [...(project.meta_creative_concepts || [])].sort((a, b) => Number(a.position || 0) - Number(b.position || 0));
    if (!concepts.length) return;
    setError("");
    setMessage("");
    setCreativeProjectMediaRuns((current) => ({ ...current, [project.id]: { status: "running", completed: 0, total: concepts.length, results: {}, errors: [] } }));
    const results = {};
    const errors = [];
    const usedVideoIds = new Set();
    let cursor = 0;
    const worker = async () => {
      while (cursor < concepts.length) {
        const concept = concepts[cursor];
        cursor += 1;
        try {
          const query = concept.visual_search_terms?.[0] || concept.visual_direction || "people listening music";
          const data = await api("/api/meta/creative-media/recommend", {
            method: "POST",
            accessToken: accessToken(),
            body: { concept_id: concept.id, query },
          });
          const recommendations = data.recommendations || [];
          const selected = recommendations.find((video) => video.ai?.production_ready === true && Number(video.ai?.overall_score || 0) >= 80 && !usedVideoIds.has(video.id)) || null;
          if (selected) usedVideoIds.add(selected.id);
          results[concept.id] = { concept, recommendations, selected_id: selected?.id || "", inspected: data.inspected || 0, queries: data.queries || [] };
        } catch (error) {
          errors.push({ concept_id: concept.id, title: concept.title, message: error.message || "AI shortlist failed" });
        }
        setCreativeProjectMediaRuns((current) => ({ ...current, [project.id]: { status: "running", completed: Object.keys(results).length + errors.length, total: concepts.length, results: { ...results }, errors: [...errors] } }));
      }
    };
    await Promise.all([worker(), worker()]);
    setCreativeProjectMediaRuns((current) => ({ ...current, [project.id]: { status: errors.length === concepts.length ? "failed" : "review", completed: concepts.length, total: concepts.length, results: { ...results }, errors: [...errors] } }));
    setMessage(errors.length ? `AI media review finished with ${errors.length} failed concept${errors.length === 1 ? "" : "s"}.` : "AI media review ready");
  }

  function chooseProjectMedia(projectId, conceptId, videoId) {
    setCreativeProjectMediaRuns((current) => ({
      ...current,
      [projectId]: {
        ...current[projectId],
        results: { ...current[projectId]?.results, [conceptId]: { ...current[projectId]?.results?.[conceptId], selected_id: videoId } },
      },
    }));
  }

  async function assignProjectMedia(project) {
    const runState = creativeProjectMediaRuns[project.id];
    const selections = Object.values(runState?.results || {}).map((result) => ({
      concept: result.concept,
      video: result.recommendations.find((candidate) => candidate.id === result.selected_id),
      query: result.queries?.[0] || "",
    })).filter((item) => item.video);
    await run("Selected AI videos assigned", async () => {
      for (const { concept, video, query } of selections) {
        await api("/api/meta/creative-media/select", {
          method: "POST",
          accessToken: accessToken(),
          body: { concept_id: concept.id, provider_id: video.id, source_url: video.source_url, width: video.source_width, height: video.source_height, duration: video.duration, image: video.image, pexels_url: video.url, creator_name: video.user?.name, creator_url: video.user?.url, query, ai: video.ai || null },
        });
      }
      return loadCreativeProjects();
    });
  }

  async function selectCreativeMedia(concept, video) {
    await run("Video assigned to concept", async () => {
      await api("/api/meta/creative-media/select", {
        method: "POST",
        accessToken: accessToken(),
        body: {
          concept_id: concept.id,
          provider_id: video.id,
          source_url: video.source_url,
          width: video.source_width,
          height: video.source_height,
          duration: video.duration,
          image: video.image,
          pexels_url: video.url,
          creator_name: video.user?.name,
          creator_url: video.user?.url,
          query: creativeMediaSearches[concept.id]?.query || "",
          ai: video.ai || null,
        },
      });
      setCreativeMediaSearches((current) => ({ ...current, [concept.id]: { ...(current[concept.id] || {}), videos: [] } }));
      return loadCreativeProjects();
    });
  }

  function openCreativeEditor(concept, asset) {
    const saved = concept.render_spec?.editor || {};
    const recommendedTemplate = CREATIVE_RENDER_TEMPLATES.find((template) => template.id === asset.metadata?.ai_recommendation?.best_template) || CREATIVE_RENDER_TEMPLATES[0];
    const duration = Math.max(1, Number(asset.duration_seconds || 15));
    setCreativeEditorDrafts((current) => ({
      ...current,
      [concept.id]: {
        template_id: saved.template_id || recommendedTemplate.id,
        asset_id: saved.asset_id || asset.id,
        hook_text: saved.hook_text || concept.hook || "",
        cta_text: saved.cta_text || concept.cta || "Listen on Spotify",
        hook_position: saved.hook_position || recommendedTemplate.hook_position,
        text_align: saved.text_align || recommendedTemplate.text_align,
        text_color: saved.text_color || "#FFFFFF",
        accent_color: saved.accent_color || "#1ED760",
        overlay_color: saved.overlay_color || "#000000",
        overlay_opacity: saved.overlay_opacity ?? 0.28,
        trim_start: saved.trim_start ?? 0,
        trim_end: saved.trim_end ?? Math.min(duration, 15),
        hook_start: saved.hook_start ?? 0,
        hook_end: saved.hook_end ?? Math.min(duration, 4),
        show_cover: saved.show_cover !== false,
        cover_position: saved.cover_position || "bottom",
        show_cta: saved.show_cta !== false,
      },
    }));
    setOpenCreativeEditorId((current) => current === concept.id ? "" : concept.id);
  }

  function updateCreativeEditor(conceptId, patch) {
    setCreativeEditorDrafts((current) => ({ ...current, [conceptId]: { ...(current[conceptId] || {}), ...patch } }));
  }

  async function saveCreativeEditor(conceptId) {
    const draft = creativeEditorDrafts[conceptId];
    if (!draft) return;
    await run("Render specification saved", async () => {
      await api("/api/meta/creative-editor/save", {
        method: "POST",
        accessToken: accessToken(),
        body: { concept_id: conceptId, ...draft },
      });
      return loadCreativeProjects();
    });
  }

  async function pollCreativeRender(renderJobId) {
    for (let attempt = 0; attempt < 30; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 8000));
      try {
        const data = await api("/api/meta/creative-renders/sync", {
          method: "POST",
          accessToken: accessToken(),
          body: { render_job_id: renderJobId },
        });
        setCreativeRenderPolling((current) => ({ ...current, [renderJobId]: data.job?.status || data.provider_status || "processing" }));
        if (data.done) {
          await loadCreativeProjects();
          return data;
        }
      } catch (e) {
        setCreativeRenderPolling((current) => ({ ...current, [renderJobId]: "failed" }));
        setError(e.message || "Render status failed.");
        return null;
      }
    }
    setCreativeRenderPolling((current) => ({ ...current, [renderJobId]: "still processing" }));
    return null;
  }

  async function queueCreativeRender(conceptId) {
    const data = await run("Render job queued", () => api("/api/meta/creative-renders/queue", {
      method: "POST",
      accessToken: accessToken(),
      body: { concept_id: conceptId },
    }));
    if (data?.job?.id) {
      setCreativeRenderPolling((current) => ({ ...current, [data.job.id]: data.job.status || "processing" }));
      loadCreativeProjects();
      pollCreativeRender(data.job.id);
    }
  }

  async function syncCreativeRender(renderJobId) {
    await run("Render status refreshed", async () => {
      const data = await api("/api/meta/creative-renders/sync", { method: "POST", accessToken: accessToken(), body: { render_job_id: renderJobId } });
      await loadCreativeProjects();
      return data;
    });
  }

  function selectedBatchTemplates(projectId) {
    return creativeBatchTemplates[projectId] || ["bold_center"];
  }

  function toggleBatchTemplate(projectId, templateId) {
    setCreativeBatchTemplates((current) => {
      const selected = current[projectId] || ["bold_center"];
      const next = selected.includes(templateId) ? selected.filter((id) => id !== templateId) : [...selected, templateId];
      return { ...current, [projectId]: next };
    });
  }

  async function pollCreativeBatch(projectId, batchId, jobIds) {
    for (let attempt = 0; attempt < 60; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 5000));
      try {
        const data = await loadCreativeProjects();
        const project = (data?.projects || []).find((item) => item.id === projectId);
        const jobs = (project?.meta_creative_render_jobs || []).filter((job) => jobIds.includes(job.id));
        const completed = jobs.filter((job) => job.status === "completed").length;
        const failed = jobs.filter((job) => ["failed", "cancelled"].includes(job.status)).length;
        setCreativeBatchRuns((current) => ({ ...current, [projectId]: { batch_id: batchId, job_ids: jobIds, total: jobIds.length, completed, failed } }));
        if (completed + failed >= jobIds.length) return;
      } catch (e) {
        setError(e.message || "Batch render status failed.");
        return;
      }
    }
  }

  async function queueCreativeBatch(project) {
    const templateIds = selectedBatchTemplates(project.id);
    if (!templateIds.length) return;
    const data = await run("Batch render queued", () => api("/api/meta/creative-renders/batch", {
      method: "POST",
      accessToken: accessToken(),
      body: { project_id: project.id, template_ids: templateIds },
    }));
    const jobIds = (data?.jobs || []).map((job) => job.id);
    if (data?.batch_id && jobIds.length) {
      setCreativeBatchRuns((current) => ({ ...current, [project.id]: { batch_id: data.batch_id, job_ids: jobIds, total: jobIds.length, completed: 0, failed: 0 } }));
      loadCreativeProjects();
      pollCreativeBatch(project.id, data.batch_id, jobIds);
    }
  }

  async function saveMetaDraft() {
    await run("Campaign draft saved", async () => {
      await api("/api/meta/campaign-drafts", { method: "POST", accessToken: accessToken(), body: metaDraftForm });
      const result = await loadMetaDrafts();
      openAdsSection("campaigns");
      setAdsWizardStep(1);
      return result;
    });
  }

  function selectMetaCampaignPlaylist(selectedId) {
    const selected = playlists.find((item) => item.id === selectedId);
    setMetaDraftForm((current) => ({
      ...current,
      playlist_id: selectedId,
      name: selected ? `${selected.name} — Spotify traffic` : current.name,
      destination_url: selected?.playlist_id ? `https://open.spotify.com/playlist/${selected.playlist_id}` : current.destination_url,
      image_url: selected?.image || current.image_url,
      headline: selected ? `Discover ${selected.name}`.slice(0, 255) : current.headline,
    }));
  }

  async function uploadMetaCreative(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (!["image/jpeg", "image/png", "image/webp"].includes(file.type)) {
      setError("Choose a JPEG, PNG, or WebP image.");
      return;
    }
    if (file.size > 3 * 1024 * 1024) {
      setError("Creative images must be 3 MB or smaller.");
      return;
    }
    await run("Creative uploaded", async () => {
      const dataUrl = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result || ""));
        reader.onerror = () => reject(new Error("creative_file_read_failed"));
        reader.readAsDataURL(file);
      });
      const data = await api("/api/meta/creative-upload", {
        method: "POST",
        accessToken: accessToken(),
        body: { content_type: file.type, data_base64: dataUrl.split(",")[1] || "" },
      });
      setMetaDraftForm((current) => ({ ...current, image_url: data.url }));
      return data;
    });
  }

  async function reviewMetaDraft(draftId) {
    await run("Campaign draft approved for paused creation", async () => {
      await api("/api/meta/campaign-drafts/review", { method: "POST", accessToken: accessToken(), body: { draft_id: draftId } });
      return loadMetaDrafts();
    });
  }

  async function createPausedMetaCampaign(draftId) {
    await run("Paused Meta campaign package created", async () => {
      try {
        await api("/api/meta/campaign-drafts/create-paused", {
          method: "POST",
          accessToken: accessToken(),
          body: { draft_id: draftId, confirmation: "CREATE PAUSED" },
        });
      } finally {
        await loadMetaDrafts();
      }
      return null;
    });
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
        <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png" />
        <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
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
              {isAdmin ? <button className={view === "ads" ? "navButton active" : "navButton"} onClick={() => openAdsSection("overview")}>Ads Manager</button> : null}
              {isAdmin ? <button className={view === "admin" ? "navButton active" : "navButton"} onClick={() => setView("admin")}>Admin</button> : null}
            </div>
          ) : null}
          {session && userContext?.linked && billingActive ? (
            <button className="settingsButton topSettingsButton" onClick={() => setSettingsOpen(true)} aria-label="Open settings">
              <Settings aria-hidden="true" />
            </button>
          ) : null}
        </nav>
      </header>
      {showSetupProgress ? (
        <section className="setupProgress" aria-label="PlaylistPilot setup progress">
          <div className="setupProgressHeader">
            <div>
              <span>Workspace setup</span>
              <strong>{onboardingStep === 2 ? "Add your Spotify API app" : onboardingStep === 3 ? "Connect a Spotify account" : "Import your playlists"}</strong>
            </div>
            <small>{Math.max(1, onboardingStep - 1)} of 4 complete</small>
          </div>
          <div className="setupProgressTrack" aria-hidden="true"><span style={{ width: `${Math.max(0, onboardingStep - 1) * 25}%` }} /></div>
          <ol className="setupProgressSteps">
            {[
              [1, "Plan", onboardingBillingReady],
              [2, "API credentials", onboardingCredentialsReady],
              [3, "Spotify account", onboardingConnectionsReady],
              [4, "Playlist import", onboardingPlaylistsReady],
            ].map(([step, label, done]) => (
              <li key={step} className={done ? "done" : onboardingStep === step ? "active" : ""}>
                <b>{done ? "✓" : step}</b><span>{label}</span>
              </li>
            ))}
          </ol>
          <button disabled={busy || (onboardingStep === 4 && !connectionId)} onClick={openCurrentSetupStep}>
            {onboardingStep === 2 ? "Open API settings" : onboardingStep === 3 ? "Open account setup" : "Import playlists"}
          </button>
        </section>
      ) : null}
      {spotifySetupAlert ? (
        <section className="spotifySetupAlert" role="alert" aria-live="assertive">
          <div>
            <strong>Spotify account needs one more setup step</strong>
            <p>{spotifySetupAlert}</p>
            <small>After adding the account under Users and Access, save the Spotify app and try Connect Spotify again.</small>
          </div>
          <button className="iconOnlyButton" onClick={() => setSpotifySetupAlert("")} aria-label="Dismiss Spotify setup message">
            <X aria-hidden="true" />
          </button>
        </section>
      ) : null}
      {busy ? (
        <div className="operationToast" role="status" aria-live="polite">
          <span className="miniSpinner" aria-hidden="true" />
          <strong>{busyLabel || "Working with Spotify"}</strong>
        </div>
      ) : null}
      {passwordRecoveryOpen ? (
        <div className="onboardingOverlay" role="dialog" aria-modal="true" aria-label="Set a new password">
          <form className="passwordRecoveryPanel" onSubmit={saveRecoveryPassword}>
            <span>Account security</span>
            <h2>Set a new password</h2>
            <p>Choose a new password with at least 10 characters for your PlaylistPilot account.</p>
            <input type="password" autoComplete="new-password" minLength={10} value={recoveryPassword} onChange={(event) => setRecoveryPassword(event.target.value)} placeholder="New password" required autoFocus />
            {error ? <div className="authError" role="alert">{error}</div> : null}
            <button type="submit" disabled={authSubmitting}>{authSubmitting ? "Saving..." : "Save new password"}</button>
          </form>
        </div>
      ) : null}

      {!session ? (
        <section className="loginScreen">
          <div className="loginCard">
            <div className="loginBrand">
              <img src="/playlistpilot-logo-v1.jpg" alt="" />
              <span>PlaylistPilot</span>
            </div>
            <div className="loginCopy">
              <span>Login & Signup</span>
              <h2>Manage Spotify playlists with less manual work.</h2>
              <p>Sign in or create an account, then connect Spotify and start managing your playlists.</p>
            </div>
            <div className="authModeTabs" role="tablist" aria-label="Email authentication mode">
              <button type="button" className={authMode === "login" ? "active" : ""} onClick={() => { setAuthMode("login"); setError(""); setAuthNotice(""); }}>Log in</button>
              <button type="button" className={authMode === "signup" ? "active" : ""} onClick={() => { setAuthMode("signup"); setError(""); setAuthNotice(""); }}>Create account</button>
            </div>
            <form className="emailAuthForm" onSubmit={submitEmailAuth}>
              <label>
                <span>Email</span>
                <input type="email" autoComplete="email" value={authEmail} onChange={(event) => setAuthEmail(event.target.value)} placeholder="you@example.com" required />
              </label>
              {authMode !== "reset" ? (
                <label>
                  <span>Password</span>
                  <input type="password" autoComplete={authMode === "signup" ? "new-password" : "current-password"} minLength={10} value={authPassword} onChange={(event) => setAuthPassword(event.target.value)} placeholder="At least 10 characters" required />
                </label>
              ) : null}
              {process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY ? (
                <div className="turnstileWrap">
                  <Turnstile
                    key={authCaptchaKey}
                    siteKey={process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY}
                    options={{ theme: "dark", size: "flexible" }}
                    onSuccess={setAuthCaptchaToken}
                    onExpire={() => setAuthCaptchaToken("")}
                    onError={() => setAuthCaptchaToken("")}
                  />
                </div>
              ) : (
                <small className="authUnavailable">Protected email signup is being configured. Use Google in the meantime.</small>
              )}
              {authNotice ? <div className="authNotice" role="status">{authNotice}</div> : null}
              {error ? <div className="authError" role="alert">{error}</div> : null}
              <div className="emailAuthActions">
                <button type="submit" disabled={!supabase || authSubmitting || !process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY}>
                  {authSubmitting ? "Please wait..." : authMode === "signup" ? "Create account" : authMode === "reset" ? "Send reset link" : "Log in"}
                </button>
                {authMode === "login" ? <button type="button" className="textButton" onClick={() => { setAuthMode("reset"); setError(""); setAuthNotice(""); }}>Forgot password?</button> : null}
                {authMode === "reset" ? <button type="button" className="textButton" onClick={() => { setAuthMode("login"); setError(""); setAuthNotice(""); }}>Back to login</button> : null}
              </div>
            </form>
            <div className="authDivider"><span>or</span></div>
            <button className="googleLoginButton" onClick={signInWithGoogle} disabled={!supabase}>
              <span>G</span>Continue with Google
            </button>
            <div className="loginMetaGrid">
              <article><strong>Multi-account</strong><small>Connect and switch Spotify accounts.</small></article>
              <article><strong>Automation</strong><small>Locks, rotators, expiry and backups.</small></article>
              <article><strong>Analytics</strong><small>Follower trends and ad performance.</small></article>
            </div>
          </div>
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
            <div className="premiumRequirement">
              <strong>Spotify Premium required</strong>
              <p>PlaylistPilot can only connect and manage Spotify Premium accounts because Spotify restricts the required Web API access to Premium users.</p>
            </div>
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
                  <div className="premiumRequirement">
                    <strong>Spotify Premium required</strong>
                    <p>The Spotify accounts you connect must have Premium access for PlaylistPilot's playlist management API features.</p>
                  </div>
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

            <section ref={spotifyAccountsSectionRef} className={`settingsSection ${onboardingStep === 3 ? "settingsSection--setupActive" : ""}`}>
              <div className="settingsSectionHeader">
                <div>
                  <h3>Spotify Accounts</h3>
                  <p>Connect the Spotify accounts you want to manage in Playlist Pilot.</p>
                </div>
                <div className="settingsHeaderActions">
                  <button className="secondaryOutline" disabled={busy} onClick={() => loadConnections()}>Refresh accounts</button>
                  <button
                    disabled={busy || (!spotifyCredentials?.configured && !spotifyCredentials?.fallback_available)}
                    onClick={startSpotifyConnect}
                  >
                    Connect Spotify
                  </button>
                </div>
              </div>
              <div className="setupNotice settingsSpotifyNotice">
                <strong>Before you connect</strong>
                <p>Add the Spotify account's name and email under <b>Users and Access</b> in your Spotify Developer app, then press Save. Spotify returns a 403 if this step is missing.</p>
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

            <section ref={spotifyApiSectionRef} className={`settingsSection ${onboardingStep === 2 ? "settingsSection--setupActive" : ""}`}>
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

      {!workspaceBootstrapped ? (
        <section className="loadingScreen" aria-live="polite">
          <div className="loaderMark">
            <img src="/playlistpilot-logo-v1.jpg" alt="" />
            <span />
          </div>
          <h2>Loading workspace</h2>
          <p>Syncing your accounts, playlists, and saved position.</p>
          {error ? <strong>{error}</strong> : null}
        </section>
      ) : !onboardingConnectionsReady ? (
        <section className="setupHold" aria-live="polite">
          <span>Setup required</span>
          <h2>Connect your first Spotify account</h2>
          <p>The Playlist Manager opens after Spotify API credentials are saved and an account is authorized. Your setup progress stays visible above until the workspace is ready.</p>
          <button disabled={busy} onClick={openCurrentSetupStep}>Continue setup</button>
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
              <option value="quarter">3 months</option>
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
        <div className="dashboardSubnav" aria-label="Dashboard sections">
          <button className={dashboardTab === "stats" ? "active" : ""} onClick={() => setDashboardTab("stats")}>Stats</button>
          <button className={dashboardTab === "ad" ? "active" : ""} onClick={() => setDashboardTab("ad")}>Ad Performance</button>
        </div>
        {dashboardTab === "stats" ? (
        <>
        <div className="metricGrid metricGrid--primary">
          <article>
            <span className="metricLabel">Total Followers</span>
            <strong className="metricValue">{formatNumber(dashboardSummary?.totals?.total_followers)}</strong>
            <small className="metricMeta">{dashboardConnectionId ? "selected account" : "active portfolio"}</small>
          </article>
          <article>
            <span className="metricLabel">Portfolio Growth</span>
            <strong className="metricValue">{growthReady ? formatNumber(dashboardSummary?.totals?.net_growth_last_days) : "Warming up"}</strong>
            <small className="metricMeta">{growthReady ? `${formatNumber(dashboardSummary?.totals?.growth_snapshot_days)} snapshot days` : "needs 2+ days"}</small>
          </article>
          <article>
            <span className="metricLabel">Tracked Playlists</span>
            <strong className="metricValue">{formatNumber(dashboardSummary?.totals?.playlists_count)}</strong>
            <small className="metricMeta">owned public lists</small>
          </article>
          <article>
            <span className="metricLabel">Actions Soon</span>
            <strong className="metricValue">{formatNumber((dashboardSummary?.upcoming_removals?.length || 0) + (dashboardSummary?.totals?.flex_due_count || 0))}</strong>
            <small className="metricMeta">{formatNumber(dashboardSummary?.upcoming_removals?.length)} removals · {formatNumber(dashboardSummary?.totals?.flex_due_count)} rotations</small>
          </article>
        </div>
        <div className="dashboardFocusGrid">
          <section className="dashboardPanel growthPanel">
            <div className="panelHeader">
              <div>
                <h2>Growth Trend</h2>
                <p>{dashboardPlaylistId ? "Follower development for the selected playlist" : "Follower development for the selected portfolio scope"}</p>
              </div>
              <div className="chartFilters">
                <div className="modeToggle" aria-label="Growth display mode">
                  <button className={dashboardGrowthMode === "followers" ? "active" : ""} onClick={() => setDashboardGrowthMode("followers")}>Followers</button>
                  <button className={dashboardGrowthMode === "growth" ? "active" : ""} onClick={() => setDashboardGrowthMode("growth")}>Growth</button>
                  <button className={dashboardGrowthMode === "cumulative" ? "active" : ""} onClick={() => setDashboardGrowthMode("cumulative")}>Cumulative</button>
                </div>
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
                  {dashboardPlaylistOptions.map((p) => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
              </div>
            </div>
            {growthReady ? (
              <>
                <div className="chartStats">
                  <article><span>Tracked</span><strong>{formatNumber(growthQuality.tracked_playlists || dashboardSeries?.eligible_playlists || 0)}</strong></article>
                  <article><span>Warming up</span><strong>{formatNumber(growthQuality.limited_playlists || 0)}</strong></article>
                  <article><span>No data yet</span><strong>{formatNumber(growthQuality.missing_playlists || 0)}</strong></article>
                </div>
                <GrowthChart
                  values={dashboardChartData.values}
                  labels={dashboardSeries?.labels || []}
                  growth={dashboardChartData.growth}
                  granularity={dashboardSeries?.granularity || dashboardGranularity}
                  valueLabel={dashboardChartData.label}
                />
                <div className="sparkLabels chartAxis">
                  <span>{dashboardSeries?.labels?.[0] ? formatShortDate(dashboardSeries.labels[0]) : ""}</span>
                  <strong>{formatDelta((dashboardSeries?.growth || []).reduce((sum, value) => sum + (Number(value) || 0), 0))}</strong>
                  <span>{dashboardSeries?.labels?.at?.(-1) ? formatShortDate(dashboardSeries.labels.at(-1)) : ""}</span>
                </div>
                <p className="chartCoverageNote">{growthQuality.note || "Trend uses playlists with enough snapshots in this range."}</p>
              </>
            ) : (
              <DashboardWarmup summary={dashboardSummary} series={dashboardSeries} onRefresh={refreshDashboardBaseline} busy={busy} />
            )}
            {selectedDashboardPlaylist ? (
              <aside className="playlistDetailDrawer">
                <div>
                  <Artwork src={selectedDashboardPlaylist.image} alt="" size="sm" />
                  <span>
                    <strong>{selectedDashboardPlaylist.name || "Untitled playlist"}</strong>
                    <small>{formatNumber(selectedDashboardPlaylist.followers_now ?? selectedDashboardPlaylist.followers)} followers · {formatNumber(selectedDashboardPlaylist.tracks_total)} tracks</small>
                  </span>
                </div>
                <section>
                  <article><span>Growth</span><strong>{selectedDashboardPlaylist.has_growth_data ? formatDelta(selectedDashboardPlaylist.delta) : "warming"}</strong></article>
                  <article><span>Relative</span><strong>{formatPercent(selectedDashboardPlaylist.percent_delta)}</strong></article>
                  <article><span>Locked</span><strong>{formatNumber(selectedDashboardPlaylist.locked_count || 0)}</strong></article>
                  <article><span>Rotator</span><strong>{formatNumber(selectedDashboardPlaylist.rotator_count || 0)}</strong></article>
                </section>
                <button onClick={() => {
                  setPlaylistId(dashboardPlaylistId);
                  setView("manager");
                }}>Open in Manager</button>
              </aside>
            ) : null}
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
        <div className="performanceHeroRow">
          <button
            className="performanceHeroCard"
            disabled={!performanceHighlights.bestMonth?.playlist_id}
            onClick={() => performanceHighlights.bestMonth?.playlist_id && setDashboardPlaylistId(performanceHighlights.bestMonth.playlist_id)}
          >
            <span>Best Performer This Month</span>
            <strong>{performanceHighlights.bestMonth?.name || "Warming up"}</strong>
            <small>{performanceHighlights.bestMonth ? `${formatDelta(performanceHighlights.bestMonth.delta)} · ${formatPercent(performanceHighlights.bestMonth.percent_delta)}` : "Needs more snapshots"}</small>
          </button>
          <button
            className="performanceHeroCard performanceHeroCard--quiet"
            disabled={!performanceHighlights.bestToday?.playlist_id}
            onClick={() => performanceHighlights.bestToday?.playlist_id && setDashboardPlaylistId(performanceHighlights.bestToday.playlist_id)}
          >
            <span>Best Performer Today</span>
            <strong>{performanceHighlights.bestToday?.name || "No trend yet"}</strong>
            <small>{performanceHighlights.bestToday ? `${formatDelta(performanceHighlights.bestToday.today_delta)} · ${formatPercent(performanceHighlights.bestToday.today_percent_delta)}` : "Needs yesterday and today"}</small>
          </button>
          <button
            className="performanceHeroCard performanceHeroCard--warning"
            disabled={!performanceHighlights.needsAttention?.playlist_id}
            onClick={() => performanceHighlights.needsAttention?.playlist_id && setDashboardPlaylistId(performanceHighlights.needsAttention.playlist_id)}
          >
            <span>Needs Attention</span>
            <strong>{performanceHighlights.needsAttention?.name || "No decline detected"}</strong>
            <small>{performanceHighlights.needsAttention ? `${formatDelta(performanceHighlights.needsAttention.today_delta)} today · was growing before` : "No growing playlist is shrinking today"}</small>
          </button>
          <button
            className="performanceHeroCard performanceHeroCard--neutral"
            disabled={!performanceHighlights.worstMonth?.playlist_id}
            onClick={() => performanceHighlights.worstMonth?.playlist_id && setDashboardPlaylistId(performanceHighlights.worstMonth.playlist_id)}
          >
            <span>Worst Performer</span>
            <strong>{performanceHighlights.worstMonth?.name || "No trend yet"}</strong>
            <small>{performanceHighlights.worstMonth ? `${formatDelta(performanceHighlights.worstMonth.delta)} · ${formatPercent(performanceHighlights.worstMonth.percent_delta)}` : "Needs more snapshots"}</small>
          </button>
        </div>
        <section className="dashboardPanel topPlaylistsPanel portfolioPanel">
            <div>
              <h2>Playlist Portfolio</h2>
              <p>All active playlists in the current account scope, sorted by followers</p>
            </div>
            <div className="playlistTable">
              <div className="playlistTableHeader" aria-hidden="true">
                <span>Playlist</span>
                <span>Followers</span>
                <span>Growth</span>
                <span>Tracks</span>
                <span>Locked</span>
                <span>Rotator</span>
                <span>Expiry</span>
              </div>
              {visiblePortfolioItems.map((item) => (
                <div key={item.playlist_id}>
                  <Artwork src={item.image} alt="" size="sm" />
                  <strong>{item.name || "Untitled playlist"}</strong>
                  <span>{formatNumber(item.followers)}</span>
                  <span>{item.has_growth_data ? formatDelta(item.delta) : "warming"}</span>
                  <span>{formatNumber(item.tracks_total)}</span>
                  <span>{formatNumber(item.locked_count || 0)}</span>
                  <span>{formatNumber(item.rotator_count || 0)}</span>
                  <b>{item.auto_remove_enabled ? `${item.auto_remove_weeks || "?"}w` : "manual"}</b>
                </div>
              ))}
              {!dashboardSummary?.top_playlists?.length ? <p>No playlists yet.</p> : null}
            </div>
            {portfolioItems.length > portfolioPageSize ? (
              <div className="moversPager portfolioPager">
                <button disabled={safePortfolioPage === 0} onClick={() => setPortfolioPage((page) => Math.max(0, page - 1))}>Prev</button>
                <span>{safePortfolioPage + 1} / {portfolioPageCount}</span>
                <button disabled={safePortfolioPage >= portfolioPageCount - 1} onClick={() => setPortfolioPage((page) => Math.min(portfolioPageCount - 1, page + 1))}>Next</button>
              </div>
            ) : null}
          </section>
        <div className="dashboardSplitGrid">
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
                    <small>
                      {item.playlist_name || "Playlist"} · {formatShortDate(item.removes_on)}
                      {Number.isFinite(Number(item.position)) ? ` · pos ${Number(item.position) + 1}` : ""}
                    </small>
                  </span>
                </div>
              ))}
              {!dashboardSummary?.upcoming_removals?.length ? <p>No upcoming removals.</p> : null}
            </div>
          </section>
          <section className="dashboardPanel rotationsPanel">
            <div>
              <h2>Upcoming Track Rotations</h2>
              <p>Rotator slots scheduled in the next 14 days</p>
            </div>
            <div className="removalList rotationList">
              {(dashboardSummary?.upcoming_rotations || []).map((item, index) => (
                <div key={`${item.slot_id || index}-${item.current_track_id || index}`}>
                  <Artwork src={item.cover_url || item.playlist_image} alt="" size="sm" />
                  <span>
                    <strong>{item.track_name || "Rotation slot"}</strong>
                    <em>{item.artist_names || item.source_playlist_name || "Reference playlist"}</em>
                    <small>
                      {item.playlist_name || "Playlist"} · {formatShortDate(String(item.next_rotation_at || "").slice(0, 10))}
                      {Number.isFinite(Number(item.position)) ? ` · pos ${Number(item.position) + 1}` : ""}
                      {item.interval ? ` · ${item.interval}` : ""}
                    </small>
                  </span>
                </div>
              ))}
              {!dashboardSummary?.upcoming_rotations?.length ? <p>No upcoming rotations.</p> : null}
            </div>
          </section>
        </div>
        </>
        ) : (
        <section className="adPerformanceView">
          <div className="metricGrid metricGrid--primary">
            <article>
              <span className="metricLabel">Daily Ad Spend</span>
              <strong className="metricValue">EUR {formatNumber(adPerformance?.totals?.current_daily_spend || 0)}</strong>
              <small className="metricMeta">{formatNumber(adPerformance?.totals?.paid_playlists || 0)} active paid playlists</small>
            </article>
            <article>
              <span className="metricLabel">Monthly Run Rate</span>
              <strong className="metricValue">EUR {formatNumber(adPerformance?.totals?.monthly_run_rate || 0)}</strong>
              <small className="metricMeta">based on current daily spend</small>
            </article>
            <article>
              <span className="metricLabel">Spend In Range</span>
              <strong className="metricValue">EUR {formatNumber(adPerformance?.totals?.period_spend || 0)}</strong>
              <small className="metricMeta">{formatDelta(adPerformance?.totals?.total_growth || 0)} followers tracked</small>
            </article>
            <article>
              <span className="metricLabel">Blended CPF</span>
              <strong className="metricValue">{Number.isFinite(Number(adPerformance?.totals?.blended_cost_per_follower)) ? `EUR ${formatNumber(adPerformance.totals.blended_cost_per_follower)}` : "n/a"}</strong>
              <small className="metricMeta">cost per follower in range</small>
            </article>
          </div>
          <div className="performanceHeroRow adInsightHeroRow">
            <article className="performanceHeroCard">
              <span>Most Efficient</span>
              <strong>{adPerformance?.best_efficiency?.name || "No paid growth yet"}</strong>
              <small>{adPerformance?.best_efficiency ? `EUR ${formatNumber(adPerformance.best_efficiency.cost_per_follower)} per follower` : "Add spend markers and wait for growth snapshots"}</small>
            </article>
            <article className="performanceHeroCard performanceHeroCard--quiet">
              <span>Highest Spend</span>
              <strong>{(adPerformance?.playlists || []).slice().sort((a, b) => Number(b.period_spend || 0) - Number(a.period_spend || 0))[0]?.name || "No spend yet"}</strong>
              <small>EUR {formatNumber((adPerformance?.playlists || []).slice().sort((a, b) => Number(b.period_spend || 0) - Number(a.period_spend || 0))[0]?.period_spend || 0)} in range</small>
            </article>
            <article className="performanceHeroCard performanceHeroCard--warning">
              <span>Needs Review</span>
              <strong>{(adPerformance?.playlists || []).filter((item) => Number(item.period_spend || 0) > 0).slice().sort((a, b) => Number(a.delta || 0) - Number(b.delta || 0))[0]?.name || "No risk detected"}</strong>
              <small>{(() => { const item = (adPerformance?.playlists || []).filter((entry) => Number(entry.period_spend || 0) > 0).slice().sort((a, b) => Number(a.delta || 0) - Number(b.delta || 0))[0]; return item ? `${formatDelta(item.delta)} growth · EUR ${formatNumber(item.period_spend)} spend` : "No paid playlist is underperforming"; })()}</small>
            </article>
            <article className="performanceHeroCard performanceHeroCard--neutral">
              <span>Campaign Markers</span>
              <strong>{formatNumber(adPerformance?.totals?.event_count || 0)}</strong>
              <small>budget changes and notes in this range</small>
            </article>
          </div>
          <div className="adControlGrid adControlGrid--single">
            <section className="dashboardPanel adEventPanel">
              <div>
                <h2>Pin spend or note</h2>
                <p>Set a daily spend from a specific date, or add a campaign note such as new creatives, budget change, or audience test.</p>
              </div>
              <div className="adEventForm">
                <select value={adForm.playlist_id} onChange={(e) => setAdForm((current) => ({ ...current, playlist_id: e.target.value }))}>
                  <option value="">Choose playlist</option>
                  {(adPerformance?.playlists || dashboardSummary?.top_playlists || []).map((item) => (
                    <option key={item.playlist_id} value={item.playlist_id}>{item.name}</option>
                  ))}
                </select>
                <input type="date" value={adForm.event_date} onChange={(e) => setAdForm((current) => ({ ...current, event_date: e.target.value }))} />
                <input type="number" min="0" step="0.01" value={adForm.daily_spend} onChange={(e) => setAdForm((current) => ({ ...current, daily_spend: e.target.value }))} placeholder="Daily spend EUR" />
                <input value={adForm.label} onChange={(e) => setAdForm((current) => ({ ...current, label: e.target.value }))} placeholder="Marker label" />
                <textarea value={adForm.note} onChange={(e) => setAdForm((current) => ({ ...current, note: e.target.value }))} placeholder="Optional note" />
                <button disabled={busy || !adForm.playlist_id || !adForm.event_date} onClick={saveAdEvent}>Save marker</button>
              </div>
            </section>
          </div>
          <div className="adPlaylistSectionHeader">
            <div>
              <h2>Playlist ad performance</h2>
              <p>Follower trend with pinned spend changes and campaign notes.</p>
            </div>
            <div className="modeToggle">
              <button className={adPlaylistView === "chart" ? "active" : ""} onClick={() => setAdPlaylistView("chart")}>Charts</button>
              <button className={adPlaylistView === "info" ? "active" : ""} onClick={() => setAdPlaylistView("info")}>Info</button>
            </div>
            {adPlaylistView === "chart" ? (
              <div className="modeToggle adMobileChartToggle" aria-label="Mobile chart mode">
                <button className={adMobileChartMode === "delta" ? "active" : ""} onClick={() => setAdMobileChartMode("delta")}>Delta</button>
                <button className={adMobileChartMode === "growth" ? "active" : ""} onClick={() => setAdMobileChartMode("growth")}>Growth</button>
              </div>
            ) : null}
          </div>
          <div className="adPlaylistGrid">
            {(adPerformance?.playlists || []).map((item) => (
              <article className="adPlaylistCard" key={item.playlist_id}>
                <div className="adPlaylistHeader">
                  <Artwork src={item.image} alt="" size="sm" />
                  <span>
                    <strong>{item.name || "Untitled playlist"}</strong>
                    <small>{formatNumber(item.followers_now)} followers · {formatDelta(item.delta)} range growth</small>
                  </span>
                </div>
                {adPlaylistView === "chart" ? (
                  <>
                    <div className={`adDualChartGrid adDualChartGrid--mobile-${adMobileChartMode}`}>
                      <section>
                        <span>Follower Delta</span>
                        <AdPlaylistChart playlist={item} />
                      </section>
                      <section>
                        <span>Follower Trend</span>
                        <AdPlaylistFollowerChart playlist={item} />
                      </section>
                    </div>
                    <div className="adPlaylistStats">
                      <span>Daily EUR {formatNumber(item.current_daily_spend || 0)}</span>
                      <span>Range EUR {formatNumber(item.period_spend || 0)}</span>
                      <span>{Number.isFinite(Number(item.cost_per_follower)) ? `CPF EUR ${formatNumber(item.cost_per_follower)}` : "CPF n/a"}</span>
                    </div>
                  </>
                ) : (
                  <>
                    <div className="adPlaylistStats adPlaylistStats--details">
                      <span>Daily EUR {formatNumber(item.current_daily_spend || 0)}</span>
                      <span>Range EUR {formatNumber(item.period_spend || 0)}</span>
                      <span>{Number.isFinite(Number(item.cost_per_follower)) ? `CPF EUR ${formatNumber(item.cost_per_follower)}` : "CPF n/a"}</span>
                      <span>Run rate EUR {formatNumber(item.monthly_run_rate || 0)}</span>
                      <span>{formatNumber(item.events?.length || 0)} markers</span>
                      <span>{item.has_notes ? "Notes active" : "No notes"}</span>
                    </div>
                    <div className="adEventList">
                      {(item.events || []).slice(-5).reverse().map((event) => (
                        <div key={event.id}>
                          <span>{formatShortDate(event.event_date)} · EUR {formatNumber(event.daily_spend || 0)}</span>
                          <strong>{event.label || event.note || "Spend marker"}</strong>
                          <button disabled={busy} onClick={() => deleteAdEvent(event.id)}>Remove</button>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </article>
            ))}
            {!adPerformance?.playlists?.length ? (
              <section className="dashboardPanel adEmptyState">
                <h2>No ad performance data yet</h2>
                <p>Add your first spend marker above. PlaylistPilot will overlay it onto the existing follower snapshots as new data arrives.</p>
              </section>
            ) : null}
          </div>
        </section>
        )}
      </section>
      ) : view === "ads" && isAdmin ? (
      <section className="adminPanel metaAdsPanel">
        <div className="statusLine">
          {busy ? <span><i className="miniSpinner" aria-hidden="true" />{busyLabel || "Working"}</span> : message ? <span>{message}</span> : <span />}
          {error ? <strong>{error}</strong> : null}
        </div>
        <div className="dashboardHero">
          <div>
            <div className="metaTitleLine">
              <h2>Meta Ads Manager</h2>
              <span className="adminBadge">Admin preview</span>
              <span className="metaReadOnlyBadge">Draft mode</span>
            </div>
            <p>Connect and audit your Meta business assets before campaign publishing is enabled.</p>
          </div>
          <div className="dashboardActions">
            <button disabled={busy} onClick={loadMetaWorkspace}>Refresh</button>
            <button disabled={busy || !metaWorkspace?.configured} onClick={auditMetaConnection}>Audit connection</button>
          </div>
        </div>

        <nav className="adsWorkspaceNav" aria-label="Ads Manager sections">
          {[{ id: "overview", label: "Overview" }, { id: "campaigns", label: "Campaigns" }, { id: "creatives", label: "Creative Studio" }, { id: "library", label: "Creative Library" }, { id: "new", label: "New campaign" }, { id: "settings", label: "Settings" }].map((item) => (
            <button key={item.id} className={adsSection === item.id ? "active" : ""} onClick={() => openAdsSection(item.id)}>{item.label}</button>
          ))}
        </nav>

        {adsSection === "overview" ? <>
        <div className="metricGrid metricGrid--primary">
          <article>
            <span className="metricLabel">Campaign records</span>
            <strong className="metricValue">{adsDraftCounts.total}</strong>
            <small className="metricMeta">drafts and paused packages</small>
          </article>
          <article>
            <span className="metricLabel">Ready to create</span>
            <strong className="metricValue">{adsDraftCounts.ready}</strong>
            <small className="metricMeta">review approved</small>
          </article>
          <article>
            <span className="metricLabel">Created paused</span>
            <strong className="metricValue">{adsDraftCounts.created}</strong>
            <small className="metricMeta">complete Meta packages</small>
          </article>
          <article>
            <span className="metricLabel">Needs attention</span>
            <strong className="metricValue">{adsDraftCounts.errors}</strong>
            <small className="metricMeta">creation errors</small>
          </article>
        </div>

        <div className="adsOverviewGrid">
          <section className="dashboardPanel adsQuickStart">
            <span className="metaReadOnlyBadge">Always PAUSED</span>
            <h2>Create your next playlist campaign</h2>
            <p>Build the audience, budget and creative in a guided flow. PlaylistPilot creates the complete package in Meta without activating it.</p>
            <button disabled={!metaWorkspace?.readiness?.publishing_ready} onClick={() => openAdsSection(metaWorkspace?.readiness?.publishing_ready ? "new" : "settings")}>{metaWorkspace?.readiness?.publishing_ready ? "New campaign" : "Complete Meta setup"}</button>
          </section>
          <section className="dashboardPanel adsConnectionSummary">
            <div className="panelHeader"><div><h2>Workspace status</h2><p>The selected identity used for new ads.</p></div><span className={`jobStatus jobStatus--${metaWorkspace?.readiness?.publishing_ready ? "done" : "pending"}`}>{metaWorkspace?.readiness?.publishing_ready ? "ready" : "setup"}</span></div>
            <dl><div><dt>Connection</dt><dd>{metaWorkspace?.configured ? metaWorkspace.status : "Not configured"}</dd></div><div><dt>Ad account</dt><dd>{(metaWorkspace?.assets || []).find((asset) => asset.asset_type === "ad_account" && asset.is_selected)?.name || "Not selected"}</dd></div><div><dt>Identity</dt><dd>{(metaWorkspace?.assets || []).find((asset) => asset.asset_type === "instagram_account" && asset.is_selected)?.name || "Not selected"}</dd></div></dl>
            <button onClick={() => openAdsSection("settings")}>Open settings</button>
          </section>
        </div>
        <div className={`metaPublishLock ${metaWorkspace?.readiness?.publishing_ready ? "ready" : ""}`}><Lock aria-hidden="true" /><div><strong>{metaWorkspace?.readiness?.publishing_ready ? "Paused campaign workflow unlocked" : "Campaign publishing is locked"}</strong><p>{metaWorkspace?.readiness?.publishing_ready ? "Create and review complete PAUSED campaign packages. Active publishing remains unavailable." : `Still required: ${(metaWorkspace?.readiness?.missing || ["successful audit and three selected assets"]).join(", ")}.`}</p></div></div>
        </> : null}

        {adsSection === "creatives" ? <>
        <section className="dashboardPanel creativeStudioHero">
          <div>
            <span className="metaReadOnlyBadge">Creative pipeline</span>
            <h2>Turn playlist identity into testable video concepts</h2>
            <p>Start with a PlaylistPilot playlist. The next stages will generate the brief and hooks, source footage, assemble variants, and send selected concepts to the render queue.</p>
          </div>
          <ol className="creativePipeline" aria-label="Creative pipeline stages">
            {["Playlist", "Brief & hooks", "Media", "Editor", "Batch render", "Review"].map((label, index) => <li key={label}><b>{index + 1}</b><span>{label}</span></li>)}
          </ol>
        </section>

        <div className="creativeStudioGrid">
          <section className="dashboardPanel creativeProjectComposer">
            <div className="panelHeader"><div><h2>New creative project</h2><p>Create the persistent workspace before generating concepts.</p></div></div>
            <div className="metaFormGrid">
              <label className="metaFormWide"><span>Playlist</span><select value={creativeProjectForm.playlist_id} onChange={(event) => selectCreativePlaylist(event.target.value)}><option value="">Select a playlist</option>{playlists.map((item) => <option key={item.id} value={item.id}>{item.name} · {formatNumber(item.followers)} followers</option>)}</select></label>
              <label className="metaFormWide"><span>Project name</span><input value={creativeProjectForm.name} onChange={(event) => setCreativeProjectForm({ ...creativeProjectForm, name: event.target.value })} placeholder="Playlist — Creative exploration" /></label>
              <label><span>Copy language</span><select value={creativeProjectForm.language} onChange={(event) => setCreativeProjectForm({ ...creativeProjectForm, language: event.target.value })}><option value="en">English</option><option value="de">German</option></select></label>
              <label><span>Primary format</span><select value={creativeProjectForm.format} onChange={(event) => setCreativeProjectForm({ ...creativeProjectForm, format: event.target.value })}><option value="9:16">9:16 · Stories & Reels</option><option value="4:5">4:5 · Feed portrait</option><option value="1:1">1:1 · Square</option></select></label>
            </div>
            {creativeProjectForm.playlist_id ? <article className="creativePlaylistSeed"><Artwork src={playlists.find((item) => item.id === creativeProjectForm.playlist_id)?.image} alt="" size="lg" /><div><span>Source playlist</span><strong>{playlists.find((item) => item.id === creativeProjectForm.playlist_id)?.name}</strong><small>{formatNumber(playlists.find((item) => item.id === creativeProjectForm.playlist_id)?.tracks_total)} tracks available for the creative brief</small></div></article> : null}
            <div className="metaFormActions"><button disabled={busy || !creativeProjectForm.playlist_id || creativeProjectForm.name.trim().length < 3} onClick={createCreativeProject}>Create creative project</button><small>No LLM or render costs are triggered yet.</small></div>
          </section>

          <section className="dashboardPanel creativeProjectList">
            <div className="panelHeader"><div><h2>Creative projects</h2><p>Persistent workspaces shared by concept generation, media, and rendering.</p></div><span className="jobStatus jobStatus--pending">{creativeProjects.length}</span></div>
            <div className="creativeProjectCards">
              {creativeProjects.map((project) => {
                const concepts = [...(project.meta_creative_concepts || [])].sort((a, b) => Number(a.position || 0) - Number(b.position || 0));
                const assets = project.meta_creative_assets || [];
                const renders = project.meta_creative_render_jobs || [];
                const completedRenders = renders.filter((job) => job.status === "completed").length;
                const isOpen = openCreativeProjectId === project.id;
                const hasBrief = Boolean(project.brief?.mood_summary);
                const readyConcepts = concepts.filter((concept) => concept.render_spec?.editor?.asset_id && concept.render_spec?.editor?.hook_text);
                const batchTemplateIds = selectedBatchTemplates(project.id);
                const localBatch = creativeBatchRuns[project.id];
                const storedBatchId = localBatch?.batch_id || renders.find((job) => job.render_spec?.batch_id)?.render_spec?.batch_id;
                const batchJobs = storedBatchId ? renders.filter((job) => job.render_spec?.batch_id === storedBatchId) : [];
                const batchTotal = localBatch?.total || batchJobs.length;
                const batchCompleted = batchJobs.filter((job) => job.status === "completed").length || localBatch?.completed || 0;
                const batchFailed = batchJobs.filter((job) => ["failed", "cancelled"].includes(job.status)).length || localBatch?.failed || 0;
                const batchActive = batchJobs.some((job) => ["queued", "processing"].includes(job.status));
                const projectMediaRun = creativeProjectMediaRuns[project.id];
                const projectMediaResults = Object.values(projectMediaRun?.results || {}).sort((a, b) => Number(a.concept?.position || 0) - Number(b.concept?.position || 0));
                const assignableMediaCount = projectMediaResults.filter((result) => result.selected_id).length;
                return <article key={project.id} className={isOpen ? "isOpen" : ""}>
                  <div className="creativeProjectSummary">
                    <Artwork src={project.playlists?.image || project.brief?.cover_image} alt="" size="lg" />
                    <div className="creativeProjectCopy"><div><span>{project.status.replaceAll("_", " ")}</span><strong>{project.name}</strong></div><small>{project.playlists?.name || project.brief?.playlist_name || "Playlist"} · {project.format} · {project.language.toUpperCase()}</small><div className="creativeProjectMetrics"><b>{concepts.length}<small>concepts</small></b><b>{renders.length}<small>render jobs</small></b><b>{completedRenders}<small>finished</small></b></div></div>
                    <button onClick={() => setOpenCreativeProjectId(isOpen ? "" : project.id)}>{isOpen ? "Close" : "Open project"}</button>
                  </div>
                  {isOpen ? <div className="creativeProjectDetail">
                    {hasBrief ? <div className="creativeBriefPanel"><span>Creative brief</span><h3>{project.brief.title || project.name}</h3><p>{project.brief.mood_summary}</p><p>{project.brief.audience_summary}</p><div>{(project.brief.core_angles || []).map((angle) => <b key={angle}>{angle}</b>)}</div></div> : <div className="creativeEmptyState"><strong>Ready to analyze</strong><p>PlaylistPilot will read the local playlist snapshot and create a brief plus eight testable concepts.</p><button disabled={busy} onClick={() => generateCreativeProject(project.id)}>{project.status === "error" ? "Retry generation" : "Generate brief & concepts"}</button>{project.last_error ? <small>{project.last_error}</small> : null}</div>}
                    {concepts.length ? <section className="creativeMediaAutomation">
                      <div className="creativeBatchHeader"><div><span>AI media director</span><h3>Find matching video for every concept</h3><p>Two searches and multi-frame Vision scoring per concept, with duplicate clips avoided across the project.</p></div><button className="aiMediaButton" disabled={busy || projectMediaRun?.status === "running"} onClick={() => recommendProjectMedia(project)}>{projectMediaRun?.status === "running" ? `Reviewing ${projectMediaRun.completed}/${projectMediaRun.total}…` : projectMediaRun?.status === "review" ? "Regenerate all" : `Generate media for all ${concepts.length}`}</button></div>
                      {projectMediaRun ? <div className="creativeProjectMediaProgress"><div><span style={{ width: `${Math.round((projectMediaRun.completed / Math.max(1, projectMediaRun.total)) * 100)}%` }} /></div><small>{projectMediaRun.status === "running" ? "Pexels search and visual ranking are running with two concurrent jobs." : `${projectMediaResults.length} concepts ready for review${projectMediaRun.errors?.length ? ` · ${projectMediaRun.errors.length} failed` : ""}`}</small></div> : null}
                      {projectMediaResults.length ? <div className="creativeProjectMediaReview">{projectMediaResults.map((result) => {
                        const selected = result.recommendations.find((video) => video.id === result.selected_id) || result.recommendations[0];
                        if (!selected) return null;
                        return <article key={result.concept.id} className={result.selected_id ? "isApproved" : "needsReview"}><div className="creativeProjectMediaVisual"><img src={selected.image || selected.preview_images?.[0]} alt="" /><b>{selected.ai?.overall_score || 0}</b></div><div><span>Concept {result.concept.position} · {result.selected_id ? "AI approved" : "Needs review"}</span><h4>{result.concept.title}</h4><strong>{result.concept.hook}</strong><select aria-label={`AI video for ${result.concept.title}`} value={result.selected_id || ""} onChange={(event) => chooseProjectMedia(project.id, result.concept.id, event.target.value)}><option value="">Choose a clip manually</option>{result.recommendations.map((video, index) => <option key={video.id} value={video.id}>#{index + 1} · {video.ai?.overall_score || 0}/100 · {video.ai?.production_ready ? "ready" : "review"} · {video.user?.name || "Pexels"}</option>)}</select><p>{result.selected_id ? selected.ai?.summary : selected.ai?.rejection_reason || selected.ai?.summary}</p><small>{selected.ai?.best_template?.replaceAll("_", " ")} · {selected.duration}s · {selected.source_width}×{selected.source_height}</small></div></article>;
                      })}</div> : null}
                      {projectMediaRun?.status === "review" && projectMediaResults.length ? <div className="creativeMediaReviewActions"><button disabled={busy || !assignableMediaCount} onClick={() => assignProjectMedia(project)}>Assign {assignableMediaCount} approved clip{assignableMediaCount === 1 ? "" : "s"}</button><small>{projectMediaResults.length - assignableMediaCount ? `${projectMediaResults.length - assignableMediaCount} concept${projectMediaResults.length - assignableMediaCount === 1 ? " needs" : "s need"} manual review. ` : ""}This does not render videos yet.</small></div> : null}
                    </section> : null}
                    {readyConcepts.length ? <section className="creativeBatchPanel">
                      <div className="creativeBatchHeader"><div><span>Batch render</span><h3>Turn {readyConcepts.length} ready concept{readyConcepts.length === 1 ? "" : "s"} into variants</h3><p>Select one or more layouts. Every ready concept is rendered once per template.</p></div><button disabled={busy || !batchTemplateIds.length || batchActive} onClick={() => queueCreativeBatch(project)}>{batchActive ? "Rendering…" : `Render ${readyConcepts.length * batchTemplateIds.length} variant${readyConcepts.length * batchTemplateIds.length === 1 ? "" : "s"}`}</button></div>
                      <div className="creativeTemplateGrid">{CREATIVE_RENDER_TEMPLATES.map((template) => <label key={template.id} className={batchTemplateIds.includes(template.id) ? "isSelected" : ""}><input type="checkbox" checked={batchTemplateIds.includes(template.id)} onChange={() => toggleBatchTemplate(project.id, template.id)} /><span><strong>{template.name}</strong><small>{template.description}</small></span></label>)}</div>
                      {batchTotal ? <div className="creativeBatchProgress"><div><span style={{ width: `${Math.round(((batchCompleted + batchFailed) / batchTotal) * 100)}%` }} /></div><small>{batchCompleted} finished · {batchFailed} failed · {Math.max(0, batchTotal - batchCompleted - batchFailed)} remaining</small></div> : null}
                    </section> : null}
                    {concepts.length ? <div className="creativeConceptGrid">{concepts.map((concept) => {
                      const mediaState = creativeMediaSearches[concept.id] || {};
                      const defaultQuery = concept.visual_search_terms?.[0] || concept.visual_direction || "people listening music";
                      const assignedAssets = assets.filter((asset) => asset.concept_id === concept.id && asset.asset_type === "video");
                      const editorDraft = creativeEditorDrafts[concept.id] || concept.render_spec?.editor || {};
                      const editorAsset = assignedAssets.find((asset) => asset.id === editorDraft.asset_id) || assignedAssets[0];
                      const conceptRenderJobs = renders.filter((job) => job.concept_id === concept.id).sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
                      const latestRenderJob = conceptRenderJobs[0];
                      return <article key={concept.id} className={assignedAssets.length ? "hasMedia" : ""}><span>Concept {concept.position} · {concept.status.replaceAll("_", " ")}</span><h3>{concept.title}</h3><strong>{concept.hook}</strong><p>{concept.story}</p><dl><div><dt>Angle</dt><dd>{concept.angle}</dd></div><div><dt>Visual</dt><dd>{concept.visual_direction}</dd></div><div><dt>Hypothesis</dt><dd>{concept.hypothesis}</dd></div></dl><div className="creativeConceptTerms">{(concept.visual_search_terms || []).map((term) => <button key={term} onClick={() => setCreativeMediaQuery(concept.id, term)}>{term}</button>)}</div>
                        {assignedAssets.map((asset) => <div className="creativeAssignedMedia" key={asset.id}><video src={asset.source_url} poster={asset.metadata?.image || ""} muted controls playsInline preload="metadata" /><div><strong>Selected Pexels clip</strong><small>{asset.width}×{asset.height} · {Number(asset.duration_seconds || 0).toFixed(1)}s</small>{asset.metadata?.pexels_url ? <a href={asset.metadata.pexels_url} target="_blank" rel="noreferrer">Video by {asset.metadata?.creator_name || "creator"} on Pexels</a> : null}<button onClick={() => openCreativeEditor(concept, asset)}>{openCreativeEditorId === concept.id ? "Close editor" : concept.render_spec?.editor ? "Edit render" : "Open editor"}</button></div></div>)}
                        {openCreativeEditorId === concept.id && editorAsset ? <div className="creativeEditor">
                          <div className={`creativeEditorPreview creativeEditorPreview--${project.format.replace(":", "x")} creativeEditorPreview--${editorDraft.template_id || "bold_center"}`} style={{ "--editor-overlay": editorDraft.overlay_color || "#000000", "--editor-opacity": editorDraft.overlay_opacity ?? 0.28, "--editor-text": editorDraft.text_color || "#FFFFFF", "--editor-accent": editorDraft.accent_color || "#1ED760" }}>
                            <video src={editorAsset.source_url} poster={editorAsset.metadata?.image || ""} muted autoPlay loop playsInline />
                            <div className="creativeEditorShade" />
                            <div className={`creativeEditorHook creativeEditorHook--${editorDraft.hook_position || "center"}`} style={{ textAlign: editorDraft.text_align || "center" }}><strong>{editorDraft.hook_text || concept.hook}</strong></div>
                            {editorDraft.show_cover !== false ? <div className={`creativeEditorBrand creativeEditorBrand--${editorDraft.cover_position || "bottom"}`}><Artwork src={project.playlists?.image || project.brief?.cover_image} alt="" size="md" /><span>{project.playlists?.name || project.brief?.playlist_name}</span></div> : null}
                            {editorDraft.show_cta !== false ? <div className="creativeEditorCta">{editorDraft.cta_text || "Listen on Spotify"}</div> : null}
                          </div>
                          <div className="creativeEditorControls">
                            <label className="creativeEditorWide"><span>Layout template</span><select value={editorDraft.template_id || "bold_center"} onChange={(event) => { const template = CREATIVE_RENDER_TEMPLATES.find((item) => item.id === event.target.value) || CREATIVE_RENDER_TEMPLATES[0]; updateCreativeEditor(concept.id, { template_id: template.id, hook_position: template.hook_position, text_align: template.text_align }); }}>{CREATIVE_RENDER_TEMPLATES.map((template) => <option key={template.id} value={template.id}>{template.name} · {template.description}</option>)}</select></label>
                            {assignedAssets.length > 1 ? <label className="creativeEditorWide"><span>Video</span><select value={editorDraft.asset_id || editorAsset.id} onChange={(event) => updateCreativeEditor(concept.id, { asset_id: event.target.value })}>{assignedAssets.map((asset, index) => <option value={asset.id} key={asset.id}>Clip {index + 1} · {asset.width}×{asset.height}</option>)}</select></label> : null}
                            <label className="creativeEditorWide"><span>Hook overlay</span><input value={editorDraft.hook_text || ""} maxLength={120} onChange={(event) => updateCreativeEditor(concept.id, { hook_text: event.target.value })} /></label>
                            <label className="creativeEditorWide"><span>CTA</span><input value={editorDraft.cta_text || ""} maxLength={80} onChange={(event) => updateCreativeEditor(concept.id, { cta_text: event.target.value })} /></label>
                            <label><span>Hook position</span><select value={editorDraft.hook_position || "center"} onChange={(event) => updateCreativeEditor(concept.id, { hook_position: event.target.value })}><option value="top">Top</option><option value="center">Center</option><option value="bottom">Bottom</option></select></label>
                            <label><span>Text alignment</span><select value={editorDraft.text_align || "center"} onChange={(event) => updateCreativeEditor(concept.id, { text_align: event.target.value })}><option value="left">Left</option><option value="center">Center</option><option value="right">Right</option></select></label>
                            <label><span>Text color</span><input type="color" value={editorDraft.text_color || "#FFFFFF"} onChange={(event) => updateCreativeEditor(concept.id, { text_color: event.target.value })} /></label>
                            <label><span>Accent</span><input type="color" value={editorDraft.accent_color || "#1ED760"} onChange={(event) => updateCreativeEditor(concept.id, { accent_color: event.target.value })} /></label>
                            <label><span>Clip starts</span><input type="number" min="0" max={Math.max(0, Number(editorAsset.duration_seconds || 1) - 0.5)} step="0.1" value={editorDraft.trim_start ?? 0} onChange={(event) => updateCreativeEditor(concept.id, { trim_start: Number(event.target.value) })} /></label>
                            <label><span>Clip ends</span><input type="number" min="0.5" max={Number(editorAsset.duration_seconds || 15)} step="0.1" value={editorDraft.trim_end ?? Math.min(Number(editorAsset.duration_seconds || 15), 15)} onChange={(event) => updateCreativeEditor(concept.id, { trim_end: Number(event.target.value) })} /></label>
                            <label><span>Hook starts</span><input type="number" min="0" step="0.1" value={editorDraft.hook_start ?? 0} onChange={(event) => updateCreativeEditor(concept.id, { hook_start: Number(event.target.value) })} /></label>
                            <label><span>Hook ends</span><input type="number" min="0.25" step="0.1" value={editorDraft.hook_end ?? 4} onChange={(event) => updateCreativeEditor(concept.id, { hook_end: Number(event.target.value) })} /></label>
                            <label><span>Overlay strength</span><input type="range" min="0" max="0.85" step="0.05" value={editorDraft.overlay_opacity ?? 0.28} onChange={(event) => updateCreativeEditor(concept.id, { overlay_opacity: Number(event.target.value) })} /></label>
                            <label><span>Cover position</span><select value={editorDraft.cover_position || "bottom"} onChange={(event) => updateCreativeEditor(concept.id, { cover_position: event.target.value })}><option value="top">Top</option><option value="center">Center</option><option value="bottom">Bottom</option></select></label>
                            <label className="creativeEditorToggle"><input type="checkbox" checked={editorDraft.show_cover !== false} onChange={(event) => updateCreativeEditor(concept.id, { show_cover: event.target.checked })} /><span>Show playlist cover</span></label>
                            <label className="creativeEditorToggle"><input type="checkbox" checked={editorDraft.show_cta !== false} onChange={(event) => updateCreativeEditor(concept.id, { show_cta: event.target.checked })} /><span>Show CTA</span></label>
                            <div className="creativeEditorActions"><div><button disabled={busy || !String(editorDraft.hook_text || "").trim()} onClick={() => saveCreativeEditor(concept.id)}>{concept.render_spec?.editor ? "Update render spec" : "Save render spec"}</button>{concept.render_spec?.editor && !["processing", "queued"].includes(latestRenderJob?.status) ? <button className="secondary" disabled={busy} onClick={() => queueCreativeRender(concept.id)}>Render video</button> : null}{["processing", "queued"].includes(latestRenderJob?.status) ? <button className="secondary" disabled={busy} onClick={() => syncCreativeRender(latestRenderJob.id)}>Refresh render</button> : null}</div><small>{latestRenderJob ? `Render: ${creativeRenderPolling[latestRenderJob.id] || latestRenderJob.status}` : concept.render_spec?.editor ? "Ready for rendering" : "No render is started yet"}{latestRenderJob?.error_message ? ` · ${latestRenderJob.error_message}` : ""}</small></div>
                          </div>
                        </div> : null}
                        <div className="creativeMediaSearch"><div><input aria-label={`Pexels query for ${concept.title}`} value={mediaState.query ?? defaultQuery} onChange={(event) => setCreativeMediaQuery(concept.id, event.target.value)} /><button disabled={mediaState.loading || mediaState.recommending} onClick={() => searchCreativeMedia(concept)}>{mediaState.loading ? "Searching…" : assignedAssets.length ? "Find another" : "Find videos"}</button><button className="aiMediaButton" disabled={mediaState.loading || mediaState.recommending} onClick={() => recommendCreativeMedia(concept)}>{mediaState.recommending ? "AI reviewing…" : "AI shortlist"}</button></div>{mediaState.videos?.length ? <><small>{mediaState.aiRanked ? `${mediaState.videos.length} AI recommendations from ${mediaState.total} inspected clips` : `${mediaState.total} Pexels results · select one to attach it`}{mediaState.queries?.length ? ` · ${mediaState.queries.join(" + ")}` : ""}</small><div className={`creativeMediaResults ${mediaState.aiRanked ? "isAiRanked" : ""}`}>{mediaState.videos.map((video) => <div key={video.id}>{video.ai ? <div className="creativeAiScore"><b>{video.ai.overall_score}</b><span>AI match</span><small>{video.ai.production_ready ? "ready" : "review"} · {video.ai.best_template.replaceAll("_", " ")}</small></div> : null}<video src={video.source_url} poster={video.image} muted controls playsInline preload="metadata" />{video.ai && video.preview_images?.length ? <div className="creativePreviewFrames">{video.preview_images.map((image, index) => <img key={`${video.id}-${index}`} src={image} alt={`Preview frame ${index + 1}`} />)}</div> : null}<div><span>{video.duration}s · {video.source_width}×{video.source_height}</span><button disabled={busy} onClick={() => selectCreativeMedia(concept, video)}>Use clip</button>{video.ai ? <p>{video.ai.production_ready ? video.ai.summary : video.ai.rejection_reason || video.ai.summary}</p> : null}<a href={video.url} target="_blank" rel="noreferrer">{video.user?.name || "Pexels"}</a></div></div>)}</div><a className="pexelsAttribution" href="https://www.pexels.com" target="_blank" rel="noreferrer">Videos provided by Pexels</a></> : null}</div>
                      </article>;
                    })}</div> : null}
                  </div> : null}
                </article>;
              })}
              {!creativeProjects.length ? <div className="creativeEmptyState"><strong>No creative projects yet</strong><p>Select a playlist to establish the first workspace.</p></div> : null}
            </div>
          </section>
        </div>
        </> : null}

        {adsSection === "library" ? <section className="dashboardPanel creativeLibrary">
          <div className="panelHeader"><div><span className="metaReadOnlyBadge">Rendered assets</span><h2>Creative Library</h2><p>Finished videos remain reusable independently from a Meta campaign.</p></div><button onClick={loadCreativeProjects}>Refresh</button></div>
          {creativeProjects.some((project) => (project.meta_creative_assets || []).some((asset) => asset.asset_type === "render")) ? <div className="creativeLibraryGrid">{creativeProjects.flatMap((project) => {
            const conceptsById = new Map((project.meta_creative_concepts || []).map((concept) => [concept.id, concept]));
            return (project.meta_creative_assets || []).filter((asset) => asset.asset_type === "render").map((asset) => ({ asset, project, concept: conceptsById.get(asset.concept_id) }));
          }).map(({ asset, project, concept }) => <article key={asset.id}><video src={asset.source_url} controls muted playsInline preload="metadata" /><div><span>{asset.metadata?.template_name || "Custom"} · {project.format} · {Number(asset.duration_seconds || 0).toFixed(1)}s</span><h3>{concept?.title || project.name}</h3><strong>{concept?.hook || project.brief?.title}</strong><small>{project.playlists?.name || project.brief?.playlist_name}</small><a href={asset.source_url} target="_blank" rel="noreferrer">Open MP4</a></div></article>)}</div> : <div className="creativeEmptyState"><strong>No rendered creatives yet</strong><p>Save an editor specification and start the first render in Creative Studio.</p><button onClick={() => openAdsSection("creatives")}>Open Creative Studio</button></div>}
        </section> : null}

        {adsSection === "settings" ? <>
        <div className="metaSetupGrid">
          <section className="dashboardPanel metaConnectionPanel">
            <div className="panelHeader">
              <div>
                <h2>Meta connection</h2>
                <p>Credentials are encrypted server-side and are never returned to this browser.</p>
              </div>
              <span className={`jobStatus jobStatus--${metaWorkspace?.status === "ready" ? "done" : metaWorkspace?.status === "error" ? "failed" : "pending"}`}>{metaWorkspace?.status || "unverified"}</span>
            </div>
            <div className="metaFormGrid">
              <label><span>App ID</span><input value={metaForm.app_id} onChange={(e) => setMetaForm({ ...metaForm, app_id: e.target.value })} inputMode="numeric" /></label>
              <label><span>Business ID</span><input value={metaForm.business_id} onChange={(e) => setMetaForm({ ...metaForm, business_id: e.target.value })} inputMode="numeric" /></label>
              <label><span>Graph API version</span><input value={metaForm.graph_version} onChange={(e) => setMetaForm({ ...metaForm, graph_version: e.target.value })} placeholder="v25.0" /></label>
              <label><span>EU ad beneficiary</span><input value={metaForm.dsa_beneficiary} onChange={(e) => setMetaForm({ ...metaForm, dsa_beneficiary: e.target.value })} placeholder="Legal person or company name" /></label>
              <label><span>EU ad payor</span><input value={metaForm.dsa_payor} onChange={(e) => setMetaForm({ ...metaForm, dsa_payor: e.target.value })} placeholder="Legal person or company name" /></label>
              <label><span>{metaWorkspace?.configured ? "Replace access token" : "System user access token"}</span><input type="password" autoComplete="new-password" value={metaForm.access_token} onChange={(e) => setMetaForm({ ...metaForm, access_token: e.target.value })} placeholder={metaWorkspace?.configured ? "Leave empty to keep current token" : "Paste token"} /></label>
              <label className="metaFormWide"><span>App secret <small>optional, enables appsecret_proof</small></span><input type="password" autoComplete="new-password" value={metaForm.app_secret} onChange={(e) => setMetaForm({ ...metaForm, app_secret: e.target.value })} placeholder={metaWorkspace?.has_app_secret ? "Stored securely; leave empty to keep" : "Optional"} /></label>
            </div>
            <div className="metaFormActions">
              <button disabled={busy || !metaForm.app_id || !metaForm.business_id || (!metaWorkspace?.configured && !metaForm.access_token)} onClick={saveMetaConnection}>Save securely</button>
              <small>Use a dedicated system-user token with only <b>ads_read</b> and <b>ads_management</b>.</small>
            </div>
            <p className="metaDsaNote">For ads targeting the EU, Meta publicly discloses who benefits from and who pays for the ad. Enter the legally correct names; PlaylistPilot will not infer them.</p>
          </section>

          <section className="dashboardPanel metaAuditPanel">
            <div className="panelHeader"><div><h2>Audit result</h2><p>Identity, permissions, and warnings from Meta.</p></div></div>
            <div className="metaIdentity">
              <span>Token identity</span>
              <strong>{metaWorkspace?.audit_summary?.identity?.name || "Not audited"}</strong>
              <small>{metaWorkspace?.audit_summary?.identity?.id || "Run the connection audit after saving."}</small>
            </div>
            <div className="metaPermissionList">
              {(metaWorkspace?.audit_summary?.permissions?.granted || []).map((permission) => <span key={permission}>{permission}</span>)}
              {!metaWorkspace?.audit_summary?.permissions?.granted?.length ? <p>No granted permissions loaded.</p> : null}
            </div>
            {(metaWorkspace?.audit_summary?.warnings || []).length ? <div className="metaWarnings">{metaWorkspace.audit_summary.warnings.map((warning) => <p key={warning}>{warning}</p>)}</div> : null}
            {metaWorkspace?.last_error && !metaWorkspace?.audit_summary?.warnings?.length ? <div className="metaWarnings"><p>{metaWorkspace.last_error}</p></div> : null}
          </section>
        </div>

        <section className="dashboardPanel metaAssetsPanel">
          <div className="panelHeader">
            <div><h2>Business assets</h2><p>Select one default asset per column. The Instagram identity must belong to the selected Page.</p></div>
          </div>
          <div className="metaAssetColumns">
            {[{ type: "ad_account", title: "Ad accounts" }, { type: "page", title: "Facebook pages" }, { type: "instagram_account", title: "Instagram accounts" }].map((group) => {
              const items = (metaWorkspace?.assets || []).filter((asset) => asset.asset_type === group.type);
              return <div className="metaAssetGroup" key={group.type}>
                <div className="metaAssetGroupHeader"><strong>{group.title}</strong><span>{items.length}</span></div>
                {items.map((asset) => <article className={asset.is_selected ? "selected" : ""} key={asset.id}>
                  <div><strong>{asset.name}</strong><small>{asset.meta_id}</small></div>
                  <div className="metaAssetActions">
                    {group.type === "ad_account" ? <span>{asset.metadata?.currency || ""} {asset.metadata?.timezone_name || ""}</span> : null}
                    <button disabled={busy || asset.is_selected} onClick={() => selectMetaAsset(asset.id)}>{asset.is_selected ? "Selected" : "Select"}</button>
                  </div>
                </article>)}
                {!items.length ? <p>No assets found.</p> : null}
              </div>;
            })}
          </div>
        </section>
        </> : null}

        {adsSection === "new" ?
        <section className="dashboardPanel metaDraftComposer">
          <div className="panelHeader">
            <div><h2>New campaign</h2><p>Build a paused campaign package in three steps. Nothing is sent to Meta while completing this form.</p></div>
            <span className="metaReadOnlyBadge">Always PAUSED</span>
          </div>
          <div className="adsWizardSteps" aria-label="Campaign creation progress">
            {["Destination", "Audience & budget", "Creative", "Delivery"].map((label, index) => <button key={label} className={adsWizardStep === index + 1 ? "active" : adsWizardStep > index + 1 ? "complete" : ""} onClick={() => setAdsWizardStep(index + 1)}><span>{index + 1}</span>{label}</button>)}
          </div>
          <div className="metaDraftGrid">
            {adsWizardStep === 1 ? <>
              <label className="metaDraftWide"><span>Playlist</span><select value={metaDraftForm.playlist_id} onChange={(e) => selectMetaCampaignPlaylist(e.target.value)}><option value="">Select a playlist</option>{playlists.map((item) => <option key={item.id} value={item.id}>{item.name} · {formatNumber(item.followers)} followers</option>)}</select></label>
              <label className="metaDraftWide"><span>Campaign name</span><input value={metaDraftForm.name} onChange={(e) => setMetaDraftForm({ ...metaDraftForm, name: e.target.value })} /></label>
              <label className="metaDraftWide"><span>Spotify destination URL</span><input type="url" value={metaDraftForm.destination_url} onChange={(e) => setMetaDraftForm({ ...metaDraftForm, destination_url: e.target.value })} placeholder="https://open.spotify.com/playlist/..." /></label>
              {metaDraftForm.playlist_id ? <article className="adsSelectedPlaylist"><Artwork src={playlists.find((item) => item.id === metaDraftForm.playlist_id)?.image} alt="" size="lg" /><div><span>Campaign destination</span><strong>{playlists.find((item) => item.id === metaDraftForm.playlist_id)?.name}</strong><small>Spotify link and cover imported automatically</small></div></article> : null}
            </> : null}
            {adsWizardStep === 2 ? <>
              <label><span>Daily budget (EUR)</span><input type="number" min="1" step="1" value={metaDraftForm.daily_budget_eur} onChange={(e) => setMetaDraftForm({ ...metaDraftForm, daily_budget_eur: e.target.value })} /></label>
              <label><span>Countries</span><input value={metaDraftForm.countries} onChange={(e) => setMetaDraftForm({ ...metaDraftForm, countries: e.target.value })} placeholder="DE, AT, CH" /></label>
              <label><span>Minimum age</span><input type="number" min="13" max="65" value={metaDraftForm.age_min} onChange={(e) => setMetaDraftForm({ ...metaDraftForm, age_min: e.target.value })} /></label>
              <label><span>Maximum age</span><input type="number" min="13" max="65" value={metaDraftForm.age_max} onChange={(e) => setMetaDraftForm({ ...metaDraftForm, age_max: e.target.value })} /></label>
            </> : null}
            {adsWizardStep === 3 ? <>
              <label className="metaDraftWide"><span>Creative image URL</span><input type="url" value={metaDraftForm.image_url} onChange={(e) => setMetaDraftForm({ ...metaDraftForm, image_url: e.target.value })} placeholder="https://.../cover.jpg" /></label>
              <label className="adsCreativeUpload metaDraftWide"><span>Or upload a custom image</span><input type="file" accept="image/jpeg,image/png,image/webp" disabled={busy} onChange={uploadMetaCreative} /><small>JPEG, PNG or WebP · maximum 3 MB · square images work best</small></label>
              <label className="metaDraftWide"><span>Headline</span><input value={metaDraftForm.headline} onChange={(e) => setMetaDraftForm({ ...metaDraftForm, headline: e.target.value })} /></label>
              <label className="metaDraftWide"><span>Primary text</span><textarea rows="4" value={metaDraftForm.primary_text} onChange={(e) => setMetaDraftForm({ ...metaDraftForm, primary_text: e.target.value })} /></label>
              <div className="adsCreativePreviewGrid">
                {[{ platform: "Instagram", identity: (metaWorkspace?.assets || []).find((asset) => asset.asset_type === "instagram_account" && asset.is_selected)?.name || "Instagram" }, { platform: "Facebook", identity: (metaWorkspace?.assets || []).find((asset) => asset.asset_type === "page" && asset.is_selected)?.name || "Facebook Page" }].map((preview) => <aside className="adsCreativePreview" key={preview.platform}><div className="adsPreviewIdentity"><span>{preview.platform} feed</span><strong>{preview.identity}</strong></div><p>{metaDraftForm.primary_text || "Your primary text"}</p>{metaDraftForm.image_url ? <img src={metaDraftForm.image_url} alt={`${preview.platform} campaign preview`} /> : <div className="adsCreativePlaceholder">Image preview</div>}<div className="adsPreviewLink"><div><small>OPEN.SPOTIFY.COM</small><strong>{metaDraftForm.headline || "Your headline"}</strong></div><b>Learn more</b></div></aside>)}
              </div>
            </> : null}
            {adsWizardStep === 4 ? <>
              <label><span>Start date</span><input type="date" min={new Date().toISOString().slice(0, 10)} value={metaDraftForm.start_date} onChange={(e) => setMetaDraftForm({ ...metaDraftForm, start_date: e.target.value })} /></label>
              <label><span>End date</span><input type="date" min={metaDraftForm.start_date || new Date().toISOString().slice(0, 10)} value={metaDraftForm.end_date} onChange={(e) => setMetaDraftForm({ ...metaDraftForm, end_date: e.target.value })} /></label>
              <fieldset className="adsPlacementChoices"><legend>Placements</legend>{[{ id: "automatic", title: "Advantage+ placements", text: "Meta distributes across Facebook and Instagram." }, { id: "feeds", title: "Feeds", text: "Facebook Feed and Instagram Feed only." }, { id: "stories_reels", title: "Stories & Reels", text: "Vertical placements on both platforms." }].map((option) => <label className={metaDraftForm.placement_mode === option.id ? "selected" : ""} key={option.id}><input type="radio" name="placement_mode" value={option.id} checked={metaDraftForm.placement_mode === option.id} onChange={(e) => setMetaDraftForm({ ...metaDraftForm, placement_mode: e.target.value })} /><span><strong>{option.title}</strong><small>{option.text}</small></span></label>)}</fieldset>
              <aside className="adsDeliverySummary"><span>Delivery summary</span><strong>€{metaDraftForm.daily_budget_eur || "0"} per day</strong><p>{metaDraftForm.start_date || "Start date"} → {metaDraftForm.end_date || "End date"}</p><small>{metaDraftForm.placement_mode === "automatic" ? "Advantage+ placements" : metaDraftForm.placement_mode === "feeds" ? "Facebook + Instagram Feeds" : "Facebook + Instagram Stories & Reels"}</small><b>Created PAUSED</b></aside>
            </> : null}
          </div>
          <div className="metaFormActions adsWizardActions">
            <button disabled={busy || adsWizardStep === 1} onClick={() => setAdsWizardStep((step) => Math.max(1, step - 1))}>Back</button>
            {adsWizardStep < 4 ? <button disabled={busy || (adsWizardStep === 1 && (!metaDraftForm.playlist_id || !metaDraftForm.destination_url)) || (adsWizardStep === 3 && !metaDraftForm.image_url)} onClick={() => setAdsWizardStep((step) => Math.min(4, step + 1))}>Continue</button> : <button disabled={busy || !metaWorkspace?.readiness?.publishing_ready || !metaDraftForm.start_date || !metaDraftForm.end_date || metaDraftForm.end_date <= metaDraftForm.start_date} onClick={saveMetaDraft}>Save campaign draft</button>}
            <small>Objective and delivery status are locked to <b>Traffic</b> and <b>PAUSED</b>.</small>
          </div>
        </section>
        : null}

        {adsSection === "campaigns" ?
        <section className="dashboardPanel metaDraftList">
          <div className="panelHeader"><div><h2>Campaigns</h2><p>Drafts and complete paused Meta packages in one place.</p></div><button onClick={() => openAdsSection("new")}>New campaign</button></div>
          <div className="metaDraftCards">
            {metaDrafts.map((draft) => <article key={draft.id}>
              <div className="metaDraftCardHeader"><div><strong>{draft.name}</strong><small>{draft.status.replaceAll("_", " ")}</small></div><span>€{(Number(draft.daily_budget_minor || 0) / 100).toFixed(2)}/day</span></div>
              <p>{draft.primary_text}</p>
              <dl><div><dt>Target</dt><dd>{(draft.countries || []).join(", ")} · {draft.age_min}–{draft.age_max}</dd></div><div><dt>Schedule</dt><dd>{draft.start_date && draft.end_date ? `${draft.start_date} → ${draft.end_date}` : "Not scheduled"}</dd></div><div><dt>Placements</dt><dd>{(draft.placement_mode || "automatic").replaceAll("_", " ")}</dd></div><div><dt>Destination</dt><dd>{draft.destination_url}</dd></div><div><dt>Creation stage</dt><dd>{(draft.creation_stage || "local").replaceAll("_", " ")}</dd></div>{draft.meta_campaign_id ? <div><dt>Meta campaign</dt><dd>{draft.meta_campaign_id}</dd></div> : null}{draft.meta_adset_id ? <div><dt>Meta ad set</dt><dd>{draft.meta_adset_id}</dd></div> : null}{draft.meta_creative_id ? <div><dt>Meta creative</dt><dd>{draft.meta_creative_id}</dd></div> : null}{draft.meta_ad_id ? <div><dt>Meta ad</dt><dd>{draft.meta_ad_id}</dd></div> : null}</dl>
              {draft.last_error ? <div className="metaWarnings"><p>{draft.last_error}</p></div> : null}
              <div className="metaDraftActions">
                <button disabled={busy || draft.status !== "draft"} onClick={() => reviewMetaDraft(draft.id)}>{draft.status === "draft" ? "Approve review" : "Reviewed"}</button>
                <button className="dangerButton" disabled={busy || !["review_ready", "error"].includes(draft.status)} onClick={() => createPausedMetaCampaign(draft.id)}>{draft.status === "error" ? "Resume PAUSED creation" : draft.status === "created_paused" ? "Created PAUSED" : "Create PAUSED package"}</button>
              </div>
            </article>)}
            {!metaDrafts.length ? <p>No campaign drafts yet.</p> : null}
          </div>
        </section>
        : null}
      </section>
      ) : view === "admin" && isAdmin ? (
      <section className="adminPanel">
        <div className="statusLine">
          {busy ? <span><i className="miniSpinner" aria-hidden="true" />{busyLabel || "Working"}</span> : message ? <span>{message}</span> : <span />}
          {error ? <strong>{error}</strong> : null}
        </div>
        <div className="dashboardHero">
          <div>
            <h2>Admin</h2>
            <p>Queue, sync health, locks, and recent worker activity.</p>
          </div>
          <div className="dashboardActions">
            <button disabled={busy} onClick={loadAdminStatus}>Refresh</button>
            <button disabled={busy} onClick={runAdminJobs}>Run worker</button>
          </div>
        </div>

        <div className="metricGrid metricGrid--primary">
          <article>
            <span className="metricLabel">Users</span>
            <strong className="metricValue">{formatNumber(adminStatus?.totals?.active_users)}</strong>
            <small className="metricMeta">{formatNumber(adminStatus?.totals?.users)} total</small>
          </article>
          <article>
            <span className="metricLabel">Connections</span>
            <strong className="metricValue">{formatNumber(adminStatus?.totals?.active_connections)}</strong>
            <small className="metricMeta">{formatNumber(adminStatus?.totals?.spotify_connections)} total</small>
          </article>
          <article>
            <span className="metricLabel">Playlists</span>
            <strong className="metricValue">{formatNumber(adminStatus?.totals?.playlists)}</strong>
            <small className="metricMeta">{formatNumber(adminStatus?.totals?.tracks)} tracks</small>
          </article>
          <article>
            <span className="metricLabel">Queue</span>
            <strong className="metricValue">{formatNumber((adminStatus?.queue?.pending || 0) + (adminStatus?.queue?.running || 0))}</strong>
            <small className="metricMeta">{formatNumber(adminStatus?.queue?.failed)} failed</small>
          </article>
        </div>

        <div className="adminGrid">
          <section className="dashboardPanel adminQueuePanel">
            <div className="panelHeader">
              <div>
                <h2>Queue Health</h2>
                <p>Pending and running sync work across all users.</p>
              </div>
              <span className={adminStatus?.queue?.failed ? "adminBadge adminBadge--danger" : "adminBadge"}>{formatNumber(adminStatus?.queue?.failed)} failed</span>
            </div>
            <div className="healthGrid">
              <article><span>Pending</span><strong>{formatNumber(adminStatus?.queue?.pending)}</strong><small>{adminStatus?.queue?.oldest_pending_at ? `oldest ${formatShortDate(String(adminStatus.queue.oldest_pending_at).slice(0, 10))}` : "none waiting"}</small></article>
              <article><span>Running</span><strong>{formatNumber(adminStatus?.queue?.running)}</strong><small>{formatNumber(adminStatus?.locks?.active)} active locks</small></article>
              <article><span>Stale</span><strong>{formatNumber(adminStatus?.sync?.stale_24h)}</strong><small>{formatNumber(adminStatus?.sync?.needs_sync)} need sync</small></article>
              <article><span>Snapshots</span><strong>{formatNumber(adminStatus?.sync?.with_recent_snapshots)}</strong><small>{formatNumber(adminStatus?.sync?.without_recent_snapshots)} missing 7d</small></article>
            </div>
            <div className="jobTypeGrid">
              {Object.entries(adminStatus?.queue?.by_type || {}).map(([key, value]) => (
                <div key={key}>
                  <span>{key.replace(":", " · ")}</span>
                  <strong>{formatNumber(value)}</strong>
                </div>
              ))}
              {!Object.keys(adminStatus?.queue?.by_type || {}).length ? <p>No active jobs.</p> : null}
            </div>
          </section>

          <section className="dashboardPanel adminQueuePanel">
            <div className="panelHeader">
              <div>
                <h2>Sync State</h2>
                <p>Playlist freshness and automation contention.</p>
              </div>
            </div>
            <div className="adminStateList">
              <div><span>Needs sync</span><strong>{formatNumber(adminStatus?.sync?.needs_sync)}</strong></div>
              <div><span>Currently syncing</span><strong>{formatNumber(adminStatus?.sync?.syncing)}</strong></div>
              <div><span>Safe edit cooldown</span><strong>{formatNumber(adminStatus?.sync?.in_cooldown)}</strong></div>
              <div><span>Playlist errors</span><strong>{formatNumber(adminStatus?.sync?.error_count)}</strong></div>
              <div><span>Active locks</span><strong>{formatNumber(adminStatus?.locks?.active)}</strong></div>
              <div><span>Expired locks</span><strong>{formatNumber(adminStatus?.locks?.expired)}</strong></div>
            </div>
          </section>
        </div>

        <div className="adminGrid adminGrid--wide">
          <section className="dashboardPanel">
            <div className="panelHeader">
              <div>
                <h2>Recent Jobs</h2>
                <p>Latest worker lifecycle events.</p>
              </div>
            </div>
            <div className="adminTable">
              {(adminStatus?.recent_jobs || []).map((job) => (
                <div key={job.id}>
                  <span className={`jobStatus jobStatus--${job.status}`}>{job.status}</span>
                  <strong>{job.job_type}</strong>
                  <span>{job.scope_type}:{String(job.scope_id || "").slice(0, 8)}</span>
                  <span>{formatNumber(job.attempts)} attempts</span>
                  <small>{job.last_error || job.completed_at || job.updated_at}</small>
                </div>
              ))}
              {!adminStatus?.recent_jobs?.length ? <p>No recent jobs.</p> : null}
            </div>
          </section>

          <section className="dashboardPanel">
            <div className="panelHeader">
              <div>
                <h2>Failed Jobs</h2>
                <p>Failures that need attention or automatic retry review.</p>
              </div>
            </div>
            <div className="adminTable">
              {(adminStatus?.failed_jobs || []).map((job) => (
                <div key={job.id}>
                  <span className="jobStatus jobStatus--failed">failed</span>
                  <strong>{job.job_type}</strong>
                  <span>{formatNumber(job.attempts)} attempts</span>
                  <small>{job.last_error || "No error message"}</small>
                </div>
              ))}
              {!adminStatus?.failed_jobs?.length ? <p>No failed jobs.</p> : null}
            </div>
          </section>
        </div>

        <div className="adminGrid adminGrid--wide">
          <section className="dashboardPanel">
            <div className="panelHeader">
              <div>
                <h2>Locks</h2>
                <p>Active mutexes protecting playlist and connection writes.</p>
              </div>
            </div>
            <div className="adminTable">
              {(adminStatus?.locks?.items || []).map((lock) => (
                <div key={lock.lock_key}>
                  <span className="jobStatus jobStatus--running">lock</span>
                  <strong>{lock.lock_key}</strong>
                  <span>{lock.owner?.split(":")?.[0] || "worker"}</span>
                  <small>expires {lock.expires_at ? new Date(lock.expires_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "unknown"}</small>
                </div>
              ))}
              {!adminStatus?.locks?.items?.length ? <p>No active locks.</p> : null}
            </div>
          </section>

          <section className="dashboardPanel">
            <div className="panelHeader">
              <div>
                <h2>Recent Connections</h2>
                <p>Newest Spotify accounts connected to the platform.</p>
              </div>
            </div>
            <div className="adminTable">
              {(adminStatus?.recent_connections || []).map((connection) => (
                <div key={connection.id}>
                  <span className={connection.is_active === false ? "jobStatus jobStatus--failed" : "jobStatus jobStatus--done"}>{connection.is_active === false ? "off" : "active"}</span>
                  <strong>{connection.display_name || connection.spotify_user_id || "Spotify Account"}</strong>
                  <span>{String(connection.bubble_user_id || "").slice(0, 16)}</span>
                  <small>{connection.created_at ? formatShortDate(String(connection.created_at).slice(0, 10)) : ""}</small>
                </div>
              ))}
              {!adminStatus?.recent_connections?.length ? <p>No recent connections.</p> : null}
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
            {busy ? (
              <span><i className="miniSpinner" aria-hidden="true" />{busyLabel || "Working with Spotify"}</span>
            ) : pendingPlaylistEdits > 0 ? (
              <span><i className="miniSpinner" aria-hidden="true" />Saving {pendingPlaylistEdits} playlist {pendingPlaylistEdits === 1 ? "change" : "changes"}</span>
            ) : message ? <span>{message}</span> : <span />}
            {error ? <strong>{error}</strong> : null}
          </div>

          <div className="playlistHeader">
            <Artwork src={playlist?.image} alt="" size="xl" />
            <div>
              <h2>Selected Playlist</h2>
              <h3>{playlistLoading && !playlist ? "Loading playlist..." : playlist?.name || "No playlist selected"}</h3>
              <p>
                {playlistLoading && !playlist
                  ? "Fetching playlist details and tracks from Spotify"
                  : `${formatNumber(playlist?.tracks_total)} Tracks · ${formatNumber(playlist?.followers)} Followers`}
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
                  ["expiry", "Cleanup"],
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
                    <div className="cleanupIntro addSongIntro">
                      <div>
                        <h2>Add song</h2>
                        <p>Add a released Spotify track now, or schedule an unreleased song for release day.</p>
                      </div>
                      <div className="cleanupStatus">
                        <strong>{futureAdds.filter((item) => item.status === "pending").length}</strong>
                        <span>scheduled</span>
                      </div>
                    </div>
                    <div className="addSongCards">
                      <section className="cleanupRuleCard addNowCard isActive">
                        <div className="cleanupRuleHeader">
                          <span className="cleanupRuleIcon"><ListEnd aria-hidden="true" /></span>
                          <div>
                            <h3>Add now</h3>
                            <p>Search Spotify or paste a track link. Position defaults to 1 when empty.</p>
                          </div>
                        </div>
                        <div className="cleanupRuleControls">
                          <div className="addNowGrid">
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
                            <button disabled={busy || !playlistId || !trackLink.trim()} onClick={addTrack}>Add now</button>
                          </div>
                        </div>
                      </section>

                      <section className={`cleanupRuleCard futureAddCard ${futureAddEnabled ? "isActive" : ""}`}>
                        <div className="cleanupRuleHeader">
                          <span className="cleanupRuleIcon"><TimerReset aria-hidden="true" /></span>
                          <div>
                            <h3>Future add</h3>
                            <p>On release day PlaylistPilot searches Spotify, verifies the best match, and adds it automatically.</p>
                          </div>
                          <label className="cleanupSwitch">
                            <input
                              type="checkbox"
                              checked={futureAddEnabled}
                              onChange={(e) => setFutureAddEnabled(e.target.checked)}
                            />
                            <span aria-hidden="true" />
                            <em>{futureAddEnabled ? "On" : "Off"}</em>
                          </label>
                        </div>
                        {futureAddEnabled ? (
                          <div className="cleanupRuleControls">
                            <div className="futureAddGrid">
                              <label className="compactField">
                                <span>Release date</span>
                                <input type="date" value={futureAddForm.release_date} onChange={(e) => setFutureAddForm((current) => ({ ...current, release_date: e.target.value }))} />
                              </label>
                              <label className="compactField">
                                <span>Artist</span>
                                <input value={futureAddForm.artist_name} onChange={(e) => setFutureAddForm((current) => ({ ...current, artist_name: e.target.value }))} placeholder="Artist name" />
                              </label>
                              <label className="compactField">
                                <span>Song title</span>
                                <input value={futureAddForm.track_title} onChange={(e) => setFutureAddForm((current) => ({ ...current, track_title: e.target.value }))} placeholder="Song title" />
                              </label>
                              <label className="compactField">
                                <span>Position</span>
                                <input value={futureAddForm.position} onChange={(e) => setFutureAddForm((current) => ({ ...current, position: e.target.value }))} placeholder="Optional" inputMode="numeric" />
                              </label>
                            </div>
                            <p className="cleanupHint">If the match is unclear, PlaylistPilot marks it as not found instead of adding the wrong song.</p>
                            <div className="toolActions">
                              <button disabled={busy || !playlistId || !futureAddForm.release_date || !futureAddForm.artist_name.trim() || !futureAddForm.track_title.trim()} onClick={createFutureAdd}>Schedule add</button>
                              <button className="secondaryOutline" disabled={busy || !playlistId} onClick={loadFutureAdds}>Refresh queue</button>
                            </div>
                          </div>
                        ) : null}
                      </section>
                    </div>
                    <div className="futureAddList addToolFutureList">
                      {futureAdds.map((item) => (
                        <article className={`futureAddItem futureAddItem--${item.status}`} key={item.id}>
                          <div>
                            <strong>{item.track_title}</strong>
                            <span>{item.artist_name}</span>
                            <small>{formatShortDate(item.release_date)}{item.target_position ? ` · pos ${item.target_position}` : ""}</small>
                          </div>
                          <em>{item.status}</em>
                          {item.status === "added" ? <small>{item.spotify_track_name || item.spotify_track_uri}</small> : item.last_error ? <small>{item.last_error}</small> : <small />}
                          {item.status === "pending" ? <button className="smallOutlineButton danger" disabled={busy} onClick={() => deleteFutureAdd(item)}>Remove</button> : null}
                        </article>
                      ))}
                      {!futureAdds.length ? <p className="emptyToolState">No future adds scheduled for this playlist yet.</p> : null}
                    </div>
                  </>
                ) : null}
                {activeTool === "expiry" ? (
                  <>
                    <div className="cleanupIntro">
                      <div>
                        <h2>Cleanup</h2>
                        <p>Choose how PlaylistPilot keeps this playlist fresh. Locked tracks are always protected.</p>
                      </div>
                      <div className="cleanupStatus">
                        <strong>{Number(autoExpiryEnabled) + Number(trackLimitEnabled)}</strong>
                        <span>active rules</span>
                      </div>
                    </div>
                    <div className="cleanupRules">
                      <section className={`cleanupRuleCard ${autoExpiryEnabled ? "isActive" : ""}`}>
                        <div className="cleanupRuleHeader">
                          <span className="cleanupRuleIcon"><TimerReset aria-hidden="true" /></span>
                          <div>
                            <h3>Weekly expiry</h3>
                            <p>Remove unlocked tracks after they reach the selected age.</p>
                          </div>
                          <label className="cleanupSwitch">
                            <input
                              type="checkbox"
                              checked={autoExpiryEnabled}
                              onChange={(e) => setAutoExpiryEnabled(e.target.checked)}
                            />
                            <span aria-hidden="true" />
                            <em>{autoExpiryEnabled ? "On" : "Off"}</em>
                          </label>
                        </div>
                        <div className="cleanupRuleControls">
                          <label className="compactField">
                            <span>Remove tracks after</span>
                            <div className="inlineNumberField">
                              <input type="number" min="1" max="104" value={autoWeeks} onChange={(e) => setAutoWeeks(e.target.value)} disabled={!autoExpiryEnabled} />
                              <small>weeks</small>
                            </div>
                          </label>
                          <p className="cleanupHint">A manual expiry set directly on a song takes priority over this playlist default.</p>
                        </div>
                      </section>

                      <section className={`cleanupRuleCard ${trackLimitEnabled ? "isActive" : ""}`}>
                        <div className="cleanupRuleHeader">
                          <span className="cleanupRuleIcon"><ListEnd aria-hidden="true" /></span>
                          <div>
                            <h3>Playlist size limit</h3>
                            <p>Automatically trim unlocked tracks when the playlist becomes too large.</p>
                          </div>
                          <label className="cleanupSwitch">
                            <input
                              type="checkbox"
                              checked={trackLimitEnabled}
                              onChange={(e) => setTrackLimitEnabled(e.target.checked)}
                            />
                            <span aria-hidden="true" />
                            <em>{trackLimitEnabled ? "On" : "Off"}</em>
                          </label>
                        </div>
                        <div className="cleanupRuleControls">
                          <div className="trackLimitGrid">
                            <label className="compactField">
                              <span>Maximum tracks</span>
                              <input
                                type="number"
                                min="1"
                                max="10000"
                                value={trackLimitCount}
                                onChange={(e) => setTrackLimitCount(e.target.value)}
                                placeholder="100"
                                disabled={!trackLimitEnabled}
                              />
                            </label>
                            <label className="compactField">
                              <span>When over the limit</span>
                              <select value={trackLimitStrategy} onChange={(e) => setTrackLimitStrategy(e.target.value)}>
                                <option value="back">Remove tracks from the bottom</option>
                                <option value="oldest">Remove oldest additions first</option>
                              </select>
                            </label>
                          </div>
                          <p className="cleanupHint">If locked tracks prevent reaching the limit, PlaylistPilot leaves them untouched.</p>
                        </div>
                      </section>
                    </div>
                    <div className="toolActions">
                      <button disabled={busy || !playlistId} onClick={saveAutoRemoval}>Save changes</button>
                      <button className="secondaryOutline" disabled={busy || !playlistId || (!autoExpiryEnabled && !trackLimitEnabled)} onClick={cleanupNow}>Run cleanup now</button>
                    </div>
                  </>
                ) : null}
                {activeTool === "flex" ? (
                  <>
                    <div className="cleanupIntro rotatorIntro">
                      <div>
                        <h2>Track Rotator</h2>
                        <p>Automatically refresh selected track positions using songs from a reference playlist.</p>
                      </div>
                      <div className="cleanupStatus">
                        <strong>{flexSlots.length}</strong>
                        <span>rotation slots</span>
                      </div>
                    </div>
                    <div className="rotatorCards">
                      <section className={`cleanupRuleCard rotatorSettingsCard ${flexEnabled ? "isActive" : ""}`}>
                        <div className="cleanupRuleHeader">
                          <span className="cleanupRuleIcon"><Shuffle aria-hidden="true" /></span>
                          <div>
                            <h3>Rotation source</h3>
                            <p>Choose the playlist and schedule used to refresh your rotation slots.</p>
                          </div>
                          <label className="cleanupSwitch">
                            <input type="checkbox" checked={flexEnabled} onChange={(e) => setFlexEnabled(e.target.checked)} />
                            <span aria-hidden="true" />
                            <em>{flexEnabled ? "On" : "Off"}</em>
                          </label>
                        </div>
                        <div className="cleanupRuleControls">
                          <div className="flexSettings">
                            <label className="compactField rotatorSourceField">
                              <span>Reference playlist</span>
                              <input value={flexReference} onChange={(e) => { setFlexReference(e.target.value); setFlexReferenceIssue(null); }} placeholder="Paste a Spotify playlist link" />
                            </label>
                            <label className="compactField">
                              <span>Rotation schedule</span>
                              <select value={flexInterval} onChange={(e) => setFlexInterval(e.target.value)}>
                                <option value="daily">Daily</option>
                                <option value="weekly">Weekly</option>
                                <option value="monthly">Monthly</option>
                              </select>
                            </label>
                          </div>
                        </div>
                      </section>
                      <section className="cleanupRuleCard rotatorSettingsCard">
                        <div className="cleanupRuleHeader">
                          <span className="cleanupRuleIcon"><Settings aria-hidden="true" /></span>
                          <div>
                            <h3>Selection rules</h3>
                            <p>Control which tracks can be selected and how often they may return.</p>
                          </div>
                        </div>
                        <div className="cleanupRuleControls">
                          <label className="toggleField rotatorDuplicateToggle">
                            <input type="checkbox" checked={flexAvoidDuplicates} onChange={(e) => setFlexAvoidDuplicates(e.target.checked)} />
                            Skip songs already in target playlist
                          </label>
                          <div className="rotatorRules">
                            <input value={flexRepeatWeeks} onChange={(e) => setFlexRepeatWeeks(e.target.value)} placeholder="No repeat weeks" inputMode="numeric" />
                            <input value={flexMaxReleaseAgeWeeks} onChange={(e) => setFlexMaxReleaseAgeWeeks(e.target.value)} placeholder="Max release age weeks" inputMode="numeric" />
                            <input value={flexMinPopularity} onChange={(e) => setFlexMinPopularity(e.target.value)} placeholder="Min popularity" inputMode="numeric" />
                            <input value={flexMaxPopularity} onChange={(e) => setFlexMaxPopularity(e.target.value)} placeholder="Max popularity" inputMode="numeric" />
                          </div>
                        </div>
                      </section>
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
                    <div className="toolActions">
                      <button className="tooltipButton" data-tooltip="Save the reference playlist, schedule, status, and selection rules." disabled={busy || !playlistId} onClick={saveFlexSettings}>
                        Save changes
                      </button>
                    </div>
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
                        <p>PlaylistPilot keeps up to 5 useful restore points per playlist: the latest manual backup plus snapshots at least one day, one week, one month and six months old. Historical points appear as the backup history grows.</p>
                      </div>
                      <button className="tooltipButton" data-tooltip="Fetch the current Spotify order and store it as a restorable snapshot." disabled={busy || !playlistId} onClick={createBackupNow}>
                        Create backup
                      </button>
                    </div>
                    <div className="backupActions">
                      <button className="smallOutlineButton" disabled={busy || !playlistId} onClick={cleanupDuplicateBackups}>Clean duplicates</button>
                      <button className="smallOutlineButton" disabled={busy || !playlistId} onClick={applyBackupRetention}>Compact backups</button>
                    </div>
                    <div className="backupList">
                      {backupSlots.map((slot) => slot.backup ? (
                        <button
                          className={selectedBackupId === slot.backup.id ? "backupItem selected" : "backupItem"}
                          key={slot.key}
                          onClick={() => openBackupDetails(slot.backup)}
                          type="button"
                        >
                          <Artwork src={slot.backup.image || playlist?.image} alt="" size="sm" />
                          <span>
                            <b>{slot.label}</b>
                            <strong>{formatShortDate(String(slot.backup.taken_at || "").slice(0, 10)) || "Backup"}</strong>
                            <small>{formatNumber(slot.backup.tracks_total)} tracks · {slot.backup.snapshot_id ? `snapshot ${String(slot.backup.snapshot_id).slice(0, 8)}` : "no snapshot"}</small>
                          </span>
                        </button>
                      ) : (
                        <div className="backupItem backupItem--empty" key={slot.key}>
                          <span className="backupSlotMark" aria-hidden="true">{slot.label.slice(0, 1)}</span>
                          <span>
                            <b>{slot.label}</b>
                            <strong>Building history</strong>
                            <small>{slot.empty}</small>
                          </span>
                        </div>
                      ))}
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
                          {(backupDetail.tracks || []).slice(0, 5).map((track) => (
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
              {playlistLoading ? (
                <div className="trackLoadingState" role="status" aria-live="polite">
                  <span><i className="miniSpinner" aria-hidden="true" />Loading tracks</span>
                  {[0, 1, 2, 3, 4].map((item) => (
                    <div className="trackSkeleton" key={item}>
                      <i />
                      <b />
                      <span />
                      <em />
                    </div>
                  ))}
                </div>
              ) : null}
              {!playlistLoading && filteredTracks.map((track) => {
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
                      {isFlexTrack ? <span className="flexBadge">Rotator</span> : null}
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
              {!playlistLoading && playlistId && !filteredTracks.length ? (
                <div className="emptyTrackState">
                  <strong>No tracks loaded yet</strong>
                  <span>Refresh the playlist or wait for the Spotify sync to finish.</span>
                </div>
              ) : null}
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
        .setupProgress {
          position: relative;
          z-index: 24;
          display: grid;
          grid-template-columns: minmax(0, 1fr) auto;
          gap: 10px 20px;
          padding: 14px clamp(20px, 3vw, 40px) 16px;
          border-bottom: 1px solid rgba(24, 224, 111, 0.22);
          background: #151a20;
          box-shadow: 0 12px 34px rgba(0, 0, 0, 0.16);
        }
        .setupProgressHeader {
          grid-column: 1 / -1;
          display: flex;
          align-items: end;
          justify-content: space-between;
          gap: 20px;
        }
        .setupProgressHeader div {
          display: grid;
          gap: 2px;
        }
        .setupProgressHeader span,
        .setupProgressHeader small {
          color: #18e06f;
          font-size: 11px;
          font-weight: 850;
          text-transform: uppercase;
        }
        .setupProgressHeader strong {
          font-size: 16px;
        }
        .setupProgressTrack {
          grid-column: 1 / -1;
          height: 3px;
          overflow: hidden;
          border-radius: 3px;
          background: #29313b;
        }
        .setupProgressTrack span {
          display: block;
          height: 100%;
          border-radius: inherit;
          background: #18e06f;
          transition: width 240ms ease;
        }
        .setupProgressSteps {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 8px;
          min-width: 0;
          margin: 0;
          padding: 0;
          list-style: none;
        }
        .setupProgressSteps li {
          display: flex;
          align-items: center;
          gap: 8px;
          min-width: 0;
          color: #747e8b;
          font-size: 12px;
          font-weight: 750;
        }
        .setupProgressSteps li.active {
          color: #f4f6fb;
        }
        .setupProgressSteps li.done {
          color: #9eb2a6;
        }
        .setupProgressSteps b {
          display: grid;
          place-items: center;
          width: 24px;
          height: 24px;
          flex: 0 0 auto;
          border: 1px solid #35404c;
          border-radius: 50%;
          color: inherit;
          font-size: 11px;
        }
        .setupProgressSteps li.active b,
        .setupProgressSteps li.done b {
          border-color: #18e06f;
          color: #18e06f;
        }
        .setupProgressSteps span {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .setupProgress > button {
          align-self: center;
          min-width: 170px;
        }
        .spotifySetupAlert {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: 18px;
          width: min(1180px, calc(100% - 32px));
          margin: 14px auto 0;
          padding: 15px 16px;
          border: 1px solid #d9a441;
          border-radius: 8px;
          background: #211d15;
          color: #f4f6fb;
        }
        .spotifySetupAlert div {
          display: grid;
          gap: 4px;
        }
        .spotifySetupAlert p,
        .spotifySetupAlert small {
          margin: 0;
          color: #d8c9aa;
          line-height: 1.45;
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
          gap: 16px;
          align-content: center;
          justify-items: center;
          min-height: calc(100vh - 180px);
          padding: clamp(28px, 5vw, 72px);
        }
        .loginCard {
          width: min(760px, 100%);
          display: grid;
          gap: 22px;
          padding: clamp(26px, 4vw, 44px);
          border: 1px solid #2a303b;
          border-radius: 10px;
          background:
            linear-gradient(135deg, rgba(24, 224, 111, 0.12), rgba(24, 28, 35, 0) 42%),
            #181c23;
          box-shadow: 0 24px 80px rgba(0, 0, 0, 0.28);
        }
        .loginBrand {
          display: inline-flex;
          align-items: center;
          gap: 12px;
          color: #f4f6fb;
          font-size: 15px;
          font-weight: 900;
          letter-spacing: 0;
        }
        .loginBrand img {
          width: 42px;
          height: 42px;
          border-radius: 8px;
          object-fit: cover;
        }
        .loginCopy {
          display: grid;
          gap: 10px;
        }
        .loginCopy > span {
          color: #18e06f;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .loginScreen h2 {
          max-width: 650px;
          font-size: clamp(34px, 5vw, 58px);
          line-height: 0.98;
        }
        .loginScreen p {
          max-width: 620px;
          color: #a6adba;
          font-size: 18px;
          line-height: 1.5;
        }
        .authModeTabs {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 4px;
          padding: 4px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #101318;
        }
        .authModeTabs button {
          border-color: transparent;
          background: transparent;
          color: #929ba8;
        }
        .authModeTabs button.active {
          border-color: rgba(24, 224, 111, 0.45);
          background: rgba(24, 224, 111, 0.1);
          color: #18e06f;
        }
        .emailAuthForm {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 12px;
        }
        .emailAuthForm label {
          display: grid;
          gap: 7px;
          min-width: 0;
        }
        .emailAuthForm label > span {
          color: #c8ced8;
          font-size: 12px;
          font-weight: 800;
        }
        .emailAuthForm input {
          width: 100%;
          min-width: 0;
          min-height: 46px;
        }
        .turnstileWrap,
        .authNotice,
        .authError,
        .authUnavailable,
        .emailAuthActions {
          grid-column: 1 / -1;
        }
        .turnstileWrap {
          min-height: 65px;
          overflow: hidden;
        }
        .authNotice,
        .authError,
        .authUnavailable {
          padding: 10px 12px;
          border-radius: 6px;
          line-height: 1.4;
        }
        .authNotice {
          border: 1px solid #2c6041;
          background: #14231b;
          color: #bfe8ce;
        }
        .authError,
        .authUnavailable {
          border: 1px solid #65363b;
          background: #25171a;
          color: #ffb8bd;
        }
        .emailAuthActions {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
        }
        .textButton {
          padding: 8px 0;
          border: 0;
          background: transparent;
          color: #a6adba;
        }
        .textButton:hover {
          color: #18e06f;
        }
        .authDivider {
          display: flex;
          align-items: center;
          gap: 12px;
          color: #6f7886;
          font-size: 12px;
          text-transform: uppercase;
        }
        .authDivider::before,
        .authDivider::after {
          content: "";
          height: 1px;
          flex: 1;
          background: #2a303b;
        }
        .passwordRecoveryPanel {
          width: min(460px, calc(100% - 32px));
          display: grid;
          gap: 14px;
          padding: 26px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #181c23;
          box-shadow: 0 24px 80px rgba(0, 0, 0, 0.45);
        }
        .passwordRecoveryPanel > span {
          color: #18e06f;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .passwordRecoveryPanel p {
          margin: 0;
          color: #a6adba;
          line-height: 1.5;
        }
        .googleLoginButton {
          justify-self: start;
          display: inline-flex;
          align-items: center;
          gap: 10px;
          min-height: 48px;
          padding: 0 18px;
          border-color: rgba(24, 224, 111, 0.5);
          background: #18e06f;
          color: #07110b;
          font-weight: 900;
        }
        .googleLoginButton span {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 24px;
          height: 24px;
          border-radius: 999px;
          background: #f4fff8;
          color: #11161d;
          font-weight: 900;
        }
        .loginMetaGrid {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 10px;
          padding-top: 4px;
        }
        .loginMetaGrid article {
          display: grid;
          gap: 5px;
          padding: 12px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: #101318;
        }
        .loginMetaGrid strong {
          color: #f4f6fb;
          font-size: 13px;
        }
        .loginMetaGrid small {
          color: #a6adba;
          line-height: 1.4;
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
        .premiumRequirement {
          display: grid;
          gap: 5px;
          padding: 13px 14px;
          border: 1px solid #2c6041;
          border-radius: 8px;
          background: #14231b;
        }
        .premiumRequirement strong {
          color: #18e06f;
        }
        .premiumRequirement p {
          margin: 0;
          color: #c1cdc5;
          font-size: 13px;
        }
        .settingsSpotifyNotice {
          margin-top: 2px;
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
        @keyframes shimmer {
          0% { background-position: 120% 0; }
          100% { background-position: -120% 0; }
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
        .settingsSection--setupActive {
          border-color: rgba(24, 224, 111, 0.58);
          box-shadow: inset 0 0 0 1px rgba(24, 224, 111, 0.08), 0 0 30px rgba(24, 224, 111, 0.06);
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
        .settingsHeaderActions {
          display: flex;
          flex-wrap: wrap;
          justify-content: flex-end;
          gap: 8px;
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
        .dashboard,
        .adminPanel {
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
        .dashboardSubnav {
          display: inline-flex;
          justify-self: start;
          gap: 4px;
          padding: 4px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #11161d;
        }
        .dashboardSubnav button {
          min-height: 36px;
          padding: 0 14px;
          border: 0;
          border-radius: 6px;
          background: transparent;
          color: #a6adba;
          font-size: 13px;
          font-weight: 900;
        }
        .dashboardSubnav button.active {
          background: rgba(24, 224, 111, 0.12);
          color: #18e06f;
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
        .metricGrid--primary {
          grid-template-columns: repeat(4, minmax(0, 1fr));
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
          grid-template-rows: 20px minmax(38px, auto) 18px;
          gap: 8px;
          min-height: 132px;
          align-content: center;
        }
        .metricLabel {
          color: #a6adba;
          font-size: 12px;
          font-weight: 700;
          line-height: 1.2;
          text-transform: uppercase;
        }
        .metricValue {
          align-self: center;
          font-size: 30px;
          line-height: 1.05;
          letter-spacing: 0;
        }
        .metricMeta {
          color: #7f8794;
          font-size: 13px;
          line-height: 1.25;
        }
        .automationHealth {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 14px;
        }
        .automationHealth article {
          display: grid;
          gap: 7px;
          padding: 14px 16px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: #12161d;
        }
        .automationHealth span {
          color: #a6adba;
          font-size: 12px;
          font-weight: 800;
          text-transform: uppercase;
        }
        .automationHealth strong {
          font-size: 18px;
          line-height: 1.2;
        }
        .automationHealth small {
          color: #7f8794;
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
        .performanceHeroRow {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 14px;
        }
        .performanceHeroCard {
          display: grid;
          align-content: center;
          justify-items: start;
          gap: 7px;
          min-height: 132px;
          padding: 18px;
          border: 1px solid rgba(24, 224, 111, 0.32);
          border-radius: 8px;
          background: linear-gradient(135deg, rgba(24, 224, 111, 0.12), #181c23 54%);
          color: #f4f6fb;
          text-align: left;
          min-width: 0;
        }
        .performanceHeroCard:hover:not(:disabled),
        .performanceHeroCard:focus-visible:not(:disabled) {
          border-color: rgba(24, 224, 111, 0.72);
          background: linear-gradient(135deg, rgba(24, 224, 111, 0.16), #1b2028 54%);
        }
        .performanceHeroCard span {
          color: #18e06f;
          font-size: 11px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .performanceHeroCard strong,
        .performanceHeroCard small {
          max-width: 100%;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .performanceHeroCard strong {
          font-size: 18px;
          line-height: 1.18;
        }
        .performanceHeroCard small {
          color: #a6adba;
          font-size: 13px;
        }
        .performanceHeroCard--quiet {
          border-color: rgba(89, 180, 255, 0.32);
          background: linear-gradient(135deg, rgba(89, 180, 255, 0.11), #181c23 54%);
        }
        .performanceHeroCard--quiet span {
          color: #7cc7ff;
        }
        .performanceHeroCard--warning {
          border-color: rgba(255, 208, 102, 0.34);
          background: linear-gradient(135deg, rgba(255, 208, 102, 0.1), #181c23 54%);
        }
        .performanceHeroCard--warning span {
          color: #ffd066;
        }
        .performanceHeroCard--neutral {
          border-color: rgba(166, 173, 186, 0.24);
          background: #181c23;
        }
        .performanceHeroCard--neutral span {
          color: #a6adba;
        }
        .adPerformanceView {
          display: grid;
          gap: 18px;
        }
        .adControlGrid {
          display: grid;
          grid-template-columns: minmax(0, 1.35fr) minmax(280px, 0.65fr);
          gap: 14px;
          align-items: start;
        }
        .adControlGrid--single {
          grid-template-columns: minmax(0, 1fr);
        }
        .adEventPanel,
        .adInsightsPanel {
          display: grid;
          gap: 14px;
        }
        .adEventForm {
          display: grid;
          grid-template-columns: minmax(260px, 1.5fr) 170px 170px minmax(220px, 1fr) 150px;
          gap: 10px;
          align-items: start;
        }
        .adEventForm select,
        .adEventForm input,
        .adEventForm textarea {
          min-height: 42px;
          width: 100%;
          border: 1px solid #2a303b;
          background: #101318;
          color: #f4f6fb;
        }
        .adEventForm textarea {
          grid-column: 1 / 5;
          min-height: 88px;
          resize: vertical;
        }
        .adEventForm textarea::placeholder,
        .adEventForm input::placeholder {
          color: #7f8794;
        }
        .adEventForm button {
          min-height: 42px;
          align-self: end;
        }
        .adInsightList {
          display: grid;
          gap: 10px;
        }
        .adInsightList article {
          display: grid;
          gap: 5px;
          padding: 12px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: #101318;
        }
        .adInsightList span {
          color: #18e06f;
          font-size: 11px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .adInsightList strong {
          color: #f4f6fb;
        }
        .adInsightList small {
          color: #a6adba;
        }
        .adPlaylistGrid {
          display: grid;
          grid-template-columns: minmax(0, 1fr);
          gap: 14px;
        }
        .adPlaylistCard {
          display: grid;
          gap: 12px;
          padding: 16px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #181c23;
          min-width: 0;
          overflow: hidden;
        }
        .adPlaylistHeader {
          display: flex;
          gap: 12px;
          align-items: center;
          min-width: 0;
        }
        .adPlaylistHeader span {
          display: grid;
          gap: 3px;
          min-width: 0;
        }
        .adPlaylistHeader strong,
        .adPlaylistHeader small {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .adPlaylistHeader small {
          color: #a6adba;
        }
        .adPlaylistSectionHeader {
          display: flex;
          justify-content: space-between;
          align-items: end;
          gap: 10px;
          flex-wrap: wrap;
          padding: 4px 2px 0;
        }
        .adPlaylistSectionHeader h2 {
          font-size: 22px;
        }
        .adPlaylistSectionHeader p {
          color: #a6adba;
          margin-top: 4px;
        }
        .adChart {
          width: 100%;
          height: 320px;
          min-height: 320px;
          min-width: 0;
          overflow: hidden;
          border-radius: 8px;
          background: rgba(18, 22, 29, 0.42);
        }
        .adDualChartGrid {
          display: grid;
          grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
          gap: 12px;
        }
        .adDualChartGrid section {
          display: grid;
          gap: 8px;
          min-width: 0;
          overflow: hidden;
        }
        .adDualChartGrid section > span {
          color: #a6adba;
          font-size: 11px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .adMiniGrowthChart :global(.growthChart) {
          height: 320px;
          min-height: 320px;
          margin-top: 0;
        }
        :global(.adChartSvg) {
          display: block;
          width: 100%;
          height: 100%;
        }
        .adChart--empty {
          display: grid;
          place-items: center;
          color: #a6adba;
          font-size: 13px;
          font-weight: 800;
        }
        .adPlaylistStats {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 8px;
        }
        .adPlaylistStats--details {
          grid-template-columns: repeat(3, minmax(0, 1fr));
        }
        .adPlaylistStats span {
          padding: 8px 10px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: #101318;
          color: #a6adba;
          font-size: 12px;
          font-weight: 800;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .adEventList {
          display: grid;
          gap: 6px;
        }
        .adEventList div {
          display: grid;
          grid-template-columns: minmax(120px, 0.55fr) minmax(0, 1fr) auto;
          gap: 8px;
          align-items: center;
          padding-top: 8px;
          border-top: 1px solid #202630;
        }
        .adEventList span,
        .adEventList strong {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .adEventList span {
          color: #7cc7ff;
          font-size: 12px;
          font-weight: 800;
        }
        .adEventList strong {
          color: #f4f6fb;
          font-size: 13px;
        }
        .adEventList button {
          min-height: 30px;
          padding: 0 10px;
          border-color: rgba(255, 77, 77, 0.45);
          color: #ff6b6b;
          background: transparent;
        }
        .adEmptyState {
          grid-column: 1 / -1;
        }
        .adminGrid {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 14px;
          align-items: start;
        }
        .adminGrid--wide {
          grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
        }
        .adminQueuePanel {
          min-height: 310px;
        }
        .adminBadge {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          min-width: 74px;
          min-height: 34px;
          padding: 7px 10px;
          border: 1px solid rgba(24, 224, 111, 0.45);
          border-radius: 999px;
          color: #18e06f;
          background: rgba(24, 224, 111, 0.08);
          font-weight: 900;
          font-size: 13px;
        }
        .adminBadge--danger {
          border-color: rgba(255, 77, 77, 0.48);
          color: #ff6b6b;
          background: rgba(255, 77, 77, 0.08);
        }
        .jobTypeGrid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
          gap: 10px;
          margin-top: 14px;
        }
        .jobTypeGrid div,
        .adminStateList div {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
          min-height: 44px;
          padding: 10px 12px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #151920;
        }
        .jobTypeGrid span,
        .adminStateList span {
          min-width: 0;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          color: #a6adba;
          font-size: 13px;
        }
        .jobTypeGrid strong,
        .adminStateList strong {
          color: #f4f6fb;
          font-size: 18px;
        }
        .adminStateList {
          display: grid;
          gap: 10px;
        }
        .adminTable {
          display: grid;
          gap: 8px;
          margin-top: 14px;
        }
        .adminTable div {
          display: grid;
          grid-template-columns: 82px minmax(140px, 1fr) minmax(90px, 0.7fr) minmax(90px, 0.8fr);
          align-items: center;
          gap: 10px;
          min-height: 48px;
          padding: 10px 12px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #151920;
        }
        .adminTable strong,
        .adminTable span,
        .adminTable small {
          min-width: 0;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .adminTable strong {
          color: #f4f6fb;
          font-size: 14px;
        }
        .adminTable small,
        .adminTable span {
          color: #a6adba;
          font-size: 12px;
        }
        .metaTitleLine {
          display: flex;
          align-items: center;
          gap: 10px;
          flex-wrap: wrap;
        }
        .metaTitleLine h2 {
          margin: 0;
        }
        .metaReadOnlyBadge {
          padding: 6px 9px;
          border: 1px solid #39414e;
          border-radius: 999px;
          color: #a6adba;
          font-size: 11px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .metaMetricText {
          font-size: 25px;
          text-transform: capitalize;
        }
        .metaSetupGrid {
          display: grid;
          grid-template-columns: minmax(0, 1.35fr) minmax(320px, 0.65fr);
          gap: 14px;
          align-items: stretch;
        }
        .metaConnectionPanel,
        .metaAuditPanel {
          min-width: 0;
        }
        .metaFormGrid {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 12px;
          margin-top: 16px;
        }
        .metaFormGrid label {
          display: grid;
          gap: 7px;
          min-width: 0;
        }
        .metaFormGrid label > span {
          color: #a6adba;
          font-size: 12px;
          font-weight: 800;
        }
        .metaFormGrid label > span small {
          color: #707987;
          font-weight: 600;
        }
        .metaFormGrid input {
          width: 100%;
          min-width: 0;
        }
        .metaFormWide {
          grid-column: 1 / -1;
        }
        .adsWorkspaceNav {
          display: flex;
          gap: 6px;
          margin: 0 0 18px;
          padding: 5px;
          border: 1px solid #292f38;
          border-radius: 10px;
          background: #12161c;
        }
        .adsWorkspaceNav button {
          flex: 0 1 170px;
          border: 0;
          background: transparent;
          color: #8d96a4;
        }
        .adsWorkspaceNav button.active {
          color: #07140c;
          background: #18e06f;
        }
        .creativeStudioHero {
          display: grid;
          grid-template-columns: minmax(0, 1.15fr) minmax(460px, 0.85fr);
          gap: 28px;
          align-items: center;
          overflow: hidden;
          background: radial-gradient(circle at 90% 0%, rgba(24, 224, 111, 0.14), transparent 36%), #171b22;
        }
        .creativeStudioHero h2 { max-width: 720px; margin: 16px 0 8px; font-size: clamp(26px, 3vw, 42px); }
        .creativeStudioHero p { max-width: 760px; margin: 0; color: #9aa3b1; line-height: 1.65; }
        .creativePipeline { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin: 0; padding: 0; list-style: none; }
        .creativePipeline li { display: grid; grid-template-columns: 26px minmax(0, 1fr); align-items: center; gap: 8px; padding: 10px; border: 1px solid #303744; border-radius: 8px; background: rgba(10, 13, 18, 0.55); }
        .creativePipeline b { display: grid; place-items: center; width: 26px; height: 26px; border-radius: 50%; color: #07140c; background: #18e06f; font-size: 11px; }
        .creativePipeline span { color: #c7cdd6; font-size: 11px; font-weight: 800; }
        .creativeStudioGrid { display: grid; grid-template-columns: minmax(340px, 0.78fr) minmax(0, 1.22fr); gap: 16px; margin-top: 16px; align-items: start; }
        .creativePlaylistSeed { display: flex; align-items: center; gap: 12px; margin-top: 14px; padding: 12px; border: 1px solid rgba(24, 224, 111, 0.3); border-radius: 9px; background: rgba(24, 224, 111, 0.04); }
        .creativePlaylistSeed div { display: grid; gap: 3px; min-width: 0; }
        .creativePlaylistSeed span, .creativePlaylistSeed small { color: #7f8998; font-size: 11px; }
        .creativeProjectCards { display: grid; gap: 10px; }
        .creativeProjectCards > article { display: grid; gap: 0; border: 1px solid #303744; border-radius: 10px; background: #11151b; overflow: hidden; }
        .creativeProjectCards > article.isOpen { border-color: rgba(24, 224, 111, 0.42); }
        .creativeProjectSummary { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: center; gap: 14px; padding: 13px; }
        .creativeProjectCopy { display: grid; gap: 7px; min-width: 0; }
        .creativeProjectCopy > div:first-child { display: grid; gap: 3px; }
        .creativeProjectCopy > div:first-child span { color: #18e06f; font-size: 9px; font-weight: 900; letter-spacing: 0.08em; text-transform: uppercase; }
        .creativeProjectCopy > small { color: #7f8998; }
        .creativeProjectMetrics { display: flex; gap: 16px; }
        .creativeProjectMetrics b { display: grid; color: #f2f5f8; font-size: 14px; }
        .creativeProjectMetrics small { color: #707987; font-size: 9px; font-weight: 700; text-transform: uppercase; }
        .creativeProjectDetail { display: grid; gap: 14px; padding: 16px; border-top: 1px solid #303744; background: #0d1116; }
        .creativeBriefPanel { display: grid; gap: 8px; padding: 16px; border: 1px solid rgba(24, 224, 111, 0.24); border-radius: 10px; background: rgba(24, 224, 111, 0.035); }
        .creativeBriefPanel > span, .creativeConceptGrid article > span { color: #18e06f; font-size: 9px; font-weight: 900; letter-spacing: 0.09em; text-transform: uppercase; }
        .creativeBriefPanel h3, .creativeConceptGrid h3 { margin: 0; }
        .creativeBriefPanel p { margin: 0; color: #a5aebb; line-height: 1.55; }
        .creativeBriefPanel > div, .creativeConceptTerms { display: flex; flex-wrap: wrap; gap: 6px; }
        .creativeBatchPanel { display: grid; gap: 13px; padding: 16px; border: 1px solid rgba(29, 185, 84, .42); border-radius: 11px; background: linear-gradient(135deg, rgba(29, 185, 84, .08), rgba(10, 14, 18, .95)); }
        .creativeBatchHeader { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
        .creativeBatchHeader h3 { margin: 3px 0; }
        .creativeBatchHeader p { margin: 0; color: #8994a2; }
        .creativeBatchHeader > div > span { color: #18e06f; font-size: 9px; font-weight: 900; text-transform: uppercase; }
        .creativeTemplateGrid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
        .creativeTemplateGrid label { display: flex; gap: 9px; padding: 11px; border: 1px solid #343d49; border-radius: 9px; cursor: pointer; background: #10151b; }
        .creativeTemplateGrid label.isSelected { border-color: #18e06f; background: rgba(24, 224, 111, .08); }
        .creativeTemplateGrid input { width: auto; align-self: start; }
        .creativeTemplateGrid label > span { display: grid; gap: 3px; }
        .creativeTemplateGrid small { color: #7f8998; line-height: 1.35; }
        .creativeBatchProgress { display: grid; gap: 6px; }
        .creativeBatchProgress > div { height: 7px; overflow: hidden; border-radius: 999px; background: #252d37; }
        .creativeBatchProgress > div > span { display: block; height: 100%; border-radius: inherit; background: #18e06f; transition: width .25s ease; }
        .creativeBatchProgress small { color: #8994a2; }
        .creativeMediaAutomation { display: grid; gap: 13px; padding: 16px; border: 1px solid rgba(91, 132, 255, .42); border-radius: 11px; background: linear-gradient(135deg, rgba(91, 132, 255, .09), rgba(10, 14, 18, .96)); }
        .creativeMediaAutomation .creativeBatchHeader > div > span { color: #88a5ff; }
        .creativeMediaAutomation .aiMediaButton { color: #081121; background: #88a5ff; }
        .creativeProjectMediaProgress { display: grid; gap: 6px; }
        .creativeProjectMediaProgress > div { height: 7px; overflow: hidden; border-radius: 999px; background: #252d37; }
        .creativeProjectMediaProgress > div > span { display: block; height: 100%; border-radius: inherit; background: #88a5ff; transition: width .25s ease; }
        .creativeProjectMediaProgress small { color: #8994a2; }
        .creativeProjectMediaReview { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; }
        .creativeProjectMediaReview > article { display: grid; grid-template-columns: 92px minmax(0, 1fr); gap: 10px; overflow: hidden; padding: 9px; border: 1px solid #303a4d; border-radius: 9px; background: #10151d; }
        .creativeProjectMediaReview > article.isApproved { border-color: rgba(24, 224, 111, .34); }
        .creativeProjectMediaReview > article.needsReview { border-color: rgba(255, 177, 64, .62); background: rgba(255, 177, 64, .045); }
        .creativeProjectMediaReview > article.needsReview article span, .creativeProjectMediaReview > article.needsReview span { color: #ffb140; }
        .creativeProjectMediaVisual { position: relative; min-height: 150px; overflow: hidden; border-radius: 7px; background: #080b10; }
        .creativeProjectMediaVisual img { width: 100%; height: 100%; object-fit: cover; }
        .creativeProjectMediaVisual b { position: absolute; top: 6px; left: 6px; padding: 5px 7px; border-radius: 7px; color: #07140c; background: #18e06f; font-size: 14px; }
        .creativeProjectMediaReview article > div:last-child { display: grid; align-content: start; gap: 5px; min-width: 0; }
        .creativeProjectMediaReview article span { color: #88a5ff; font-size: 8px; font-weight: 900; text-transform: uppercase; }
        .creativeProjectMediaReview h4 { margin: 0; }
        .creativeProjectMediaReview strong { color: #f3f6fa; font-size: 12px; }
        .creativeProjectMediaReview p { margin: 0; color: #9aa5b3; font-size: 9px; line-height: 1.4; }
        .creativeProjectMediaReview small { color: #778291; font-size: 8px; text-transform: uppercase; }
        .creativeProjectMediaReview select { width: 100%; min-width: 0; padding: 7px; font-size: 9px; }
        .creativeMediaReviewActions { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
        .creativeMediaReviewActions small { color: #8994a2; }
        .creativeBriefPanel b, .creativeConceptTerms b, .creativeConceptTerms button { padding: 5px 8px; border: 1px solid #343d49; border-radius: 999px; color: #aeb7c3; background: transparent; font-size: 9px; }
        .creativeConceptGrid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
        .creativeConceptGrid article { display: grid; align-content: start; gap: 9px; padding: 14px; border: 1px solid #303744; border-radius: 10px; background: #131820; }
        .creativeConceptGrid article.hasMedia { border-color: rgba(24, 224, 111, 0.38); }
        .creativeConceptGrid article > strong { color: #f4f7fa; font-size: 18px; line-height: 1.25; }
        .creativeConceptGrid article > p { margin: 0; color: #929daa; line-height: 1.5; }
        .creativeConceptGrid dl { display: grid; gap: 7px; margin: 2px 0; }
        .creativeConceptGrid dl div { display: grid; gap: 2px; }
        .creativeConceptGrid dt { color: #677282; font-size: 9px; font-weight: 800; text-transform: uppercase; }
        .creativeConceptGrid dd { margin: 0; color: #b8c0cb; font-size: 11px; line-height: 1.45; }
        .creativeMediaSearch { display: grid; gap: 8px; margin-top: 4px; padding-top: 12px; border-top: 1px solid #2b333e; }
        .creativeMediaSearch > div:first-child { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; gap: 7px; }
        .creativeMediaSearch .aiMediaButton { color: #07140c; background: #18e06f; }
        .creativeMediaSearch input { min-width: 0; }
        .creativeMediaSearch > small { color: #788391; font-size: 10px; }
        .creativeMediaResults { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
        .creativeMediaResults > div { display: grid; overflow: hidden; border: 1px solid #323b47; border-radius: 8px; background: #0c1015; }
        .creativeMediaResults.isAiRanked > div { position: relative; border-color: rgba(24, 224, 111, .38); }
        .creativeAiScore { position: absolute; z-index: 4; top: 7px; left: 7px; display: grid; grid-template-columns: auto auto; align-items: center; gap: 0 5px; padding: 6px 8px; border: 1px solid rgba(255,255,255,.18); border-radius: 8px; color: #fff; background: rgba(5, 9, 12, .88); backdrop-filter: blur(8px); }
        .creativeAiScore b { grid-row: 1 / 3; color: #18e06f; font-size: 20px; }
        .creativeAiScore span, .creativeAiScore small { font-size: 8px; line-height: 1; text-transform: uppercase; }
        .creativeAiScore small { color: #94a0ad; }
        .creativePreviewFrames { display: grid !important; grid-template-columns: repeat(3, minmax(0, 1fr)) !important; gap: 2px !important; padding: 2px !important; }
        .creativePreviewFrames img { width: 100%; aspect-ratio: 9 / 16; max-height: 90px; object-fit: cover; }
        .creativeMediaResults video, .creativeAssignedMedia video { width: 100%; aspect-ratio: 9 / 16; max-height: 270px; object-fit: cover; background: #080a0d; }
        .creativeMediaResults > div > div { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 5px; align-items: center; padding: 7px; }
        .creativeMediaResults > div > div > p { grid-column: 1 / -1; margin: 2px 0; color: #aab3bf; font-size: 10px; line-height: 1.4; }
        .creativeMediaResults span, .creativeMediaResults a { color: #7f8998; font-size: 9px; }
        .creativeMediaResults a { grid-column: 1 / -1; }
        .pexelsAttribution { color: #929daa; font-size: 10px; }
        .creativeAssignedMedia { display: grid; grid-template-columns: 110px minmax(0, 1fr); gap: 10px; align-items: center; padding: 9px; border: 1px solid rgba(24, 224, 111, 0.3); border-radius: 8px; background: rgba(24, 224, 111, 0.035); }
        .creativeAssignedMedia video { max-height: 150px; border-radius: 6px; }
        .creativeAssignedMedia > div { display: grid; gap: 4px; }
        .creativeAssignedMedia small, .creativeAssignedMedia a { color: #85909d; font-size: 10px; }
        .creativeEditor { display: grid; grid-template-columns: minmax(210px, 0.7fr) minmax(0, 1.3fr); gap: 14px; padding: 14px; border: 1px solid rgba(24, 224, 111, 0.35); border-radius: 10px; background: #090d11; }
        .creativeEditorPreview { position: relative; width: 100%; max-width: 320px; aspect-ratio: 9 / 16; justify-self: center; overflow: hidden; border-radius: 12px; background: #050608; box-shadow: 0 18px 48px rgba(0,0,0,.38); }
        .creativeEditorPreview--4x5 { aspect-ratio: 4 / 5; }
        .creativeEditorPreview--1x1 { aspect-ratio: 1; }
        .creativeEditorPreview--editorial_top .creativeEditorHook strong { font-size: clamp(17px, 2.6vw, 28px); line-height: 1.04; }
        .creativeEditorPreview--minimal_bottom .creativeEditorHook strong { font-size: clamp(15px, 2.2vw, 24px); line-height: 1.08; }
        .creativeEditorPreview--minimal_bottom .creativeEditorHook strong::after { width: 28px; height: 3px; }
        .creativeEditorPreview > video { width: 100%; height: 100%; object-fit: cover; }
        .creativeEditorShade { position: absolute; inset: 0; background: var(--editor-overlay); opacity: var(--editor-opacity); pointer-events: none; }
        .creativeEditorHook { position: absolute; z-index: 2; left: 7%; right: 7%; display: flex; align-items: center; color: var(--editor-text); }
        .creativeEditorHook strong { width: 100%; font-size: clamp(20px, 3.1vw, 34px); line-height: .98; letter-spacing: -0.04em; text-shadow: 0 2px 16px rgba(0,0,0,.55); }
        .creativeEditorHook strong::after { content: ""; display: block; width: 42px; height: 4px; margin: 10px auto 0; border-radius: 999px; background: var(--editor-accent); }
        .creativeEditorHook[style*="left"] strong::after { margin-left: 0; }
        .creativeEditorHook[style*="right"] strong::after { margin-right: 0; }
        .creativeEditorHook--top { top: 10%; }
        .creativeEditorHook--center { top: 39%; }
        .creativeEditorHook--bottom { bottom: 20%; }
        .creativeEditorBrand { position: absolute; z-index: 3; left: 7%; right: 7%; display: flex; align-items: center; gap: 8px; color: #fff; font-size: 10px; font-weight: 800; text-shadow: 0 2px 10px #000; }
        .creativeEditorBrand--top { top: 4%; }
        .creativeEditorBrand--center { top: 52%; }
        .creativeEditorBrand--bottom { bottom: 8%; }
        .creativeEditorCta { position: absolute; z-index: 4; right: 7%; bottom: 3%; padding: 7px 10px; border-radius: 999px; color: #07140c; background: var(--editor-accent); font-size: 9px; font-weight: 900; }
        .creativeEditorControls { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; align-content: start; }
        .creativeEditorControls label { display: grid; gap: 5px; }
        .creativeEditorControls label > span { color: #7f8998; font-size: 9px; font-weight: 800; text-transform: uppercase; }
        .creativeEditorControls input[type="color"] { width: 100%; min-height: 38px; padding: 4px; }
        .creativeEditorWide, .creativeEditorActions { grid-column: 1 / -1; }
        .creativeEditorToggle { display: flex !important; grid-template-columns: auto 1fr; align-items: center; }
        .creativeEditorToggle input { width: auto; }
        .creativeEditorActions { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding-top: 6px; }
        .creativeEditorActions > div { display: flex; flex-wrap: wrap; gap: 7px; }
        .creativeEditorActions button.secondary { color: #d7dde5; background: #252c35; }
        .creativeEditorActions small { color: #788391; }
        .creativeLibrary { display: grid; gap: 16px; }
        .creativeLibrary .panelHeader h2 { margin-top: 14px; }
        .creativeLibrary .panelHeader p { margin: 4px 0 0; color: #8993a0; }
        .creativeLibraryGrid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
        .creativeLibraryGrid article { display: grid; overflow: hidden; border: 1px solid #303844; border-radius: 11px; background: #10151b; }
        .creativeLibraryGrid video { width: 100%; aspect-ratio: 9 / 16; max-height: 520px; object-fit: cover; background: #07090c; }
        .creativeLibraryGrid article > div { display: grid; gap: 6px; padding: 13px; }
        .creativeLibraryGrid span { color: #18e06f; font-size: 9px; font-weight: 900; text-transform: uppercase; }
        .creativeLibraryGrid h3 { margin: 0; }
        .creativeLibraryGrid small { color: #7f8998; }
        .creativeLibraryGrid a { justify-self: start; margin-top: 4px; color: #bfc8d3; font-size: 11px; }
        .creativeEmptyState, .creativeLibraryEmpty > div { display: grid; justify-items: start; gap: 8px; padding: 24px; border: 1px dashed #3a4351; border-radius: 10px; color: #8d96a4; }
        .creativeEmptyState p, .creativeLibraryEmpty p { margin: 0; color: #8d96a4; }
        .creativeLibraryEmpty { display: grid; gap: 14px; }
        .creativeLibraryEmpty > div small { color: #7f8998; }
        .adsOverviewGrid {
          display: grid;
          grid-template-columns: 1.35fr 1fr;
          gap: 16px;
          margin: 16px 0;
        }
        .adsQuickStart {
          display: grid;
          align-content: center;
          justify-items: start;
          min-height: 230px;
          background: radial-gradient(circle at 85% 15%, rgba(24, 224, 111, 0.15), transparent 42%), #171b22;
        }
        .adsQuickStart h2 { margin: 18px 0 8px; font-size: clamp(24px, 3vw, 38px); }
        .adsQuickStart p { max-width: 620px; margin: 0 0 20px; color: #9aa3b1; line-height: 1.6; }
        .adsConnectionSummary dl { display: grid; gap: 12px; margin: 18px 0; }
        .adsConnectionSummary dl div { display: flex; justify-content: space-between; gap: 20px; padding-bottom: 10px; border-bottom: 1px solid #292f38; }
        .adsConnectionSummary dt { color: #7f8998; }
        .adsConnectionSummary dd { margin: 0; text-align: right; }
        .adsWizardSteps {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 8px;
          margin: 20px 0 6px;
        }
        .adsWizardSteps button {
          display: flex;
          align-items: center;
          justify-content: flex-start;
          gap: 9px;
          border-color: #303744;
          color: #8d96a4;
          background: #12161c;
        }
        .adsWizardSteps button span {
          display: grid;
          place-items: center;
          width: 24px;
          height: 24px;
          border-radius: 50%;
          background: #252b35;
          font-size: 11px;
        }
        .adsWizardSteps button.active { border-color: #18e06f; color: #f4f6f8; }
        .adsWizardSteps button.active span,
        .adsWizardSteps button.complete span { color: #07140c; background: #18e06f; }
        .adsSelectedPlaylist {
          grid-column: span 2;
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px;
          border: 1px solid rgba(24, 224, 111, 0.35);
          border-radius: 9px;
          background: rgba(24, 224, 111, 0.05);
        }
        .adsSelectedPlaylist div { display: grid; gap: 3px; }
        .adsSelectedPlaylist span,
        .adsSelectedPlaylist small { color: #7f8998; font-size: 11px; }
        .adsCreativeUpload {
          align-content: start;
          padding: 10px 12px;
          border: 1px dashed #3a4351;
          border-radius: 8px;
        }
        .adsCreativeUpload small { color: #7f8998; font-weight: 500; }
        .adsCreativeUpload input { padding: 7px 0; border: 0; background: transparent; }
        .adsCreativePreviewGrid {
          grid-column: 1 / -1;
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 12px;
        }
        .adsCreativePreview {
          display: grid;
          gap: 10px;
          overflow: hidden;
          padding: 12px;
          border: 1px solid #303744;
          border-radius: 9px;
          background: #11151b;
        }
        .adsPreviewIdentity { display: grid; gap: 3px; }
        .adsPreviewIdentity span { color: #7f8998; font-size: 10px; font-weight: 900; text-transform: uppercase; }
        .adsCreativePreview img,
        .adsCreativePlaceholder { width: calc(100% + 24px); height: 280px; margin: 0 -12px; object-fit: cover; background: #202631; }
        .adsCreativePlaceholder { display: grid; place-items: center; color: #657080; }
        .adsCreativePreview p { margin: 0; color: #a6adba; font-size: 12px; }
        .adsPreviewLink { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
        .adsPreviewLink div { display: grid; gap: 3px; }
        .adsPreviewLink small { color: #7f8998; font-size: 9px; }
        .adsPreviewLink b { padding: 7px 9px; border: 1px solid #3a4351; border-radius: 5px; font-size: 10px; white-space: nowrap; }
        .adsWizardActions { justify-content: flex-end; }
        .adsWizardActions small { margin-right: auto; order: -1; }
        .adsPlacementChoices {
          grid-column: 1 / -1;
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 10px;
          margin: 4px 0 0;
          padding: 0;
          border: 0;
        }
        .adsPlacementChoices legend { margin-bottom: 10px; color: #a6adba; font-size: 12px; font-weight: 800; }
        .adsPlacementChoices label {
          display: flex;
          grid-template-columns: auto 1fr;
          align-items: flex-start;
          gap: 10px;
          padding: 14px;
          border: 1px solid #303744;
          border-radius: 9px;
          background: #11151b;
          cursor: pointer;
        }
        .adsPlacementChoices label.selected { border-color: #18e06f; background: rgba(24, 224, 111, 0.06); }
        .adsPlacementChoices input { width: auto; margin-top: 3px; accent-color: #18e06f; }
        .adsPlacementChoices label span { display: grid; gap: 5px; }
        .adsPlacementChoices small { color: #7f8998; font-weight: 500; line-height: 1.4; }
        .adsDeliverySummary {
          grid-column: 1 / -1;
          display: grid;
          grid-template-columns: minmax(0, 1fr) auto;
          gap: 8px 20px;
          align-items: center;
          padding: 18px;
          border: 1px solid rgba(24, 224, 111, 0.35);
          border-radius: 9px;
          background: rgba(24, 224, 111, 0.05);
        }
        .adsDeliverySummary > span { grid-column: 1 / -1; color: #7f8998; font-size: 10px; font-weight: 900; text-transform: uppercase; }
        .adsDeliverySummary strong { font-size: 22px; }
        .adsDeliverySummary p,
        .adsDeliverySummary small { margin: 0; color: #a6adba; }
        .adsDeliverySummary b { grid-column: 2; grid-row: 2 / span 3; padding: 8px 10px; border-radius: 999px; color: #07140c; background: #18e06f; font-size: 10px; }
        .metaFormActions {
          display: flex;
          align-items: center;
          gap: 14px;
          margin-top: 14px;
        }
        .metaFormActions small {
          color: #7f8998;
          line-height: 1.4;
        }
        .metaDsaNote {
          margin: 14px 0 0;
          padding: 11px 12px;
          border-left: 3px solid #ffd066;
          color: #a6adba;
          background: rgba(255, 208, 102, 0.05);
          font-size: 12px;
          line-height: 1.5;
        }
        .metaIdentity {
          display: grid;
          gap: 4px;
          padding: 14px 0;
          border-bottom: 1px solid #292f38;
        }
        .metaIdentity span,
        .metaIdentity small {
          color: #7f8998;
          font-size: 12px;
        }
        .metaPermissionList {
          display: flex;
          gap: 7px;
          flex-wrap: wrap;
          padding: 14px 0;
        }
        .metaPermissionList span {
          padding: 6px 8px;
          border: 1px solid rgba(24, 224, 111, 0.35);
          border-radius: 6px;
          color: #18e06f;
          background: rgba(24, 224, 111, 0.06);
          font-size: 11px;
          font-weight: 800;
        }
        .metaPermissionList p,
        .metaAssetGroup > p {
          margin: 0;
          color: #7f8998;
          font-size: 13px;
        }
        .metaWarnings {
          display: grid;
          gap: 6px;
          padding: 11px 12px;
          border: 1px solid rgba(255, 208, 102, 0.35);
          border-radius: 7px;
          background: rgba(255, 208, 102, 0.06);
        }
        .metaWarnings p {
          margin: 0;
          color: #ffd066;
          font-size: 12px;
        }
        .metaAssetColumns {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 14px;
          margin-top: 16px;
        }
        .metaAssetGroup {
          display: grid;
          align-content: start;
          gap: 8px;
          min-width: 0;
        }
        .metaAssetGroupHeader {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding-bottom: 9px;
          border-bottom: 1px solid #2a303b;
        }
        .metaAssetGroupHeader span {
          color: #18e06f;
          font-weight: 900;
        }
        .metaAssetGroup article {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 10px;
          min-width: 0;
          padding: 11px 12px;
          border: 1px solid #2a303b;
          border-radius: 7px;
          background: #151920;
        }
        .metaAssetGroup article.selected {
          border-color: rgba(24, 224, 111, 0.58);
          background: rgba(24, 224, 111, 0.06);
        }
        .metaAssetGroup article div {
          display: grid;
          gap: 3px;
          min-width: 0;
        }
        .metaAssetGroup article strong,
        .metaAssetGroup article small,
        .metaAssetActions span {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .metaAssetGroup article small,
        .metaAssetActions span {
          color: #7f8998;
          font-size: 11px;
        }
        .metaAssetGroup .metaAssetActions {
          justify-items: end;
          flex: 0 0 auto;
        }
        .metaAssetActions button {
          min-height: 30px;
          padding: 5px 9px;
          font-size: 11px;
        }
        .metaDraftComposer,
        .metaDraftList {
          margin-top: 16px;
        }
        .metaDraftGrid {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 12px;
          margin-top: 16px;
        }
        .metaDraftGrid label {
          display: grid;
          gap: 6px;
          color: #a6adba;
          font-size: 12px;
          font-weight: 800;
        }
        .metaDraftGrid input,
        .metaDraftGrid select,
        .metaDraftGrid textarea {
          width: 100%;
          border: 1px solid #303744;
          border-radius: 7px;
          background: #11151b;
          color: #f4f6f8;
          padding: 10px 11px;
          font: inherit;
          resize: vertical;
        }
        .metaDraftWide { grid-column: span 2; }
        .metaDraftCards {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 12px;
          margin-top: 16px;
        }
        .metaDraftCards > article {
          display: grid;
          gap: 12px;
          padding: 14px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #151920;
        }
        .metaDraftCards > p { color: #7f8998; }
        .metaDraftCardHeader,
        .metaDraftActions {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 10px;
        }
        .metaDraftCardHeader div { display: grid; gap: 3px; }
        .metaDraftCardHeader small { color: #18e06f; text-transform: uppercase; font-weight: 900; }
        .metaDraftCards article > p { margin: 0; color: #c1c7d0; font-size: 13px; }
        .metaDraftCards dl { display: grid; gap: 7px; margin: 0; }
        .metaDraftCards dl div { display: grid; grid-template-columns: 90px 1fr; gap: 8px; }
        .metaDraftCards dt { color: #7f8998; font-size: 11px; }
        .metaDraftCards dd { margin: 0; overflow: hidden; color: #c1c7d0; font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
        .metaDraftActions { justify-content: flex-end; }
        .metaPublishLock {
          display: flex;
          align-items: center;
          gap: 13px;
          padding: 15px 17px;
          border: 1px solid #303744;
          border-radius: 8px;
          background: #14181f;
        }
        .metaPublishLock svg {
          width: 20px;
          color: #18e06f;
        }
        .metaPublishLock p {
          margin: 3px 0 0;
          color: #8d96a4;
          font-size: 13px;
        }
        .metaPublishLock.ready {
          border-color: rgba(24, 224, 111, 0.42);
          background: rgba(24, 224, 111, 0.05);
        }
        .jobStatus {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 74px;
          min-height: 26px;
          border: 1px solid rgba(166, 173, 186, 0.22);
          border-radius: 999px;
          color: #a6adba;
          font-size: 11px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .jobStatus--pending {
          border-color: rgba(255, 208, 102, 0.5);
          color: #ffd066;
        }
        .jobStatus--running,
        .jobStatus--done {
          border-color: rgba(24, 224, 111, 0.48);
          color: #18e06f;
        }
        .jobStatus--failed {
          border-color: rgba(255, 77, 77, 0.48);
          color: #ff6b6b;
        }
        .jobStatus--failed {
          border-color: rgba(255, 77, 77, 0.48);
          color: #ff6b6b;
        }
        .growthPanel {
          min-height: 560px;
          display: flex;
          flex-direction: column;
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
        .modeToggle {
          display: inline-flex;
          align-items: center;
          gap: 4px;
          padding: 4px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: #12161d;
        }
        .modeToggle button {
          height: 32px;
          padding: 0 10px;
          border: 0;
          background: transparent;
          color: #a6adba;
          font-size: 12px;
          font-weight: 800;
        }
        .modeToggle button.active {
          background: rgba(24, 224, 111, 0.12);
          color: #18e06f;
        }
        .adMobileChartToggle {
          display: none;
        }
        .chartFilters select:last-child {
          min-width: 220px;
          max-width: 320px;
        }
        .chartStats {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 10px;
          margin-top: 18px;
        }
        .chartStats article {
          display: grid;
          gap: 3px;
          padding: 10px 12px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: rgba(18, 22, 29, 0.72);
        }
        .chartStats span {
          color: #a6adba;
          font-size: 11px;
          font-weight: 800;
          text-transform: uppercase;
        }
        .chartStats strong {
          color: #f4f6fb;
          font-size: 18px;
        }
        :global(.growthChart) {
          position: relative;
          width: 100%;
          height: 300px;
          min-height: 300px;
          margin-top: 14px;
          padding: 0;
          overflow: hidden;
          border-radius: 8px;
          background: rgba(18, 22, 29, 0.42);
          contain: layout paint;
        }
        :global(.growthChart) svg {
          display: block;
          width: 100%;
          height: 100%;
          overflow: hidden;
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
          top: 12px;
          z-index: 8;
          min-width: 176px;
          max-width: min(240px, calc(100% - 24px));
          padding: 10px 12px;
          border: 1px solid rgba(24, 224, 111, 0.28);
          border-radius: 8px;
          background: rgba(15, 18, 23, 0.96);
          color: #f4f6fb;
          box-shadow: 0 16px 40px rgba(0, 0, 0, 0.34);
          pointer-events: none;
          transform: translateX(-50%);
          backdrop-filter: blur(8px);
          display: grid;
          gap: 5px;
        }
        :global(.chartTooltip) strong,
        :global(.chartTooltip) span,
        :global(.chartTooltip) em {
          display: block;
          line-height: 1.3;
          white-space: nowrap;
        }
        :global(.chartTooltip) strong {
          font-size: 13px;
          color: #f4f6fb;
        }
        :global(.chartTooltip) span {
          color: #a6adba;
          font-size: 12px;
        }
        :global(.chartTooltip) em {
          color: #18e06f;
          font-size: 13px;
          font-style: normal;
          font-weight: 700;
        }
        :global(.chartTooltip) em b {
          color: #18e06f;
          font-weight: 900;
          margin-right: 5px;
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
          margin-top: 14px;
          padding-top: 10px;
          border-top: 1px solid rgba(166, 173, 186, 0.12);
        }
        .sparkLabels strong {
          color: #18e06f;
          font-size: 14px;
        }
        .sparkLabels span:last-child {
          text-align: right;
        }
        .chartCoverageNote {
          margin-top: 10px;
          color: #7f8794;
          font-size: 12px;
          line-height: 1.4;
        }
        .playlistDetailDrawer {
          display: grid;
          gap: 14px;
          margin-top: 16px;
          padding: 14px;
          border: 1px solid rgba(24, 224, 111, 0.24);
          border-radius: 8px;
          background: rgba(18, 22, 29, 0.78);
        }
        .playlistDetailDrawer > div {
          display: flex;
          align-items: center;
          gap: 12px;
          min-width: 0;
        }
        .playlistDetailDrawer > div span {
          display: grid;
          gap: 3px;
          min-width: 0;
        }
        .playlistDetailDrawer strong,
        .playlistDetailDrawer small {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .playlistDetailDrawer small {
          color: #a6adba;
          font-size: 12px;
        }
        .playlistDetailDrawer section {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 8px;
        }
        .playlistDetailDrawer article {
          display: grid;
          gap: 3px;
          padding: 10px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: #101318;
        }
        .playlistDetailDrawer article span {
          color: #a6adba;
          font-size: 11px;
          font-weight: 800;
          text-transform: uppercase;
        }
        .playlistDetailDrawer article strong {
          color: #f4f6fb;
          font-size: 16px;
        }
        .playlistDetailDrawer button {
          justify-self: start;
        }
        .rankPanel {
          min-height: 560px;
          align-self: stretch;
          display: grid;
          grid-template-rows: auto minmax(390px, 1fr) auto;
        }
        .topPlaylistsPanel,
        .removalsPanel {
          min-height: 360px;
        }
        :global(.growthBars) {
          display: grid;
          gap: 10px;
          margin-top: 14px;
          min-height: 390px;
          align-content: start;
        }
        :global(.growthBar) {
          display: grid;
          grid-template-columns: 24px 44px minmax(0, 1fr) auto;
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
        :global(.growthBar--empty) {
          visibility: hidden;
          pointer-events: none;
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
        :global(.growthBarCopy) {
          display: grid;
          gap: 4px;
          min-width: 0;
        }
        :global(.growthBarCopy) strong,
        :global(.growthBarCopy) span {
          display: block;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        :global(.growthBarCopy) span {
          font-size: 12px;
          line-height: 1.25;
        }
        :global(.growthBar) b {
          font-size: 14px;
        }
        :global(.growthDelta) {
          justify-self: end;
          display: inline-flex;
          align-items: center;
          min-width: 64px;
          justify-content: center;
          padding: 7px 9px;
          border-radius: 999px;
          border: 1px solid rgba(24, 224, 111, 0.42);
          background: rgba(24, 224, 111, 0.08);
          color: #18e06f;
          white-space: nowrap;
        }
        :global(.growthDelta.negative) {
          border-color: rgba(255, 77, 77, 0.48);
          background: rgba(255, 77, 77, 0.08);
          color: #ff6464;
        }
        :global(.growthDelta.muted) {
          min-width: 74px;
          border-color: rgba(166, 173, 186, 0.28);
          background: rgba(166, 173, 186, 0.08);
          color: #a6adba;
          font-size: 12px;
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
        :global(.growthChart--recharts) {
          padding: 6px 4px 2px 0;
        }
        :global(.rechartsTooltip) {
          min-width: 184px;
          padding: 11px 12px;
          border: 1px solid rgba(24, 224, 111, 0.3);
          border-radius: 8px;
          background: rgba(15, 18, 23, 0.97);
          color: #f4f6fb;
          box-shadow: 0 16px 40px rgba(0, 0, 0, 0.36);
          display: grid;
          gap: 5px;
        }
        :global(.rechartsTooltip strong),
        :global(.rechartsTooltip span),
        :global(.rechartsTooltip em) {
          display: block;
          line-height: 1.3;
          white-space: nowrap;
        }
        :global(.rechartsTooltip strong) {
          font-size: 13px;
        }
        :global(.rechartsTooltip span) {
          color: #a6adba;
          font-size: 12px;
        }
        :global(.rechartsTooltip em) {
          color: #18e06f;
          font-size: 13px;
          font-style: normal;
          font-weight: 800;
        }
        :global(.rechartsTooltip b) {
          color: #18e06f;
          margin-right: 5px;
        }
        .playlistTable {
          display: grid;
          gap: 2px;
          margin-top: 18px;
        }
        .playlistTableHeader,
        .playlistTable div {
          display: grid;
          grid-template-columns: 52px minmax(240px, 2fr) minmax(104px, 0.75fr) minmax(92px, 0.65fr) minmax(76px, 0.5fr) minmax(76px, 0.5fr) minmax(76px, 0.5fr) minmax(92px, 0.65fr);
          align-items: center;
          gap: 12px;
          min-height: 64px;
          padding: 6px 0;
          border-top: 1px solid #202630;
          min-width: 0;
        }
        .playlistTableHeader {
          min-height: 32px;
          border-top: 0;
          padding: 0 0 6px;
          color: #7f8794;
          font-size: 11px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .playlistTableHeader span:first-child {
          grid-column: 1 / 3;
        }
        .playlistTable strong,
        .playlistTable span,
        .playlistTable b,
        .playlistTable small {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .playlistTable b {
          color: #18e06f;
          font-size: 13px;
        }
        .playlistTable small {
          color: #7f8794;
          font-size: 12px;
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
          overflow-y: auto;
          overscroll-behavior: contain;
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
        .addSongCards {
          display: grid;
          grid-template-columns: minmax(0, 1fr);
          gap: 14px;
          align-items: start;
        }
        .addNowCard,
        .futureAddCard {
          min-width: 0;
        }
        .addNowGrid {
          display: grid;
          grid-template-columns: minmax(300px, 1fr) 120px 140px auto;
          gap: 10px;
          align-items: start;
        }
        .addNowGrid > input {
          width: 100%;
        }
        .addToolFutureList {
          margin-top: 0;
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
        .cleanupRules {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 14px;
        }
        .cleanupIntro {
          display: flex;
          align-items: end;
          justify-content: space-between;
          gap: 18px;
          margin-bottom: 16px;
        }
        .cleanupIntro > div:first-child {
          display: grid;
          gap: 5px;
        }
        .cleanupIntro > div:first-child > span {
          color: #18e06f;
          font-size: 11px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .cleanupIntro h2,
        .cleanupIntro p {
          margin: 0;
        }
        .cleanupStatus {
          display: grid;
          justify-items: end;
          gap: 1px;
          flex: 0 0 auto;
        }
        .cleanupStatus strong {
          color: #18e06f;
          font-size: 24px;
          line-height: 1;
        }
        .cleanupStatus span {
          color: #7f8794;
          font-size: 11px;
          font-weight: 800;
          text-transform: uppercase;
        }
        .cleanupRuleCard {
          display: grid;
          align-content: start;
          gap: 18px;
          padding: 18px;
          border: 1px solid #2a303b;
          border-radius: 8px;
          background: #12161d;
          transition: border-color 160ms ease, background 160ms ease;
        }
        .cleanupRuleCard.isActive {
          border-color: rgba(24, 224, 111, 0.38);
          background: linear-gradient(145deg, rgba(24, 224, 111, 0.075), #12161d 45%);
        }
        .cleanupRuleHeader {
          display: grid;
          grid-template-columns: 38px minmax(0, 1fr) auto;
          align-items: start;
          gap: 12px;
        }
        .cleanupRuleHeader > div {
          display: grid;
          gap: 5px;
          min-width: 0;
        }
        .cleanupRuleIcon {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 38px;
          height: 38px;
          border: 1px solid #303743;
          border-radius: 8px;
          color: #7f8794;
          background: #181d25;
        }
        .cleanupRuleIcon svg {
          width: 18px;
          height: 18px;
        }
        .cleanupRuleCard.isActive .cleanupRuleIcon {
          border-color: rgba(24, 224, 111, 0.42);
          color: #18e06f;
          background: rgba(24, 224, 111, 0.08);
        }
        .cleanupRuleCard h3 {
          margin: 0;
          font-size: 16px;
          color: #f4f6fb;
        }
        .cleanupRuleCard p {
          margin: 0;
          font-size: 13px;
          color: #a6adba;
          line-height: 1.45;
        }
        .cleanupRuleControls {
          display: grid;
          align-content: start;
          gap: 12px;
          padding-top: 14px;
          border-top: 1px solid #252c37;
        }
        .cleanupHint {
          min-height: 38px;
          color: #7f8794 !important;
          font-size: 12px !important;
        }
        .inlineNumberField {
          display: grid;
          grid-template-columns: minmax(0, 1fr) auto;
          align-items: center;
          gap: 8px;
        }
        .inlineNumberField small {
          color: #a6adba;
          font-weight: 700;
        }
        .cleanupSwitch {
          display: grid;
          grid-template-columns: 34px auto;
          align-items: center;
          gap: 7px;
          color: #f4f6fb;
          font-weight: 800;
          font-size: 11px;
          cursor: pointer;
        }
        .cleanupSwitch input {
          position: absolute;
          opacity: 0;
          pointer-events: none;
        }
        .cleanupSwitch > span {
          position: relative;
          width: 34px;
          height: 20px;
          border: 1px solid #3a424f;
          border-radius: 999px;
          background: #252c37;
          transition: 160ms ease;
        }
        .cleanupSwitch > span::after {
          content: "";
          position: absolute;
          top: 3px;
          left: 3px;
          width: 12px;
          height: 12px;
          border-radius: 50%;
          background: #a6adba;
          transition: 160ms ease;
        }
        .cleanupSwitch input:checked + span {
          border-color: rgba(24, 224, 111, 0.72);
          background: rgba(24, 224, 111, 0.2);
        }
        .cleanupSwitch input:checked + span::after {
          transform: translateX(14px);
          background: #18e06f;
        }
        .cleanupSwitch em {
          color: #7f8794;
          font-style: normal;
          text-transform: uppercase;
        }
        .cleanupSwitch input:checked ~ em {
          color: #18e06f;
        }
        .trackLimitGrid {
          display: grid;
          grid-template-columns: minmax(120px, 0.7fr) minmax(180px, 1fr);
          gap: 12px;
        }
        .toolActions {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          margin-top: 14px;
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
        .compactField input,
        .compactField select {
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
        .rotatorCards {
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 14px;
        }
        .rotatorSettingsCard {
          min-width: 0;
        }
        .flexSettings {
          display: grid;
          grid-template-columns: minmax(0, 1.5fr) minmax(140px, 0.6fr);
          gap: 10px;
          align-items: end;
        }
        .rotatorSourceField {
          min-width: 0;
        }
        .rotatorRules {
          display: grid;
          grid-template-columns: repeat(2, minmax(120px, 1fr));
          gap: 10px;
          align-items: center;
        }
        .toggleField {
          display: flex;
          align-items: center;
          gap: 8px;
          color: #a6adba;
          font-weight: 700;
          min-width: 0;
          line-height: 1.35;
        }
        .toggleField input {
          width: 18px;
          height: 18px;
          padding: 0;
          flex: 0 0 auto;
        }
        .rotatorDuplicateToggle {
          padding: 10px 12px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: #101318;
        }
        .futureAddCard {
          margin-top: 0;
        }
        .futureAddGrid {
          display: grid;
          grid-template-columns: minmax(150px, 0.75fr) minmax(180px, 1fr) minmax(180px, 1fr) minmax(110px, 0.5fr);
          gap: 10px;
          align-items: end;
        }
        .futureAddList {
          display: grid;
          gap: 8px;
          margin-top: 14px;
        }
        .futureAddItem {
          display: grid;
          grid-template-columns: minmax(0, 1fr) auto minmax(0, 0.8fr) auto;
          align-items: center;
          gap: 12px;
          min-height: 70px;
          padding: 12px;
          border: 1px solid #252c37;
          border-radius: 8px;
          background: #12161d;
        }
        .futureAddItem > div {
          display: grid;
          gap: 3px;
          min-width: 0;
        }
        .futureAddItem strong,
        .futureAddItem span,
        .futureAddItem small {
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .futureAddItem span,
        .futureAddItem small {
          color: #a6adba;
          font-size: 12px;
        }
        .futureAddItem em {
          justify-self: start;
          min-width: 78px;
          padding: 6px 9px;
          border: 1px solid rgba(166, 173, 186, 0.28);
          border-radius: 999px;
          color: #a6adba;
          font-size: 11px;
          font-style: normal;
          font-weight: 900;
          text-align: center;
          text-transform: uppercase;
        }
        .futureAddItem--pending em {
          border-color: rgba(255, 208, 102, 0.44);
          color: #ffd066;
          background: rgba(255, 208, 102, 0.08);
        }
        .futureAddItem--added em {
          border-color: rgba(24, 224, 111, 0.44);
          color: #18e06f;
          background: rgba(24, 224, 111, 0.08);
        }
        .futureAddItem--failed em,
        .futureAddItem--not_found em {
          border-color: rgba(255, 77, 77, 0.44);
          color: #ff6b6b;
          background: rgba(255, 77, 77, 0.08);
        }
        .emptyToolState {
          margin: 0;
          padding: 12px;
          border: 1px dashed #303743;
          border-radius: 8px;
          color: #a6adba;
          background: #101318;
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
        .backupItem span > b {
          color: #24d366;
          font-size: 10px;
          font-weight: 900;
          text-transform: uppercase;
        }
        .backupItem--empty {
          border-style: dashed;
          color: #7f8997;
          background: #101318;
        }
        .backupItem--empty:hover {
          border-color: #303844;
          background: #101318;
        }
        .backupItem--empty strong {
          color: #a6adba;
        }
        .backupSlotMark {
          display: grid !important;
          place-items: center;
          width: 42px;
          height: 42px;
          border: 1px solid #303844;
          border-radius: 6px;
          color: #687280;
          font-weight: 900;
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
        .trackLoadingState {
          display: grid;
          gap: 10px;
          padding: 16px;
          border-top: 1px solid #202630;
          background: rgba(18, 22, 29, 0.72);
        }
        .trackLoadingState > span {
          display: inline-flex;
          align-items: center;
          gap: 9px;
          color: #18e06f;
          font-size: 13px;
          font-weight: 900;
        }
        .trackSkeleton {
          display: grid;
          grid-template-columns: 28px 52px minmax(0, 1fr) 156px;
          align-items: center;
          gap: 12px;
          min-height: 64px;
          padding: 8px 0;
        }
        .trackSkeleton i,
        .trackSkeleton b,
        .trackSkeleton span,
        .trackSkeleton em {
          display: block;
          border-radius: 8px;
          background: linear-gradient(90deg, #232a35 0%, #303846 48%, #232a35 100%);
          background-size: 220% 100%;
          animation: shimmer 1.05s linear infinite;
        }
        .trackSkeleton i {
          height: 16px;
          border-radius: 999px;
        }
        .trackSkeleton b {
          width: 52px;
          height: 52px;
        }
        .trackSkeleton span {
          height: 18px;
        }
        .trackSkeleton em {
          height: 32px;
        }
        .emptyTrackState {
          display: grid;
          gap: 6px;
          padding: 28px 18px;
          border-top: 1px solid #202630;
          color: #a6adba;
        }
        .emptyTrackState strong {
          color: #f4f6fb;
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
          display: inline-flex;
          align-items: center;
          justify-content: center;
          min-width: 62px;
          height: 24px;
          border-radius: 999px;
          padding: 0 8px;
          font-size: 12px;
          font-weight: 800;
          line-height: 1;
        }
        .locked,
        .flexBadge {
          color: #18e06f;
          background: rgba(24, 224, 111, 0.12);
          border: 1px solid rgba(24, 224, 111, 0.35);
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
          .metricGrid--primary,
          .automationHealth,
          .dashboardFocusGrid,
          .dashboardSplitGrid,
          .adminGrid,
          .adminGrid--wide,
          .metaSetupGrid,
          .metaAssetColumns,
          .metaFormGrid,
          .metaDraftGrid,
          .metaDraftCards,
          .adsOverviewGrid,
          .creativeStudioHero,
          .creativeStudioGrid,
          .performanceHeroRow,
          .adControlGrid,
          .adPlaylistGrid,
          .removalList {
            grid-template-columns: 1fr;
          }
          .metaFormWide {
            grid-column: auto;
          }
          .metaDraftWide { grid-column: auto; }
          .adsSelectedPlaylist { grid-column: auto; }
          .adsCreativePreviewGrid { grid-template-columns: 1fr; }
          .metaFormActions {
            align-items: stretch;
            flex-direction: column;
          }
          .adsWorkspaceNav { overflow-x: auto; }
          .adsWorkspaceNav button { flex: 1 0 135px; }
          .creativePipeline { grid-template-columns: 1fr 1fr; }
          .creativeProjectSummary { grid-template-columns: auto minmax(0, 1fr); }
          .creativeProjectSummary > button { grid-column: 1 / -1; }
          .creativeConceptGrid { grid-template-columns: 1fr; }
          .creativeMediaResults { grid-template-columns: 1fr 1fr; }
          .creativeMediaSearch > div:first-child { grid-template-columns: 1fr 1fr; }
          .creativeMediaSearch > div:first-child input { grid-column: 1 / -1; }
          .creativeEditor { grid-template-columns: 1fr; }
          .creativeTemplateGrid { grid-template-columns: 1fr; }
          .creativeProjectMediaReview { grid-template-columns: 1fr; }
          .creativeBatchHeader { align-items: stretch; flex-direction: column; }
          .creativeEditorControls { grid-template-columns: 1fr; }
          .creativeEditorWide, .creativeEditorActions { grid-column: auto; }
          .creativeLibraryGrid { grid-template-columns: 1fr; }
          .adsWizardSteps { grid-template-columns: 1fr; }
          .adsPlacementChoices { grid-template-columns: 1fr; }
          .adsDeliverySummary { grid-template-columns: 1fr; }
          .adsDeliverySummary b { grid-column: auto; grid-row: auto; justify-self: start; }
          .adEventForm {
            grid-template-columns: 1fr;
          }
          .adEventForm textarea {
            grid-column: auto;
          }
          .adPlaylistStats,
          .adDualChartGrid,
          .adEventList div {
            grid-template-columns: 1fr;
          }
          .adminTable div {
            grid-template-columns: 82px minmax(0, 1fr);
          }
          .adminTable small {
            grid-column: 2;
          }
          .playlistTableHeader {
            display: none;
          }
          .playlistTable div {
            grid-template-columns: 52px minmax(0, 1fr) 100px;
          }
          .playlistTable span:nth-of-type(2),
          .playlistTable span:nth-of-type(3),
          .playlistTable b {
            display: none;
          }
          .workspace {
            grid-template-columns: 1fr;
            height: auto;
            overflow: visible;
            padding: 24px;
            gap: 28px;
          }
          .sidebar {
            position: relative;
            z-index: 1;
            max-width: 100%;
            overflow: hidden;
          }
          .content {
            overflow: visible;
          }
          .playlistList {
            max-height: 42vh;
            overflow-y: auto;
            padding-right: 4px;
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
          .dashboard,
          .adminPanel {
            gap: 14px;
            padding: 14px 14px 24px;
          }
          .dashboardHero {
            display: grid;
            gap: 14px;
            align-items: stretch;
          }
          .dashboardHero h2 {
            font-size: 32px;
          }
          .dashboardHero p {
            font-size: 13px;
            line-height: 1.35;
          }
          .dashboardActions {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 8px;
          }
          .dashboardActions select,
          .dashboardActions input,
          .dashboardActions button {
            width: 100%;
            min-width: 0;
            height: 42px;
          }
          .dashboardActions button,
          .dashboardActions input[type="date"] {
            grid-column: span 2;
          }
          .dashboardSubnav {
            display: grid;
            grid-template-columns: 1fr 1fr;
            width: 100%;
          }
          .dashboardSubnav button {
            width: 100%;
          }
          .metricGrid,
          .metricGrid--primary {
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
          }
          .metricGrid article {
            min-height: 112px;
            padding: 13px;
            grid-template-rows: auto minmax(32px, auto) auto;
          }
          .metricLabel {
            font-size: 10px;
          }
          .metricValue {
            font-size: 22px;
            overflow-wrap: anywhere;
          }
          .metricMeta {
            font-size: 11px;
          }
          .dashboardPanel {
            padding: 14px;
          }
          .dashboardFocusGrid,
          .dashboardSplitGrid,
          .performanceHeroRow,
          .adInsightHeroRow {
            grid-template-columns: 1fr;
            gap: 10px;
          }
          .growthPanel,
          .rankPanel,
          .topPlaylistsPanel,
          .removalsPanel {
            min-height: 0;
          }
          .rankPanel {
            grid-template-rows: auto auto auto;
          }
          .panelHeader {
            display: grid;
            gap: 12px;
          }
          .chartFilters {
            display: grid;
            grid-template-columns: 1fr;
            justify-content: stretch;
          }
          .chartFilters .modeToggle {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            width: 100%;
          }
          .chartFilters select {
            width: 100%;
            max-width: none;
            min-width: 0;
          }
          .chartStats,
          .warmupStats,
          .playlistDetailDrawer section {
            grid-template-columns: 1fr;
          }
          :global(.growthChart),
          .adChart,
          .adMiniGrowthChart :global(.growthChart) {
            height: 240px;
            min-height: 240px;
          }
          :global(.rechartsTooltip),
          :global(.chartTooltip) {
            max-width: calc(100vw - 52px);
            min-width: 0;
            white-space: normal;
          }
          :global(.growthBars) {
            min-height: 0;
            gap: 8px;
          }
          :global(.growthBar) {
            grid-template-columns: 42px minmax(0, 1fr);
            min-height: 68px;
            gap: 9px;
          }
          :global(.growthRank) {
            display: none;
          }
          :global(.growthBar) .artwork--sm,
          :global(.growthBar) .coverFallback.artwork--sm {
            grid-row: span 2;
            width: 42px;
            height: 42px;
          }
          :global(.growthDelta) {
            grid-column: 2;
            justify-self: start;
            min-width: 0;
            padding: 5px 8px;
            font-size: 12px;
          }
          .performanceHeroCard {
            min-height: 104px;
            padding: 14px;
          }
          .performanceHeroCard strong,
          .performanceHeroCard small {
            white-space: normal;
            overflow-wrap: anywhere;
          }
          .playlistTable {
            gap: 10px;
          }
          .playlistTable div {
            grid-template-columns: 42px minmax(0, 1fr);
            gap: 8px 10px;
            min-height: 0;
            padding: 10px;
            border: 1px solid #252c37;
            border-radius: 8px;
            background: #12161d;
          }
          .playlistTable div > strong {
            grid-column: 2;
            white-space: normal;
            overflow-wrap: anywhere;
          }
          .playlistTable div > .artwork,
          .playlistTable div > .coverFallback {
            grid-row: 1 / 3;
          }
          .playlistTable span,
          .playlistTable b {
            display: grid !important;
            grid-column: 1 / -1;
            grid-template-columns: minmax(82px, 0.55fr) minmax(0, 1fr);
            align-items: center;
            min-height: 34px;
            padding: 8px 10px;
            border: 1px solid #252c37;
            border-radius: 8px;
            background: #101318;
            font-size: 12px;
            text-align: right;
          }
          .playlistTable span::before,
          .playlistTable b::before {
            color: #7f8794;
            font-size: 10px;
            font-weight: 900;
            text-align: left;
            text-transform: uppercase;
          }
          .playlistTable span:nth-of-type(1)::before {
            content: "Followers";
          }
          .playlistTable span:nth-of-type(2)::before {
            content: "Growth";
          }
          .playlistTable span:nth-of-type(3)::before {
            content: "Tracks";
          }
          .playlistTable span:nth-of-type(4)::before {
            content: "Locked";
          }
          .playlistTable span:nth-of-type(5)::before {
            content: "Rotator";
          }
          .playlistTable b::before {
            content: "Expiry";
          }
          .removalList div {
            grid-template-columns: 42px minmax(0, 1fr);
            padding: 10px 0;
          }
          .removalList strong,
          .removalList em,
          .removalList small {
            white-space: normal;
            overflow-wrap: anywhere;
          }
          .adPerformanceView {
            gap: 14px;
          }
          .adEventForm {
            grid-template-columns: 1fr;
            gap: 8px;
          }
          .adEventForm textarea,
          .adEventForm button {
            grid-column: auto;
          }
          .adPlaylistSectionHeader {
            display: grid;
            gap: 10px;
            align-items: stretch;
          }
          .adPlaylistSectionHeader .modeToggle {
            display: grid;
            grid-template-columns: 1fr 1fr;
            width: 100%;
          }
          .adMobileChartToggle {
            display: grid !important;
          }
          .adPlaylistCard {
            padding: 12px;
            gap: 10px;
          }
          .adPlaylistHeader {
            display: grid;
            grid-template-columns: 44px minmax(0, 1fr);
            gap: 10px;
          }
          .adPlaylistHeader strong,
          .adPlaylistHeader small {
            white-space: normal;
            overflow-wrap: anywhere;
          }
          .adDualChartGrid {
            grid-template-columns: 1fr;
          }
          .adDualChartGrid section {
            min-height: 282px;
            overflow: visible;
          }
          .adChart {
            height: 240px;
            min-height: 240px;
            overflow: visible;
          }
          .adChart :global(.recharts-responsive-container) {
            min-width: 240px;
            min-height: 240px;
          }
          .adDualChartGrid--mobile-delta section:nth-child(2),
          .adDualChartGrid--mobile-growth section:nth-child(1) {
            display: none;
          }
          .adPlaylistStats,
          .adPlaylistStats--details {
            grid-template-columns: 1fr;
            gap: 6px;
          }
          .adPlaylistStats span {
            white-space: normal;
            overflow-wrap: anywhere;
          }
          .adEventList div {
            grid-template-columns: 1fr;
          }
          .adEventList button {
            justify-self: start;
          }
          .topbar {
            position: relative;
            grid-template-columns: minmax(0, 1fr);
            padding: 22px;
          }
          .setupProgress {
            grid-template-columns: 1fr;
            gap: 10px;
            padding: 14px 16px 16px;
          }
          .setupProgressHeader {
            align-items: start;
          }
          .setupProgressSteps {
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 9px 12px;
          }
          .setupProgress > button {
            width: 100%;
          }
          .settingsSectionHeader,
          .settingsHeaderActions {
            grid-template-columns: 1fr;
            width: 100%;
          }
          .settingsHeaderActions {
            display: grid;
          }
          .onboardingSteps,
          .onboardingStage,
          .onboardingReady,
          .loginMetaGrid,
          .onboardingPlanGrid,
          .subscriptionGate,
          .subscriptionGatePlans {
            grid-template-columns: 1fr;
          }
          .emailAuthForm {
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
            grid-template-columns: 42px minmax(0, 1fr);
          }
          :global(.growthSignal) {
            grid-column: 2;
            grid-template-columns: 1fr;
            gap: 6px;
          }
          .playlistTable div {
            grid-template-columns: 42px minmax(0, 1fr);
          }
          .playlistTable span,
          .playlistTable b {
            grid-column: 1 / -1;
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
            gap: 28px;
          }
          .sidebar {
            gap: 18px;
            padding-bottom: 4px;
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
          .playlistList {
            max-height: min(300px, 34vh);
            border: 1px solid #202630;
            border-radius: 8px;
            padding: 8px;
            background: rgba(16, 19, 24, 0.62);
          }
          .playlistCard {
            min-height: 72px;
            grid-template-columns: 52px minmax(0, 1fr);
            gap: 10px;
            padding: 9px;
          }
          .playlistCard :global(.artwork--lg),
          .playlistCard :global(.coverFallback.artwork--lg) {
            width: 52px;
            height: 52px;
          }
          .playlistCard strong {
            font-size: 14px;
          }
          .playlistCard small {
            font-size: 11px;
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
          .addSongCards,
          .addNowGrid,
          .cleanupRules,
          .trackLimitGrid,
          .rotatorCards,
          .flexSettings,
          .futureAddGrid {
            grid-template-columns: 1fr;
          }
          .cleanupIntro {
            align-items: start;
          }
          .cleanupRuleHeader {
            grid-template-columns: 38px minmax(0, 1fr);
          }
          .cleanupRuleHeader .cleanupSwitch {
            grid-column: 1 / -1;
            justify-self: start;
          }
          .toolActions {
            display: grid;
            grid-template-columns: 1fr;
          }
          .flexSettings,
          .rotatorRules,
          .healthGrid,
          .futureAddItem,
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
