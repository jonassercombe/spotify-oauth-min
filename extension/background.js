const API_BASE = "https://playlist-pilot.com";
const AUTH_KEY = "playlistpilotAuth";
const CONTEXT_KEY = "playlistpilotContexts";
const CONNECT_NONCE_KEY = "playlistpilotConnectNonce";
const ACCOUNT_PROFILES_KEY = "playlistpilotPlatformProfiles";
const SESSION_SNAPSHOTS_KEY = "playlistpilotSessionSnapshots";
const REVIEW_QUEUE_CACHE_KEY = "playlistpilotReviewQueueCache";
const FULL_SCAN_SNAPSHOT_KEY = "playlistpilotFullScanSnapshot";
const FOCUSED_TRACK_KEY = "playlistpilotFocusedTrack";
const SUBMITHUB_AD_SETTINGS_KEY = "playlistpilotSubmitHubAdSettingsV1";
const ADAPTER_REGISTRY_CACHE_KEY = "playlistpilotAdapterRegistryV1";
const FEEDBACK_TEMPLATES_KEY = "playlistpilotFeedbackTemplates";
const FEEDBACK_CONTEXT_MENU_ID = "playlistpilot-generate-from-selection";
const FEEDBACK_PROFILE_MENU_PREFIX = `${FEEDBACK_CONTEXT_MENU_ID}:profile:`;
const SUPPORTED_PLATFORMS = new Set(["submithub", "groover", "playlistpush", "unhurd"]);
const AUTH_REFRESH_ALARM = "playlistpilot-auth-refresh";
const SUBMITHUB_AD_DETAIL_DELAY_MS = 3000;
let sessionWriteQueue = Promise.resolve();
let fullScanRunning = null;
let submitHubAdScanRunning = null;
let authRefreshPromise = null;
const recentCompletedReviews = new Map();
const reviewNavigationHistory = [];
let reviewQueueState = { items: [], currentKey: "", scannedAt: 0 };

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function waitForTabReady(tabId, timeoutMs = 20000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const tab = await browser.tabs.get(tabId).catch(() => null);
    if (!tab) throw new Error("Collector tab closed unexpectedly");
    if (tab.status === "complete") {
      await delay(350);
      return tab;
    }
    await delay(200);
  }
  throw new Error("Collector page took too long to load");
}

async function waitForTabUrlReady(tabId, expectedUrl, timeoutMs = 20000) {
  const expected = new URL(expectedUrl).href;
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const tab = await browser.tabs.get(tabId).catch(() => null);
    if (!tab) throw new Error("Collector tab closed unexpectedly");
    if (tab.status === "complete" && new URL(tab.url || expected).href === expected) {
      await delay(350);
      return tab;
    }
    await delay(200);
  }
  throw new Error(`Collector did not reach ${new URL(expected).pathname}`);
}

function platformForUrl(value) {
  try {
    const host = new URL(value || "").hostname;
    if (host === "submithub.com" || host.endsWith(".submithub.com")) return "submithub";
    if (host === "groover.co" || host.endsWith(".groover.co")) return "groover";
    if (host === "app.playlistpush.com") return "playlistpush";
    if (host === "curator.unhurdmusic.com") return "unhurd";
  } catch {}
  return "";
}

function locationForPlatform(platform) {
  if (platform === "groover") return "https://groover.co/en/influencer/dashboard/?tab=to_do&f=toReview";
  if (platform === "playlistpush") return "https://app.playlistpush.com/my/reviews";
  if (platform === "unhurd") return "https://curator.unhurdmusic.com/pitches";
  return "https://www.submithub.com/";
}

function sessionKey(platform, cookieStoreId = "firefox-default") {
  return `${platform}:${cookieStoreId || "firefox-default"}`;
}

async function storedProfiles() {
  const value = (await browser.storage.local.get(ACCOUNT_PROFILES_KEY))[ACCOUNT_PROFILES_KEY];
  return Array.isArray(value) ? value : [];
}

async function reorderAccountProfiles(profileIds = []) {
  const profiles = await storedProfiles();
  const byId = new Map(profiles.map((profile) => [profile.id, profile]));
  const ordered = profileIds.map((id) => byId.get(String(id))).filter(Boolean);
  const seen = new Set(ordered.map((profile) => profile.id));
  ordered.push(...profiles.filter((profile) => !seen.has(profile.id)));
  await browser.storage.local.set({ [ACCOUNT_PROFILES_KEY]: ordered });
  await browser.runtime.sendMessage({ type: "COCKPIT_UPDATED" }).catch(() => {});
  return { ok: true };
}

async function storedSessions() {
  const value = (await browser.storage.local.get(SESSION_SNAPSHOTS_KEY))[SESSION_SNAPSHOTS_KEY];
  return value && typeof value === "object" ? value : {};
}

function updateStoredSessions(mutator) {
  const job = sessionWriteQueue.catch(() => {}).then(async () => {
    const sessions = await storedSessions();
    const result = await mutator(sessions);
    await browser.storage.local.set({ [SESSION_SNAPSHOTS_KEY]: sessions });
    return result;
  });
  sessionWriteQueue = job;
  return job;
}

function contextInbox(context = {}) {
  const inbox = context.inbox || {};
  if (context.platform === "groover") {
    return { open: Number(inbox.total || 0), urgent: Number(inbox.urgent || 0) };
  }
  if (context.platform === "playlistpush" || context.platform === "unhurd") {
    const open = Number(inbox.total || 0);
    return { open, urgent: open };
  }
  return { open: Number(inbox.total ?? inbox.visible ?? 0), urgent: 0 };
}

function deadlineHours(value) {
  const text = String(value || "").toLowerCase();
  const hours = Number(text.match(/(\d+(?:\.\d+)?)\s*(?:hours?|hrs?|h)\b/)?.[1]);
  if (Number.isFinite(hours)) return hours;
  const minutes = Number(text.match(/(\d+(?:\.\d+)?)\s*(?:minutes?|mins?|m)\b/)?.[1]);
  if (Number.isFinite(minutes)) return minutes / 60;
  const days = Number(text.match(/(\d+(?:\.\d+)?)\s*days?\b/)?.[1]);
  return Number.isFinite(days) ? days * 24 : null;
}

function dueWithin24Count(context = {}) {
  if (context.platform === "playlistpush" || context.platform === "unhurd") {
    return Number(context.inbox?.total ?? context.inbox?.visible ?? 0);
  }
  const uniqueSubmissions = Array.isArray(context.submissions)
    ? [...new Map(context.submissions.map((submission, index) => [
      String(submission?.id || `${submission?.title || "submission"}-${index}`),
      submission,
    ])).values()]
    : [];
  const submissionDeadlines = uniqueSubmissions
    .map((submission) => submission.deadlineLabel)
    .filter(Boolean);
  const values = context.platform === "groover"
    ? (submissionDeadlines.length ? submissionDeadlines : (context.inbox?.toListenDeadlineLabels || []))
    : submissionDeadlines.length
      ? submissionDeadlines
      : [context.deadlineLabel, ...(context.inbox?.deadlineLabels || [])].filter(Boolean);
  const detected = values.filter((value) => {
    const hours = deadlineHours(value);
    return hours !== null && hours <= 24;
  }).length;
  return detected;
}

function quickSwitchBadge(context = {}) {
  const allOpenAreUrgent = context.platform === "playlistpush" || context.platform === "unhurd";
  const count = allOpenAreUrgent
    ? Number(context.inbox?.total ?? context.inbox?.visible ?? 0)
    : dueWithin24Count(context);
  return {
    count,
    label: allOpenAreUrgent ? "open submissions" : "submissions due within 24 hours",
  };
}

function normalizeWorkflow(platform, input = {}) {
  const fallback = platform === "groover" ? 4 : 8;
  const expiryWeeks = Number(input.expiryWeeks ?? input.expiry_weeks ?? fallback);
  const position = Number(input.position);
  return {
    playlistId: String(input.playlistId || input.playlist_id || "").slice(0, 120),
    expiryWeeks: Number.isInteger(expiryWeeks) && expiryWeeks >= 1 && expiryWeeks <= 104 ? expiryWeeks : fallback,
    position: Number.isInteger(position) && position >= 1 && position <= 10000 ? position : null,
    lock: !!input.lock,
    autoPrepare: input.autoPrepare !== false,
    trackingEnabled: input.trackingEnabled !== false,
  };
}

function normalizeEarnings(input = {}) {
  const amount = Number(input.amount ?? input.rate ?? 0);
  const currency = String(input.currency || "EUR").trim().toUpperCase();
  return {
    enabled: input.enabled !== false,
    amount: Number.isFinite(amount) && amount >= 0 && amount <= 10000 ? Math.round(amount * 10000) / 10000 : 0,
    currency: /^[A-Z]{3}$/.test(currency) ? currency : "EUR",
  };
}

async function profileForPlatformSession(platform, cookieStoreId = "firefox-default", platformProfile = "") {
  const profiles = await storedProfiles();
  const key = sessionKey(platform, cookieStoreId);
  const sessions = await storedSessions();
  const mappedId = sessions[key]?.profileId;
  const candidates = profiles.filter((profile) =>
    profile.platform === platform && (profile.cookieStoreId || "firefox-default") === cookieStoreId
  );
  const detected = String(platformProfile || "").trim().toLowerCase();
  const exactSessionMatch = candidates.find((profile) => profile.id === mappedId) ||
    (detected ? candidates.find((profile) => {
      const name = String(profile.name || "").trim().toLowerCase();
      return name && (detected.includes(name) || name.includes(detected));
    }) : null) || candidates[0] || null;
  if (exactSessionMatch) return exactSessionMatch;
  if (!detected) return null;
  const detectedMatches = profiles.filter((profile) => {
    if (profile.platform !== platform) return false;
    const values = [profile.name, profile.platformProfile]
      .map((value) => String(value || "").trim().toLowerCase())
      .filter(Boolean);
    return values.some((value) => detected.includes(value) || value.includes(detected));
  });
  return detectedMatches.length === 1 ? detectedMatches[0] : null;
}

async function recordReviewEarning(review, tab, resolvedProfile = null) {
  const platform = String(review?.platform || "").toLowerCase();
  const cookieStoreId = tab?.cookieStoreId || "firefox-default";
  const profile = resolvedProfile || await profileForPlatformSession(platform, cookieStoreId, review?.platformProfile);
  if (!profile) return { ok: true, ignored: true, reason: "account_profile_missing" };
  const earnings = normalizeEarnings(profile.earnings);
  if (!earnings.enabled || earnings.amount <= 0) return { ok: true, ignored: true, reason: "earnings_disabled" };
  return api("/api/extension/review-earnings", {
    method: "POST",
    body: {
      ...review,
      accountProfileId: profile.id,
      amount: earnings.amount,
      currency: earnings.currency,
    },
  });
}

async function storedAuth() {
  return (await browser.storage.local.get(AUTH_KEY))[AUTH_KEY] || null;
}

async function setAuth(session) {
  if (!session) {
    await browser.storage.local.remove(AUTH_KEY);
    return;
  }
  await browser.storage.local.set({
    [AUTH_KEY]: {
      access_token: session.access_token,
      refresh_token: session.refresh_token,
      expires_at: Number(session.expires_at || 0),
      email: session.email || "",
    },
  });
}

function isInvalidRefreshError(status, message) {
  return (status === 400 || status === 401) &&
    /invalid.*refresh|refresh.*invalid|refresh.*expired|already used|session.*not found/i.test(String(message || ""));
}

async function refreshSession(requestedSession) {
  if (authRefreshPromise) return authRefreshPromise;
  authRefreshPromise = (async () => {
    const session = await storedAuth();
    if (!session?.refresh_token) throw new Error("PlaylistPilot session expired");

    // A concurrent request may have completed token rotation already. Never send
    // the superseded one-use refresh token again.
    if (requestedSession?.refresh_token && requestedSession.refresh_token !== session.refresh_token) return session;

    let lastError = null;
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      try {
        const response = await fetch(`${API_BASE}/api/extension/auth/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: session.refresh_token }),
        });
        const payload = await response.json().catch(() => ({}));
        if (response.ok && payload?.access_token) {
          const next = {
            ...session,
            access_token: payload.access_token,
            refresh_token: payload.refresh_token || session.refresh_token,
            expires_at: Number(payload.expires_at || Math.floor(Date.now() / 1000) + Number(payload.expires_in || 3600)),
            refreshed_at: Math.floor(Date.now() / 1000),
          };
          await setAuth(next);
          console.info("[auth] PlaylistPilot session refreshed", { expiresAt: next.expires_at });
          return next;
        }
        const message = payload?.error || "Could not refresh PlaylistPilot session";
        if (isInvalidRefreshError(response.status, message)) {
          await setAuth(null);
          console.warn("[auth] refresh token is no longer valid; reconnect required", { status: response.status });
          throw new Error("PlaylistPilot connection expired. Please connect once more.");
        }
        lastError = new Error(message);
        if (response.status < 500 && response.status !== 429) break;
      } catch (error) {
        if (/connection expired/i.test(String(error?.message || ""))) throw error;
        lastError = error;
      }
      if (attempt < 3) await delay(attempt * 500);
    }
    console.warn("[auth] temporary session refresh failure; stored login retained", {
      error: String(lastError?.message || lastError || "unknown"),
    });
    throw lastError || new Error("Could not refresh PlaylistPilot session");
  })().finally(() => {
    authRefreshPromise = null;
  });
  return authRefreshPromise;
}

async function validSession() {
  let session = await storedAuth();
  if (!session) throw new Error("Connect PlaylistPilot first");
  const expiresSoon = !session.expires_at || session.expires_at * 1000 < Date.now() + 10 * 60_000;
  if (expiresSoon) session = await refreshSession(session);
  return session;
}

async function api(path, options = {}, retry = true) {
  const session = await validSession();
  const response = await fetch(`${API_BASE}${path}`, {
    method: options.method || "GET",
    headers: {
      Authorization: `Bearer ${session.access_token}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  if (response.status === 401 && retry) {
    await refreshSession(session);
    return api(path, options, false);
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload?.error || `PlaylistPilot request failed (${response.status})`);
  return payload;
}

async function saveContext(tab, context, { notify = true } = {}) {
  const tabId = typeof tab === "object" ? tab?.id : tab;
  if (!tabId || !context?.platform) return null;
  const cookieStoreId = typeof tab === "object" ? tab.cookieStoreId || "firefox-default" : "firefox-default";
  const now = new Date().toISOString();
  const normalized = {
    ...context,
    tabId,
    windowId: typeof tab === "object" ? tab.windowId : undefined,
    cookieStoreId,
    url: typeof tab === "object" ? tab.url || "" : context.url || "",
    observedAt: now,
    adapterVersion: context.adapterVersion || "legacy",
  };
  const stored = (await browser.storage.local.get(CONTEXT_KEY))[CONTEXT_KEY] || {};
  stored[String(tabId)] = normalized;
  await browser.storage.local.set({ [CONTEXT_KEY]: stored });
  const profiles = await storedProfiles();
  const matchedProfile = profiles.find((profile) =>
    profile.platform === context.platform && profile.cookieStoreId === cookieStoreId
  );
  const key = sessionKey(context.platform, cookieStoreId);
  await updateStoredSessions((sessions) => {
    sessions[key] = {
      ...(sessions[key] || {}),
      key,
      profileId: matchedProfile?.id || sessions[key]?.profileId || "",
      platform: context.platform,
      cookieStoreId,
      tabId,
      windowId: normalized.windowId,
      url: normalized.url,
      platformProfile: context.platformProfile || sessions[key]?.platformProfile || "",
      context: normalized,
      health: "ok",
      lastSeenAt: now,
      lastError: "",
    };
  });
  if (notify) {
    await browser.runtime.sendMessage({ type: "PLATFORM_CONTEXT_UPDATED", context: normalized }).catch(() => {});
    await browser.runtime.sendMessage({ type: "COCKPIT_UPDATED" }).catch(() => {});
  }
  return normalized;
}

async function refreshAccountAfterReview(tab, review = {}) {
  const platform = String(review.platform || platformForUrl(tab?.url)).toLowerCase();
  if (!tab?.id || !SUPPORTED_PLATFORMS.has(platform)) return;
  const cookieStoreId = tab.cookieStoreId || "firefox-default";
  const completionKey = `${platform}:${cookieStoreId}:${review.platformSubmissionId || review.spotifyTrackId || "current"}`;
  const now = Date.now();
  for (const [key, timestamp] of recentCompletedReviews) {
    if (now - timestamp > 30000) recentCompletedReviews.delete(key);
  }
  if (!recentCompletedReviews.has(completionKey)) {
    recentCompletedReviews.set(completionKey, now);
    const key = sessionKey(platform, cookieStoreId);
    await updateStoredSessions((sessions) => {
      const session = sessions[key];
      if (!session?.context) return;
      const context = session.context;
      const completedId = String(review.platformSubmissionId || "");
      const submissions = Array.isArray(context.submissions)
        ? context.submissions.filter((submission) => !completedId || String(submission?.id || "") !== completedId)
        : [];
      const oldTotal = Number(context.inbox?.total ?? context.inbox?.visible ?? 0);
      const oldUrgent = Number(context.inbox?.urgent || 0);
      const completedSubmission = Array.isArray(context.submissions)
        ? context.submissions.find((submission) => completedId && String(submission?.id || "") === completedId)
        : null;
      const completedHours = deadlineHours(completedSubmission?.deadlineLabel);
      const wasDueSoon = completedHours !== null && completedHours <= 24;
      session.context = {
        ...context,
        submissions,
        inbox: {
          ...(context.inbox || {}),
          total: Math.max(0, oldTotal - 1),
          urgent: platform === "playlistpush" || platform === "unhurd"
            ? Math.max(0, oldTotal - 1)
            : Math.max(0, oldUrgent - (wasDueSoon ? 1 : 0)),
        },
      };
      session.lastSeenAt = new Date().toISOString();
    });
    await browser.runtime.sendMessage({ type: "COCKPIT_UPDATED" }).catch(() => {});
  }

  // Reconcile the optimistic decrement with the platform's settled DOM. This
  // reads only the existing tab; it never reloads or navigates the page.
  setTimeout(async () => {
    const liveTab = await browser.tabs.get(tab.id).catch(() => null);
    if (!liveTab) return;
    const live = await sendToPlatformTab(liveTab, { type: "SCAN_PLATFORM" }).catch(() => null);
    if (live?.platform) await saveContext(liveTab, live);
  }, 1200);
}

async function activeContext() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab?.id) return null;
  try {
    const live = await sendToPlatformTab(tab, { type: "SCAN_PLATFORM" });
    if (live?.platform) {
      return saveContext(tab, live);
    }
  } catch {}
  const stored = (await browser.storage.local.get(CONTEXT_KEY))[CONTEXT_KEY] || {};
  return stored[String(tab.id)] || null;
}

async function sendToPlatformTab(tab, message) {
  if (!tab?.id || !platformForUrl(tab.url)) throw new Error("Open a curator submission first");
  try {
    return await browser.tabs.sendMessage(tab.id, message);
  } catch (initialError) {
    // Tabs that were already open during an extension update do not receive
    // the new declarative content script. Inject it once on demand and retry.
    if (!browser.scripting?.executeScript) throw initialError;
    await browser.scripting.executeScript({
      target: { tabId: tab.id },
      files: ["content/adapter-contract.js", "content/content-script.js"],
    });
    return browser.tabs.sendMessage(tab.id, message);
  }
}

async function markSessionError(tab, error) {
  const platform = platformForUrl(tab?.url);
  if (!platform || !tab?.id) return;
  const cookieStoreId = tab.cookieStoreId || "firefox-default";
  const key = sessionKey(platform, cookieStoreId);
  await updateStoredSessions((sessions) => {
    sessions[key] = {
      ...(sessions[key] || {}),
      key,
      platform,
      cookieStoreId,
      tabId: tab.id,
      url: tab.url || "",
      health: "unreadable",
      lastError: String(error?.message || error || "page_not_readable").slice(0, 300),
      lastAttemptAt: new Date().toISOString(),
    };
  });
}

async function scanAllSessions() {
  await browser.storage.local.remove(REVIEW_QUEUE_CACHE_KEY);
  const tabs = await browser.tabs.query({});
  const supportedTabs = tabs.filter((tab) => platformForUrl(tab.url));
  let scanned = 0;
  let failed = 0;
  for (const tab of supportedTabs) {
    try {
      const context = await browser.tabs.sendMessage(tab.id, { type: "SCAN_PLATFORM" });
      if (!context?.platform) throw new Error("platform_context_missing");
      await saveContext(tab, context, { notify: false });
      scanned += 1;
    } catch (error) {
      failed += 1;
      await markSessionError(tab, error);
    }
  }
  await browser.runtime.sendMessage({ type: "COCKPIT_UPDATED" }).catch(() => {});
  return { ok: true, tabs: supportedTabs.length, scanned, failed };
}

async function notifyFullScan(progress) {
  await browser.runtime.sendMessage({ type: "FULL_SCAN_PROGRESS", progress }).catch(() => {});
}

async function adapterRegistry({ force = false } = {}) {
  const cached = (await browser.storage.local.get(ADAPTER_REGISTRY_CACHE_KEY))[ADAPTER_REGISTRY_CACHE_KEY];
  if (!force && cached?.fetchedAt && Date.now() - Date.parse(cached.fetchedAt) < 6 * 60 * 60 * 1000) return cached.releases || [];
  try {
    const response = await api("/api/extension/adapters");
    const releases = Array.isArray(response.releases) ? response.releases : [];
    await browser.storage.local.set({ [ADAPTER_REGISTRY_CACHE_KEY]: { releases, fetchedAt: new Date().toISOString() } });
    return releases;
  } catch {
    return cached?.releases || [];
  }
}

function rescueConfigFor(releases, platform) {
  return releases.find((release) => release.platform === platform && release.page_kind === "any") || null;
}

async function scanTabWithRetries(tab, attempts = 12, releases = []) {
  let lastError = null;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const platform = platformForUrl(tab.url);
      const context = await sendToPlatformTab(tab, { type: "SCAN_PLATFORM", rescueConfig: rescueConfigFor(releases, platform) });
      if (context?.platform) return context;
      lastError = new Error("No platform data found");
    } catch (error) {
      lastError = error;
    }
    await delay(350);
  }
  throw lastError || new Error("Platform page could not be read");
}

async function waitForSubmitHubProfile(tabId, profileName, timeoutMs = 12000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const tab = await browser.tabs.get(tabId).catch(() => null);
    if (!tab) throw new Error("SubmitHub account tab closed unexpectedly");
    if (tab.status === "complete") {
      const context = await browser.tabs.sendMessage(tabId, { type: "SCAN_PLATFORM" }).catch(() => null);
      if (context?.platform === "submithub" && String(context.platformProfile || "").toLowerCase().includes(profileName.toLowerCase())) return context;
    }
    await delay(300);
  }
  throw new Error(`SubmitHub did not switch to ${profileName}`);
}

async function scanSubmitHubAdsWhenReady(tabId, timeoutMs = 15000) {
  const started = Date.now();
  let latest = null;
  while (Date.now() - started < timeoutMs) {
    latest = await browser.tabs.sendMessage(tabId, { type: "SCAN_SUBMITHUB_ADS" }).catch(() => null);
    if (latest?.ok && (latest.detailUrls?.length || latest.campaigns?.length)) return latest;
    if (latest?.error && /login|captcha|security|blocked|rate.limit/i.test(latest.error)) return latest;
    await delay(500);
  }
  return latest;
}

async function scanSubmitHubAdDetailWhenReady(tabId, timeoutMs = 12000) {
  const started = Date.now();
  let latest = null;
  while (Date.now() - started < timeoutMs) {
    latest = await browser.tabs.sendMessage(tabId, { type: "SCAN_SUBMITHUB_AD_DETAIL" }).catch(() => null);
    if (latest?.ok && latest.status !== "unknown" && (latest.dailySpend !== null || latest.remaining !== null)) return latest;
    if (latest?.error && /login|captcha|security|blocked|rate.limit/i.test(latest.error)) return latest;
    await delay(400);
  }
  return latest;
}

async function collectSubmitHubAds(tab, onProgress = null) {
  const cookieStoreId = tab.cookieStoreId || "firefox-default";
  if (cookieStoreId !== "firefox-default") {
    const identity = await browser.contextualIdentities.get(cookieStoreId).catch(() => null);
    if (!identity) throw new Error(`The saved Firefox container ${cookieStoreId} no longer exists. Reassign the SubmitHub account session.`);
  }
  const collector = await browser.tabs.create({
    url: "https://www.submithub.com/",
    cookieStoreId,
    active: false,
  });
  try {
    await waitForTabReady(collector.id);
    const switched = await browser.tabs.sendMessage(collector.id, { type: "SWITCH_SUBMITHUB_ACCOUNT", name: "bored indie kid" }).catch(() => null);
    if (switched?.ok) {
      await delay(1000);
      await waitForTabReady(collector.id).catch(() => null);
    }
    const routes = await browser.tabs.sendMessage(collector.id, { type: "DISCOVER_SUBMITHUB_SCAN_ROUTES" }).catch(() => null);
    const adsUrl = routes?.adsUrl;
    if (!adsUrl) return { available: false, campaigns: [], warning: "SubmitHub ads page was not found in this profile navigation." };
    await browser.tabs.update(collector.id, { url: adsUrl });
    await waitForTabUrlReady(collector.id, adsUrl);
    const result = await scanSubmitHubAdsWhenReady(collector.id);
    if (!result?.ok) return { available: false, campaigns: [], warning: result?.error || "SubmitHub ads page could not be read." };
    const campaigns = [];
    const activeItems = (result.detailUrls || [])
      .filter((item) => /^active$/i.test(String(item.status || "")))
      .slice(0, 50);
    let warning = "";
    for (let index = 0; index < activeItems.length; index += 1) {
      const item = activeItems[index];
      await onProgress?.({ current: index + 1, total: activeItems.length, label: item.name || "Campaign" });
      if (index > 0) await delay(SUBMITHUB_AD_DETAIL_DELAY_MS);
      const detailUrl = new URL(item.url);
      detailUrl.searchParams.set("tab", "ads");
      await browser.tabs.update(collector.id, { url: detailUrl.href });
      try {
        await waitForTabUrlReady(collector.id, detailUrl.href, 12000);
      } catch {
        warning = `Campaign ${index + 1}/${activeItems.length} took too long to load. Scan stopped.`;
        break;
      }
      await browser.tabs.sendMessage(collector.id, { type: "OPEN_SUBMITHUB_AD_DETAIL" }).catch(() => null);
      const detail = await scanSubmitHubAdDetailWhenReady(collector.id);
      if (!detail?.ok) {
        warning = detail?.error || "Some campaign detail metrics could not be read; overview performance is still shown.";
        campaigns.push({
          id: item.url,
          name: item.name,
          url: item.url,
          status: item.status,
          spent: null,
          dailySpend: null,
          remaining: null,
          impressions: item.overview?.views ?? null,
          conversions: item.overview?.conversions ?? null,
          ctr: item.overview?.ctr ?? null,
          detailReadable: false,
        });
        continue;
      }
      const status = detail?.status && detail.status !== "unknown" ? detail.status : item.status;
      if (detail?.ok && /^active$/i.test(String(status || ""))) campaigns.push({
        ...detail,
        status,
        name: item.name || detail.name,
        impressions: detail.impressions ?? item.overview?.views ?? null,
        conversions: detail.conversions ?? item.overview?.conversions ?? null,
        ctr: detail.ctr ?? item.overview?.ctr ?? null,
      });
    }
    const totals = campaigns.reduce((sum, item) => ({
      credits: sum.credits + Number(item.spent || 0),
      dailySpend: sum.dailySpend + Number(item.dailySpend || 0),
      remaining: sum.remaining + Number(item.remaining || 0),
      impressions: sum.impressions + Number(item.impressions || 0),
      adClicks: sum.adClicks + Number(item.adClicks || 0),
      conversions: sum.conversions + Number(item.conversions || 0),
    }), { credits: 0, dailySpend: 0, remaining: 0, impressions: 0, adClicks: 0, conversions: 0 });
    totals.usd = totals.credits * 0.5;
    totals.ctr = totals.impressions > 0 ? totals.adClicks / totals.impressions * 100 : null;
    totals.dailySpendReadable = campaigns.filter((item) => Number.isFinite(Number(item.dailySpend))).length;
    totals.activeCampaigns = activeItems.length;
    const missingDailySpend = Math.max(0, activeItems.length - totals.dailySpendReadable);
    return {
      ok: true,
      available: true,
      campaigns,
      totals,
      warning: warning || (missingDailySpend
        ? `${missingDailySpend}/${activeItems.length} active campaign budgets could not be read. Scan again before syncing.`
        : campaigns.length ? "" : "No active SubmitHub ads were found."),
    };
  } finally {
    await browser.tabs.remove(collector.id).catch(() => {});
  }
}

async function scanSubmitHubAdsOnly() {
  if (submitHubAdScanRunning) return submitHubAdScanRunning;
  submitHubAdScanRunning = (async () => {
    const profiles = await storedProfiles();
    const submitHubProfiles = profiles.filter((item) => item.platform === "submithub");
    if (!submitHubProfiles.length) throw new Error("No SubmitHub account is configured in PlaylistPilot.");
    submitHubProfiles.sort((left, right) => {
      const score = (item) => /bored indie kid|\bbik\b/i.test(`${item.name || ""} ${item.platformProfile || ""}`) ? 1 : 0;
      return score(right) - score(left);
    });
    await browser.runtime.sendMessage({ type: "SUBMITHUB_AD_SCAN_PROGRESS", progress: { phase: "starting" } }).catch(() => {});
    let ads = null;
    const attemptedStores = new Set();
    const failures = [];
    for (const profile of submitHubProfiles) {
      const cookieStoreId = profile.cookieStoreId || "firefox-default";
      if (attemptedStores.has(cookieStoreId)) continue;
      attemptedStores.add(cookieStoreId);
      try {
        const candidate = await collectSubmitHubAds({ cookieStoreId }, async (progress) => {
          await browser.runtime.sendMessage({ type: "SUBMITHUB_AD_SCAN_PROGRESS", progress: { phase: "campaign", account: profile.name, ...progress } }).catch(() => {});
        });
        if (!ads || (candidate.campaigns?.length || 0) > (ads.campaigns?.length || 0)) ads = candidate;
        if (candidate.campaigns?.length) break;
      } catch (error) {
        failures.push(`${profile.name || cookieStoreId}: ${error.message}`);
      }
    }
    if (!ads) throw new Error(failures[0] || "No readable SubmitHub session was found.");
    ads.profile = "bored indie kid";
    ads.capturedAt = new Date().toISOString();
    const previous = await fullScanSnapshot();
    const snapshot = previous
      ? { ...previous, submitHubAds: ads }
      : { startedAt: ads.capturedAt, completedAt: ads.capturedAt, results: [], totals: { open: 0, urgent: 0, dueWithin24: 0, readable: 0 }, submitHubAds: ads };
    await browser.storage.local.set({ [FULL_SCAN_SNAPSHOT_KEY]: snapshot });
    await browser.runtime.sendMessage({ type: "SUBMITHUB_AD_SCAN_PROGRESS", progress: { phase: "complete", ads } }).catch(() => {});
    await browser.runtime.sendMessage({ type: "COCKPIT_UPDATED" }).catch(() => {});
    return { ok: true, ads, snapshot };
  })().finally(() => { submitHubAdScanRunning = null; });
  return submitHubAdScanRunning;
}

async function runFullScan() {
  if (fullScanRunning) return fullScanRunning;
  fullScanRunning = (async () => {
    const startedAt = new Date().toISOString();
    const profiles = await storedProfiles();
    const targets = profiles.length ? profiles : [];
    const releases = await adapterRegistry({ force: true });
    const results = [];
    const refreshedTabIds = new Set();
    let submitHubAds = null;
    await notifyFullScan({ phase: "starting", current: 0, total: targets.length, startedAt });
    for (let index = 0; index < targets.length; index += 1) {
      const profile = targets[index];
      const label = profile.name || profile.platform;
      await notifyFullScan({ phase: "scanning", current: index, total: targets.length, label, startedAt });
      let tab = null;
      let temporary = false;
      try {
        const openTabs = await browser.tabs.query({});
        // Unhurd's detail route only exposes the current pitch. A manual Scan
        // uses a quiet, temporary inbox tab so all pending deadlines are read
        // without navigating or refreshing the curator's working tab.
        tab = profile.platform === "unhurd" ? null : openTabs.find((candidate) =>
          platformForUrl(candidate.url) === profile.platform &&
          (candidate.cookieStoreId || "firefox-default") === (profile.cookieStoreId || "firefox-default")
        );
        if (!tab) {
          tab = await browser.tabs.create({
            url: locationForPlatform(profile.platform),
            cookieStoreId: profile.cookieStoreId || "firefox-default",
            active: false,
          });
          temporary = true;
          await waitForTabReady(tab.id);
        } else if (!refreshedTabIds.has(tab.id)) {
          await notifyFullScan({ phase: "refreshing", current: index, total: targets.length, label, startedAt });
          await browser.tabs.reload(tab.id);
          await waitForTabReady(tab.id);
          refreshedTabIds.add(tab.id);
        }
        const context = await scanTabWithRetries(tab, 12, releases);
        await saveContext(tab, context, { notify: false });
        const result = {
          profileId: profile.id,
          name: label,
          platform: profile.platform,
          platformProfile: context.platformProfile || "",
          status: "ok",
          inbox: contextInbox(context),
          dueWithin24: dueWithin24Count(context),
          adapterHealth: context.adapterHealth || null,
          capturedAt: new Date().toISOString(),
        };
        results.push(result);
        if (profile.platform === "submithub" && !/bored\s*indie\s*kid/i.test(`${context.platformProfile || ""}`)) {
          const routes = await browser.tabs.sendMessage(tab.id, { type: "DISCOVER_SUBMITHUB_SCAN_ROUTES" }).catch(() => null);
          if (routes?.accountOptions?.some((item) => /bored\s*indie\s*kid/i.test(item.name))) {
            await browser.tabs.sendMessage(tab.id, { type: "SWITCH_SUBMITHUB_ACCOUNT", name: "bored indie kid" });
            const switchedContext = await waitForSubmitHubProfile(tab.id, "bored indie kid");
            await saveContext(tab, switchedContext, { notify: false });
            results.push({
              profileId: `${profile.id}:bored-indie-kid`,
              parentProfileId: profile.id,
              name: "bored indie kid",
              platform: "submithub",
              platformProfile: switchedContext.platformProfile || "bored indie kid",
              status: "ok",
              inbox: contextInbox(switchedContext),
              dueWithin24: dueWithin24Count(switchedContext),
              capturedAt: new Date().toISOString(),
            });
          }
        }
        // The collector performs its own internal profile switch, so account
        // aliases such as "BIK" or "My Spotify Account" must not prevent it
        // from running. One SubmitHub Firefox session is sufficient.
        if (profile.platform === "submithub" && !submitHubAds) {
          submitHubAds = await collectSubmitHubAds(tab);
          submitHubAds.profile = "bored indie kid";
          submitHubAds.capturedAt = new Date().toISOString();
        }
      } catch (error) {
        results.push({ profileId: profile.id, name: label, platform: profile.platform, status: "error", error: String(error?.message || error), capturedAt: new Date().toISOString() });
      } finally {
        if (temporary && tab?.id) await browser.tabs.remove(tab.id).catch(() => {});
      }
      await notifyFullScan({ phase: "scanning", current: index + 1, total: targets.length, label, startedAt });
    }
    const totals = results.reduce((sum, result) => ({
      open: sum.open + Number(result.inbox?.open || 0),
      urgent: sum.urgent + Number(result.inbox?.urgent || 0),
      dueWithin24: sum.dueWithin24 + Number(result.dueWithin24 || 0),
      readable: sum.readable + (result.status === "ok" ? 1 : 0),
    }), { open: 0, urgent: 0, dueWithin24: 0, readable: 0 });
    const snapshot = { startedAt, completedAt: new Date().toISOString(), results, totals, submitHubAds };
    const healthReports = results.map((result) => result.adapterHealth).filter(Boolean);
    if (healthReports.length) await api("/api/extension/adapters/health", {
      method: "POST",
      body: { extensionVersion: browser.runtime.getManifest().version, reports: healthReports },
    }).catch(() => null);
    await browser.storage.local.set({ [FULL_SCAN_SNAPSHOT_KEY]: snapshot });
    await notifyFullScan({ phase: "complete", current: targets.length, total: targets.length, snapshot });
    await browser.runtime.sendMessage({ type: "COCKPIT_UPDATED" }).catch(() => {});
    return { ok: true, snapshot };
  })().finally(() => { fullScanRunning = null; });
  return fullScanRunning;
}

async function fullScanSnapshot() {
  return (await browser.storage.local.get(FULL_SCAN_SNAPSHOT_KEY))[FULL_SCAN_SNAPSHOT_KEY] || null;
}

function feedbackParts(selection = "") {
  const likes = [];
  const mismatch = [];
  for (const rawLine of String(selection).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (/^\+\s*/.test(line)) likes.push(line.replace(/^\+\s*/, "").trim());
    if (/^-\s*/.test(line)) mismatch.push(line.replace(/^-\s*/, "").trim());
  }
  if (!likes.length && !mismatch.length) {
    const matches = [...String(selection).matchAll(/(?:^|\s)([+-])\s*([^+-]+?)(?=(?:\s[+-]\s)|$)/g)];
    for (const match of matches) (match[1] === "+" ? likes : mismatch).push(match[2].trim());
  }
  return { likes: likes.join(" "), mismatch: mismatch.join(" ") };
}

function feedbackSamples(value = "") {
  return String(value || "").split(/\n\s*\n+/).map((sample) => sample.replace(/\s+/g, " ").trim()).filter((sample) => sample.length >= 8).slice(0, 24);
}

function normalizedPlacementPlaylist(value) {
  let clean = String(value || "").replace(/\s+/g, " ").trim();
  clean = clean.replace(/^(?:add (?:the )?song to|share (?:it )?in)\s*/i, "");
  clean = clean.split(/\s+(?=When\s*:|Position\s*:|Scheduled\s*:)/i)[0].trim();
  if (!clean || clean.length > 180 || /^(?:When|Position|Scheduled)\s*:/i.test(clean)) return "";
  if (/^(?:selected|select|choose|playlist|add to playlist|modify|today|tomorrow|immediately)$/i.test(clean)) return "";
  return clean;
}

const UNKNOWN_PLAYLIST_PLACEHOLDER = "[PLAYLIST NAME]";

async function generateFeedbackFromSelection(tab, selection, profileId = "") {
  const context = await browser.tabs.sendMessage(tab.id, { type: "GET_FEEDBACK_GENERATION_CONTEXT" })
    .catch(() => tabReviewContext(tab)) || {};
  const { likes, mismatch } = feedbackParts(selection);
  if (!likes && !mismatch) throw new Error("Prefix the selected notes with + or - first");
  const mode = likes && !mismatch ? "accept" : "decline";
  const detectedPlaylists = Array.isArray(context.selectedPlatformPlaylists)
    ? [...new Set(context.selectedPlatformPlaylists.map(normalizedPlacementPlaylist).filter(Boolean))].slice(0, 10)
    : [];
  const selectedPlaylists = mode === "accept" && !detectedPlaylists.length
    ? [UNKNOWN_PLAYLIST_PLACEHOLDER]
    : detectedPlaylists;
  const [stored, profiles] = await Promise.all([
    browser.storage.local.get(FEEDBACK_TEMPLATES_KEY),
    storedProfiles(),
  ]);
  const templates = Array.isArray(stored[FEEDBACK_TEMPLATES_KEY]) ? stored[FEEDBACK_TEMPLATES_KEY] : [];
  const profile = profiles.find((item) => item.platform === context.platform && item.cookieStoreId === (tab.cookieStoreId || "firefox-default"));
  const template = templates.find((item) => item.id === profileId) ||
    templates.find((item) => profile && item.scope === `account:${profile.id}`) ||
    templates.find((item) => item.scope === `platform:${context.platform}`) ||
    templates.find((item) => item.scope === "global") || templates[0] || {};
  const result = await api("/api/extension/feedback/generate", {
    method: "POST",
    body: {
      mode,
      likes,
      mismatch,
      references: feedbackSamples(template.references),
      settings: {
        templateName: template.name || "My voice",
        language: template.language || "auto",
        tone: template.tone || "matched",
        length: template.length || "matched",
        imperfections: template.imperfections || "matched",
        grammar: template.grammar || "matched",
        customRules: template.customRules || "",
      },
      track: { title: context.trackTitle || "", artists: context.artistNames || [], platform: context.platform || "" },
      placement: mode === "accept" ? {
        playlists: selectedPlaylists,
        weeks: Number(context.placementWeeks) || Number(profile?.workflow?.expiryWeeks) ||
          (context.platform === "groover" ? 4 : context.platform === "playlistpush" ? 8 : null),
      } : null,
    },
  });
  if (!result?.feedback) throw new Error("No feedback draft was returned");
  return result.feedback;
}

async function saveAccountProfile(input = {}) {
  const platform = String(input.platform || "").toLowerCase();
  if (!SUPPORTED_PLATFORMS.has(platform)) throw new Error("Choose a supported platform");
  const name = String(input.name || "").trim().slice(0, 80);
  if (!name) throw new Error("Account name is required");

  let cookieStoreId = String(input.cookieStoreId || "firefox-default");
  let containerName = "";
  if (cookieStoreId === "__new__") {
    if (!browser.contextualIdentities) throw new Error("Firefox Containers are unavailable");
    const created = await browser.contextualIdentities.create({
      name,
      color: platform === "groover" ? "purple" : platform === "playlistpush" ? "blue" : "green",
      icon: "briefcase",
    });
    cookieStoreId = created.cookieStoreId;
    containerName = created.name;
  }

  const profiles = await storedProfiles();
  const id = String(input.id || crypto.randomUUID());
  const duplicate = profiles.find((profile) =>
    profile.id !== id && profile.platform === platform && profile.cookieStoreId === cookieStoreId
  );
  if (duplicate) throw new Error(`This ${platform} container is already assigned to “${duplicate.name}”`);
  const now = new Date().toISOString();
  const existing = profiles.find((profile) => profile.id === id);
  const profile = {
    ...(existing || {}),
    id,
    name,
    // Saving through the account form is an explicit user choice. Do not let
    // later platform scans replace this label with the detected account name.
    autoDiscovered: false,
    nameSource: "manual",
    platform,
    cookieStoreId,
    containerName: containerName || input.containerName || existing?.containerName || "",
    keepReady: input.keepReady !== false,
    workflow: normalizeWorkflow(platform, input.workflow || existing?.workflow),
    earnings: normalizeEarnings(input.earnings || existing?.earnings),
    createdAt: existing?.createdAt || now,
    updatedAt: now,
  };
  const next = existing
    ? profiles.map((item) => item.id === id ? profile : item)
    : [...profiles, profile];
  await browser.storage.local.set({ [ACCOUNT_PROFILES_KEY]: next });
  await api("/api/extension/review-earning-rates", {
    method: "POST",
    body: { accountProfileId: id, platform, ...profile.earnings },
  }).catch(() => null);

  const key = sessionKey(platform, cookieStoreId);
  await updateStoredSessions((sessions) => {
    for (const [sessionId, session] of Object.entries(sessions)) {
      if (session.profileId === id && sessionId !== key) {
        sessions[sessionId] = { ...session, profileId: "" };
      }
    }
    if (sessions[key]) {
      sessions[key] = { ...sessions[key], profileId: id };
    }
  });
  if (profile.keepReady) await ensureAccountSessions();
  await browser.runtime.sendMessage({ type: "COCKPIT_UPDATED" }).catch(() => {});
  return profile;
}

async function deleteAccountProfile(profileId) {
  const profiles = await storedProfiles();
  const next = profiles.filter((profile) => profile.id !== profileId);
  await browser.storage.local.set({ [ACCOUNT_PROFILES_KEY]: next });
  await updateStoredSessions((sessions) => {
    for (const [key, session] of Object.entries(sessions)) {
      if (session.profileId === profileId) sessions[key] = { ...session, profileId: "" };
    }
  });
  await browser.runtime.sendMessage({ type: "COCKPIT_UPDATED" }).catch(() => {});
  return { ok: true };
}

async function openAccountProfile(profileId) {
  const profile = (await storedProfiles()).find((item) => item.id === profileId);
  if (!profile) throw new Error("Account profile not found");
  const tabs = await browser.tabs.query({});
  const existing = tabs.find((tab) =>
    platformForUrl(tab.url) === profile.platform &&
    (tab.cookieStoreId || "firefox-default") === (profile.cookieStoreId || "firefox-default")
  );
  if (existing?.id) {
    await browser.tabs.update(existing.id, { active: true });
    if (existing.windowId && browser.windows) {
      await browser.windows.update(existing.windowId, { focused: true }).catch(() => {});
    }
    return { ok: true, action: "focused", tabId: existing.id };
  }
  const tab = await browser.tabs.create({
    url: locationForPlatform(profile.platform),
    cookieStoreId: profile.cookieStoreId || "firefox-default",
    active: true,
  });
  return { ok: true, action: "opened", tabId: tab.id };
}

async function focusAccountTab(tabId) {
  const tab = await browser.tabs.get(Number(tabId)).catch(() => null);
  if (!tab?.id || !platformForUrl(tab.url)) throw new Error("This curator tab is no longer open");
  await focusTab(tab);
  return { ok: true, action: "focused", tabId: tab.id };
}

async function openPlatform(platform) {
  if (!SUPPORTED_PLATFORMS.has(platform)) throw new Error("Unsupported curator platform");
  const tab = await browser.tabs.create({ url: locationForPlatform(platform), active: true });
  return { ok: true, action: "opened", tabId: tab.id };
}

async function ensureAccountSessions() {
  const [profiles, tabs] = await Promise.all([storedProfiles(), browser.tabs.query({})]);
  const readyProfiles = profiles.filter((profile) => profile.keepReady !== false);
  let opened = 0;
  for (const profile of readyProfiles) {
    const exists = tabs.some((tab) =>
      platformForUrl(tab.url) === profile.platform &&
      (tab.cookieStoreId || "firefox-default") === (profile.cookieStoreId || "firefox-default")
    );
    if (exists) continue;
    await browser.tabs.create({
      url: locationForPlatform(profile.platform),
      cookieStoreId: profile.cookieStoreId || "firefox-default",
      active: false,
    });
    opened += 1;
  }
  return { ok: true, configured: readyProfiles.length, opened };
}

async function prefillFeedbackDraft(message) {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  const platform = platformForUrl(tab?.url);
  if (!tab?.id || !platform) throw new Error("Open the matching curator submission first");
  if (message.expectedPlatform && message.expectedPlatform !== platform) {
    throw new Error(`This draft belongs to ${message.expectedPlatform}; the active tab is ${platform}`);
  }
  const text = String(message.text || "").trim();
  if (!text) throw new Error("Generate feedback first");
  const response = await browser.tabs.sendMessage(tab.id, {
    type: "PREFILL_FEEDBACK",
    text,
    mode: message.mode === "decline" ? "decline" : "accept",
    expectedSubmissionId: String(message.expectedSubmissionId || ""),
  });
  if (!response?.ok) throw new Error(response?.error || "Feedback field not found");
  return response;
}

async function activePlatformAction(payload) {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !platformForUrl(tab.url)) throw new Error("Open a supported curator submission first");
  const response = await browser.tabs.sendMessage(tab.id, payload);
  if (!response?.ok) throw new Error(response?.error || "The platform control is not available on this page");
  return response;
}

async function focusTab(tab) {
  await browser.tabs.update(tab.id, { active: true });
  if (tab.windowId && browser.windows) await browser.windows.update(tab.windowId, { focused: true }).catch(() => {});
}

function reviewPriority(context = {}, profileIndex = 0) {
  const deadlines = [context.deadlineLabel, ...(context.inbox?.deadlineLabels || [])]
    .map(deadlineHours).filter((value) => value !== null);
  const soonest = deadlines.length ? Math.min(...deadlines) : 100000;
  const open = Number(context.inbox?.total ?? context.inbox?.visible ?? 0);
  const urgent = context.platform === "playlistpush" || context.platform === "unhurd"
    ? open
    : Number(context.inbox?.urgent || 0);
  return { urgent, soonest, open, profileIndex };
}

async function tabReviewContext(tab) {
  try {
    const context = await browser.tabs.sendMessage(tab.id, { type: "SCAN_PLATFORM" });
    return context?.platform ? context : null;
  } catch {
    return null;
  }
}

async function collectSubmitHubAccount(sourceTab) {
  const cookieStoreId = sourceTab.cookieStoreId || "firefox-default";
  const collector = await browser.tabs.create({
    url: "https://www.submithub.com/?page=1",
    cookieStoreId,
    active: false,
  });
  const submissions = [];
  let pages = 1;
  try {
    await waitForTabReady(collector.id);
    for (let page = 1; page <= pages; page += 1) {
      if (page > 1) {
        await browser.tabs.update(collector.id, { url: `https://www.submithub.com/?page=${page}` });
        await waitForTabReady(collector.id);
      }
      const context = await browser.tabs.sendMessage(collector.id, { type: "SCAN_PLATFORM" });
      if (context?.platform !== "submithub" || context.loginState !== "authenticated") throw new Error("SubmitHub collector is not signed in");
      pages = Math.min(50, Math.max(pages, Number(context.pagination?.pages || 1)));
      for (const submission of context.submissions || []) {
        if (!submissions.some((item) => item.id === submission.id)) submissions.push(submission);
      }
    }
  } finally {
    await browser.tabs.remove(collector.id).catch(() => {});
  }
  return { submissions, pages, collectedAt: new Date().toISOString(), sourceTabId: sourceTab.id };
}

async function collectDeepReviewQueue() {
  const tabs = (await browser.tabs.query({})).filter((tab) => platformForUrl(tab.url));
  const cache = (await browser.storage.local.get(REVIEW_QUEUE_CACHE_KEY))[REVIEW_QUEUE_CACHE_KEY] || {};
  for (const tab of tabs) {
    const platform = platformForUrl(tab.url);
    const key = sessionKey(platform, tab.cookieStoreId || "firefox-default");
    if (platform === "submithub") cache[key] = await collectSubmitHubAccount(tab);
    else {
      const context = await tabReviewContext(tab);
      if (context) cache[key] = { submissions: context.submissions || [], pages: 1, collectedAt: new Date().toISOString(), sourceTabId: tab.id };
    }
  }
  await browser.storage.local.set({ [REVIEW_QUEUE_CACHE_KEY]: cache });
  reviewQueueState.scannedAt = 0;
  return cache;
}

async function buildReviewQueue() {
  await ensureAccountSessions();
  const [tabs, profiles, storedQueueCache] = await Promise.all([
    browser.tabs.query({}),
    storedProfiles(),
    browser.storage.local.get(REVIEW_QUEUE_CACHE_KEY),
  ]);
  const queueCache = storedQueueCache[REVIEW_QUEUE_CACHE_KEY] || {};
  const platformTabs = tabs.filter((tab) => platformForUrl(tab.url));
  const groups = await Promise.all(platformTabs.map(async (tab) => {
    const context = await tabReviewContext(tab);
    if (!context) return [];
    const cookieStoreId = tab.cookieStoreId || "firefox-default";
    const profileIndex = profiles.findIndex((profile) => profile.platform === context.platform && profile.cookieStoreId === cookieStoreId);
    const cacheKey = sessionKey(context.platform, cookieStoreId);
    const cached = queueCache[cacheKey];
    const submissions = Array.isArray(cached?.submissions) && cached.submissions.length ? cached.submissions : context.submissions;
    return (Array.isArray(submissions) ? submissions : []).map((submission, index) => ({
      ...submission,
      key: `${context.platform}:${cookieStoreId}:${submission.id}`,
      platform: context.platform,
      platformProfile: context.platformProfile || "",
      cookieStoreId,
      tabId: tab.id,
      profileIndex: profileIndex < 0 ? profiles.length : profileIndex,
      order: Number.isFinite(Number(submission.order)) ? Number(submission.order) : index,
      deadlineHours: deadlineHours(submission.deadlineLabel),
    }));
  }));
  const items = groups.flat().filter((item) => item.id).sort((left, right) => {
    const leftDeadline = left.deadlineHours ?? 100000;
    const rightDeadline = right.deadlineHours ?? 100000;
    const leftUrgency = Number(left.urgency ?? -1);
    const rightUrgency = Number(right.urgency ?? -1);
    return rightUrgency - leftUrgency || leftDeadline - rightDeadline || left.profileIndex - right.profileIndex || left.order - right.order;
  });
  const currentKey = items.some((item) => item.key === reviewQueueState.currentKey) ? reviewQueueState.currentKey : "";
  reviewQueueState = { items, currentKey, scannedAt: Date.now() };
  return reviewQueueState;
}

async function reviewQueueData(refresh = false) {
  if (refresh || !reviewQueueState.scannedAt || Date.now() - reviewQueueState.scannedAt > 30000) await buildReviewQueue();
  const index = reviewQueueState.items.findIndex((item) => item.key === reviewQueueState.currentKey);
  return {
    total: reviewQueueState.items.length,
    position: index < 0 ? 0 : index + 1,
    current: index < 0 ? null : reviewQueueState.items[index],
    scannedAt: reviewQueueState.scannedAt,
  };
}

async function activateReviewTab(tab, options = {}) {
  await focusTab(tab);
  const response = await browser.tabs.sendMessage(tab.id, {
    type: "ACTIVATE_REVIEW_WORKFLOW",
    autoPlay: !!options.autoPlay,
    prepareDecline: !!options.prepareDecline,
  });
  if (!response?.ok) throw new Error(response?.error || "No review is available in this account");
  return response;
}

async function navigateGlobalReview(message = {}) {
  const direction = message.direction === "previous" ? "previous" : "next";
  const queue = await buildReviewQueue();
  if (!queue.items.length) throw new Error("No loaded submission was found across the configured accounts");
  let index = queue.items.findIndex((item) => item.key === queue.currentKey);
  if (index < 0) {
    const [activeTab] = await browser.tabs.query({ active: true, currentWindow: true });
    const activeContext = activeTab?.id ? await tabReviewContext(activeTab) : null;
    if (activeContext?.status === "in_review" && activeContext.platformSubmissionId) {
      index = queue.items.findIndex((item) => item.tabId === activeTab.id && item.id === activeContext.platformSubmissionId);
    }
  }
  const targetIndex = index < 0
    ? direction === "previous" ? queue.items.length - 1 : 0
    : (index + (direction === "previous" ? -1 : 1) + queue.items.length) % queue.items.length;
  const target = queue.items[targetIndex];
  const tab = await browser.tabs.get(target.tabId).catch(() => null);
  if (!tab) throw new Error("The queued platform tab is no longer open. Scan accounts again.");
  await focusTab(tab);
  if (target.platform === "submithub" && target.pageUrl && tab.url !== target.pageUrl) {
    await browser.tabs.update(tab.id, { url: target.pageUrl });
    await waitForTabReady(tab.id);
  }
  const result = await browser.tabs.sendMessage(tab.id, {
    type: "OPEN_QUEUED_SUBMISSION",
    submissionId: target.id,
    autoPlay: !!message.autoPlay,
    prepareDecline: !!message.prepareDecline,
  });
  if (!result?.ok) throw new Error(result?.error || "The queued submission could not be opened");
  reviewQueueState.currentKey = target.key;
  return { ...result, scope: "queue", switchedAccount: true, platform: target.platform, queuePosition: targetIndex + 1, queueTotal: queue.items.length };
}

async function cockpitData() {
  let [profiles, sessions, tabs, scanSnapshot, containers] = await Promise.all([
    storedProfiles(),
    storedSessions(),
    browser.tabs.query({}),
    fullScanSnapshot(),
    listContainers().catch(() => []),
  ]);
  const activeTabIds = new Set(tabs.map((tab) => tab.id));
  const now = Date.now();
  let normalizedSessions = Object.values(sessions)
    .filter((session) => SUPPORTED_PLATFORMS.has(session.platform))
    .map((session) => {
      const seenAt = Date.parse(session.lastSeenAt || "");
      const active = activeTabIds.has(session.tabId);
      const stale = !Number.isFinite(seenAt) || now - seenAt > 15 * 60 * 1000;
      const health = session.health === "unreadable" ? "unreadable" : stale ? "stale" : active ? "active" : "closed";
      const badge = quickSwitchBadge(session.context);
      return {
        ...session,
        active,
        stale,
        health,
        inbox: contextInbox(session.context),
        dueWithin24: dueWithin24Count(session.context),
        badgeCount: badge.count,
        badgeLabel: badge.label,
      };
    })
    .sort((left, right) => Date.parse(right.lastSeenAt || 0) - Date.parse(left.lastSeenAt || 0));

  // Tabs that were already open when the extension was installed/reloaded do not
  // have a content-script snapshot until their page reloads. Keep them visible in
  // Quick Switch immediately, using the URL + Firefox container as identity.
  for (const tab of tabs) {
    const platform = platformForUrl(tab.url);
    if (!platform || !tab.id) continue;
    const cookieStoreId = tab.cookieStoreId || "firefox-default";
    const key = sessionKey(platform, cookieStoreId);
    const existingIndex = normalizedSessions.findIndex((session) => session.key === key);
    if (existingIndex >= 0) {
      normalizedSessions[existingIndex] = {
        ...normalizedSessions[existingIndex],
        tabId: tab.id,
        windowId: tab.windowId,
        url: tab.url || normalizedSessions[existingIndex].url,
        active: true,
        stale: false,
        health: normalizedSessions[existingIndex].health === "unreadable" ? "unreadable" : "active",
      };
      continue;
    }
    normalizedSessions.push({
      key,
      profileId: "",
      platform,
      cookieStoreId,
      tabId: tab.id,
      windowId: tab.windowId,
      url: tab.url || "",
      platformProfile: "",
      context: { platform, cookieStoreId, tabId: tab.id, url: tab.url || "", inbox: {} },
      inbox: { open: 0, urgent: 0 },
      dueWithin24: 0,
      badgeCount: 0,
      badgeLabel: platform === "playlistpush" || platform === "unhurd"
        ? "open submissions"
        : platform === "groover" ? "To listen songs expiring within 24 hours" : "submissions expiring within 24 hours",
      active: true,
      stale: false,
      health: "active",
      provisional: true,
    });
  }

  // Promote every detected Firefox login session into the same persistent model
  // used by configured accounts. This removes the temporary/fixed split while
  // keeping platform + container as the stable account identity.
  const nowIso = new Date().toISOString();
  let profilesChanged = false;
  for (const session of normalizedSessions.filter((item) => item.active)) {
    const existingIndex = profiles.findIndex((profile) =>
      profile.platform === session.platform &&
      (profile.cookieStoreId || "firefox-default") === (session.cookieStoreId || "firefox-default")
    );
    const detectedName = String(session.platformProfile || "").trim();
    if (existingIndex >= 0) {
      const existing = profiles[existingIndex];
      if (existing.autoDiscovered && existing.nameSource !== "manual" && detectedName && existing.name !== detectedName) {
        profiles[existingIndex] = { ...existing, name: detectedName, updatedAt: nowIso };
        profilesChanged = true;
      }
      continue;
    }
    const container = containers.find((item) => item.cookieStoreId === session.cookieStoreId);
    const fallbackName = container?.name || (session.cookieStoreId === "firefox-default" ? "Default session" : session.cookieStoreId);
    profiles.push({
      id: crypto.randomUUID(),
      name: detectedName || fallbackName,
      platform: session.platform,
      cookieStoreId: session.cookieStoreId || "firefox-default",
      containerName: container?.name || "",
      keepReady: true,
      workflow: normalizeWorkflow(session.platform),
      autoDiscovered: true,
      nameSource: "detected",
      createdAt: nowIso,
      updatedAt: nowIso,
    });
    profilesChanged = true;
  }
  if (profilesChanged) {
    await browser.storage.local.set({ [ACCOUNT_PROFILES_KEY]: profiles });
    console.info("[quick-switch] open curator sessions reconciled into persistent account profiles", {
      profiles: profiles.length,
      activeSessions: normalizedSessions.filter((session) => session.active).length,
    });
  }

  const profilesWithSessions = profiles.map((profile) => {
    const session = normalizedSessions.find((item) =>
      item.profileId === profile.id ||
      (item.platform === profile.platform && item.cookieStoreId === profile.cookieStoreId)
    ) || null;
    return { ...profile, session };
  });
  const unassigned = normalizedSessions.filter((session) =>
    !profilesWithSessions.some((profile) =>
      profile.id === session.profileId ||
      (profile.platform === session.platform && profile.cookieStoreId === session.cookieStoreId)
    )
  );
  const visibleSessions = [...new Map([
    ...profilesWithSessions.map((profile) => profile.session).filter(Boolean),
    ...unassigned,
  ].map((session) => [session.key, session])).values()];
  const platformStates = [...SUPPORTED_PLATFORMS].map((platform) => {
    const configuredProfiles = profiles.filter((profile) => profile.platform === platform);
    const activeSessions = normalizedSessions.filter((session) => session.platform === platform && session.active);
    return {
      platform,
      configured: configuredProfiles.length,
      active: activeSessions.length,
      state: activeSessions.length ? "active" : configuredProfiles.length ? "closed" : "missing",
      firstProfileId: configuredProfiles[0]?.id || "",
    };
  });
  return {
    ok: true,
    profiles: profilesWithSessions,
    unassigned,
    platforms: platformStates,
    stats: {
      accounts: profiles.length + unassigned.length,
      active: normalizedSessions.filter((session) => session.active).length,
      open: visibleSessions.reduce((sum, session) => sum + Number(session.inbox?.open || 0), 0),
      urgent: visibleSessions.reduce((sum, session) => sum + Number(session.inbox?.urgent || 0), 0),
      dueWithin24: visibleSessions.reduce((sum, session) => sum + Number(session.dueWithin24 || 0), 0),
    },
    scanSnapshot,
  };
}

async function createPlacement(input) {
  if (!input?.playlist_id || !input?.spotify_track_url || !input?.spotify_track_id) {
    throw new Error("Track and playlist are required");
  }
  const current = await api(`/api/playlist-items/list?playlist_row_id=${encodeURIComponent(input.playlist_id)}&repair=0`);
  const items = Array.isArray(current) ? current : current?.items || [];
  const existing = items.find((item) => item.track_id === input.spotify_track_id);
  const requestedPosition = Number(input.position) > 0 ? Math.floor(Number(input.position)) : null;
  const expiryWeeks = Number(input.expiry_weeks) > 0 ? Number(input.expiry_weeks) : null;

  if (!existing) {
    await api("/api/playlist-items/add", {
      method: "POST",
      body: {
        playlist_id: input.playlist_id,
        link_or_uri: input.spotify_track_url,
        position: requestedPosition,
        exp_weeks: expiryWeeks,
      },
    });
  }

  if (input.lock || existing) {
    const position = requestedPosition || Number(existing?.position ?? 0) + 1;
    await api("/api/locks/set", {
      method: "POST",
      body: {
        playlist_id: input.playlist_id,
        track_id: input.spotify_track_id,
        locked_position: position,
        is_locked: !!input.lock,
        exp_weeks: expiryWeeks,
      },
    });
  }

  return {
    ok: true,
    action: existing ? "managed" : "added",
    track_id: input.spotify_track_id,
    playlist_id: input.playlist_id,
  };
}

async function beginConnect() {
  const nonceBytes = crypto.getRandomValues(new Uint8Array(18));
  const nonce = Array.from(nonceBytes, (value) => value.toString(16).padStart(2, "0")).join("");
  await browser.storage.local.set({ [CONNECT_NONCE_KEY]: nonce });
  await browser.tabs.create({ url: `${API_BASE}/extension-auth?nonce=${encodeURIComponent(nonce)}` });
  return { ok: true };
}

async function acceptLinkedSession(message, tabId) {
  const pending = (await browser.storage.local.get(CONNECT_NONCE_KEY))[CONNECT_NONCE_KEY];
  if (!pending || pending !== message.nonce) throw new Error("Extension connection expired");
  if (!message.session?.access_token || !message.session?.refresh_token) throw new Error("Invalid PlaylistPilot session");
  await setAuth(message.session);
  await browser.storage.local.remove(CONNECT_NONCE_KEY);
  await syncFeedbackProfiles().catch(() => {});
  await syncEarningRates().catch(() => {});
  await browser.runtime.sendMessage({ type: "AUTH_UPDATED" }).catch(() => {});
  if (tabId) await browser.tabs.remove(tabId).catch(() => {});
  return { ok: true };
}

async function listContainers() {
  if (!browser.contextualIdentities) return [];
  return browser.contextualIdentities.query({});
}

browser.runtime.onMessage.addListener((message, sender) => {
  return (async () => {
    switch (message?.type) {
      case "PLATFORM_SNAPSHOT":
        if (sender.tab?.id && message.context?.platform) {
          await saveContext(sender.tab, message.context);
          reviewQueueState.scannedAt = 0;
        }
        return { ok: true };
      case "PLATFORM_FEEDBACK_FIELD_UPDATED":
        await browser.runtime.sendMessage({
          type: "LIVE_FEEDBACK_UPDATED",
          value: String(message.value || ""),
          tabId: sender.tab?.id,
        }).catch(() => {});
        return { ok: true };
      case "PLATFORM_TRACK_FOCUSED": {
        if (!sender.tab?.id || !message.focus?.spotifyTrackId) return { ok: false };
        // A background curator tab may finish loading after the user has
        // already switched elsewhere. Never let that stale load steal the
        // compact player's focus from the visible tab.
        const senderTab = await browser.tabs.get(sender.tab.id).catch(() => null);
        if (!senderTab?.active) return { ok: true, ignored: true, reason: "background_tab" };
        const focus = {
          ...message.focus,
          tabId: sender.tab.id,
          windowId: sender.tab.windowId,
          cookieStoreId: sender.tab.cookieStoreId || "firefox-default",
          capturedAt: new Date().toISOString(),
        };
        await browser.storage.local.set({ [FOCUSED_TRACK_KEY]: focus });
        await browser.runtime.sendMessage({ type: "FOCUSED_TRACK_UPDATED", focus }).catch(() => {});
        return { ok: true, focus };
      }
      case "GROOVER_ACCEPTANCE_CONFIRMED":
      case "PLATFORM_ACCEPTANCE_CONFIRMED":
        if (!sender.tab?.id) throw new Error("Curator platform tab missing");
        {
          try {
            const platform = String(message.accepted?.platform || "groover").toLowerCase();
            if (!["groover", "playlistpush", "submithub", "unhurd"].includes(platform)) throw new Error("Unsupported acceptance platform");
            await refreshAccountAfterReview(sender.tab, { ...message.accepted, platform });
            const cookieStoreId = sender.tab.cookieStoreId || "firefox-default";
            const profile = await profileForPlatformSession(platform, cookieStoreId, message.accepted?.platformProfile);
            const workflow = normalizeWorkflow(platform, profile?.workflow || {});
            if (!workflow.trackingEnabled) return { ok: true, ignored: true, reason: "tracking_disabled" };
            const result = await api("/api/extension/accepted-tracks", {
              method: "POST",
              body: { ...message.accepted, manual_expiry_weeks: workflow.expiryWeeks },
            });
            const notification = { type: "PLATFORM_ACCEPTANCE_SAVED", platform, track: result.track || message.accepted };
            await Promise.all([
              browser.tabs.sendMessage(sender.tab.id, notification).catch(() => {}),
              browser.runtime.sendMessage(notification).catch(() => {}),
            ]);
            // A successful acceptance is itself a completed paid review on
            // Groover and Unhurd. Record it here as an idempotent safety net;
            // the generic watcher may report the same completion as well, but
            // the API's unique key prevents duplicate income.
            if (platform === "groover" || platform === "unhurd") {
              try {
                const earning = await recordReviewEarning({
                  ...message.accepted,
                  platform,
                  decision: "accept",
                  reviewedAt: new Date().toISOString(),
                }, sender.tab, profile);
                if (earning?.ignored) {
                  const explanation = earning.reason === "account_profile_missing"
                    ? "Für diesen Firefox-Container ist kein eindeutiges Account-Profil hinterlegt."
                    : "Für dieses Account-Profil ist kein aktiver Income-Satz hinterlegt.";
                  await browser.tabs.sendMessage(sender.tab.id, {
                    type: "REVIEW_EARNING_SAVE_FAILED",
                    message: explanation,
                  }).catch(() => {});
                }
                if (earning?.inserted) {
                  const earningNotification = { type: "REVIEW_EARNING_SAVED", event: earning.event };
                  await Promise.all([
                    browser.tabs.sendMessage(sender.tab.id, earningNotification).catch(() => {}),
                    browser.runtime.sendMessage(earningNotification).catch(() => {}),
                  ]);
                }
              } catch (earningError) {
                await browser.tabs.sendMessage(sender.tab.id, {
                  type: "REVIEW_EARNING_SAVE_FAILED",
                  message: earningError?.message || "The completed review could not be recorded.",
                }).catch(() => {});
              }
            }
            return result;
          } catch (error) {
            await browser.tabs.sendMessage(sender.tab.id, {
              type: "PLATFORM_ACCEPTANCE_SAVE_FAILED",
              message: error?.message || "The accepted song could not be saved.",
            }).catch(() => {});
            throw error;
          }
        }
      case "PLATFORM_REVIEW_CONFIRMED": {
        if (!sender.tab?.id) throw new Error("Curator platform tab missing");
        try {
          await refreshAccountAfterReview(sender.tab, message.review || {});
          const result = await recordReviewEarning(message.review || {}, sender.tab);
          if (result.ignored) {
            const explanation = result.reason === "account_profile_missing"
              ? "Für diesen Firefox-Container ist kein passendes Account-Profil hinterlegt."
              : "Für dieses Account-Profil ist kein aktiver Income-Satz hinterlegt.";
            await browser.tabs.sendMessage(sender.tab.id, {
              type: "REVIEW_EARNING_SAVE_FAILED",
              message: explanation,
            }).catch(() => {});
          }
          if (result.inserted) {
            const notification = { type: "REVIEW_EARNING_SAVED", event: result.event };
            await Promise.all([
              browser.tabs.sendMessage(sender.tab.id, notification).catch(() => {}),
              browser.runtime.sendMessage(notification).catch(() => {}),
            ]);
          }
          return result;
        } catch (error) {
          await browser.tabs.sendMessage(sender.tab.id, {
            type: "REVIEW_EARNING_SAVE_FAILED",
            message: error?.message || "The completed review could not be recorded.",
          }).catch(() => {});
          throw error;
        }
      }
      case "GET_ACTIVE_CONTEXT":
        return activeContext();
      case "GET_FOCUSED_TRACK":
        return (await browser.storage.local.get(FOCUSED_TRACK_KEY))[FOCUSED_TRACK_KEY] || null;
      case "FOCUS_CURRENT_PAGE_TRACK": {
        const tabs = await browser.tabs.query({ active: true, currentWindow: true });
        const tab = tabs[0];
        if (!tab?.id || !platformForUrl(tab.url)) throw new Error("Open a curator submission first");
        const focus = await sendToPlatformTab(tab, { type: "GET_FOCUSED_PAGE_TRACK" });
        if (!focus?.spotifyTrackId) throw new Error("No Spotify track found on the current submission");
        const saved = { ...focus, tabId: tab.id, windowId: tab.windowId, cookieStoreId: tab.cookieStoreId || "firefox-default", capturedAt: new Date().toISOString() };
        await browser.storage.local.set({ [FOCUSED_TRACK_KEY]: saved });
        await browser.runtime.sendMessage({ type: "FOCUSED_TRACK_UPDATED", focus: saved }).catch(() => {});
        return saved;
      }
      case "NAVIGATE_FOCUSED_TRACK": {
        const current = (await browser.storage.local.get(FOCUSED_TRACK_KEY))[FOCUSED_TRACK_KEY] || null;
        const tracks = Array.isArray(current?.pageTracks) ? current.pageTracks : [];
        if (!tracks.length) throw new Error("No other detected tracks on this page");
        const currentIndex = Math.max(0, tracks.findIndex((track) => track.spotifyTrackId === current.spotifyTrackId));
        const delta = message.direction === "previous" ? -1 : 1;
        const next = tracks[(currentIndex + delta + tracks.length) % tracks.length];
        const focus = { ...current, ...next, pageTracks: tracks, capturedAt: new Date().toISOString(), source: "player_navigation" };
        await browser.storage.local.set({ [FOCUSED_TRACK_KEY]: focus });
        await browser.runtime.sendMessage({ type: "FOCUSED_TRACK_UPDATED", focus }).catch(() => {});
        return focus;
      }
      case "GET_AUTH_STATE": {
        let session = await storedAuth();
        if (!session) return { connected: false, email: "" };
        try {
          session = await validSession();
          return { connected: true, email: session.email || "", expiresAt: session.expires_at || 0 };
        } catch (error) {
          const retained = await storedAuth();
          return {
            connected: !!retained?.refresh_token,
            email: retained?.email || session.email || "",
            degraded: !!retained?.refresh_token,
            error: String(error?.message || error),
          };
        }
      }
      case "BEGIN_AUTH_CONNECT":
        return beginConnect();
      case "PLAYLISTPILOT_AUTH_SESSION":
        return acceptLinkedSession(message, sender.tab?.id);
      case "SIGN_OUT":
        await setAuth(null);
        await installFeedbackContextMenu([]).catch(() => {});
        return { ok: true };
      case "LIST_PLAYLISTS":
        return api("/api/playlists/list");
      case "LIST_ACCEPTED_TRACKS":
        return api("/api/extension/accepted-tracks");
      case "LIST_REVIEW_EARNINGS":
        return api(`/api/extension/review-earnings?tz_offset=${encodeURIComponent(new Date().getTimezoneOffset())}`);
      case "GET_SUBMITHUB_AD_SETTINGS":
        return (await browser.storage.local.get(SUBMITHUB_AD_SETTINGS_KEY))[SUBMITHUB_AD_SETTINGS_KEY] || { autoSync: false, mappings: {} };
      case "SAVE_SUBMITHUB_AD_SETTINGS": {
        const settings = {
          autoSync: !!message.settings?.autoSync,
          mappings: message.settings?.mappings && typeof message.settings.mappings === "object" ? message.settings.mappings : {},
        };
        await browser.storage.local.set({ [SUBMITHUB_AD_SETTINGS_KEY]: settings });
        return { ok: true, settings };
      }
      case "SYNC_SUBMITHUB_ADS":
        return api("/api/extension/submithub-ads/sync", { method: "POST", body: message.input || {} });
      case "SCAN_SUBMITHUB_ADS_ONLY":
        return scanSubmitHubAdsOnly();
      case "SET_ACCEPTED_TRACK_EXPIRY":
        return api("/api/extension/accepted-tracks", { method: "PATCH", body: message.input });
      case "GET_PLAYLIST_DETAIL":
        return api(`/api/playlists/get?playlist_id=${encodeURIComponent(message.playlistId || "")}`);
      case "LIST_PLAYLIST_ITEMS":
        return api(`/api/playlist-items/list?playlist_row_id=${encodeURIComponent(message.playlistId || "")}&meta=1&repair=0`);
      case "CREATE_PLACEMENT":
        return createPlacement(message.input);
      case "SAVE_PLAYLIST_SETTINGS":
        return api("/api/playlists/settings/save", { method: "POST", body: message.input });
      case "SET_PLAYLIST_TRACK_LOCK":
        return api("/api/locks/set", {
          method: "POST",
          body: {
            playlist_id: message.input?.playlist_id,
            track_id: message.input?.track_id,
            locked_position: message.input?.position,
            is_locked: !!message.input?.lock,
            exp_weeks: message.input?.expiry_weeks ?? null,
          },
        });
      case "MOVE_PLAYLIST_TRACK":
        return api("/api/playlist-items/move", {
          method: "POST",
          body: {
            playlist_id: message.input?.playlist_id,
            track_id: message.input?.track_id,
            from_position: message.input?.from_position,
            dir: message.input?.direction,
            steps: 1,
          },
        });
      case "REMOVE_PLAYLIST_TRACK":
        return api("/api/playlist-items/remove", { method: "POST", body: message.input });
      case "CREATE_PLAYLIST_BACKUP":
        return api("/api/backups/create", { method: "POST", body: message.input });
      case "GENERATE_FEEDBACK":
        return api("/api/extension/feedback/generate", { method: "POST", body: message.input });
      case "GENERATE_FEEDBACK_FROM_SELECTION": {
        if (!sender.tab?.id) throw new Error("Platform tab missing");
        const feedback = await generateFeedbackFromSelection(sender.tab, message.selection, message.profileId);
        return { ok: true, feedback };
      }
      case "LIST_FEEDBACK_PROFILES":
        return api("/api/extension/feedback/profiles");
      case "SYNC_FEEDBACK_PROFILES": {
        const result = await api("/api/extension/feedback/profiles/sync", { method: "POST", body: { profiles: message.profiles } });
        if (Array.isArray(result.profiles)) await browser.storage.local.set({ [FEEDBACK_TEMPLATES_KEY]: result.profiles });
        await installFeedbackContextMenu(result.profiles || []).catch(() => {});
        return result;
      }
      case "DELETE_FEEDBACK_PROFILE": {
        const result = await api("/api/extension/feedback/profiles/delete", { method: "POST", body: { id: message.profileId } });
        await syncFeedbackProfiles().catch(() => {});
        return result;
      }
      case "PREFILL_FEEDBACK_DRAFT":
        return prefillFeedbackDraft(message);
      case "GET_REVIEW_STATE":
        return activePlatformAction({ type: "GET_REVIEW_STATE" });
      case "SHOW_DIRECT_TYPING_PORTAL":
        return activePlatformAction({ type: "SHOW_DIRECT_TYPING_PORTAL", mode: message.mode === "decline" ? "decline" : "accept" });
      case "CONTROL_PLAYBACK":
        return activePlatformAction({ type: "CONTROL_PLAYBACK" });
      case "NAVIGATE_SUBMISSION":
        return activePlatformAction({ type: "NAVIGATE_SUBMISSION", direction: message.direction, autoPlay: !!message.autoPlay, prepareDecline: !!message.prepareDecline });
      case "NAVIGATE_GLOBAL_REVIEW":
        return navigateGlobalReview(message);
      case "GET_REVIEW_QUEUE_STATE":
        return reviewQueueData(!!message.refresh);
      case "PREPARE_DECISION":
        return activePlatformAction({ type: "PREPARE_DECISION", mode: message.mode });
      case "GET_ACCOUNT_COCKPIT":
        return cockpitData();
      case "SCAN_ALL_SESSIONS":
        return runFullScan();
      case "GET_FULL_SCAN_SNAPSHOT":
        return { ok: true, snapshot: await fullScanSnapshot() };
      case "SAVE_ACCOUNT_PROFILE":
        return saveAccountProfile(message.input);
      case "REORDER_ACCOUNT_PROFILES":
        return reorderAccountProfiles(message.profileIds);
      case "DELETE_ACCOUNT_PROFILE":
        return deleteAccountProfile(message.profileId);
      case "OPEN_ACCOUNT_PROFILE":
        return openAccountProfile(message.profileId);
      case "FOCUS_ACCOUNT_TAB":
        return focusAccountTab(message.tabId);
      case "OPEN_PLATFORM":
        return openPlatform(String(message.platform || ""));
      case "ENSURE_ACCOUNT_SESSIONS":
        return ensureAccountSessions();
      case "LIST_CONTAINERS":
        return listContainers();
      default:
        return null;
    }
  })().catch((error) => ({ ok: false, error: error?.message || String(error) }));
});

browser.action.onClicked.addListener(() => browser.sidebarAction.open().catch(() => {}));

async function installFeedbackContextMenu(profiles = null) {
  if (!browser.menus) return;
  if (!Array.isArray(profiles)) {
    const stored = await browser.storage.local.get(FEEDBACK_TEMPLATES_KEY);
    profiles = Array.isArray(stored[FEEDBACK_TEMPLATES_KEY]) ? stored[FEEDBACK_TEMPLATES_KEY] : [];
  }
  await browser.menus.removeAll();
  browser.menus.create({
    id: FEEDBACK_CONTEXT_MENU_ID,
    title: "Generate PlaylistPilot feedback",
    contexts: ["editable"],
    documentUrlPatterns: [
      "https://*.submithub.com/*",
      "https://groover.co/*",
      "https://app.playlistpush.com/*",
      "https://curator.unhurdmusic.com/*",
    ],
  });
  for (const profile of profiles.slice(0, 50)) {
    browser.menus.create({
      id: `${FEEDBACK_PROFILE_MENU_PREFIX}${profile.id}`,
      parentId: FEEDBACK_CONTEXT_MENU_ID,
      title: String(profile.name || "Feedback profile").slice(0, 80),
      contexts: ["editable"],
    });
  }
  if (!profiles.length) {
    browser.menus.create({
      id: `${FEEDBACK_PROFILE_MENU_PREFIX}default`,
      parentId: FEEDBACK_CONTEXT_MENU_ID,
      title: "Default profile",
      contexts: ["editable"],
    });
  }
}

browser.menus?.onClicked.addListener(async (info, tab) => {
  const menuId = String(info.menuItemId || "");
  if (!menuId.startsWith(FEEDBACK_PROFILE_MENU_PREFIX) || !tab?.id) return;
  const profileId = menuId.slice(FEEDBACK_PROFILE_MENU_PREFIX.length) === "default" ? "" : menuId.slice(FEEDBACK_PROFILE_MENU_PREFIX.length);
  const status = (message, kind = "progress") => browser.tabs.sendMessage(tab.id, {
    type: "SHOW_FEEDBACK_GENERATOR_STATUS", message, kind,
  }).catch(() => null);
  try {
    const saved = await browser.tabs.sendMessage(tab.id, { type: "GET_EDITABLE_FEEDBACK_SELECTION" });
    const selection = String(saved?.selection || info.selectionText || "");
    if (!saved?.ok || !selection.trim()) throw new Error(saved?.error || "Select + and - notes inside the platform feedback field first.");
    const stored = await browser.storage.local.get(FEEDBACK_TEMPLATES_KEY);
    const templates = Array.isArray(stored[FEEDBACK_TEMPLATES_KEY]) ? stored[FEEDBACK_TEMPLATES_KEY] : [];
    const profileName = templates.find((item) => item.id === profileId)?.name || "default profile";
    await status(`PlaylistPilot is generating with “${profileName}”…`);
    const feedback = await generateFeedbackFromSelection(tab, selection, profileId);
    const applied = await browser.tabs.sendMessage(tab.id, { type: "APPLY_GENERATED_FEEDBACK", feedback });
    if (!applied?.ok) throw new Error(applied?.error || "Generated feedback could not be inserted.");
  } catch (error) {
    await status(`PlaylistPilot: ${error?.message || String(error)}`, "error");
    console.error("[feedback-context-menu] failed", { tabId: tab.id, profileId, error: String(error?.message || error) });
  }
});

async function generateFeedbackWithShortcut(tab, slot) {
  if (!tab?.id || !platformForUrl(tab.url)) return;
  const stored = await browser.storage.local.get(FEEDBACK_TEMPLATES_KEY);
  const templates = Array.isArray(stored[FEEDBACK_TEMPLATES_KEY]) ? stored[FEEDBACK_TEMPLATES_KEY] : [];
  const template = templates[slot - 1];
  const profileId = template?.id || "";
  const status = (message, kind = "progress") => browser.tabs.sendMessage(tab.id, {
    type: "SHOW_FEEDBACK_GENERATOR_STATUS", message, kind,
  }).catch(() => null);
  try {
    if (!template) throw new Error(`No feedback profile is assigned to shortcut slot ${slot}.`);
    const saved = await browser.tabs.sendMessage(tab.id, { type: "GET_EDITABLE_FEEDBACK_SELECTION" });
    const selection = String(saved?.selection || "");
    if (!saved?.ok || !selection.trim()) throw new Error(saved?.error || "Select + and - notes in the feedback field first.");
    await status(`PlaylistPilot is generating with “${template.name || `profile ${slot}`}”…`);
    const feedback = await generateFeedbackFromSelection(tab, selection, profileId);
    const applied = await browser.tabs.sendMessage(tab.id, { type: "APPLY_GENERATED_FEEDBACK", feedback });
    if (!applied?.ok) throw new Error(applied?.error || "Generated feedback could not be inserted.");
  } catch (error) {
    await status(`PlaylistPilot: ${error?.message || String(error)}`, "error");
  }
}

browser.commands?.onCommand.addListener(async (command) => {
  const slot = Number(String(command || "").match(/^generate-feedback-profile-(\d)$/)?.[1]);
  if (!(slot >= 1 && slot <= 4)) return;
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  await generateFeedbackWithShortcut(tab, slot);
});

async function syncFeedbackProfiles() {
  const stored = await browser.storage.local.get(FEEDBACK_TEMPLATES_KEY);
  const local = Array.isArray(stored[FEEDBACK_TEMPLATES_KEY]) ? stored[FEEDBACK_TEMPLATES_KEY] : [];
  const remote = await api("/api/extension/feedback/profiles");
  let profiles = Array.isArray(remote.profiles) ? remote.profiles : [];
  if (!profiles.length && local.length) {
    const migrated = await api("/api/extension/feedback/profiles/sync", { method: "POST", body: { profiles: local } });
    profiles = Array.isArray(migrated.profiles) ? migrated.profiles : local;
  }
  if (profiles.length) await browser.storage.local.set({ [FEEDBACK_TEMPLATES_KEY]: profiles });
  await installFeedbackContextMenu(profiles);
  return profiles;
}

async function syncEarningRates() {
  const remote = await api("/api/extension/review-earning-rates");
  const rates = Array.isArray(remote.rates) ? remote.rates : [];
  if (!rates.length) return [];
  const byKey = new Map(rates.map((rate) => [`${rate.platform}:${rate.account_profile_id}`, rate]));
  const profiles = await storedProfiles();
  const next = profiles.map((profile) => {
    const rate = byKey.get(`${profile.platform}:${profile.id}`);
    return rate ? { ...profile, earnings: normalizeEarnings(rate), updatedAt: profile.updatedAt } : profile;
  });
  await browser.storage.local.set({ [ACCOUNT_PROFILES_KEY]: next });
  return rates;
}

installFeedbackContextMenu().catch(() => {});
storedAuth().then((session) => session ? Promise.all([syncFeedbackProfiles(), syncEarningRates()]) : null).catch(() => {});
browser.storage.local.remove(REVIEW_QUEUE_CACHE_KEY).catch(() => {});
browser.runtime.onInstalled.addListener(() => installFeedbackContextMenu().catch(() => {}));
async function syncPlayerToActiveTab(tabId) {
  const tab = await browser.tabs.get(tabId).catch(() => null);
  if (!tab?.id || !tab.active || !platformForUrl(tab.url)) return null;
  const focus = await sendToPlatformTab(tab, { type: "GET_FOCUSED_PAGE_TRACK" }).catch(() => null);
  if (!focus?.spotifyTrackId) return null;
  const saved = {
    ...focus,
    tabId: tab.id,
    windowId: tab.windowId,
    cookieStoreId: tab.cookieStoreId || "firefox-default",
    capturedAt: new Date().toISOString(),
    source: "active_tab",
  };
  await browser.storage.local.set({ [FOCUSED_TRACK_KEY]: saved });
  await browser.runtime.sendMessage({ type: "FOCUSED_TRACK_UPDATED", focus: saved }).catch(() => {});
  return saved;
}

browser.tabs.onActivated.addListener(({ tabId }) => {
  syncPlayerToActiveTab(tabId).catch(() => {});
  browser.runtime.sendMessage({ type: "ACTIVE_TAB_CHANGED" }).catch(() => {});
});
browser.tabs.onRemoved.addListener(async (tabId) => {
  const stored = (await browser.storage.local.get(CONTEXT_KEY))[CONTEXT_KEY] || {};
  if (stored[String(tabId)]) {
    delete stored[String(tabId)];
    await browser.storage.local.set({ [CONTEXT_KEY]: stored });
  }
  await updateStoredSessions((sessions) => {
    for (const [key, session] of Object.entries(sessions)) {
      if (session.tabId === tabId) {
        sessions[key] = { ...session, health: "closed", closedAt: new Date().toISOString() };
      }
    }
  });
  await browser.runtime.sendMessage({ type: "COCKPIT_UPDATED" }).catch(() => {});
});
browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url || changeInfo.status === "complete") {
    if (tab.active) {
      setTimeout(() => syncPlayerToActiveTab(tabId).catch(() => {}), 500);
    }
    browser.runtime.sendMessage({ type: "COCKPIT_UPDATED" }).catch(() => {});
  }
});

browser.runtime.onInstalled.addListener(() => {
  ensureAccountSessions().catch(() => {});
  browser.alarms.create(AUTH_REFRESH_ALARM, { periodInMinutes: 20 });
});
browser.runtime.onStartup.addListener(() => {
  ensureAccountSessions().catch(() => {});
  browser.alarms.create(AUTH_REFRESH_ALARM, { periodInMinutes: 20 });
  validSession().catch(() => {});
});
browser.alarms.create(AUTH_REFRESH_ALARM, { periodInMinutes: 20 });
browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== AUTH_REFRESH_ALARM) return;
  validSession().catch((error) => console.warn("[auth] scheduled refresh deferred", {
    error: String(error?.message || error),
  }));
});
