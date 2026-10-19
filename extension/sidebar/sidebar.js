const STYLE_LIBRARY_KEY = "playlistpilotFeedbackStyleLibrary";
const FEEDBACK_TEMPLATES_KEY = "playlistpilotFeedbackTemplates";
const SIDEBAR_VIEW_KEY = "playlistpilotSidebarViewV2";
const state = {
  context: null,
  focusedTrack: null,
  connected: false,
  playlists: [],
  managerPlaylistId: "",
  managerDetail: null,
  managerItems: [],
  managerMeta: null,
  managerBusy: false,
  feedbackMode: "accept",
  lastPlatform: "",
  cockpit: null,
  containers: [],
  workflowKey: "",
  feedbackDraftContext: null,
  placementReviewSnapshot: null,
  activeView: "queue",
  feedbackTemplates: [],
  activeFeedbackTemplateId: "",
  feedbackTemplateContextKey: "",
  dockDragActive: false,
  reviewSubmissionKey: "",
  bridgeRemoteUpdate: false,
  spotifyPlayerReady: false,
  spotifyPlayerPlaying: false,
  spotifyLoadedTrackId: "",
  spotifyPlayAttemptTimer: null,
  spotifyAutoPlayPending: false,
  acceptedTracks: [],
  acceptedTracksFilter: "all",
  reviewEarnings: null,
  declinePreparedSubmissionKey: "",
  cockpitReloadTimer: null,
  adSettings: { autoSync: false, mappings: {} },
};

const byId = (id) => document.getElementById(id);
const elements = {
  moreButton: byId("moreButton"),
  accountMenu: byId("accountMenu"),
  authLabel: byId("authLabel"),
  connectButton: byId("connectButton"),
  signOutButton: byId("signOutButton"),
  refreshButton: byId("refreshButton"),
  emptyCard: byId("emptyCard"),
  contextCard: byId("contextCard"),
  reviewCard: byId("reviewCard"),
  overviewPlayer: byId("overviewPlayer"),
  overviewPlayerTitle: byId("overviewPlayerTitle"),
  overviewPlayerArtist: byId("overviewPlayerArtist"),
  reviewBridgeBadge: byId("reviewBridgeBadge"),
  previousSubmissionButton: byId("previousSubmissionButton"),
  playPauseButton: byId("playPauseButton"),
  nextSubmissionButton: byId("nextSubmissionButton"),
  reviewQueuePosition: byId("reviewQueuePosition"),
  autoPlayInput: byId("autoPlayInput"),
  defaultDeclineInput: byId("defaultDeclineInput"),
  prepareAcceptButton: byId("prepareAcceptButton"),
  prepareDeclineButton: byId("prepareDeclineButton"),
  liveFeedbackInput: byId("liveFeedbackInput"),
  reviewStatus: byId("reviewStatus"),
  spotifyFallback: byId("spotifyFallback"),
  spotifyEmbed: byId("spotifyEmbed"),
  spotifyPlayerStatus: byId("spotifyPlayerStatus"),
  openSpotifyButton: byId("openSpotifyButton"),
  spotifyActivateButton: byId("spotifyActivateButton"),
  adapterCard: byId("adapterCard"),
  adapterStatusBadge: byId("adapterStatusBadge"),
  adapterFields: byId("adapterFields"),
  adapterWarnings: byId("adapterWarnings"),
  adapterMeta: byId("adapterMeta"),
  copyAdapterReportButton: byId("copyAdapterReportButton"),
  adapterStatus: byId("adapterStatus"),
  adapterQuickStatus: byId("adapterQuickStatus"),
  placementCard: byId("placementCard"),
  managerCard: byId("managerCard"),
  acceptedTracksCard: byId("acceptedTracksCard"),
  acceptedTracksList: byId("acceptedTracksList"),
  acceptedTracksStatus: byId("acceptedTracksStatus"),
  reloadAcceptedTracksButton: byId("reloadAcceptedTracksButton"),
  acceptedTracksFilter: byId("acceptedTracksFilter"),
  feedbackCard: byId("feedbackCard"),
  sessionCard: byId("sessionCard"),
  sessionDockCard: byId("sessionDockCard"),
  sessionDock: byId("sessionDock"),
  ensureSessionsButton: byId("ensureSessionsButton"),
  platformBadge: byId("platformBadge"),
  profileLabel: byId("profileLabel"),
  queueStats: byId("queueStats"),
  trackTitle: byId("trackTitle"),
  artistNames: byId("artistNames"),
  deadlineLabel: byId("deadlineLabel"),
  spotifyLink: byId("spotifyLink"),
  decisionBadge: byId("decisionBadge"),
  playlistSelect: byId("playlistSelect"),
  positionInput: byId("positionInput"),
  expiryInput: byId("expiryInput"),
  lockInput: byId("lockInput"),
  placementButton: byId("placementButton"),
  placementStatus: byId("placementStatus"),
  managerPlaylistSelect: byId("managerPlaylistSelect"),
  managerStats: byId("managerStats"),
  playlistSettings: byId("playlistSettings"),
  autoExpiryInput: byId("autoExpiryInput"),
  autoExpiryWeeksInput: byId("autoExpiryWeeksInput"),
  saveSettingsButton: byId("saveSettingsButton"),
  backupButton: byId("backupButton"),
  reloadPlaylistButton: byId("reloadPlaylistButton"),
  openManagerButton: byId("openManagerButton"),
  trackFilterInput: byId("trackFilterInput"),
  managerTrackList: byId("managerTrackList"),
  managerStatus: byId("managerStatus"),
  acceptModeButton: byId("acceptModeButton"),
  declineModeButton: byId("declineModeButton"),
  feedbackLikesInput: byId("feedbackLikesInput"),
  feedbackMismatchInput: byId("feedbackMismatchInput"),
  generateFeedbackButton: byId("generateFeedbackButton"),
  feedbackOutputLabel: byId("feedbackOutputLabel"),
  feedbackOutput: byId("feedbackOutput"),
  feedbackOutputActions: byId("feedbackOutputActions"),
  copyFeedbackButton: byId("copyFeedbackButton"),
  insertFeedbackButton: byId("insertFeedbackButton"),
  clearFeedbackButton: byId("clearFeedbackButton"),
  feedbackStatus: byId("feedbackStatus"),
  styleLibraryInput: byId("styleLibraryInput"),
  saveStyleLibraryButton: byId("saveStyleLibraryButton"),
  styleCountBadge: byId("styleCountBadge"),
  feedbackTemplateSelect: byId("feedbackTemplateSelect"),
  newFeedbackTemplateButton: byId("newFeedbackTemplateButton"),
  deleteFeedbackTemplateButton: byId("deleteFeedbackTemplateButton"),
  feedbackTemplateNameInput: byId("feedbackTemplateNameInput"),
  feedbackTemplateScopeSelect: byId("feedbackTemplateScopeSelect"),
  feedbackLanguageSelect: byId("feedbackLanguageSelect"),
  feedbackToneSelect: byId("feedbackToneSelect"),
  feedbackLengthSelect: byId("feedbackLengthSelect"),
  feedbackImperfectionsSelect: byId("feedbackImperfectionsSelect"),
  feedbackGrammarSelect: byId("feedbackGrammarSelect"),
  feedbackRulesInput: byId("feedbackRulesInput"),
  scanSessionsButton: byId("scanSessionsButton"),
  cockpitStats: byId("cockpitStats"),
  platformCoverage: byId("platformCoverage"),
  scanMeta: byId("scanMeta"),
  submitHubAds: byId("submitHubAds"),
  earningsSummary: byId("earningsSummary"),
  accountList: byId("accountList"),
  unassignedSessions: byId("unassignedSessions"),
  addAccountButton: byId("addAccountButton"),
  accountForm: byId("accountForm"),
  accountIdInput: byId("accountIdInput"),
  accountNameInput: byId("accountNameInput"),
  accountPlatformSelect: byId("accountPlatformSelect"),
  accountContainerSelect: byId("accountContainerSelect"),
  accountPlaylistSelect: byId("accountPlaylistSelect"),
  accountExpiryInput: byId("accountExpiryInput"),
  accountEarningAmountInput: byId("accountEarningAmountInput"),
  accountEarningCurrencySelect: byId("accountEarningCurrencySelect"),
  accountEarningTrackingInput: byId("accountEarningTrackingInput"),
  accountTrackingInput: byId("accountTrackingInput"),
  accountPositionInput: byId("accountPositionInput"),
  accountLockInput: byId("accountLockInput"),
  accountAutoPrepareInput: byId("accountAutoPrepareInput"),
  accountKeepReadyInput: byId("accountKeepReadyInput"),
  saveAccountButton: byId("saveAccountButton"),
  cancelAccountButton: byId("cancelAccountButton"),
  cockpitStatus: byId("cockpitStatus"),
  adsCard: byId("adsCard"),
  adsSummary: byId("adsSummary"),
  adsMeta: byId("adsMeta"),
  adsAutoSyncInput: byId("adsAutoSyncInput"),
  adsCampaignList: byId("adsCampaignList"),
  scanAdsButton: byId("scanAdsButton"),
  syncAdsButton: byId("syncAdsButton"),
  adsStatus: byId("adsStatus"),
  workflowHint: byId("workflowHint"),
  workflowHintText: byId("workflowHintText"),
  workflowApplyButton: byId("workflowApplyButton"),
  placementReviewDialog: byId("placementReviewDialog"),
  placementReviewRows: byId("placementReviewRows"),
  trackedPlacementFields: byId("trackedPlacementFields"),
  trackedPlaylistSelect: byId("trackedPlaylistSelect"),
  trackedExpiryInput: byId("trackedExpiryInput"),
  trackedPositionInput: byId("trackedPositionInput"),
  placementReviewWarning: byId("placementReviewWarning"),
  placementReviewAcknowledgeRow: byId("placementReviewAcknowledgeRow"),
  placementReviewAcknowledgeInput: byId("placementReviewAcknowledgeInput"),
  closePlacementReviewButton: byId("closePlacementReviewButton"),
  cancelPlacementReviewButton: byId("cancelPlacementReviewButton"),
  confirmPlacementButton: byId("confirmPlacementButton"),
  focusNavButton: byId("focusNavButton"),
  queueNavButton: byId("queueNavButton"),
  toolsNavButton: byId("toolsNavButton"),
  adsNavButton: byId("adsNavButton"),
};

function setStatus(element, message = "", kind = "") {
  element.textContent = message;
  element.className = `status ${kind}`.trim();
}

async function setActiveView(view, { persist = true, load = true } = {}) {
  const next = ["focus", "queue", "tools", "ads"].includes(view) ? view : "focus";
  state.activeView = next;
  document.body.dataset.view = next;
  elements.focusNavButton.classList.toggle("active", next === "focus");
  elements.queueNavButton.classList.toggle("active", next === "queue");
  elements.toolsNavButton.classList.toggle("active", next === "tools");
  elements.adsNavButton.classList.toggle("active", next === "ads");
  if (persist) await browser.storage.local.set({ [SIDEBAR_VIEW_KEY]: next });
  if (!load || !state.connected) return;
  if (next === "focus") {
    await loadStyleLibrary();
  } else if (next === "queue") {
    await Promise.all([
      loadCockpit(),
      state.playlists.length ? Promise.resolve() : loadPlaylists({ loadManager: false }),
    ]);
  } else if (next === "tools") {
    await Promise.all([
      loadAcceptedTracks(),
      state.playlists.length ? Promise.resolve() : loadPlaylists({ loadManager: false }),
    ]);
  } else {
    await loadAdsPanel();
  }
}

function adCampaignKey(campaign = {}) {
  return String(campaign.url || campaign.name || "campaign");
}

function normalizedMatchTokens(value = "") {
  const ignored = new Set(["a", "an", "and", "for", "from", "in", "of", "on", "the", "to", "your", "playlist", "playlists", "music", "vibes"]);
  return String(value || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .split(/\s+/)
    .filter((token) => token && !ignored.has(token));
}

function suggestedPlaylistId(campaign = {}) {
  const campaignTokens = normalizedMatchTokens(campaign.name);
  if (!campaignTokens.length) return "";
  const campaignSet = new Set(campaignTokens);
  const ranked = state.playlists.map((playlist) => {
    const playlistTokens = normalizedMatchTokens(playlist.name);
    const playlistSet = new Set(playlistTokens);
    const intersection = [...campaignSet].filter((token) => playlistSet.has(token)).length;
    const union = new Set([...campaignSet, ...playlistSet]).size;
    const coverage = intersection / Math.max(1, Math.min(campaignSet.size, playlistSet.size));
    const jaccard = intersection / Math.max(1, union);
    const exact = campaignTokens.join(" ") === playlistTokens.join(" ");
    return { id: playlist.id, score: exact ? 2 : coverage * 0.65 + jaccard * 0.35 };
  }).sort((left, right) => right.score - left.score);
  const best = ranked[0];
  const runnerUp = ranked[1];
  if (!best || best.score < 0.58) return "";
  if (runnerUp && best.score < 2 && best.score - runnerUp.score < 0.12) return "";
  return best.id;
}

async function saveAdSettings() {
  await send({ type: "SAVE_SUBMITHUB_AD_SETTINGS", settings: state.adSettings });
}

function renderAdsPanel() {
  elements.adsCard.classList.toggle("hidden", !state.connected);
  const ads = state.cockpit?.scanSnapshot?.submitHubAds || null;
  const campaigns = ads?.campaigns || [];
  const totalDaily = Number(ads?.totals?.dailySpend || 0);
  const monthlyRunRate = totalDaily * 30;
  elements.adsSummary.replaceChildren(...[
    ["Daily", `${totalDaily.toFixed(1)} cr`],
    ["Monthly est.", `${monthlyRunRate.toFixed(0)} cr`],
  ].map(([label, value]) => {
    const node = document.createElement("span");
    const strong = document.createElement("strong");
    strong.textContent = value;
    node.append(strong, document.createTextNode(label));
    return node;
  }));
  elements.adsMeta.textContent = ads?.capturedAt
    ? `${campaigns.length} active campaigns · scanned ${new Date(ads.capturedAt).toLocaleString()}${ads.warning ? ` · ${ads.warning}` : ""}`
    : "No ad scan yet.";
  elements.adsAutoSyncInput.checked = !!state.adSettings.autoSync;
  elements.syncAdsButton.disabled = !campaigns.some((campaign) => state.adSettings.mappings[adCampaignKey(campaign)]);
  if (!campaigns.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = ads?.warning || "Run a manual scan to load active campaigns.";
    elements.adsCampaignList.replaceChildren(empty);
    return;
  }
  elements.adsCampaignList.replaceChildren(...campaigns.map((campaign) => {
    const card = document.createElement("article");
    card.className = "adsCampaign";
    const header = document.createElement("div");
    header.className = "adsCampaignHeader";
    const name = document.createElement("strong");
    name.textContent = campaign.name || "SubmitHub campaign";
    const metrics = document.createElement("span");
    metrics.textContent = [
      campaign.dailySpend == null ? "budget unavailable" : `${campaign.dailySpend} cr/day`,
      campaign.conversions == null ? "" : `${campaign.conversions} opens`,
      campaign.ctr == null ? "" : `${Number(campaign.ctr).toFixed(2)}% CTR`,
    ].filter(Boolean).join(" · ") || "No metrics recognized";
    header.append(name, metrics);
    const select = document.createElement("select");
    select.setAttribute("aria-label", `Playlist for ${campaign.name || "campaign"}`);
    select.append(new Option("Do not sync", ""), ...state.playlists.map((playlist) => new Option(playlist.name || "Playlist", playlist.id)));
    const key = adCampaignKey(campaign);
    select.value = state.adSettings.mappings[key] || "";
    select.addEventListener("change", async () => {
      state.adSettings.mappings[key] = select.value;
      if (!select.value) delete state.adSettings.mappings[key];
      await saveAdSettings();
      renderAdsPanel();
    });
    const detail = document.createElement("details");
    detail.className = "adsCampaignDetails";
    const detailSummary = document.createElement("summary");
    detailSummary.textContent = "Details";
    const detailMetrics = document.createElement("div");
    detailMetrics.textContent = [
      campaign.spent == null ? "Lifetime spend unavailable" : `${Number(campaign.spent).toFixed(1)} cr lifetime spend`,
      campaign.remaining == null ? "" : `${Number(campaign.remaining).toFixed(1)} cr remaining`,
      campaign.dailySpend == null ? "" : `${(Number(campaign.dailySpend) * 30).toFixed(0)} cr estimated monthly run rate`,
    ].filter(Boolean).join(" · ");
    detail.append(detailSummary, detailMetrics);
    card.append(header, select, detail);
    return card;
  }));
}

async function loadAdsPanel() {
  if (!state.connected) return;
  const [cockpit, settings] = await Promise.all([
    send({ type: "GET_ACCOUNT_COCKPIT" }),
    send({ type: "GET_SUBMITHUB_AD_SETTINGS" }),
    state.playlists.length ? Promise.resolve() : loadPlaylists({ loadManager: false }),
  ]);
  state.cockpit = cockpit;
  state.adSettings = { autoSync: false, mappings: {}, ...(settings || {}) };
  let inferredMapping = false;
  for (const campaign of cockpit?.scanSnapshot?.submitHubAds?.campaigns || []) {
    const key = adCampaignKey(campaign);
    if (state.adSettings.mappings[key]) continue;
    const playlistId = suggestedPlaylistId(campaign);
    if (!playlistId) continue;
    state.adSettings.mappings[key] = playlistId;
    inferredMapping = true;
  }
  if (inferredMapping) await saveAdSettings();
  renderAdsPanel();
}

async function syncSubmitHubAds(snapshot = state.cockpit?.scanSnapshot) {
  const campaigns = snapshot?.submitHubAds?.campaigns || [];
  const missingBudgets = campaigns.filter((campaign) => !Number.isFinite(Number(campaign.dailySpend))).length;
  if (missingBudgets) throw new Error(`${missingBudgets}/${campaigns.length} active campaign budgets are missing. Scan again before syncing.`);
  const mapped = campaigns.map((campaign) => ({
    name: campaign.name,
    playlistId: state.adSettings.mappings[adCampaignKey(campaign)] || "",
    dailySpendCredits: campaign.dailySpend,
  })).filter((campaign) => campaign.playlistId && Number.isFinite(Number(campaign.dailySpendCredits)));
  if (!mapped.length) throw new Error("Map at least one campaign with a recognized daily spend first.");
  const result = await send({
    type: "SYNC_SUBMITHUB_ADS",
    input: { campaigns: mapped, eventDate: new Date().toISOString().slice(0, 10) },
  });
  setStatus(elements.adsStatus, `${result.synced || 0} campaign${result.synced === 1 ? "" : "s"} synced to PlaylistPilot.`, result.errors ? "error" : "success");
  return result;
}

function renderAcceptedTracks() {
  const statusFor = (track) => track.playlist_added_at && track.expires_at ? "active" : track.playlist_id ? "waiting" : "needs_mapping";
  const tracks = (state.acceptedTracks || []).filter((track) =>
    state.acceptedTracksFilter === "all" || statusFor(track) === state.acceptedTracksFilter
  );
  elements.acceptedTracksCard.classList.toggle("hidden", !state.connected);
  if (!tracks.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = state.acceptedTracks.length ? "No placements match this filter." : "No tracked acceptances yet.";
    elements.acceptedTracksList.replaceChildren(empty);
    return;
  }
  elements.acceptedTracksList.replaceChildren(...tracks.map((track) => {
    const row = document.createElement("article");
    row.className = "acceptedTrack";
    const identity = document.createElement("div");
    identity.className = "acceptedTrackIdentity";
    const title = document.createElement("strong");
    title.textContent = track.track_title || "Unknown track";
    const artist = document.createElement("span");
    const platform = platformLabel(track.platform || "groover");
    const playlists = Array.isArray(track.platform_playlists) ? track.platform_playlists.filter(Boolean).join(", ") : "";
    artist.textContent = [(track.artist_names || []).join(", ") || track.spotify_track_id, platform, playlists].filter(Boolean).join(" · ");
    const status = document.createElement("small");
    status.className = "acceptedTrackStatus";
    status.textContent = track.playlist_added_at && track.expires_at
      ? `Active · expires ${new Date(track.expires_at).toLocaleDateString()}`
      : track.playlist_id
        ? "Waiting for the track to appear on Spotify"
        : "Playlist mapping required";
    identity.append(title, artist, status);
    const controls = document.createElement("div");
    controls.className = "acceptedExpiryControls";
    const playlistSelect = document.createElement("select");
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Choose PlaylistPilot playlist";
    playlistSelect.append(placeholder, ...state.playlists.map((playlist) => {
      const option = document.createElement("option");
      option.value = playlist.id;
      option.textContent = playlist.name;
      return option;
    }));
    playlistSelect.value = state.playlists.some((playlist) => playlist.id === track.playlist_id) ? track.playlist_id : "";
    playlistSelect.disabled = !!track.playlist_added_at;
    const input = document.createElement("input");
    input.type = "number";
    input.min = "1";
    input.max = "104";
    input.placeholder = "Weeks";
    input.value = track.manual_expiry_weeks || "";
    const save = document.createElement("button");
    save.type = "button";
    save.textContent = "Save";
    save.addEventListener("click", async () => {
      const weeks = input.value === "" ? null : Number(input.value);
      if (weeks !== null && (!Number.isInteger(weeks) || weeks < 1 || weeks > 104)) {
        setStatus(elements.acceptedTracksStatus, "Expiry must be between 1 and 104 weeks.", "error");
        return;
      }
      save.disabled = true;
      try {
        await send({
          type: "SET_ACCEPTED_TRACK_EXPIRY",
          input: { id: track.id, manual_expiry_weeks: weeks, playlist_id: playlistSelect.value || null },
        });
        await loadAcceptedTracks();
        setStatus(elements.acceptedTracksStatus, "Manual expiry saved.", "success");
      } catch (error) {
        setStatus(elements.acceptedTracksStatus, error.message, "error");
      } finally {
        save.disabled = false;
      }
    });
    controls.append(playlistSelect, input, save);
    row.append(identity, controls);
    return row;
  }));
}

async function loadAcceptedTracks() {
  if (!state.connected) return;
  try {
    const result = await send({ type: "LIST_ACCEPTED_TRACKS" });
    state.acceptedTracks = Array.isArray(result.tracks) ? result.tracks : [];
    renderAcceptedTracks();
  } catch (error) {
    setStatus(elements.acceptedTracksStatus, error.message, "error");
  }
}

function queueEntries(context) {
  const inbox = context?.inbox || {};
  if (context?.platform === "groover") {
    return [
      ["Open", inbox.total],
      ["≤24h", dueSoonCount(context)],
      ["To listen", inbox.toListen],
      ["To complete", inbox.toComplete],
    ];
  }
  if (context?.platform === "playlistpush") {
    return [["Open", inbox.total], ["≤24h", dueSoonCount(context)]];
  }
  return [
    ["Open", inbox.total ?? inbox.visible],
    ["Visible", inbox.visible],
    ["≤24h", dueSoonCount(context)],
  ];
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

function dueSoonCount(context) {
  if (context?.platform === "playlistpush") {
    return Number(context?.inbox?.total ?? context?.inbox?.visible ?? 0);
  }
  const detected = [context?.deadlineLabel, ...(context?.inbox?.deadlineLabels || [])]
    .filter(Boolean)
    .filter((value) => {
      const hours = deadlineHours(value);
      return hours !== null && hours <= 24;
    }).length;
  return detected;
}

function defaultExpiry(platform) {
  return platform === "groover" ? 4 : 8;
}

function currentWorkflowProfile() {
  if (!state.context?.platform || !state.cockpit?.profiles) return null;
  return state.cockpit.profiles.find((profile) =>
    profile.platform === state.context.platform &&
    profile.cookieStoreId === (state.context.cookieStoreId || "firefox-default")
  ) || null;
}

function workflowForProfile(profile) {
  return {
    playlistId: profile?.workflow?.playlistId || "",
    expiryWeeks: Number(profile?.workflow?.expiryWeeks || defaultExpiry(profile?.platform || state.context?.platform)),
    position: Number(profile?.workflow?.position) > 0 ? Number(profile.workflow.position) : null,
    lock: !!profile?.workflow?.lock,
    autoPrepare: profile?.workflow?.autoPrepare !== false,
    trackingEnabled: profile?.workflow?.trackingEnabled !== false,
  };
}

function applyCurrentWorkflow(force = false) {
  const profile = currentWorkflowProfile();
  if (!profile) return;
  const workflow = workflowForProfile(profile);
  const key = `${profile.id}:${profile.updatedAt || ""}:${state.context?.platformSubmissionId || state.context?.spotifyTrackId || state.context?.tabId || ""}`;
  if (!force && (!workflow.autoPrepare || state.workflowKey === key)) return;
  if (workflow.playlistId && state.playlists.some((playlist) => playlist.id === workflow.playlistId)) {
    elements.playlistSelect.value = workflow.playlistId;
  }
  elements.expiryInput.value = workflow.expiryWeeks;
  elements.positionInput.value = workflow.position || "";
  elements.lockInput.checked = workflow.lock;
  state.workflowKey = key;
  updatePlacementButton();
}

function renderWorkflowHint() {
  const profile = currentWorkflowProfile();
  elements.workflowHint.classList.toggle("hidden", !profile);
  if (!profile) return;
  const workflow = workflowForProfile(profile);
  const playlist = state.playlists.find((item) => item.id === workflow.playlistId);
  elements.workflowHintText.textContent = `${profile.name}: ${playlist?.name || "choose playlist"} · ${workflow.position ? `slot ${workflow.position} · ` : ""}${workflow.expiryWeeks} weeks${workflow.lock ? " · locked" : ""}`;
  applyCurrentWorkflow();
}

function textList(value) {
  if (Array.isArray(value)) {
    return value.flatMap((entry) => textList(entry)).filter(Boolean);
  }
  if (value === null || value === undefined) return [];
  const text = String(value).trim();
  if (!text) return [];
  if (text.startsWith("[") && text.endsWith("]")) {
    try {
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed)) return textList(parsed);
    } catch {}
  }
  return [text];
}

function itemArtistNames(item = {}) {
  return textList(item.artist_names ?? item.artistNames ?? item.artists ?? item.artist_name ?? item.artist);
}

const SPOTIFY_PLAYER_ORIGIN = "https://playlist-pilot.com";
const SPOTIFY_PLAYER_MESSAGE = "PLAYLISTPILOT_SPOTIFY_PLAYER";

function sendSpotifyPlayer(action, trackId = "") {
  elements.spotifyEmbed.contentWindow?.postMessage({ type: SPOTIFY_PLAYER_MESSAGE, action, trackId }, SPOTIFY_PLAYER_ORIGIN);
}

function renderSpotifyPlayerState(message = "") {
  const status = message || (state.focusedTrack && !state.spotifyPlayerReady ? "Loading Spotify…" : "");
  elements.spotifyPlayerStatus.textContent = status;
  elements.spotifyPlayerStatus.classList.toggle("hidden", !status);
  elements.playPauseButton.textContent = state.spotifyPlayerPlaying ? "❚❚ Pause" : "▶ Play";
}

function syncSpotifyPlayer(trackId) {
  if (!trackId) return;
  const changed = state.spotifyLoadedTrackId !== trackId;
  if (changed) {
    window.clearTimeout(state.spotifyPlayAttemptTimer);
    state.spotifyLoadedTrackId = trackId;
    state.spotifyPlayerPlaying = false;
    sendSpotifyPlayer("load", trackId);
  }
}

function renderFocusedTrack(focus) {
  const previousId = state.focusedTrack?.spotifyTrackId || "";
  state.focusedTrack = focus?.spotifyTrackId ? focus : null;
  const tracks = Array.isArray(state.focusedTrack?.pageTracks) ? state.focusedTrack.pageTracks : [];
  const hasTrack = !!state.focusedTrack;
  elements.overviewPlayerTitle.textContent = hasTrack ? (state.focusedTrack.trackTitle || "Spotify track") : "Choose a submission on the page";
  elements.overviewPlayerArtist.textContent = hasTrack
    ? [textList(state.focusedTrack.artistNames).join(", "), platformLabel(state.focusedTrack.platform)].filter(Boolean).join(" · ")
    : "No track selected";
  elements.spotifyEmbed.classList.toggle("hidden", !hasTrack);
  elements.playPauseButton.disabled = !hasTrack;
  elements.openSpotifyButton.disabled = !hasTrack;
  elements.previousSubmissionButton.disabled = tracks.length < 2;
  elements.nextSubmissionButton.disabled = tracks.length < 2;
  if (hasTrack && previousId !== state.focusedTrack.spotifyTrackId) syncSpotifyPlayer(state.focusedTrack.spotifyTrackId);
  renderSpotifyPlayerState();
}

window.addEventListener("message", (event) => {
  if (event.origin !== SPOTIFY_PLAYER_ORIGIN || event.source !== elements.spotifyEmbed.contentWindow || event.data?.type !== SPOTIFY_PLAYER_MESSAGE) return;
  if (event.data.event === "bridgeReady" && state.focusedTrack?.spotifyTrackId) {
    sendSpotifyPlayer("load", state.focusedTrack.spotifyTrackId);
  }
  if (event.data.event === "ready") {
    state.spotifyPlayerReady = true;
    renderSpotifyPlayerState();
    if (state.focusedTrack?.spotifyTrackId) syncSpotifyPlayer(state.focusedTrack.spotifyTrackId);
  }
  if (event.data.event === "playing" || event.data.event === "playbackUpdate") {
    if (event.data.playing) window.clearTimeout(state.spotifyPlayAttemptTimer);
    state.spotifyPlayerPlaying = !!event.data.playing;
    renderSpotifyPlayerState();
  }
  if (event.data.event === "error") renderSpotifyPlayerState(event.data.message || "Spotify player unavailable");
});

function renderContext() {
  const context = state.context;
  const supported = !!context?.platform;
  renderSessionDock();
  elements.emptyCard.classList.toggle("hidden", supported);
  elements.contextCard.classList.toggle("hidden", !supported);
  elements.reviewCard.classList.toggle("hidden", !supported);
  elements.adapterCard.classList.toggle("hidden", !supported);
  elements.feedbackCard.classList.toggle("hidden", !state.connected);
  elements.placementCard.classList.toggle("hidden", !supported || !context?.spotifyTrackId || !state.connected);
  if (supported && state.lastPlatform !== context.platform) {
    state.lastPlatform = context.platform;
    if (state.feedbackTemplates.length) activateFeedbackTemplateForContext();
  }
  updateFeedbackButton();
  return;

  /* Legacy live-review rendering is intentionally unreachable in v0.24.
     It remains in this release only to keep storage/API migration low-risk. */
  const submissionKey = `${context.platform}:${context.platformSubmissionId || context.spotifyTrackId || context.url || "inbox"}`;
  if (state.reviewSubmissionKey !== submissionKey) {
    state.reviewSubmissionKey = submissionKey;
    elements.liveFeedbackInput.classList.remove("typingActive");
    initializeReviewSubmission().catch(() => {});
  }

  elements.platformBadge.textContent = context.platform;
  elements.profileLabel.textContent = context.platformProfile || "Account detected";
  elements.trackTitle.textContent = context.trackTitle || "Open a submission";
  elements.artistNames.textContent = textList(context.artistNames).join(", ");
  elements.deadlineLabel.textContent = context.deadlineLabel ? `Due ${context.deadlineLabel}` : "";
  elements.spotifyLink.classList.toggle("hidden", !context.spotifyTrackUrl);
  if (context.spotifyTrackUrl) elements.spotifyLink.href = context.spotifyTrackUrl;
  elements.spotifyFallback.classList.toggle("hidden", !context.spotifyTrackId);
  syncSpotifyPlayer(context.spotifyTrackId, state.spotifyAutoPlayPending && elements.autoPlayInput.checked);
  state.spotifyAutoPlayPending = false;
  elements.decisionBadge.textContent = context.proposedDecision || "Manual";
  if (state.lastPlatform !== context.platform) {
    elements.expiryInput.value = defaultExpiry(context.platform);
    state.lastPlatform = context.platform;
  }
  elements.queueStats.replaceChildren(...queueEntries(context)
    .filter(([label, value]) => value !== undefined && value !== null && (label === "Open" || Number(value) !== 0))
    .map(([label, value]) => {
      const node = document.createElement("span");
      node.textContent = `${label}: ${value}`;
      return node;
    }));
  updatePlacementButton();
  updateFeedbackButton();
  renderWorkflowHint();
  renderAdapterDiagnostics();
}

async function initializeReviewSubmission() {
  const context = state.context;
  const submissionKey = context
    ? `${context.platform || ""}:${context.cookieStoreId || "firefox-default"}:${context.platformSubmissionId || context.spotifyTrackId || ""}`
    : "";
  const shouldPrepareDecline = !!submissionKey &&
    submissionKey !== state.declinePreparedSubmissionKey &&
    elements.defaultDeclineInput.checked &&
    !context?.proposedDecision &&
    (context?.status === "in_review" || !!context?.spotifyTrackId);
  if (shouldPrepareDecline) {
    // Mark before the async call so concurrent renders cannot prepare the same
    // submission twice. Manual Accept remains untouched after this one-time setup.
    state.declinePreparedSubmissionKey = submissionKey;
    setFeedbackMode("decline");
    await send({ type: "PREPARE_DECISION", mode: "decline" }).catch(() => null);
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  await loadReviewState();
}

function setReviewBridgeState(available, message = "") {
  elements.reviewBridgeBadge.textContent = available ? "Live" : "Open form";
  elements.reviewBridgeBadge.className = `adapterStatusBadge ${available ? "healthy" : "degraded"}`;
  if (message) setStatus(elements.reviewStatus, message, available ? "success" : "error");
}

async function loadReviewState() {
  try {
    const result = await send({ type: "GET_REVIEW_STATE" });
    state.bridgeRemoteUpdate = true;
    elements.liveFeedbackInput.value = result.value || "";
    state.bridgeRemoteUpdate = false;
    elements.playPauseButton.textContent = result.playing ? "❚❚ Pause" : "▶ Play";
    setReviewBridgeState(result.bridgeAvailable);
  } catch (error) {
    setReviewBridgeState(false, error.message);
  }
}

async function runReviewAction(message, progress) {
  setStatus(elements.reviewStatus, progress);
  try {
    const result = await send(message);
    if (typeof result.playing === "boolean") elements.playPauseButton.textContent = result.playing ? "❚❚ Pause" : "▶ Play";
    const destination = result.switchedAccount ? ` Switched to ${platformLabel(result.platform)}.` : "";
    if (result.queueTotal) elements.reviewQueuePosition.textContent = `${result.queuePosition} / ${result.queueTotal}`;
    setStatus(elements.reviewStatus, `Review ready.${destination} Nothing was submitted.`, "success");
    setTimeout(() => refresh().catch(() => {}), /NAVIGATE/.test(message.type) ? 950 : 250);
    return result;
  } catch (error) {
    if (message.type === "CONTROL_PLAYBACK" && state.context?.spotifyTrackId) {
      elements.spotifyFallback.open = true;
      setStatus(elements.reviewStatus, "Platform player unavailable — Spotify fallback opened below.", "error");
    } else {
      setStatus(elements.reviewStatus, error.message, "error");
    }
    throw error;
  }
}

function warningLabel(value) {
  if (value === "review_without_track_title") return "Track title missing on an open review";
  if (value === "review_without_spotify_track") return "Spotify track missing on an open review";
  if (value === "account_label_not_detected") return "Account label could not be detected";
  return String(value || "").replaceAll("_", " ");
}

function renderAdapterDiagnostics() {
  const health = state.context?.adapterHealth;
  if (!health) {
    elements.adapterQuickStatus.className = "adapterQuickStatus degraded";
    elements.adapterQuickStatus.title = "Adapter details: reload required";
    elements.adapterStatusBadge.textContent = "Legacy";
    elements.adapterStatusBadge.className = "adapterStatusBadge degraded";
    elements.adapterFields.replaceChildren();
    elements.adapterWarnings.replaceChildren();
    elements.adapterMeta.textContent = "Reload this platform tab after updating the extension.";
    return;
  }
  const status = health.status || (health.warnings?.length ? "degraded" : "healthy");
  elements.adapterQuickStatus.className = `adapterQuickStatus ${status}`;
  elements.adapterQuickStatus.title = `Adapter ${status} · ${Math.round(Number(health.confidence || 0) * 100)}% confidence`;
  elements.adapterStatusBadge.textContent = status;
  elements.adapterStatusBadge.className = `adapterStatusBadge ${status}`;
  const detected = new Set(health.detectedFields || []);
  const fields = [
    ["profile", "Account"],
    ["track_title", "Track"],
    ["spotify_track", "Spotify"],
    ["submission_id", "Submission"],
    ["inbox", "Inbox"],
    ["deadline", "Deadline"],
  ];
  elements.adapterFields.replaceChildren(...fields.map(([key, label]) => {
    const chip = document.createElement("span");
    chip.className = detected.has(key) ? "detected" : "";
    chip.textContent = `${detected.has(key) ? "✓" : "–"} ${label}`;
    return chip;
  }));
  elements.adapterWarnings.replaceChildren(...(health.warnings || []).map((warning) => {
    const item = document.createElement("span");
    item.textContent = warningLabel(warning);
    return item;
  }));
  elements.adapterMeta.textContent = `${health.adapterVersion || state.context.adapterVersion || "legacy"} · ${Math.round(Number(health.confidence || 0) * 100)}% confidence`;
}

async function copyAdapterReport() {
  const report = state.context?.adapterHealth?.report;
  if (!report) {
    setStatus(elements.adapterStatus, "No diagnostic report available. Reload the platform tab first.", "error");
    return;
  }
  const payload = JSON.stringify({ ...report, capturedAt: new Date().toISOString() }, null, 2);
  try {
    await navigator.clipboard.writeText(payload);
  } catch {
    const helper = document.createElement("textarea");
    helper.value = payload;
    document.body.append(helper);
    helper.select();
    document.execCommand("copy");
    helper.remove();
  }
  setStatus(elements.adapterStatus, "Anonymized diagnostic copied.", "success");
}

function renderAuth(auth) {
  state.connected = !!auth?.connected;
  elements.authLabel.textContent = state.connected ? auth.email || "Connected" : "Not connected";
  elements.connectButton.classList.toggle("hidden", state.connected);
  elements.signOutButton.classList.toggle("hidden", !state.connected);
  elements.managerCard.classList.toggle("hidden", !state.connected);
  elements.feedbackCard.classList.toggle("hidden", !state.connected);
  elements.sessionCard.classList.toggle("hidden", !state.connected);
  elements.sessionDockCard.classList.toggle("hidden", !state.connected || !state.cockpit?.profiles?.length);
  updatePlacementButton();
  updateFeedbackButton();
}

function updatePlacementButton() {
  elements.placementButton.disabled = !state.connected || !state.context?.spotifyTrackId || !elements.playlistSelect.value;
}

function updateFeedbackButton() {
  const hasInput = !!(elements.feedbackLikesInput.value.trim() || elements.feedbackMismatchInput.value.trim());
  elements.generateFeedbackButton.disabled = !state.connected || !hasInput;
}

async function send(message) {
  const response = await browser.runtime.sendMessage(message);
  if (response?.ok === false) throw new Error(response.error || "Extension request failed");
  return response;
}

function playlistOptions(playlists, placeholderText = "Choose a playlist") {
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = placeholderText;
  return [
    placeholder,
    ...playlists.map((playlist) => {
      const option = document.createElement("option");
      option.value = playlist.id;
      option.textContent = `${playlist.name} · ${Number(playlist.tracks_total || 0)} tracks`;
      return option;
    }),
  ];
}

async function loadPlaylists({ loadManager = state.activeView === "tools" } = {}) {
  if (!state.connected) return;
  const playlists = await send({ type: "LIST_PLAYLISTS" });
  state.playlists = Array.isArray(playlists) ? playlists : [];
  if (state.activeView === "tools" && state.acceptedTracks.length) renderAcceptedTracks();
  const placementCurrent = elements.playlistSelect.value;
  const managerCurrent = state.managerPlaylistId || elements.managerPlaylistSelect.value;

  elements.playlistSelect.replaceChildren(...playlistOptions(state.playlists));
  elements.managerPlaylistSelect.replaceChildren(...playlistOptions(state.playlists));
  if (state.playlists.some((playlist) => playlist.id === placementCurrent)) {
    elements.playlistSelect.value = placementCurrent;
  }

  const nextManagerId = state.playlists.some((playlist) => playlist.id === managerCurrent)
    ? managerCurrent
    : state.playlists[0]?.id || "";
  state.managerPlaylistId = nextManagerId;
  elements.managerPlaylistSelect.value = nextManagerId;
  updatePlacementButton();
  if (loadManager && nextManagerId) await loadManagerPlaylist(nextManagerId);
  else if (loadManager) renderManager();
  renderWorkflowHint();
}

function platformLabel(platform) {
  if (platform === "submithub") return "SubmitHub";
  if (platform === "playlistpush") return "PlaylistPush";
  if (platform === "unhurd") return "Unhurd";
  return "Groover";
}

function relativeSeen(value) {
  const time = Date.parse(value || "");
  if (!Number.isFinite(time)) return "Never scanned";
  const minutes = Math.max(0, Math.floor((Date.now() - time) / 60000));
  if (minutes < 1) return "Scanned just now";
  if (minutes < 60) return `Scanned ${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return hours < 24 ? `Scanned ${hours}h ago` : `Scanned ${Math.floor(hours / 24)}d ago`;
}

function populateContainerSelect(selected = "__new__") {
  const options = [];
  const fresh = document.createElement("option");
  fresh.value = "__new__";
  fresh.textContent = "Create a new Firefox Container";
  options.push(fresh);
  const standard = document.createElement("option");
  standard.value = "firefox-default";
  standard.textContent = "Default Firefox session";
  options.push(standard);
  for (const container of state.containers) {
    const option = document.createElement("option");
    option.value = container.cookieStoreId;
    option.textContent = container.name;
    options.push(option);
  }
  if (selected && !options.some((option) => option.value === selected)) {
    const current = document.createElement("option");
    current.value = selected;
    current.textContent = `Current session (${selected})`;
    options.push(current);
  }
  elements.accountContainerSelect.replaceChildren(...options);
  elements.accountContainerSelect.value = selected || "__new__";
}

function populateAccountPlaylistSelect(selected = "") {
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Choose when placing";
  const options = [
    placeholder,
    ...state.playlists.map((playlist) => {
      const option = document.createElement("option");
      option.value = playlist.id;
      option.textContent = playlist.name;
      return option;
    }),
  ];
  elements.accountPlaylistSelect.replaceChildren(...options);
  elements.accountPlaylistSelect.value = state.playlists.some((playlist) => playlist.id === selected) ? selected : "";
}

function openAccountForm(profile = null, session = null) {
  const platform = profile?.platform || session?.platform || state.context?.platform || "groover";
  const cookieStoreId = profile?.cookieStoreId || session?.cookieStoreId || "__new__";
  elements.accountIdInput.value = profile?.id || "";
  elements.accountNameInput.value = profile?.name || session?.platformProfile || `${platformLabel(platform)} · account`;
  elements.accountPlatformSelect.value = platform;
  populateContainerSelect(cookieStoreId);
  const workflow = workflowForProfile(profile || { platform });
  populateAccountPlaylistSelect(workflow.playlistId);
  elements.accountExpiryInput.value = workflow.expiryWeeks;
  elements.accountPositionInput.value = workflow.position || "";
  elements.accountLockInput.checked = workflow.lock;
  elements.accountAutoPrepareInput.checked = workflow.autoPrepare;
  elements.accountTrackingInput.checked = workflow.trackingEnabled;
  elements.accountEarningAmountInput.value = Number(profile?.earnings?.amount || 0);
  elements.accountEarningCurrencySelect.value = /^[A-Z]{3}$/.test(profile?.earnings?.currency || "") ? profile.earnings.currency : "EUR";
  elements.accountEarningTrackingInput.checked = profile?.earnings?.enabled !== false;
  elements.accountKeepReadyInput.checked = profile?.keepReady !== false;
  elements.accountForm.classList.remove("hidden");
  elements.addAccountButton.classList.add("hidden");
  elements.accountNameInput.focus();
}

function closeAccountForm() {
  elements.accountForm.classList.add("hidden");
  elements.addAccountButton.classList.remove("hidden");
  elements.accountIdInput.value = "";
}

function accountCount(label, value, emphasize = false) {
  const node = document.createElement("span");
  if (emphasize) node.className = "activeMeta";
  node.textContent = `${label}: ${Number(value || 0)}`;
  return node;
}

function renderAccountCard(profile) {
  const session = profile.session;
  const card = document.createElement("details");
  card.className = "accountCard";
  const header = document.createElement("summary");
  header.className = "accountHeader";
  const dot = document.createElement("span");
  dot.className = `healthDot ${session?.health || "closed"}`;
  dot.title = session?.health === "unreadable"
    ? `Adapter could not read this tab${session.lastError ? `: ${session.lastError}` : ""}`
    : session?.health === "stale"
      ? "Session is open but its data is stale"
      : session?.health === "active"
        ? "Session is active and readable"
        : "No open tab for this account";
  const identity = document.createElement("div");
  identity.className = "accountIdentity";
  const name = document.createElement("strong");
  name.textContent = profile.name;
  const detail = document.createElement("span");
  const detected = session?.platformProfile && session.platformProfile !== profile.name ? ` · ${session.platformProfile}` : "";
  const warning = session?.context?.adapterHealth?.warnings?.length ? " · adapter check" : "";
  const earning = profile.earnings?.enabled !== false && Number(profile.earnings?.amount || 0) > 0
    ? ` · ${Number(profile.earnings.amount).toLocaleString(undefined, { maximumFractionDigits: 4 })} ${profile.earnings.currency || "EUR"}/review`
    : "";
  detail.textContent = `${platformLabel(profile.platform)}${detected}${earning} · ${relativeSeen(session?.lastSeenAt)}${warning}`;
  identity.append(name, detail);
  header.append(dot, identity);
  const counts = document.createElement("div");
  counts.className = "accountCounts";
  const countValues = [
    ["Open", session?.inbox?.open, false],
    ["≤24h", session?.dueWithin24, true],
  ].filter(([label, value]) => label === "Open" || Number(value || 0) > 0);
  counts.replaceChildren(...countValues.map(([label, value, emphasize]) =>
    accountCount(label, value, emphasize && Number(value || 0) > 0)
  ));
  header.append(counts);
  const buttons = document.createElement("div");
  buttons.className = "accountButtons";
  const open = actionButton(session?.active ? "Open session" : "Launch account", "Open in the assigned Firefox session", () => {
    send({ type: "OPEN_ACCOUNT_PROFILE", profileId: profile.id })
      .catch((error) => setStatus(elements.cockpitStatus, error.message, "error"));
  });
  const edit = actionButton("Edit", "Edit account profile", () => openAccountForm(profile));
  const remove = actionButton("×", "Remove profile mapping", async () => {
    if (!window.confirm(`Remove “${profile.name}” from PlaylistPilot? The Firefox Container and its login stay intact.`)) return;
    try {
      await send({ type: "DELETE_ACCOUNT_PROFILE", profileId: profile.id });
      await loadCockpit();
      setStatus(elements.cockpitStatus, "Account profile removed. Firefox login was kept.", "success");
    } catch (error) {
      setStatus(elements.cockpitStatus, error.message, "error");
    }
  }, "dangerButton");
  buttons.append(open, edit, remove);
  card.append(header, buttons);
  return card;
}

function renderCockpit() {
  const cockpit = state.cockpit || { profiles: [], unassigned: [], stats: {} };
  // Keep the headline in lockstep with the account rows below. A full scan may
  // temporarily contain extra account-switch observations that are useful for
  // diagnostics but must not inflate the user-facing totals.
  const stableStats = cockpit.stats || {};
  const stats = [
    ["Open", stableStats.open],
    ["Due soon", stableStats.dueWithin24],
  ];
  elements.cockpitStats.replaceChildren(...stats.map(([label, value]) => {
    const node = document.createElement("span");
    const strong = document.createElement("strong");
    strong.textContent = String(Number(value || 0));
    node.append(strong, document.createTextNode(label));
    return node;
  }));

  elements.platformCoverage.replaceChildren(...(cockpit.platforms || []).map((item) => {
    const row = document.createElement("div");
    row.className = `platformCoverageItem ${item.state}`;
    const identity = document.createElement("span");
    const dot = document.createElement("i");
    const label = document.createElement("strong");
    label.textContent = platformLabel(item.platform);
    const status = document.createElement("small");
    status.textContent = item.state === "active"
      ? `${item.active} open`
      : item.state === "closed" ? `${item.configured} saved · closed` : "not connected";
    identity.append(dot, label, status);
    row.append(identity);
    if (item.state !== "active") {
      const open = document.createElement("button");
      open.type = "button";
      open.textContent = item.state === "missing" ? "Open" : "Launch";
      open.addEventListener("click", () => send(item.firstProfileId
        ? { type: "OPEN_ACCOUNT_PROFILE", profileId: item.firstProfileId }
        : { type: "OPEN_PLATFORM", platform: item.platform })
        .catch((error) => setStatus(elements.cockpitStatus, error.message, "error")));
      row.append(open);
    }
    return row;
  }));

  const snapshot = cockpit.scanSnapshot;
  elements.scanMeta.textContent = snapshot?.completedAt
    ? `Updated ${new Date(snapshot.completedAt).toLocaleString()} · ${snapshot.totals?.readable || 0}/${snapshot.results?.length || 0} accounts`
    : "Not scanned yet. Scan all checks every configured account once.";
  renderEarningsSummary();
  const ads = snapshot?.submitHubAds;
  elements.submitHubAds.classList.toggle("hidden", !ads);
  if (ads) {
    const title = document.createElement("div");
    title.className = "adsHeader";
    const totalDaily = Number(ads.totals?.dailySpend || 0);
    const headerPart = (label, value) => {
      const part = document.createElement("span");
      const small = document.createElement("small");
      const strong = document.createElement("strong");
      small.textContent = label;
      strong.textContent = value;
      part.append(small, strong);
      return part;
    };
    title.append(
      headerPart("SubmitHub ads", ads.profile || "bored indie kid"),
      headerPart("Daily / month est.", `${totalDaily.toFixed(1)} / ${(totalDaily * 30).toFixed(0)} cr`),
    );
    const rows = (ads.campaigns || []).map((campaign) => {
      const row = document.createElement("div");
      row.className = "adMetricRow";
      const values = [
        campaign.spent === null ? "" : `${Number(campaign.spent).toFixed(1)} cr spent`,
        campaign.dailySpend === null ? "" : `${campaign.dailySpend} cr/day`,
        campaign.conversions === null ? "" : `${campaign.conversions} Spotify opens`,
        campaign.ctr === null ? "" : `${Number(campaign.ctr).toFixed(2)}% CTR`,
      ].filter(Boolean).join(" · ");
      const name = document.createElement("strong");
      const metrics = document.createElement("span");
      name.textContent = campaign.name;
      metrics.textContent = values || "Metrics not recognized";
      row.append(name, metrics);
      return row;
    });
    const warning = document.createElement("p");
    warning.className = "scanWarning";
    warning.textContent = ads.warning || "";
    elements.submitHubAds.replaceChildren(title, ...rows, ...(ads.warning ? [warning] : []));
  }

  if (cockpit.profiles?.length) {
    elements.accountList.replaceChildren(...cockpit.profiles.map(renderAccountCard));
  } else {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "Add your platform accounts and link each one to its Firefox session.";
    elements.accountList.replaceChildren(empty);
  }

  if (cockpit.unassigned?.length) {
    const title = document.createElement("div");
    title.className = "unassignedTitle";
    title.textContent = "Unassigned open sessions";
    const cards = cockpit.unassigned.map((session) => {
      const row = document.createElement("div");
      row.className = "unassignedCard";
      const label = document.createElement("span");
      label.textContent = `${platformLabel(session.platform)} · ${session.platformProfile || session.cookieStoreId}`;
      const assign = document.createElement("button");
      assign.type = "button";
      assign.textContent = "Add";
      assign.addEventListener("click", () => openAccountForm(null, session));
      row.append(label, assign);
      return row;
    });
    elements.unassignedSessions.replaceChildren(title, ...cards);
  } else {
    elements.unassignedSessions.replaceChildren();
  }
  renderSessionDock();
}

function renderEarningsSummary() {
  const summary = state.reviewEarnings?.summary;
  elements.earningsSummary.classList.toggle("hidden", !summary);
  if (!summary) return;
  const fx = state.reviewEarnings?.fx;
  const money = (period) => fx?.unavailable || period?.unsupportedCurrencies?.length
    ? "EUR conversion unavailable"
    : Math.floor(Math.max(0, Number(period?.eur || 0))).toLocaleString(undefined, { style: "currency", currency: "EUR", minimumFractionDigits: 0, maximumFractionDigits: 0 });
  const title = document.createElement("div");
  title.className = "adsHeader";
  const label = document.createElement("strong");
  label.textContent = "Estimated review income";
  title.append(label);
  const periods = [["Today", summary.today], ["This week", summary.week], ["This month", summary.month]];
  const rows = periods.map(([name, period]) => {
    const row = document.createElement("div");
    row.className = "adMetricRow";
    const periodLabel = document.createElement("span");
    const value = document.createElement("strong");
    periodLabel.textContent = `${name} · ${Number(period?.reviews || 0)} reviews`;
    value.textContent = money(period);
    row.append(periodLabel, value);
    return row;
  });
  const rateNote = document.createElement("small");
  rateNote.className = "muted";
  rateNote.textContent = fx?.referenceDate ? `Converted with ECB reference rates · ${fx.referenceDate}${fx.stale ? " · cached" : ""}` : "ECB exchange rates temporarily unavailable";
  elements.earningsSummary.replaceChildren(title, ...rows, rateNote);
}

function renderSessionDock() {
  const profiles = state.cockpit?.profiles || [];
  elements.sessionDockCard.classList.toggle("hidden", !state.connected || !profiles.length);
  if (!profiles.length) {
    elements.sessionDock.replaceChildren();
    return;
  }
  elements.sessionDock.replaceChildren(...profiles.map((profile) => {
    const session = profile.session;
    const current = profile.platform === state.context?.platform &&
      profile.cookieStoreId === (state.context?.cookieStoreId || "firefox-default");
    const button = document.createElement("button");
    button.type = "button";
    button.draggable = true;
    button.dataset.profileId = profile.id;
    button.className = `dockAccount ${profile.platform} ${session?.health || "closed"}${current ? " current" : ""}`;
    button.title = `${profile.name} · drag to reorder · ${session?.inbox?.open || 0} open${Number(session?.badgeCount || 0) > 0 ? ` · ${session.badgeCount} ${session.badgeLabel}` : ""}`;
    const avatar = document.createElement("span");
    avatar.className = "dockAvatar";
    const favicon = document.createElement("img");
    favicon.alt = "";
    favicon.referrerPolicy = "no-referrer";
    favicon.src = profile.platform === "playlistpush"
      ? "https://app.playlistpush.com/favicon.ico"
      : profile.platform === "submithub"
        ? "https://www.submithub.com/favicon.ico"
        : profile.platform === "unhurd"
          ? "https://curator.unhurdmusic.com/favicon.ico"
          : "https://groover.co/favicon.ico";
    const fallback = document.createElement("span");
    fallback.className = "dockFallback hidden";
    fallback.textContent = profile.platform === "playlistpush" ? "P" : profile.platform === "submithub" ? "S" : profile.platform === "unhurd" ? "U" : "G";
    favicon.addEventListener("error", () => {
      favicon.classList.add("hidden");
      fallback.classList.remove("hidden");
    }, { once: true });
    avatar.append(favicon, fallback);
    if (Number(session?.badgeCount || 0) > 0) {
      const deadline = document.createElement("span");
      deadline.className = "dockDeadline";
      deadline.textContent = String(session.badgeCount);
      deadline.title = `${session.badgeCount} ${session.badgeLabel}`;
      avatar.append(deadline);
    }
    const name = document.createElement("span");
    name.className = "dockName";
    name.textContent = profile.name;
    const platform = document.createElement("span");
    platform.className = "dockPlatform";
    platform.textContent = platformLabel(profile.platform);
    button.append(avatar, name, platform);
    button.addEventListener("dragstart", (event) => {
      state.dockDragActive = true;
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", profile.id);
      button.classList.add("dragging");
    });
    button.addEventListener("dragover", (event) => {
      event.preventDefault();
      button.classList.add("dropTarget");
    });
    button.addEventListener("dragleave", () => button.classList.remove("dropTarget"));
    button.addEventListener("drop", async (event) => {
      event.preventDefault();
      const draggedId = event.dataTransfer.getData("text/plain");
      const ids = profiles.map((item) => item.id).filter((id) => id !== draggedId);
      ids.splice(Math.max(0, ids.indexOf(profile.id)), 0, draggedId);
      try {
        await send({ type: "REORDER_ACCOUNT_PROFILES", profileIds: ids });
        await loadCockpit();
      } catch (error) {
        setStatus(elements.cockpitStatus, error.message, "error");
      }
    });
    button.addEventListener("dragend", () => {
      elements.sessionDock.querySelectorAll(".dragging, .dropTarget").forEach((node) => node.classList.remove("dragging", "dropTarget"));
      setTimeout(() => { state.dockDragActive = false; }, 0);
    });
    button.addEventListener("click", () => {
      if (state.dockDragActive) return;
      send({ type: "OPEN_ACCOUNT_PROFILE", profileId: profile.id })
        .catch((error) => setStatus(elements.cockpitStatus, error.message, "error"));
    });
    return button;
  }));
}

async function loadCockpit({ scan = false } = {}) {
  if (!state.connected) return;
  if (scan) {
    elements.scanSessionsButton.disabled = true;
    setStatus(elements.cockpitStatus, "Starting full account scan…");
  }
  try {
    const scanResult = scan ? await send({ type: "SCAN_ALL_SESSIONS" }) : null;
    const [cockpit, containers, earnings] = await Promise.all([
      send({ type: "GET_ACCOUNT_COCKPIT" }),
      send({ type: "LIST_CONTAINERS" }),
      send({ type: "LIST_REVIEW_EARNINGS" }).catch(() => null),
    ]);
    state.cockpit = cockpit;
    state.containers = Array.isArray(containers) ? containers : [];
    state.reviewEarnings = earnings;
    renderCockpit();
    renderContext();
    if (state.feedbackTemplates.length) activateFeedbackTemplateForContext({ force: true });
    if (scan) {
      const snapshot = scanResult?.snapshot;
      setStatus(elements.cockpitStatus, `${snapshot?.totals?.readable || 0}/${snapshot?.results?.length || 0} accounts scanned · ${snapshot?.totals?.open || 0} open · ${snapshot?.totals?.dueWithin24 || 0} due soon.`, "success");
      const settings = await send({ type: "GET_SUBMITHUB_AD_SETTINGS" });
      state.adSettings = { autoSync: false, mappings: {}, ...(settings || {}) };
      if (state.adSettings.autoSync && snapshot?.submitHubAds?.campaigns?.length) {
        await syncSubmitHubAds(snapshot);
      }
    }
  } catch (error) {
    setStatus(elements.cockpitStatus, error.message, "error");
  } finally {
    if (scan) elements.scanSessionsButton.disabled = false;
  }
}

function expiryDaysRemaining(item) {
  if (!item?.expiry_weeks || !item?.added_at) return null;
  const added = Date.parse(item.added_at);
  if (!Number.isFinite(added)) return null;
  return Math.ceil((added + Number(item.expiry_weeks) * 7 * 86400000 - Date.now()) / 86400000);
}

function renderManagerStats() {
  const items = state.managerItems;
  const locked = items.filter((item) => item.is_locked).length;
  const expiringSoon = items.filter((item) => {
    const days = expiryDaysRemaining(item);
    return days !== null && days <= 7;
  }).length;
  const stats = [
    ["Tracks", items.length],
    ["Locked", locked],
    ["≤ 7 days", expiringSoon],
  ];
  elements.managerStats.replaceChildren(...stats.map(([label, value]) => {
    const node = document.createElement("span");
    const strong = document.createElement("strong");
    strong.textContent = String(value);
    node.append(strong, document.createTextNode(label));
    return node;
  }));
}

function actionButton(label, title, onClick, className = "") {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.title = title;
  button.disabled = state.managerBusy;
  if (className) button.className = className;
  button.addEventListener("click", onClick);
  return button;
}

function renderManagerTracks() {
  const query = elements.trackFilterInput.value.trim().toLowerCase();
  const filtered = state.managerItems.filter((item) => {
    const haystack = `${item.track_name || ""} ${itemArtistNames(item).join(" ")}`.toLowerCase();
    return !query || haystack.includes(query);
  }).slice(0, 60);

  if (!state.managerPlaylistId) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "Choose a playlist to manage its tracks.";
    elements.managerTrackList.replaceChildren(empty);
    return;
  }
  if (!filtered.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = query ? "No matching tracks." : "No tracks loaded yet.";
    elements.managerTrackList.replaceChildren(empty);
    return;
  }

  elements.managerTrackList.replaceChildren(...filtered.map((item) => {
    const row = document.createElement("article");
    row.className = "managerTrack";
    const position = document.createElement("span");
    position.className = "trackPosition";
    position.textContent = String(Number(item.position || 0) + 1);
    const main = document.createElement("div");
    main.className = "managerTrackMain";
    const title = document.createElement("div");
    title.className = "managerTrackTitle";
    title.textContent = item.track_name || "Unknown track";
    const artist = document.createElement("div");
    artist.className = "managerTrackArtist";
    artist.textContent = itemArtistNames(item).join(", ");
    const meta = document.createElement("div");
    meta.className = "trackMeta";
    if (item.is_locked) {
      const badge = document.createElement("span");
      badge.className = "activeMeta";
      badge.textContent = "Locked";
      meta.append(badge);
    }
    if (item.expiry_weeks) {
      const badge = document.createElement("span");
      const days = expiryDaysRemaining(item);
      badge.className = days !== null && days <= 7 ? "activeMeta" : "";
      badge.textContent = days === null ? `${item.expiry_weeks}w expiry` : `${Math.max(0, days)}d left`;
      meta.append(badge);
    }
    if (item.age_label) {
      const badge = document.createElement("span");
      badge.textContent = `Age ${item.age_label}`;
      meta.append(badge);
    }
    const actions = document.createElement("div");
    actions.className = "trackActions";
    actions.append(
      actionButton("↑", "Move one position up", () => moveTrack(item, "up")),
      actionButton("↓", "Move one position down", () => moveTrack(item, "down")),
      actionButton(item.is_locked ? "Unlock" : "Lock", item.is_locked ? "Unlock position" : "Lock current position", () => toggleTrackLock(item)),
      actionButton("Expiry", "Set song-specific expiry", () => setTrackExpiry(item)),
      actionButton("×", "Remove from Spotify playlist", () => removeTrack(item), "dangerButton"),
    );
    main.append(title, artist, meta, actions);
    row.append(position, main);
    return row;
  }));
}

function renderManager() {
  const detail = state.managerDetail;
  const hasPlaylist = !!state.managerPlaylistId;
  elements.playlistSettings.classList.toggle("hidden", !hasPlaylist);
  elements.autoExpiryInput.checked = !!detail?.auto_remove_enabled;
  elements.autoExpiryWeeksInput.value = detail?.auto_remove_weeks || "";
  elements.autoExpiryWeeksInput.disabled = !elements.autoExpiryInput.checked || state.managerBusy;
  elements.saveSettingsButton.disabled = !hasPlaylist || state.managerBusy;
  elements.backupButton.disabled = !hasPlaylist || state.managerBusy;
  elements.reloadPlaylistButton.disabled = !hasPlaylist || state.managerBusy;
  renderManagerStats();
  renderManagerTracks();
}

async function loadManagerPlaylist(playlistId, { quiet = false } = {}) {
  state.managerPlaylistId = playlistId || "";
  state.managerDetail = null;
  state.managerItems = [];
  state.managerMeta = null;
  if (!playlistId) {
    renderManager();
    return;
  }
  if (!quiet) setStatus(elements.managerStatus, "Loading playlist…");
  try {
    const [detail, payload] = await Promise.all([
      send({ type: "GET_PLAYLIST_DETAIL", playlistId }),
      send({ type: "LIST_PLAYLIST_ITEMS", playlistId }),
    ]);
    if (state.managerPlaylistId !== playlistId) return;
    state.managerDetail = detail || null;
    state.managerItems = Array.isArray(payload) ? payload : payload?.items || [];
    state.managerMeta = Array.isArray(payload) ? null : payload?.meta || null;
    setStatus(elements.managerStatus, state.managerMeta?.partial ? "Playlist sync is incomplete; reload shortly." : "");
  } catch (error) {
    setStatus(elements.managerStatus, error.message, "error");
  } finally {
    renderManager();
  }
}

async function runManagerAction(label, action) {
  if (state.managerBusy) return;
  state.managerBusy = true;
  setStatus(elements.managerStatus, `${label}…`);
  renderManager();
  try {
    await action();
    await loadManagerPlaylist(state.managerPlaylistId, { quiet: true });
    setStatus(elements.managerStatus, `${label} complete.`, "success");
  } catch (error) {
    setStatus(elements.managerStatus, error.message, "error");
  } finally {
    state.managerBusy = false;
    renderManager();
  }
}

async function moveTrack(item, direction) {
  await runManagerAction("Moving track", () => send({
    type: "MOVE_PLAYLIST_TRACK",
    input: {
      playlist_id: state.managerPlaylistId,
      track_id: item.track_id,
      from_position: item.position,
      direction,
    },
  }));
}

async function toggleTrackLock(item) {
  await runManagerAction(item.is_locked ? "Unlocking track" : "Locking track", () => send({
    type: "SET_PLAYLIST_TRACK_LOCK",
    input: {
      playlist_id: state.managerPlaylistId,
      track_id: item.track_id,
      position: Number(item.position || 0) + 1,
      lock: !item.is_locked,
      expiry_weeks: item.expiry_weeks,
    },
  }));
}

async function setTrackExpiry(item) {
  const value = window.prompt("Song expiry in weeks. Leave empty to clear.", item.expiry_weeks || "");
  if (value === null) return;
  const trimmed = value.trim();
  const weeks = trimmed === "" ? null : Number(trimmed);
  if (weeks !== null && (!Number.isInteger(weeks) || weeks < 1 || weeks > 104)) {
    setStatus(elements.managerStatus, "Expiry must be an integer from 1 to 104 weeks.", "error");
    return;
  }
  await runManagerAction("Updating expiry", () => send({
    type: "SET_PLAYLIST_TRACK_LOCK",
    input: {
      playlist_id: state.managerPlaylistId,
      track_id: item.track_id,
      position: Number(item.position || 0) + 1,
      lock: !!item.is_locked,
      expiry_weeks: weeks,
    },
  }));
}

async function removeTrack(item) {
  if (!window.confirm(`Remove “${item.track_name || "this track"}” from the Spotify playlist?`)) return;
  await runManagerAction("Removing track", () => send({
    type: "REMOVE_PLAYLIST_TRACK",
    input: {
      playlist_id: state.managerPlaylistId,
      track_id: item.track_id,
      position0: item.position,
    },
  }));
}

function contextKey(context) {
  return `${context?.platform || ""}:${context?.cookieStoreId || ""}:${context?.platformSubmissionId || context?.spotifyTrackId || ""}`;
}

function reviewRow(label, value) {
  const row = document.createElement("div");
  row.className = "reviewRow";
  const key = document.createElement("span");
  key.textContent = label;
  const content = document.createElement("strong");
  content.textContent = String(value || "—");
  row.append(key, content);
  return row;
}

function closePlacementReview() {
  state.placementReviewSnapshot = null;
  elements.trackedPlacementFields.classList.add("hidden");
  if (elements.placementReviewDialog.open) elements.placementReviewDialog.close();
}

function openPlacementReview() {
  const context = state.context;
  const playlist = state.playlists.find((item) => item.id === elements.playlistSelect.value);
  if (!context?.spotifyTrackId || !playlist) return;
  const snapshot = {
    contextKey: contextKey(context),
    context: {
      platform: context.platform,
      cookieStoreId: context.cookieStoreId,
      platformSubmissionId: context.platformSubmissionId,
      trackTitle: context.trackTitle,
      artistNames: textList(context.artistNames),
      spotifyTrackUrl: context.spotifyTrackUrl,
      spotifyTrackId: context.spotifyTrackId,
    },
    playlistId: playlist.id,
    playlistName: playlist.name,
    position: elements.positionInput.value,
    expiryWeeks: elements.expiryInput.value,
    lock: elements.lockInput.checked,
    adapterStatus: context.adapterHealth?.status || "legacy",
    adapterWarnings: context.adapterHealth?.warnings || [],
  };
  state.placementReviewSnapshot = snapshot;
  elements.trackedPlacementFields.classList.add("hidden");
  elements.placementReviewRows.replaceChildren(
    reviewRow("Platform", platformLabel(snapshot.context.platform)),
    reviewRow("Track", snapshot.context.trackTitle || snapshot.context.spotifyTrackId),
    reviewRow("Artist", snapshot.context.artistNames.join(", ")),
    reviewRow("Playlist", snapshot.playlistName),
    reviewRow("Position", snapshot.position || "Append"),
    reviewRow("Expiry", snapshot.expiryWeeks ? `${snapshot.expiryWeeks} weeks` : "Playlist default"),
    reviewRow("Lock", snapshot.lock ? "Yes" : "No"),
    reviewRow("Adapter", snapshot.adapterStatus),
  );
  const hasWarning = snapshot.adapterStatus !== "healthy" || snapshot.adapterWarnings.length;
  elements.placementReviewWarning.classList.toggle("hidden", !hasWarning);
  elements.placementReviewWarning.textContent = hasWarning
    ? `Adapter check: ${snapshot.adapterWarnings.map(warningLabel).join("; ") || snapshot.adapterStatus}. Verify the track before applying.`
    : "";
  elements.placementReviewAcknowledgeRow.classList.toggle("hidden", !hasWarning);
  elements.placementReviewAcknowledgeInput.checked = false;
  elements.confirmPlacementButton.disabled = hasWarning;
  if (!elements.placementReviewDialog.open) elements.placementReviewDialog.showModal();
}

function normalizedPlaylistLabel(value) {
  return String(value || "").toLocaleLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

async function openTrackedAcceptancePlacement(track) {
  const platform = String(track?.platform || "").toLowerCase();
  if (platform !== "unhurd" || !state.connected) return;
  if (!state.playlists.length) await loadPlaylists({ loadManager: false });
  const platformNames = textList(track.platform_playlists || track.platformPlaylists);
  const wanted = platformNames.map(normalizedPlaylistLabel).filter(Boolean);
  const playlist = state.playlists.find((item) => item.id === track.playlist_id) || state.playlists.find((item) => {
    const candidate = normalizedPlaylistLabel(item.name);
    return wanted.some((name) => candidate === name || candidate.includes(name) || name.includes(candidate));
  }) || null;
  elements.trackedPlaylistSelect.replaceChildren(...playlistOptions(state.playlists, "Choose the PlaylistPilot playlist"));
  elements.trackedPlaylistSelect.value = playlist?.id || "";
  elements.trackedExpiryInput.value = "8";
  elements.trackedPositionInput.value = "10";
  elements.trackedPlacementFields.classList.remove("hidden");
  state.placementReviewSnapshot = {
    trackedAcceptance: true,
    context: {
      platform,
      platformSubmissionId: track.platform_submission_id || track.platformSubmissionId,
      trackTitle: track.track_title || track.trackTitle,
      artistNames: textList(track.artist_names || track.artistNames),
      spotifyTrackUrl: track.spotify_track_url || track.spotifyTrackUrl,
      spotifyTrackId: track.spotify_track_id || track.spotifyTrackId,
    },
    playlistId: playlist?.id || "",
    playlistName: playlist?.name || platformNames[0] || "Not matched yet",
    position: "10",
    expiryWeeks: "8",
    lock: false,
  };
  elements.placementReviewRows.replaceChildren(
    reviewRow("Platform", "Unhurd"),
    reviewRow("Track", state.placementReviewSnapshot.context.trackTitle || state.placementReviewSnapshot.context.spotifyTrackId),
    reviewRow("Artist", state.placementReviewSnapshot.context.artistNames.join(", ")),
    reviewRow("Suggested", platformNames[0] || "No playlist detected"),
  );
  elements.placementReviewWarning.classList.add("hidden");
  elements.placementReviewAcknowledgeRow.classList.add("hidden");
  elements.confirmPlacementButton.disabled = !playlist;
  elements.confirmPlacementButton.textContent = "Add to playlist";
  if (!elements.placementReviewDialog.open) elements.placementReviewDialog.showModal();
}

async function placeTrack(snapshot = state.placementReviewSnapshot) {
  if (!snapshot) return;
  if (!snapshot.trackedAcceptance && contextKey(state.context) !== snapshot.contextKey) {
    elements.placementReviewWarning.classList.remove("hidden");
    elements.placementReviewWarning.textContent = "The active submission changed. Close this review and prepare the placement again.";
    elements.confirmPlacementButton.disabled = true;
    return;
  }
  if (snapshot.trackedAcceptance) {
    const playlist = state.playlists.find((item) => item.id === elements.trackedPlaylistSelect.value);
    const expiryWeeks = Number(elements.trackedExpiryInput.value);
    const position = Number(elements.trackedPositionInput.value);
    if (!playlist || !Number.isInteger(expiryWeeks) || expiryWeeks < 1 || expiryWeeks > 104 ||
        !Number.isInteger(position) || position < 1 || position > 10000) {
      elements.placementReviewWarning.classList.remove("hidden");
      elements.placementReviewWarning.textContent = "Choose a playlist, an expiry between 1 and 104 weeks, and a valid playlist slot.";
      return;
    }
    snapshot = { ...snapshot, playlistId: playlist.id, playlistName: playlist.name, expiryWeeks: String(expiryWeeks), position: String(position) };
  }
  const context = snapshot.context;
  elements.placementReviewDialog.close();
  elements.placementButton.disabled = true;
  setStatus(elements.placementStatus, "Syncing Spotify and PlaylistPilot…");
  try {
    const result = await send({
      type: "CREATE_PLACEMENT",
      input: {
        playlist_id: snapshot.playlistId,
        spotify_track_url: context.spotifyTrackUrl,
        spotify_track_id: context.spotifyTrackId,
        position: snapshot.position,
        expiry_weeks: snapshot.expiryWeeks,
        lock: snapshot.lock,
        source_platform: context.platform,
        source_submission_id: context.platformSubmissionId,
      },
    });
    setStatus(elements.placementStatus, result.action === "added" ? "Track added successfully." : "Existing track updated.", "success");
    if (state.managerPlaylistId === snapshot.playlistId) {
      await loadManagerPlaylist(state.managerPlaylistId, { quiet: true });
    }
  } catch (error) {
    setStatus(elements.placementStatus, error.message, "error");
  } finally {
    state.placementReviewSnapshot = null;
    elements.trackedPlacementFields.classList.add("hidden");
    elements.confirmPlacementButton.textContent = "Apply playlist change";
    updatePlacementButton();
  }
}

function styleSamples(text = elements.styleLibraryInput.value) {
  return String(text || "")
    .split(/\n\s*\n+/)
    .map((sample) => sample.replace(/\s+/g, " ").trim())
    .filter((sample) => sample.length >= 8)
    .slice(0, 250);
}

function renderStyleCount() {
  const count = styleSamples().length;
  const template = activeFeedbackTemplate();
  elements.styleCountBadge.textContent = template ? template.name : `${count} sample${count === 1 ? "" : "s"}`;
}

function newFeedbackTemplate(overrides = {}) {
  return {
    id: globalThis.crypto?.randomUUID?.() || `template-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    name: "My voice",
    scope: "global",
    language: "auto",
    tone: "matched",
    length: "matched",
    imperfections: "matched",
    grammar: "matched",
    customRules: "",
    references: "",
    ...overrides,
  };
}

function activeFeedbackTemplate() {
  return state.feedbackTemplates.find((template) => template.id === state.activeFeedbackTemplateId) || state.feedbackTemplates[0] || null;
}

function feedbackContextKey() {
  const profile = currentWorkflowProfile();
  return profile ? `account:${profile.id}` : state.context?.platform ? `platform:${state.context.platform}` : "global";
}

function fillFeedbackScopes(selected = "global") {
  const scopes = [
    ["global", "All platforms & accounts"],
    ["platform:groover", "Groover · all accounts"],
    ["platform:submithub", "SubmitHub · all accounts"],
    ["platform:playlistpush", "PlaylistPush · all accounts"],
    ["platform:unhurd", "Unhurd · all accounts"],
    ...(state.cockpit?.profiles || []).map((profile) => [`account:${profile.id}`, `${platformLabel(profile.platform)} · ${profile.name}`]),
  ];
  elements.feedbackTemplateScopeSelect.replaceChildren(...scopes.map(([value, label]) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    return option;
  }));
  elements.feedbackTemplateScopeSelect.value = scopes.some(([value]) => value === selected) ? selected : "global";
}

function renderFeedbackTemplate() {
  const template = activeFeedbackTemplate();
  elements.feedbackTemplateSelect.replaceChildren(...state.feedbackTemplates.map((item) => {
    const option = document.createElement("option");
    option.value = item.id;
    option.textContent = item.name;
    return option;
  }));
  if (!template) return;
  elements.feedbackTemplateSelect.value = template.id;
  elements.feedbackTemplateNameInput.value = template.name;
  fillFeedbackScopes(template.scope);
  elements.feedbackLanguageSelect.value = template.language || "auto";
  elements.feedbackToneSelect.value = template.tone || "matched";
  elements.feedbackLengthSelect.value = template.length || "matched";
  elements.feedbackImperfectionsSelect.value = template.imperfections || "matched";
  elements.feedbackGrammarSelect.value = template.grammar || "matched";
  elements.feedbackRulesInput.value = template.customRules || "";
  elements.styleLibraryInput.value = template.references || "";
  elements.deleteFeedbackTemplateButton.disabled = state.feedbackTemplates.length <= 1;
  renderStyleCount();
}

function activateFeedbackTemplateForContext({ force = false } = {}) {
  const contextKey = feedbackContextKey();
  if (!force && state.feedbackTemplateContextKey === contextKey) return;
  state.feedbackTemplateContextKey = contextKey;
  const platformKey = state.context?.platform ? `platform:${state.context.platform}` : "";
  const match = state.feedbackTemplates.find((template) => template.scope === contextKey) ||
    state.feedbackTemplates.find((template) => template.scope === platformKey) ||
    state.feedbackTemplates.find((template) => template.scope === "global") || state.feedbackTemplates[0];
  if (match) state.activeFeedbackTemplateId = match.id;
  renderFeedbackTemplate();
}

async function loadStyleLibrary() {
  const stored = await browser.storage.local.get([STYLE_LIBRARY_KEY, FEEDBACK_TEMPLATES_KEY]);
  const saved = Array.isArray(stored[FEEDBACK_TEMPLATES_KEY]) ? stored[FEEDBACK_TEMPLATES_KEY] : [];
  let cloud = [];
  if (state.connected) {
    const result = await send({ type: "LIST_FEEDBACK_PROFILES" }).catch(() => null);
    cloud = Array.isArray(result?.profiles) ? result.profiles : [];
    if (!cloud.length && saved.length) {
      const migrated = await send({ type: "SYNC_FEEDBACK_PROFILES", profiles: saved }).catch(() => null);
      cloud = Array.isArray(migrated?.profiles) ? migrated.profiles : [];
    }
  }
  state.feedbackTemplates = cloud.length ? cloud : saved.length ? saved : [newFeedbackTemplate({ references: stored[STYLE_LIBRARY_KEY] || "" })];
  await browser.storage.local.set({ [FEEDBACK_TEMPLATES_KEY]: state.feedbackTemplates });
  activateFeedbackTemplateForContext({ force: true });
}

async function saveStyleLibrary() {
  const template = activeFeedbackTemplate();
  if (!template) return;
  Object.assign(template, {
    name: elements.feedbackTemplateNameInput.value.trim() || "My voice",
    scope: elements.feedbackTemplateScopeSelect.value || "global",
    language: elements.feedbackLanguageSelect.value,
    tone: elements.feedbackToneSelect.value,
    length: elements.feedbackLengthSelect.value,
    imperfections: elements.feedbackImperfectionsSelect.value,
    grammar: elements.feedbackGrammarSelect.value,
    customRules: elements.feedbackRulesInput.value.trim(),
    references: elements.styleLibraryInput.value.trim(),
    updatedAt: new Date().toISOString(),
  });
  const result = await send({ type: "SYNC_FEEDBACK_PROFILES", profiles: state.feedbackTemplates });
  if (Array.isArray(result?.profiles) && result.profiles.length) state.feedbackTemplates = result.profiles;
  await browser.storage.local.set({ [FEEDBACK_TEMPLATES_KEY]: state.feedbackTemplates });
  state.feedbackTemplateContextKey = "";
  activateFeedbackTemplateForContext({ force: true });
  setStatus(elements.feedbackStatus, `“${template.name}” saved and assigned.`, "success");
}

function feedbackReferences() {
  const samples = styleSamples();
  if (samples.length <= 24) return samples;
  const step = samples.length / 24;
  return Array.from({ length: 24 }, (_, index) => samples[Math.floor(index * step)]);
}

function feedbackSettings() {
  const template = activeFeedbackTemplate() || newFeedbackTemplate();
  return {
    templateName: template.name,
    language: template.language,
    tone: template.tone,
    length: template.length,
    imperfections: template.imperfections,
    grammar: template.grammar,
    customRules: template.customRules,
  };
}

function setFeedbackMode(mode) {
  state.feedbackMode = mode;
  elements.acceptModeButton.classList.toggle("active", mode === "accept");
  elements.declineModeButton.classList.toggle("active", mode === "decline");
  elements.feedbackMismatchInput.placeholder = mode === "accept"
    ? "Optional: mention any caveat without undermining the acceptance"
    : "Playlist fit, genre, pacing, mix, personal taste…";
}

async function generateFeedback() {
  const likes = elements.feedbackLikesInput.value.trim();
  const mismatch = elements.feedbackMismatchInput.value.trim();
  if (!likes && !mismatch) return;
  elements.generateFeedbackButton.disabled = true;
  setStatus(elements.feedbackStatus, "Learning your voice and drafting…");
  try {
    const detectedPlaylists = textList(state.context?.selectedPlatformPlaylists);
    const placementWeeks = Number(state.context?.placementWeeks) ||
      (state.context?.platform === "groover" ? 4 : state.context?.platform === "playlistpush" ? 8 : null);
    const result = await send({
      type: "GENERATE_FEEDBACK",
      input: {
        mode: state.feedbackMode,
        likes,
        mismatch,
        references: feedbackReferences(),
        settings: feedbackSettings(),
        track: {
          title: state.context?.trackTitle || "",
          artists: textList(state.context?.artistNames),
          platform: state.context?.platform || "",
        },
        placement: state.feedbackMode === "accept" ? {
          playlists: detectedPlaylists.length ? detectedPlaylists : ["[PLAYLIST NAME]"],
          weeks: placementWeeks,
        } : null,
      },
    });
    elements.feedbackOutput.value = result.feedback || "";
    state.feedbackDraftContext = result.feedback ? {
      platform: state.context?.platform || "",
      submissionId: state.context?.platformSubmissionId || "",
      mode: state.feedbackMode,
    } : null;
    elements.feedbackOutputLabel.classList.toggle("hidden", !result.feedback);
    elements.feedbackOutputActions.classList.toggle("hidden", !result.feedback);
    setStatus(elements.feedbackStatus, result.feedback ? "Draft ready — edit anything before sending." : "No draft returned.", result.feedback ? "success" : "error");
  } catch (error) {
    setStatus(elements.feedbackStatus, error.message, "error");
  } finally {
    updateFeedbackButton();
  }
}

async function copyFeedback() {
  const text = elements.feedbackOutput.value.trim();
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    elements.feedbackOutput.select();
    document.execCommand("copy");
  }
  setStatus(elements.feedbackStatus, "Feedback copied.", "success");
}

async function insertFeedback() {
  const text = elements.feedbackOutput.value.trim();
  if (!text) return;
  elements.insertFeedbackButton.disabled = true;
  setStatus(elements.feedbackStatus, "Preparing the visible platform form…");
  try {
    const result = await send({
      type: "PREFILL_FEEDBACK_DRAFT",
      text,
      mode: state.feedbackDraftContext?.mode || state.feedbackMode,
      expectedPlatform: state.feedbackDraftContext?.platform || "",
      expectedSubmissionId: state.feedbackDraftContext?.submissionId || "",
    });
    setStatus(elements.feedbackStatus, `Draft inserted into ${platformLabel(result.platform)}. Review it there before submitting.`, "success");
  } catch (error) {
    setStatus(elements.feedbackStatus, error.message, "error");
  } finally {
    elements.insertFeedbackButton.disabled = false;
  }
}

async function refresh({ scan = false } = {}) {
  setStatus(elements.placementStatus);
  const [auth, context, focusedTrack] = await Promise.all([
    send({ type: "GET_AUTH_STATE" }),
    send({ type: "GET_ACTIVE_CONTEXT" }).catch(() => null),
    send({ type: "GET_FOCUSED_TRACK" }).catch(() => null),
  ]);
  renderAuth(auth);
  state.context = context?.platform ? context : null;
  renderContext();
  renderFocusedTrack(focusedTrack);
  if (state.connected) {
    const tasks = [loadCockpit({ scan })];
    if (state.activeView === "focus") {
      tasks.push(loadStyleLibrary());
    } else if (state.activeView === "queue") {
      if (!state.playlists.length) tasks.push(loadPlaylists({ loadManager: false }));
    } else if (state.activeView === "tools") {
      tasks.push(loadAcceptedTracks());
      if (!state.playlists.length) tasks.push(loadPlaylists({ loadManager: false }));
    } else if (state.activeView === "ads") {
      tasks.push(loadAdsPanel());
    }
    await Promise.all(tasks);
  }
}

elements.connectButton.addEventListener("click", () => send({ type: "BEGIN_AUTH_CONNECT" }).catch((error) => setStatus(elements.placementStatus, error.message, "error")));
elements.moreButton.addEventListener("click", (event) => {
  event.stopPropagation();
  const opening = elements.accountMenu.classList.contains("hidden");
  elements.accountMenu.classList.toggle("hidden", !opening);
  elements.moreButton.setAttribute("aria-expanded", String(opening));
});
document.addEventListener("click", (event) => {
  if (elements.accountMenu.contains(event.target) || event.target === elements.moreButton) return;
  elements.accountMenu.classList.add("hidden");
  elements.moreButton.setAttribute("aria-expanded", "false");
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    elements.accountMenu.classList.add("hidden");
    elements.moreButton.setAttribute("aria-expanded", "false");
  }
});
elements.signOutButton.addEventListener("click", async () => {
  await send({ type: "SIGN_OUT" });
  state.playlists = [];
  state.managerPlaylistId = "";
  state.managerItems = [];
  state.cockpit = null;
  renderAuth({ connected: false });
  renderContext();
});
elements.refreshButton.addEventListener("click", () => refresh({ scan: true }).catch((error) => setStatus(elements.managerStatus, error.message, "error")));
elements.focusNavButton.addEventListener("click", () => setActiveView("focus").catch((error) => setStatus(elements.placementStatus, error.message, "error")));
elements.queueNavButton.addEventListener("click", () => setActiveView("queue").catch((error) => setStatus(elements.cockpitStatus, error.message, "error")));
elements.toolsNavButton.addEventListener("click", () => setActiveView("tools").catch((error) => setStatus(elements.managerStatus, error.message, "error")));
elements.adsNavButton.addEventListener("click", () => setActiveView("ads").catch((error) => setStatus(elements.adsStatus, error.message, "error")));
elements.adsAutoSyncInput.addEventListener("change", async () => {
  state.adSettings.autoSync = elements.adsAutoSyncInput.checked;
  await saveAdSettings().catch((error) => setStatus(elements.adsStatus, error.message, "error"));
});
elements.scanAdsButton.addEventListener("click", async () => {
  elements.scanAdsButton.disabled = true;
  setStatus(elements.adsStatus, "Scanning SubmitHub accounts and active campaigns…");
  try {
    const scanResult = await send({ type: "SCAN_SUBMITHUB_ADS_ONLY" });
    await loadAdsPanel();
    if (state.adSettings.autoSync && scanResult?.snapshot?.submitHubAds?.campaigns?.length) {
      await syncSubmitHubAds(scanResult.snapshot);
    }
    if (!state.adSettings.autoSync) setStatus(elements.adsStatus, "Ad scan complete. Review mappings or sync manually.", "success");
    else if (!scanResult?.snapshot?.submitHubAds?.campaigns?.length) setStatus(elements.adsStatus, "Ad scan complete. No active campaigns were found in the scanned sessions.", "success");
  } catch (error) {
    setStatus(elements.adsStatus, error.message, "error");
  } finally {
    elements.scanAdsButton.disabled = false;
  }
});
elements.syncAdsButton.addEventListener("click", async () => {
  elements.syncAdsButton.disabled = true;
  setStatus(elements.adsStatus, "Syncing mapped daily spend…");
  try { await syncSubmitHubAds(); }
  catch (error) { setStatus(elements.adsStatus, error.message, "error"); }
  finally { elements.syncAdsButton.disabled = false; }
});
elements.adapterQuickStatus.addEventListener("click", () => setActiveView("tools").catch((error) => setStatus(elements.adapterStatus, error.message, "error")));
elements.playlistSelect.addEventListener("change", updatePlacementButton);
elements.workflowApplyButton.addEventListener("click", () => applyCurrentWorkflow(true));
elements.placementButton.addEventListener("click", openPlacementReview);
elements.copyAdapterReportButton.addEventListener("click", copyAdapterReport);
elements.closePlacementReviewButton.addEventListener("click", closePlacementReview);
elements.cancelPlacementReviewButton.addEventListener("click", closePlacementReview);
elements.confirmPlacementButton.addEventListener("click", () => placeTrack());
elements.trackedPlaylistSelect.addEventListener("change", () => {
  if (state.placementReviewSnapshot?.trackedAcceptance) {
    elements.confirmPlacementButton.disabled = !elements.trackedPlaylistSelect.value;
  }
});
elements.placementReviewAcknowledgeInput.addEventListener("change", () => {
  elements.confirmPlacementButton.disabled = !elements.placementReviewAcknowledgeInput.checked;
});
elements.placementReviewDialog.addEventListener("close", () => {
  state.placementReviewSnapshot = null;
  elements.trackedPlacementFields.classList.add("hidden");
  elements.confirmPlacementButton.textContent = "Apply playlist change";
});
elements.managerPlaylistSelect.addEventListener("change", () => {
  const playlistId = elements.managerPlaylistSelect.value;
  state.managerPlaylistId = playlistId;
  loadManagerPlaylist(playlistId).catch((error) => setStatus(elements.managerStatus, error.message, "error"));
});
elements.trackFilterInput.addEventListener("input", renderManagerTracks);
elements.autoExpiryInput.addEventListener("change", () => {
  elements.autoExpiryWeeksInput.disabled = !elements.autoExpiryInput.checked;
});
elements.saveSettingsButton.addEventListener("click", async () => {
  const enabled = elements.autoExpiryInput.checked;
  const weeks = enabled ? Number(elements.autoExpiryWeeksInput.value) : null;
  if (enabled && (!Number.isInteger(weeks) || weeks < 1 || weeks > 104)) {
    setStatus(elements.managerStatus, "Default expiry must be 1–104 weeks.", "error");
    return;
  }
  await runManagerAction("Saving playlist rules", () => send({
    type: "SAVE_PLAYLIST_SETTINGS",
    input: { playlist_id: state.managerPlaylistId, auto_remove_enabled: enabled, auto_remove_weeks: weeks },
  }));
});
elements.backupButton.addEventListener("click", () => runManagerAction("Creating backup", () => send({
  type: "CREATE_PLAYLIST_BACKUP",
  input: { playlist_id: state.managerPlaylistId },
})));
elements.reloadPlaylistButton.addEventListener("click", () => loadManagerPlaylist(state.managerPlaylistId));
elements.openManagerButton.addEventListener("click", () => browser.tabs.create({
  url: `https://playlist-pilot.com/app${state.managerPlaylistId ? `?playlist_id=${encodeURIComponent(state.managerPlaylistId)}` : ""}`,
}));
elements.acceptModeButton.addEventListener("click", () => setFeedbackMode("accept"));
elements.declineModeButton.addEventListener("click", () => setFeedbackMode("decline"));
elements.previousSubmissionButton.addEventListener("click", async () => {
  try {
    renderFocusedTrack(await send({ type: "NAVIGATE_FOCUSED_TRACK", direction: "previous" }));
  } catch (error) {
    renderSpotifyPlayerState(error.message);
  }
});
elements.nextSubmissionButton.addEventListener("click", async () => {
  try {
    renderFocusedTrack(await send({ type: "NAVIGATE_FOCUSED_TRACK", direction: "next" }));
  } catch (error) {
    renderSpotifyPlayerState(error.message);
  }
});

const CURATOR_PERMISSION_ORIGINS = [
  "https://*.submithub.com/*",
  "https://groover.co/*",
  "https://app.playlistpush.com/*",
  "https://curator.unhurdmusic.com/*",
];

function requestCuratorPermissionsFromGesture(errorMessage) {
  return browser.permissions.request({ origins: CURATOR_PERMISSION_ORIGINS }).then((granted) => {
    if (!granted) throw new Error(errorMessage);
    return true;
  });
}

elements.spotifyActivateButton.addEventListener("click", async () => {
  const permissionRequest = requestCuratorPermissionsFromGesture(
    "Allow PlaylistPilot access to the curator platforms to read the current track.",
  );
  elements.spotifyActivateButton.disabled = true;
  try {
    await permissionRequest;
    renderFocusedTrack(await send({ type: "FOCUS_CURRENT_PAGE_TRACK" }));
  } catch (error) {
    renderSpotifyPlayerState(error.message);
  } finally {
    elements.spotifyActivateButton.disabled = false;
  }
});
elements.playPauseButton.addEventListener("click", () => {
  if (!state.focusedTrack?.spotifyTrackId) return;
  if (!state.spotifyPlayerPlaying) {
    window.clearTimeout(state.spotifyPlayAttemptTimer);
    state.spotifyPlayAttemptTimer = window.setTimeout(() => {
      if (!state.spotifyPlayerPlaying) {
        renderSpotifyPlayerState("No playable Spotify preview available? Open the full track with ↗.");
      }
    }, 2200);
  }
  sendSpotifyPlayer(state.spotifyPlayerPlaying ? "pause" : "play", state.focusedTrack.spotifyTrackId);
});
elements.openSpotifyButton.addEventListener("click", () => {
  if (!state.focusedTrack?.spotifyTrackId) return;
  browser.tabs.create({ url: `https://open.spotify.com/track/${encodeURIComponent(state.focusedTrack.spotifyTrackId)}` });
});
elements.prepareAcceptButton.addEventListener("click", async () => {
  setFeedbackMode("accept");
  await runReviewAction({ type: "PREPARE_DECISION", mode: "accept" }, "Opening the platform accept fields…").catch(() => {});
  loadReviewState().catch(() => {});
});
elements.prepareDeclineButton.addEventListener("click", async () => {
  setFeedbackMode("decline");
  await runReviewAction({ type: "PREPARE_DECISION", mode: "decline" }, "Opening the platform decline fields…").catch(() => {});
  loadReviewState().catch(() => {});
});
elements.liveFeedbackInput.addEventListener("click", async () => {
  setStatus(elements.reviewStatus, "Opening the direct-typing portal on the platform page…");
  try {
    const result = await send({ type: "SHOW_DIRECT_TYPING_PORTAL", mode: state.feedbackMode });
    state.bridgeRemoteUpdate = true;
    elements.liveFeedbackInput.value = result.value || "";
    state.bridgeRemoteUpdate = false;
    elements.liveFeedbackInput.classList.add("typingActive");
    setReviewBridgeState(true);
    setStatus(elements.reviewStatus, "Portal opened on the page. Click its field once, then type normally.", "success");
  } catch (error) {
    elements.liveFeedbackInput.classList.remove("typingActive");
    setReviewBridgeState(false, error.message);
  }
});
elements.feedbackLikesInput.addEventListener("input", updateFeedbackButton);
elements.feedbackMismatchInput.addEventListener("input", updateFeedbackButton);
elements.generateFeedbackButton.addEventListener("click", generateFeedback);
elements.copyFeedbackButton.addEventListener("click", copyFeedback);
elements.insertFeedbackButton.addEventListener("click", insertFeedback);
elements.clearFeedbackButton.addEventListener("click", () => {
  elements.feedbackOutput.value = "";
  state.feedbackDraftContext = null;
  elements.feedbackOutputLabel.classList.add("hidden");
  elements.feedbackOutputActions.classList.add("hidden");
  setStatus(elements.feedbackStatus);
});
elements.styleLibraryInput.addEventListener("input", renderStyleCount);
elements.saveStyleLibraryButton.addEventListener("click", () => saveStyleLibrary().catch((error) => setStatus(elements.feedbackStatus, error.message, "error")));
elements.feedbackTemplateSelect.addEventListener("change", () => {
  state.activeFeedbackTemplateId = elements.feedbackTemplateSelect.value;
  renderFeedbackTemplate();
});
elements.newFeedbackTemplateButton.addEventListener("click", () => {
  const scope = feedbackContextKey();
  const template = newFeedbackTemplate({ name: `${platformLabel(state.context?.platform) || "New"} voice`, scope });
  state.feedbackTemplates.push(template);
  state.activeFeedbackTemplateId = template.id;
  renderFeedbackTemplate();
  elements.feedbackTemplateNameInput.focus();
});
elements.deleteFeedbackTemplateButton.addEventListener("click", async () => {
  const template = activeFeedbackTemplate();
  if (!template || state.feedbackTemplates.length <= 1 || !window.confirm(`Delete “${template.name}”?`)) return;
  await send({ type: "DELETE_FEEDBACK_PROFILE", profileId: template.id });
  state.feedbackTemplates = state.feedbackTemplates.filter((item) => item.id !== template.id);
  state.activeFeedbackTemplateId = state.feedbackTemplates[0].id;
  await browser.storage.local.set({ [FEEDBACK_TEMPLATES_KEY]: state.feedbackTemplates });
  activateFeedbackTemplateForContext({ force: true });
});
elements.scanSessionsButton.addEventListener("click", async () => {
  const permissionRequest = requestCuratorPermissionsFromGesture(
    "Allow PlaylistPilot access to the curator platforms before scanning their account pages.",
  );
  try {
    await permissionRequest;
    await loadCockpit({ scan: true });
  } catch (error) {
    setStatus(elements.cockpitStatus, error.message, "error");
  }
});
elements.reloadAcceptedTracksButton.addEventListener("click", () => loadAcceptedTracks());
elements.acceptedTracksFilter.addEventListener("change", () => {
  state.acceptedTracksFilter = elements.acceptedTracksFilter.value;
  renderAcceptedTracks();
});
browser.runtime.onMessage.addListener((message) => {
  if (message?.type === "FOCUSED_TRACK_UPDATED") renderFocusedTrack(message.focus);
  if (message?.type === "GROOVER_ACCEPTANCE_SAVED" || message?.type === "PLATFORM_ACCEPTANCE_SAVED") {
    loadAcceptedTracks();
    setStatus(elements.acceptedTracksStatus, `${platformLabel(message.platform || "groover")} acceptance captured.`, "success");
    if (String(message.platform || "").toLowerCase() === "unhurd") {
      openTrackedAcceptancePlacement(message.track).catch((error) => {
        setStatus(elements.acceptedTracksStatus, `Unhurd placement could not be prepared: ${error.message}`, "error");
      });
    }
    return;
  }
  if (message?.type === "REVIEW_EARNING_SAVED") {
    send({ type: "LIST_REVIEW_EARNINGS" }).then((earnings) => {
      state.reviewEarnings = earnings;
      renderEarningsSummary();
    }).catch(() => {});
  }
  if (message?.type === "SUBMITHUB_AD_SCAN_PROGRESS") {
    const progress = message.progress || {};
    if (progress.phase === "campaign") {
      setStatus(elements.adsStatus, `Reading campaign ${progress.current}/${progress.total}${progress.label ? ` · ${progress.label}` : ""}…`);
    } else if (progress.phase === "starting") {
      setStatus(elements.adsStatus, "Opening SubmitHub ads in the saved session…");
    }
    return;
  }
  if (message?.type !== "FULL_SCAN_PROGRESS") return;
  const progress = message.progress || {};
  if (progress.phase === "scanning") {
    setStatus(elements.cockpitStatus, `Scanning ${progress.current}/${progress.total}${progress.label ? ` · ${progress.label}` : ""}…`);
  }
});
elements.ensureSessionsButton.addEventListener("click", async () => {
  elements.ensureSessionsButton.disabled = true;
  setStatus(elements.cockpitStatus, "Loading all configured account sessions…");
  try {
    const result = await send({ type: "ENSURE_ACCOUNT_SESSIONS" });
    await loadCockpit({ scan: false });
    setStatus(elements.cockpitStatus, result.opened
      ? `${result.opened} session${result.opened === 1 ? "" : "s"} opened in the background.`
      : "All configured sessions are already ready.", "success");
  } catch (error) {
    setStatus(elements.cockpitStatus, error.message, "error");
  } finally {
    elements.ensureSessionsButton.disabled = false;
  }
});
elements.addAccountButton.addEventListener("click", () => openAccountForm());
elements.cancelAccountButton.addEventListener("click", closeAccountForm);
elements.accountPlatformSelect.addEventListener("change", () => {
  elements.accountExpiryInput.value = defaultExpiry(elements.accountPlatformSelect.value);
});
elements.accountForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  elements.saveAccountButton.disabled = true;
  setStatus(elements.cockpitStatus, "Saving account profile…");
  try {
    const profile = await send({
      type: "SAVE_ACCOUNT_PROFILE",
      input: {
        id: elements.accountIdInput.value || undefined,
        name: elements.accountNameInput.value,
        platform: elements.accountPlatformSelect.value,
        cookieStoreId: elements.accountContainerSelect.value,
        keepReady: elements.accountKeepReadyInput.checked,
        workflow: {
          playlistId: elements.accountPlaylistSelect.value,
          expiryWeeks: Number(elements.accountExpiryInput.value),
          position: elements.accountPositionInput.value ? Number(elements.accountPositionInput.value) : null,
          lock: elements.accountLockInput.checked,
          autoPrepare: elements.accountAutoPrepareInput.checked,
          trackingEnabled: elements.accountTrackingInput.checked,
        },
        earnings: {
          enabled: elements.accountEarningTrackingInput.checked,
          amount: Number(elements.accountEarningAmountInput.value || 0),
          currency: elements.accountEarningCurrencySelect.value,
        },
      },
    });
    closeAccountForm();
    await loadCockpit();
    setStatus(elements.cockpitStatus, `“${profile.name}” is ready.`, "success");
  } catch (error) {
    setStatus(elements.cockpitStatus, error.message, "error");
  } finally {
    elements.saveAccountButton.disabled = false;
  }
});

browser.runtime.onMessage.addListener((message) => {
  if (message?.type === "PLATFORM_CONTEXT_UPDATED") {
    state.context = message.context;
    renderContext();
    if (state.feedbackTemplates.length) activateFeedbackTemplateForContext();
  }
  if (message?.type === "AUTH_UPDATED" || message?.type === "ACTIVE_TAB_CHANGED") {
    refresh().catch(() => {});
  }
  if (message?.type === "COCKPIT_UPDATED" && state.connected) {
    clearTimeout(state.cockpitReloadTimer);
    state.cockpitReloadTimer = setTimeout(() => loadCockpit().catch(() => {}), 500);
  }
  if (message?.type === "LIVE_FEEDBACK_UPDATED") {
    state.bridgeRemoteUpdate = true;
    elements.liveFeedbackInput.value = message.value || "";
    state.bridgeRemoteUpdate = false;
    elements.liveFeedbackInput.classList.add("typingActive");
    setReviewBridgeState(true);
  }
});

setFeedbackMode("accept");
async function initialize() {
  const stored = await browser.storage.local.get(SIDEBAR_VIEW_KEY);
  await setActiveView(stored[SIDEBAR_VIEW_KEY] || "queue", { persist: false, load: false });
  await refresh();
}
initialize().catch((error) => setStatus(elements.managerStatus, error.message, "error"));
