(() => {
  const PLATFORM_HOSTS = {
    "www.submithub.com": "submithub",
    "submithub.com": "submithub",
    "groover.co": "groover",
    "app.playlistpush.com": "playlistpush",
    "curator.unhurdmusic.com": "unhurd",
  };
  const AdapterContract = globalThis.PlaylistPilotAdapterContract;
  const ADAPTER_VERSION = AdapterContract?.version || "legacy";
  let selectedPlaylistPushCard = null;
  let scanTimer = null;
  let bridgeWriteInProgress = false;
  let embeddedPlaying = false;
  let lastEditableSelection = null;
  let pendingGrooverAcceptance = null;
  let pendingPlatformAcceptance = null;
  let pendingGrooverReview = null;
  let pendingPlatformReview = null;
  let lastPublishedFingerprint = "";
  let lastPublishedAt = 0;
  let lastFocusedTrackId = "";
  let lastFocusedLocation = location.href;
  let activeRescueConfig = null;

  const text = (node) => String(node?.innerText || node?.textContent || "").trim();
  const lines = (node) => text(node).split(/\n+/).map((value) => value.trim()).filter(Boolean);
  const unique = (values) => [...new Set(values.filter(Boolean))];
  const spotifyTrackUrl = (root = document) =>
    root.querySelector('a[href*="open.spotify.com/track/"]')?.href ||
    root.querySelector('a[href^="spotify:track:"]')?.href ||
    "";
  const spotifyTrackId = (value) =>
    String(value || "").match(/(?:track[/:])([A-Za-z0-9]{22})/)?.[1] || "";
  const countdown = (value) =>
    String(value || "").match(/(?:expir(?:es|ing)?\s*)?(?:in\s*)?(?:about\s*)?(~?\d+\s*(?:days?|hours?|hrs?|h)(?:,\s*\d+\s*m)?)/i)?.[1] || "";
  const releaseDate = (value) =>
    String(value || "").match(/Release date:\s*([^\n]+)/i)?.[1]?.trim() || "";
  const deadlineLabels = (selector) => Array.from(document.querySelectorAll(selector))
    .map((node) => countdown(text(node)))
    .filter(Boolean);

  function selectedLabels(root, selector) {
    return Array.from(root.querySelectorAll(selector))
      .filter((input) => input.checked)
      .map((input) => text(input.closest("label") || input.parentElement))
      .filter(Boolean);
  }

  function playlistPushSelectedPlaylistNames(root = document) {
    const found = [];
    const add = (value) => {
      const clean = AdapterContract?.normalizePlaylistName(value) || "";
      if (clean && !found.includes(clean)) found.push(clean);
      return !!clean;
    };
    const selectedInputs = Array.from(root.querySelectorAll('input[type="checkbox"]:checked, input[type="radio"]:checked'));
    for (const input of selectedInputs) {
      const ownText = text(input.closest("label") || input.parentElement);
      if (/only feedback|won't offer|do not want|don't want|decline|reject/i.test(ownText)) continue;

      // PlaylistPush renders the authoritative playlist name as the title of
      // the cover sibling. The selected card's visible text only contains its
      // scheduling metadata ("When", "Position", "modify"). Read the title
      // first so that metadata can never be mistaken for the playlist name.
      const playlistPushCard = input.closest(".playlist-grid-item");
      const coverTitle = playlistPushCard
        ?.querySelector(":scope > .cover[title], :scope > [class*='cover'][title]")
        ?.getAttribute("title");
      if (add(coverTitle)) continue;

      let container = input.closest("label") || input.parentElement;
      let resolved = false;
      for (let depth = 0; container && depth < 6 && !resolved; depth += 1, container = container.parentElement) {
        const marker = `${container.className || ""} ${container.getAttribute?.("aria-label") || ""} ${text(container)}`;
        if (!/playlist|when\s*:|position\s*:|scheduled\s*:/i.test(marker)) continue;
        const preferred = Array.from(container.querySelectorAll('h1, h2, h3, h4, strong, [class*="playlist-name" i], [class*="playlist-title" i]'))
          .map(text);
        for (const candidate of [...preferred, ...lines(container)]) {
          if (add(candidate)) { resolved = true; break; }
        }
      }
    }
    return found.slice(0, 5);
  }

  function selectedPlaylistNames(platform, root = document) {
    const names = [];
    const add = (value) => {
      const clean = AdapterContract?.normalizePlaylistName
        ? AdapterContract.normalizePlaylistName(value)
        : String(value || "").replace(/\s+/g, " ").trim();
      if (clean && !names.includes(clean)) names.push(clean);
    };
    if (platform === "playlistpush") {
      for (const name of playlistPushSelectedPlaylistNames(root)) add(name);
    }
    if (platform === "unhurd") {
      const pageText = text(root);
      add(pageText.match(/I confirm I have added this track to\s+(.+?)(?:\n|$)/i)?.[1]);
      add(pageText.match(/Pitched to\s+(.+?)\s+Received\b/i)?.[1]);
    }
    for (const input of root.querySelectorAll('input[type="checkbox"]:checked, input[type="radio"]:checked')) {
      const label = input.closest("label") || input.parentElement;
      const labelText = text(label);
      if (/only feedback|won't offer|do not want|don't want/i.test(labelText)) continue;
      if (platform !== "playlistpush") add(labelText);
    }
    for (const select of root.querySelectorAll("select")) {
      const option = select.selectedOptions?.[0];
      if (option && option.value && !/select|choose/i.test(text(option))) add(text(option));
    }
    const selectedControls = platform === "playlistpush" ? [] : Array.from(root.querySelectorAll('button, [role="button"], [aria-selected="true"], .active, .selected'))
      .filter((node) => visibleElement([node]) && (/^selected$/i.test(text(node)) || /playlist/i.test(`${node.className || ""} ${node.getAttribute?.("aria-label") || ""}`)));
    for (const control of selectedControls) {
      let container = control.parentElement;
      for (let depth = 0; container && depth < 5; depth += 1, container = container.parentElement) {
        const candidate = lines(container).find((value) =>
          !/^(selected|select|choose|followers?|tracks?|playlist|position|add song to playlist|modify|today|tomorrow)$/i.test(value) &&
          !/^\d[\d,.]*$/.test(value) && value.length <= 180
        );
        if (candidate) { add(candidate); break; }
      }
    }
    return unique(names).slice(0, platform === "groover" ? 10 : 5);
  }

  function scanSubmitHub() {
    const root = document.querySelector("main") || document.body;
    const pageText = text(root);
    const visibleFeedback = visibleTextarea([".decline-feedback-box textarea", "textarea[name^='feedback-input-']"]);
    const activeCard = visibleFeedback?.closest(".campaign-box") || root.querySelector(".campaign-box");
    const campaignLink = activeCard?.querySelector('a[href*="/campaign/"]') || root.querySelector('a[href*="/campaign/"]');
    const trackUrl = spotifyTrackUrl(activeCard || root) || spotifyTrackUrl(root);
    const artistNames = unique(Array.from((activeCard || root).querySelectorAll('a[href*="/artist/id/"]')).map(text)).slice(0, 4);
    const campaignId = campaignLink?.getAttribute("href")?.match(/\/campaign\/([^/?#]+)/)?.[1] || "";
    const campaignIds = unique(Array.from(root.querySelectorAll('a[href*="/campaign/"]')).map((a) =>
      a.getAttribute("href")?.match(/\/campaign\/([^/?#]+)/)?.[1]
    ));
    const countFor = (label) => Math.max(0, ...Array.from(text(document.body).matchAll(new RegExp(`(\\d+)\\s+${label}`, "gi")))
      .map((match) => Number(match[1] || 0)));
    const visibleDeadlines = deadlineLabels(".campaign-box, [class*='submission']");
    const selected = selectedLabels(root, '.approve-box input[name="spotify-playlist"]');
    const title = text(campaignLink) || document.title.split("|")[0].trim();
    const declineVisible = !!visibleFeedback;
    const approveVisible = !!activeCard?.querySelector(".approve-box");
    const submissions = Array.from(root.querySelectorAll(".campaign-box")).map((card, index) => {
      const link = card.querySelector('a[href*="/campaign/"]');
      const id = link?.getAttribute("href")?.match(/\/campaign\/([^/?#]+)/)?.[1] || "";
      return id ? {
        id,
        title: text(link),
        artistNames: unique(Array.from(card.querySelectorAll('a[href*="/artist/id/"]')).map(text)).slice(0, 4),
        deadlineLabel: countdown(text(card)),
        pageUrl: `${location.origin}${location.pathname}${location.search}`,
        order: index,
      } : null;
    }).filter(Boolean);
    return {
      platform: "submithub",
      platformProfile: text(root.querySelector("h3")) || text(document.querySelector('a[href*="/playlister/"]')),
      platformSubmissionId: campaignId,
      trackTitle: title,
      artistNames,
      spotifyTrackUrl: trackUrl,
      spotifyTrackId: spotifyTrackId(trackUrl),
      releaseDate: releaseDate(text(activeCard) || pageText),
      deadlineLabel: countdown(text(activeCard) || pageText),
      status: declineVisible || approveVisible ? "in_review" : campaignId ? "new" : "inbox",
      proposedDecision: approveVisible ? "accept" : declineVisible ? "decline" : null,
      selectedPlatformPlaylists: selected,
      submissions,
      pagination: {
        page: Number(new URL(location.href).searchParams.get("page") || 1),
        pages: Math.max(1, ...Array.from(root.querySelectorAll('a[href*="?page="]')).map((link) => Number(new URL(link.href, location.href).searchParams.get("page") || 1))),
      },
      inbox: {
        total: countFor("Premium") + countFor("Standard"),
        visible: campaignIds.length,
        deadlineLabels: visibleDeadlines,
      },
    };
  }

  function discoverSubmitHubScanRoutes() {
    if (PLATFORM_HOSTS[location.hostname] !== "submithub") return { ok: false, error: "Not a SubmitHub page" };
    const links = Array.from(document.querySelectorAll("a[href]"));
    const candidates = links.map((link) => ({
      label: text(link).replace(/\s+/g, " ").trim(),
      url: new URL(link.getAttribute("href"), location.href).href,
    }));
    const adRoute = candidates.find((item) => {
      const candidate = new URL(item.url);
      return candidate.pathname === "/links" && /^links$/i.test(item.label);
    }) || candidates.find((item) => /\/links(?:[?#]|$)/i.test(item.url)) ||
      candidates.find((item) => /\/ads\/create(?:[?#]|$)/i.test(item.url));
    const profileRoutes = candidates.filter((item) =>
      /switch|profile|playlister|curator/i.test(item.label) &&
      /dashboard|inbox|campaign|profile|playlister|curator/i.test(item.url)
    ).filter((item, index, all) => all.findIndex((candidate) => candidate.url === item.url) === index).slice(0, 20);
    const currentProfile = text(document.querySelector("main h3")) ||
      document.querySelector('a[href*="/playlister/"]')?.getAttribute("href")?.split("/").filter(Boolean).pop() || "";
    const accountOptions = Array.from(document.querySelectorAll(".manage-accounts .existing-account")).map((row) => ({
      name: text(row.querySelector("div")) || text(row),
      email: text(row.querySelector(".small")),
    })).filter((item) => item.name);
    return { ok: true, adsUrl: adRoute?.url || `${location.origin}/links`, profileRoutes, currentProfile, accountOptions };
  }

  async function switchSubmitHubAccount(name) {
    const trigger = document.querySelector("#my-blog-dropdown-trigger, .nav-account-li > a");
    trigger?.click();
    await new Promise((resolve) => setTimeout(resolve, 300));
    const row = Array.from(document.querySelectorAll(".manage-accounts .existing-account, a[href*='/playlister/'], [role='menuitem']"))
      .find((item) => text(item).toLowerCase().includes(String(name || "").toLowerCase()));
    if (!row) return { ok: false, error: "SubmitHub account was not found in the account switcher." };
    row.click();
    return { ok: true, switching: true };
  }

  function submitHubAccessBarrier() {
    const page = text(document.body).replace(/\s+/g, " ").toLowerCase();
    if (/\/login(?:[/?#]|$)/i.test(location.pathname) || document.querySelector('input[type="password"]')) {
      return "SubmitHub requested a new login. Campaign scanning stopped.";
    }
    if (/captcha|verify (?:that )?you are human|security check|too many requests|temporarily blocked|rate limit/i.test(page)) {
      return "SubmitHub displayed an access or rate-limit check. Campaign scanning stopped without retrying.";
    }
    return "";
  }

  function scanSubmitHubAds() {
    if (PLATFORM_HOSTS[location.hostname] !== "submithub") return { ok: false, error: "Not a SubmitHub page" };
    const accessBarrier = submitHubAccessBarrier();
    if (accessBarrier) return { ok: false, error: accessBarrier };
    const page = text(document.body);
    const metric = (source, patterns) => {
      for (const pattern of patterns) {
        const match = String(source).match(pattern);
        if (match) return Number(String(match[1]).replace(/,/g, ""));
      }
      return null;
    };
    const detailUrls = Array.from(document.querySelectorAll("a[href]"))
      .filter((link) => /SubmitHub\s+Ads\s*\[[^\]]+\]/i.test(text(link)))
      .map((link) => {
      const row = link.closest("tr, li, [class*='campaign'], [class*='advert']");
      const rowText = text(row).replace(/\s+/g, " ").trim();
      const status = text(link).match(/SubmitHub\s+Ads\s*\[([^\]]+)\]/i)?.[1]?.toLowerCase() || "unknown";
      const titleLink = row?.querySelector('a[href^="/links/"]:not([href*="tab=ads"])');
      const directTitle = Array.from(titleLink?.childNodes || [])
        .filter((node) => node.nodeType === Node.TEXT_NODE)
        .map((node) => node.textContent.trim())
        .filter(Boolean)
        .join(" ");
      return {
        name: directTitle || text(titleLink) || text(link).replace(/SubmitHub\s+Ads\s*\[[^\]]+\]/i, "").trim(),
        url: link.href,
        status,
        overview: {
          views: metric(rowText, [/Views\s*:\s*([\d,.]+)/i]),
          conversions: metric(rowText, [/Conversions\s*:\s*([\d,.]+)/i]),
          ctr: metric(rowText, [/CTR\s*:\s*([\d,.]+)\s*%/i]),
        },
      };
    }).filter((item, index, all) => all.findIndex((candidate) => candidate.url === item.url) === index);
    const rows = Array.from(document.querySelectorAll("tr, [class*='campaign'], [class*='advert'], [class*='promotion']"));
    const campaigns = rows.map((row, index) => {
      const value = text(row).replace(/\s+/g, " ").trim();
      if (!value || !/(?:credit|ctr|followers?\s*\/\s*day|followers? per day|ad spend)/i.test(value)) return null;
      const credits = metric(value, [/(?:spent|spend|cost)[^\d]{0,20}([\d,.]+)\s*credits?/i, /([\d,.]+)\s*credits?/i]);
      const ctr = metric(value, [/(?:ctr|click[- ]through rate)[^\d]{0,12}([\d,.]+)\s*%/i]);
      const followersPerDay = metric(value, [/([\d,.]+)\s*(?:followers?|follows?)\s*(?:\/|per)\s*day/i, /(?:followers?\s*(?:\/|per)\s*day)[^\d]{0,12}([\d,.]+)/i]);
      const heading = row.querySelector("h1, h2, h3, h4, strong, a");
      const name = text(heading) || value.slice(0, 100);
      return { id: row.id || row.dataset?.id || `ad-${index}`, name, credits, usd: credits === null ? null : credits * 0.5, ctr, followersPerDay, raw: value.slice(0, 500) };
    }).filter(Boolean).filter((item, index, all) => all.findIndex((candidate) => candidate.raw === item.raw) === index);
    const totalCredits = campaigns.reduce((sum, item) => sum + Number(item.credits || 0), 0) || metric(page, [/(?:total\s+)?(?:spent|spend|cost)[^\d]{0,20}([\d,.]+)\s*credits?/i]);
    return {
      ok: true,
      available: campaigns.length > 0 || totalCredits !== null,
      campaigns,
      detailUrls,
      totals: { credits: totalCredits, usd: totalCredits === null ? null : totalCredits * 0.5 },
      warning: campaigns.length ? "" : "Ads page opened, but its current metric layout was not recognized.",
    };
  }

  async function openSubmitHubAdDetail() {
    if (PLATFORM_HOSTS[location.hostname] !== "submithub") return { ok: false, error: "Not a SubmitHub page" };
    const controls = Array.from(document.querySelectorAll("a, button, [role='button']"))
      .filter((node) => /SubmitHub\s+Ads/i.test(text(node)));
    const control = controls.find((node) => !/\[(?:active|paused|canceled|complete)\]/i.test(text(node))) || controls[0];
    if (control) {
      control.click();
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    return { ok: true, opened: !!control };
  }

  async function scanSubmitHubAdDetail() {
    if (PLATFORM_HOSTS[location.hostname] !== "submithub") return { ok: false, error: "Not a SubmitHub page" };
    const accessBarrier = submitHubAccessBarrier();
    if (accessBarrier) return { ok: false, error: accessBarrier };
    const bodyText = () => text(document.querySelector("main") || document.body).replace(/\s+/g, " ");
    const numberFor = (value, pattern) => {
      const match = String(value).match(pattern);
      return match ? Number(match[1].replace(/,/g, "")) : null;
    };
    const initial = bodyText();
    const status = initial.match(/Status:\s*([a-z]+)/i)?.[1]?.toLowerCase() || "unknown";
    const dailySpend = numberFor(initial, /Daily spend:\s*([\d,.]+)\s*credits?/i);
    const remaining = numberFor(initial, /Remaining:\s*([\d,.]+)\s*credits?/i) ?? numberFor(initial, /([\d,.]+)\s*credits? remaining/i);
    const directSpent = numberFor(initial, /(?:Spent|Ad spend|Total spend)\s*:\s*([\d,.]+)\s*credits?/i);
    const purchased = [...initial.matchAll(/([\d,.]+)\s*credits?\s*\([^)]*\)/gi)].reduce((sum, match) => sum + Number(match[1].replace(/,/g, "")), 0);
    const resultControl = Array.from(document.querySelectorAll(".link, button, a")).find((node) => /^Results$/i.test(text(node)));
    if (resultControl) {
      resultControl.click();
      await new Promise((resolve) => setTimeout(resolve, 350));
    }
    const resultText = bodyText();
    const tableRow = Array.from(document.querySelectorAll("table tr")).map(text).find((value) => /^\s*[\d,]+\s+[\d,]+\s+[\d,]+\s*\([\d.]+%\)/.test(value));
    const values = tableRow?.match(/^\s*([\d,]+)\s+([\d,]+)\s+([\d,]+)\s*\(([\d.]+)%\)\s+([\d.]+)/);
    const impressions = values ? Number(values[1].replace(/,/g, "")) : numberFor(resultText, /Impressions[^\d]+([\d,]+)/i);
    const adClicks = values ? Number(values[2].replace(/,/g, "")) : numberFor(resultText, /Ad clicks[^\d]+([\d,]+)/i);
    const conversions = values ? Number(values[3].replace(/,/g, "")) : null;
    const conversionRate = values ? Number(values[4]) : null;
    const conversionsPerCredit = values ? Number(values[5]) : null;
    return {
      ok: true,
      name: text(document.querySelector('main a[href^="/links/"]:not([href="/links"])')) || document.title.replace(/\s*\|\s*SubmitHub\s*$/i, ""),
      url: location.href,
      status,
      dailySpend,
      remaining,
      purchased: purchased || null,
      spent: directSpent ?? (purchased && remaining !== null ? Math.max(0, purchased - remaining) : null),
      impressions,
      adClicks,
      ctr: impressions > 0 && adClicks !== null ? adClicks / impressions * 100 : null,
      conversions,
      conversionRate,
      conversionsPerCredit,
    };
  }

  function scanGroover() {
    const dialog = document.querySelector('[role="dialog"]');
    const root = dialog || document.body;
    const pageText = text(root);
    const trackUrl = spotifyTrackUrl(root);
    const dialogLines = lines(root);
    const spotifyLabelIndex = dialogLines.findIndex((value) => value === "Spotify track link");
    const submissionCopy = pageText.match(/([^\n]+?)\s+just submitted the track\s+[“\"]([^”\"]+)[”\"]/i);
    const trackTitle = submissionCopy?.[2]?.trim() || (dialog && spotifyLabelIndex > 0 ? dialogLines[spotifyLabelIndex - 1] : "");
    const artistNames = unique([
      submissionCopy?.[1]?.trim(),
      ...Array.from(root.querySelectorAll('a[href*="/band/profile/"]')).map(text),
    ]).slice(0, 3);
    const url = new URL(location.href);
    const buttons = Array.from(document.querySelectorAll("button")).map(text);
    const countFor = (label) => Number(buttons.find((value) => value.startsWith(label))?.match(/\((\d+)\)/)?.[1] || 0);
    const visibleDeadlines = deadlineLabels("[class*='tw-grid-cols'][class*='tw-cursor-pointer']");
    const playlistSelections = selectedLabels(root, 'input[type="checkbox"]').filter((value) =>
      !/only feedback/i.test(value)
    );
    const submissionRows = Array.from(document.querySelectorAll('[role="row"][class*="cursor-pointer"]')).map((row, index) => {
      const href = row.querySelector('a[href*="inspect="]')?.href || row.getAttribute("href") || "";
      const rowLines = lines(row);
      const semanticFallback = `${rowLines[0] || "submission"}|${rowLines[1] || ""}|${countdown(text(row))}`;
      const id = href.match(/[?&]inspect=([^&#]+)/)?.[1] || row.dataset.id || semanticFallback;
      return { id, title: rowLines[0] || "Submission", artistNames: rowLines[1] ? [rowLines[1]] : [], deadlineLabel: countdown(text(row)), order: index };
    });
    const submissions = [...new Map(submissionRows.map((submission) => [submission.id, submission])).values()];
    const isToListenView = url.searchParams.get("f") === "toReview" ||
      Array.from(document.querySelectorAll("button, [role='tab']")).some((node) =>
        /to listen/i.test(text(node)) && (node.getAttribute("aria-selected") === "true" || node.classList.contains("active"))
      );
    return {
      platform: "groover",
      platformProfile: text(document.querySelector('button[aria-label*="profile" i]')) ||
        text(Array.from(document.querySelectorAll("button")).find((button) => text(button).includes("bored indie kid"))),
      platformSubmissionId: url.searchParams.get("inspect") || "",
      trackTitle,
      artistNames,
      spotifyTrackUrl: trackUrl,
      spotifyTrackId: spotifyTrackId(trackUrl),
      releaseDate: releaseDate(pageText),
      deadlineLabel: countdown(pageText),
      status: dialog ? "in_review" : /to complete/i.test(pageText) ? "incomplete" : /to listen/i.test(pageText) ? "new" : "inbox",
      proposedDecision: root.querySelector('input[type="checkbox"]:checked') ? "accept" : null,
      selectedPlatformPlaylists: playlistSelections,
      submissions,
      inbox: {
        total: countFor("All"),
        urgent: countFor("Urgent"),
        toListen: countFor("To listen"),
        toComplete: countFor("To complete"),
        deadlineLabels: visibleDeadlines,
        toListenDeadlineLabels: isToListenView ? submissions.map((submission) => submission.deadlineLabel).filter(Boolean) : [],
      },
    };
  }

  function grooverAcceptedTrackSnapshot() {
    const context = scanGroover();
    const dialog = document.querySelector('[role="dialog"]');
    if (!dialog || !context.spotifyTrackId || !context.platformSubmissionId) return null;
    const opportunityChecked = Array.from(dialog.querySelectorAll('input[type="checkbox"]')).some((input) =>
      input.checked && /add to playlist/i.test(text(input.closest("label") || input.parentElement))
    );
    // Groover's current playlist picker renders a custom Selected button while
    // leaving the underlying opportunity checkbox unchecked. Treat that visible
    // state as authoritative instead of relying only on input.checked.
    const selectedPlaylistButtons = Array.from(dialog.querySelectorAll("button")).filter((button) =>
      /^selected$/i.test(text(button)) && visibleElement([button])
    );
    if (!opportunityChecked && !selectedPlaylistButtons.length) return null;
    const checkedPlaylists = Array.from(dialog.querySelectorAll('input[type="checkbox"]:checked')).map((input) =>
      text(input.closest("label") || input.parentElement)
    ).filter((label) => /playlist/i.test(label) && !/only feedback/i.test(label));
    const selectedPlaylists = selectedPlaylistButtons.map((button) => {
      let container = button.parentElement;
      for (let depth = 0; container && depth < 5; depth += 1, container = container.parentElement) {
        const candidates = lines(container).filter((value) =>
          !/^(selected|select|followers?|tracks?|playlist|position)$/i.test(value) &&
          !/^\d[\d,\.]*$/.test(value)
        );
        if (candidates.length) return candidates[0];
      }
      return "";
    });
    const platformPlaylists = unique([...checkedPlaylists, ...selectedPlaylists]);
    return {
      platform: "groover",
      platformProfile: context.platformProfile || "",
      platformSubmissionId: context.platformSubmissionId,
      spotifyTrackId: context.spotifyTrackId,
      spotifyTrackUrl: context.spotifyTrackUrl,
      trackTitle: context.trackTitle,
      artistNames: context.artistNames || [],
      platformPlaylists,
      pageUrl: location.href,
      capturedAt: new Date().toISOString(),
    };
  }

  function feedbackGenerationContext() {
    const context = scan() || {};
    const platform = context.platform || PLATFORM_HOSTS[location.hostname] || "";
    const root = platform === "groover" ? (document.querySelector('[role="dialog"]') || document) : document;
    const playlistNames = selectedPlaylistNames(platform, root);
    const selectedPlacementText = Array.from(root.querySelectorAll('input[type="checkbox"]:checked, input[type="radio"]:checked'))
      .map((input) => text(input.closest("label") || input.parentElement))
      .join(" ");
    const visibleWeeks = Number(selectedPlacementText.match(/\b(\d{1,3})\s*weeks?\b/i)?.[1] || 0) || null;
    return {
      platform,
      trackTitle: context.trackTitle || "",
      artistNames: context.artistNames || [],
      selectedPlatformPlaylists: playlistNames.length ? playlistNames : (context.selectedPlatformPlaylists || []),
      placementWeeks: visibleWeeks,
    };
  }

  function maybeConfirmGrooverAcceptance() {
    const pending = pendingGrooverReview || pendingGrooverAcceptance;
    if (!pending) return;
    const current = scanGroover();
    const dialogText = text(document.querySelector('[role="dialog"]'));
    const changedSubmission = current.platformSubmissionId && current.platformSubmissionId !== pending.platformSubmissionId;
    const dialogClosed = !document.querySelector('[role="dialog"]');
    const explicitSuccess = /feedback (?:was )?sent|thank you for your feedback|response (?:was )?sent/i.test(dialogText);
    if (!changedSubmission && !dialogClosed && !explicitSuccess) return;
    const accepted = pendingGrooverAcceptance;
    const review = pendingGrooverReview;
    pendingGrooverAcceptance = null;
    pendingGrooverReview = null;
    if (accepted) browser.runtime.sendMessage({ type: "GROOVER_ACCEPTANCE_CONFIRMED", accepted }).catch(() => {});
    if (review) browser.runtime.sendMessage({ type: "PLATFORM_REVIEW_CONFIRMED", review }).catch(() => {});
  }

  function watchPendingGrooverAcceptance() {
    let attempts = 0;
    const timer = setInterval(() => {
      attempts += 1;
      maybeConfirmGrooverAcceptance();
      if ((!pendingGrooverAcceptance && !pendingGrooverReview) || attempts >= 80) {
        pendingGrooverAcceptance = null;
        pendingGrooverReview = null;
        clearInterval(timer);
      }
    }, 250);
  }

  function reviewCompletionSnapshot(platform, decision, rootOverride = null) {
    const context = scan();
    if (!context || context.platform !== platform || !["accept", "decline"].includes(decision)) return null;
    const root = rootOverride || document;
    const campaignLink = platform === "submithub" ? root.querySelector('a[href*="/campaign/"]') : null;
    const platformSubmissionId = campaignLink?.getAttribute("href")?.match(/\/campaign\/([^/?#]+)/)?.[1] ||
      context.platformSubmissionId || context.spotifyTrackId;
    if (!platformSubmissionId) return null;
    return {
      platform,
      platformProfile: context.platformProfile || "",
      platformSubmissionId,
      decision,
      trackTitle: text(campaignLink) || context.trackTitle || "",
      artistNames: context.artistNames || [],
      spotifyTrackId: context.spotifyTrackId || "",
      reviewedAt: new Date().toISOString(),
      adapterVersion: ADAPTER_VERSION,
    };
  }

  function selectedReviewDecision(platform, root = document) {
    if (platform === "playlistpush") {
      const controls = Array.from(document.querySelectorAll("a.button, button, [role='button']"));
      const active = (node) => node.classList.contains("active") || node.classList.contains("selected") ||
        node.getAttribute("aria-pressed") === "true" || node.getAttribute("aria-selected") === "true";
      if (controls.some((node) => active(node) && /don't want to add|do not want to add|feedback only|decline|reject/i.test(text(node)))) return "decline";
      if (controls.some((node) => active(node) && /add song to playlist/i.test(text(node)))) return "accept";
      // PlaylistPush currently stores the rejection choice in the selected
      // reason radio. The "Don't want to add" link itself is not consistently
      // marked active, so use the actual form state as the authority.
      const rejectionReason = Array.from(root.querySelectorAll('input[type="radio"]:checked')).some((input) => {
        let node = input.closest("label") || input.parentElement;
        for (let depth = 0; node && depth < 4; depth += 1, node = node.parentElement) {
          if (/not good enough|wrong (?:genre|mood|language)|doesn.?t match|don.?t like the song enough/i.test(text(node))) return true;
        }
        return false;
      });
      if (rejectionReason) return "decline";
    }
    if (platform === "submithub") {
      if (visibleTextarea([".decline-feedback-box textarea", "textarea[name^='feedback-input-']"])) return "decline";
      if (visibleElement(Array.from(root.querySelectorAll(".approve-box, [class*='approve']")))) return "accept";
    }
    if (platform === "unhurd") {
      const rootText = text(root);
      if (/Comments\s*\(optional\)/i.test(rootText)) return "accept";
      if (currentFeedbackField("decline") && /Production quality[\s\S]*Track appeal[\s\S]*Playlist mood match/i.test(rootText)) return "decline";
    }
    return scan()?.proposedDecision || null;
  }

  function platformAcceptanceSnapshot(platform, rootOverride = null) {
    const context = scan();
    if (!context || context.platform !== platform) return null;
    const root = rootOverride || (platform === "submithub"
      ? (Array.from(document.querySelectorAll(".campaign-box .approve-box")).find((node) => visibleElement([node]))?.closest(".campaign-box") || document.querySelector(".campaign-box") || document)
      : platform === "unhurd"
        ? (document.querySelector("main, #main-content, [id='main-content']") || document)
      : (document.querySelector(".right-content") || document));
    const campaignLink = platform === "submithub" ? root.querySelector('a[href*="/campaign/"]') : null;
    const rootTrackUrl = spotifyTrackUrl(root);
    const rootSubmissionId = campaignLink?.getAttribute("href")?.match(/\/campaign\/([^/?#]+)/)?.[1] || "";
    const rootArtists = platform === "submithub"
      ? unique(Array.from(root.querySelectorAll('a[href*="/artist/id/"]')).map(text)).slice(0, 4)
      : [];
    const spotifyUrl = rootTrackUrl || context.spotifyTrackUrl;
    const submissionId = rootSubmissionId || context.platformSubmissionId;
    const trackTitle = text(campaignLink) || context.trackTitle;
    const spotifyId = spotifyTrackId(spotifyUrl) || context.spotifyTrackId;
    if (!spotifyId || !submissionId || !trackTitle) return null;
    const platformPlaylists = unique([
      ...(context.selectedPlatformPlaylists || []),
      ...selectedPlaylistNames(platform, root),
    ]).filter((name) => !/only feedback|don't want|do not want/i.test(name));
    if (!platformPlaylists.length) return null;
    if (platform === "unhurd" && selectedReviewDecision(platform, root) !== "accept") return null;
    if (platform === "playlistpush") {
      const controls = Array.from(document.querySelectorAll("a.button, button, [role='button']"));
      const selected = (node) => node.classList.contains("active") || node.classList.contains("selected") ||
        node.getAttribute("aria-pressed") === "true" || node.getAttribute("aria-selected") === "true";
      const acceptSelected = controls.some((node) => /add song to playlist/i.test(text(node)) && selected(node));
      const declineSelected = controls.some((node) => /don't want to add|do not want to add|decline|reject|feedback only/i.test(text(node)) && selected(node));
      if (!globalThis.PlaylistPilotAdapterContract?.acceptanceEligible({
        platform,
        acceptSelected,
        declineSelected,
        playlistCount: platformPlaylists.length,
      })) return null;
    }
    return {
      data: {
        platform,
        platformProfile: context.platformProfile || "",
        platformSubmissionId: submissionId,
        spotifyTrackId: spotifyId,
        spotifyTrackUrl: spotifyUrl,
        trackTitle,
        artistNames: rootArtists.length ? rootArtists : (context.artistNames || []),
        platformPlaylists,
        pageUrl: location.href,
        capturedAt: new Date().toISOString(),
      },
      initialSubmissionId: submissionId,
      formRoot: root,
    };
  }

  function watchPlatformAcceptance() {
    let attempts = 0;
    const timer = setInterval(() => {
      attempts += 1;
      const pending = pendingPlatformReview || pendingPlatformAcceptance;
      if (!pending) { clearInterval(timer); return; }
      const current = scan();
      const page = text(document.body);
      const initialSubmissionId = pending.initialSubmissionId || pending.platformSubmissionId;
      const formRoot = pending.formRoot || pendingPlatformAcceptance?.formRoot;
      const changedSubmission = current?.platformSubmissionId && current.platformSubmissionId !== initialSubmissionId;
      const formClosed = formRoot ? (!formRoot.isConnected || !visibleElement([formRoot])) : false;
      const feedbackField = pending.feedbackField || null;
      const feedbackFieldClosed = feedbackField ? (!feedbackField.isConnected || !visibleElement([feedbackField])) : false;
      const submissionRoot = pending.submissionRoot || null;
      const submissionRemoved = submissionRoot ? !submissionRoot.isConnected : false;
      const inboxDecreased = Number.isFinite(Number(pending.initialOpenCount)) &&
        Number(current?.inbox?.total || 0) < Number(pending.initialOpenCount);
      const explicitSuccess = /review (?:was )?(?:submitted|completed)|song (?:was )?added|shared (?:with|to) (?:the )?playlist|submission (?:was )?approved|thank you for (?:your )?review/i.test(page);
      // This watcher only starts after a deliberate final acceptance click. SubmitHub
      // commonly removes the reviewed card without leaving a durable success message.
      if (changedSubmission || submissionRemoved || inboxDecreased ||
          ((feedbackFieldClosed || formClosed) && (explicitSuccess || attempts >= 2))) {
        const accepted = pendingPlatformAcceptance?.data;
        const review = pendingPlatformReview?.data;
        pendingPlatformAcceptance = null;
        pendingPlatformReview = null;
        clearInterval(timer);
        if (accepted) browser.runtime.sendMessage({ type: "PLATFORM_ACCEPTANCE_CONFIRMED", accepted }).catch(() => {});
        if (review) browser.runtime.sendMessage({ type: "PLATFORM_REVIEW_CONFIRMED", review }).catch(() => {});
        return;
      }
      if (attempts >= 80) {
        pendingPlatformAcceptance = null;
        pendingPlatformReview = null;
        clearInterval(timer);
      }
    }, 250);
  }

  function cardData(card) {
    if (!card) return { title: "", artists: [] };
    const cardLines = lines(card);
    return { title: cardLines[0] || "", artists: cardLines[1] ? [cardLines[1]] : [] };
  }

  function percentage(value) {
    const number = Number(String(value ?? "").replace(/%$/, ""));
    if (!Number.isFinite(number)) return null;
    return number > 1 ? number / 100 : number;
  }

  function playlistPushTimeRemaining(card) {
    if (!card) return null;
    const explicit = card.querySelector("[data-time-remaining], [data-remaining], [data-percent-remaining]");
    if (explicit) {
      const value = explicit.dataset.timeRemaining ?? explicit.dataset.remaining ?? explicit.dataset.percentRemaining;
      const fraction = percentage(value);
      if (fraction !== null) return Math.max(0, Math.min(1, fraction));
    }
    const progress = card.querySelector("progress, [role='progressbar']");
    if (progress) {
      const now = Number(progress.value ?? progress.getAttribute("aria-valuenow"));
      const max = Number(progress.max ?? progress.getAttribute("aria-valuemax") ?? 100);
      if (Number.isFinite(now) && Number.isFinite(max) && max > 0) return Math.max(0, Math.min(1, now / max));
    }
    for (const circle of card.querySelectorAll("svg circle")) {
      const styles = getComputedStyle(circle);
      const dash = parseFloat(circle.getAttribute("stroke-dasharray") || styles.strokeDasharray);
      const offset = parseFloat(circle.getAttribute("stroke-dashoffset") || styles.strokeDashoffset);
      if (Number.isFinite(dash) && dash > 0 && Number.isFinite(offset)) {
        return Math.max(0, Math.min(1, 1 - Math.abs(offset) / dash));
      }
    }
    const styled = card.querySelector("[style*='--progress'], [style*='--percentage'], [style*='conic-gradient']");
    const match = styled?.getAttribute("style")?.match(/(?:--progress|--percentage)\s*:\s*([\d.]+)%?/i);
    return match ? Math.max(0, Math.min(1, percentage(match[1]))) : null;
  }

  function scanPlaylistPush() {
    const root = document.querySelector(".right-content") || document.body;
    const cards = Array.from(document.querySelectorAll(".pointer.curate"));
    const activeCard = (selectedPlaylistPushCard?.isConnected ? selectedPlaylistPushCard : null) ||
      document.querySelector(".pointer.curate.active, .pointer.curate.selected") ||
      (root !== document.body ? cards[0] : null);
    const active = cardData(activeCard);
    const trackUrl = spotifyTrackUrl(root);
    const inboxLabel = text(document.querySelector('a[href="/my/reviews"]'));
    const openCount = Number(inboxLabel.match(/(\d+)\s*$/)?.[1] || cards.length);
    const reviewVisible = !!visibleTextarea(["textarea[name='comment']", "textarea[placeholder*='write your review' i]"]);
    const addActive = !!Array.from(document.querySelectorAll("a.button")).find((node) =>
      /add song to playlist/i.test(text(node)) && node.classList.contains("active")
    );
    const timerFractions = cards.map(playlistPushTimeRemaining).filter((value) => value !== null);
    const submissions = cards.map((card, index) => {
      const data = cardData(card);
      const trackId = spotifyTrackId(spotifyTrackUrl(card));
      const id = trackId || card.dataset.id || card.getAttribute("data-review-id") || `card-${index}-${data.title}`;
      const remaining = playlistPushTimeRemaining(card);
      return { id, title: data.title || "Submission", artistNames: data.artists, urgency: remaining === null ? null : 1 - remaining, order: index };
    });
    return {
      platform: "playlistpush",
      platformProfile: text(document.querySelector("header"))?.match(/Curator\s+([^\n]+)/i)?.[1] || "",
      platformSubmissionId: spotifyTrackId(trackUrl),
      trackTitle: active.title,
      artistNames: active.artists,
      spotifyTrackUrl: trackUrl,
      spotifyTrackId: spotifyTrackId(trackUrl),
      releaseDate: "",
      deadlineLabel: "",
      status: reviewVisible ? "in_review" : trackUrl ? "new" : "inbox",
      proposedDecision: reviewVisible ? (addActive ? "accept" : null) : null,
      selectedPlatformPlaylists: playlistPushSelectedPlaylistNames(document),
      submissions,
      inbox: {
        total: openCount,
        urgent: openCount,
        timerDetected: timerFractions.length,
        deadlineAvailable: timerFractions.length > 0,
      },
    };
  }

  function scanUnhurd() {
    const root = document.querySelector("main, #main-content, [id='main-content']") || document.body;
    const pageLines = lines(root);
    const url = new URL(location.href);
    const detailId = url.pathname.match(/^\/pitches\/([0-9a-f-]{36})\/?$/i)?.[1] || "";
    const spotifyUrl = spotifyTrackUrl(root);
    // Unhurd renders separate desktop/mobile navigation trees. Read all of
    // them because a hidden responsive copy can briefly contain stale text.
    const pendingLinks = Array.from(document.querySelectorAll('a[href="/pitches"], a[href$="/pitches"]'));
    const visiblePendingLinks = pendingLinks.filter((link) => {
      const style = getComputedStyle(link);
      const rect = link.getBoundingClientRect();
      return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0;
    });
    const pendingTotals = (visiblePendingLinks.length ? visiblePendingLinks : pendingLinks)
      .map((link) => Number(text(link).match(/(\d+)\s*pending/i)?.[1] || 0))
      .filter((value) => Number.isFinite(value));
    const pendingTotal = pendingTotals.length ? Math.max(...pendingTotals) : 0;
    const pitchLinks = Array.from(document.querySelectorAll('a[href*="/pitches/"]')).filter((link) =>
      /\/pitches\/[0-9a-f-]{36}(?:[/?#]|$)/i.test(link.getAttribute("href") || "")
    );
    const submissions = [...new Map(pitchLinks.map((link, index) => {
      const id = (link.getAttribute("href") || "").match(/\/pitches\/([0-9a-f-]{36})/i)?.[1] || "";
      const values = lines(link);
      const pendingIndex = values.findIndex((value) => /^pending$/i.test(value));
      return [id, {
        id,
        title: values[0] || "Pitch",
        artistNames: values[1] ? [values[1]] : [],
        deadlineLabel: countdown(text(link)),
        order: index,
        playlist: pendingIndex > 1 ? values[pendingIndex - 1].replace(/^Pitched to\s*/i, "") : "",
      }];
    }).filter(([id]) => id))].map(([, submission]) => submission);
    const title = detailId
      ? text(root.querySelector("h1, h2")) || pageLines[0] || ""
      : "";
    const titleIndex = title ? pageLines.indexOf(title) : -1;
    const artistNames = detailId && titleIndex >= 0 && pageLines[titleIndex + 1]
      ? [pageLines[titleIndex + 1]]
      : [];
    const pageText = text(root);
    const pitchedPlaylist = pageText.match(/Pitched to\s+(.+?)\s+Received\b/i)?.[1]?.trim() || "";
    const confirmationPlaylist = pageText.match(/I confirm I have added this track to\s+(.+?)(?:\n|$)/i)?.[1]?.trim() || "";
    const acceptSelected = /Comments\s*\(optional\)/i.test(pageText) || !!Array.from(root.querySelectorAll("button")).find((button) =>
      /^accept$/i.test(text(button)) && (button.getAttribute("aria-pressed") === "true" || button.dataset.state === "active" || button.classList.contains("active"))
    );
    const declineSelected = !acceptSelected && !!currentFeedbackField("decline");
    return {
      platform: "unhurd",
      platformProfile: "",
      platformSubmissionId: detailId,
      trackTitle: title,
      artistNames,
      spotifyTrackUrl: spotifyUrl,
      spotifyTrackId: spotifyTrackId(spotifyUrl),
      releaseDate: pageText.match(/Released\s+([^\n]+)/i)?.[1]?.trim() || "",
      deadlineLabel: countdown(pageText),
      status: detailId ? (acceptSelected || declineSelected ? "in_review" : "new") : "inbox",
      proposedDecision: acceptSelected ? "accept" : declineSelected ? "decline" : null,
      selectedPlatformPlaylists: acceptSelected ? unique([confirmationPlaylist || pitchedPlaylist]) : [],
      submissions,
      inbox: {
        total: pendingTotal || submissions.length,
        urgent: pendingTotal || submissions.length,
        deadlineLabels: submissions.map((submission) => submission.deadlineLabel).filter(Boolean),
      },
    };
  }

  function scan(rescueConfig = activeRescueConfig) {
    const platform = PLATFORM_HOSTS[location.hostname];
    if (!platform) return null;
    let context = platform === "submithub"
      ? scanSubmitHub()
      : platform === "groover"
        ? scanGroover()
        : platform === "playlistpush"
          ? scanPlaylistPush()
          : scanUnhurd();
    let rescuedFields = [];
    if (rescueConfig && AdapterContract?.applyRescueRules) {
      const rescued = AdapterContract.applyRescueRules(context, rescueConfig, document);
      context = rescued.context;
      rescuedFields = rescued.rescuedFields;
      if (!context.spotifyTrackId && context.spotifyTrackUrl) context.spotifyTrackId = spotifyTrackId(context.spotifyTrackUrl);
    }
    const inboxValues = Object.values(context.inbox || {}).filter((value) => typeof value === "number");
    const detectedFields = [
      context.platformProfile ? "profile" : "",
      context.trackTitle ? "track_title" : "",
      context.spotifyTrackId ? "spotify_track" : "",
      context.platformSubmissionId ? "submission_id" : "",
      inboxValues.length ? "inbox" : "",
      context.deadlineLabel || context.inbox?.deadlineLabels?.length ? "deadline" : "",
      context.inbox?.timerDetected ? "timer" : "",
    ].filter(Boolean);
    const reviewing = context.status === "in_review";
    const confidence = Math.min(1, reviewing
      ? (
        (context.trackTitle ? 0.35 : 0) +
        (context.spotifyTrackId ? 0.35 : 0) +
        (context.platformProfile ? 0.1 : 0) +
        (context.platformSubmissionId ? 0.1 : 0) +
        (context.deadlineLabel || context.inbox?.deadlineLabels?.length ? 0.1 : 0)
      )
      : (
        (inboxValues.length ? 0.7 : 0) +
        (context.platformProfile ? 0.2 : 0) +
        (context.deadlineLabel || context.inbox?.deadlineLabels?.length ? 0.1 : 0)
      ));
    const warnings = [];
    if (context.status === "in_review" && !context.trackTitle) warnings.push("review_without_track_title");
    if (context.status === "in_review" && !context.spotifyTrackId) warnings.push("review_without_spotify_track");
    if (!context.platformProfile) warnings.push("account_label_not_detected");
    if (context.platform === "playlistpush" && context.inbox?.total > 0 && !context.inbox?.timerDetected) {
      warnings.push("playlistpush_timer_not_detected");
    }
    const pageKind = context.status === "in_review" ? "review" : context.status === "inbox" ? "inbox" : context.status || "unknown";
    const report = AdapterContract?.buildReport({
      platform: context.platform,
      pageKind,
      pathname: location.pathname,
      confidence,
      detectedFields,
      warnings,
      rescuedFields,
      numericInboxFields: inboxValues.length,
      deadlineLabels: context.inbox?.deadlineLabels?.length || 0,
    }) || {
      adapterVersion: ADAPTER_VERSION,
      platform: context.platform,
      pageKind,
      pathPattern: "",
      status: warnings.length ? "degraded" : "healthy",
      confidence,
      detectedFields,
      warnings,
      counters: {},
    };
    return {
      ...context,
      adapterVersion: ADAPTER_VERSION,
      adapterHealth: { ...report, report },
      loginState: context.platformProfile || inboxValues.some((value) => value > 0) || context.status === "in_review"
        ? "authenticated"
        : "unknown",
    };
  }

  function detectedPageTracks() {
    const platform = PLATFORM_HOSTS[location.hostname];
    const selectors = platform === "playlistpush"
      ? ".pointer.curate"
      : platform === "submithub"
        ? ".campaign-box"
        : platform === "unhurd"
          ? 'a[href*="/pitches/"]'
          : '[role="dialog"], [role="row"][class*="cursor-pointer"]';
    const tracks = [];
    for (const node of document.querySelectorAll(selectors)) {
      const url = spotifyTrackUrl(node);
      const id = spotifyTrackId(url);
      if (!id || tracks.some((track) => track.spotifyTrackId === id)) continue;
      const data = cardData(node);
      tracks.push({
        spotifyTrackId: id,
        spotifyTrackUrl: url,
        trackTitle: data.title || "Spotify track",
        artistNames: data.artists || [],
        platform,
      });
    }
    const current = scan();
    if (current?.spotifyTrackId && !tracks.some((track) => track.spotifyTrackId === current.spotifyTrackId)) {
      tracks.push({
        spotifyTrackId: current.spotifyTrackId,
        spotifyTrackUrl: current.spotifyTrackUrl,
        trackTitle: current.trackTitle || "Spotify track",
        artistNames: current.artistNames || [],
        platform: current.platform,
      });
    }
    return tracks.slice(0, 100);
  }

  function focusedPageTrack({ force = false } = {}) {
    const context = scan();
    if (!context?.spotifyTrackId) return null;
    const pageTracks = detectedPageTracks();
    const selected = pageTracks.find((track) => track.spotifyTrackId === context.spotifyTrackId) || {
      spotifyTrackId: context.spotifyTrackId,
      spotifyTrackUrl: context.spotifyTrackUrl,
      trackTitle: context.trackTitle || "Spotify track",
      artistNames: context.artistNames || [],
      platform: context.platform,
    };
    const focus = { ...selected, pageTracks, source: force ? "manual" : "page_click" };
    if (!force && focus.spotifyTrackId === lastFocusedTrackId) return focus;
    lastFocusedTrackId = focus.spotifyTrackId;
    if (!force) browser.runtime.sendMessage({ type: "PLATFORM_TRACK_FOCUSED", focus }).catch(() => {});
    return focus;
  }

  function captureFocusedTrackAfterClick() {
    window.setTimeout(() => focusedPageTrack(), 450);
    window.setTimeout(() => focusedPageTrack(), 1100);
  }

  function publish() {
    const context = scan();
    if (context) {
      const fingerprint = JSON.stringify({
        platform: context.platform,
        platformProfile: context.platformProfile,
        platformSubmissionId: context.platformSubmissionId,
        trackTitle: context.trackTitle,
        spotifyTrackId: context.spotifyTrackId,
        deadlineLabel: context.deadlineLabel,
        status: context.status,
        proposedDecision: context.proposedDecision,
        selectedPlatformPlaylists: context.selectedPlatformPlaylists,
        submissions: context.submissions,
        inbox: context.inbox,
        loginState: context.loginState,
      });
      // DOM churn, timers and scrolling can produce many mutations without any
      // meaningful curator-state change. Do not turn those into extension updates.
      if (fingerprint !== lastPublishedFingerprint || Date.now() - lastPublishedAt > 60000) {
        lastPublishedFingerprint = fingerprint;
        lastPublishedAt = Date.now();
        browser.runtime.sendMessage({ type: "PLATFORM_SNAPSHOT", context }).catch(() => {});
      }
    }
    return context;
  }

  function schedulePublish() {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(publish, 450);
  }

  function visibleTextarea(selectors) {
    for (const selector of selectors) {
      const matches = Array.from(document.querySelectorAll(selector));
      const target = matches.find((node) => {
        const style = getComputedStyle(node);
        const rect = node.getBoundingClientRect();
        return !node.disabled && style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0;
      });
      if (target) return target;
    }
    return null;
  }

  document.addEventListener("contextmenu", (event) => {
    const field = event.target?.closest?.("textarea, input[type='text'], [contenteditable='true']");
    if (!field) {
      lastEditableSelection = null;
      return;
    }
    if (field instanceof HTMLTextAreaElement || field instanceof HTMLInputElement) {
      const start = Number(field.selectionStart ?? 0);
      const end = Number(field.selectionEnd ?? start);
      lastEditableSelection = { field, start, end, text: field.value.slice(start, end) };
      return;
    }
    const selection = getSelection();
    lastEditableSelection = selection?.rangeCount
      ? { field, range: selection.getRangeAt(0).cloneRange(), text: selection.toString() }
      : null;
  }, true);

  function captureActiveEditableSelection() {
    const field = document.activeElement?.closest?.("textarea, input[type='text'], [contenteditable='true']");
    if (!field) return null;
    if (field instanceof HTMLTextAreaElement || field instanceof HTMLInputElement) {
      const start = Number(field.selectionStart ?? 0);
      const end = Number(field.selectionEnd ?? start);
      const selected = field.value.slice(start, end);
      if (!selected.trim()) return null;
      lastEditableSelection = { field, start, end, text: selected };
      return lastEditableSelection;
    }
    const selection = getSelection();
    if (!selection?.rangeCount || !selection.toString().trim()) return null;
    lastEditableSelection = { field, range: selection.getRangeAt(0).cloneRange(), text: selection.toString() };
    return lastEditableSelection;
  }

  function showFeedbackGeneratorStatus(message, kind = "progress") {
    let toast = document.getElementById("playlistpilot-feedback-toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.id = "playlistpilot-feedback-toast";
      Object.assign(toast.style, {
        position: "fixed", right: "18px", bottom: "18px", zIndex: "2147483647",
        maxWidth: "360px", padding: "11px 14px", borderRadius: "11px",
        color: "#f4f7f5", background: "#141920", border: "1px solid #303744",
        boxShadow: "0 16px 45px rgba(0,0,0,.5)", font: "600 12px/1.4 system-ui, sans-serif",
      });
      document.documentElement.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.borderColor = kind === "error" ? "#ff6b6b" : kind === "success" ? "#24d366" : "#303744";
    clearTimeout(toast._playlistPilotTimer);
    if (kind !== "progress") toast._playlistPilotTimer = setTimeout(() => toast.remove(), 5500);
  }

  function replaceSavedSelection(feedback) {
    const saved = lastEditableSelection;
    if (!saved?.field?.isConnected || !saved.text.trim()) return { ok: false, error: "Select + and - notes inside the platform feedback field first." };
    saved.field.focus();
    if (saved.field instanceof HTMLTextAreaElement || saved.field instanceof HTMLInputElement) {
      const nextValue = `${saved.field.value.slice(0, saved.start)}${feedback}${saved.field.value.slice(saved.end)}`;
      const prototype = saved.field instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;
      if (setter) setter.call(saved.field, nextValue);
      else saved.field.value = nextValue;
      const cursor = saved.start + feedback.length;
      saved.field.setSelectionRange?.(cursor, cursor);
    } else if (saved.range) {
      saved.range.deleteContents();
      saved.range.insertNode(document.createTextNode(feedback));
    }
    saved.field.dispatchEvent(new Event("input", { bubbles: true }));
    saved.field.dispatchEvent(new Event("change", { bubbles: true }));
    schedulePublish();
    return { ok: true, submitted: false };
  }

  function feedbackSelectors(platform, mode) {
    return platform === "submithub"
      ? mode === "accept"
        ? [".approve-box textarea", "textarea[name*='feedback' i]", "textarea"]
        : [".decline-feedback-box textarea", "textarea[name*='feedback' i]", "textarea"]
      : platform === "groover"
        ? ["textarea[name*='feedback' i]", "textarea[placeholder*='feedback' i]", "textarea"]
        : platform === "unhurd"
          ? ["textarea[placeholder*='comment' i]", "textarea[name*='comment' i]", "textarea"]
          : ["textarea[name='comment']", "textarea[placeholder*='comment' i]", "textarea"];
  }

  function visibleElement(nodes) {
    return Array.from(nodes).find((node) => {
      const style = getComputedStyle(node);
      const rect = node.getBoundingClientRect();
      return !node.disabled && style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0;
    }) || null;
  }

  function safeActionButton(pattern) {
    return visibleElement(Array.from(document.querySelectorAll("button, [role='button'], a.button")).filter((node) => {
      const label = `${text(node)} ${node.getAttribute("aria-label") || ""} ${node.getAttribute("title") || ""}`.trim();
      const finalAction = node.matches("button[type='submit'], input[type='submit']") || /submit|send feedback|finish review|confirm review/i.test(label);
      return !finalAction && pattern.test(label);
    }));
  }

  function currentFeedbackField(mode = "decline") {
    return visibleTextarea(feedbackSelectors(PLATFORM_HOSTS[location.hostname], mode));
  }

  function setFeedbackField(value, mode, expectedSubmissionId, { focus = false } = {}) {
    const current = scan();
    if (expectedSubmissionId && current?.platformSubmissionId && current.platformSubmissionId !== expectedSubmissionId) {
      return { ok: false, error: "The open submission changed. Review the text before continuing." };
    }
    const target = currentFeedbackField(mode);
    if (!target) return { ok: false, error: `Open the ${mode} feedback form on ${PLATFORM_HOSTS[location.hostname]} first` };
    bridgeWriteInProgress = true;
    const descriptor = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value");
    if (descriptor?.set) descriptor.set.call(target, String(value || ""));
    else target.value = String(value || "");
    target.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: null }));
    target.dispatchEvent(new Event("change", { bubbles: true }));
    if (focus) target.focus();
    queueMicrotask(() => { bridgeWriteInProgress = false; });
    return { ok: true, platform: PLATFORM_HOSTS[location.hostname], mode, submitted: false, value: target.value };
  }

  function focusFeedbackField(mode) {
    const target = currentFeedbackField(mode);
    if (!target) return { ok: false, error: `Open the ${mode} feedback form first` };
    target.scrollIntoView({ behavior: "smooth", block: "center" });
    target.focus({ preventScroll: true });
    const length = target.value.length;
    target.setSelectionRange?.(length, length);
    return { ok: true, value: target.value, submitted: false };
  }

  function directPortal() {
    let portal = document.getElementById("playlistpilot-direct-typing-portal");
    if (portal) return portal;
    portal = document.createElement("div");
    portal.id = "playlistpilot-direct-typing-portal";
    portal.innerHTML = `<div class="pp-portal-head"><span>PLAYLISTPILOT</span><button type="button" aria-label="Close direct typing portal">×</button></div><strong>Direct typing</strong><div class="pp-portal-field" role="button" tabindex="0"></div><small>Click the field, then type normally. Input goes directly to the website.</small>`;
    const style = document.createElement("style");
    style.id = "playlistpilot-direct-typing-style";
    style.textContent = `#playlistpilot-direct-typing-portal{position:fixed;right:18px;bottom:18px;z-index:2147483646;width:min(360px,calc(100vw - 36px));padding:12px;border:1px solid #35413a;border-radius:15px;background:#141920;color:#f4f7f5;box-shadow:0 24px 70px rgba(0,0,0,.55);font:13px/1.4 Inter,system-ui,sans-serif}#playlistpilot-direct-typing-portal .pp-portal-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:3px}#playlistpilot-direct-typing-portal .pp-portal-head span{color:#24d366;font-size:9px;font-weight:800;letter-spacing:.1em}#playlistpilot-direct-typing-portal button{border:0;background:transparent;color:#aeb6c2;font-size:18px;cursor:pointer}#playlistpilot-direct-typing-portal strong{display:block;margin-bottom:8px}#playlistpilot-direct-typing-portal .pp-portal-field{min-height:88px;max-height:180px;overflow:auto;padding:9px;border:1px solid #303744;border-radius:10px;background:#101318;color:#f4f7f5;white-space:pre-wrap;cursor:text}#playlistpilot-direct-typing-portal .pp-portal-field.active{border-color:#24d366;box-shadow:0 0 0 3px rgba(36,211,102,.14)}#playlistpilot-direct-typing-portal .pp-portal-field.empty{color:#7f8998}#playlistpilot-direct-typing-portal small{display:block;margin-top:7px;color:#8f99a7;font-size:9px}`;
    document.documentElement.append(style);
    document.body.append(portal);
    portal.querySelector("button").addEventListener("click", () => portal.remove());
    return portal;
  }

  async function showDirectTypingPortal(mode) {
    let target = currentFeedbackField(mode);
    if (!target) {
      prepareDecision(mode);
      await new Promise((resolve) => setTimeout(resolve, 500));
      target = currentFeedbackField(mode);
    }
    if (!target) return { ok: false, error: `The ${mode} feedback field is not available yet.` };
    const portal = directPortal();
    const field = portal.querySelector(".pp-portal-field");
    const render = () => {
      const value = target.value || "";
      field.textContent = value || "Click here to type in the real feedback field…";
      field.classList.toggle("empty", !value);
    };
    const focusRealField = (event) => {
      event.preventDefault();
      target.scrollIntoView({ behavior: "smooth", block: "center" });
      target.focus({ preventScroll: true });
      target.setSelectionRange?.(target.value.length, target.value.length);
      field.classList.add("active");
    };
    field.onpointerdown = focusRealField;
    field.onkeydown = (event) => {
      if (event.key === "Enter" || event.key === " ") focusRealField(event);
    };
    target.addEventListener("input", render);
    target.addEventListener("blur", () => field.classList.remove("active"));
    render();
    portal.hidden = false;
    return { ok: true, value: target.value, submitted: false, requiresPageClick: true };
  }

  async function activateReviewWorkflow(autoPlay, prepareDecline) {
    const context = scan();
    if (!context?.trackTitle && !context?.spotifyTrackId) {
      return navigateSubmission("next", autoPlay, prepareDecline);
    }
    if (prepareDecline) {
      prepareDecision("decline");
      await new Promise((resolve) => setTimeout(resolve, 550));
    }
    let playback = null;
    if (autoPlay) playback = await controlPlayback().catch((error) => ({ ok: false, error: error?.message || String(error) }));
    if (prepareDecline) await showDirectTypingPortal("decline").catch(() => null);
    schedulePublish();
    return { ok: true, activated: true, playback, submitted: false };
  }

  function controlPlayback() {
    const media = visibleElement(document.querySelectorAll("audio, video"));
    if (media) {
      if (media.paused) {
        return media.play().then(() => ({ ok: true, playing: true })).catch(() => ({ ok: false, error: "Playback was blocked; press Play once on the platform page." }));
      }
      media.pause();
      return Promise.resolve({ ok: true, playing: false });
    }
    const youtubeFrame = visibleElement(document.querySelectorAll('iframe[src*="youtube.com/embed/"], iframe[src*="youtube-nocookie.com/embed/"]'));
    if (youtubeFrame?.contentWindow) {
      embeddedPlaying = !embeddedPlaying;
      youtubeFrame.contentWindow.postMessage(JSON.stringify({ event: "command", func: embeddedPlaying ? "playVideo" : "pauseVideo", args: [] }), "*");
      return Promise.resolve({ ok: true, playing: embeddedPlaying, source: "youtube_embed" });
    }
    const platformPlay = visibleElement(document.querySelectorAll('[aria-label*="play" i], button[title*="play" i], button[class*="playButton" i], button[class*="play-button" i], .play-button, .play-btn'));
    if (platformPlay && !/playlist|display/i.test(`${platformPlay.getAttribute("aria-label") || ""} ${platformPlay.title || ""}`)) {
      platformPlay.click();
      return Promise.resolve({ ok: true, playing: true, source: "platform_control" });
    }
    const button = safeActionButton(/(^|\s)(play|pause|resume)(\s|$)/i);
    if (!button) return Promise.resolve({ ok: false, error: "Visible platform player control not found." });
    const wasPause = /pause/i.test(`${text(button)} ${button.getAttribute("aria-label") || ""}`);
    button.click();
    return Promise.resolve({ ok: true, playing: !wasPause });
  }

  function openSubmissionById(submissionId, autoPlay, prepareDecline) {
    const platform = PLATFORM_HOSTS[location.hostname];
    const wanted = String(submissionId || "");
    let target = null;
    if (platform === "submithub") {
      const cards = Array.from(document.querySelectorAll(".campaign-box"));
      target = cards.find((card) => card.querySelector('a[href*="/campaign/"]')?.getAttribute("href")?.match(/\/campaign\/([^/?#]+)/)?.[1] === wanted);
      if (target) {
        const activeField = visibleTextarea([".decline-feedback-box textarea", "textarea[name^='feedback-input-']"]);
        const activeCard = activeField?.closest(".campaign-box");
        const cancel = activeCard && activeCard !== target
          ? Array.from(activeCard.querySelectorAll("a.btn-flat, button")).find((node) => /^cancel$/i.test(text(node)))
          : null;
        if (cancel) cancel.click();
        target.querySelector(".decline-button")?.click();
      }
    } else if (platform === "groover") {
      const rows = Array.from(document.querySelectorAll('[role="row"][class*="cursor-pointer"]'));
      target = rows.find((row, index) => {
        const href = row.querySelector('a[href*="inspect="]')?.href || row.getAttribute("href") || "";
        const id = href.match(/[?&]inspect=([^&#]+)/)?.[1] || row.dataset.id || `row-${index}-${lines(row)[0] || "submission"}`;
        return id === wanted;
      });
      target?.click();
    } else if (platform === "playlistpush") {
      const cards = Array.from(document.querySelectorAll(".pointer.curate"));
      target = cards.find((card, index) => {
        const data = cardData(card);
        const id = spotifyTrackId(spotifyTrackUrl(card)) || card.dataset.id || card.getAttribute("data-review-id") || `card-${index}-${data.title}`;
        return id === wanted;
      });
      if (target) {
        selectedPlaylistPushCard = target;
        target.click();
      }
    } else if (platform === "unhurd") {
      target = Array.from(document.querySelectorAll('a[href*="/pitches/"]')).find((link) =>
        (link.getAttribute("href") || "").includes(`/pitches/${wanted}`)
      );
      target?.click();
    }
    if (!target) return { ok: false, error: "The queued submission is no longer loaded on this page." };
    embeddedPlaying = false;
    if (prepareDecline) setTimeout(() => prepareDecision("decline"), 500);
    if (prepareDecline) setTimeout(() => showDirectTypingPortal("decline"), 950);
    if (autoPlay) setTimeout(() => controlPlayback(), 900);
    setTimeout(schedulePublish, 1000);
    return { ok: true, submissionId: wanted, submitted: false };
  }

  function navigateSubmission(direction, autoPlay, prepareDecline) {
    const platform = PLATFORM_HOSTS[location.hostname];
    const afterSelection = () => {
      embeddedPlaying = false;
      if (prepareDecline) setTimeout(() => prepareDecision("decline"), 500);
      if (prepareDecline) setTimeout(() => showDirectTypingPortal("decline"), 950);
      if (autoPlay) setTimeout(() => controlPlayback(), 900);
      setTimeout(schedulePublish, 1000);
    };
    if (platform === "groover") {
      if (direction === "next") {
        const currentTitle = scan()?.trackTitle || "";
        const candidates = Array.from(document.querySelectorAll('[role="row"][class*="cursor-pointer"]')).map((row, index) => {
          const match = text(row).match(/in\s+(\d+)\s+(days?|hours?)/i);
          const amount = Number(match?.[1]);
          const hours = match?.[2]?.toLowerCase().startsWith("hour") ? amount : amount * 24;
          return { row, title: lines(row)[0] || "", hours: Number.isFinite(hours) ? hours : Infinity, index };
        }).filter((item) => Number.isFinite(item.hours) && (!currentTitle || item.title !== currentTitle)).sort((left, right) => left.hours - right.hours || left.index - right.index);
        if (candidates[0]?.row) {
          candidates[0].row.click();
          afterSelection();
          return { ok: true, direction, strategy: "earliest_deadline", submitted: false };
        }
      }
      const arrow = document.querySelector(`[role="dialog"] button.arrowWrap--${direction === "previous" ? "left" : "right"}`);
      if (arrow && !arrow.disabled) {
        arrow.click();
        afterSelection();
        return { ok: true, direction, strategy: "dialog_arrow", submitted: false };
      }
    }
    if (platform === "playlistpush") {
      const cards = Array.from(document.querySelectorAll(".pointer.curate"));
      const active = selectedPlaylistPushCard || document.querySelector(".pointer.curate.active, .pointer.curate.selected");
      const index = Math.max(0, cards.indexOf(active));
      const urgentOrder = cards.map((card, cardIndex) => ({ card, cardIndex, remaining: playlistPushTimeRemaining(card) }))
        .filter((item) => item.card !== active && item.remaining !== null)
        .sort((left, right) => left.remaining - right.remaining || left.cardIndex - right.cardIndex);
      const target = direction === "next" && urgentOrder.length
        ? urgentOrder[0].card
        : cards[index + (direction === "previous" ? -1 : 1)];
      if (target) {
        selectedPlaylistPushCard = target;
        target.click();
        afterSelection();
        return { ok: true, direction, submitted: false };
      }
    }
    if (platform === "submithub") {
      const cards = Array.from(document.querySelectorAll(".campaign-box"));
      const visibleFeedback = visibleTextarea([".decline-feedback-box textarea", "textarea[name^='feedback-input-']"]);
      const activeCard = visibleFeedback?.closest(".campaign-box") || null;
      const activeIndex = activeCard ? cards.indexOf(activeCard) : -1;
      const targetIndex = activeIndex < 0
        ? direction === "previous" ? cards.length - 1 : 0
        : activeIndex + (direction === "previous" ? -1 : 1);
      const targetCard = cards[targetIndex];
      const targetControl = targetCard?.querySelector(".decline-button");
      if (targetControl) {
        const cancel = activeCard
          ? Array.from(activeCard.querySelectorAll("a.btn-flat, button")).find((node) => /^cancel$/i.test(text(node)))
          : null;
        if (cancel) cancel.click();
        targetControl.click();
        afterSelection();
        return { ok: true, direction, strategy: "adjacent_campaign", submitted: false };
      }
    }
    if (platform === "unhurd") {
      const links = Array.from(document.querySelectorAll('a[href*="/pitches/"]')).filter((link) =>
        /\/pitches\/[0-9a-f-]{36}(?:[/?#]|$)/i.test(link.getAttribute("href") || "")
      );
      const currentId = location.pathname.match(/\/pitches\/([0-9a-f-]{36})/i)?.[1] || "";
      const index = links.findIndex((link) => (link.getAttribute("href") || "").includes(currentId));
      const target = links[index + (direction === "previous" ? -1 : 1)] || links[direction === "previous" ? links.length - 1 : 0];
      if (target) {
        target.click();
        afterSelection();
        return { ok: true, direction, strategy: "pitch_link", submitted: false };
      }
    }
    const pattern = direction === "previous"
      ? /previous submission|previous track|previous song|vorherige submission|vorheriger song/i
      : /next submission|next track|next song|nächste submission|nächster song/i;
    const button = safeActionButton(pattern);
    if (!button) return { ok: false, error: `${direction === "previous" ? "Previous" : "Next"} control not found on this page.` };
    button.click();
    afterSelection();
    return { ok: true, direction, submitted: false };
  }

  function prepareDecision(mode) {
    const platform = PLATFORM_HOSTS[location.hostname];
    if (platform === "unhurd") {
      const control = Array.from(document.querySelectorAll("button")).find((button) =>
        new RegExp(`^${mode === "decline" ? "decline" : "accept"}$`, "i").test(text(button))
      );
      if (control) {
        control.click();
        setTimeout(schedulePublish, 250);
        return { ok: true, mode, submitted: false };
      }
    }
    if (platform === "submithub") {
      const current = scan();
      if (mode === "decline" && currentFeedbackField(mode)) return { ok: true, mode, submitted: false };
      const campaignLink = current?.platformSubmissionId
        ? document.querySelector(`a[href*="/campaign/${CSS.escape(current.platformSubmissionId)}"]`)
        : null;
      const card = campaignLink?.closest(".campaign-box") || document.querySelector(".campaign-box");
      const control = mode === "decline" ? card?.querySelector(".decline-button") : card?.querySelector(".approve-button, .like-button");
      if (control) {
        control.click();
        setTimeout(schedulePublish, 300);
        return { ok: true, mode, submitted: false };
      }
    }
    if (platform === "groover") {
      const inputs = Array.from(document.querySelectorAll('[role="dialog"] input[type="checkbox"]'));
      const declineInput = inputs.find((node) => /won't offer any opportunities|only feedback/i.test(text(node.closest("label") || node.parentElement)));
      const labels = Array.from(document.querySelectorAll('[role="dialog"] label, [role="dialog"] [role="checkbox"]'));
      const declineControl = declineInput || labels.find((node) => /won't offer any opportunities|only feedback/i.test(text(node)));
      const acceptControl = document.querySelector('[role="dialog"] input[type="checkbox"][aria-label*="playlist" i]') ||
        Array.from(document.querySelectorAll('[role="dialog"] input[type="checkbox"]')).find((node) => /add to playlist/i.test(text(node.closest("label") || node.parentElement)));
      const control = mode === "decline" ? declineControl : acceptControl;
      const input = control?.matches?.('input[type="checkbox"]') ? control : control?.querySelector?.('input[type="checkbox"]');
      if (control && !input?.checked) control.click();
      if (control) return { ok: true, mode, submitted: false };
    }
    if (platform === "playlistpush") {
      const openReview = Array.from(document.querySelectorAll("a.button, button")).find((node) => /^review this song$/i.test(text(node)));
      if (openReview && !currentFeedbackField(mode)) {
        openReview.click();
        setTimeout(() => {
          const decline = Array.from(document.querySelectorAll("a.button, button, [role='button']")).find((node) => /don't want to add|do not want to add|feedback only/i.test(text(node)));
          if (mode === "decline" && decline) decline.click();
          schedulePublish();
        }, 350);
        return { ok: true, mode, submitted: false, openedForm: true };
      }
      const decline = Array.from(document.querySelectorAll("a.button, button, [role='button']")).find((node) => /don't want to add|do not want to add|feedback only/i.test(text(node)));
      if (mode === "decline" && decline) {
        decline.click();
        return { ok: true, mode, submitted: false };
      }
    }
    const pattern = mode === "accept" ? /accept|approve|add song|share.*playlist|opportunity/i : /decline|reject|pass|feedback only/i;
    const button = safeActionButton(pattern);
    if (!button) return { ok: false, error: `A safe ${mode} preparation control was not found. Open it on the platform page.` };
    button.click();
    setTimeout(schedulePublish, 250);
    return { ok: true, mode, submitted: false };
  }

  function prefillFeedback(value, mode, expectedSubmissionId) {
    return setFeedbackField(value, mode, expectedSubmissionId, { focus: true });
  }

  if (location.hostname === "playlist-pilot.com") {
    window.addEventListener("message", (event) => {
      if (event.source !== window || event.origin !== location.origin) return;
      if (event.data?.type !== "PLAYLISTPILOT_EXTENSION_SESSION") return;
      browser.runtime.sendMessage({
        type: "PLAYLISTPILOT_AUTH_SESSION",
        nonce: event.data.nonce,
        session: event.data.session,
      }).catch(() => {});
    });
  } else {
    // Pick up a submission that was already open when the extension/content
    // script loaded. For SPA navigation (notably Unhurd), only reconsider the
    // player when the URL changes; scrolling and unrelated DOM mutations must
    // never make the player jump between tracks.
    window.setTimeout(() => focusedPageTrack(), 600);
    window.setTimeout(() => focusedPageTrack(), 1600);
    window.setInterval(() => {
      if (location.href === lastFocusedLocation) return;
      lastFocusedLocation = location.href;
      window.setTimeout(() => focusedPageTrack(), 500);
    }, 1000);

    document.addEventListener("click", (event) => {
      const card = event.target?.closest?.(".pointer.curate");
      if (card) selectedPlaylistPushCard = card;
      const platform = PLATFORM_HOSTS[location.hostname];
      const submissionTarget = platform === "playlistpush"
        ? event.target?.closest?.(".pointer.curate")
        : platform === "submithub"
          ? event.target?.closest?.(".campaign-box")
          : platform === "unhurd"
            ? event.target?.closest?.('a[href*="/pitches/"]')
          : event.target?.closest?.('[role="row"][class*="cursor-pointer"], [role="dialog"]');
      if (submissionTarget) captureFocusedTrackAfterClick();
      if (PLATFORM_HOSTS[location.hostname] === "groover") {
        const button = event.target?.closest?.("button");
        if (button && /send my feedback/i.test(text(button))) {
          pendingGrooverAcceptance = grooverAcceptedTrackSnapshot();
          pendingGrooverReview = reviewCompletionSnapshot("groover", pendingGrooverAcceptance ? "accept" : "decline");
          if (pendingGrooverAcceptance || pendingGrooverReview) watchPendingGrooverAcceptance();
        }
      }
      if (platform === "playlistpush" || platform === "submithub" || platform === "unhurd") {
        const control = event.target?.closest?.('button, input[type="submit"], a.button, [role="button"]');
        const label = `${text(control)} ${control?.value || ""} ${control?.getAttribute?.("aria-label") || ""}`.trim();
        const finalPattern = platform === "playlistpush"
          ? /submit review|finish review|complete review|confirm(?: review)?|add (?:this )?song/i
          : /submit|send|approve|confirm(?: review)?|share/i;
        const declinePattern = /decline|reject|not for me|don't want|do not want|feedback only/i;
        const clickedRoot = platform === "submithub" && control
          ? (control.closest(".campaign-box") || Array.from(document.querySelectorAll(".campaign-box .approve-box")).find((node) => visibleElement([node]))?.closest(".campaign-box"))
          : null;
        const decision = control ? selectedReviewDecision(platform, clickedRoot || document) : null;
        const feedbackField = decision ? currentFeedbackField(decision) : null;
        // SubmitHub may label the *final* rejection control "Decline" or "Not for
        // me" as well. During the initial preparation click the feedback field is
        // not visible yet (this listener runs in capture phase), so requiring that
        // real field keeps preparation and completed-review tracking separate.
        const submitHubFinalDecline = platform === "submithub" && decision === "decline" &&
          declinePattern.test(label) && feedbackField && visibleElement([feedbackField]);
        const isFinalReviewControl = (finalPattern.test(label) && !declinePattern.test(label)) || submitHubFinalDecline;
        if (control && isFinalReviewControl) {
          const snapshot = platformAcceptanceSnapshot(platform, clickedRoot);
          const reviewData = decision ? reviewCompletionSnapshot(platform, decision, clickedRoot || document) : null;
          pendingPlatformReview = reviewData ? {
            data: reviewData,
            initialSubmissionId: reviewData.platformSubmissionId,
            initialOpenCount: Number(scan()?.inbox?.total || 0),
            feedbackField,
            submissionRoot: platform === "playlistpush"
              ? (selectedPlaylistPushCard?.isConnected ? selectedPlaylistPushCard : document.querySelector(".pointer.curate.active, .pointer.curate.selected"))
              : clickedRoot,
            // Watch the actual feedback form/box first. The surrounding SubmitHub
            // campaign card can remain mounted after a review was submitted.
            formRoot: feedbackField?.closest("form, .decline-feedback-box, .approve-box, [role='dialog']") || clickedRoot || null,
          } : null;
          if (snapshot) {
            pendingPlatformAcceptance = snapshot;
          }
          if (snapshot || pendingPlatformReview) {
            watchPlatformAcceptance();
          }
        }
      }
    }, true);

    // SubmitHub variants do not always use the same final button label. The
    // actual feedback form submission is a more stable completion signal and
    // supplements (rather than replaces) the click-based adapter above.
    document.addEventListener("submit", (event) => {
      if (PLATFORM_HOSTS[location.hostname] !== "submithub") return;
      const form = event.target instanceof HTMLFormElement ? event.target : null;
      if (!form) return;
      const campaignRoot = form.closest(".campaign-box") || form;
      const feedbackField = visibleTextarea([
        ".decline-feedback-box textarea",
        "textarea[name^='feedback-input-']",
        "textarea[name*='feedback' i]",
      ]);
      let decision = selectedReviewDecision("submithub", campaignRoot);
      if (!decision && feedbackField && (form.contains(feedbackField) || campaignRoot.contains(feedbackField))) decision = "decline";
      if (!decision) return;
      const reviewData = reviewCompletionSnapshot("submithub", decision, campaignRoot);
      if (!reviewData || pendingPlatformReview?.data?.platformSubmissionId === reviewData.platformSubmissionId) return;
      pendingPlatformReview = {
        data: reviewData,
        initialSubmissionId: reviewData.platformSubmissionId,
        initialOpenCount: Number(scan()?.inbox?.total || 0),
        feedbackField,
        submissionRoot: campaignRoot,
        formRoot: form,
      };
      watchPlatformAcceptance();
    }, true);
  }

  browser.runtime.onMessage.addListener((message) => {
    if (message?.type === "GROOVER_ACCEPTANCE_SAVED" || message?.type === "PLATFORM_ACCEPTANCE_SAVED") {
      const track = message.track || {};
      const title = String(track.track_title || track.trackTitle || "Accepted song").trim();
      const artists = Array.isArray(track.artist_names) ? track.artist_names : track.artistNames;
      const artist = Array.isArray(artists) ? artists.filter(Boolean).join(", ") : String(artists || "").trim();
      showFeedbackGeneratorStatus(`✓ ${title}${artist ? ` · ${artist}` : ""} erkannt und in PlaylistPilot gespeichert.`, "success");
      return Promise.resolve({ ok: true });
    }
    if (message?.type === "GROOVER_ACCEPTANCE_SAVE_FAILED" || message?.type === "PLATFORM_ACCEPTANCE_SAVE_FAILED") {
      showFeedbackGeneratorStatus(`PlaylistPilot konnte den Song nicht speichern: ${message.message || "Unbekannter Fehler"}`, "error");
      return Promise.resolve({ ok: true });
    }
    if (message?.type === "REVIEW_EARNING_SAVED") {
      const amount = Number(message.event?.amount || 0);
      const currency = String(message.event?.currency || "").trim();
      showFeedbackGeneratorStatus(`✓ Review erkannt${amount > 0 ? ` · ${amount.toFixed(2)} ${currency}` : ""}`, "success");
      return Promise.resolve({ ok: true });
    }
    if (message?.type === "REVIEW_EARNING_SAVE_FAILED") {
      showFeedbackGeneratorStatus(`PlaylistPilot konnte den Review nicht verbuchen: ${message.message || "Unbekannter Fehler"}`, "error");
      return Promise.resolve({ ok: true });
    }
    if (message?.type === "SCAN_PLATFORM") {
      if (message.rescueConfig && typeof message.rescueConfig === "object") activeRescueConfig = message.rescueConfig;
      return Promise.resolve(scan());
    }
    if (message?.type === "GET_FOCUSED_PAGE_TRACK") return Promise.resolve(focusedPageTrack({ force: true }));
    if (message?.type === "DISCOVER_SUBMITHUB_SCAN_ROUTES") return Promise.resolve(discoverSubmitHubScanRoutes());
    if (message?.type === "SWITCH_SUBMITHUB_ACCOUNT") return Promise.resolve(switchSubmitHubAccount(message.name));
    if (message?.type === "SCAN_SUBMITHUB_ADS") return Promise.resolve(scanSubmitHubAds());
    if (message?.type === "OPEN_SUBMITHUB_AD_DETAIL") return openSubmitHubAdDetail();
    if (message?.type === "SCAN_SUBMITHUB_AD_DETAIL") return scanSubmitHubAdDetail();
    if (message?.type === "PREFILL_FEEDBACK") {
      return Promise.resolve(prefillFeedback(message.text, message.mode, message.expectedSubmissionId));
    }
    if (message?.type === "SHOW_DIRECT_TYPING_PORTAL") return showDirectTypingPortal(message.mode === "decline" ? "decline" : "accept");
    if (message?.type === "GET_REVIEW_STATE") {
      const acceptField = currentFeedbackField("accept");
      const declineField = currentFeedbackField("decline");
      const field = acceptField || declineField;
      const media = visibleElement(document.querySelectorAll("audio, video"));
      return Promise.resolve({ ok: true, bridgeAvailable: !!field, value: field?.value || "", playing: media ? !media.paused : false });
    }
    if (message?.type === "CONTROL_PLAYBACK") return controlPlayback();
    if (message?.type === "NAVIGATE_SUBMISSION") return Promise.resolve(navigateSubmission(message.direction, !!message.autoPlay, !!message.prepareDecline));
    if (message?.type === "OPEN_QUEUED_SUBMISSION") return Promise.resolve(openSubmissionById(message.submissionId, !!message.autoPlay, !!message.prepareDecline));
    if (message?.type === "GET_EDITABLE_FEEDBACK_SELECTION") {
      const saved = captureActiveEditableSelection() || lastEditableSelection;
      return Promise.resolve(saved?.field?.isConnected && saved.text.trim()
        ? { ok: true, selection: saved.text }
        : { ok: false, error: "Select + and - notes inside the platform feedback field first." });
    }
    if (message?.type === "GET_FEEDBACK_GENERATION_CONTEXT") return Promise.resolve(feedbackGenerationContext());
    if (message?.type === "SHOW_FEEDBACK_GENERATOR_STATUS") {
      showFeedbackGeneratorStatus(message.message, message.kind);
      return Promise.resolve({ ok: true });
    }
    if (message?.type === "APPLY_GENERATED_FEEDBACK") {
      const result = replaceSavedSelection(String(message.feedback || ""));
      showFeedbackGeneratorStatus(result.ok ? "PlaylistPilot feedback inserted. Nothing was submitted." : result.error, result.ok ? "success" : "error");
      return Promise.resolve(result);
    }
    if (message?.type === "ACTIVATE_REVIEW_WORKFLOW") return activateReviewWorkflow(!!message.autoPlay, !!message.prepareDecline);
    if (message?.type === "PREPARE_DECISION") return Promise.resolve(prepareDecision(message.mode === "decline" ? "decline" : "accept"));
    return undefined;
  });

})();
