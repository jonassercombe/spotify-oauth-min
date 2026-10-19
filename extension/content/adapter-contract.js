(() => {
  const VERSION = "2026.09.2";
  const RESCUE_FIELDS = new Set(["trackTitle", "platformProfile", "spotifyTrackUrl", "deadlineLabel"]);

  function validRescueRule(rule = {}) {
    return RESCUE_FIELDS.has(rule.field) && typeof rule.selector === "string" &&
      rule.selector.length > 0 && rule.selector.length <= 240 &&
      !/[{};]/.test(rule.selector) && ["text", "href", "aria-label", "title", "value"].includes(rule.attribute || "text");
  }

  function applyRescueRules(context = {}, config = {}, root = document) {
    const output = { ...context };
    const rescuedFields = [];
    const rules = Array.isArray(config.rules) ? config.rules.slice(0, 40) : [];
    for (const rule of rules) {
      if (!validRescueRule(rule) || output[rule.field]) continue;
      let node = null;
      try { node = root.querySelector(rule.selector); } catch { continue; }
      if (!node) continue;
      const attribute = rule.attribute || "text";
      let value = attribute === "text" ? (node.innerText || node.textContent || "") : node.getAttribute(attribute) || node[attribute] || "";
      value = String(value).replace(/\s+/g, " ").trim().slice(0, 500);
      if (rule.pattern) {
        try { value = value.match(new RegExp(String(rule.pattern).slice(0, 180), "i"))?.[Number(rule.group || 1)] || ""; } catch { value = ""; }
      }
      if (!value) continue;
      output[rule.field] = value;
      rescuedFields.push(rule.field);
    }
    return { context: output, rescuedFields };
  }

  function normalizePlaylistName(value) {
    let clean = String(value || "").replace(/\s+/g, " ").trim();
    clean = clean.replace(/^(?:add (?:the )?song to|share (?:it )?in)\s*/i, "");
    clean = clean.split(/\s+(?=When\s*:|Position\s*:|Scheduled\s*:)/i)[0].trim();
    if (!clean || clean.length > 180) return "";
    if (/^(?:selected|select|choose|playlist|add to playlist|modify|today|tomorrow|immediately)$/i.test(clean)) return "";
    if (/^(?:When|Position|Scheduled)\s*:/i.test(clean)) return "";
    if (/^(?:#?\d+|\d+\s*(?:followers?|tracks?|songs?))$/i.test(clean)) return "";
    if (/^\d+\s*(?:days?|weeks?|months?)$/i.test(clean)) return "";
    return clean;
  }

  function acceptanceEligible(input = {}) {
    if (String(input.platform || "") !== "playlistpush") return true;
    return input.acceptSelected === true && input.declineSelected !== true && Number(input.playlistCount || 0) > 0;
  }

  function sanitizePath(value) {
    return String(value || "/")
      .split("/")
      .map((segment) => {
        if (!segment) return "";
        if (segment.length > 18 || /\d{4,}/.test(segment)) return ":id";
        return segment.replace(/[A-Za-z0-9_-]{16,}/g, ":id");
      })
      .join("/")
      .slice(0, 180);
  }

  function healthStatus(confidence, warnings = []) {
    if (warnings.some((warning) => /^review_without_/.test(warning)) || Number(confidence) < 0.25) return "broken";
    if (warnings.length || Number(confidence) < 0.55) return "degraded";
    return "healthy";
  }

  function buildReport(input = {}) {
    const detectedFields = Array.isArray(input.detectedFields) ? [...input.detectedFields] : [];
    const warnings = Array.isArray(input.warnings) ? [...input.warnings] : [];
    const confidence = Math.round(Math.max(0, Math.min(1, Number(input.confidence) || 0)) * 100) / 100;
    return {
      adapterVersion: VERSION,
      platform: String(input.platform || ""),
      pageKind: String(input.pageKind || "unknown"),
      pathPattern: sanitizePath(input.pathname),
      status: healthStatus(confidence, warnings),
      confidence,
      detectedFields,
      warnings,
      rescuedFields: Array.isArray(input.rescuedFields) ? [...input.rescuedFields] : [],
      counters: {
        numericInboxFields: Number(input.numericInboxFields || 0),
        deadlineLabels: Number(input.deadlineLabels || 0),
      },
    };
  }

  globalThis.PlaylistPilotAdapterContract = {
    version: VERSION,
    sanitizePath,
    healthStatus,
    buildReport,
    acceptanceEligible,
    normalizePlaylistName,
    validRescueRule,
    applyRescueRules,
  };
})();
