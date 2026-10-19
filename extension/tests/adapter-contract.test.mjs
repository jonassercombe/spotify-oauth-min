import { readFile } from "node:fs/promises";
import vm from "node:vm";

const source = await readFile(new URL("../content/adapter-contract.js", import.meta.url), "utf8");
const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(source, sandbox);
const contract = sandbox.PlaylistPilotAdapterContract;

if (!contract || !/^\d{4}\.\d{2}\.\d+$/.test(contract.version)) {
  throw new Error("Adapter contract version is missing");
}

const report = contract.buildReport({
  platform: "submithub",
  pageKind: "review",
  pathname: "/campaign/MdDb8rEvjEq3itwXD",
  confidence: 0.9,
  detectedFields: ["track_title", "spotify_track"],
  warnings: [],
  numericInboxFields: 2,
  deadlineLabels: 4,
});
if (report.pathPattern !== "/campaign/:id" || report.status !== "healthy") {
  throw new Error(`Adapter report was not anonymized correctly: ${JSON.stringify(report)}`);
}

if (contract.healthStatus(0.8, ["review_without_spotify_track"]) !== "broken") {
  throw new Error("Critical adapter warning must produce broken status");
}
if (contract.healthStatus(0.45, []) !== "degraded") {
  throw new Error("Low adapter confidence must produce degraded status");
}

const rescueRoot = {
  querySelector(selector) {
    return selector === "[data-track-title]" ? { innerText: "Recovered title", getAttribute: () => "" } : null;
  },
};
const rescued = contract.applyRescueRules({ trackTitle: "" }, {
  rules: [{ field: "trackTitle", selector: "[data-track-title]", attribute: "text" }],
}, rescueRoot);
if (rescued.context.trackTitle !== "Recovered title" || rescued.rescuedFields[0] !== "trackTitle") {
  throw new Error("Declarative rescue rule did not recover a missing read-only field");
}
if (contract.validRescueRule({ field: "decision", selector: "button", attribute: "text" })) {
  throw new Error("Rescue rules must never control decision or write fields");
}

if (!contract.acceptanceEligible({ platform: "playlistpush", acceptSelected: true, declineSelected: false, playlistCount: 1 })) {
  throw new Error("Explicit PlaylistPush acceptance with a playlist must be eligible");
}
for (const state of [
  { acceptSelected: false, declineSelected: true, playlistCount: 1 },
  { acceptSelected: false, declineSelected: false, playlistCount: 1 },
  { acceptSelected: true, declineSelected: true, playlistCount: 1 },
  { acceptSelected: true, declineSelected: false, playlistCount: 0 },
]) {
  if (contract.acceptanceEligible({ platform: "playlistpush", ...state })) {
    throw new Error(`PlaylistPush decline or ambiguous state must not be eligible: ${JSON.stringify(state)}`);
  }
}

const playlistCases = new Map([
  ["Chill House When: today Position: #10 modify", "Chill House"],
  ["When: today Position: #10 modify", ""],
  ["When: today", ""],
  ["Position: #10", ""],
  ["modify", ""],
  ["8 weeks", ""],
  ["Add the song to Melodic House", "Melodic House"],
]);
for (const [input, expected] of playlistCases) {
  const actual = contract.normalizePlaylistName(input);
  if (actual !== expected) throw new Error(`Playlist name normalization failed: ${JSON.stringify({ input, expected, actual })}`);
}

console.log("Adapter contract smoke tests passed");
