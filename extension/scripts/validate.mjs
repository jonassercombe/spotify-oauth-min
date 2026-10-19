import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const extensionDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const requiredFiles = [
  "manifest.json",
  "background.js",
  "content/adapter-contract.js",
  "content/content-script.js",
  "sidebar/sidebar.html",
  "sidebar/sidebar.css",
  "sidebar/sidebar.js",
  "icons/playlistpilot.svg",
];

const source = Object.fromEntries(await Promise.all(requiredFiles.map(async (file) => [
  file,
  await readFile(path.join(extensionDir, file), "utf8"),
])));
const manifest = JSON.parse(source["manifest.json"]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

assert(manifest.manifest_version === 3, "Firefox extension must use Manifest V3");
assert(/^\d+\.\d+\.\d+$/.test(manifest.version), "Extension version must be semver");
for (const permission of ["alarms", "contextualIdentities", "cookies", "storage", "tabs"]) {
  assert(manifest.permissions?.includes(permission), `Missing permission: ${permission}`);
}
for (const permission of ["activeTab", "clipboardWrite", "<all_urls>"]) {
  assert(!manifest.permissions?.includes(permission), `Release must not request unused permission: ${permission}`);
}
assert(manifest.browser_specific_settings?.gecko?.id, "Release requires a stable Firefox add-on ID");
assert(manifest.browser_specific_settings?.gecko?.data_collection_permissions, "Release must declare Firefox data collection permissions");
for (const host of ["submithub.com", "groover.co", "playlistpush.com", "unhurdmusic.com", "playlist-pilot.com"]) {
  assert(manifest.host_permissions?.some((pattern) => pattern.includes(host)), `Missing host permission: ${host}`);
}

const sidebarIds = new Set([...source["sidebar/sidebar.html"].matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]));
for (const [, id] of source["sidebar/sidebar.js"].matchAll(/byId\("([^"]+)"\)/g)) {
  assert(sidebarIds.has(id), `Sidebar script references missing element #${id}`);
}

assert(!/\b(?:api[_-]?key|service[_-]?role|client[_-]?secret)\b\s*[:=]\s*["'][^"']+/i.test(
  Object.values(source).join("\n")
), "Potential secret embedded in extension source");
assert(!/\bfetch\s*\(/.test(source["content/content-script.js"]), "Content adapters must not call platform APIs directly");

for (const file of ["background.js", "content/adapter-contract.js", "content/content-script.js", "sidebar/sidebar.js"]) {
  await execFileAsync(process.execPath, ["--check", path.join(extensionDir, file)]);
}
await execFileAsync(process.execPath, [path.join(extensionDir, "tests/adapter-contract.test.mjs")]);

console.log(`PlaylistPilot Firefox ${manifest.version}: validation passed`);
