import { cp, mkdir, rm } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const extensionDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const stageDir = path.join(extensionDir, ".package");
const distDir = path.join(extensionDir, "dist");
const output = path.join(distDir, "playlistpilot-firefox.zip");

await rm(stageDir, { recursive: true, force: true });
await rm(output, { force: true });
await mkdir(stageDir, { recursive: true });
await mkdir(distDir, { recursive: true });

for (const entry of ["manifest.json", "background.js", "icons", "content", "sidebar"]) {
  await cp(path.join(extensionDir, entry), path.join(stageDir, entry), { recursive: true });
}

await execFileAsync("zip", ["-qr", output, "."], { cwd: stageDir });
await rm(stageDir, { recursive: true, force: true });
console.log(output);
