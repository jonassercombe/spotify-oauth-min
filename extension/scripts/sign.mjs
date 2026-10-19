import { mkdir } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const channel = process.argv[2];
if (!["listed", "unlisted"].includes(channel)) throw new Error("Channel must be listed or unlisted");
if (!process.env.WEB_EXT_API_KEY || !process.env.WEB_EXT_API_SECRET) {
  throw new Error("Set WEB_EXT_API_KEY and WEB_EXT_API_SECRET from the AMO Developer Hub");
}

const extensionDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const projectDir = path.dirname(extensionDir);
const artifactsDir = path.join(extensionDir, "dist", channel);
await mkdir(artifactsDir, { recursive: true });

const args = [
  "sign",
  "--source-dir", extensionDir,
  "--artifacts-dir", artifactsDir,
  "--channel", channel,
  "--api-key", process.env.WEB_EXT_API_KEY,
  "--api-secret", process.env.WEB_EXT_API_SECRET,
  "--ignore-files", "dist/**", ".package/**", "tests/**", "scripts/**", "amo/**", "README.md", ".DS_Store",
];
if (channel === "listed") args.push("--amo-metadata", path.join(extensionDir, "amo", "metadata.json"));

const executable = process.platform === "win32" ? "web-ext.cmd" : "web-ext";
const { stdout, stderr } = await execFileAsync(path.join(projectDir, "node_modules", ".bin", executable), args, {
  cwd: projectDir,
  env: process.env,
  maxBuffer: 10 * 1024 * 1024,
});
if (stdout) process.stdout.write(stdout);
if (stderr) process.stderr.write(stderr);
