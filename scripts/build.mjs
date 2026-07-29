import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveMoonCommand } from "./moon-command.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const moon = resolveMoonCommand();
const result = spawnSync(moon, ["build", "--target", "js", "--release"], {
  cwd: root,
  stdio: "inherit",
});

if (result.status !== 0) {
  process.exit(result.status ?? 1);
}

const engineSource = join(root, "_build", "js", "release", "build", "privacy_guard.js");
const webSource = join(root, "web");
const webDist = join(root, "dist", "web");

await mkdir(webDist, { recursive: true });
await Promise.all([
  copyFile(engineSource, join(webSource, "engine.js")),
  copyFile(engineSource, join(webDist, "engine.js")),
  copyFile(join(webSource, "index.html"), join(webDist, "index.html")),
  copyFile(join(webSource, "styles.css"), join(webDist, "styles.css")),
  copyFile(join(webSource, "app.js"), join(webDist, "app.js")),
  copyFile(join(webSource, "manifest.webmanifest"), join(webDist, "manifest.webmanifest")),
]);

const metadata = {
  name: "墨隐 Moyin",
  version: "0.3.0",
  builtAt: new Date().toISOString(),
  engine: "MoonBit JavaScript backend",
};
await writeFile(join(root, "dist", "build-info.json"), `${JSON.stringify(metadata, null, 2)}\n`);

const generated = await readFile(engineSource, "utf8");
console.log(`\n✓ MoonBit engine: ${(Buffer.byteLength(generated) / 1024).toFixed(1)} KiB`);
console.log(`✓ Web app: ${webDist}`);
console.log("✓ Run `npm run dev` and open http://127.0.0.1:4173");
