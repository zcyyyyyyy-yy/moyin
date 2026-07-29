import { spawnSync } from "node:child_process";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveMoonCommand } from "./moon-command.mjs";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const result = spawnSync(resolveMoonCommand(), ["test", "--target", "js"], {
  cwd: root,
  stdio: "inherit",
});

process.exit(result.status ?? 1);
