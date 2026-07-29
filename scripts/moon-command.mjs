import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export function resolveMoonCommand() {
  const homeBinary = join(homedir(), ".moon", "bin", process.platform === "win32" ? "moon.exe" : "moon");
  return existsSync(homeBinary) ? homeBinary : "moon";
}
