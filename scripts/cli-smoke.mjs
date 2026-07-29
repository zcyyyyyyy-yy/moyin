import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const cli = join(root, "cli", "moyin.mjs");
const temporary = await mkdtemp(join(tmpdir(), "moyin-cli-"));

function run(args, expectedStatus = 0) {
  const result = spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: "utf8",
  });
  if (result.status !== expectedStatus) {
    throw new Error(
      `CLI 状态码应为 ${expectedStatus}，实际为 ${result.status}\n${result.stderr}`,
    );
  }
  return result.stdout;
}

try {
  const baselinePath = join(temporary, "baseline.txt");
  const candidatePath = join(temporary, "candidate.txt");
  const customPath = join(temporary, "custom.txt");
  await writeFile(baselinePath, "构建成功，没有客户数据。", "utf8");
  await writeFile(candidatePath, "构建成功，手机号 13812345678。", "utf8");
  await writeFile(customPath, "项目代号 ORCHID，内网 192.168.1.8。", "utf8");

  const filtered = JSON.parse(
    run([customPath, "--categories", "custom", "--custom-term", "ORCHID"]),
  );
  if (filtered.summary.total !== 1 || filtered.findings[0].category !== "custom") {
    throw new Error("分类过滤或自定义敏感词结果不符合预期");
  }

  const pseudonymA = run([candidatePath, "--tokenize", "--salt", "scope-a"]);
  const pseudonymB = run([candidatePath, "--tokenize", "--salt", "scope-b"]);
  if (!pseudonymA.includes("[PHONE_") || pseudonymA === pseudonymB) {
    throw new Error("带盐一致化替换结果不符合预期");
  }

  const driftOutput = run(
    [candidatePath, "--baseline", baselinePath, "--salt", "ci-scope", "--fail-on-drift"],
    2,
  );
  const drift = JSON.parse(driftOutput);
  if (drift.decision.allowed || drift.new_values !== 1) {
    throw new Error("隐私基线门禁结果不符合预期");
  }
  if (driftOutput.includes("13812345678")) {
    throw new Error("隐私漂移报告不应包含敏感原文");
  }

  console.log(
    `CLI 冒烟测试通过：规则过滤、带盐匿名化、隐私基线门禁，共 ${drift.changes.length} 项变化`,
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}

