#!/usr/bin/env node
import { existsSync } from "node:fs";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { basename, dirname, extname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { pathToFileURL } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const enginePath = join(root, "dist", "web", "engine.js");

function showHelp() {
  console.log(`
墨隐 Moyin — 离线敏感信息检测与脱敏

用法：
  npm run scan -- <文件>              输出风险报告
  npm run scan -- <文件> --mask       仅输出脱敏文本
  npm run scan -- <文件> --tokenize   输出一致化匿名文本
  npm run scan -- <文件> --out <路径> 将结果写入文件
  echo "文本" | npm run scan -- -     从标准输入读取
  node cli/moyin.mjs <目录>            批量生成安全副本目录

选项：
  --mask       输出脱敏文本而不是 JSON 报告
  --tokenize   使用稳定匿名标识，相同原文得到相同标识
  --out, -o    指定输出路径
  --force      允许写入已经存在的批处理输出目录
  --help, -h   显示帮助
`);
}

const args = process.argv.slice(2);
if (args.includes("--help") || args.includes("-h")) {
  showHelp();
  process.exit(0);
}

if (!existsSync(enginePath)) {
  console.error("未找到编译后的 MoonBit 引擎，请先运行：npm run build");
  process.exit(1);
}

const options = {
  mask: false,
  tokenize: false,
  force: false,
  outputPath: undefined,
};
const positional = [];
for (let index = 0; index < args.length; index += 1) {
  const arg = args[index];
  if (arg === "--mask") options.mask = true;
  else if (arg === "--tokenize") options.tokenize = true;
  else if (arg === "--force") options.force = true;
  else if (arg === "--out" || arg === "-o") {
    options.outputPath = args[index + 1];
    index += 1;
  } else if (!arg.startsWith("-") || arg === "-") {
    positional.push(arg);
  } else {
    console.error(`未知选项：${arg}`);
    process.exit(1);
  }
}

const inputArg = positional[0];
if (!inputArg) {
  showHelp();
  process.exit(1);
}

if (options.mask && options.tokenize) {
  console.error("--mask 与 --tokenize 不能同时使用");
  process.exit(1);
}

if ((args.includes("--out") || args.includes("-o")) && !options.outputPath) {
  console.error("--out 后需要提供输出路径");
  process.exit(1);
}

const engine = await import(pathToFileURL(enginePath).href);
const mode = options.tokenize ? "tokenize" : "mask";
const reportFor = (text) =>
  JSON.parse(mode === "tokenize" ? engine.scan_tokenized_json(text) : engine.scan_json(text));
const transform = (text) =>
  options.tokenize ? engine.tokenize_text(text) : engine.mask_text(text);

const supportedExtensions = new Set([
  ".txt",
  ".log",
  ".json",
  ".csv",
  ".md",
  ".yaml",
  ".yml",
  ".xml",
  ".ini",
  ".conf",
  ".config",
]);
const ignoredDirectories = new Set([".git", "node_modules", "_build", "dist", ".moonagent"]);

function supportedFile(path) {
  const name = basename(path).toLowerCase();
  return supportedExtensions.has(extname(name)) || name === ".env" || name.startsWith(".env.");
}

async function collectFiles(directory, excludedRoot) {
  const files = [];
  async function walk(current) {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const path = join(current, entry.name);
      if (excludedRoot && (path === excludedRoot || path.startsWith(`${excludedRoot}${sep}`))) {
        continue;
      }
      if (entry.isDirectory() && !ignoredDirectories.has(entry.name)) await walk(path);
      else if (entry.isFile() && supportedFile(path)) files.push(path);
    }
  }
  await walk(directory);
  return files;
}

async function processDirectory(inputDirectory) {
  const outputRoot = resolve(
    options.outputPath || `${inputDirectory.replace(/[\\/]$/, "")}-safe-${mode}`,
  );
  if (outputRoot === inputDirectory) {
    throw new Error("输出目录不能与输入目录相同");
  }
  if (existsSync(outputRoot) && !options.force) {
    throw new Error(`输出目录已存在：${outputRoot}\n如需继续写入，请添加 --force`);
  }

  const files = await collectFiles(inputDirectory, outputRoot);
  const aggregate = {
    tool: "墨隐 Moyin",
    version: engine.engine_version(),
    mode,
    source: inputDirectory,
    output: outputRoot,
    generated_at: new Date().toISOString(),
    totals: { files: 0, findings: 0, high: 0, medium: 0, low: 0 },
    files: [],
  };

  for (const file of files) {
    const fileStat = await stat(file);
    if (fileStat.size > 20 * 1024 * 1024) {
      aggregate.files.push({
        path: relative(inputDirectory, file),
        skipped: true,
        reason: "文件超过 20 MB",
      });
      continue;
    }
    const text = await readFile(file, "utf8");
    const report = reportFor(text);
    const relativePath = relative(inputDirectory, file);
    const destination = join(outputRoot, relativePath);
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, report.masked_text, "utf8");
    aggregate.totals.files += 1;
    aggregate.totals.findings += report.summary.total;
    aggregate.totals.high += report.summary.high;
    aggregate.totals.medium += report.summary.medium;
    aggregate.totals.low += report.summary.low;
    aggregate.files.push({
      path: relativePath,
      findings: report.summary,
      verdict: report.verdict,
    });
  }

  await mkdir(outputRoot, { recursive: true });
  await writeFile(
    join(outputRoot, "_moyin-report.json"),
    `${JSON.stringify(aggregate, null, 2)}\n`,
    "utf8",
  );
  console.log(`批处理完成：${aggregate.totals.files} 个文件`);
  console.log(`发现信息：${aggregate.totals.findings} 项，高风险 ${aggregate.totals.high} 项`);
  console.log(`安全副本：${outputRoot}`);
  console.log(`汇总报告：${join(outputRoot, "_moyin-report.json")}`);
}

if (inputArg !== "-") {
  const inputPath = resolve(inputArg);
  const inputStat = await stat(inputPath);
  if (inputStat.isDirectory()) {
    await processDirectory(inputPath);
    process.exit(0);
  }
}

let input = "";
if (inputArg === "-") {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  input = Buffer.concat(chunks).toString("utf8");
} else {
  input = await readFile(resolve(inputArg), "utf8");
}

const output =
  options.mask || options.tokenize
    ? transform(input)
    : JSON.stringify(reportFor(input), null, 2);
if (options.outputPath) {
  await writeFile(resolve(options.outputPath), output, "utf8");
  console.error(`已写入：${resolve(options.outputPath)}`);
} else {
  process.stdout.write(`${output}\n`);
}
