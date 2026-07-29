import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const edgeCandidates =
  process.platform === "win32"
    ? [
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
      ]
    : ["/usr/bin/microsoft-edge", "/usr/bin/chromium", "/usr/bin/google-chrome"];
const browser = edgeCandidates.find(existsSync);

if (!browser) {
  console.log("跳过浏览器冒烟测试：未发现 Edge/Chromium。");
  process.exit(0);
}

const server = spawn(process.execPath, ["scripts/serve.mjs"], {
  cwd: root,
  stdio: "ignore",
});
const profileDir = join(root, "_build", "browser-smoke-profile");
const debugPort = 9333;
const edge = spawn(
  browser,
  [
    "--headless",
    "--disable-gpu",
    "--no-first-run",
    "--hide-scrollbars",
    `--remote-debugging-port=${debugPort}`,
    `--user-data-dir=${profileDir}`,
    "about:blank",
  ],
  { stdio: "ignore" },
);

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function waitForJson(url) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return await response.json();
    } catch {
      // Browser and server are still starting.
    }
    await delay(100);
  }
  throw new Error(`等待调试端点超时：${url}`);
}

async function waitForHttp(url) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Local server is still starting.
    }
    await delay(100);
  }
  throw new Error(`等待本地服务超时：${url}`);
}

function createCdpClient(socketUrl) {
  const socket = new WebSocket(socketUrl);
  const pending = new Map();
  let sequence = 0;
  const ready = new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });

  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (!message.id || !pending.has(message.id)) return;
    const { resolve, reject } = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) reject(new Error(message.error.message));
    else resolve(message.result);
  });

  return {
    ready,
    send(method, params = {}) {
      sequence += 1;
      const id = sequence;
      socket.send(JSON.stringify({ id, method, params }));
      return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
    },
    close() {
      socket.close();
    },
  };
}

try {
  await waitForHttp("http://127.0.0.1:4173/");
  const targets = await waitForJson(`http://127.0.0.1:${debugPort}/json`);
  const page = targets.find((target) => target.type === "page");
  if (!page) throw new Error("未找到浏览器页面目标");

  const client = createCdpClient(page.webSocketDebuggerUrl);
  await client.ready;
  await client.send("Page.enable");
  await client.send("Runtime.enable");
  await client.send("Page.navigate", { url: "http://127.0.0.1:4173/" });
  await delay(800);

  const evaluation = await client.send("Runtime.evaluate", {
    awaitPromise: true,
    returnByValue: true,
    expression: `(async () => {
      document.querySelector("#sampleButton").click();
      document.querySelector('[data-mode="tokenize"]').click();
      document.querySelector("#scanButton").click();
      await new Promise((resolve) => setTimeout(resolve, 250));
      return {
        title: document.title,
        total: document.querySelector("#totalCount").textContent,
        high: document.querySelector("#highCount").textContent,
        visible: !document.querySelector("#resultsSection").classList.contains("is-hidden"),
        version: document.querySelector("#engineVersion").textContent,
        findings: document.querySelectorAll(".finding-card").length,
        tokenized: document.querySelector("#maskedOutput").textContent.includes("[PHONE_"),
        verdict: document.querySelector("#verdictLabel").textContent
      };
    })()`,
  });
  const value = evaluation.result.value;
  const passed =
    value.title.includes("墨隐") &&
    value.total === "6" &&
    value.high === "4" &&
    value.visible &&
    value.version === "0.2.0" &&
    value.findings === 6 &&
    value.tokenized &&
    value.verdict === "建议阻止外发";

  if (!passed) {
    throw new Error(`浏览器结果不符合预期：${JSON.stringify(value)}`);
  }
  console.log(`浏览器冒烟测试通过：${JSON.stringify(value)}`);
  client.close();
} finally {
  edge.kill();
  server.kill();
}
