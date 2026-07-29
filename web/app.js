import {
  available_rules_json,
  engine_version,
  scan_configured_json,
} from "./engine.js";

const MAX_FILE_SIZE = 5 * 1024 * 1024;
const sampleText = `生产日志导出预览
用户：林小姐
手机号：13812345678
邮箱：alice@example.com
身份证：11010519491231002X
测试银行卡：4532015112830366
内网地址：192.168.1.9
API_KEY=sk-DEMO0000000000000000
备注：请在发送给外部供应商之前完成脱敏。`;

const elements = {
  input: document.querySelector("#sourceInput"),
  fileInput: document.querySelector("#fileInput"),
  fileName: document.querySelector("#fileName"),
  charCount: document.querySelector("#charCount"),
  dropZone: document.querySelector("#dropZone"),
  scanButton: document.querySelector("#scanButton"),
  sampleButton: document.querySelector("#sampleButton"),
  clearButton: document.querySelector("#clearButton"),
  results: document.querySelector("#resultsSection"),
  findingsList: document.querySelector("#findingsList"),
  emptyState: document.querySelector("#emptyState"),
  maskedOutput: document.querySelector("#maskedOutput"),
  total: document.querySelector("#totalCount"),
  high: document.querySelector("#highCount"),
  medium: document.querySelector("#mediumCount"),
  low: document.querySelector("#lowCount"),
  scanTime: document.querySelector("#scanTime"),
  engineVersion: document.querySelector("#engineVersion"),
  verdictBanner: document.querySelector("#verdictBanner"),
  verdictIcon: document.querySelector("#verdictIcon"),
  verdictLabel: document.querySelector("#verdictLabel"),
  verdictMessage: document.querySelector("#verdictMessage"),
  outputDescription: document.querySelector("#outputDescription"),
  copyButton: document.querySelector("#copyButton"),
  downloadMaskButton: document.querySelector("#downloadMaskButton"),
  downloadReportButton: document.querySelector("#downloadReportButton"),
  toast: document.querySelector("#toast"),
  rulesGrid: document.querySelector("#rulesGrid"),
  customTerms: document.querySelector("#customTerms"),
  tokenSalt: document.querySelector("#tokenSalt"),
  includeLowRisk: document.querySelector("#includeLowRisk"),
  advancedSettings: document.querySelector("#advancedSettings"),
  resultMeta: document.querySelector("#resultMeta"),
};

let currentReport = null;
let currentFileName = "moyin-result";
let replacementMode = "mask";

function updateInputMeta() {
  elements.charCount.textContent = `${elements.input.value.length.toLocaleString("zh-CN")} 字符`;
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("is-visible");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => elements.toast.classList.remove("is-visible"), 2200);
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function riskLabel(risk) {
  return { high: "高风险", medium: "中风险", low: "低风险" }[risk] ?? risk;
}

function renderRuleOptions() {
  const rules = JSON.parse(available_rules_json());
  for (const rule of rules) {
    const label = document.createElement("label");
    label.className = "rule-option";
    label.title = rule.description;
    label.innerHTML = `
      <input type="checkbox" value="${escapeHtml(rule.category)}" ${
        rule.enabled_by_default ? "checked" : ""
      } />
      <span>
        <strong>${escapeHtml(rule.label)}</strong>
        <small>${riskLabel(rule.risk)}</small>
      </span>
    `;
    elements.rulesGrid.append(label);
  }
}

function selectedCategories() {
  return [...elements.rulesGrid.querySelectorAll('input[type="checkbox"]:checked')]
    .map((input) => input.value)
    .join(",");
}

function renderFindings(findings) {
  elements.findingsList.replaceChildren();
  elements.emptyState.classList.toggle("is-hidden", findings.length !== 0);

  for (const [index, finding] of findings.entries()) {
    const article = document.createElement("article");
    article.className = "finding-card";
    article.innerHTML = `
      <div class="finding-index">${String(index + 1).padStart(2, "0")}</div>
      <div class="finding-body">
        <div class="finding-title">
          <h3>${escapeHtml(finding.label)}</h3>
          <span class="risk-pill ${finding.risk}">${riskLabel(finding.risk)}</span>
        </div>
        <div class="finding-values">
          <code>${escapeHtml(finding.original)}</code>
          <span aria-hidden="true">→</span>
          <code class="masked">${escapeHtml(finding.masked)}</code>
        </div>
        <p>${escapeHtml(finding.reason)}</p>
      </div>
      <div class="finding-range">${finding.start}—${finding.end}</div>
    `;
    elements.findingsList.append(article);
  }
}

function renderReport(report, elapsed) {
  currentReport = report;
  elements.total.textContent = report.summary.total;
  elements.high.textContent = report.summary.high;
  elements.medium.textContent = report.summary.medium;
  elements.low.textContent = report.summary.low;
  elements.maskedOutput.textContent = report.masked_text;
  elements.engineVersion.textContent = report.version;
  elements.scanTime.textContent = `${elapsed.toFixed(1)} ms · 本地完成`;
  elements.resultMeta.textContent = `${report.categories.length} 类命中 · ${report.chunk_count} 个扫描块${
    report.truncated ? " · 已达到结果上限" : ""
  }`;
  elements.verdictBanner.className = `verdict-banner ${report.verdict.level}`;
  elements.verdictIcon.textContent =
    report.verdict.level === "safe" ? "✓" : report.verdict.level === "review" ? "?" : "!";
  elements.verdictLabel.textContent = report.verdict.label;
  elements.verdictMessage.textContent = report.verdict.message;
  elements.outputDescription.textContent =
    report.mode === "tokenize"
      ? "相同敏感值已替换为相同匿名标识，可保留关联关系"
      : "已按确定性规则遮挡，可直接复核";
  renderFindings(report.findings);
  elements.results.classList.remove("is-hidden");
  elements.results.scrollIntoView({ behavior: "smooth", block: "start" });
}

function runScan() {
  const text = elements.input.value;
  if (!text.trim()) {
    showToast("请先粘贴文本或导入文件");
    elements.input.focus();
    return;
  }

  elements.scanButton.classList.add("is-loading");
  elements.scanButton.querySelector("span").textContent = "正在本地检测…";
  requestAnimationFrame(() => {
    const start = performance.now();
    try {
      const report = JSON.parse(
        scan_configured_json(
          text,
          replacementMode,
          elements.tokenSalt.value,
          selectedCategories(),
          elements.customTerms.value,
          elements.includeLowRisk.checked,
          10000,
          65536,
        ),
      );
      renderReport(report, performance.now() - start);
    } catch (error) {
      console.error(error);
      showToast("检测失败，请检查控制台信息");
    } finally {
      elements.scanButton.classList.remove("is-loading");
      elements.scanButton.querySelector("span").textContent = "开始本地检测";
    }
  });
}

async function loadFile(file) {
  if (!file) return;
  if (file.size > MAX_FILE_SIZE) {
    showToast("文件超过 5 MB，请拆分后再试");
    return;
  }
  elements.input.value = await file.text();
  elements.fileName.textContent = file.name;
  currentFileName = file.name.replace(/\.[^.]+$/, "") || "moyin-result";
  updateInputMeta();
  showToast(`已载入 ${file.name}`);
}

function download(content, name, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

elements.input.addEventListener("input", () => {
  updateInputMeta();
  elements.fileName.textContent = "手动输入";
});
elements.scanButton.addEventListener("click", runScan);
elements.sampleButton.addEventListener("click", () => {
  elements.input.value = sampleText;
  elements.fileName.textContent = "内置演示数据";
  currentFileName = "moyin-sample";
  updateInputMeta();
  showToast("示例已填入，点击开始检测");
});
elements.clearButton.addEventListener("click", () => {
  elements.input.value = "";
  elements.fileInput.value = "";
  elements.fileName.textContent = "等待输入";
  elements.results.classList.add("is-hidden");
  currentReport = null;
  updateInputMeta();
  elements.input.focus();
});
elements.fileInput.addEventListener("change", (event) => loadFile(event.target.files?.[0]));

document.querySelectorAll(".mode-option").forEach((option) => {
  option.addEventListener("click", () => {
    replacementMode = option.dataset.mode;
    elements.tokenSalt.disabled = replacementMode !== "tokenize";
    document
      .querySelectorAll(".mode-option")
      .forEach((item) => item.classList.toggle("is-active", item === option));
    if (currentReport) {
      elements.results.classList.add("is-hidden");
      currentReport = null;
      showToast("替换方式已切换，请重新检测");
    }
  });
});

elements.advancedSettings.addEventListener("toggle", () => {
  if (elements.advancedSettings.open) {
    elements.advancedSettings.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
});

for (const eventName of ["dragenter", "dragover"]) {
  elements.dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropZone.classList.add("is-dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  elements.dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropZone.classList.remove("is-dragging");
  });
}
elements.dropZone.addEventListener("drop", (event) => loadFile(event.dataTransfer?.files?.[0]));

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => item.classList.remove("is-active"));
    tab.classList.add("is-active");
    const masked = tab.dataset.tab === "masked";
    document.querySelector("#findingsTab").classList.toggle("is-hidden", masked);
    document.querySelector("#maskedTab").classList.toggle("is-hidden", !masked);
  });
});

elements.copyButton.addEventListener("click", async () => {
  if (!currentReport) return;
  await navigator.clipboard.writeText(currentReport.masked_text);
  showToast("脱敏文本已复制");
});
elements.downloadMaskButton.addEventListener("click", () => {
  if (!currentReport) return;
  const suffix = currentReport.mode === "tokenize" ? "tokenized" : "masked";
  download(currentReport.masked_text, `${currentFileName}-${suffix}.txt`, "text/plain;charset=utf-8");
});
elements.downloadReportButton.addEventListener("click", () => {
  if (!currentReport) return;
  download(
    `${JSON.stringify(currentReport, null, 2)}\n`,
    `${currentFileName}-report.json`,
    "application/json;charset=utf-8",
  );
});

renderRuleOptions();
elements.engineVersion.textContent = engine_version();
updateInputMeta();
