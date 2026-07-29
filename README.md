# 墨隐 Moyin

墨隐是一款使用 MoonBit 编写核心引擎的离线敏感信息检测与脱敏工具。它可以在发送日志、配置、JSON、CSV 或普通文本之前，定位潜在隐私与访问凭据，并生成可复核的脱敏结果。

所有扫描均在本机完成，浏览器端不会上传原文。

## 功能

- 检测中国大陆手机号
- 验证并检测中国居民身份证号
- 检测电子邮箱
- 通过 Luhn 校验识别银行卡号
- 检测 IPv4 地址
- 检测 `sk-`、`AKIA` 前缀及常见键值形式的访问凭据
- 自动解决重叠结果并生成 UTF-16 位置
- 支持星号脱敏和确定性匿名标识两种替换模式
- 根据最高风险给出外发判定
- 网页拖拽导入、风险统计、复制及下载
- Node.js CLI 批量处理整个目录并保留目录结构
- 输出稳定的 JSON 报告结构

## 技术结构

```text
engine.mbt / moyin.mbt
        │
        ├─ MoonBit 单元测试
        │
        └─ JavaScript 后端编译产物
                 │
                 ├─ web/ 离线浏览器界面
                 └─ cli/ 命令行工具
```

网页与 CLI 调用相同的 MoonBit `scan_json` 和 `mask_text` 接口，不维护两套检测规则。

## 环境要求

- MoonBit 工具链
- Node.js 18 或更高版本

Windows 安装 MoonBit：

```powershell
Invoke-RestMethod -Uri 'https://cli.moonbitlang.com/install/powershell.ps1' | Invoke-Expression
```

## 快速启动

```powershell
cd D:\cursor_project\moyin
npm run build
npm run dev
```

浏览器打开：

```text
http://127.0.0.1:4173
```

页面中可以点击“填入示例”，然后点击“开始本地检测”体验完整流程。

## 命令行使用

扫描示例日志并输出 JSON：

```powershell
npm run scan -- examples/sample.log
```

仅输出脱敏后的文本：

```powershell
node cli/moyin.mjs examples/sample.log --mask
```

使用一致化匿名标识：

```powershell
node cli/moyin.mjs examples/sample.log --tokenize
```

同一个敏感值每次都会生成相同标识，例如同一个手机号的多次出现均替换为 `[PHONE_149353]`。这样可以继续分析记录之间的关联，又不暴露原始值。

写入指定文件：

```powershell
node cli/moyin.mjs examples/sample.log --mask --out examples/sample.masked.log
```

从标准输入读取：

```powershell
Get-Content examples/sample.log -Raw | node cli/moyin.mjs - --mask
```

批量处理目录：

```powershell
node cli/moyin.mjs D:\logs --tokenize
```

默认生成相邻的 `D:\logs-safe-tokenize` 目录，保留原来的子目录结构，并额外写入 `_moyin-report.json`。汇总报告只记录每个文件的风险数量与外发判定，不记录检测到的敏感原文。

指定批处理输出目录：

```powershell
node cli/moyin.mjs D:\logs --mask --out D:\logs-for-vendor
```

为防止意外覆盖，输出目录已经存在时命令会停止。确认需要继续写入时可以添加 `--force`。

## 开发与验证

运行 MoonBit 测试：

```powershell
npm test
```

运行真实 Edge/Chromium 浏览器冒烟测试：

```powershell
npm run test:web
```

按项目约定更新接口并格式化：

```powershell
moon info
moon fmt
moon check --target js
```

## 报告示例

```json
{
  "version": "0.2.0",
  "mode": "mask",
  "input_length": 11,
  "findings": [
    {
      "category": "phone",
      "label": "手机号码",
      "risk": "high",
      "start": 0,
      "end": 11,
      "original": "13812345678",
      "masked": "138****5678",
      "reason": "中国大陆手机号码可直接联系并关联个人"
    }
  ],
  "summary": {
    "total": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "verdict": {
    "level": "block",
    "label": "建议阻止外发",
    "message": "发现高风险身份信息或访问凭据，请完成替换并人工复核后再发送。",
    "can_export": false
  },
  "masked_text": "138****5678"
}
```

## 检测原则

墨隐不仅按字符串形状匹配：

- 身份证号会验证第 18 位校验码。
- 银行卡号会执行 Luhn 校验。
- 不同规则命中同一段文本时，优先保留更精确、风险更高的结果。
- 一致化替换采用稳定摘要编号，相同原文在不同文件中也得到相同匿名标识。
- 高风险结果会触发“建议阻止外发”，中风险触发“需要人工复核”。
- 浏览器位置使用 UTF-16 代码单元，与 JavaScript 字符串切片一致。

这些策略能降低误报，但无法保证识别全部秘密格式。正式对外发送重要数据前，仍应进行人工复核。

## 目录

```text
moyin/
├─ engine.mbt              # 检测、校验、去重与脱敏
├─ moyin.mbt               # 公共 JSON/文本接口
├─ moyin_test.mbt          # 黑盒测试
├─ moyin_wbtest.mbt        # 白盒测试
├─ web/                    # 浏览器界面
├─ cli/                    # Node CLI
├─ scripts/                # 构建、服务和浏览器测试
├─ examples/               # 安全的虚构示例数据
├─ moon.mod
├─ moon.pkg
└─ package.json
```

## 许可证

Apache-2.0
