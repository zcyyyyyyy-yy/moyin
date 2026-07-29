# 墨隐 Moyin

[![CI](https://github.com/zcyyyyyyy-yy/moyin/actions/workflows/ci.yml/badge.svg)](https://github.com/zcyyyyyyy-yy/moyin/actions/workflows/ci.yml)
[![MoonBit](https://img.shields.io/badge/core-MoonBit-3b82f6)](https://www.moonbitlang.com/)
[![License](https://img.shields.io/badge/license-Apache--2.0-9dffca)](LICENSE)

墨隐解决“日志、配置或测试数据发给外部之前，如何快速发现并移除隐私与访问凭据”的问题。核心引擎使用 MoonBit 编写，可在浏览器和命令行中完全离线运行；输入原文不会上传到服务器。

它不仅生成脱敏副本，还能把上一次扫描作为隐私基线，在 CI 或发布前识别新增、增加、减少和已经消失的风险。基线报告只保存带盐匿名指纹，不保存手机号、邮箱、密钥等原文。

## 主要能力

| 能力 | 说明 |
| --- | --- |
| 13 类规则 | 手机号、座机、邮箱、身份证、银行卡、车牌、IPv4、MAC、JWT、API 密钥、URL 凭据、私钥、自定义词 |
| 有效性校验 | 身份证校验位、银行卡 Luhn、IPv4 分段范围与格式边界 |
| 两种替换方式 | 可读的星号脱敏；保留关联关系的带盐一致化匿名标识 |
| 配置化扫描 | 分类开关、低风险过滤、自定义词、结果上限和大文本分块 |
| 隐私基线门禁 | 对比基线与候选文件，新增高风险数据时可让 CI 以状态码 2 失败 |
| 多种入口 | 离线网页、单文件 CLI、标准输入和保留目录结构的批处理 |
| 可解释报告 | 每项结果包含分类、风险、位置、命中原因和替换预览 |

## 快速体验

需要 [MoonBit 工具链](https://www.moonbitlang.com/download/)和 Node.js 18+。

```bash
git clone https://github.com/zcyyyyyyy-yy/moyin.git
cd moyin
npm run build
npm run dev
```

浏览器打开 `http://127.0.0.1:4173`，点击“填入示例”即可体验。页面中的规则选择、自定义敏感词和匿名化盐值都在本机处理。

## 命令行

输出完整 JSON 风险报告：

```bash
npm run scan -- examples/sample.log
```

生成可阅读的脱敏副本：

```bash
node cli/moyin.mjs examples/sample.log --mask
```

用项目盐值生成可关联但不可直接识别的匿名标识：

```bash
node cli/moyin.mjs examples/sample.log --tokenize --salt team-2026-private
```

只检查指定规则，并加入项目自定义词：

```bash
node cli/moyin.mjs examples/sample.log \
  --categories phone,email,secret,custom \
  --custom-term ORCHID \
  --no-low-risk
```

批量生成安全副本目录：

```bash
node cli/moyin.mjs ./logs --tokenize --salt release-42
```

默认创建相邻的 `logs-safe-tokenize`，保留子目录结构，并生成不含敏感原文的 `_moyin-report.json`。已存在的输出目录不会被覆盖，明确需要继续时添加 `--force`。

查看全部选项：

```bash
node cli/moyin.mjs --help
```

## 隐私基线与 CI 门禁

先准备一份已经人工确认的基线文件，再与候选文件比较：

```bash
node cli/moyin.mjs candidate.log \
  --baseline baseline.log \
  --salt repository-private-scope \
  --fail-on-drift \
  --out privacy-drift.json
```

默认策略：

- 新增高风险信息时阻止；
- 新增中风险值超过 3 个时阻止；
- 总风险分增加超过 20 时阻止；
- 未通过时仍输出完整漂移报告，并以状态码 `2` 退出。

漂移报告中的 `anonymous_id` 用于识别“是否为同一敏感值”，但不会写入原文。盐值应由 CI Secret 提供，不要提交到仓库。

## 架构

```text
MoonBit rule registry
        │
        ├── validators + overlap resolver
        ├── configurable chunk scanner
        ├── masking / salted pseudonymization
        └── privacy inventory + drift policy
                         │
                JavaScript ESM output
                         │
                  ┌──────┴──────┐
              Offline Web      Node CLI
```

网页与 CLI 使用同一份 MoonBit 编译产物，不维护两套检测逻辑。详细设计见 [架构说明](docs/ARCHITECTURE.md)。

## 开发与验证

运行完整验证：

```bash
npm run test:all
```

也可以分别运行：

```bash
moon fmt --check
moon info
moon check --target js
moon test --target js
moon bench --target js
moon coverage analyze -- -f summary
npm run test:cli
npm run test:web
moon package --list
```

当前包含 49 项 MoonBit 单元测试、CLI 集成测试、真实 Edge/Chromium 浏览器冒烟测试和两组性能基准。GitHub Actions 会在 push 与 pull request 时执行格式、接口、单测、构建、CLI、浏览器和打包检查。

## 检测原则与限制

- 更精确、风险更高的规则优先，重叠区间不会被重复替换。
- 大文本按逻辑分块扫描，并保留重叠窗口以覆盖跨边界信息。
- 浏览器报告位置使用 UTF-16 代码单元，与 JavaScript 字符串切片一致。
- 一致化替换用于降低直接识别风险，不等同于不可逆密码学匿名化。
- 规则引擎无法覆盖所有私有密钥格式、自然语言上下文或经过编码的数据。

墨隐是外发前检查与开发门禁工具，不是数据合规结论。重要数据仍应由负责人复核。安全模型与报告方式见 [安全说明](docs/SECURITY.md)。

## 项目资料

- [架构与数据流](docs/ARCHITECTURE.md)
- [安全模型](docs/SECURITY.md)
- [OSC 2026 参赛准备](docs/OSC2026.md)
- [贡献指南](CONTRIBUTING.md)
- [版本记录](CHANGELOG.md)

## 许可证

[Apache License 2.0](LICENSE)
