# 贡献指南

感谢改进墨隐。规则变更会直接影响误报和漏报，因此每项改动都应可解释、可复现并包含测试。

## 本地开发

```bash
npm run build
npm run test:all
```

提交前请执行：

```bash
moon info
moon fmt
moon fmt --check
moon check --target js
moon test --target js
```

## 新增检测规则

- 使用虚构数据和公开测试编号，不提交真实个人信息或有效密钥。
- 同时添加正例、反例、左右边界和与其他规则重叠的测试。
- 对可校验的格式实现校验算法，不只依赖字符串长度。
- 在规则注册表中写明风险等级和简短原因。
- 说明规则可能产生的误报与漏报。

## 提交信息

推荐使用简洁的 Conventional Commits 风格：

```text
feat(engine): add passport detector
fix(cli): preserve utf8 output
test(rules): cover token boundaries
docs: explain pseudonymization scope
```

## 安全

不要在 Issue、测试、日志或 Pull Request 中粘贴真实密钥和个人信息。安全漏洞请按 [安全说明](docs/SECURITY.md) 私下报告。

