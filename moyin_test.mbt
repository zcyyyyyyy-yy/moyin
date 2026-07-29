///|
test "detects and masks common sensitive data" {
  let input = "电话 13812345678，邮箱 alice@example.com，IP 192.168.1.9"
  let report = @privacy_guard.scan(input)
  assert_eq(report.summary.total, 3)
  assert_eq(report.summary.high, 1)
  assert_eq(report.summary.medium, 1)
  assert_eq(report.summary.low, 1)
  assert_true(report.masked_text.contains("138****5678"))
  assert_true(report.masked_text.contains("a***@example.com"))
  assert_true(report.masked_text.contains("192.168.*.*"))
}

///|
test "validates Chinese identity checksum" {
  let valid = @privacy_guard.scan("身份证 11010519491231002X")
  assert_eq(valid.summary.total, 1)
  assert_eq(valid.findings[0].category, "cn_id")
  let invalid = @privacy_guard.scan("身份证 110105194912310021")
  assert_eq(invalid.summary.total, 0)
}

///|
test "validates card with Luhn checksum" {
  let report = @privacy_guard.scan("测试卡 4532015112830366")
  assert_eq(report.summary.total, 1)
  assert_eq(report.findings[0].category, "bank_card")
}

///|
test "detects explicit secret prefixes and named credentials" {
  let report = @privacy_guard.scan(
    "OPENAI_KEY=sk-DEMO0000000000000000 password: demoSecret123",
  )
  assert_eq(report.summary.total, 2)
  assert_eq(report.summary.high, 2)
  assert_true(!report.masked_text.contains("demoSecret123"))
}

///|
test "does not flag ordinary text" {
  let report = @privacy_guard.scan(
    "这是一段不包含敏感信息的普通文本。",
  )
  assert_eq(report.summary.total, 0)
  assert_eq(
    report.masked_text,
    "这是一段不包含敏感信息的普通文本。",
  )
}

///|
test "tokenization is deterministic and preserves relationships" {
  let input = "主账号 13812345678，重复账号 13812345678"
  let report = @privacy_guard.scan_with_mode(input, "tokenize")
  assert_eq(report.mode, "tokenize")
  assert_eq(report.summary.total, 2)
  assert_eq(report.findings[0].masked, report.findings[1].masked)
  assert_true(report.masked_text.contains("[PHONE_"))
  assert_eq(report.verdict.level, "block")
  assert_true(!report.verdict.can_export)
}

///|
test "safe text receives an exportable verdict" {
  let report = @privacy_guard.scan("普通的公开说明文本")
  assert_eq(report.verdict.level, "safe")
  assert_true(report.verdict.can_export)
}
