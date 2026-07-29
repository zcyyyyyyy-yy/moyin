///|
test "detects Chinese landline numbers" {
  let report = @privacy_guard.scan("客服电话 010-12345678，分机 123")
  assert_eq(report.summary.total, 1)
  assert_eq(report.findings[0].category, "landline")
  assert_eq(report.findings[0].masked, "010-****5678")
  assert_eq(report.verdict.level, "review")
}

///|
test "detects four-digit landline area codes" {
  let report = @privacy_guard.scan("深圳办公室：0755-87654321")
  assert_eq(report.summary.total, 1)
  assert_eq(report.findings[0].category, "landline")
}

///|
test "rejects date-like landline false positives" {
  let report = @privacy_guard.scan("日期 2026-07-29，编号 123-456")
  assert_eq(report.summary.total, 0)
}

///|
test "detects ordinary Chinese vehicle plates" {
  let report = @privacy_guard.scan("车辆 京A12345 已进入停车场")
  assert_eq(report.summary.total, 1)
  assert_eq(report.findings[0].category, "vehicle_plate")
  assert_eq(report.findings[0].risk, "medium")
}

///|
test "detects new-energy Chinese vehicle plates" {
  let report = @privacy_guard.scan("新能源车牌 粤BD12345")
  assert_eq(report.summary.total, 1)
  assert_eq(report.findings[0].category, "vehicle_plate")
  assert_eq(report.findings[0].end - report.findings[0].start, 8)
}

///|
test "does not accept unknown province plate prefixes" {
  let report = @privacy_guard.scan("编号 X京A12345Y")
  assert_eq(report.summary.total, 0)
}

///|
test "detects colon-separated MAC addresses" {
  let report = @privacy_guard.scan("设备地址 aa:bb:cc:dd:ee:ff")
  assert_eq(report.summary.total, 1)
  assert_eq(report.findings[0].category, "mac")
  assert_eq(report.summary.low, 1)
}

///|
test "detects hyphen-separated MAC addresses" {
  let report = @privacy_guard.scan("MAC=AA-BB-CC-DD-EE-FF")
  assert_eq(report.summary.total, 1)
  assert_eq(report.findings[0].category, "mac")
}

///|
test "rejects invalid MAC addresses" {
  let report = @privacy_guard.scan("MAC=GG:BB:CC:DD:EE:FF")
  assert_eq(report.summary.total, 0)
}

///|
test "detects JWT access tokens" {
  let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureABCD1234"
  let report = @privacy_guard.scan("Authorization: Bearer " + token)
  assert_eq(report.summary.total, 1)
  assert_eq(report.findings[0].category, "jwt")
  assert_eq(report.summary.high, 1)
}

///|
test "rejects incomplete JWT shapes" {
  let report = @privacy_guard.scan("value eyJshort.payload")
  assert_eq(report.summary.total, 0)
}

///|
test "detects URL embedded database credentials" {
  let report = @privacy_guard.scan(
    "DATABASE_URL=postgres://alice:s3cr3t-pass@db.example.com:5432/app",
  )
  assert_eq(report.summary.total, 1)
  assert_eq(report.findings[0].category, "url_credential")
  assert_eq(report.findings[0].original, "alice:s3cr3t-pass")
  assert_eq(report.findings[0].masked, "alice:******")
}

///|
test "does not flag URLs without passwords" {
  let report = @privacy_guard.scan("主页 https://example.com/docs")
  assert_eq(report.summary.total, 0)
}

///|
test "redacts complete PEM private key blocks" {
  let input =
    #|-----BEGIN PRIVATE KEY-----
    #|DEMO_NOT_A_REAL_PRIVATE_KEY
    #|-----END PRIVATE KEY-----
  let report = @privacy_guard.scan(input)
  assert_eq(report.summary.total, 1)
  assert_eq(report.findings[0].category, "private_key")
  assert_eq(report.masked_text, "[REDACTED PRIVATE KEY]")
}

///|
test "does not flag public certificate markers as private keys" {
  let input =
    #|-----BEGIN CERTIFICATE-----
    #|DEMO_CERTIFICATE
    #|-----END CERTIFICATE-----
  let report = @privacy_guard.scan(input)
  assert_eq(report.summary.total, 0)
}

///|
test "supports case-insensitive custom literal rules" {
  let config = @privacy_guard.config_from_strings(
    "mask", "", "custom", "Project Nightfall\n内部客户A", true, 100, 4096,
  )
  let report = @privacy_guard.scan_with_config(
    "project nightfall 属于内部客户A", config,
  )
  assert_eq(report.summary.total, 2)
  assert_eq(report.findings[0].category, "custom")
  assert_eq(report.summary.medium, 2)
}

///|
test "ignores blank custom literal entries" {
  let config = @privacy_guard.config_from_strings(
    "mask", "", "custom", "\n \n", true, 100, 4096,
  )
  let report = @privacy_guard.scan_with_config("普通文本", config)
  assert_eq(report.summary.total, 0)
}

///|
test "can enable only selected categories" {
  let config = @privacy_guard.config_from_strings(
    "mask", "", "phone", "", true, 100, 4096,
  )
  let report = @privacy_guard.scan_with_config(
    "电话 13812345678 邮箱 alice@example.com IP 192.168.1.9", config,
  )
  assert_eq(report.summary.total, 1)
  assert_eq(report.findings[0].category, "phone")
}

///|
test "can exclude low-risk network findings" {
  let config = @privacy_guard.config_from_strings(
    "mask", "", "", "", false, 100, 4096,
  )
  let report = @privacy_guard.scan_with_config(
    "IP 192.168.1.9 MAC aa:bb:cc:dd:ee:ff", config,
  )
  assert_eq(report.summary.total, 0)
}

///|
test "enforces maximum finding count and marks truncation" {
  let config = @privacy_guard.config_from_strings(
    "mask", "", "phone", "", true, 2, 4096,
  )
  let report = @privacy_guard.scan_with_config(
    "13812345678 13912345678 13712345678", config,
  )
  assert_eq(report.summary.total, 2)
  assert_true(report.truncated)
}

///|
test "normalizes invalid maximum finding limits" {
  let config = @privacy_guard.config_from_strings(
    "mask", "", "phone", "", true, 0, 4096,
  )
  let report = @privacy_guard.scan_with_config("13812345678", config)
  assert_eq(report.summary.total, 1)
  assert_true(!report.truncated)
}

///|
test "finds values crossing a chunk boundary" {
  let prefix = "x".repeat(1018)
  let input = prefix + "13812345678" + " suffix"
  let config = @privacy_guard.config_from_strings(
    "mask", "", "phone", "", true, 100, 1024,
  )
  let report = @privacy_guard.scan_with_config(input, config)
  assert_eq(report.summary.total, 1)
  assert_eq(report.findings[0].start, 1018)
  assert_eq(report.chunk_count, 2)
}

///|
test "empty input reports zero scanned chunks" {
  let report = @privacy_guard.scan("")
  assert_eq(report.chunk_count, 0)
  assert_eq(report.summary.total, 0)
}

///|
test "salted pseudonyms are stable within a namespace" {
  let first = @privacy_guard.tokenize_text_with_salt("13812345678", "tenant-a")
  let second = @privacy_guard.tokenize_text_with_salt("13812345678", "tenant-a")
  assert_eq(first, second)
  assert_true(first.contains("[PHONE_"))
}

///|
test "different salts create unlinkable pseudonym namespaces" {
  let first = @privacy_guard.tokenize_text_with_salt("13812345678", "tenant-a")
  let second = @privacy_guard.tokenize_text_with_salt("13812345678", "tenant-b")
  assert_true(first != second)
}

///|
test "reports per-category summaries" {
  let report = @privacy_guard.scan("13812345678 alice@example.com 192.168.1.9")
  assert_eq(report.categories.length(), 3)
  assert_eq(report.categories[0].category, "phone")
  assert_eq(report.categories[0].count, 1)
}

///|
test "publishes rule registry metadata" {
  let rules = @privacy_guard.available_rules()
  assert_true(rules.length() >= 13)
  assert_eq(rules[0].category, "phone")
  assert_true(@privacy_guard.available_rules_json().contains("private_key"))
}

///|
test "configured JSON API returns normalized configuration fields" {
  let output = @privacy_guard.scan_configured_json(
    "13812345678", "tokenize", "demo", "phone", "", false, 5, 1024,
  )
  assert_true(output.contains("\"mode\": \"tokenize\""))
  assert_true(output.contains("\"chunk_count\": 1"))
  assert_true(output.contains("\"truncated\": false"))
}
