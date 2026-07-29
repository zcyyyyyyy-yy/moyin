///|
test "privacy inventory deduplicates repeated values" {
  let report = @privacy_guard.scan(
    "第一次 13812345678，第二次仍是 13812345678，邮箱 a@example.com",
  )
  let inventory = @privacy_guard.build_privacy_inventory(report, "test-salt")
  assert_eq(inventory.finding_total, 3)
  assert_eq(inventory.unique_total, 2)
  assert_eq(inventory.fingerprints[0].occurrences, 2)
  assert_eq(inventory.risk_score, 24)
}

///|
test "privacy inventory omits original values from its JSON" {
  let report = @privacy_guard.scan("手机号 13812345678")
  let inventory = @privacy_guard.build_privacy_inventory(report, "scope-a")
  let json = @json.to_json(inventory).stringify()
  assert_false(json.contains("13812345678"))
  assert_true(json.contains("mi_phone_"))
}

///|
test "privacy fingerprints are stable within a salt" {
  let report = @privacy_guard.scan("手机号 13812345678")
  let first = @privacy_guard.build_privacy_inventory(report, "scope-a")
  let second = @privacy_guard.build_privacy_inventory(report, "scope-a")
  assert_eq(
    first.fingerprints[0].anonymous_id,
    second.fingerprints[0].anonymous_id,
  )
}

///|
test "privacy fingerprints differ across salts" {
  let report = @privacy_guard.scan("手机号 13812345678")
  let first = @privacy_guard.build_privacy_inventory(report, "scope-a")
  let second = @privacy_guard.build_privacy_inventory(report, "scope-b")
  assert_not_eq(
    first.fingerprints[0].anonymous_id,
    second.fingerprints[0].anonymous_id,
  )
}

///|
test "drift reports newly introduced high-risk values" {
  let drift = @privacy_guard.compare_privacy_texts(
    "构建状态正常", "构建状态正常，联系电话 13812345678", "ci-scope",
  )
  assert_eq(drift.new_values, 1)
  assert_eq(drift.added_occurrences, 1)
  assert_eq(drift.score_delta, 10)
  assert_eq(drift.changes[0].change, "new")
  assert_eq(drift.decision.level, "block")
  assert_false(drift.decision.allowed)
}

///|
test "drift reports resolved sensitive values" {
  let drift = @privacy_guard.compare_privacy_texts(
    "联系电话 13812345678", "联系电话已删除", "ci-scope",
  )
  assert_eq(drift.new_values, 0)
  assert_eq(drift.resolved_values, 1)
  assert_eq(drift.removed_occurrences, 1)
  assert_eq(drift.score_delta, -10)
  assert_eq(drift.decision.level, "pass")
}

///|
test "drift recognizes persistent values without exposing them" {
  let drift = @privacy_guard.compare_privacy_texts(
    "邮箱 alice@example.com", "负责人邮箱 alice@example.com", "ci-scope",
  )
  assert_eq(drift.persistent_values, 1)
  assert_eq(drift.changes[0].change, "persistent")
  assert_eq(drift.changes[0].delta, 0)
  let json = @json.to_json(drift).stringify()
  assert_false(json.contains("alice@example.com"))
}

///|
test "drift recognizes increased occurrences" {
  let drift = @privacy_guard.compare_privacy_texts(
    "邮箱 alice@example.com", "邮箱 alice@example.com，抄送 alice@example.com",
    "ci-scope",
  )
  assert_eq(drift.persistent_values, 1)
  assert_eq(drift.added_occurrences, 1)
  assert_eq(drift.changes[0].change, "increased")
  assert_eq(drift.changes[0].delta, 1)
}

///|
test "drift recognizes decreased occurrences" {
  let drift = @privacy_guard.compare_privacy_texts(
    "邮箱 alice@example.com，抄送 alice@example.com", "邮箱 alice@example.com",
    "ci-scope",
  )
  assert_eq(drift.persistent_values, 1)
  assert_eq(drift.removed_occurrences, 1)
  assert_eq(drift.changes[0].change, "decreased")
  assert_eq(drift.changes[0].delta, -1)
}

///|
test "custom drift policy can allow new high-risk values" {
  let policy = @privacy_guard.drift_policy(false, 3, 20, [])
  let drift = @privacy_guard.compare_privacy_reports(
    @privacy_guard.scan("无敏感信息"),
    @privacy_guard.scan("手机号 13812345678"),
    "scope",
    policy,
  )
  assert_true(drift.decision.allowed)
  assert_eq(drift.decision.level, "review")
}

///|
test "custom drift policy blocks medium-risk bursts" {
  let policy = @privacy_guard.drift_policy(false, 1, 100, [])
  let drift = @privacy_guard.compare_privacy_reports(
    @privacy_guard.scan("无敏感信息"),
    @privacy_guard.scan("邮箱 a@example.com 和 b@example.com"),
    "scope",
    policy,
  )
  assert_false(drift.decision.allowed)
  assert_true(drift.decision.reasons[0].contains("中风险"))
}

///|
test "ignored categories do not affect drift policy" {
  let policy = @privacy_guard.drift_policy(true, 0, 100, ["email"])
  let drift = @privacy_guard.compare_privacy_reports(
    @privacy_guard.scan("无敏感信息"),
    @privacy_guard.scan("邮箱 a@example.com"),
    "scope",
    policy,
  )
  assert_true(drift.decision.allowed)
}

///|
test "empty texts produce an empty passing drift" {
  let drift = @privacy_guard.compare_privacy_texts("", "", "scope")
  assert_eq(drift.baseline.unique_total, 0)
  assert_eq(drift.candidate.unique_total, 0)
  assert_eq(drift.changes.length(), 0)
  assert_true(drift.decision.allowed)
}
