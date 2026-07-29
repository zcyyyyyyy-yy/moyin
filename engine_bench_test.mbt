///|
test (b : @bench.T) {
  let mixed = "用户 13812345678，邮箱 alice@example.com，" +
    "身份证 11010519491231002X，内网 192.168.1.9，" +
    "API_KEY=sk-DEMO0000000000000000，车牌 京A12345。"
  let bulk = mixed.repeat(256)
  b.bench(name="scan_mixed_record", fn() {
    b.keep(@privacy_guard.scan(mixed).summary.total)
  })
  b.bench(name="scan_256_records", fn() {
    b.keep(@privacy_guard.scan(bulk).summary.total)
  })
}
