///|
test "scan_json exposes a stable JSON shape" {
  let output = scan_json("联系 13812345678")
  assert_true(output.contains("\"version\": \"0.3.0\""))
  assert_true(output.contains("\"mode\": \"mask\""))
  assert_true(output.contains("\"category\": \"phone\""))
}
