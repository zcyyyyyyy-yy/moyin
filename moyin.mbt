///|
/// Current public engine version.
pub fn engine_version() -> String {
  "0.3.0"
}

///|
/// Scan text and serialize the full report for JavaScript and CLI consumers.
pub fn scan_json(text : String) -> String {
  @json.to_json(scan(text)).stringify(indent=2)
}

///|
/// Scan text using stable anonymous tokens and serialize the report.
pub fn scan_tokenized_json(text : String) -> String {
  @json.to_json(scan_with_mode(text, "tokenize")).stringify(indent=2)
}

///|
/// Scan text with a caller-provided pseudonymization salt.
pub fn scan_tokenized_with_salt_json(text : String, salt : String) -> String {
  let config = config_from_strings("tokenize", salt, "", "", true, 10000, 65536)
  @json.to_json(scan_with_config(text, config)).stringify(indent=2)
}

///|
/// Fully configurable entry point designed for JavaScript and C FFI callers.
pub fn scan_configured_json(
  text : String,
  mode : String,
  salt : String,
  categories_csv : String,
  custom_terms_lines : String,
  include_low_risk : Bool,
  max_findings : Int,
  chunk_size : Int,
) -> String {
  let config = config_from_strings(
    mode, salt, categories_csv, custom_terms_lines, include_low_risk, max_findings,
    chunk_size,
  )
  @json.to_json(scan_with_config(text, config)).stringify(indent=2)
}

///|
/// Return only the deterministically redacted text.
pub fn mask_text(text : String) -> String {
  scan(text).masked_text
}

///|
/// Return text with deterministic per-value anonymous tokens.
pub fn tokenize_text(text : String) -> String {
  scan_with_mode(text, "tokenize").masked_text
}

///|
/// Return deterministic pseudonyms scoped by a caller-provided salt.
pub fn tokenize_text_with_salt(text : String, salt : String) -> String {
  let config = config_from_strings("tokenize", salt, "", "", true, 10000, 65536)
  scan_with_config(text, config).masked_text
}

///|
/// Describe the built-in rule registry for UIs and external tooling.
pub fn available_rules_json() -> String {
  @json.to_json(available_rules()).stringify(indent=2)
}

///|
/// Compare a baseline and candidate text without exposing values in the result.
pub fn compare_privacy_json(
  baseline_text : String,
  candidate_text : String,
  fingerprint_salt : String,
) -> String {
  @json.to_json(
    compare_privacy_texts(baseline_text, candidate_text, fingerprint_salt),
  ).stringify(indent=2)
}
