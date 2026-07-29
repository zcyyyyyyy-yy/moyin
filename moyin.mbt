///|
/// Current public engine version.
pub fn engine_version() -> String {
  "0.2.0"
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
/// Return only the deterministically redacted text.
pub fn mask_text(text : String) -> String {
  scan(text).masked_text
}

///|
/// Return text with deterministic per-value anonymous tokens.
pub fn tokenize_text(text : String) -> String {
  scan_with_mode(text, "tokenize").masked_text
}
