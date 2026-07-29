///|
/// A single sensitive-data finding. Offsets use UTF-16 code units so browser
/// consumers can highlight the exact same range without conversion.
pub struct Finding {
  category : String
  label : String
  risk : String
  start : Int
  end : Int
  original : String
  masked : String
  reason : String
} derive(ToJson, Debug, Eq)

///|
/// Aggregate counts displayed by the browser UI.
pub struct Summary {
  total : Int
  high : Int
  medium : Int
  low : Int
} derive(ToJson, Debug, Eq)

///|
/// A simple release gate derived from the highest finding risk.
pub struct Verdict {
  level : String
  label : String
  message : String
  can_export : Bool
} derive(ToJson, Debug, Eq)

///|
/// Stable report schema shared by the browser and CLI.
pub struct ScanReport {
  version : String
  mode : String
  input_length : Int
  findings : Array[Finding]
  summary : Summary
  verdict : Verdict
  masked_text : String
} derive(ToJson, Debug, Eq)

///|
priv struct Candidate {
  category : String
  label : String
  risk : String
  start : Int
  end : Int
  masked : String
  reason : String
  priority : Int
}

///|
const ASCII_ZERO : Int = 48

///|
const ASCII_NINE : Int = 57

///|
fn code_at(text : String, index : Int) -> Int {
  text.unsafe_get(index).to_int()
}

///|
fn is_digit_code(code : Int) -> Bool {
  code >= ASCII_ZERO && code <= ASCII_NINE
}

///|
fn is_ascii_letter(code : Int) -> Bool {
  (code >= 65 && code <= 90) || (code >= 97 && code <= 122)
}

///|
fn is_ascii_alnum(code : Int) -> Bool {
  is_ascii_letter(code) || is_digit_code(code)
}

///|
fn is_email_local(code : Int) -> Bool {
  is_ascii_alnum(code) ||
  code == 46 ||
  code == 95 ||
  code == 37 ||
  code == 43 ||
  code == 45
}

///|
fn is_email_domain(code : Int) -> Bool {
  is_ascii_alnum(code) || code == 46 || code == 45
}

///|
fn is_token_code(code : Int) -> Bool {
  is_ascii_alnum(code) || code == 45 || code == 95 || code == 46
}

///|
fn candidate(
  category : String,
  label : String,
  risk : String,
  start : Int,
  end : Int,
  masked : String,
  reason : String,
  priority : Int,
) -> Candidate {
  { category, label, risk, start, end, masked, reason, priority }
}

///|
fn stable_code(value : String) -> String {
  let mut hash = 17
  for index = 0; index < value.length(); index = index + 1 {
    hash = (hash * 131 + code_at(value, index)) % 1000000
  }
  hash.to_string().pad_start(6, '0')
}

///|
fn replacement_for(
  item : Candidate,
  original : String,
  mode : String,
) -> String {
  if mode == "tokenize" {
    "[" + item.category.to_upper() + "_" + stable_code(original) + "]"
  } else {
    item.masked
  }
}

///|
fn add_emails(text : String, out : Array[Candidate]) -> Unit {
  let length = text.length()
  let mut cursor = 0
  while cursor < length {
    if code_at(text, cursor) == 64 {
      let mut start = cursor
      while start > 0 && is_email_local(code_at(text, start - 1)) {
        start = start - 1
      }
      let mut end = cursor + 1
      while end < length && is_email_domain(code_at(text, end)) {
        end = end + 1
      }
      let local_len = cursor - start
      let domain = text[cursor + 1:end].to_owned()
      let dot = domain.rev_find(".")
      let valid_domain = match dot {
        Some(index) =>
          index > 0 &&
          index < domain.length() - 2 &&
          !domain.has_prefix(".") &&
          !domain.has_suffix(".")
        None => false
      }
      if local_len > 0 && valid_domain {
        let first = text[start:start + 1].to_owned()
        out.push(
          candidate(
            "email",
            "电子邮箱",
            "medium",
            start,
            end,
            first + "***@" + domain,
            "邮箱地址可用于关联个人身份或发起钓鱼攻击",
            70,
          ),
        )
      }
      cursor = end
    } else {
      cursor = cursor + 1
    }
  }
}

///|
fn id_checksum_valid(value : String) -> Bool {
  if value.length() != 18 {
    return false
  }
  let weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
  let checks = "10X98765432"
  let mut sum = 0
  for i = 0; i < 17; i = i + 1 {
    let code = code_at(value, i)
    if !is_digit_code(code) {
      return false
    }
    sum = sum + (code - ASCII_ZERO) * weights[i]
  }
  let expected = code_at(checks, sum % 11)
  let actual = code_at(value.to_upper(), 17)
  expected == actual
}

///|
fn luhn_valid(value : String) -> Bool {
  if value.length() < 16 || value.length() > 19 {
    return false
  }
  let mut sum = 0
  let mut double_digit = false
  for i = value.length() - 1; i >= 0; i = i - 1 {
    let code = code_at(value, i)
    if !is_digit_code(code) {
      return false
    }
    let mut digit = code - ASCII_ZERO
    if double_digit {
      digit = digit * 2
      if digit > 9 {
        digit = digit - 9
      }
    }
    sum = sum + digit
    double_digit = !double_digit
  }
  sum % 10 == 0
}

///|
fn add_digit_runs(text : String, out : Array[Candidate]) -> Unit {
  let length = text.length()
  let mut cursor = 0
  while cursor < length {
    if is_digit_code(code_at(text, cursor)) {
      let start = cursor
      while cursor < length && is_digit_code(code_at(text, cursor)) {
        cursor = cursor + 1
      }
      let run_length = cursor - start
      let value = text[start:cursor].to_owned()
      if run_length == 11 &&
        code_at(value, 0) == 49 &&
        code_at(value, 1) >= 51 &&
        code_at(value, 1) <= 57 {
        out.push(
          candidate(
            "phone",
            "手机号码",
            "high",
            start,
            cursor,
            value[:3].to_owned() + "****" + value[7:].to_owned(),
            "中国大陆手机号码可直接联系并关联个人",
            90,
          ),
        )
      }
      let id_end = if run_length == 17 &&
        cursor < length &&
        (code_at(text, cursor) == 88 || code_at(text, cursor) == 120) {
        cursor + 1
      } else {
        cursor
      }
      let id_value = text[start:id_end].to_owned()
      if id_value.length() == 18 && id_checksum_valid(id_value) {
        out.push(
          candidate(
            "cn_id",
            "中国居民身份证号",
            "high",
            start,
            id_end,
            id_value[:6].to_owned() + "********" + id_value[14:].to_owned(),
            "已通过居民身份证校验位验证，属于高敏感身份信息",
            120,
          ),
        )
      }
      if run_length >= 16 && run_length <= 19 && luhn_valid(value) {
        out.push(
          candidate(
            "bank_card",
            "银行卡号",
            "high",
            start,
            cursor,
            value[:4].to_owned() +
            " **** **** " +
            value[run_length - 4:].to_owned(),
            "已通过 Luhn 校验，可能是有效的支付卡号",
            110,
          ),
        )
      }
    } else {
      cursor = cursor + 1
    }
  }
}

///|
fn ipv4_valid(value : String) -> Bool {
  let pieces = value.split(".").to_array()
  if pieces.length() != 4 {
    return false
  }
  for piece in pieces {
    if piece.is_empty() || piece.length() > 3 {
      return false
    }
    let mut number = 0
    for index = 0; index < piece.length(); index = index + 1 {
      let code = piece.unsafe_get(index).to_int()
      if !is_digit_code(code) {
        return false
      }
      number = number * 10 + code - ASCII_ZERO
    }
    if number > 255 ||
      (piece.length() > 1 && piece.unsafe_get(0).to_int() == 48) {
      return false
    }
  }
  true
}

///|
fn add_ipv4(text : String, out : Array[Candidate]) -> Unit {
  let length = text.length()
  let mut cursor = 0
  while cursor < length {
    if is_digit_code(code_at(text, cursor)) {
      let start = cursor
      let mut dots = 0
      while cursor < length &&
            (
              is_digit_code(code_at(text, cursor)) ||
              code_at(text, cursor) == 46
            ) {
        if code_at(text, cursor) == 46 {
          dots = dots + 1
        }
        cursor = cursor + 1
      }
      if dots == 3 {
        let value = text[start:cursor].to_owned()
        if ipv4_valid(value) {
          let pieces = value.split(".").to_array()
          out.push(
            candidate(
              "ipv4",
              "IPv4 地址",
              "low",
              start,
              cursor,
              pieces[0].to_owned() + "." + pieces[1].to_owned() + ".*.*",
              "IP 地址可能暴露网络位置、设备或内部拓扑",
              50,
            ),
          )
        }
      }
    } else {
      cursor = cursor + 1
    }
  }
}

///|
fn add_prefixed_secret(
  text : String,
  out : Array[Candidate],
  prefix : String,
  min_total_length : Int,
  exact_length : Int?,
  label : String,
) -> Unit {
  let length = text.length()
  let mut search_from = 0
  while search_from < length {
    let tail = text[search_from:].to_owned()
    match tail.find(prefix) {
      Some(relative) => {
        let start = search_from + relative
        let mut end = start + prefix.length()
        while end < length && is_token_code(code_at(text, end)) {
          end = end + 1
        }
        let token_length = end - start
        let exact_ok = match exact_length {
          Some(expected) => token_length == expected
          None => true
        }
        if token_length >= min_total_length && exact_ok {
          let value = text[start:end].to_owned()
          out.push(
            candidate(
              "secret",
              label,
              "high",
              start,
              end,
              value[:4].to_owned() + "…" + value[token_length - 4:].to_owned(),
              "访问凭据一旦泄露可能导致账户或云资源被接管",
              130,
            ),
          )
        }
        search_from = if end > start { end } else { start + 1 }
      }
      None => return
    }
  }
}

///|
fn add_generic_secrets(text : String, out : Array[Candidate]) -> Unit {
  let lower = text.to_lower()
  let keywords = [
    "api_key", "apikey", "access_token", "token", "client_secret", "password", "passwd",
  ]
  for keyword in keywords {
    let mut search_from = 0
    while search_from < text.length() {
      let tail = lower[search_from:].to_owned()
      match tail.find(keyword) {
        Some(relative) => {
          let key_start = search_from + relative
          let mut start = key_start + keyword.length()
          while start < text.length() {
            let code = code_at(text, start)
            if code == 32 ||
              code == 9 ||
              code == 34 ||
              code == 39 ||
              code == 58 ||
              code == 61 {
              start = start + 1
            } else {
              break
            }
          }
          let mut end = start
          while end < text.length() && is_token_code(code_at(text, end)) {
            end = end + 1
          }
          if end - start >= 8 {
            let value = text[start:end].to_owned()
            out.push(
              candidate(
                "secret",
                "通用访问凭据",
                "high",
                start,
                end,
                value[:2].to_owned() +
                "…" +
                value[value.length() - 2:].to_owned(),
                "敏感字段名附近存在疑似明文凭据",
                125,
              ),
            )
          }
          search_from = if end > key_start {
            end
          } else {
            key_start + keyword.length()
          }
        }
        None => break
      }
    }
  }
}

///|
fn add_secrets(text : String, out : Array[Candidate]) -> Unit {
  add_prefixed_secret(text, out, "sk-", 20, None, "API 密钥")
  add_prefixed_secret(text, out, "AKIA", 20, Some(20), "云访问密钥")
  add_generic_secrets(text, out)
}

///|
fn accepted_candidates(candidates : Array[Candidate]) -> Array[Candidate] {
  candidates.sort_by(fn(a, b) {
    if a.start != b.start {
      a.start - b.start
    } else if a.priority != b.priority {
      b.priority - a.priority
    } else {
      b.end - b.start - (a.end - a.start)
    }
  })
  let accepted : Array[Candidate] = []
  let mut occupied_until = 0
  for item in candidates {
    if item.start >= occupied_until {
      accepted.push(item)
      occupied_until = item.end
    }
  }
  accepted
}

///|
fn redact(text : String, findings : Array[Finding]) -> String {
  let builder = StringBuilder::StringBuilder(size_hint=text.length())
  let mut cursor = 0
  for item in findings {
    if item.start > cursor {
      builder.write_substring(text, cursor, item.start - cursor)
    }
    builder.write_string(item.masked)
    cursor = item.end
  }
  if cursor < text.length() {
    builder.write_substring(text, cursor, text.length() - cursor)
  }
  builder.to_string()
}

///|
/// Detect supported sensitive data using the selected replacement mode.
pub fn scan_with_mode(text : String, requested_mode : String) -> ScanReport {
  let mode = if requested_mode == "tokenize" { "tokenize" } else { "mask" }
  let candidates : Array[Candidate] = []
  add_emails(text, candidates)
  add_digit_runs(text, candidates)
  add_ipv4(text, candidates)
  add_secrets(text, candidates)
  let accepted = accepted_candidates(candidates)
  let findings : Array[Finding] = []
  let mut high = 0
  let mut medium = 0
  let mut low = 0
  for item in accepted {
    let original = text[item.start:item.end].to_owned()
    let replacement = replacement_for(item, original, mode)
    findings.push({
      category: item.category,
      label: item.label,
      risk: item.risk,
      start: item.start,
      end: item.end,
      original,
      masked: replacement,
      reason: item.reason,
    })
    match item.risk {
      "high" => high = high + 1
      "medium" => medium = medium + 1
      _ => low = low + 1
    }
  }
  let verdict = if high > 0 {
    {
      level: "block",
      label: "建议阻止外发",
      message: "发现高风险身份信息或访问凭据，请完成替换并人工复核后再发送。",
      can_export: false,
    }
  } else if medium > 0 {
    {
      level: "review",
      label: "需要人工复核",
      message: "发现可能关联个人身份的信息，建议确认接收方是否确有需要。",
      can_export: false,
    }
  } else {
    {
      level: "safe",
      label: "可以生成外发副本",
      message: "未发现高、中风险信息，仍建议在正式发送前快速浏览结果。",
      can_export: true,
    }
  }
  {
    version: engine_version(),
    mode,
    input_length: text.length(),
    findings,
    summary: { total: findings.length(), high, medium, low },
    verdict,
    masked_text: redact(text, findings),
  }
}

///|
/// Detect supported sensitive data using star masking.
pub fn scan(text : String) -> ScanReport {
  scan_with_mode(text, "mask")
}
