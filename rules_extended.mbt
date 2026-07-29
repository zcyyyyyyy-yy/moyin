///|
const CN_PROVINCE_PREFIXES : String = "京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼"

///|
fn is_hex_code(code : Int) -> Bool {
  is_digit_code(code) ||
  (code >= 65 && code <= 70) ||
  (code >= 97 && code <= 102)
}

///|
fn is_base64url_code(code : Int) -> Bool {
  is_ascii_alnum(code) || code == 45 || code == 95
}

///|
fn is_ascii_space_code(code : Int) -> Bool {
  code == 9 || code == 10 || code == 13 || code == 32
}

///|
fn has_left_token_boundary(text : String, start : Int) -> Bool {
  start == 0 || !is_ascii_alnum(code_at(text, start - 1))
}

///|
fn has_right_token_boundary(text : String, end : Int) -> Bool {
  end >= text.length() || !is_ascii_alnum(code_at(text, end))
}

///|
fn add_landlines(text : String, out : Array[Candidate]) -> Unit {
  let length = text.length()
  let mut cursor = 0
  while cursor < length {
    if code_at(text, cursor) == ASCII_ZERO &&
      has_left_token_boundary(text, cursor) {
      let start = cursor
      while cursor < length && is_digit_code(code_at(text, cursor)) {
        cursor = cursor + 1
      }
      let area_length = cursor - start
      if area_length >= 3 &&
        area_length <= 4 &&
        cursor < length &&
        (code_at(text, cursor) == 45 || code_at(text, cursor) == 32) {
        let separator = cursor
        cursor = cursor + 1
        let subscriber_start = cursor
        while cursor < length && is_digit_code(code_at(text, cursor)) {
          cursor = cursor + 1
        }
        let subscriber_length = cursor - subscriber_start
        if subscriber_length >= 7 &&
          subscriber_length <= 8 &&
          has_right_token_boundary(text, cursor) {
          let area = text[start:separator].to_owned()
          let subscriber = text[subscriber_start:cursor].to_owned()
          out.push(
            candidate(
              "landline",
              "固定电话号码",
              "medium",
              start,
              cursor,
              area + "-****" + subscriber[subscriber.length() - 4:].to_owned(),
              "固定电话号码可用于联系个人、家庭或定位所属地区",
              priority_for_category("landline"),
            ),
          )
        }
      }
      if cursor == start {
        cursor = cursor + 1
      }
    } else {
      cursor = cursor + 1
    }
  }
}

///|
fn plate_tail_valid(text : String, start : Int, count : Int) -> Bool {
  if start + count > text.length() {
    return false
  }
  for index = start; index < start + count; index = index + 1 {
    let code = code_at(text, index)
    if !is_ascii_alnum(code) {
      return false
    }
  }
  true
}

///|
fn province_prefix_at(text : String, index : Int) -> Bool {
  if index >= text.length() {
    return false
  }
  CN_PROVINCE_PREFIXES.contains(text[index:index + 1])
}

///|
fn add_vehicle_plates(text : String, out : Array[Candidate]) -> Unit {
  let length = text.length()
  let mut cursor = 0
  while cursor + 7 <= length {
    if province_prefix_at(text, cursor) &&
      has_left_token_boundary(text, cursor) &&
      is_ascii_letter(code_at(text, cursor + 1)) {
      let normal_end = cursor + 7
      let energy_end = cursor + 8
      let normal_valid = plate_tail_valid(text, cursor + 2, 5)
      let energy_valid = plate_tail_valid(text, cursor + 2, 6)
      let end = if energy_valid && has_right_token_boundary(text, energy_end) {
        energy_end
      } else if normal_valid && has_right_token_boundary(text, normal_end) {
        normal_end
      } else {
        cursor
      }
      if end > cursor {
        let value = text[cursor:end].to_owned()
        out.push(
          candidate(
            "vehicle_plate",
            "中国机动车号牌",
            "medium",
            cursor,
            end,
            value[:2].to_owned() +
            "·***" +
            value[value.length() - 2:].to_owned(),
            "机动车号牌可以关联车辆所有人及出行记录",
            priority_for_category("vehicle_plate"),
          ),
        )
        cursor = end
      } else {
        cursor = cursor + 1
      }
    } else {
      cursor = cursor + 1
    }
  }
}

///|
fn mac_at(text : String, start : Int) -> Bool {
  if start + 17 > text.length() {
    return false
  }
  let separator = code_at(text, start + 2)
  if separator != 58 && separator != 45 {
    return false
  }
  for offset = 0; offset < 17; offset = offset + 1 {
    let position = offset % 3
    let code = code_at(text, start + offset)
    if position == 2 {
      if code != separator {
        return false
      }
    } else if !is_hex_code(code) {
      return false
    }
  }
  true
}

///|
fn add_mac_addresses(text : String, out : Array[Candidate]) -> Unit {
  let mut cursor = 0
  while cursor + 17 <= text.length() {
    let end = cursor + 17
    if mac_at(text, cursor) &&
      has_left_token_boundary(text, cursor) &&
      has_right_token_boundary(text, end) {
      let value = text[cursor:end].to_owned()
      out.push(
        candidate(
          "mac",
          "MAC 地址",
          "low",
          cursor,
          end,
          value[:8].to_owned() + ":**:**:**",
          "硬件地址可能用于识别局域网设备或追踪终端",
          priority_for_category("mac"),
        ),
      )
      cursor = end
    } else {
      cursor = cursor + 1
    }
  }
}

///|
fn jwt_candidate_end(text : String, start : Int) -> Int {
  if start + 3 > text.length() || !text[start:].has_prefix("eyJ") {
    return start
  }
  let mut cursor = start
  let mut dots = 0
  let mut segment_length = 0
  let mut shortest_segment = 1000000
  while cursor < text.length() {
    let code = code_at(text, cursor)
    if is_base64url_code(code) {
      segment_length = segment_length + 1
      cursor = cursor + 1
    } else if code == 46 && dots < 2 && segment_length > 0 {
      shortest_segment = Int::min(shortest_segment, segment_length)
      segment_length = 0
      dots = dots + 1
      cursor = cursor + 1
    } else {
      break
    }
  }
  shortest_segment = Int::min(shortest_segment, segment_length)
  if dots == 2 && shortest_segment >= 8 && cursor - start >= 40 {
    cursor
  } else {
    start
  }
}

///|
fn add_jwt_tokens(text : String, out : Array[Candidate]) -> Unit {
  let mut cursor = 0
  while cursor + 3 <= text.length() {
    if text[cursor:].has_prefix("eyJ") && has_left_token_boundary(text, cursor) {
      let end = jwt_candidate_end(text, cursor)
      if end > cursor && has_right_token_boundary(text, end) {
        let value = text[cursor:end].to_owned()
        out.push(
          candidate(
            "jwt",
            "JWT 访问令牌",
            "high",
            cursor,
            end,
            value[:8].to_owned() + "…" + value[value.length() - 6:].to_owned(),
            "JWT 可能携带身份声明并允许访问受保护接口",
            priority_for_category("jwt"),
          ),
        )
        cursor = end
      } else {
        cursor = cursor + 1
      }
    } else {
      cursor = cursor + 1
    }
  }
}

///|
fn url_authority_end(text : String, start : Int) -> Int {
  let mut cursor = start
  while cursor < text.length() {
    let code = code_at(text, cursor)
    if is_ascii_space_code(code) ||
      code == 34 ||
      code == 39 ||
      code == 60 ||
      code == 62 {
      break
    }
    cursor = cursor + 1
  }
  cursor
}

///|
fn add_url_credentials(text : String, out : Array[Candidate]) -> Unit {
  let mut search_from = 0
  while search_from < text.length() {
    let tail = text[search_from:].to_owned()
    match tail.find("://") {
      Some(relative) => {
        let authority_start = search_from + relative + 3
        let authority_end = url_authority_end(text, authority_start)
        let authority = text[authority_start:authority_end].to_owned()
        match authority.find("@") {
          Some(at) =>
            match authority[:at].find(":") {
              Some(colon) => {
                let credential_end = authority_start + at
                let password_start = authority_start + colon + 1
                if password_start < credential_end {
                  let username = text[authority_start:authority_start + colon].to_owned()
                  out.push(
                    candidate(
                      "url_credential",
                      "URL 内嵌凭据",
                      "high",
                      authority_start,
                      credential_end,
                      username + ":******",
                      "URL 中包含的用户名和密码容易被日志、历史记录或监控系统收集",
                      priority_for_category("url_credential"),
                    ),
                  )
                }
              }
              None => ()
            }
          None => ()
        }
        search_from = if authority_end > authority_start {
          authority_end
        } else {
          authority_start
        }
      }
      None => break
    }
  }
}

///|
fn line_end_after(text : String, start : Int) -> Int {
  let mut cursor = start
  while cursor < text.length() &&
        code_at(text, cursor) != 10 &&
        code_at(text, cursor) != 13 {
    cursor = cursor + 1
  }
  cursor
}

///|
fn add_private_keys(text : String, out : Array[Candidate]) -> Unit {
  let begin_marker = "-----BEGIN "
  let mut search_from = 0
  while search_from < text.length() {
    let tail = text[search_from:].to_owned()
    match tail.find(begin_marker) {
      Some(relative) => {
        let start = search_from + relative
        let header_end = line_end_after(text, start)
        let header = text[start:header_end].to_owned()
        if header.contains("PRIVATE KEY-----") {
          let end_marker_start = text[header_end:].find("-----END ")
          let end = match end_marker_start {
            Some(offset) => line_end_after(text, header_end + offset)
            None => header_end
          }
          out.push(
            candidate(
              "private_key",
              "私钥材料",
              "high",
              start,
              end,
              "[REDACTED PRIVATE KEY]",
              "私钥泄露会导致签名身份、服务器或加密资产被直接接管",
              priority_for_category("private_key"),
            ),
          )
          search_from = if end > start { end } else { header_end }
        } else {
          search_from = header_end
        }
      }
      None => break
    }
  }
}

///|
fn add_custom_terms(
  text : String,
  terms : Array[String],
  out : Array[Candidate],
) -> Unit {
  if terms.is_empty() {
    return
  }
  let lower = text.to_lower()
  for term in terms {
    let normalized = term.trim().to_owned()
    if normalized.is_empty() {
      continue
    }
    let needle = normalized.to_lower()
    let mut search_from = 0
    while search_from < text.length() {
      let tail = lower[search_from:].to_owned()
      match tail.find(needle) {
        Some(relative) => {
          let start = search_from + relative
          let end = start + normalized.length()
          out.push(
            candidate(
              "custom",
              "自定义敏感词",
              "medium",
              start,
              end,
              "[CUSTOM_REDACTED]",
              "该内容命中了调用者配置的自定义敏感规则",
              priority_for_category("custom"),
            ),
          )
          search_from = if end > start { end } else { start + 1 }
        }
        None => break
      }
    }
  }
}
