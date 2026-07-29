///|
/// Runtime configuration for a scan.
///
/// An empty `enabled_categories` array enables every built-in rule. Custom
/// terms are exact literals and are reported under the `custom` category.
pub struct ScanConfig {
  mode : String
  salt : String
  enabled_categories : Array[String]
  custom_terms : Array[String]
  include_low_risk : Bool
  max_findings : Int
  chunk_size : Int
} derive(ToJson, Debug, Eq)

///|
/// Public metadata for one built-in rule.
pub struct RuleInfo {
  category : String
  label : String
  risk : String
  description : String
  enabled_by_default : Bool
} derive(ToJson, Debug, Eq)

///|
/// Per-category counts included in a scan report.
pub struct CategorySummary {
  category : String
  label : String
  count : Int
} derive(ToJson, Debug, Eq)

///|
/// Sensible defaults for interactive and CLI scans.
pub fn default_config() -> ScanConfig {
  {
    mode: "mask",
    salt: "",
    enabled_categories: [],
    custom_terms: [],
    include_low_risk: true,
    max_findings: 10000,
    chunk_size: 65536,
  }
}

///|
/// Normalize user-provided options so internal scanners can rely on invariants.
fn normalize_config(config : ScanConfig) -> ScanConfig {
  let mode = if config.mode == "tokenize" { "tokenize" } else { "mask" }
  let max_findings = if config.max_findings <= 0 {
    10000
  } else if config.max_findings > 100000 {
    100000
  } else {
    config.max_findings
  }
  let chunk_size = if config.chunk_size <= 0 {
    65536
  } else if config.chunk_size < 1024 {
    1024
  } else {
    config.chunk_size
  }
  {
    mode,
    salt: config.salt,
    enabled_categories: config.enabled_categories,
    custom_terms: config.custom_terms,
    include_low_risk: config.include_low_risk,
    max_findings,
    chunk_size,
  }
}

///|
fn category_enabled(config : ScanConfig, category : String) -> Bool {
  if config.enabled_categories.is_empty() {
    return true
  }
  for enabled in config.enabled_categories {
    if enabled == category {
      return true
    }
  }
  false
}

///|
/// Metadata for all rules currently shipped with the engine.
pub fn available_rules() -> Array[RuleInfo] {
  [
    {
      category: "phone",
      label: "手机号码",
      risk: "high",
      description: "中国大陆 11 位手机号码，校验号段边界",
      enabled_by_default: true,
    },
    {
      category: "landline",
      label: "固定电话号码",
      risk: "medium",
      description: "带区号和分隔符的中国大陆固定电话号码",
      enabled_by_default: true,
    },
    {
      category: "email",
      label: "电子邮箱",
      risk: "medium",
      description: "常见 RFC 风格电子邮箱地址",
      enabled_by_default: true,
    },
    {
      category: "cn_id",
      label: "中国居民身份证号",
      risk: "high",
      description: "18 位居民身份证号码并验证校验位",
      enabled_by_default: true,
    },
    {
      category: "bank_card",
      label: "银行卡号",
      risk: "high",
      description: "16 至 19 位支付卡号并执行 Luhn 校验",
      enabled_by_default: true,
    },
    {
      category: "vehicle_plate",
      label: "中国机动车号牌",
      risk: "medium",
      description: "普通及新能源机动车号牌",
      enabled_by_default: true,
    },
    {
      category: "ipv4",
      label: "IPv4 地址",
      risk: "low",
      description: "四段十进制 IPv4 地址并校验每段范围",
      enabled_by_default: true,
    },
    {
      category: "mac",
      label: "MAC 地址",
      risk: "low",
      description: "六组十六进制硬件地址",
      enabled_by_default: true,
    },
    {
      category: "jwt",
      label: "JWT 访问令牌",
      risk: "high",
      description: "由三个 Base64URL 段组成的 JSON Web Token",
      enabled_by_default: true,
    },
    {
      category: "secret",
      label: "访问凭据",
      risk: "high",
      description: "API Key、云密钥和敏感键值字段",
      enabled_by_default: true,
    },
    {
      category: "url_credential",
      label: "URL 内嵌凭据",
      risk: "high",
      description: "数据库或网络 URL 中的用户名和密码",
      enabled_by_default: true,
    },
    {
      category: "private_key",
      label: "私钥材料",
      risk: "high",
      description: "PEM 私钥头及其所在敏感行",
      enabled_by_default: true,
    },
    {
      category: "custom",
      label: "自定义敏感词",
      risk: "medium",
      description: "由调用者提供的精确文本规则",
      enabled_by_default: true,
    },
  ]
}

///|
fn priority_for_category(category : String) -> Int {
  match category {
    "private_key" => 160
    "url_credential" => 150
    "jwt" => 145
    "secret" => 140
    "cn_id" => 130
    "bank_card" => 120
    "phone" => 100
    "vehicle_plate" => 90
    "email" => 80
    "landline" => 70
    "custom" => 65
    "mac" => 55
    "ipv4" => 50
    _ => 10
  }
}

///|
fn split_non_empty(value : String, separator : String) -> Array[String] {
  let output : Array[String] = []
  for part in value.split(separator) {
    let item = part.trim()
    if !item.is_empty() {
      output.push(item.to_owned())
    }
  }
  output
}

///|
/// Build a configuration from strings that are convenient to pass through a
/// JavaScript or C FFI boundary.
pub fn config_from_strings(
  mode : String,
  salt : String,
  categories_csv : String,
  custom_terms_lines : String,
  include_low_risk : Bool,
  max_findings : Int,
  chunk_size : Int,
) -> ScanConfig {
  normalize_config({
    mode,
    salt,
    enabled_categories: split_non_empty(categories_csv, ","),
    custom_terms: split_non_empty(custom_terms_lines, "\n"),
    include_low_risk,
    max_findings,
    chunk_size,
  })
}
