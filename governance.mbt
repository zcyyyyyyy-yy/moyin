///|
/// A privacy-safe fingerprint representing one distinct sensitive value.
///
/// The source value is deliberately omitted. `anonymous_id` is deterministic
/// only within the caller-provided salt scope.
pub struct PrivacyFingerprint {
  category : String
  label : String
  risk : String
  anonymous_id : String
  occurrences : Int
} derive(ToJson, Debug, Eq)

///|
/// Aggregate inventory suitable for CI artifacts and long-term storage.
pub struct PrivacyInventory {
  input_length : Int
  finding_total : Int
  unique_total : Int
  risk_score : Int
  fingerprints : Array[PrivacyFingerprint]
  categories : Array[CategorySummary]
} derive(ToJson, Debug, Eq)

///|
/// Policy controlling whether a privacy drift should block delivery.
pub struct DriftPolicy {
  block_new_high : Bool
  max_new_medium : Int
  max_score_increase : Int
  ignored_categories : Array[String]
} derive(ToJson, Debug, Eq)

///|
/// One distinct value whose presence changed between two scans.
pub struct DriftItem {
  change : String
  category : String
  label : String
  risk : String
  anonymous_id : String
  before_count : Int
  after_count : Int
  delta : Int
} derive(ToJson, Debug, Eq)

///|
/// Machine-readable CI decision for a privacy drift.
pub struct DriftDecision {
  level : String
  label : String
  allowed : Bool
  reasons : Array[String]
} derive(ToJson, Debug, Eq)

///|
/// Comparison between a baseline and a candidate scan.
pub struct PrivacyDriftReport {
  version : String
  baseline : PrivacyInventory
  candidate : PrivacyInventory
  new_values : Int
  resolved_values : Int
  persistent_values : Int
  added_occurrences : Int
  removed_occurrences : Int
  score_delta : Int
  changes : Array[DriftItem]
  decision : DriftDecision
} derive(ToJson, Debug, Eq)

///|
/// Conservative defaults for release and pull-request gates.
pub fn default_drift_policy() -> DriftPolicy {
  {
    block_new_high: true,
    max_new_medium: 3,
    max_score_increase: 20,
    ignored_categories: [],
  }
}

///|
/// Build a custom drift policy for CI or release workflows.
pub fn drift_policy(
  block_new_high : Bool,
  max_new_medium : Int,
  max_score_increase : Int,
  ignored_categories : Array[String],
) -> DriftPolicy {
  {
    block_new_high,
    max_new_medium: Int::max(0, max_new_medium),
    max_score_increase: Int::max(0, max_score_increase),
    ignored_categories,
  }
}

///|
fn risk_weight(risk : String) -> Int {
  if risk == "high" {
    10
  } else if risk == "medium" {
    4
  } else {
    1
  }
}

///|
fn ignored_by_policy(policy : DriftPolicy, category : String) -> Bool {
  for ignored in policy.ignored_categories {
    if ignored == category {
      return true
    }
  }
  false
}

///|
fn finding_occurrences(
  findings : Array[Finding],
  category : String,
  original : String,
) -> Int {
  let mut count = 0
  for finding in findings {
    if finding.category == category && finding.original == original {
      count = count + 1
    }
  }
  count
}

///|
fn finding_seen_before(
  findings : Array[Finding],
  end_index : Int,
  category : String,
  original : String,
) -> Bool {
  for index = 0; index < end_index; index = index + 1 {
    let finding = findings[index]
    if finding.category == category && finding.original == original {
      return true
    }
  }
  false
}

///|
/// Convert a normal scan report into a privacy-safe inventory.
///
/// Inventories can be committed or retained as CI artifacts because they never
/// include the original sensitive values or their masked previews.
pub fn build_privacy_inventory(
  report : ScanReport,
  fingerprint_salt : String,
) -> PrivacyInventory {
  let fingerprints : Array[PrivacyFingerprint] = []
  let mut score = 0
  for index = 0; index < report.findings.length(); index = index + 1 {
    let finding = report.findings[index]
    score = score + risk_weight(finding.risk)
    if !finding_seen_before(
        report.findings,
        index,
        finding.category,
        finding.original,
      ) {
      fingerprints.push({
        category: finding.category,
        label: finding.label,
        risk: finding.risk,
        anonymous_id: "mi_" +
        finding.category +
        "_" +
        stable_code(finding.original, fingerprint_salt),
        occurrences: finding_occurrences(
          report.findings,
          finding.category,
          finding.original,
        ),
      })
    }
  }
  {
    input_length: report.input_length,
    finding_total: report.summary.total,
    unique_total: fingerprints.length(),
    risk_score: score,
    fingerprints,
    categories: report.categories,
  }
}

///|
fn inventory_index(
  inventory : PrivacyInventory,
  category : String,
  anonymous_id : String,
) -> Int {
  for index = 0; index < inventory.fingerprints.length(); index = index + 1 {
    let item = inventory.fingerprints[index]
    if item.category == category && item.anonymous_id == anonymous_id {
      return index
    }
  }
  -1
}

///|
fn drift_item(
  change : String,
  item : PrivacyFingerprint,
  before_count : Int,
  after_count : Int,
) -> DriftItem {
  {
    change,
    category: item.category,
    label: item.label,
    risk: item.risk,
    anonymous_id: item.anonymous_id,
    before_count,
    after_count,
    delta: after_count - before_count,
  }
}

///|
fn drift_decision(
  policy : DriftPolicy,
  changes : Array[DriftItem],
  score_delta : Int,
) -> DriftDecision {
  let reasons : Array[String] = []
  let mut new_high = 0
  let mut new_medium = 0
  for item in changes {
    if ignored_by_policy(policy, item.category) {
      continue
    }
    if (item.change == "new" || item.change == "increased") && item.delta > 0 {
      if item.risk == "high" {
        new_high = new_high + item.delta
      } else if item.risk == "medium" {
        new_medium = new_medium + item.delta
      }
    }
  }
  if policy.block_new_high && new_high > 0 {
    reasons.push("新增 " + new_high.to_string() + " 处高风险敏感信息")
  }
  if new_medium > policy.max_new_medium {
    reasons.push(
      "新增中风险信息 " +
      new_medium.to_string() +
      " 处，超过策略上限 " +
      policy.max_new_medium.to_string(),
    )
  }
  if score_delta > policy.max_score_increase {
    reasons.push(
      "风险分增加 " +
      score_delta.to_string() +
      "，超过策略上限 " +
      policy.max_score_increase.to_string(),
    )
  }
  if !reasons.is_empty() {
    {
      level: "block",
      label: "隐私基线检查未通过",
      allowed: false,
      reasons,
    }
  } else if score_delta > 0 {
    {
      level: "review",
      label: "风险有所增加，建议复核",
      allowed: true,
      reasons: ["新增风险仍在当前策略允许范围内"],
    }
  } else {
    {
      level: "pass",
      label: "隐私基线检查通过",
      allowed: true,
      reasons: ["未发现超出基线的敏感信息风险"],
    }
  }
}

///|
/// Compare two completed scans without retaining original sensitive values.
pub fn compare_privacy_reports(
  baseline_report : ScanReport,
  candidate_report : ScanReport,
  fingerprint_salt : String,
  policy : DriftPolicy,
) -> PrivacyDriftReport {
  let baseline = build_privacy_inventory(baseline_report, fingerprint_salt)
  let candidate = build_privacy_inventory(candidate_report, fingerprint_salt)
  let changes : Array[DriftItem] = []
  let mut new_values = 0
  let mut resolved_values = 0
  let mut persistent_values = 0
  let mut added_occurrences = 0
  let mut removed_occurrences = 0
  for current in candidate.fingerprints {
    let previous_index = inventory_index(
      baseline,
      current.category,
      current.anonymous_id,
    )
    if previous_index < 0 {
      new_values = new_values + 1
      added_occurrences = added_occurrences + current.occurrences
      changes.push(drift_item("new", current, 0, current.occurrences))
    } else {
      persistent_values = persistent_values + 1
      let previous = baseline.fingerprints[previous_index]
      if current.occurrences > previous.occurrences {
        added_occurrences = added_occurrences +
          current.occurrences -
          previous.occurrences
        changes.push(
          drift_item(
            "increased",
            current,
            previous.occurrences,
            current.occurrences,
          ),
        )
      } else if current.occurrences < previous.occurrences {
        removed_occurrences = removed_occurrences +
          previous.occurrences -
          current.occurrences
        changes.push(
          drift_item(
            "decreased",
            current,
            previous.occurrences,
            current.occurrences,
          ),
        )
      } else {
        changes.push(
          drift_item(
            "persistent",
            current,
            previous.occurrences,
            current.occurrences,
          ),
        )
      }
    }
  }
  for previous in baseline.fingerprints {
    if inventory_index(candidate, previous.category, previous.anonymous_id) < 0 {
      resolved_values = resolved_values + 1
      removed_occurrences = removed_occurrences + previous.occurrences
      changes.push(drift_item("resolved", previous, previous.occurrences, 0))
    }
  }
  let score_delta = candidate.risk_score - baseline.risk_score
  {
    version: engine_version(),
    baseline,
    candidate,
    new_values,
    resolved_values,
    persistent_values,
    added_occurrences,
    removed_occurrences,
    score_delta,
    changes,
    decision: drift_decision(policy, changes, score_delta),
  }
}

///|
/// Scan and compare two texts with default detection and drift policies.
pub fn compare_privacy_texts(
  baseline_text : String,
  candidate_text : String,
  fingerprint_salt : String,
) -> PrivacyDriftReport {
  compare_privacy_reports(
    scan(baseline_text),
    scan(candidate_text),
    fingerprint_salt,
    default_drift_policy(),
  )
}
