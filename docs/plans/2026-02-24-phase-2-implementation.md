# Phase 2: Multi-Scanner Intelligence — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add JFrog Xray (SCA) and Tenable WAS (DAST) parsers, build the correlation engine and cross-tool deduplication, implement the 5-factor composite risk score with real data, and deliver three new UI views — Deduplication Dashboard, Correlation Page, and Attack Chains.

**Architecture:** Extends the existing Parser trait and ingestion pipeline with two new parsers, adds a configurable app code resolver for extracting application identifiers from scanner-specific fields, builds relationship-based cross-tool dedup and correlation on top of the existing `finding_relationships` table, and delivers three new frontend pages with TanStack Router/Table. All backend services follow the existing thin-routes → services → models pattern.

**Tech Stack:** Rust/Axum/SQLx (backend), React/TypeScript/TanStack Router+Table/shadcn-ui (frontend), PostgreSQL (DB), `regex` crate (app code patterns), `csv`/`serde_json` (parsing)

---

## Task 1: Database Migration

**Files:**
- Create: `backend/migrations/002_correlation_and_app_patterns.sql`

**Step 1: Write the migration file**

```sql
-- Phase 2: Correlation rules + app code patterns

-- ============================================================
-- CORRELATION RULES TABLE
-- ============================================================

CREATE TABLE correlation_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    rule_type   VARCHAR(50) NOT NULL,
    conditions  JSONB NOT NULL,
    confidence  confidence_level NOT NULL DEFAULT 'Medium',
    is_active   BOOLEAN NOT NULL DEFAULT true,
    priority    INTEGER NOT NULL DEFAULT 0,
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_correlation_rules_updated_at
    BEFORE UPDATE ON correlation_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================
-- APP CODE PATTERNS TABLE
-- ============================================================

CREATE TABLE app_code_patterns (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_tool     VARCHAR(100) NOT NULL,
    field_name      VARCHAR(100) NOT NULL,
    regex_pattern   TEXT NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 0,
    description     TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_app_code_patterns_updated_at
    BEFORE UPDATE ON app_code_patterns
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================
-- SEED: DEFAULT CORRELATION RULES (CR-1 through CR-6)
-- ============================================================

INSERT INTO correlation_rules (name, description, rule_type, conditions, confidence, priority) VALUES
(
    'CR-1: Same CVE cross-category (SCA↔DAST)',
    'SCA reports vulnerable dependency; DAST confirms it is exploitable at a reachable endpoint. Both reference the same CVE.',
    'cross_tool',
    '{"match_on": "cve_id", "categories": ["SCA", "DAST"], "same_application": true}'::JSONB,
    'High',
    10
),
(
    'CR-2: Same CWE cross-category (SAST↔DAST)',
    'SAST finds code weakness; DAST confirms exploitability at an endpoint. Uses production-branch SAST findings.',
    'cross_tool',
    '{"match_on": "cwe_id", "categories": ["SAST", "DAST"], "same_application": true, "sast_branch": "production"}'::JSONB,
    'Medium',
    9
),
(
    'CR-3: SCA vulnerable package matched to SAST file imports',
    'SCA flags a vulnerable library; SAST finds code that imports/uses that library. Uses production-branch SAST findings.',
    'cross_tool',
    '{"match_on": "package_to_import", "categories": ["SCA", "SAST"], "same_application": true, "sast_branch": "production"}'::JSONB,
    'Medium',
    8
),
(
    'CR-4: DAST endpoint matched to SAST handler',
    'DAST finds vulnerability at a URL; SAST found weakness in the code handling that route. Uses production-branch SAST findings.',
    'cross_tool',
    '{"match_on": "url_to_handler", "categories": ["DAST", "SAST"], "same_application": true, "sast_branch": "production"}'::JSONB,
    'Medium',
    7
),
(
    'CR-5: Same rule_id across multiple files (SAST pattern)',
    'Systemic pattern: the same code weakness repeated across multiple files in one application. Operates within each branch independently.',
    'intra_tool',
    '{"match_on": "rule_id_multi_file", "categories": ["SAST"], "same_application": true, "same_branch": true}'::JSONB,
    'High',
    6
),
(
    'CR-6: Same CWE in same file (SAST cluster)',
    'Multiple weaknesses of the same class concentrated in one file. Operates within each branch independently.',
    'intra_tool',
    '{"match_on": "cwe_same_file", "categories": ["SAST"], "same_application": true, "same_branch": true}'::JSONB,
    'High',
    5
);

-- ============================================================
-- SEED: DEFAULT APP CODE PATTERNS
-- ============================================================

INSERT INTO app_code_patterns (source_tool, field_name, regex_pattern, priority, description) VALUES
('JFrog Xray', 'path', '^[^/]+/(?P<app_code>[^/]+)/', 10, 'Second segment of repo path'),
('JFrog Xray', 'impacted_artifact', 'gav://com\.\w+\.(?P<app_code>\w+):', 5, 'Third segment of GAV groupId'),
('Tenable WAS', 'DNS Name', '^[st](?P<app_code>[^.]+)\.', 10, 'Strip s/t env prefix from subdomain'),
('Tenable WAS', 'DNS Name', '^(?P<app_code>[^.]+)\.', 5, 'Full first subdomain (fallback, no strip)'),
('Tenable WAS', 'URL', 'https?://[st](?P<app_code>[^.]+)\.', 10, 'Strip s/t env prefix from URL subdomain'),
('Tenable WAS', 'URL', 'https?://(?P<app_code>[^.]+)\.', 5, 'Full subdomain from URL (fallback)');
```

**Step 2: Verify migration compiles**

Run: `cd /home/marco/Programming/FullStack/synapsec/backend && cargo sqlx migrate run`
Expected: Migration applied successfully (or if no DB available, at least `cargo build` succeeds with the new migration file present).

**Step 3: Add models for the new tables**

Create `backend/src/models/correlation_rule.rs`:

```rust
//! Correlation rule model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::models::finding::ConfidenceLevel;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CorrelationRule {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub rule_type: String,
    pub conditions: serde_json::Value,
    pub confidence: ConfidenceLevel,
    pub is_active: bool,
    pub priority: i32,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateCorrelationRule {
    pub name: String,
    pub description: Option<String>,
    pub rule_type: String,
    pub conditions: serde_json::Value,
    pub confidence: Option<ConfidenceLevel>,
    pub priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateCorrelationRule {
    pub name: Option<String>,
    pub description: Option<String>,
    pub rule_type: Option<String>,
    pub conditions: Option<serde_json::Value>,
    pub confidence: Option<ConfidenceLevel>,
    pub is_active: Option<bool>,
    pub priority: Option<i32>,
}
```

Create `backend/src/models/app_code_pattern.rs`:

```rust
//! App code pattern model for configurable regex-based app code extraction.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AppCodePattern {
    pub id: Uuid,
    pub source_tool: String,
    pub field_name: String,
    pub regex_pattern: String,
    pub priority: i32,
    pub description: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

Register both models in `backend/src/models/mod.rs` (add `pub mod correlation_rule;` and `pub mod app_code_pattern;`).

**Step 4: Add `regex` dependency to Cargo.toml**

Add `regex = "1"` to `[dependencies]` in `backend/Cargo.toml`.

**Step 5: Run cargo check**

Run: `cargo check`
Expected: Compiles with no errors.

**Step 6: Commit**

```bash
git add backend/migrations/002_correlation_and_app_patterns.sql \
        backend/src/models/correlation_rule.rs \
        backend/src/models/app_code_pattern.rs \
        backend/src/models/mod.rs \
        backend/Cargo.toml backend/Cargo.lock
git commit -m "feat: add Phase 2 migration, correlation rule and app code pattern models"
```

---

## Task 2: App Code Resolver Service

**Files:**
- Create: `backend/src/services/app_code_resolver.rs`
- Modify: `backend/src/services/mod.rs` (add `pub mod app_code_resolver;`)

**Step 1: Write the failing test**

In `backend/src/services/app_code_resolver.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_resolves_from_path() {
        let patterns = vec![
            PatternEntry {
                field_name: "path".to_string(),
                regex_pattern: r"^[^/]+/(?P<app_code>[^/]+)/".to_string(),
                priority: 10,
            },
        ];
        let fields = vec![
            ("path".to_string(), "prod-release-local/gpe30/gpe30-set/v1.2.0-rc1/set-ear.ear".to_string()),
        ];
        let result = resolve(&patterns, &fields);
        assert_eq!(result, Some("gpe30".to_string()));
    }

    #[test]
    fn xray_resolves_from_gav() {
        let patterns = vec![
            PatternEntry {
                field_name: "impacted_artifact".to_string(),
                regex_pattern: r"gav://com\.\w+\.(?P<app_code>\w+):".to_string(),
                priority: 5,
            },
        ];
        let fields = vec![
            ("impacted_artifact".to_string(), "gav://com.ourcompany.gpe30:set-ear:0.0.1".to_string()),
        ];
        let result = resolve(&patterns, &fields);
        assert_eq!(result, Some("gpe30".to_string()));
    }

    #[test]
    fn tenable_strips_env_prefix() {
        let patterns = vec![
            PatternEntry {
                field_name: "DNS Name".to_string(),
                regex_pattern: r"^[st](?P<app_code>[^.]+)\.".to_string(),
                priority: 10,
            },
            PatternEntry {
                field_name: "DNS Name".to_string(),
                regex_pattern: r"^(?P<app_code>[^.]+)\.".to_string(),
                priority: 5,
            },
        ];
        let fields = vec![
            ("DNS Name".to_string(), "sacronym.environment.env.domain.com".to_string()),
        ];
        let result = resolve(&patterns, &fields);
        assert_eq!(result, Some("acronym".to_string()));
    }

    #[test]
    fn tenable_no_prefix_uses_full_subdomain() {
        let patterns = vec![
            PatternEntry {
                field_name: "DNS Name".to_string(),
                regex_pattern: r"^[st](?P<app_code>[^.]+)\.".to_string(),
                priority: 10,
            },
            PatternEntry {
                field_name: "DNS Name".to_string(),
                regex_pattern: r"^(?P<app_code>[^.]+)\.".to_string(),
                priority: 5,
            },
        ];
        let fields = vec![
            ("DNS Name".to_string(), "myapp.environment.env.domain.com".to_string()),
        ];
        let result = resolve(&patterns, &fields);
        // Higher-priority pattern extracts "yapp" (strips 'm'... no, 'm' is not 's' or 't')
        // Actually [st] only matches s or t. 'myapp' starts with 'm' so pattern #1 won't match.
        // Falls through to pattern #2 which extracts "myapp".
        assert_eq!(result, Some("myapp".to_string()));
    }

    #[test]
    fn returns_none_when_no_match() {
        let patterns = vec![
            PatternEntry {
                field_name: "missing_field".to_string(),
                regex_pattern: r"(?P<app_code>\w+)".to_string(),
                priority: 10,
            },
        ];
        let fields = vec![
            ("other_field".to_string(), "some value".to_string()),
        ];
        let result = resolve(&patterns, &fields);
        assert_eq!(result, None);
    }

    #[test]
    fn priority_ordering_tries_highest_first() {
        let patterns = vec![
            PatternEntry {
                field_name: "path".to_string(),
                regex_pattern: r"^(?P<app_code>low_priority)".to_string(),
                priority: 1,
            },
            PatternEntry {
                field_name: "path".to_string(),
                regex_pattern: r"^[^/]+/(?P<app_code>[^/]+)/".to_string(),
                priority: 10,
            },
        ];
        let fields = vec![
            ("path".to_string(), "repo/appcode/rest".to_string()),
        ];
        let result = resolve(&patterns, &fields);
        assert_eq!(result, Some("appcode".to_string()));
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --lib services::app_code_resolver`
Expected: FAIL — module and functions not defined yet.

**Step 3: Write the implementation**

```rust
//! Configurable regex-based app code extraction from scanner fields.
//!
//! Tries patterns in priority order (highest first). The first match
//! with a non-empty `app_code` named capture group wins.

use regex::Regex;

/// A single app code extraction pattern (loaded from DB or test fixture).
#[derive(Debug, Clone)]
pub struct PatternEntry {
    pub field_name: String,
    pub regex_pattern: String,
    pub priority: i32,
}

/// Resolve an app code from a set of field name→value pairs using the given patterns.
///
/// Patterns are tried in descending priority order. Returns the first
/// non-empty `app_code` capture, or `None` if nothing matches.
pub fn resolve(patterns: &[PatternEntry], fields: &[(String, String)]) -> Option<String> {
    let mut sorted: Vec<&PatternEntry> = patterns.iter().collect();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

    for pattern in sorted {
        let re = match Regex::new(&pattern.regex_pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for (field_name, field_value) in fields {
            if field_name != &pattern.field_name {
                continue;
            }
            if let Some(caps) = re.captures(field_value) {
                if let Some(m) = caps.name("app_code") {
                    let code = m.as_str().to_string();
                    if !code.is_empty() {
                        return Some(code);
                    }
                }
            }
        }
    }

    None
}
```

**Step 4: Register module**

Add `pub mod app_code_resolver;` to `backend/src/services/mod.rs`.

**Step 5: Run tests to verify they pass**

Run: `cargo test --lib services::app_code_resolver`
Expected: All 6 tests PASS.

**Step 6: Commit**

```bash
git add backend/src/services/app_code_resolver.rs backend/src/services/mod.rs
git commit -m "feat: add configurable regex-based app code resolver service"
```

---

## Task 3: Add `ParserType` Variants and Update Ingestion Route

**Files:**
- Modify: `backend/src/services/ingestion.rs` (add `JfrogXray` and `TenableWas` to `ParserType`)
- Modify: `backend/src/parsers/mod.rs` (add module declarations)
- Modify: `backend/src/routes/ingestion.rs` (update error message)

**Step 1: Add parser type variants**

In `backend/src/services/ingestion.rs`, update the `ParserType` enum:

```rust
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ParserType {
    Sonarqube,
    Sarif,
    #[serde(rename = "jfrog_xray")]
    JfrogXray,
    #[serde(rename = "tenable_was")]
    TenableWas,
}
```

Update the `Display` impl:

```rust
impl std::fmt::Display for ParserType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sonarqube => write!(f, "sonarqube"),
            Self::Sarif => write!(f, "sarif"),
            Self::JfrogXray => write!(f, "jfrog_xray"),
            Self::TenableWas => write!(f, "tenable_was"),
        }
    }
}
```

Update the `ingest_file` parser selection to add placeholder arms (parsers will be implemented in Tasks 4–5):

```rust
let parser: Box<dyn Parser> = match parser_type {
    ParserType::Sonarqube => Box::new(SonarQubeParser::new()),
    ParserType::Sarif => Box::new(SarifParser::new()),
    ParserType::JfrogXray => Box::new(crate::parsers::jfrog_xray::JfrogXrayParser::new()),
    ParserType::TenableWas => Box::new(crate::parsers::tenable_was::TenableWasParser::new()),
};
```

**Step 2: Add module declarations in `parsers/mod.rs`**

Add to `backend/src/parsers/mod.rs`:

```rust
pub mod jfrog_xray;
pub mod tenable_was;
```

**Step 3: Create stub parser files**

Create `backend/src/parsers/jfrog_xray.rs` with a minimal struct that implements Parser (returning empty ParseResult for now). Same for `backend/src/parsers/tenable_was.rs`. These will be fleshed out in Tasks 4–5.

**Step 4: Update the ingestion route error message**

In `backend/src/routes/ingestion.rs`, update the parser_type validation error:

Change: `"Invalid parser_type '{text}'. Supported: sonarqube, sarif"`
To: `"Invalid parser_type '{text}'. Supported: sonarqube, sarif, jfrog_xray, tenable_was"`

**Step 5: Update existing tests**

In the `tests` module of `ingestion.rs`, add deserialization tests for the new variants:

```rust
#[test]
fn parser_type_jfrog_xray() {
    let pt: ParserType = serde_json::from_str("\"jfrog_xray\"").unwrap();
    assert_eq!(pt, ParserType::JfrogXray);
    assert_eq!(pt.to_string(), "jfrog_xray");
}

#[test]
fn parser_type_tenable_was() {
    let pt: ParserType = serde_json::from_str("\"tenable_was\"").unwrap();
    assert_eq!(pt, ParserType::TenableWas);
    assert_eq!(pt.to_string(), "tenable_was");
}
```

**Step 6: Run all tests**

Run: `cargo test`
Expected: All tests pass.

**Step 7: Commit**

```bash
git add backend/src/services/ingestion.rs backend/src/parsers/mod.rs \
        backend/src/parsers/jfrog_xray.rs backend/src/parsers/tenable_was.rs \
        backend/src/routes/ingestion.rs
git commit -m "feat: add JfrogXray and TenableWas parser type variants"
```

---

## Task 4: JFrog Xray Parser (SCA)

**Files:**
- Create: `backend/tests/fixtures/jfrog_xray_sample.json`
- Modify: `backend/src/parsers/jfrog_xray.rs`

**Step 1: Create test fixture**

Create `backend/tests/fixtures/jfrog_xray_sample.json` — a realistic test fixture derived from the real Xray export format. Include 5 records:
- 2 records for the same package with different CVEs (tests multi-CVE fan-out)
- 1 record with empty `fixed_versions` (tests no-fix handling)
- 1 record with transitive dependency (`impact_path` length 3+)
- 1 record with direct dependency (`impact_path` length 2)

Each record follows the real structure: `cves[]`, `cvss3_max_score`, `summary`, `severity`, `vulnerable_component` (GAV), `component_physical_path`, `impacted_artifact`, `impact_path[]`, `path`, `fixed_versions[]`, `published`, `artifact_scan_time`, `issue_id`, `package_type`, `provider`, `description`, `references[]`.

The `impacted_artifact` should use GAV format with app codes matching existing seed apps (e.g. `gav://com.ourcompany.APP01:set-ear:0.0.1`).

**Step 2: Write the failing tests**

In `backend/src/parsers/jfrog_xray.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_finds_all_records() {
        let parser = JfrogXrayParser::new();
        let data = include_bytes!("../../tests/fixtures/jfrog_xray_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        // 5 rows, but one has 2 CVEs → 6 findings (one per CVE)
        assert_eq!(result.findings.len(), 6);
        assert_eq!(result.errors.len(), 0);
        assert_eq!(result.source_tool, "JFrog Xray");
    }

    #[test]
    fn severity_mapping() {
        let parser = JfrogXrayParser::new();
        assert_eq!(parser.map_severity("Critical"), SeverityLevel::Critical);
        assert_eq!(parser.map_severity("High"), SeverityLevel::High);
        assert_eq!(parser.map_severity("Medium"), SeverityLevel::Medium);
        assert_eq!(parser.map_severity("Low"), SeverityLevel::Low);
        assert_eq!(parser.map_severity(""), SeverityLevel::Info);
    }

    #[test]
    fn extracts_package_from_gav() {
        let parser = JfrogXrayParser::new();
        let data = include_bytes!("../../tests/fixtures/jfrog_xray_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        let first = &result.findings[0];
        if let CategoryData::Sca(ref sca) = first.category_data {
            assert!(!sca.package_name.is_empty());
            assert!(!sca.package_version.is_empty());
        } else {
            panic!("Expected SCA category data");
        }
    }

    #[test]
    fn fingerprint_is_per_cve() {
        let parser = JfrogXrayParser::new();
        let data = include_bytes!("../../tests/fixtures/jfrog_xray_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        // Records 0 and 1 come from same Xray row but different CVEs
        assert_ne!(result.findings[0].core.fingerprint, result.findings[1].core.fingerprint);
    }

    #[test]
    fn dependency_type_inferred() {
        let parser = JfrogXrayParser::new();
        let data = include_bytes!("../../tests/fixtures/jfrog_xray_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        // Check that transitive/direct is correctly inferred from impact_path length
        let has_transitive = result.findings.iter().any(|f| {
            if let CategoryData::Sca(ref sca) = f.category_data {
                sca.dependency_type == Some(DependencyType::Transitive)
            } else {
                false
            }
        });
        let has_direct = result.findings.iter().any(|f| {
            if let CategoryData::Sca(ref sca) = f.category_data {
                sca.dependency_type == Some(DependencyType::Direct)
            } else {
                false
            }
        });
        assert!(has_transitive);
        assert!(has_direct);
    }

    #[test]
    fn preserves_raw_finding() {
        let parser = JfrogXrayParser::new();
        let data = include_bytes!("../../tests/fixtures/jfrog_xray_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        let first = &result.findings[0];
        assert!(first.core.raw_finding.get("issue_id").is_some());
    }

    #[test]
    fn app_code_in_metadata() {
        let parser = JfrogXrayParser::new();
        let data = include_bytes!("../../tests/fixtures/jfrog_xray_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        let first = &result.findings[0];
        // Xray parser stores the raw GAV fields in metadata for app code resolver
        assert!(first.core.metadata.get("impacted_artifact").is_some());
        assert!(first.core.metadata.get("path").is_some());
    }

    #[test]
    fn rejects_csv_format() {
        let parser = JfrogXrayParser::new();
        let result = parser.parse(b"", InputFormat::Csv);
        assert!(result.is_err());
    }
}
```

**Step 3: Run tests to verify they fail**

Run: `cargo test --lib parsers::jfrog_xray`
Expected: FAIL — parser not yet implemented.

**Step 4: Write the implementation**

Implement `JfrogXrayParser` in `backend/src/parsers/jfrog_xray.rs`:

Key implementation points:
- Deserialize the top-level `{ "total_rows": N, "rows": [...] }` structure
- For each row, iterate over `cves[]` — each CVE produces a separate `ParsedFinding`
- Parse `vulnerable_component` (GAV format `gav://group:artifact:version`) to extract `package_name` (artifact) and `package_version`
- Infer `DependencyType` from `impact_path.len()`: 2 = Direct, 3+ = Transitive
- Use `fingerprint::compute_sca()` with app_code from metadata resolver fields, package_name, package_version, cve_id
- Store `impacted_artifact`, `path`, and `component_physical_path` in `metadata` for the app code resolver
- Map severity 1:1 (Critical/High/Medium/Low), default empty → Info
- Parse ISO 8601 dates with timezone offsets for `published` and `artifact_scan_time`

**Step 5: Run tests to verify they pass**

Run: `cargo test --lib parsers::jfrog_xray`
Expected: All 8 tests PASS.

**Step 6: Run full test suite**

Run: `cargo test`
Expected: All tests pass.

**Step 7: Commit**

```bash
git add backend/src/parsers/jfrog_xray.rs backend/tests/fixtures/jfrog_xray_sample.json
git commit -m "feat: implement JFrog Xray SCA parser with multi-CVE fan-out"
```

---

## Task 5: Tenable WAS Parser (DAST)

**Files:**
- Create: `backend/tests/fixtures/tenable_was_sample.csv`
- Modify: `backend/src/parsers/tenable_was.rs`

**Step 1: Create test fixture**

Create `backend/tests/fixtures/tenable_was_sample.csv` — a realistic CSV fixture with the full 53-column header from the real export. Include 5 records:
- 1 scan info record (Plugin=98000, Severity=Info, Family=General) — should be skipped
- 1 sitemap record (Plugin=98009, Severity=Info, Family=General) — should be skipped
- 1 High severity finding with CVE, CVSS V3 score, Input Name, and Proof
- 1 Medium severity finding with no CVE but CWE in Cross References
- 1 Low severity finding with empty Input Name (tests fingerprint without parameter)

Use RFC 4180 compliant quoting for multi-line fields (Plugin Output, Description).

**Step 2: Write the failing tests**

In `backend/src/parsers/tenable_was.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csv_skips_info_general() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        // 5 rows, 2 are info/general → 3 findings
        assert_eq!(result.findings.len(), 3);
        assert_eq!(result.errors.len(), 0);
        assert_eq!(result.source_tool, "Tenable WAS");
    }

    #[test]
    fn severity_mapping() {
        let parser = TenableWasParser::new();
        assert_eq!(parser.map_severity("Critical"), SeverityLevel::Critical);
        assert_eq!(parser.map_severity("High"), SeverityLevel::High);
        assert_eq!(parser.map_severity("Medium"), SeverityLevel::Medium);
        assert_eq!(parser.map_severity("Low"), SeverityLevel::Low);
        assert_eq!(parser.map_severity("Info"), SeverityLevel::Info);
    }

    #[test]
    fn extracts_target_url() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        let first = &result.findings[0];
        if let CategoryData::Dast(ref dast) = first.category_data {
            assert!(dast.target_url.starts_with("https://"));
        } else {
            panic!("Expected DAST category data");
        }
    }

    #[test]
    fn fingerprint_uses_plugin_url_input() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        let first = &result.findings[0];
        assert!(!first.core.fingerprint.is_empty());
        assert_eq!(first.core.fingerprint.len(), 64);
    }

    #[test]
    fn parses_human_readable_dates() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        let first = &result.findings[0];
        // first_seen should be parsed from "First Discovered" column
        assert!(first.core.metadata.get("first_discovered").is_some());
    }

    #[test]
    fn extracts_cwe_from_cross_references() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        // Second finding (index 1) has CWE in cross references
        let has_cwe = result.findings.iter().any(|f| !f.core.cwe_ids.is_empty());
        assert!(has_cwe);
    }

    #[test]
    fn dns_name_in_metadata() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        let first = &result.findings[0];
        assert!(first.core.metadata.get("dns_name").is_some());
    }

    #[test]
    fn cvss_score_prefers_v3() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        // First finding has CVSS V3 Base Score
        let first = &result.findings[0];
        assert!(first.core.cvss_score.is_some());
    }

    #[test]
    fn rejects_json_format() {
        let parser = TenableWasParser::new();
        let result = parser.parse(b"", InputFormat::Json);
        assert!(result.is_err());
    }
}
```

**Step 3: Run tests to verify they fail**

Run: `cargo test --lib parsers::tenable_was`
Expected: FAIL — parser not yet implemented.

**Step 4: Write the implementation**

Implement `TenableWasParser` in `backend/src/parsers/tenable_was.rs`:

Key implementation points:
- CSV-only parser. Rejects all other formats.
- Skip records where `Severity == "Info"` AND `Family == "General"` (scan metadata, not vulnerabilities)
- Deserialize all 53 columns via a `TenableWasRecord` struct with serde rename attributes matching CSV headers exactly
- Parse `"Sep 5, 2025 15:30:16 UTC"` date format using `chrono::NaiveDateTime::parse_from_str` with format `"%b %d, %Y %H:%M:%S UTC"`
- CVSS score preference: V3 → V4 → V2 (first non-empty wins)
- Extract CWE from `Cross References` column via regex `CWE:(\d+)`
- Fingerprint: `compute_dast(app_code, plugin_id + ":" + target_url, "", input_name)` — plugin_id combined with URL for uniqueness since there's no http_method
- Store `DNS Name`, `URL`, `IP Address`, `Port`, `Host ID`, `EPSS`, `VPR`, `ACR`, `AES` in metadata for app code resolver and enrichment
- `web_application_name` = DNS Name
- `parameter` = Input Name
- `request_evidence` = Proof
- `response_evidence` = Plugin Output (may be very long — store as-is)

**Step 5: Run tests to verify they pass**

Run: `cargo test --lib parsers::tenable_was`
Expected: All 9 tests PASS.

**Step 6: Run full test suite**

Run: `cargo test`
Expected: All tests pass.

**Step 7: Commit**

```bash
git add backend/src/parsers/tenable_was.rs backend/tests/fixtures/tenable_was_sample.csv
git commit -m "feat: implement Tenable WAS DAST parser with info-record filtering"
```

---

## Task 6: Wire App Code Resolver into Ingestion Pipeline

**Files:**
- Modify: `backend/src/services/ingestion.rs` (update `process_finding` to use resolver)

**Step 1: Write the test**

Add an integration-style unit test to `ingestion.rs` that verifies the app code resolver is consulted during `process_finding`. Since `process_finding` requires a DB, write a test for the resolver wiring logic in isolation:

```rust
#[test]
fn resolver_fields_extracted_from_xray_metadata() {
    let metadata = serde_json::json!({
        "impacted_artifact": "gav://com.ourcompany.gpe30:set-ear:0.0.1",
        "path": "prod-release-local/gpe30/gpe30-set/v1.2.0-rc1/set-ear.ear",
    });
    let fields = extract_resolver_fields(&metadata);
    assert!(fields.iter().any(|(k, _)| k == "impacted_artifact"));
    assert!(fields.iter().any(|(k, _)| k == "path"));
}
```

**Step 2: Implement resolver wiring**

In `ingestion.rs`:
- Add a helper `extract_resolver_fields(metadata: &serde_json::Value) -> Vec<(String, String)>` that extracts known field name→value pairs from `metadata` for the resolver
- Modify `process_finding` to:
  1. First try the existing `metadata["app_code"]` path (for SonarQube which already has it)
  2. If empty, call `app_code_resolver::resolve()` with patterns loaded from DB and fields from metadata
  3. For now, load patterns with a simple query in `process_finding` (we'll optimize with caching later if needed)

**Step 3: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add backend/src/services/ingestion.rs
git commit -m "feat: wire app code resolver into ingestion pipeline"
```

---

## Task 7: Seed Data (SCA + DAST Fixtures)

**Files:**
- Modify: `backend/src/services/seed.rs` (or wherever seed data lives — check actual file)
- Alternative: Create migration-based seed in `002_correlation_and_app_patterns.sql` (already has pattern seeds)

**Step 1: Identify seed mechanism**

Check if there's an existing `seed.rs` or seed script. If not, create seed SQL that can be run via a separate migration or script.

**Step 2: Add SCA and DAST sample findings**

Create sample findings that:
- Reference existing seed applications (APP01, APP02, APP03)
- Include SCA findings with CVEs that overlap with DAST findings (to test correlation later)
- Include DAST findings with CWEs that overlap with existing SAST findings
- Include pre-created `finding_relationships` for correlation groups

**Step 3: Verify seed data works**

Run migrations or seed script and verify data appears in DB.

**Step 4: Commit**

```bash
git add <seed files>
git commit -m "feat: add SCA and DAST seed data with correlation relationships"
```

---

## Task 8: Cross-Tool Deduplication Service

**Files:**
- Create: `backend/src/services/cross_dedup.rs`
- Modify: `backend/src/services/mod.rs` (add `pub mod cross_dedup;`)
- Modify: `backend/src/services/ingestion.rs` (call cross-dedup after intra-tool dedup)

**Step 1: Write the failing tests**

In `backend/src/services/cross_dedup.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sca_same_cve_same_app_is_match() {
        let finding_a = CrossDedupCandidate {
            id: Uuid::new_v4(),
            category: FindingCategory::Sca,
            application_id: Some(Uuid::nil()),
            source_tool: "JFrog Xray".to_string(),
            cve_ids: vec!["CVE-2021-44228".to_string()],
            cwe_ids: vec![],
            package_name: Some("log4j-core".to_string()),
            file_path: None,
            line_number: None,
            branch: None,
            target_url: None,
            parameter: None,
        };
        let finding_b = CrossDedupCandidate {
            id: Uuid::new_v4(),
            category: FindingCategory::Sca,
            application_id: Some(Uuid::nil()),
            source_tool: "Snyk".to_string(),
            cve_ids: vec!["CVE-2021-44228".to_string()],
            cwe_ids: vec![],
            package_name: Some("log4j-core".to_string()),
            file_path: None,
            line_number: None,
            branch: None,
            target_url: None,
            parameter: None,
        };
        let result = check_cross_dedup(&finding_a, &finding_b);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.confidence, ConfidenceLevel::High);
    }

    #[test]
    fn same_tool_is_not_cross_dedup() {
        let finding_a = CrossDedupCandidate {
            id: Uuid::new_v4(),
            category: FindingCategory::Sca,
            application_id: Some(Uuid::nil()),
            source_tool: "JFrog Xray".to_string(),
            cve_ids: vec!["CVE-2021-44228".to_string()],
            cwe_ids: vec![],
            package_name: Some("log4j-core".to_string()),
            file_path: None,
            line_number: None,
            branch: None,
            target_url: None,
            parameter: None,
        };
        let finding_b = CrossDedupCandidate {
            id: Uuid::new_v4(),
            category: FindingCategory::Sca,
            application_id: Some(Uuid::nil()),
            source_tool: "JFrog Xray".to_string(), // Same tool
            cve_ids: vec!["CVE-2021-44228".to_string()],
            cwe_ids: vec![],
            package_name: Some("log4j-core".to_string()),
            file_path: None,
            line_number: None,
            branch: None,
            target_url: None,
            parameter: None,
        };
        let result = check_cross_dedup(&finding_a, &finding_b);
        assert!(result.is_none());
    }

    #[test]
    fn different_category_is_not_cross_dedup() {
        let finding_a = CrossDedupCandidate {
            id: Uuid::new_v4(),
            category: FindingCategory::Sca,
            application_id: Some(Uuid::nil()),
            source_tool: "JFrog Xray".to_string(),
            cve_ids: vec!["CVE-2021-44228".to_string()],
            cwe_ids: vec![],
            package_name: Some("log4j-core".to_string()),
            file_path: None,
            line_number: None,
            branch: None,
            target_url: None,
            parameter: None,
        };
        let finding_b = CrossDedupCandidate {
            id: Uuid::new_v4(),
            category: FindingCategory::Dast, // Different category
            application_id: Some(Uuid::nil()),
            source_tool: "Tenable WAS".to_string(),
            cve_ids: vec!["CVE-2021-44228".to_string()],
            cwe_ids: vec![],
            package_name: None,
            file_path: None,
            line_number: None,
            branch: None,
            target_url: Some("https://example.com/api".to_string()),
            parameter: None,
        };
        let result = check_cross_dedup(&finding_a, &finding_b);
        assert!(result.is_none()); // Cross-category goes to correlation, not dedup
    }

    #[test]
    fn sast_same_cwe_same_file_nearby_line_same_branch() {
        let finding_a = CrossDedupCandidate {
            id: Uuid::new_v4(),
            category: FindingCategory::Sast,
            application_id: Some(Uuid::nil()),
            source_tool: "SonarQube".to_string(),
            cve_ids: vec![],
            cwe_ids: vec!["CWE-89".to_string()],
            package_name: None,
            file_path: Some("src/main/java/Dao.java".to_string()),
            line_number: Some(42),
            branch: Some("production".to_string()),
            target_url: None,
            parameter: None,
        };
        let finding_b = CrossDedupCandidate {
            id: Uuid::new_v4(),
            category: FindingCategory::Sast,
            application_id: Some(Uuid::nil()),
            source_tool: "Checkmarx".to_string(),
            cve_ids: vec![],
            cwe_ids: vec!["CWE-89".to_string()],
            package_name: None,
            file_path: Some("src/main/java/Dao.java".to_string()),
            line_number: Some(45), // Within ±5
            branch: Some("production".to_string()),
            target_url: None,
            parameter: None,
        };
        let result = check_cross_dedup(&finding_a, &finding_b);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.confidence, ConfidenceLevel::High);
    }

    #[test]
    fn sast_different_branch_is_not_dedup() {
        let finding_a = CrossDedupCandidate {
            id: Uuid::new_v4(),
            category: FindingCategory::Sast,
            application_id: Some(Uuid::nil()),
            source_tool: "SonarQube".to_string(),
            cve_ids: vec![],
            cwe_ids: vec!["CWE-89".to_string()],
            package_name: None,
            file_path: Some("src/main/java/Dao.java".to_string()),
            line_number: Some(42),
            branch: Some("production".to_string()),
            target_url: None,
            parameter: None,
        };
        let finding_b = CrossDedupCandidate {
            id: Uuid::new_v4(),
            category: FindingCategory::Sast,
            application_id: Some(Uuid::nil()),
            source_tool: "Checkmarx".to_string(),
            cve_ids: vec![],
            cwe_ids: vec!["CWE-89".to_string()],
            package_name: None,
            file_path: Some("src/main/java/Dao.java".to_string()),
            line_number: Some(42),
            branch: Some("master".to_string()), // Different branch
            target_url: None,
            parameter: None,
        };
        let result = check_cross_dedup(&finding_a, &finding_b);
        assert!(result.is_none());
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --lib services::cross_dedup`
Expected: FAIL.

**Step 3: Write the implementation**

Implement the `CrossDedupCandidate` struct, `CrossDedupMatch` struct, and `check_cross_dedup()` function that applies the 5 matching rules from design doc Section 2.3:
- SCA ↔ SCA: Same CVE + same package + same application + different tool → High
- SAST ↔ SAST: Same CWE + same file + line ±5 + same branch + different tool → High
- SAST ↔ SAST: Same CWE + same file + same branch + different line → Medium
- DAST ↔ DAST: Same plugin/check + same URL + same parameter + different tool → High
- DAST ↔ DAST: Same CWE + same URL (no param match) → Medium

Guard: Must be same category, different source_tool, same application_id.

**Step 4: Run tests to verify they pass**

Run: `cargo test --lib services::cross_dedup`
Expected: All 5 tests PASS.

**Step 5: Commit**

```bash
git add backend/src/services/cross_dedup.rs backend/src/services/mod.rs
git commit -m "feat: implement cross-tool deduplication matching rules"
```

---

## Task 9: Correlation Engine

**Files:**
- Create: `backend/src/services/correlation.rs`
- Modify: `backend/src/services/mod.rs` (add `pub mod correlation;`)

**Step 1: Write the failing tests**

Test the 6 correlation rules (CR-1 through CR-6) from design doc Section 3.2. Each test creates candidate finding pairs and checks if the engine correctly identifies relationships.

Key tests:
- `cr1_same_cve_sca_dast_same_app` → correlated_with, High
- `cr2_same_cwe_sast_dast_production_branch` → correlated_with, Medium
- `cr2_sast_master_branch_not_matched` → no match (cross-category uses production only)
- `cr5_same_rule_multiple_files` → grouped_under, High
- `cr6_same_cwe_same_file` → grouped_under, High
- `cr5_different_branch_separate_groups` → two separate group results

**Step 2: Run tests to verify they fail**

Run: `cargo test --lib services::correlation`
Expected: FAIL.

**Step 3: Write the implementation**

Implement:
- `CorrelationCandidate` struct (similar to CrossDedupCandidate but with additional fields)
- `CorrelationMatch` struct with `rule_name`, `relationship_type`, `confidence`
- `correlate_finding(new_finding, existing_findings) -> Vec<CorrelationMatch>` — pure logic function
- `CorrelationGroup` struct with `primary_finding_id`, `findings`, `relationships`, `tool_coverage`, `group_risk_score`
- SQL query for `get_correlation_groups(pool, app_id, branch)` using recursive CTE to walk `finding_relationships`

Recursive CTE for groups:

```sql
WITH RECURSIVE group_walk AS (
    SELECT source_finding_id AS finding_id, source_finding_id AS group_root
    FROM finding_relationships
    WHERE relationship_type IN ('correlated_with', 'grouped_under')
    UNION
    SELECT fr.target_finding_id, gw.group_root
    FROM finding_relationships fr
    JOIN group_walk gw ON fr.source_finding_id = gw.finding_id
    WHERE fr.relationship_type IN ('correlated_with', 'grouped_under')
)
SELECT group_root, array_agg(DISTINCT finding_id) AS member_ids
FROM group_walk
GROUP BY group_root
```

**Step 4: Run tests to verify they pass**

Run: `cargo test --lib services::correlation`
Expected: All tests PASS.

**Step 5: Commit**

```bash
git add backend/src/services/correlation.rs backend/src/services/mod.rs
git commit -m "feat: implement correlation engine with 6 rules and group computation"
```

---

## Task 10: Correlation API Routes

**Files:**
- Create: `backend/src/routes/correlation.rs`
- Modify: `backend/src/routes/mod.rs` (add `pub mod correlation;`)
- Modify: `backend/src/main.rs` (register routes)

**Step 1: Implement route handlers**

Create `backend/src/routes/correlation.rs` with these handlers following the existing route pattern (thin handlers, delegate to service):

```rust
// GET /api/v1/correlations/groups — list correlation groups (paginated, filterable by app)
pub async fn list_groups(...)

// GET /api/v1/correlations/groups/:id — get a specific group with all member findings
pub async fn get_group(...)

// GET /api/v1/correlations/rules — list correlation rules
pub async fn list_rules(...)

// POST /api/v1/correlations/rules — create custom rule (manager+)
pub async fn create_rule(...)

// PUT /api/v1/correlations/rules/:id — update rule (manager+)
pub async fn update_rule(...)

// POST /api/v1/correlations/run/:app_id — trigger re-correlation for an application (manager+)
pub async fn run_correlation(...)

// POST /api/v1/relationships — manually create a relationship (analyst+)
pub async fn create_relationship(...)

// DELETE /api/v1/relationships/:id — remove a relationship (analyst+)
pub async fn delete_relationship(...)
```

**Step 2: Register routes in main.rs**

Add the correlation routes router:

```rust
let correlation_routes = Router::new()
    .route("/correlations/groups", get(routes::correlation::list_groups))
    .route("/correlations/groups/{id}", get(routes::correlation::get_group))
    .route("/correlations/rules", get(routes::correlation::list_rules).post(routes::correlation::create_rule))
    .route("/correlations/rules/{id}", put(routes::correlation::update_rule))
    .route("/correlations/run/{app_id}", post(routes::correlation::run_correlation))
    .route("/relationships", post(routes::correlation::create_relationship))
    .route("/relationships/{id}", delete(routes::correlation::delete_relationship));
```

Nest under `/api/v1`: `.nest("/api/v1", correlation_routes)`

**Step 3: Run cargo check**

Run: `cargo check`
Expected: Compiles with no errors.

**Step 4: Commit**

```bash
git add backend/src/routes/correlation.rs backend/src/routes/mod.rs backend/src/main.rs
git commit -m "feat: add correlation and relationship API routes"
```

---

## Task 11: Deduplication Dashboard API Routes

**Files:**
- Create: `backend/src/routes/deduplication.rs`
- Modify: `backend/src/routes/mod.rs` (add `pub mod deduplication;`)
- Modify: `backend/src/main.rs` (register routes)

**Step 1: Implement route handlers**

```rust
// GET /api/v1/deduplication/stats — dedup statistics
pub async fn stats(...)

// GET /api/v1/deduplication/pending — pending review pairs (paginated)
pub async fn pending(...)

// GET /api/v1/deduplication/history — recent decisions (paginated)
pub async fn history(...)

// POST /api/v1/deduplication/:relationship_id/confirm — analyst confirms a match
pub async fn confirm(...)

// POST /api/v1/deduplication/:relationship_id/reject — analyst rejects a match
pub async fn reject(...)
```

**Step 2: Implement service functions**

Add to `backend/src/services/deduplication.rs` (or a new file if cleaner):
- `get_dedup_stats(pool) -> DedupStats` — queries counts from ingestion_logs and finding_relationships
- `list_pending_reviews(pool, pagination) -> PagedResult<PendingReview>` — LOW/MEDIUM confidence `duplicate_of` relationships without analyst confirmation
- `list_dedup_history(pool, pagination) -> PagedResult<DedupDecision>` — confirmed/rejected actions from audit log
- `confirm_relationship(pool, relationship_id, user_id)` — updates confidence to High, logs decision
- `reject_relationship(pool, relationship_id, user_id)` — deletes relationship, logs decision

**Step 3: Register routes in main.rs**

```rust
let dedup_routes = Router::new()
    .route("/deduplication/stats", get(routes::deduplication::stats))
    .route("/deduplication/pending", get(routes::deduplication::pending))
    .route("/deduplication/history", get(routes::deduplication::history))
    .route("/deduplication/{relationship_id}/confirm", post(routes::deduplication::confirm))
    .route("/deduplication/{relationship_id}/reject", post(routes::deduplication::reject));
```

**Step 4: Run cargo check**

Run: `cargo check`
Expected: Compiles.

**Step 5: Commit**

```bash
git add backend/src/routes/deduplication.rs backend/src/routes/mod.rs \
        backend/src/services/deduplication.rs backend/src/main.rs
git commit -m "feat: add deduplication dashboard API routes and service"
```

---

## Task 12: Attack Chains API Routes

**Files:**
- Create: `backend/src/routes/attack_chains.rs`
- Modify: `backend/src/routes/mod.rs` (add `pub mod attack_chains;`)
- Modify: `backend/src/main.rs` (register routes)

**Step 1: Implement route handlers**

```rust
// GET /api/v1/attack-chains — list applications with attack chain summaries (paginated)
// Supports ?branch= filter (default: production)
pub async fn list(...)

// GET /api/v1/attack-chains/:app_id — get all attack chains for one application
// Supports ?branch= filter (default: production)
pub async fn get_by_app(...)
```

**Step 2: Implement service functions**

Create `backend/src/services/attack_chains.rs`:
- `list_application_summaries(pool, branch, pagination)` — returns apps ranked by risk with chain counts, tool coverage, severity breakdown
- `get_app_attack_chains(pool, app_id, branch)` — returns correlation groups for one app, plus uncorrelated findings

**Step 3: Register routes in main.rs**

```rust
let attack_chain_routes = Router::new()
    .route("/attack-chains", get(routes::attack_chains::list))
    .route("/attack-chains/{app_id}", get(routes::attack_chains::get_by_app));
```

**Step 4: Run cargo check**

Run: `cargo check`
Expected: Compiles.

**Step 5: Commit**

```bash
git add backend/src/routes/attack_chains.rs backend/src/routes/mod.rs \
        backend/src/services/attack_chains.rs backend/src/services/mod.rs \
        backend/src/main.rs
git commit -m "feat: add attack chains API routes and service"
```

---

## Task 13: Wire Correlation Density into Risk Score

**Files:**
- Modify: `backend/src/services/risk_score.rs` (no changes needed — already handles CorrelationInput)
- Create: `backend/src/services/risk_score_wiring.rs` — function that queries real relationship data

**Step 1: Write the test**

```rust
#[test]
fn computes_correlation_input_from_relationships() {
    // Given 3 relationships linking findings from SAST, SCA, DAST
    let relationships = vec![
        RelationshipInfo { source_tool: "SonarQube".into(), target_tool: "JFrog Xray".into() },
        RelationshipInfo { source_tool: "SonarQube".into(), target_tool: "Tenable WAS".into() },
    ];
    let input = compute_correlation_input(&relationships);
    assert_eq!(input.distinct_tool_count, 3); // SonarQube, JFrog Xray, Tenable WAS
    assert_eq!(input.correlated_finding_count, 3); // the finding + 2 linked findings
}
```

**Step 2: Implement**

Create `compute_correlation_input(pool, finding_id) -> CorrelationInput` that:
1. Queries `finding_relationships` for all relationships involving the finding
2. JOINs to `findings` to get `source_tool` for each linked finding
3. Counts distinct tools and correlated findings
4. Returns `CorrelationInput { distinct_tool_count, correlated_finding_count }`

**Step 3: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add backend/src/services/risk_score_wiring.rs backend/src/services/mod.rs
git commit -m "feat: wire correlation density to real relationship data for risk score"
```

---

## Task 14: Frontend — TypeScript Types

**Files:**
- Create: `frontend/src/types/correlation.ts`
- Create: `frontend/src/types/deduplication.ts`
- Create: `frontend/src/types/attack-chains.ts`

**Step 1: Create correlation types**

```typescript
// frontend/src/types/correlation.ts

export type CorrelationRule = {
  id: string
  name: string
  description: string | null
  rule_type: string
  conditions: Record<string, unknown>
  confidence: 'High' | 'Medium' | 'Low'
  is_active: boolean
  priority: number
  created_by: string | null
  created_at: string
  updated_at: string
}

export type CorrelationGroup = {
  group_id: string
  primary_finding_id: string
  tool_coverage: string[]
  group_risk_score: number
  findings: CorrelationGroupFinding[]
  relationships: CorrelationRelationship[]
}

export type CorrelationGroupFinding = {
  id: string
  title: string
  category: 'SAST' | 'SCA' | 'DAST'
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
  source_tool: string
  status: string
}

export type CorrelationRelationship = {
  source: string
  target: string
  type: 'correlated_with' | 'grouped_under' | 'duplicate_of' | 'superseded_by'
  confidence: 'High' | 'Medium' | 'Low'
  notes: string | null
}

export type CreateRelationship = {
  source_finding_id: string
  target_finding_id: string
  relationship_type: string
  confidence?: string
  notes?: string
}

export type CreateCorrelationRule = {
  name: string
  description?: string
  rule_type: string
  conditions: Record<string, unknown>
  confidence?: string
  priority?: number
}
```

**Step 2: Create deduplication types**

```typescript
// frontend/src/types/deduplication.ts

export type DedupStats = {
  total_raw_ingested: number
  unique_findings: number
  dedup_ratio: number
  cross_tool_matches: number
  pending_review: number
}

export type PendingReview = {
  relationship_id: string
  finding_a: PendingFinding
  finding_b: PendingFinding
  match_reason: string
  confidence: 'High' | 'Medium' | 'Low'
  created_at: string
}

export type PendingFinding = {
  id: string
  title: string
  category: 'SAST' | 'SCA' | 'DAST'
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
  source_tool: string
}

export type DedupDecision = {
  relationship_id: string
  action: 'confirm' | 'reject'
  actor_name: string
  acted_at: string
  finding_a_title: string
  finding_b_title: string
}
```

**Step 3: Create attack chain types**

```typescript
// frontend/src/types/attack-chains.ts

export type AttackChainSummary = {
  application_id: string
  app_name: string
  app_code: string
  risk_score: number
  attack_chain_count: number
  tool_coverage: string[]
  severity_breakdown: {
    critical: number
    high: number
    medium: number
    low: number
  }
  uncorrelated_count: number
}

export type AttackChainDetail = {
  title: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
  tool_coverage: string[]
  group_risk_score: number
  confidence: 'High' | 'Medium' | 'Low'
  findings: CorrelationGroupFinding[]
  relationships: CorrelationRelationship[]
}

// Re-use from correlation types
import type { CorrelationGroupFinding, CorrelationRelationship } from './correlation'
```

**Step 4: Commit**

```bash
git add frontend/src/types/correlation.ts frontend/src/types/deduplication.ts \
        frontend/src/types/attack-chains.ts
git commit -m "feat: add TypeScript types for correlation, deduplication, and attack chains"
```

---

## Task 15: Frontend — API Clients

**Files:**
- Create: `frontend/src/api/correlation.ts`
- Create: `frontend/src/api/deduplication.ts`
- Create: `frontend/src/api/attack-chains.ts`

**Step 1: Create correlation API client**

```typescript
// frontend/src/api/correlation.ts
import { apiGet, apiPost, apiPut } from './client'
import type { PagedResult } from '@/types/api'
import type {
  CorrelationGroup,
  CorrelationRule,
  CreateCorrelationRule,
  CreateRelationship,
} from '@/types/correlation'

export function getCorrelationGroups(params?: Record<string, string>) {
  return apiGet<PagedResult<CorrelationGroup>>('/correlations/groups', params)
}

export function getCorrelationGroup(id: string) {
  return apiGet<CorrelationGroup>(`/correlations/groups/${id}`)
}

export function getCorrelationRules() {
  return apiGet<CorrelationRule[]>('/correlations/rules')
}

export function createCorrelationRule(body: CreateCorrelationRule) {
  return apiPost<CorrelationRule>('/correlations/rules', body)
}

export function updateCorrelationRule(id: string, body: Partial<CreateCorrelationRule>) {
  return apiPut<CorrelationRule>(`/correlations/rules/${id}`, body)
}

export function runCorrelation(appId: string) {
  return apiPost<{ message: string }>(`/correlations/run/${appId}`, {})
}

export function createRelationship(body: CreateRelationship) {
  return apiPost<{ id: string }>('/relationships', body)
}

export function deleteRelationship(id: string) {
  return apiDelete<void>(`/relationships/${id}`)
}
```

Follow the same pattern for `deduplication.ts` and `attack-chains.ts`.

**Step 2: Commit**

```bash
git add frontend/src/api/correlation.ts frontend/src/api/deduplication.ts \
        frontend/src/api/attack-chains.ts
git commit -m "feat: add API client functions for correlation, dedup, and attack chains"
```

---

## Task 16: Frontend — Findings Page Tabs

**Files:**
- Modify: `frontend/src/pages/FindingsPage.tsx`
- Modify: `frontend/src/api/findings.ts` (add `include_category_data` param support)
- Modify: `public/locales/en/translation.json` (add tab labels)
- Modify: `public/locales/it/translation.json` (add tab labels)

**Step 1: Add i18n keys**

Add to both translation files:

```json
"findings": {
  "tabs": {
    "all": "All",
    "sast": "SAST",
    "sca": "SCA",
    "dast": "DAST"
  },
  "columns": {
    "file_path": "File Path",
    "line_number": "Line",
    "rule_id": "Rule",
    "language": "Language",
    "package_name": "Package",
    "package_version": "Version",
    "fixed_version": "Fix Available",
    "dependency_type": "Dependency",
    "known_exploited": "KEV",
    "target_url": "URL",
    "parameter": "Parameter",
    "web_application_name": "Application",
    "plugin_id": "Plugin"
  }
}
```

**Step 2: Update FindingsPage with tabs**

Add horizontal tabs (using shadcn/ui `Tabs` component) at the top of the page. Each tab sets a URL search param `?tab=all|sast|sca|dast`. The tab controls:
- Which category filter is applied to the API call
- Which columns are shown in the TanStack Table
- SAST tab additionally gets a branch dropdown filter

**Step 3: Update API client to support `include_category_data`**

In `frontend/src/api/findings.ts`, add the param to the `getFindings` call when a specific tab is selected.

**Step 4: Run lint**

Run: `cd /home/marco/Programming/FullStack/synapsec/frontend && npm run lint`
Expected: No errors.

**Step 5: Commit**

```bash
git add frontend/src/pages/FindingsPage.tsx frontend/src/api/findings.ts \
        frontend/public/locales/en/translation.json frontend/public/locales/it/translation.json
git commit -m "feat: add SAST/SCA/DAST tabs to Findings page with category-specific columns"
```

---

## Task 17: Frontend — Deduplication Dashboard Page

**Files:**
- Create: `frontend/src/pages/DeduplicationPage.tsx`
- Modify: `frontend/src/router.tsx` (add route)
- Modify: `public/locales/en/translation.json` (add dedup keys)
- Modify: `public/locales/it/translation.json` (add dedup keys)

**Step 1: Add i18n keys**

```json
"deduplication": {
  "title": "Deduplication Dashboard",
  "stats": {
    "total_raw": "Total Raw Ingested",
    "unique": "Unique Findings",
    "ratio": "Dedup Ratio",
    "cross_tool": "Cross-Tool Matches",
    "pending": "Pending Review"
  },
  "pending_table": {
    "title": "Pending Review",
    "finding_a": "Finding A",
    "finding_b": "Finding B",
    "reason": "Match Reason",
    "confidence": "Confidence",
    "actions": "Actions",
    "confirm": "Confirm",
    "reject": "Reject"
  },
  "history_table": {
    "title": "Recent Decisions"
  }
}
```

**Step 2: Create the page component**

`DeduplicationPage.tsx` structure:
- **Section 1:** 5 stat cards in a grid (Total Raw, Unique, Dedup Ratio %, Cross-Tool Matches, Pending Review)
- **Section 2:** Pending Review table (TanStack Table) with Finding A, Finding B, Match Reason, Confidence badge, Confirm/Reject buttons
- **Section 3:** Recent Decisions table (TanStack Table) with action, actor, timestamp

All strings via `useTranslation()`.

**Step 3: Add route**

In `frontend/src/router.tsx`, add:

```typescript
import { DeduplicationPage } from '@/pages/DeduplicationPage'

const deduplicationRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/deduplication',
  component: DeduplicationPage,
})
```

Add to `layoutRoute.addChildren([...])`.

**Step 4: Run lint and build**

Run: `npm run lint && npm run build`
Expected: No errors.

**Step 5: Commit**

```bash
git add frontend/src/pages/DeduplicationPage.tsx frontend/src/router.tsx \
        frontend/public/locales/en/translation.json frontend/public/locales/it/translation.json
git commit -m "feat: add Deduplication Dashboard page with stats, pending review, and history"
```

---

## Task 18: Frontend — Correlation Page

**Files:**
- Create: `frontend/src/pages/CorrelationPage.tsx`
- Modify: `frontend/src/router.tsx` (add route)
- Modify: `public/locales/en/translation.json` (add correlation keys)
- Modify: `public/locales/it/translation.json` (add correlation keys)

**Step 1: Add i18n keys**

```json
"correlation": {
  "title": "Correlation Engine",
  "groups": {
    "title": "Correlation Groups",
    "primary": "Primary Finding",
    "tools": "Tool Coverage",
    "risk": "Group Risk",
    "members": "Members"
  },
  "rules": {
    "title": "Correlation Rules",
    "name": "Rule Name",
    "type": "Type",
    "confidence": "Confidence",
    "active": "Active",
    "create": "Create Rule"
  }
}
```

**Step 2: Create the page component**

`CorrelationPage.tsx` structure:
- Two sections with tabs: **Groups** | **Rules**
- Groups tab: table of correlation groups with primary finding, tool coverage badges, group risk score, member count
- Rules tab: table of rules with name, type, confidence, active toggle; Create Rule button opens modal
- Manual link/unlink actions accessible from group detail

**Step 3: Add route**

```typescript
import { CorrelationPage } from '@/pages/CorrelationPage'

const correlationRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/correlation',
  component: CorrelationPage,
})
```

**Step 4: Run lint and build**

Run: `npm run lint && npm run build`
Expected: No errors.

**Step 5: Commit**

```bash
git add frontend/src/pages/CorrelationPage.tsx frontend/src/router.tsx \
        frontend/public/locales/en/translation.json frontend/public/locales/it/translation.json
git commit -m "feat: add Correlation page with groups table and rules management"
```

---

## Task 19: Frontend — Attack Chains Page

**Files:**
- Create: `frontend/src/pages/AttackChainsPage.tsx`
- Create: `frontend/src/pages/AttackChainDetailPage.tsx`
- Modify: `frontend/src/router.tsx` (add routes)
- Modify: `public/locales/en/translation.json` (add attack chain keys)
- Modify: `public/locales/it/translation.json` (add attack chain keys)

**Step 1: Add i18n keys**

```json
"attack_chains": {
  "title": "Attack Chains",
  "columns": {
    "application": "Application",
    "risk_score": "Risk Score",
    "chains": "Attack Chains",
    "tools": "Tool Coverage",
    "severity": "Severity Breakdown",
    "uncorrelated": "Uncorrelated"
  },
  "detail": {
    "title": "Attack Chains — {{appName}}",
    "chain_card": {
      "risk": "Risk",
      "confidence": "Confidence",
      "tools": "Tools",
      "findings": "Findings"
    },
    "uncorrelated_title": "Uncorrelated Findings"
  },
  "branch_filter": "Branch"
}
```

**Step 2: Create the list page**

`AttackChainsPage.tsx`:
- TanStack Table with columns: Application (name + code), Risk Score (color-coded), Attack Chains count, Tool Coverage badges (SAST/SCA/DAST), Severity Breakdown (inline Critical/High/Medium/Low counts), Uncorrelated count
- Sorted by risk score descending
- Branch filter dropdown (defaults to "production")
- Click row navigates to detail page

**Step 3: Create the detail page**

`AttackChainDetailPage.tsx`:
- Page title: "Attack Chains — {App Name}"
- Branch filter dropdown
- Grid of attack chain cards, each showing: chain title, severity badge, tool coverage badges, member findings list, group risk score, confidence
- Below cards: Uncorrelated Findings table

**Step 4: Add routes**

```typescript
import { AttackChainsPage } from '@/pages/AttackChainsPage'
import { AttackChainDetailPage } from '@/pages/AttackChainDetailPage'

const attackChainsRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/attack-chains',
  component: AttackChainsPage,
})

const attackChainDetailRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/attack-chains/$appId',
  component: AttackChainDetailPage,
})
```

**Step 5: Run lint and build**

Run: `npm run lint && npm run build`
Expected: No errors.

**Step 6: Commit**

```bash
git add frontend/src/pages/AttackChainsPage.tsx frontend/src/pages/AttackChainDetailPage.tsx \
        frontend/src/router.tsx \
        frontend/public/locales/en/translation.json frontend/public/locales/it/translation.json
git commit -m "feat: add Attack Chains list and detail pages"
```

---

## Task 20: Frontend — Updated Sidebar Navigation

**Files:**
- Modify: `frontend/src/components/layout/Sidebar.tsx`
- Modify: `public/locales/en/translation.json` (add new nav keys)
- Modify: `public/locales/it/translation.json` (add new nav keys)

**Step 1: Add i18n keys**

Add to both translation files:

```json
"nav": {
  "dashboard": "Dashboard",
  "findings": "Findings",
  "applications": "Applications",
  "attack_chains": "Attack Chains",
  "triage": "Triage Queue",
  "ingestion": "Ingestion",
  "deduplication": "Deduplication",
  "correlation": "Correlation",
  "unmapped": "Unmapped Apps"
}
```

**Step 2: Update Sidebar component**

Replace the existing `NAV_ITEMS` array in `Sidebar.tsx` with two groups matching the design doc Section 7.1:

```typescript
import {
  LayoutDashboard,
  Search,
  Building2,
  Upload,
  ListChecks,
  AlertCircle,
  Link2,
  Copy,
  GitBranch,
} from 'lucide-react'

const MAIN_NAV: NavItem[] = [
  { labelKey: 'nav.dashboard', path: '/', icon: LayoutDashboard },
  { labelKey: 'nav.findings', path: '/findings', icon: Search },
  { labelKey: 'nav.applications', path: '/applications', icon: Building2 },
  { labelKey: 'nav.attack_chains', path: '/attack-chains', icon: GitBranch },
  { labelKey: 'nav.triage', path: '/triage', icon: ListChecks },
]

const OPS_NAV: NavItem[] = [
  { labelKey: 'nav.ingestion', path: '/ingestion', icon: Upload },
  { labelKey: 'nav.deduplication', path: '/deduplication', icon: Copy },
  { labelKey: 'nav.correlation', path: '/correlation', icon: Link2 },
  { labelKey: 'nav.unmapped', path: '/unmapped', icon: AlertCircle },
]
```

Render `MAIN_NAV`, then a `<Separator />`, then `OPS_NAV`.

**Step 3: Run lint**

Run: `npm run lint`
Expected: No errors.

**Step 4: Commit**

```bash
git add frontend/src/components/layout/Sidebar.tsx \
        frontend/public/locales/en/translation.json frontend/public/locales/it/translation.json
git commit -m "feat: restructure sidebar navigation with analyst workflow funnel layout"
```

---

## Task 21: Backend — Findings API Category Data Support

**Files:**
- Modify: `backend/src/services/finding.rs` (add `include_category_data` support to `list()`)
- Modify: `backend/src/routes/findings.rs` (add query param)

**Step 1: Update FindingFilters**

Add `branch` and `include_category_data` to `FindingFilters`:

```rust
pub struct FindingFilters {
    // ... existing fields ...
    pub branch: Option<String>,
    pub include_category_data: Option<bool>,
}
```

**Step 2: Update list() to optionally JOIN category tables**

When `include_category_data` is true and `category` is set, the list query JOINs to the appropriate category table and includes extra columns in a new response DTO:

```rust
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct FindingSummaryWithCategory {
    #[serde(flatten)]
    pub base: FindingSummary,
    pub category_data: Option<serde_json::Value>,
}
```

When `branch` is set and `category` is SAST, add a filter: `JOIN finding_sast ON ... WHERE finding_sast.branch = $N`.

**Step 3: Run tests**

Run: `cargo test`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add backend/src/services/finding.rs backend/src/routes/findings.rs
git commit -m "feat: add category data and branch filter support to findings list API"
```

---

## Task 22: E2E Tests

**Files:**
- Create/modify: `e2e/` directory tests (Playwright)

**Step 1: Add page load tests**

```typescript
test('Attack Chains page loads', async ({ page }) => {
  await page.goto('/attack-chains')
  await expect(page.getByRole('heading', { name: /attack chains/i })).toBeVisible()
})

test('Correlation page loads', async ({ page }) => {
  await page.goto('/correlation')
  await expect(page.getByRole('heading', { name: /correlation/i })).toBeVisible()
})

test('Deduplication page loads', async ({ page }) => {
  await page.goto('/deduplication')
  await expect(page.getByRole('heading', { name: /deduplication/i })).toBeVisible()
})

test('Findings tabs switch correctly', async ({ page }) => {
  await page.goto('/findings')
  // Click SAST tab
  await page.getByRole('tab', { name: 'SAST' }).click()
  await expect(page).toHaveURL(/tab=sast/)
  // Click SCA tab
  await page.getByRole('tab', { name: 'SCA' }).click()
  await expect(page).toHaveURL(/tab=sca/)
  // Click DAST tab
  await page.getByRole('tab', { name: 'DAST' }).click()
  await expect(page).toHaveURL(/tab=dast/)
})

test('Sidebar shows new navigation items', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByText('Attack Chains')).toBeVisible()
  await expect(page.getByText('Deduplication')).toBeVisible()
  await expect(page.getByText('Correlation')).toBeVisible()
})
```

**Step 2: Run E2E tests**

Run: `npx playwright test`
Expected: All tests pass.

**Step 3: Commit**

```bash
git add e2e/
git commit -m "test: add E2E tests for Phase 2 pages and navigation"
```

---

## Execution Summary

| Task | Component | Est. Commits |
|------|-----------|-------------|
| 1 | Migration + models | 1 |
| 2 | App code resolver | 1 |
| 3 | ParserType variants | 1 |
| 4 | Xray parser | 1 |
| 5 | Tenable WAS parser | 1 |
| 6 | Resolver wiring | 1 |
| 7 | Seed data | 1 |
| 8 | Cross-tool dedup | 1 |
| 9 | Correlation engine | 1 |
| 10 | Correlation routes | 1 |
| 11 | Dedup dashboard routes | 1 |
| 12 | Attack chains routes | 1 |
| 13 | Risk score wiring | 1 |
| 14 | Frontend types | 1 |
| 15 | Frontend API clients | 1 |
| 16 | Findings tabs | 1 |
| 17 | Dedup dashboard page | 1 |
| 18 | Correlation page | 1 |
| 19 | Attack chains pages | 1 |
| 20 | Sidebar navigation | 1 |
| 21 | Category data API | 1 |
| 22 | E2E tests | 1 |
| **Total** | | **22 commits** |
