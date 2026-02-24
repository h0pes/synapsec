# SynApSec Phase 2: Multi-Scanner Intelligence — Design Document

**Date:** 2026-02-23
**Status:** Draft — pending user review
**Depends on:** Phase 1 Foundation (complete)

**Goal:** Add JFrog Xray (SCA) and Tenable WAS (DAST) parsers, build the correlation engine and cross-tool deduplication, implement the 5-factor composite risk score with real data, and deliver three new UI views — Deduplication Dashboard, Correlation Page, and Attack Chains — that make SynApSec's intelligence layer visible and actionable.

**Phase 2 Exit Criteria:** All three scanners integrated via file import. Cross-tool deduplication operational with analyst review workflow. Correlation engine producing auto-detected groups with confidence scores. 5-factor composite risk score computed for all findings. Deduplication, Correlation, and Attack Chain views functional in UI. Findings page supports tabbed per-category views with category-specific columns.

**Explicitly Deferred to Phase 3:**

- Notifications (Email + Microsoft Teams adaptive cards)
- SLA framework (configurable deadlines, breach alerts)
- Smart triage (rule-based AI provider abstraction)
- MFA (TOTP)
- **Interactive graph visualization for Attack Chains** (hard requirement for Phase 3 — Phase 2 data model and API are designed to support it with zero rework)
- Executive dashboards
- Compliance reporting

---

## 1. Parsers

### 1.1 JFrog Xray Parser (SCA)

**Input format:** JSON only. The Xray CSV export is unusable due to field-length formatting issues. JSON comes from the Xray violations export.

**JSON structure:** Top-level wrapper `{ "total_rows": N, "rows": [...] }`. Each element of `rows` is one vulnerability record.

**Volume:** ~820k records across all severities. Ingestion must use batch processing (see Section 1.4).

**Sample record (abbreviated):**

```json
{
  "cves": [
    {
      "cve": "CVE-2016-1000031",
      "cvss_v2_score": 7.5,
      "cvss_v3_score": 9.8,
      "cvss_v3_vector": "CVSS:3.0/AV:N/AC:L/..."
    }
  ],
  "cvss3_max_score": 9.8,
  "summary": "Apache Commons FileUpload before 1.3.3 DiskFileItem ...",
  "severity": "Critical",
  "severity_source": "CVSS V3 from NVD",
  "vulnerable_component": "gav://commons-fileupload:commons-fileupload:1.3",
  "component_physical_path": "set-web.war/WEB-INF/lib/commons-fileupload-1.3.jar",
  "impacted_artifact": "gav://com.ourcompany.appcode:set-ear:0.0.1",
  "impact_path": ["gav://com.ourcompany.appcode:set-ear:0.0.1", "gav://..."],
  "path": "prod-release-local/appcode/appcode-set/v1.2.0-rc1/set-ear.ear",
  "fixed_versions": ["1.3.3"],
  "published": "2017-07-05T13:31:10+02:00",
  "artifact_scan_time": "2025-12-04T17:23:55+01:00",
  "issue_id": "XRAY-55689",
  "package_type": "maven",
  "provider": "JFrog",
  "description": "...",
  "references": ["https://..."],
  "applicability": null,
  "applicability_result": ""
}
```

**Field mapping to `finding_sca` + `findings` tables:**

| Xray Field                | SynApSec Field                      | Notes                                                               |
| ------------------------- | ----------------------------------- | ------------------------------------------------------------------- |
| `vulnerable_component`    | `finding_sca.package_name`          | Parse from GAV: `gav://group:artifact:version` → extract `artifact` |
| `vulnerable_component`    | `finding_sca.package_version`       | Parse version from GAV                                              |
| `package_type`            | `finding_sca.package_type`          | e.g. `maven`, `npm`, `pypi`                                         |
| `fixed_versions[0]`       | `finding_sca.fixed_version`         | First available fix (array, may be empty)                           |
| `impact_path`             | `finding_sca.dependency_path`       | JSON array showing transitive dependency chain                      |
| `impacted_artifact`       | `finding_sca.affected_artifact`     | Full GAV of the impacted artifact                                   |
| `component_physical_path` | `finding_sca.build_project`         | Physical path within artifact (e.g. `set-web.war/WEB-INF/lib/...`)  |
| `summary`                 | `findings.title`                    | Short vulnerability summary                                         |
| `description`             | `findings.description`              | Full vulnerability description                                      |
| `severity`                | `findings.original_severity`        | Xray uses Critical/High/Medium/Low                                  |
| `cvss3_max_score`         | `findings.cvss_score`               | Pre-computed max across all CVEs                                    |
| `cves[0].cvss_v3_vector`  | `findings.cvss_vector`              | Vector from highest-scoring CVE                                     |
| `cves[].cve`              | `findings.cve_ids`                  | JSON array of all CVE identifiers                                   |
| `issue_id`                | `findings.source_finding_id`        | Xray issue ID (e.g. `XRAY-55689`)                                   |
| `published`               | `findings.first_seen`               | ISO 8601 with timezone offset                                       |
| `artifact_scan_time`      | `findings.last_seen`                | When Xray last scanned the artifact                                 |
| `references`              | `findings.metadata.references`      | Array of reference URLs, stored in metadata JSONB                   |
| `severity_source`         | `findings.metadata.severity_source` | e.g. "CVSS V3 from NVD"                                             |
| `applicability`           | `findings.metadata.applicability`   | Xray contextual analysis result (nullable)                          |
| (full record)             | `findings.raw_finding`              | Entire JSON record preserved for audit                              |

**App code extraction:** The application code is embedded in organization-specific fields — see Section 1.4 for the configurable resolver.

**Fingerprint:** `Hash(application_id + package_name + package_version + cve_id)` — one fingerprint per CVE. A single Xray record with multiple CVEs produces multiple findings.

**Dependency type inference:** If `impact_path` has 3+ entries, the vulnerable component is transitive (`Transitive`); if 2 entries (artifact → component), it's `Direct`.

**Severity normalization:** Xray's Critical/High/Medium/Low maps 1:1 to `SeverityLevel`. Records without a severity (unlikely but defensive) map to `Info`.

### 1.2 Tenable WAS Parser (DAST)

**Input format:** CSV only. Tenable WAS exports are available exclusively as CSV. No JSON export is available from the Tenable WAS console.

**CSV parsing challenges:** Fields like `Plugin Output` and `Description` contain multi-line text with embedded newlines inside quoted fields (RFC 4180 compliant). Rust's `csv` crate handles this correctly. The CSV header row defines 53 columns.

**Volume:** Significantly fewer records than Xray (exact count TBD). Batch processing still recommended for consistency (see Section 1.5).

**Key CSV columns (from real export):**

| CSV Column                                 | Content Example                                       |
| ------------------------------------------ | ----------------------------------------------------- |
| `Plugin`                                   | `"98000"` — numeric plugin ID                         |
| `Family`                                   | `"General"`                                           |
| `Severity`                                 | `"Info"`, `"Low"`, `"Medium"`, `"High"`, `"Critical"` |
| `IP Address`                               | `"10.174.244.10"`                                     |
| `Protocol`                                 | `"TCP"`                                               |
| `Input Name`                               | Parameter name (vulnerable input field)               |
| `Input Type`                               | Parameter type                                        |
| `Proof`                                    | Evidence of vulnerability                             |
| `URL`                                      | `"https://acronym.env.domain.com:12345/path/to/page"` |
| `Port`                                     | `"35341"`                                             |
| `DNS Name`                                 | `"acronym.env.domain.com"`                            |
| `Plugin Output`                            | Multi-line detailed output (can be very long)         |
| `First Discovered`                         | `"Sep 5, 2025 15:30:16 UTC"` — human-readable date    |
| `Last Observed`                            | `"Feb 18, 2026 23:03:51 UTC"`                         |
| `Host ID`                                  | UUID — Tenable's internal asset ID                    |
| `Synopsis`                                 | Short title (e.g. `"Web Application Sitemap"`)        |
| `Description`                              | Long description (multi-line)                         |
| `Steps to Remediate`                       | Remediation guidance                                  |
| `See Also`                                 | Reference URLs                                        |
| `Risk Factor`                              | `"Info"`, `"Low"`, `"Medium"`, `"High"`, `"Critical"` |
| `Vulnerability Priority Rating`            | Tenable VPR score                                     |
| `Exploit Prediction Scoring System (EPSS)` | EPSS score                                            |
| `CVSS V2 Base Score`                       | Numeric or empty                                      |
| `CVSS V3 Base Score`                       | Numeric or empty                                      |
| `CVSS V4 Base Score`                       | Numeric or empty                                      |
| `CVSS V3 Vector`                           | Vector string or empty                                |
| `CVSS V4 Vector`                           | Vector string or empty                                |
| `CVE`                                      | CVE identifier(s) or empty                            |
| `BID`                                      | Bugtraq ID or empty                                   |
| `Cross References`                         | Additional reference IDs                              |
| `Exploit?`                                 | `"No"` / `"Yes"`                                      |
| `Exploit Frameworks`                       | Framework names if exploitable                        |
| `ACR`                                      | Asset Criticality Rating (Tenable metric)             |
| `AES`                                      | Asset Exposure Score (Tenable metric)                 |
| `Check Type`                               | `"remote"`                                            |

**Field mapping to `finding_dast` + `findings` tables:**

| CSV Column                      | SynApSec Field                         | Notes                                                          |
| ------------------------------- | -------------------------------------- | -------------------------------------------------------------- |
| `URL`                           | `finding_dast.target_url`              | Full URL of vulnerable endpoint                                |
| `Input Name`                    | `finding_dast.parameter`               | Vulnerable parameter name (replaces assumed `Parameter`)       |
| `Proof`                         | `finding_dast.request_evidence`        | Evidence of the vulnerability                                  |
| `Plugin Output`                 | `finding_dast.response_evidence`       | Detailed scan output (multi-line)                              |
| `DNS Name`                      | `finding_dast.web_application_name`    | Hostname — used for app code resolution (see Section 1.4)      |
| `Synopsis`                      | `findings.title`                       | Short vulnerability title                                      |
| `Description`                   | `findings.description`                 | Full description (multi-line)                                  |
| `Severity`                      | `findings.original_severity`           | Critical/High/Medium/Low/Info                                  |
| `Plugin`                        | `findings.source_finding_id`           | Numeric plugin ID, combined with URL+Input Name for uniqueness |
| `CVE`                           | `findings.cve_ids`                     | JSON array (may be empty)                                      |
| `CVSS V3 Base Score`            | `findings.cvss_score`                  | Prefer V3; fall back to V4, then V2                            |
| `CVSS V3 Vector`                | `findings.cvss_vector`                 | Prefer V3; fall back to V4, then V2                            |
| `Steps to Remediate`            | `findings.remediation_guidance`        | Direct mapping                                                 |
| `First Discovered`              | `findings.first_seen`                  | Parse human-readable: `"Sep 5, 2025 15:30:16 UTC"`             |
| `Last Observed`                 | `findings.last_seen`                   | Same date format                                               |
| `EPSS`                          | `findings.metadata.epss`               | Stored in metadata JSONB for now                               |
| `Vulnerability Priority Rating` | `findings.metadata.vpr`                | Tenable's own priority score                                   |
| `ACR`                           | `findings.metadata.acr`                | Asset Criticality Rating                                       |
| `AES`                           | `findings.metadata.aes`                | Asset Exposure Score                                           |
| `Exploit?`                      | `findings.metadata.exploitable`        | Boolean                                                        |
| `Exploit Frameworks`            | `findings.metadata.exploit_frameworks` | String                                                         |
| `Host ID`                       | `findings.metadata.tenable_host_id`    | Tenable's asset UUID                                           |
| `IP Address`                    | `findings.metadata.ip_address`         | Target IP                                                      |
| `Port`                          | `findings.metadata.port`               | Target port                                                    |
| `See Also`                      | `findings.metadata.references`         | Reference URLs                                                 |
| `Cross References`              | `findings.metadata.cross_references`   | Additional identifiers (e.g. OWASP, CWE via cross-ref)         |
| (full record)                   | `findings.raw_finding`                 | Entire CSV row preserved as JSON for audit                     |

**CWE extraction:** Tenable WAS CSV has no dedicated CWE column. CWE identifiers may appear in `Cross References` (e.g. `CWE:89`). The parser extracts CWE IDs from cross-references via regex, falling back to empty array if absent.

**HTTP method:** No dedicated column exists. The parser does not populate `finding_dast.http_method` — it remains NULL. If URL patterns suggest method context, analysts can enrich manually.

**Authentication context:** `finding_dast.authentication_required` and `authentication_context` can be inferred from `Plugin Output` if Selenium authentication was used (detected via "Selenium Authentication: Succeeded" in scan info records).

**Informational records:** Plugins like 98000 (Scan Information) and 98009 (Web Application Sitemap) are scan metadata, not vulnerabilities. The parser skips records where `Severity = "Info"` AND `Family = "General"`. Actual informational-severity findings (specific plugin families) are still ingested.

**Date parsing:** Tenable uses human-readable format `"MMM d, yyyy HH:mm:ss UTC"` (e.g. `"Sep 5, 2025 15:30:16 UTC"`). Requires custom `chrono` format string, not ISO 8601.

**App code extraction:** The application code must be parsed from `URL` or `DNS Name` — see Section 1.4 for the configurable resolver.

**Fingerprint:** `Hash(application_id + plugin_id + target_url + input_name)` — `input_name` replaces the previously assumed `parameter` field. When `Input Name` is empty, fingerprint uses `Hash(application_id + plugin_id + target_url)`.

**Severity normalization:** Tenable's `Severity` column uses Critical/High/Medium/Low/Info which maps 1:1 to `SeverityLevel`. The `Risk Factor` column uses slightly different labels (e.g. "Informational" vs "Info") — we use `Severity`, not `Risk Factor`.

### 1.3 Parser Implementation

Both parsers implement the existing `Parser` trait from `parsers/mod.rs` and produce `Vec<ParsedFinding>` that flows through the same ingestion pipeline as SonarQube. The `ParserType` enum gains two new variants: `JfrogXray` and `TenableWas`.

**New backend files:**

- `parsers/jfrog_xray.rs`
- `parsers/tenable_was.rs`

**Test fixtures:**

- `tests/fixtures/jfrog_xray_sample.json`
- `tests/fixtures/tenable_was_sample.csv`

### 1.4 App Code Resolution

Both Xray and Tenable WAS embed the application identifier in unstructured fields using organization-specific conventions. There is no universal extraction rule — it varies by organization and even by scanner configuration.

**App code format:** Enterprise app codes (also called "acronym codes") are typically 5 characters — usually 4 letters followed by a digit (often `0`), e.g. `PAYM1`, `USRP0`. However, this is not always the case (e.g. `gpe30` is 5 characters but with a different pattern). The resolver must not hardcode a strict format assumption.

**Xray examples** (app code = `gpe30`):

- GAV groupId in `impacted_artifact`: `gav://com.ourcompany.gpe30:set-ear:0.0.1` → extract `gpe30` from groupId
- Repository path in `path`: `prod-release-local/gpe30/gpe30-set/v1.2.0-rc1/set-ear.ear` → second path segment

**Tenable WAS examples** (app code = `acronym`):

- URL: `https://sacronym.environment.env.domain.com:12345/scriptAcronym/ESTERO/init2` → extract subdomain prefix, **strip environment prefix**
- DNS Name: `sacronym.environment.env.domain.com` → first subdomain segment, **strip environment prefix**

**DAST environment prefixes:** In Tenable WAS data, the DNS/URL subdomain is prefixed with an environment indicator that must be stripped before matching:
- `s` prefix = system-test environment (e.g. `sacronym` → app code `acronym`)
- `t` prefix = development environment (e.g. `tacronym` → app code `acronym`)
- No prefix = production (e.g. `acronym` → app code `acronym`)

The regex patterns for Tenable WAS must account for this prefix stripping.

**Strategy: Configurable regex-based resolver.**

New migration adds an `app_code_patterns` table:

```sql
CREATE TABLE app_code_patterns (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_tool     VARCHAR(100) NOT NULL,   -- 'JFrog Xray', 'Tenable WAS', etc.
    field_name      VARCHAR(100) NOT NULL,   -- which field to extract from
    regex_pattern   TEXT NOT NULL,            -- regex with a named capture group `app_code`
    priority        INTEGER NOT NULL DEFAULT 0,  -- higher = tried first
    description     TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_app_code_patterns_updated_at
    BEFORE UPDATE ON app_code_patterns
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

**Seed rules (organization-specific, adjustable):**

| # | Source Tool | Field               | Regex                                     | Priority | Description                                 |
|---|------------|----------------------|-------------------------------------------|----------|---------------------------------------------|
| 1 | JFrog Xray  | `path`              | `^[^/]+/(?P<app_code>[^/]+)/`             | 10       | Second segment of repo path                 |
| 2 | JFrog Xray  | `impacted_artifact` | `gav://com\.\w+\.(?P<app_code>\w+):`      | 5        | Third segment of GAV groupId                |
| 3 | Tenable WAS | `DNS Name`          | `^[st](?P<app_code>[^.]+)\.`              | 10       | Strip `s`/`t` env prefix from subdomain     |
| 4 | Tenable WAS | `DNS Name`          | `^(?P<app_code>[^.]+)\.`                  | 5        | Full first subdomain (fallback, no strip)   |
| 5 | Tenable WAS | `URL`               | `https?://[st](?P<app_code>[^.]+)\.`      | 10       | Strip `s`/`t` env prefix from URL subdomain |
| 6 | Tenable WAS | `URL`               | `https?://(?P<app_code>[^.]+)\.`          | 5        | Full subdomain from URL (fallback)          |

**Why two Tenable patterns per field:** Pattern #3 strips the `s`/`t` prefix and is tried first (higher priority). If the extracted app code doesn't match any known application (step 3 in the resolution flow), the resolver falls through to pattern #4 which tries the full subdomain. This handles edge cases where an app code naturally starts with `s` or `t` (e.g. app code `sbank0` → pattern #3 extracts `bank0` → no match → pattern #4 extracts `sbank0` → matches).

**Resolution flow during ingestion:**

1. For each parsed finding, try active patterns for the source tool in priority order
2. First match that produces a non-empty `app_code` is used
3. Look up `app_code` against `applications.app_code` (case-insensitive)
4. If matched → set `findings.application_id`
5. If no match → finding is ingested with `application_id = NULL` and appears in the **Unmapped Apps** page for manual resolution

**Admin UI:** The app code patterns are manageable via a settings endpoint (Phase 2 scope: API only, UI deferred to Phase 3 settings page). For now, patterns are configured via seed data or direct DB edits.

### 1.5 Volume and Performance

With ~820k Xray records (the largest dataset by far), naive single-record processing is not viable.

**Batch ingestion strategy:**

- Parser produces `Vec<ParsedFinding>` as before (streaming deserialization for large files via `serde_json::StreamDeserializer` for Xray, `csv::Reader` iterator for Tenable)
- Ingestion service processes findings in configurable batches (default: 1000 records per batch)
- Each batch is a single database transaction: bulk INSERT with `ON CONFLICT` for dedup
- Progress reporting: `ingestion_logs` updated after each batch with running totals
- Memory: parser streams records rather than loading the entire file into memory

**Estimated ingestion time targets:**

- Xray 820k records: < 30 minutes (target, depends on DB hardware)
- Tenable WAS: significantly faster (fewer records overall)

**Frontend UX during large imports:**

- Ingestion page shows a progress indicator (records processed / total)
- The `total_rows` field in Xray JSON provides the denominator upfront
- For CSV (no upfront count), progress shows records processed with a spinner

### 1.6 SBOM Parser (Future)

SBOM export details are not yet available. SBOM parser will be added once the export format is provided. The `finding_sca` table already has an `sbom_reference` column ready for this.

### 1.7 Branch and Environment Strategy

Each scanner category operates against a different stage of the software lifecycle:

| Category | Target | Environment Equivalent |
|---|---|---|
| **SAST** (SonarQube) | Source code on two branches: `master` (development) and `production` | Development + Production |
| **SCA** (JFrog Xray) | Build artifacts (production releases) | Production |
| **DAST** (Tenable WAS) | System-test environment (deployed, running application) | Pre-production (close to production) |

SonarQube findings already carry a `branch` attribute (stored in `metadata`) that differentiates which branch they came from. A finding for the same CWE at the same file:line may exist on **both** branches simultaneously — these are **not duplicates**. They represent the vulnerability state of two different environments with independent remediation timelines.

**Design decision: production branch is the source of truth for risk.**

This affects every intelligence feature:

1. **Cross-tool correlation** defaults to matching against **production-branch SAST findings**, because SCA and DAST both reflect production-like code. A DAST-confirmed SQL injection should correlate with the SAST finding on the `production` branch (the code actually running), not the `master` branch (which may already contain a fix not yet deployed).

2. **Deduplication** across SAST tools (when a second SAST scanner is added) must compare findings **within the same branch only**. A finding on `master` and the same finding on `production` are distinct records.

3. **Attack Chains and risk scoring** default to the **production** branch perspective — this shows what's actually at risk right now.

4. **Remediation tracking** benefits from both branches:
   - Finding exists on **both** `master` and `production` → vulnerability is active everywhere
   - Finding exists on **`production` only** (gone from `master`) → fix is in the development pipeline, awaiting deployment
   - Finding exists on **`master` only** → new issue in development, not yet in production
   - Finding gone from **both** → remediation complete

5. **All views are filterable by branch** so analysts can switch perspective (e.g., "show me what's coming on master that isn't in production yet").

This strategy is implemented as a `?branch=production` query parameter on relevant API endpoints, defaulting to `production` when not specified. The SonarQube parser already stores branch in `findings.metadata.branch`; the correlation engine reads this field when matching.

---

## 2. Cross-Tool Deduplication

### 2.1 Problem

Phase 1 dedup is intra-tool only — it matches by exact fingerprint, meaning the same vulnerability reported by two different tools creates two separate findings. Cross-tool dedup identifies when findings from different scanners refer to the same underlying issue.

### 2.2 Key Principle: Dedup vs Correlation

True **deduplication** means the *same vulnerability* was independently reported by multiple tools. This realistically only happens when two tools of the **same category** scan the same target:
- Two SCA tools both flag the same CVE in the same library
- Two SAST tools both flag the same code weakness at the same location
- Two DAST tools both find the same issue on the same endpoint

**Cross-category** findings (e.g., SCA vulnerability + SAST code weakness + DAST confirmed exploit) are almost always *different perspectives on related risks*. An SCA finding about a vulnerable library and a SAST finding about insecure code are not duplicates — they have different root causes, different remediation paths, and different lifecycle tracking. These belong in the **Correlation Engine** (Section 3), not deduplication.

Importantly: SAST tools produce **CWE** identifiers (code weakness classes), not **CVE** identifiers (specific known vulnerabilities in specific software versions). There is no CVE on the SAST side to match against an SCA finding.

### 2.3 Matching Rules

Cross-tool dedup runs **after** intra-tool dedup during ingestion. It targets same-category, different-tool scenarios.

**Branch constraint:** For SAST findings, dedup only matches findings on the **same branch** (see Section 1.7). A CWE-89 on `master` and the same CWE-89 on `production` are NOT duplicates — they track independent remediation timelines.

| Rule | Categories | Confidence | Logic |
|---|---|---|---|
| Same CVE + same package + same application | SCA ↔ SCA | High | Different `source_tool`, exact CVE + `package_name` match on same `application_id` |
| Same CWE + same file + same/nearby line + same branch | SAST ↔ SAST | High | Different `source_tool`, same CWE + `file_path` + line within ±5 range on same `application_id` + same `branch` |
| Same CWE + same file + same branch (different line) | SAST ↔ SAST | Medium | Same CWE + `file_path` + same `branch` but lines differ by more than 5 — possible same issue flagged at different granularity |
| Same plugin/check + same URL + same parameter | DAST ↔ DAST | High | Different `source_tool`, same vulnerability type + `target_url` + `parameter` on same `application_id` |
| Same CWE + same URL (no parameter match) | DAST ↔ DAST | Medium | Same vulnerability class at same endpoint but different parameter or no parameter — possible same issue |

**Note:** Currently we have one tool per category (SonarQube=SAST, Xray=SCA, Tenable WAS=DAST), so cross-tool dedup won't trigger until additional scanners are onboarded. However, the rules are implemented now so the platform is ready. The intra-tool dedup (Phase 1 fingerprint matching) continues to handle same-tool duplicates across imports.

### 2.4 Relationship Creation

When a cross-tool dedup match is found, it creates a `finding_relationships` row:

- `relationship_type`: always `duplicate_of` (dedup only produces duplicates — cross-category relationships like `correlated_with` are handled by the Correlation Engine in Section 3)
- `confidence`: matches the rule confidence (High or Medium)
- `created_by`: NULL (system-generated — distinguishes from manual analyst links)
- `notes`: describes which rule triggered the match

Medium-confidence matches are flagged for analyst review in the Deduplication Dashboard. The platform may hide confirmed duplicates from default finding views.

### 2.5 Analyst Override

All auto-generated dedup relationships appear in the Deduplication dashboard. Analysts can:

- **Confirm** — marks a Medium match as analyst-verified
- **Reject** — removes the relationship, adds a `notes` entry explaining why
- **Split** — breaks an incorrect `duplicate_of` back into independent findings
- **Merge** — manually marks two findings as `duplicate_of` when the engine missed them

### 2.6 Impact on Risk Score

When relationships change, `correlation_density` in the risk score is recalculated for affected findings. The scoring (already implemented in `risk_score.rs` but currently receiving 0):

- 3+ tools/findings correlated → score 100
- 2 tools → score 70
- Multiple same-tool → score 40
- Standalone → score 10

Phase 2 wires this to real relationship data from the correlation engine.

---

## 3. Correlation Engine

### 3.1 Distinction from Deduplication

Deduplication asks: "Is this the _same_ vulnerability seen by multiple tools?"
Correlation asks: "Are these _different_ vulnerabilities that together form a bigger risk?"

Example: A SQL injection in code (SAST) + an unpatched database driver (SCA) + a confirmed SQL injection on the exposed endpoint (DAST) are three different findings, but correlated they reveal an exploitable attack path from source code to production. Each finding keeps its own lifecycle, but they're linked as a correlation group.

### 3.2 Correlation Rules

Rule-based matching, configurable and extensible. Initial rule set from the PRD:

**Branch strategy for correlation (see Section 1.7):** Cross-category rules (CR-1 through CR-4) that involve SAST findings match against the **production branch** by default, because SCA and DAST both reflect production-deployed code. Intra-SAST rules (CR-5, CR-6) operate within each branch independently.

| #    | Rule                                                   | Input Categories | Relationship Type | Confidence | Rationale |
| ---- | ------------------------------------------------------ | ---------------- | ----------------- | ---------- | --------- |
| CR-1 | Same CVE on same application across categories         | SCA ↔ DAST      | `correlated_with` | High       | SCA reports vulnerable dependency; DAST confirms it's exploitable at a reachable endpoint. Both reference the same CVE. (Note: SAST does not produce CVEs, so SCA ↔ SAST is not applicable here.) |
| CR-2 | Same CWE on same application across categories         | SAST ↔ DAST    | `correlated_with` | Medium     | SAST finds code weakness (e.g. CWE-89 SQL injection); DAST confirms exploitability at an endpoint. Uses **production-branch** SAST findings (see Section 1.7). |
| CR-3 | SCA vulnerable package matched to SAST file imports    | SCA → SAST      | `correlated_with` | Medium     | SCA flags a vulnerable library; SAST finds code that imports/uses that library. Uses **production-branch** SAST findings. Together they indicate the vulnerable code path is actually exercised. |
| CR-4 | DAST endpoint matched to SAST handler via app metadata | DAST → SAST     | `correlated_with` | Medium     | DAST finds a vulnerability at a URL; SAST found a weakness in the code handling that route. Uses **production-branch** SAST findings. Requires URL-to-file mapping via application metadata. |
| CR-5 | Same rule_id across multiple files in same application | SAST ↔ SAST    | `grouped_under`   | High       | Systemic pattern: the same code weakness repeated across multiple files. Operates **within each branch independently** — a pattern on `master` and the same pattern on `production` produce separate groups. |
| CR-6 | Same CWE in same file (clustered vulnerabilities)      | SAST ↔ SAST    | `grouped_under`   | High       | Multiple weaknesses of the same class concentrated in one file. Operates **within each branch independently**. |

### 3.3 When Correlation Runs

- **On ingestion:** After a new finding passes dedup, the engine evaluates it against existing findings on the same `application_id`. Scoped per-application to avoid full-table scans. For cross-category rules (CR-1 through CR-4), SAST findings are filtered to the `production` branch. For intra-SAST rules (CR-5, CR-6), findings are matched within the same branch as the incoming finding.
- **On demand:** An analyst can trigger "re-correlate" for an application (useful after bulk import or rule changes). Supports an optional `?branch=` parameter to target a specific branch; defaults to `production`.

### 3.4 Correlation Groups

A "correlation group" is a connected set of findings linked via `correlated_with` or `grouped_under` relationships. The API computes groups dynamically via a recursive CTE — no separate table needed. Each group has:

- A **primary finding** (highest severity or oldest)
- A **group risk** (aggregate of member risk scores)
- **Tool coverage** (which categories are represented)

### 3.5 Correlation Rules Storage

New migration (`002_correlation_and_app_patterns.sql`) — includes both tables. Correlation rules portion:

```sql
CREATE TABLE correlation_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    rule_type   VARCHAR(50) NOT NULL,  -- 'cross_tool', 'intra_tool', 'pattern'
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
```

The 6 initial rules are seeded as default system rules.

### 3.6 API Endpoints

| Method   | Path                               | Purpose                                                |
| -------- | ---------------------------------- | ------------------------------------------------------ |
| `GET`    | `/api/v1/correlations/groups`      | List correlation groups (paginated, filterable by app) |
| `GET`    | `/api/v1/correlations/groups/:id`  | Get a specific group with all member findings          |
| `GET`    | `/api/v1/correlations/rules`       | List correlation rules                                 |
| `POST`   | `/api/v1/correlations/rules`       | Create custom rule                                     |
| `PUT`    | `/api/v1/correlations/rules/:id`   | Update rule                                            |
| `POST`   | `/api/v1/correlations/run/:app_id` | Trigger re-correlation for an application              |
| `POST`   | `/api/v1/relationships`            | Manually create a relationship (analyst link)          |
| `DELETE` | `/api/v1/relationships/:id`        | Remove a relationship (analyst unlink)                 |

### 3.7 Graph Visualization Data Model (Phase 3 Preparation)

The correlation group API returns data shaped for graph rendering:

```json
{
  "group_id": "uuid",
  "primary_finding_id": "uuid",
  "tool_coverage": ["SAST", "SCA", "DAST"],
  "group_risk_score": 87.5,
  "findings": [
    { "id": "uuid", "title": "...", "category": "SAST", "severity": "High" },
    { "id": "uuid", "title": "...", "category": "SCA", "severity": "Critical" }
  ],
  "relationships": [
    {
      "source": "uuid",
      "target": "uuid",
      "type": "correlated_with",
      "confidence": "High"
    }
  ]
}
```

`findings` = nodes, `relationships` = edges. Phase 3 graph visualization (target library: React Flow) plugs directly into this response without API changes.

**Graph views (Phase 3):**

1. **Per-application graph** — accessed from the Attack Chains detail page (`/attack-chains/:app_id`). Shows all correlation groups for one application: its findings as nodes, its relationships as edges. This is the primary use case.
2. **Risk-score-filtered graph** — same graph structure, filtered by a risk score threshold (e.g., "show only groups with group_risk_score >= 80"). Implemented as a client-side slider/filter on the Attack Chains detail page that shows or hides groups below the threshold, keeping the graph focused on the highest-risk chains. No additional API needed — the `group_risk_score` field is already in the response.

---

## 4. Attack Chains (Per-Application Risk View)

### 4.1 Concept

Attack Chains takes correlation data and presents it as an application-centric risk story. Instead of "here are 47 findings for Payment Service", it says: "Payment Service has 3 attack chains: an exploitable SQL injection path (SAST+DAST), an unpatched critical dependency (SCA), and a cluster of hardcoded credentials across 5 files (SAST)."

### 4.2 Data Source

Attack chains are derived from correlation groups, filtered per application. Each correlation group on an application becomes an attack chain. Standalone findings (no correlations) are grouped separately as "Uncorrelated Findings."

No new database table — attack chains are a view layer over existing `findings` + `finding_relationships` data.

### 4.3 Page Structure

**Top-level view — all applications ranked by risk:**

| Column             | Content                                   |
| ------------------ | ----------------------------------------- |
| Application        | Name + app_code                           |
| Risk Score         | Aggregate composite score (highest chain) |
| Attack Chains      | Count of correlated groups                |
| Tool Coverage      | Badges: SAST / SCA / DAST                 |
| Severity Breakdown | Critical / High / Medium / Low counts     |
| Uncorrelated       | Count of standalone findings              |

Sorted by risk score descending. Filterable by criticality tier, business unit, tool coverage, and **branch** (defaults to `production` — see Section 1.7).

**Application detail view — attack chain cards:**

Each attack chain is a card showing:

- **Chain title** — derived from the primary finding's title or the shared CWE description
- **Severity badge** — highest severity among member findings
- **Tool coverage** — which categories are represented
- **Member findings** — listed with category badge, severity, and title
- **Group risk score** — from the correlation engine
- **Confidence** — lowest confidence among the group's relationships

Below the attack chain cards: a table of **Uncorrelated Findings** for the same application.

### 4.4 API Endpoints

| Method | Path                            | Purpose                                                   |
| ------ | ------------------------------- | --------------------------------------------------------- |
| `GET`  | `/api/v1/attack-chains`         | List applications with attack chain summaries (paginated). Supports `?branch=` filter (default: `production`) |
| `GET`  | `/api/v1/attack-chains/:app_id` | Get all attack chains for one application. Supports `?branch=` filter (default: `production`) |

### 4.5 Phase 3 Graph Visualization — Design Commitment

The card-based view in Phase 2 **will be augmented, not replaced** in Phase 3 with an interactive graph:

- Each finding is a **node** (colored by category: blue=SAST, purple=SCA, teal=DAST)
- Each relationship is an **edge** (solid=High confidence, dashed=Medium, dotted=Low)
- Nodes sized by severity
- Click a node to see finding detail
- Click an edge to see the correlation rule that created it
- **Risk score filter** — slider/threshold control to show only correlation groups above a given risk score, keeping the graph focused on the most critical chains
- Target library: **React Flow** (MIT licensed, designed for interactive node graphs)

The graph is accessed from the **Attack Chains detail page** (`/attack-chains/:app_id`), providing a per-application perspective. The risk score filter is client-side — no additional API needed since `group_risk_score` is already in the Phase 2 response shape (Section 3.7).

The Phase 2 API response shape (nodes + edges in correlation group response) is explicitly designed to feed this graph with zero API changes. This is a **hard requirement** for Phase 3.

---

## 5. Deduplication Dashboard

### 5.1 Page Structure

A dedicated sidebar entry giving analysts visibility and control over the dedup engine. Statistics and tables are global by default (all branches), with an optional branch filter for SAST-related data.

**Section 1 — Statistics (top cards):**

| Stat               | Source                                                                       |
| ------------------ | ---------------------------------------------------------------------------- |
| Total Raw Ingested | Sum of `ingestion_logs.total_records`                                        |
| Unique Findings    | Count of `findings`                                                          |
| Dedup Ratio        | `1 - (unique / raw)` as percentage                                           |
| Cross-Tool Matches | Count of `finding_relationships` where `relationship_type = 'duplicate_of'`  |
| Pending Review     | Count of relationships with `confidence = 'Low'` and no analyst confirmation |

**Section 2 — Pending Review (main table):**

Low-confidence matches needing analyst decision:

| Column       | Content                           |
| ------------ | --------------------------------- |
| Finding A    | Title + category badge + severity |
| Finding B    | Title + category badge + severity |
| Match Reason | Which rule triggered              |
| Confidence   | Low / Medium badge                |
| Actions      | Confirm / Reject buttons          |

Sorted by creation date descending. Filterable by confidence, application, category.

**Section 3 — Recent Decisions (history table):**

Analyst-confirmed and rejected matches for audit trail. Shows who acted, when, and what action.

### 5.2 API Endpoints

| Method | Path                                             | Purpose                          |
| ------ | ------------------------------------------------ | -------------------------------- |
| `GET`  | `/api/v1/deduplication/stats`                    | Dedup statistics                 |
| `GET`  | `/api/v1/deduplication/pending`                  | Pending review pairs (paginated) |
| `GET`  | `/api/v1/deduplication/history`                  | Recent decisions (paginated)     |
| `POST` | `/api/v1/deduplication/:relationship_id/confirm` | Analyst confirms a match         |
| `POST` | `/api/v1/deduplication/:relationship_id/reject`  | Analyst rejects a match          |

---

## 6. Findings Page Tabs

### 6.1 Tab Structure

Horizontal tabs at the top of the existing Findings page: **All | SAST | SCA | DAST**

| Tab      | Filter                      | Additional Columns                                                                            |
| -------- | --------------------------- | --------------------------------------------------------------------------------------------- |
| **All**  | None (current unified view) | Common columns only: title, severity, status, application, source tool, first seen, last seen |
| **SAST** | `finding_category = 'SAST'` | file_path, line_number, rule_id, project, language                                            |
| **SCA**  | `finding_category = 'SCA'`  | package_name, package_version, fixed_version, dependency_type, known_exploited                |
| **DAST** | `finding_category = 'DAST'` | target_url, parameter (Input Name), web_application_name (DNS), plugin_id                     |

### 6.2 Implementation

The existing `GET /api/v1/findings` endpoint already supports `?category=SAST` filtering. Category-specific columns require a JOIN to the category table — the backend adds an optional `include_category_data=true` query param that triggers the join and includes extra fields in the response as a `category_data` object.

Tabs are URL-driven (`/findings?tab=sast`) so they're bookmarkable and shareable. The SAST tab additionally supports a **branch filter** (`/findings?tab=sast&branch=production`) defaulting to all branches. This lets analysts focus on production findings or compare branches.

---

## 7. Updated Navigation

### 7.1 Sidebar Structure

```
Dashboard              — overview: where do I stand?
Findings               — analysis: what vulnerabilities exist? (tabs: All | SAST | SCA | DAST)
Applications           — context: which apps are affected?
Attack Chains      ★   — insight: how do findings connect per app?
Triage Queue           — action: what needs my decision?
───────────────────
Ingestion              — import: bring data in
Deduplication      ★   — engine: duplicate removal
Correlation        ★   — engine: relationship detection
Unmapped Apps          — cleanup: data quality
```

The sidebar follows the analyst workflow funnel: **overview → drill down → contextualize → correlate → decide**.

- **Above the line** — daily analyst journey. Each item naturally leads to the next: check the overview, investigate findings, understand which apps are affected, see how findings chain together, then triage what needs attention.
- **Below the line** — pipeline operations in data-flow order (import → deduplicate → correlate) plus data quality cleanup. These are periodic/administrative tasks, not the daily workflow.

---

## 8. New Files Summary

### 8.1 Backend

| File                                              | Purpose                                                          |
| ------------------------------------------------- | ---------------------------------------------------------------- |
| `parsers/jfrog_xray.rs`                           | JFrog Xray SCA parser (JSON only, streaming)                     |
| `parsers/tenable_was.rs`                          | Tenable WAS DAST parser (CSV only, RFC 4180)                     |
| `services/app_code_resolver.rs`                   | Configurable regex-based app code extraction from scanner fields |
| `services/correlation.rs`                         | Correlation engine (rules, matching, group computation)          |
| `routes/correlation.rs`                           | Correlation API endpoints                                        |
| `routes/deduplication.rs`                         | Deduplication dashboard API endpoints                            |
| `routes/attack_chains.rs`                         | Attack chain API endpoints                                       |
| `migrations/002_correlation_and_app_patterns.sql` | `correlation_rules` + `app_code_patterns` tables + seed data     |
| `tests/fixtures/jfrog_xray_sample.json`           | Test fixture for SCA parser (derived from real export)           |
| `tests/fixtures/tenable_was_sample.csv`           | Test fixture for DAST parser (derived from real export)          |

### 8.2 Frontend

| File                              | Purpose                                               |
| --------------------------------- | ----------------------------------------------------- |
| `pages/AttackChainsPage.tsx`      | Application risk list                                 |
| `pages/AttackChainDetailPage.tsx` | Per-app attack chain cards + uncorrelated findings    |
| `pages/CorrelationPage.tsx`       | Correlation rules, groups, manual link/unlink         |
| `pages/DeduplicationPage.tsx`     | Stats, pending review, decision history               |
| `api/correlation.ts`              | Correlation API client                                |
| `api/deduplication.ts`            | Deduplication API client                              |
| `api/attack-chains.ts`            | Attack chain API client                               |
| `types/correlation.ts`            | TypeScript types for correlation, relationship, group |
| `types/deduplication.ts`          | TypeScript types for dedup stats, pending review      |

### 8.3 Seed Data Updates

Extend `seed.rs` to include:

- Default `app_code_patterns` for both Xray (GAV groupId, repo path) and Tenable WAS (DNS subdomain, URL subdomain)
- Sample JFrog Xray fixture (SCA findings with CVEs, derived from real export format)
- Sample Tenable WAS fixture (DAST findings with URLs, derived from real CSV export)
- Pre-created correlation relationships between seed findings
- Default correlation rules (CR-1 through CR-6)
- This ensures all new pages have data to display in development

### 8.4 E2E Tests

Extend the Playwright suite:

- Attack Chains page loads and shows applications
- Correlation page loads and shows rules
- Deduplication page loads and shows stats
- Findings tabs switch correctly between All/SAST/SCA/DAST

---

## 9. Execution Order

| #   | Component                                                        | Dependencies                                          |
| --- | ---------------------------------------------------------------- | ----------------------------------------------------- |
| 1   | Migration: `correlation_rules` table + `app_code_patterns` table | None                                                  |
| 2   | App code resolver service                                        | Migration applied                                     |
| 3   | JFrog Xray parser (JSON, batch ingestion)                        | Migration + app code resolver                         |
| 4   | Tenable WAS parser (CSV, batch ingestion)                        | Migration + app code resolver                         |
| 5   | Seed data (SCA + DAST fixtures + app code patterns)              | Parsers implemented                                   |
| 6   | Cross-tool deduplication logic                                   | Parsers (need multi-tool data)                        |
| 7   | Correlation engine                                               | Cross-tool dedup (shares relationship infrastructure) |
| 8   | Wire correlation density into risk score                         | Correlation engine                                    |
| 9   | Findings page tabs                                               | Parsers (need SCA/DAST data to display)               |
| 10  | Deduplication dashboard (backend + frontend)                     | Cross-tool dedup                                      |
| 11  | Correlation page (backend + frontend)                            | Correlation engine                                    |
| 12  | Attack Chains page (backend + frontend)                          | Correlation engine                                    |
| 13  | Updated sidebar navigation                                       | All new pages                                         |
| 14  | E2E tests                                                        | All pages implemented                                 |
