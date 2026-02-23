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

**Input formats:** JSON (Xray violations API response), CSV (export from Xray UI)

**Field mapping to `finding_sca` + `findings` tables:**

| Xray Field | SynApSec Field | Notes |
|---|---|---|
| `impacted_artifact` | `finding_sca.affected_artifact` | e.g. `libs-release/com/example/lib.jar` |
| `impacted_artifact` (parsed) | `finding_sca.package_name` | Extract from artifact path |
| `component_versions.fixed_versions` | `finding_sca.fixed_version` | First available fix |
| `severity` | `findings.original_severity` | Xray uses Critical/High/Medium/Low/Unknown |
| `cves[].cve` | `findings.cve_ids` | JSON array |
| `cves[].cvss_v3_score` | `findings.cvss_score` | Highest CVSS among CVEs |
| `cves[].cvss_v3_vector` | `findings.cvss_vector` | |
| `watch_name` / `issue_id` | `findings.source_finding_id` | Composite key |
| `properties.build.name` | `finding_sca.build_project` | Maps to `app_code` for application resolution |

**Fingerprint:** `Hash(application_id + package_name + package_version + cve_id)`

**Severity normalization:** Xray's severity maps 1:1 to `SeverityLevel` (both use Critical/High/Medium/Low). `Unknown` maps to `Info`.

### 1.2 Tenable WAS Parser (DAST)

**Input formats:** CSV (Tenable WAS export), JSON (Tenable.io API response)

**Field mapping to `finding_dast` + `findings` tables:**

| Tenable Field | SynApSec Field | Notes |
|---|---|---|
| `URL` | `finding_dast.target_url` | Full URL of vulnerable endpoint |
| `Method` | `finding_dast.http_method` | GET/POST/PUT/etc |
| `Parameter` | `finding_dast.parameter` | Vulnerable parameter |
| `Plugin Name` | `findings.title` | |
| `Plugin ID` | `findings.source_finding_id` | Combined with URL for uniqueness |
| `Severity` | `findings.original_severity` | Tenable uses Critical/High/Medium/Low/Info |
| `CWE` | `findings.cwe_ids` | JSON array |
| `Request` | `finding_dast.request_evidence` | HTTP request text |
| `Response` | `finding_dast.response_evidence` | HTTP response text |
| `Web Application` | `finding_dast.web_application_name` | Maps to `app_code` for application resolution |

**Fingerprint:** `Hash(application_id + target_url + http_method + parameter)`

**Severity normalization:** Tenable maps 1:1 (same scale as ours).

### 1.3 Parser Implementation

Both parsers implement the existing `Parser` trait from `parsers/mod.rs` and produce `Vec<ParsedFinding>` that flows through the same ingestion pipeline as SonarQube. The `ParserType` enum gains two new variants: `JfrogXray` and `TenableWas`.

**New backend files:**
- `parsers/jfrog_xray.rs`
- `parsers/tenable_was.rs`

**Test fixtures:**
- `tests/fixtures/jfrog_xray_sample.json`
- `tests/fixtures/tenable_was_sample.csv`

---

## 2. Cross-Tool Deduplication

### 2.1 Problem

Phase 1 dedup is intra-tool only — it matches by exact fingerprint, meaning the same vulnerability reported by two different tools creates two separate findings. Cross-tool dedup identifies when findings from different scanners refer to the same underlying issue.

### 2.2 Matching Rules

Cross-tool dedup runs **after** intra-tool dedup during ingestion. It uses shared identifiers (CVE, CWE) plus location context to find probable matches across categories.

| Rule | Categories | Confidence | Logic |
|---|---|---|---|
| Same CVE + same application | SCA ↔ SAST, SCA ↔ DAST | High | Exact CVE match on same `application_id` |
| Same CWE + same application + location overlap | SAST ↔ DAST | Medium | Same CWE on same app; DAST URL maps to SAST file via `scanner_project_ids` metadata |
| Same package + same CVE (different tools) | SCA ↔ SCA | High | Different `source_tool`, same `package_name` + `cve_id` |
| Same CWE + same application (no location match) | Any ↔ Any | Low | Weaker signal — same vulnerability class but unconfirmed same instance |

### 2.3 Relationship Creation

When a cross-tool match is found, it creates a `finding_relationships` row:
- `relationship_type`: `duplicate_of` (High confidence) or `correlated_with` (Medium/Low)
- `confidence`: matches the rule confidence
- `created_by`: NULL (system-generated — distinguishes from manual analyst links)
- `notes`: describes which rule triggered the match

**Key distinction:** `duplicate_of` means "this is the same vulnerability seen by two tools" (the platform may hide the duplicate in default views). `correlated_with` means "these are related and likely connected, but may be distinct findings worth tracking separately."

### 2.4 Analyst Override

All auto-generated relationships appear in the Deduplication dashboard. Analysts can:
- **Confirm** — upgrades a Medium/Low match to analyst-verified
- **Reject** — removes the relationship, adds a `notes` entry explaining why
- **Split** — breaks an incorrect `duplicate_of` back into independent findings
- **Merge** — manually marks two findings as `duplicate_of` when the engine missed them

### 2.5 Impact on Risk Score

When relationships change, `correlation_density` in the risk score is recalculated for affected findings. The scoring (already implemented in `risk_score.rs` but currently receiving 0):
- 3+ tools/findings correlated → score 100
- 2 tools → score 70
- Multiple same-tool → score 40
- Standalone → score 10

Phase 2 wires this to real relationship data from the correlation engine.

---

## 3. Correlation Engine

### 3.1 Distinction from Deduplication

Deduplication asks: "Is this the *same* vulnerability seen by multiple tools?"
Correlation asks: "Are these *different* vulnerabilities that together form a bigger risk?"

Example: A SQL injection in code (SAST) + an unpatched database driver (SCA) + a confirmed SQL injection on the exposed endpoint (DAST) are three different findings, but correlated they reveal an exploitable attack path from source code to production. Each finding keeps its own lifecycle, but they're linked as a correlation group.

### 3.2 Correlation Rules

Rule-based matching, configurable and extensible. Initial rule set from the PRD:

| # | Rule | Input Categories | Relationship Type | Confidence |
|---|---|---|---|---|
| CR-1 | Same CVE across different tools | SCA ↔ SAST, SCA ↔ DAST | `correlated_with` | High |
| CR-2 | Same CWE on same application across categories | SAST ↔ DAST | `correlated_with` | Medium |
| CR-3 | SCA vulnerable package matched to SAST file imports | SCA → SAST | `correlated_with` | Medium |
| CR-4 | DAST endpoint matched to SAST handler via app metadata | DAST → SAST | `correlated_with` | Medium |
| CR-5 | Same rule_id across multiple files in same application | SAST ↔ SAST | `grouped_under` | High |
| CR-6 | Same CWE in same file (clustered vulnerabilities) | SAST ↔ SAST | `grouped_under` | High |

### 3.3 When Correlation Runs

- **On ingestion:** After a new finding passes dedup, the engine evaluates it against all existing findings on the same `application_id`. Scoped per-application to avoid full-table scans.
- **On demand:** An analyst can trigger "re-correlate" for an application (useful after bulk import or rule changes).

### 3.4 Correlation Groups

A "correlation group" is a connected set of findings linked via `correlated_with` or `grouped_under` relationships. The API computes groups dynamically via a recursive CTE — no separate table needed. Each group has:
- A **primary finding** (highest severity or oldest)
- A **group risk** (aggregate of member risk scores)
- **Tool coverage** (which categories are represented)

### 3.5 Correlation Rules Storage

New migration (`002_correlation_rules.sql`):

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

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/correlations/groups` | List correlation groups (paginated, filterable by app) |
| `GET` | `/api/v1/correlations/groups/:id` | Get a specific group with all member findings |
| `GET` | `/api/v1/correlations/rules` | List correlation rules |
| `POST` | `/api/v1/correlations/rules` | Create custom rule |
| `PUT` | `/api/v1/correlations/rules/:id` | Update rule |
| `POST` | `/api/v1/correlations/run/:app_id` | Trigger re-correlation for an application |
| `POST` | `/api/v1/relationships` | Manually create a relationship (analyst link) |
| `DELETE` | `/api/v1/relationships/:id` | Remove a relationship (analyst unlink) |

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
    { "source": "uuid", "target": "uuid", "type": "correlated_with", "confidence": "High" }
  ]
}
```

`findings` = nodes, `relationships` = edges. Phase 3 graph visualization (target library: React Flow) plugs directly into this response without API changes.

---

## 4. Attack Chains (Per-Application Risk View)

### 4.1 Concept

Attack Chains takes correlation data and presents it as an application-centric risk story. Instead of "here are 47 findings for Payment Service", it says: "Payment Service has 3 attack chains: an exploitable SQL injection path (SAST+DAST), an unpatched critical dependency (SCA), and a cluster of hardcoded credentials across 5 files (SAST)."

### 4.2 Data Source

Attack chains are derived from correlation groups, filtered per application. Each correlation group on an application becomes an attack chain. Standalone findings (no correlations) are grouped separately as "Uncorrelated Findings."

No new database table — attack chains are a view layer over existing `findings` + `finding_relationships` data.

### 4.3 Page Structure

**Top-level view — all applications ranked by risk:**

| Column | Content |
|---|---|
| Application | Name + app_code |
| Risk Score | Aggregate composite score (highest chain) |
| Attack Chains | Count of correlated groups |
| Tool Coverage | Badges: SAST / SCA / DAST |
| Severity Breakdown | Critical / High / Medium / Low counts |
| Uncorrelated | Count of standalone findings |

Sorted by risk score descending. Filterable by criticality tier, business unit, tool coverage.

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

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/attack-chains` | List applications with attack chain summaries (paginated) |
| `GET` | `/api/v1/attack-chains/:app_id` | Get all attack chains for one application |

### 4.5 Phase 3 Graph Visualization — Design Commitment

The card-based view in Phase 2 **will be augmented, not replaced** in Phase 3 with an interactive graph:
- Each finding is a **node** (colored by category: blue=SAST, green=SCA, orange=DAST)
- Each relationship is an **edge** (solid=High confidence, dashed=Medium, dotted=Low)
- Nodes sized by severity
- Click a node to see finding detail
- Click an edge to see the correlation rule that created it
- Target library: **React Flow** (MIT licensed, designed for interactive node graphs)

The Phase 2 API response shape (nodes + edges in correlation group response) is explicitly designed to feed this graph with zero API changes. This is a **hard requirement** for Phase 3.

---

## 5. Deduplication Dashboard

### 5.1 Page Structure

A dedicated sidebar entry giving analysts visibility and control over the dedup engine.

**Section 1 — Statistics (top cards):**

| Stat | Source |
|---|---|
| Total Raw Ingested | Sum of `ingestion_logs.total_records` |
| Unique Findings | Count of `findings` |
| Dedup Ratio | `1 - (unique / raw)` as percentage |
| Cross-Tool Matches | Count of `finding_relationships` where `relationship_type = 'duplicate_of'` |
| Pending Review | Count of relationships with `confidence = 'Low'` and no analyst confirmation |

**Section 2 — Pending Review (main table):**

Low-confidence matches needing analyst decision:

| Column | Content |
|---|---|
| Finding A | Title + category badge + severity |
| Finding B | Title + category badge + severity |
| Match Reason | Which rule triggered |
| Confidence | Low / Medium badge |
| Actions | Confirm / Reject buttons |

Sorted by creation date descending. Filterable by confidence, application, category.

**Section 3 — Recent Decisions (history table):**

Analyst-confirmed and rejected matches for audit trail. Shows who acted, when, and what action.

### 5.2 API Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/deduplication/stats` | Dedup statistics |
| `GET` | `/api/v1/deduplication/pending` | Pending review pairs (paginated) |
| `GET` | `/api/v1/deduplication/history` | Recent decisions (paginated) |
| `POST` | `/api/v1/deduplication/:relationship_id/confirm` | Analyst confirms a match |
| `POST` | `/api/v1/deduplication/:relationship_id/reject` | Analyst rejects a match |

---

## 6. Findings Page Tabs

### 6.1 Tab Structure

Horizontal tabs at the top of the existing Findings page: **All | SAST | SCA | DAST**

| Tab | Filter | Additional Columns |
|---|---|---|
| **All** | None (current unified view) | Common columns only: title, severity, status, application, source tool, first seen, last seen |
| **SAST** | `finding_category = 'SAST'` | file_path, line_number, rule_id, project, language |
| **SCA** | `finding_category = 'SCA'` | package_name, package_version, fixed_version, dependency_type, known_exploited |
| **DAST** | `finding_category = 'DAST'` | target_url, http_method, parameter, authentication_required |

### 6.2 Implementation

The existing `GET /api/v1/findings` endpoint already supports `?category=SAST` filtering. Category-specific columns require a JOIN to the category table — the backend adds an optional `include_category_data=true` query param that triggers the join and includes extra fields in the response as a `category_data` object.

Tabs are URL-driven (`/findings?tab=sast`) so they're bookmarkable and shareable.

---

## 7. Updated Navigation

### 7.1 Sidebar Structure

```
Dashboard
Findings              ← adds tabs internally (All | SAST | SCA | DAST)
Applications
Attack Chains      ★  NEW
Correlation        ★  NEW
Deduplication      ★  NEW
───────────────────
Ingestion
Triage Queue
Unmapped Apps
```

The separator groups navigation into two logical sections:
- **Top** — analytical views (what's happening, what's connected, what's at risk)
- **Bottom** — operational views (ingest data, triage findings, resolve unmapped apps)

Attack Chains is positioned prominently after the inventory views (Findings, Applications) and before the engine views (Correlation, Deduplication).

---

## 8. New Files Summary

### 8.1 Backend

| File | Purpose |
|---|---|
| `parsers/jfrog_xray.rs` | JFrog Xray SCA parser |
| `parsers/tenable_was.rs` | Tenable WAS DAST parser |
| `services/correlation.rs` | Correlation engine (rules, matching, group computation) |
| `routes/correlation.rs` | Correlation API endpoints |
| `routes/deduplication.rs` | Deduplication dashboard API endpoints |
| `routes/attack_chains.rs` | Attack chain API endpoints |
| `migrations/002_correlation_rules.sql` | `correlation_rules` table + seed rules |
| `tests/fixtures/jfrog_xray_sample.json` | Test fixture for SCA parser |
| `tests/fixtures/tenable_was_sample.csv` | Test fixture for DAST parser |

### 8.2 Frontend

| File | Purpose |
|---|---|
| `pages/AttackChainsPage.tsx` | Application risk list |
| `pages/AttackChainDetailPage.tsx` | Per-app attack chain cards + uncorrelated findings |
| `pages/CorrelationPage.tsx` | Correlation rules, groups, manual link/unlink |
| `pages/DeduplicationPage.tsx` | Stats, pending review, decision history |
| `api/correlation.ts` | Correlation API client |
| `api/deduplication.ts` | Deduplication API client |
| `api/attack-chains.ts` | Attack chain API client |
| `types/correlation.ts` | TypeScript types for correlation, relationship, group |
| `types/deduplication.ts` | TypeScript types for dedup stats, pending review |

### 8.3 Seed Data Updates

Extend `seed.rs` to include:
- Sample JFrog Xray fixture (SCA findings with CVEs)
- Sample Tenable WAS fixture (DAST findings with URLs)
- Pre-created correlation relationships between seed findings
- This ensures all new pages have data to display in development

### 8.4 E2E Tests

Extend the Playwright suite:
- Attack Chains page loads and shows applications
- Correlation page loads and shows rules
- Deduplication page loads and shows stats
- Findings tabs switch correctly between All/SAST/SCA/DAST

---

## 9. Execution Order

| # | Component | Dependencies |
|---|---|---|
| 1 | Migration: `correlation_rules` table | None |
| 2 | JFrog Xray parser | Migration applied |
| 3 | Tenable WAS parser | Migration applied |
| 4 | Seed data (SCA + DAST fixtures) | Parsers implemented |
| 5 | Cross-tool deduplication logic | Parsers (need multi-tool data) |
| 6 | Correlation engine | Cross-tool dedup (shares relationship infrastructure) |
| 7 | Wire correlation density into risk score | Correlation engine |
| 8 | Findings page tabs | Parsers (need SCA/DAST data to display) |
| 9 | Deduplication dashboard (backend + frontend) | Cross-tool dedup |
| 10 | Correlation page (backend + frontend) | Correlation engine |
| 11 | Attack Chains page (backend + frontend) | Correlation engine |
| 12 | Updated sidebar navigation | All new pages |
| 13 | E2E tests | All pages implemented |
