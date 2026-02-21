# SynApSec PRD Refinement — Design Document

**Date:** 2026-02-19 (updated 2026-02-21)
**Status:** Approved
**Context:** Collaborative refinement of ASOC_PRD_v1.md through 33 design decisions

---

## 1. Technology Stack & Infrastructure

| Component | Decision |
|---|---|
| **Backend** | Rust with Axum, SQLx, Tower, Tokio |
| **Frontend** | React + TypeScript + Vite + TailwindCSS + shadcn/ui + custom typography |
| **Database** | PostgreSQL (single DB — structured data, JSONB for raw findings/metadata, full-text search via tsvector/tsquery, materialized views for dashboard aggregations) |
| **Caching** | Redis (API response caching, session management) |
| **Message Queue** | RabbitMQ or Redis Streams (async ingestion pipeline) |
| **Reverse Proxy** | Nginx (TLS termination, static file serving) |
| **Containerization** | Docker Compose (initial), Kubernetes-ready architecture |
| **HTTPS** | Enforced everywhere including local dev via mkcert |
| **API Documentation** | OpenAPI 3.0 |
| **API Versioning** | URL path (`/api/v1/...`) |
| **Repository** | Monorepo (`/frontend`, `/backend`, `/docs`, `/docker`) |
| **Git Strategy** | GitHub Flow (feature branches + PRs to main) |
| **i18n** | JSON translation files, n-language scalable (English + Italian initial) |

**Rationale:** Rust/Axum chosen for maximum security and performance, leveraging existing team expertise. PostgreSQL as single data store avoids Elasticsearch operational overhead at this scale (2M findings, 25 concurrent users). Docker Compose simplifies initial on-premises deployment while container images remain Kubernetes-compatible for future migration.

---

## 2. Data Model Refinements

### 2.1 Field Requirement Tiers

The original PRD marked several fields as Required that cannot be known at automated ingestion time. Fields are now categorized into three tiers:

| Tier | Fields | Enforced By |
|---|---|---|
| **Required at ingestion** | source_tool, source_finding_id, finding_category, title, description, normalized_severity, original_severity, raw_finding, fingerprint | Schema validation |
| **Required at triage** | application_id, remediation_owner | State machine (must be set before transitioning past Confirmed) |
| **Auto-populated** | office_owner, office_manager (from application record), first_seen, last_seen, composite_risk_score, sla_due_date, sla_status | System logic |

### 2.2 Application Resolution Chain

The corporate acronym (`app_code`, 4 letters + 1 digit) is the universal application identifier across all scanners. Resolution during ingestion:

1. Parser extracts corporate acronym (`app_code`) from scanner output
2. Look up `app_code` in application registry
3. **Found** → set `application_id`, auto-populate owners from application record
4. **Not found** → auto-create stub application record (flagged "unverified" for analyst review)
5. **Fallback** → check `scanner_project_ids` mapping if `app_code` extraction fails

This resolves PRD Open Question Q6. Zero findings are lost; unmapped applications surface in a dedicated analyst queue.

### 2.3 Application Record — Enriched from Corporate APM

The enterprise Application Portfolio Management (APM) system exports ~5000 application records with ~250 fields per record. Of these, ~1300 are actively scanned (SAST: 1300, SCA: 1000, DAST: 100). All 5000 records should be imported into SynApSec to enable full app_code resolution and scanner coverage reporting.

**Hybrid storage approach:** Critical fields that SynApSec actively queries/filters on get dedicated columns. Everything else is preserved in JSONB metadata.

**New dedicated columns (beyond original PRD):**

| Field | Type | Source APM Field | Purpose |
|---|---|---|---|
| `ssa_code` | String | CODICE SSA | Parent container group for the acronym |
| `ssa_name` | String | DESCRIZIONE SSA | SSA description |
| `functional_reference_email` | String | REFERENTE FUNZIONALE ACRONIMO EMAIL | Business/functional owner |
| `technical_reference_email` | String | REFERENTE TECNICO ACRONIMO EMAIL | Technical owner, candidate remediation_owner |
| `effective_office_owner` | String | Computed | Resolved owner after Struttura Reale override |
| `effective_office_name` | String | Computed | Resolved office name after override |
| `confidentiality_level` | String | CONFIDENTIALITY LEVEL | CIA triad — from Risk Management |
| `integrity_level` | String | INTEGRITY LEVEL | CIA triad — from Risk Management |
| `availability_level` | String | AVAILABILITY LEVEL | CIA triad — from Risk Management |
| `is_dora_fei` | Boolean | L'acronimo è un acronimo di FE? | DORA essential/important function flag |
| `is_gdpr_subject` | Boolean | Acronimo soggetto a GDPR | GDPR applicability |
| `has_pci_data` | Boolean | FLAG DATI PCI | PCI data flag |
| `is_psd2_relevant` | Boolean | FLAG RILEVANZA PSD2 | PSD2 relevance |
| `apm_metadata` | JSONB | All remaining fields | Full corporate APM record preserved |

**Ownership Override Logic (Struttura Reale di Gestione):**

The corporate APM has two organizational blocks:
1. **Standard hierarchy:** Ufficio → Servizio → Direzione (with respective Responsabile)
2. **Struttura Reale di Gestione:** The actual management structure (may differ from standard)

During application import, SynApSec applies this logic:
- If Struttura Reale fields are populated AND differ from standard hierarchy → use Struttura Reale as the effective owner
- Otherwise → use standard hierarchy
- The resolved owner is stored in `effective_office_owner` and `effective_office_name`
- Both original blocks are preserved in `apm_metadata` for audit/reference

**Criticality fallback:** Not all APM records have a calculated ACRONYM CRITICALITY. For applications without a criticality level, SynApSec defaults to "Medium" and flags the record for analyst review.

**Application Import:**
- Upload corporate APM export as CSV/Excel
- Configurable field mapping (CSV column → SynApSec field) to handle format changes
- Import all ~5000 records (not just scanned ones) for full portfolio visibility
- Scanner coverage metric: scanned applications / total applications
- Import is repeatable (update existing records by app_code match, add new ones)

### 2.4 Asset Criticality — Dual Model

The enterprise Risk Management department calculates asset criticality using a complex methodology incorporating data relevance (personal, confidential, financial, credit cards, market sensitive, cyber security), process relevance (SEPA, SWIFT, Target2, DORA important functions, internet/mobile banking), and asset characterization (externalized service, internet facing, cloud technology, RTO/RPO).

- **External scale (stored as-is):** Very High, High, Medium High, Medium, Medium Low, Low
- **Internal tier mapping (configurable):** Default: Very High + High → Tier 1, Medium High + Medium → Tier 2, Medium Low + Low → Tier 3
- **Risk score:** Uses full 6-level granularity (Very High=100, High=85, Medium High=70, Medium=55, Medium Low=35, Low=15)
- **SLA matrix:** Operates on 3 internal tiers (derived via configurable mapping)

The mapping is configurable to accommodate future changes to the corporate criticality methodology.

### 2.4 Revised Fingerprint Algorithms

Original PRD fingerprints were fragile — SAST included line_number_start (breaks on code refactoring), DAST included cwe_id (not always available from scanners).

| Category | Primary Fingerprint | Secondary Confirmation |
|---|---|---|
| **SAST** | `Hash(application_id + file_path + rule_id + branch)` | Line number within configurable tolerance (default ±20) + code snippet similarity |
| **SCA** | `Hash(application_id + package_name + package_version + cve_id)` | Unchanged — stable identifiers |
| **DAST** | `Hash(application_id + target_url + http_method + parameter)` | CWE used as correlation attribute, not identity |

All fingerprint algorithms are configurable per scanner. Changing algorithms on a live system triggers a re-fingerprinting migration job with continuity warnings.

### 2.5 New Category-Specific Fields

**SAST-Specific Layer — Addition:**
- `quality_gate` (String, Optional) — Which quality gate profile was applied to the scan. Contextual metadata, not actionable by SynApSec.

**SCA-Specific Layer — Addition:**
- `build_project` (String, Optional) — Identifies which specific build/project within an application produced the finding. Handles the one-acronym-to-many-builds relationship in JFrog Xray.

---

## 3. Risk-Based Prioritization — Revised Model

### 3.1 Problem: Double-Counting

The original PRD included Exposure (15%) and Data Sensitivity (10%) as separate risk score factors. However, both are already incorporated into the corporate asset criticality calculation by Risk Management. Using them as separate factors double-counts their influence.

### 3.2 Solution: New Factors

Exposure and Data Sensitivity are replaced with two factors that provide genuinely new signal only SynApSec can produce:

| Factor | Weight | Scoring Scale | Source |
|---|---|---|---|
| Normalized Severity | 30% | Critical=100, High=80, Medium=50, Low=25, Info=5 | Finding data |
| Asset Criticality | 25% | Very High=100, High=85, Medium High=70, Medium=55, Medium Low=35, Low=15 | Application record (from Risk Management) |
| Exploitability | 20% | Known-exploited=100, Functional=80, PoC=50, Theoretical=20 | SCA: EPSS/KEV; DAST: confirmed exploitable; SAST: taint analysis confidence |
| **Finding Age** | **15%** | >2x SLA=100, >1x SLA=80, >75% SLA=60, >50% SLA=40, <50% SLA=20 | Platform-computed (dynamic — increases over time) |
| **Correlation Density** | **10%** | 3+ tools/findings=100, 2 tools=70, multiple same tool=40, standalone=10 | Platform-computed (from correlation engine) |

**Finding Age** creates organic escalation pressure — older unresolved findings naturally rise in priority without manual intervention.

**Correlation Density** rewards the platform's own intelligence — findings corroborated by multiple sources are more likely real and indicate systemic issues.

All weights and scoring scales are configurable (FR-RSK-005). The model supports adding new factors without code changes.

### 3.3 Recalculation Strategy — Hybrid

- **Severity, Asset Criticality, Exploitability** → recalculated on events (ingestion, correlation change, application metadata update)
- **Finding Age** → computed on-read (trivial date calculation, always current)
- **Correlation Density** → recalculated when correlations are added or removed

### 3.4 Priority Levels

| Score Range | Priority | Action |
|---|---|---|
| 80-100 | P1 — Critical | Immediate remediation |
| 60-79 | P2 — High | Urgent remediation |
| 40-59 | P3 — Medium | Planned remediation |
| 20-39 | P4 — Low | Backlog |
| 0-19 | P5 — Info | Track only |

---

## 4. Finding Lifecycle — Revised State Machine

### 4.1 Changes from Original PRD

1. **"New" state retained with purpose:** Auto-confirms by default, but configurable triage rules can hold specific findings for analyst review (e.g., Critical + Very High asset, low dedup confidence, historically high false positive rules).
2. **False_Positive_Requested added:** Developer-initiated dispute workflow. Developers submit justification; analyst approves (→ False_Positive) or rejects (→ back to Confirmed). Formalizes the existing ServiceNow-based dispute process.
3. **Won't Fix and Accepted Risk replaced** with two governance-aligned states matching corporate non-conformity model:
   - **Risk_Accepted:** Non-conformity without remediation plan. Governed expiry, periodic re-review, approval per severity.
   - **Deferred_Remediation:** Non-conformity with remediation plan. Committed remediation date becomes extended SLA. Escalation if date breached.
4. **Invalidated added:** Admin-only state for mistaken ingestion. Audit trail preserved. No hard deletes anywhere in the platform.

### 4.2 States

| State | Type | Description |
|---|---|---|
| New | Initial | Finding just ingested. Auto-transitions to Confirmed unless held by triage rule. |
| Confirmed | Active | Finding validated as real. SLA clock starts here. |
| In_Remediation | Active | Assigned to development team, ticket created. |
| Mitigated | Active | Developer reports fix implemented. |
| Verified | Active | Fix confirmed (analyst or re-scan). |
| Closed | Terminal | Finding resolved. |
| False_Positive_Requested | Pending | Developer disputes finding with justification. Awaiting analyst review. |
| False_Positive | Terminal | Finding confirmed as not valid. |
| Risk_Accepted | Governed terminal | Non-conformity without remediation plan. Expiry + periodic re-review. |
| Deferred_Remediation | Governed active | Non-conformity with remediation plan. Committed date becomes extended SLA. |
| Invalidated | Terminal | Mistaken ingestion. Admin-only. Audit trail preserved. |

### 4.3 State Transitions

| From | To | Who | Conditions |
|---|---|---|---|
| New | Confirmed | Auto | Default behavior (configurable triage rules can hold in New) |
| New | Confirmed | Analyst | Manual confirmation from triage queue |
| Confirmed | In_Remediation | Analyst+ | Finding assigned, ticket created |
| Confirmed | False_Positive | Analyst+ | Justification required |
| Confirmed | False_Positive_Requested | Developer | Justification required (dispute) |
| False_Positive_Requested | False_Positive | Analyst+ | Dispute approved |
| False_Positive_Requested | Confirmed | Analyst+ | Dispute rejected |
| Confirmed | Risk_Accepted | Manager/CISO | Justification, approval per severity, expiry date, re-review schedule |
| Confirmed | Deferred_Remediation | Manager | Justification (why SLA can't be met), committed remediation date, approval |
| Deferred_Remediation | In_Remediation | Auto/Developer | When committed date approaches or remediation begins |
| In_Remediation | Mitigated | Developer | Fix implemented |
| Mitigated | Verified | Analyst+ | Fix confirmed manually or finding absent from next scan |
| Verified | Closed | Auto/Analyst | Finding resolved |
| Risk_Accepted | Confirmed | Auto | Acceptance expires → returns for re-evaluation |
| Closed | New | Auto | Same vulnerability re-detected in subsequent scan |
| Any | Invalidated | Admin only | Mistaken ingestion, justification required |

### 4.4 Bulk Operations

- Bulk operations respect all state transition rules (justification, approval requirements)
- **Risk_Accepted and Deferred_Remediation are excluded from bulk operations** — these require individual governance review
- No hard deletes — only Invalidated status with audit trail

### 4.5 Risk Acceptance Governance

| Severity | Approval Authority | Max Duration | Re-review |
|---|---|---|---|
| P1 — Critical | CISO or delegate | 90 days | Monthly |
| P2 — High | AppSec Manager | 180 days | Quarterly |
| P3 — Medium | AppSec Team Lead | 365 days | Annual |
| P4 — Low | AppSec Analyst | 365 days | Annual |

All parameters configurable.

---

## 5. Authentication, Authorization & User Management

### 5.1 Authentication — Phased

| Phase | Mechanism |
|---|---|
| Initial | Local username + password (argon2id hashing, configurable complexity, secure reset) |
| Initial | Optional MFA via TOTP (Google Authenticator, Microsoft Authenticator) |
| Phase 3 | Enterprise IdP integration (SAML 2.0 / OIDC). Domain credentials. |

### 5.2 Authorization Model

- Admin maintains an **authorization table** mapping users to roles
- Enterprise IdP flow: domain user authenticates → platform checks authorization table → allowed with assigned role OR login denied if not listed
- 7 RBAC roles: Platform Admin, AppSec Analyst, AppSec Manager, Developer, Executive, Auditor, API Service Account

### 5.3 Security Controls

- Account lockout: 3 failed attempts
- Session timeout: 30 minutes inactivity
- HTTPS enforced everywhere (mkcert for local dev)
- No credentials or finding data in application logs

### 5.4 API Key Management — Two Types

| Type | Purpose | Managed By | Storage |
|---|---|---|---|
| **External scanner keys** | Call SonarQube/Xray/Tenable APIs | Each user, in their profile | Encrypted at rest (application-level encryption) |
| **SynApSec API keys** | External systems push data into SynApSec | Platform Admin | Scoped to specific operations, auditable, revocable |

External scanner key lifecycle governed by source platform. SynApSec handles expired/invalid key errors gracefully with clear error messages.

---

## 6. Ingestion, Deduplication & Correlation

### 6.1 Ingestion Patterns

| Pattern | Usage | Priority |
|---|---|---|
| **File Import (Batch)** | Primary during development. JSON, CSV, XML, SARIF. Upload via UI and API. | Must — Phase 1 |
| **API Pull (Scheduled Polling)** | Platform calls scanner APIs. Configurable intervals. | Must — Phase 1 (architecture), functional when scanner API access available |
| **API Push (Webhook)** | External systems push findings to SynApSec. CI/CD pipelines, SARIF. | Must — Phase 1 |

### 6.2 Ingestion Pipeline (9 Stages)

1. **Retrieval** — Parser fetches raw findings
2. **Validation** — Validated against data model schema; invalid records quarantined
3. **Normalization** — Fields mapped to common data model
4. **Fingerprint computation** — Deduplication hash computed per category algorithm
5. **Deduplication check** — Compared against existing findings
6. **Application resolution** — Corporate acronym lookup → stub creation fallback
7. **Enrichment** — Risk score, remediation guidance, owner auto-population
8. **Storage** — Persisted to PostgreSQL
9. **Notification + Workflow triggers** — Alerts dispatched, automation rules executed

Each stage independently monitorable. Failures handled with retry, quarantine, and alerting.

### 6.3 Auto-Confirm with Configurable Triage Rules

- **Default:** Findings auto-transition New → Confirmed
- **Exception rules (configurable):** Hold specific findings in New for analyst review
- **Example rules:** "Critical severity + Very High asset criticality → hold", "Low dedup confidence → hold", "Scanner rule with >80% historical false positive rate → hold"

### 6.4 Deduplication

- **Intra-tool:** Fingerprint match → update `last_seen`, no new record
- **Cross-tool:** Shared identifiers (CVE, CWE) + location matching
- Configurable matching rules with defaults per category
- Supports both merge and link strategies (configurable default)
- All decisions logged and auditable; analyst can override

### 6.5 Correlation

- Cross-category and intra-category correlation
- Rule-based with configurable matching criteria
- **Initial rule set:**
  - Same CVE across different tools
  - Same CWE on same application
  - SCA vulnerable package matched to SAST file imports
  - DAST endpoint matched to SAST handler (via application inventory metadata)
  - SAST: same rule_id across multiple files in same application (systemic issue)
  - SAST: same CWE in same file (clustered vulnerabilities)
- Confidence model: High / Medium / Low per correlation
- Analysts can manually create, confirm, or reject correlations
- Correlation graph visualization per application/asset

### 6.6 Data Migration

- One-time bulk import of historical findings from all 3 operational scanners
- Uses the file import pathway (Pattern 3)
- Historical findings ingested with original timestamps preserved

---

## 7. Workflow Automation & Integrations

### 7.1 Integration Architecture

Pluggable integration interface from day one. Concrete connectors are implementations of the abstract interface. Core platform never depends on specific external systems.

### 7.2 Integration Priority

| Integration | Priority | Phase |
|---|---|---|
| Email (SMTP) | Must | Phase 2 |
| Microsoft Teams (native adaptive cards) | Must | Phase 2 |
| Generic Webhook | Should | Phase 2 |
| ServiceNow (bidirectional) | Should | When test access available |
| Jira (bidirectional) | Should | When test access available |

### 7.3 Notification Events

| Event | Channel |
|---|---|
| New critical/high finding on Tier 1 asset | Teams (real-time) + Email |
| SLA approaching breach | Teams + Email |
| SLA breached | Email (formal) + Teams |
| Risk acceptance expiring | Email (formal) |
| Deferred remediation date approaching | Teams + Email |
| Ingestion failure/pipeline stall | Teams (operational alert) |
| False positive dispute submitted | Teams (to assigned analyst) |

Notification rules configurable per user/role.

### 7.4 Automated Assignment

- By application owner (derived from application record)
- By team / organizational unit
- By finding category (SAST/SCA/DAST)
- By asset criticality tier
- Configurable rule priority and fallback

### 7.5 Remediation Guidance

- Templates configurable by CWE / vulnerability type
- Maintained in English and Italian
- Editable by AppSec team
- Attached to findings automatically during ingestion enrichment

---

## 8. Dashboards, Reporting & Search

### 8.1 Search

- PostgreSQL full-text search across finding titles, descriptions, code snippets
- GIN indexes for full-text search and JSONB metadata queries
- Combinable attribute filters + free-text search
- Under 2 seconds for up to 10,000 results

### 8.2 Materialized Views

- Refreshed periodically (configurable, default every 15 minutes)
- Pre-compute: findings by severity/status/category, SLA compliance rates, application risk scores, trend data
- Executive dashboards read from materialized views

### 8.3 Dashboards

| Dashboard | Audience | Key Additions from Refinement |
|---|---|---|
| Operational | AppSec Analyst | Triage queue, unmapped application queue, false positive dispute queue |
| Security Posture | Executive | Non-conformity summary (Risk_Accepted + Deferred_Remediation backlog) |
| Application Risk | All roles | Correlation graph visualization, SBOM summary (Phase 3) |
| Compliance | Auditor/Manager | Non-conformity register with full approval trail |

### 8.4 New Metrics

- Deduplication effectiveness (raw ingested vs. unique)
- Correlation density per application
- Non-conformities without plan (risk exposure)
- Non-conformities with plan (committed date compliance rate)
- Triage rule effectiveness (held %, actual false positive %)
- Ingestion pipeline health (throughput, errors, queue depth)

### 8.5 Reporting

- Compliance reports mapped to regulatory frameworks
- Export: PDF, CSV, JSON via UI and API
- Scheduled report generation and distribution (email)
- Custom report builder (Should priority)
- Trend analysis at portfolio, application, and team levels

---

## 9. AI-Assisted Triage & Observability

### 9.1 AI Provider Abstraction Layer

```
Triage Request → AI Provider Interface → [pluggable backend]
                                              ├── Rule-based engine (Phase 2-3)
                                              ├── Local LLM (Phase 4+)
                                              └── Cloud LLM with guardrails (future, if approved)
```

### 9.2 Phase 2-3: Rule-Based Smart Triage

- Learns from historical analyst decisions
- Suggests likely false positives based on pattern matching
- Feeds configurable triage rules
- Fully explainable — every suggestion cites the triggering rule/pattern
- Analyst decisions continuously improve the rule base

### 9.3 Architecture Constraints

- **Local-only** as default and initial constraint (banking sector data confidentiality)
- Data classification rules governing what data can be sent to which provider type
- Architecture supports future local LLM (Ollama, llama.cpp) without rework
- Different providers can serve different operations

### 9.4 Application Observability

| Capability | Details |
|---|---|
| Health check endpoints | `/health/live` (process alive), `/health/ready` (dependencies connected) |
| Application metrics | Ingestion throughput, queue depth, error rates, API response times, active sessions, deduplication ratios |
| Structured logging | JSON-formatted, correlation IDs across pipeline stages, no sensitive data |
| Pipeline monitoring | Alert on stall, error rate threshold, queue depth threshold |
| Audit logging | Immutable trail, exportable to enterprise SIEM |

---

## 10. Non-Functional Requirements

### 10.1 Performance

- 1,000 findings/minute ingestion throughput
- Dashboard load: under 3 seconds
- API single finding: under 500ms (p95)
- API search/list: under 2 seconds (p95) for up to 10,000 results
- 25 concurrent users without degradation
- Report generation: under 30 seconds for 100K findings

### 10.2 Scalability

- 2 million findings without degradation
- Horizontal scalability for ingestion workers
- Database partitioning/archival strategies

### 10.3 Data Retention

- Fully configurable per data type (active findings, closed findings, raw scanner output, audit logs)
- Archival capability (cold storage, not deletion)
- Purge with audit trail when retention expires
- Conservative defaults (5 years) until enterprise governance specifies

### 10.4 UI/UX Quality (New NFR)

- Elegant, modern, professional design — not a generic admin template
- TailwindCSS + shadcn/ui foundation with custom typography and graphic elements
- Light and dark themes
- WCAG 2.1 Level AA accessibility
- Responsive: desktop (primary), tablet (secondary)
- i18n: English + Italian initial, scalable to n-languages via JSON translation files
- Locale-aware formatting (dates, numbers)

### 10.5 Security

- HTTPS everywhere (mkcert local dev, proper certificates deployed)
- Encryption at rest (AES-256)
- TLS 1.2+ in transit
- Application-level encryption for scanner API keys and credentials
- Secure coding as mandatory practice

### 10.6 Testing

- 80% unit test coverage for core business logic
- Integration tests for all parsers
- Automated CI/CD pipeline
- Comprehensive API documentation (OpenAPI 3.0)

---

## 11. Phasing & Roadmap (Revised)

### Phase 1: Foundation (Months 1-4)

- Common finding data model (three-tier, revised field requirements)
- Ingestion framework + SonarQube parser (file import primary, API pull architecture ready)
- SARIF support
- Basic deduplication (intra-tool, revised fingerprint algorithms)
- Finding lifecycle management (revised state machine with all new states)
- Application registry with corporate acronym resolution + stub auto-creation
- Basic web UI (finding list, detail view, status management, triage queue, unmapped app queue)
- REST API v1 (core CRUD operations)
- RBAC (local auth, admin-created users, 7 roles)
- PostgreSQL setup (full-text search indexes, JSONB)
- Docker Compose deployment
- HTTPS everywhere (mkcert)
- Health check endpoints and structured logging

**Exit Criteria:** SonarQube findings ingested via file import, deduplicated, browsable, and manageable through UI and API. State machine fully operational.

### Phase 2: Multi-Scanner & Correlation (Months 5-8)

- JFrog Xray parser (SCA) with build_project support
- Tenable WAS parser (DAST)
- Cross-tool deduplication
- Correlation engine (initial rule set, confidence model)
- Correlation graph visualization per application
- Severity normalization across all three tools
- Risk-based prioritization (revised 5-factor composite score)
- SLA framework (3-tier, configurable mapping from 6-level criticality)
- Operational dashboard + materialized views
- Notification engine (Email + Microsoft Teams adaptive cards)
- Automated assignment rules
- Rule-based smart triage (AI provider abstraction layer)
- False positive dispute workflow
- Application metrics and pipeline monitoring
- MFA support (TOTP)

**Exit Criteria:** All three scanners integrated. Cross-tool correlation operational. Risk scoring with all 5 factors. Real-time notifications via Teams. Triage rules reducing analyst workload.

### Phase 3: Governance & Reporting (Months 9-12)

- Executive security posture dashboard
- Application risk view
- Compliance reporting
- Risk_Accepted workflow with full governance
- Deferred_Remediation workflow
- Non-conformity register and reporting
- Audit trail and export
- SBOM import, storage, and analysis (sbom-tools as reference)
- Remediation guidance templates (English + Italian)
- Advanced correlation rules
- Custom report builder
- Trend analysis and analytics
- Scheduled reports
- Bulk import of historical data from all 3 scanners
- Enterprise IdP integration (SAML 2.0 / OIDC) with authorization table

**Exit Criteria:** Full audit-ready reporting. Risk governance operational. Executive dashboards live. Enterprise SSO active. Platform is the single source of truth for AppSec.

### Phase 4: Maturation & Expansion (Months 13+)

- ServiceNow bidirectional integration (when access available)
- Jira bidirectional integration (when access available)
- Parser developer guide + additional scanner integrations
- Performance optimization and scaling
- Local LLM exploration for triage assistance
- Advanced automation rules (if-then engine)
- Expanded RBAC for Vulnerability Management and SOC teams
- Kubernetes deployment option
- Configurable data retention policies
- SBOM diffing and compliance validation

---

## 12. Resolved Open Questions

| # | Original Question | Resolution |
|---|---|---|
| Q1 | Backend tech stack | Rust/Axum (was erroneously listed as Python/Django vs Java/Spring Boot) |
| Q2 | PostgreSQL JSONB vs Elasticsearch | PostgreSQL only — full-text search + materialized views |
| Q3 | SBOM storage | SynApSec stores and analyzes SBOMs. Phase 3. sbom-tools as reference. |
| Q4 | SLA configurable per BU | Global initially, fully configurable |
| Q5 | Docker Compose vs Kubernetes | Docker Compose initially, Kubernetes-ready architecture |
| Q6 | Findings for unmapped applications | Auto-create stub application record, flag as unverified |
| Q7 | Risk scoring global vs per-BU | Global initially |
| Q8 | Data retention policy | Fully configurable per data type, conservative defaults |
| Q9 | Jira Cloud vs Data Center | Deferred — Jira downgraded to Should |
| Q10 | Unstable finding identifiers | Tiered fingerprinting with configurable algorithms |

---

## 13. Complete Decision Log

| # | Issue | Decision |
|---|---|---|
| 1 | Tech stack contradiction | Rust/Axum confirmed. Q1 corrected. |
| 2 | Asset criticality scale | 6-level external input, configurable mapping to 3 internal tiers |
| 3 | Risk score double-counting | Replaced Exposure + Data Sensitivity with Finding Age (15%) + Correlation Density (10%) |
| 4 | Risk score recalculation | Hybrid: event-driven for heavy factors, on-read for age component |
| 5 | Required fields at ingestion | Two categories: required-at-ingestion vs required-at-triage, enforced by state machine |
| 6 | Application ID resolution | Corporate acronym as primary key, auto-create stub for unmapped apps, scanner_project_ids as fallback |
| 7 | Fingerprint algorithms | Removed line_number from SAST, removed cwe_id from DAST, tiered matching, configurable per scanner |
| 8 | "New" state purpose | Auto-confirm by default with configurable triage rules to hold specific findings |
| 9 | False positive disputes | Added False_Positive_Requested state for developer-initiated disputes with analyst approval/rejection |
| 10 | Won't Fix vs Accepted Risk | Replaced with Risk_Accepted (no plan, governed expiry) and Deferred_Remediation (committed date, extended SLA) |
| 11 | Frontend stack | React + TypeScript + Vite + TailwindCSS + shadcn/ui, elegant modern UI as explicit NFR |
| 12 | Search capability | PostgreSQL full-text search + materialized views, no Elasticsearch |
| 13 | i18n scope | UI chrome + remediation guidance + notifications, scalable to n-languages |
| 14 | ServiceNow/Jira priority | Downgraded to Should, pluggable integration interface from day one |
| 15 | User management | Admin-created initially, enterprise IdP later, authorization table for role mapping, 3 attempts lockout, 30 min timeout |
| 16 | API key management | Two types: external scanner keys (per-user, encrypted) and SynApSec API keys (admin-managed, scoped) |
| 17 | Observability | Health checks, application metrics, structured logging, pipeline stall alerting |
| 18 | Data migration | Platform starts fresh, bulk import historical data from all 3 scanners |
| 19 | Deployment | Docker Compose initially, Kubernetes-ready |
| 20 | SBOM strategy | SynApSec stores and analyzes, Phase 3, sbom-tools as reference |
| 21 | Data retention | Fully configurable, archival capability, conservative defaults |
| 22 | AI/ML triage | Rule-based Phase 2-3, pluggable AI provider abstraction, local-only constraint |
| 23 | Notifications | Email + Microsoft Teams (native adaptive cards) + generic webhook |
| 24 | Finding deletion | No hard deletes, Invalidated status with audit trail, admin-only |
| 25 | Bulk operations | Respect all transition rules, Risk_Accepted and Deferred_Remediation excluded |
| 26 | API versioning | URL path versioning (`/api/v1/...`) |
| 27 | HTTPS in local dev | Enforced everywhere via mkcert |
| 28 | Git strategy | GitHub Flow (feature branches + PRs) |
| 29 | Monorepo | Single repo: `/frontend`, `/backend`, `/docs`, `/docker` |
| 30 | Quality gate | Stored as SAST metadata, contextual only |
| 31 | Application data model enrichment | Hybrid: dedicated columns for queried fields (SSA, CIA levels, regulatory flags, effective owner), JSONB for full APM record (~250 fields) |
| 32 | Ownership override logic | Struttura Reale di Gestione overrides standard org hierarchy when different; resolved into effective_office_owner |
| 33 | Application portfolio import | Import all ~5000 APM records (not just scanned), configurable CSV field mapping, repeatable updates by app_code match |
