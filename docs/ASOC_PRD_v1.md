# Product Requirements Document (PRD)

# Application Security Orchestration and Correlation Platform

**Document Version:** 1.0 DRAFT
**Date:** February 2026
**Author:** Application Security Team
**Status:** Draft for Review
**Classification:** Internal — Confidential

---

## Document Control

| Version | Date     | Author      | Changes                           |
| ------- | -------- | ----------- | --------------------------------- |
| 0.1     | Feb 2026 | AppSec Team | Initial market research completed |
| 1.0     | Feb 2026 | AppSec Team | First PRD draft                   |

---

## Table of Contents

1. Executive Summary
2. Problem Statement
3. Vision and Objectives
4. Scope and Boundaries
5. Target Users and Personas
6. Functional Requirements
7. Common Finding Data Model
8. Integration Architecture
9. Ingestion and Parser Framework
10. Correlation and Deduplication Engine
11. Risk-Based Prioritization
12. Workflow and Lifecycle Management
13. Dashboards, Reporting and Analytics
14. Asset and Application Inventory
15. Compliance and Governance
16. Non-Functional Requirements
17. Security Requirements
18. Technology and Architecture
19. Deployment and Infrastructure
20. Roadmap and Phasing
21. Success Metrics and KPIs
22. Risks and Mitigations
23. Open Questions and Decisions
24. Appendices

---

## 1. Executive Summary

### 1.1 Purpose

This document defines the product requirements for a custom-built Application Security Orchestration and Correlation (ASOC) platform designed for a large enterprise. The platform will serve as the centralized command center for application security, unifying findings from multiple commercial security testing tools into a single pane of glass with deduplication, automated correlation, risk-based prioritization, and workflow management.

### 1.2 Why Build vs. Buy

The market research (see companion document: ASOC Market Research v1) identified 15+ commercial vendors in the ASOC/ASPM space, with enterprise licensing costs ranging from $500K to $1.5M for comprehensive implementations. Building a custom platform is strategically justified because:

- **Vendor independence:** The enterprise already invests in best-of-breed commercial scanners (SonarQube, JFrog Xray, Tenable WAS). A custom ASOC avoids locking into a second vendor layer that may dictate or constrain scanner choices.
- **Tailored to internal processes:** Enterprise governance models, approval workflows, risk acceptance processes, and compliance requirements are unique. A custom platform can be precisely shaped to match them.
- **Flexible integration:** The parser/connector framework can be extended by the internal team to support any scanner, current or future, without waiting for a vendor's roadmap.
- **Cost efficiency:** For an initial 7-person team, a custom platform built on open-source foundations delivers lower total cost of ownership than enterprise ASPM licensing.
- **Institutional knowledge:** The platform becomes an owned asset — the organizational memory for application security that doesn't disappear if a vendor is acquired or sunsets a product.

### 1.3 Key Design Principles

The following principles guide all design decisions:

1. **Concepts over labels.** The platform implements the capabilities that matter — deduplication, orchestration, correlation, risk-based governance, continuous posture monitoring, compliance, business context, asset criticality — regardless of whether these are traditionally classified as "ASOC" or "ASPM."
2. **Vendor-agnostic by design.** The ingestion layer must be pluggable. No assumption about specific scanners should be baked into the core platform.
3. **Data model first.** The common finding data model is the foundation. Every other capability depends on it. It must be comprehensive enough to support rich correlation yet flexible enough to accommodate tools we haven't integrated yet.
4. **API-first architecture.** Every operation must be available via RESTful API. The UI is a consumer of the API, not a separate system. This enables CI/CD integration, automation, and future extensibility.
5. **Learn from DefectDojo, don't replicate it.** DefectDojo (OWASP Flagship, 4,500+ GitHub stars, 150+ integrations, 30M+ downloads) is the most mature open-source reference. We study its parser architecture and data model but deliberately address its weaknesses: limited correlation intelligence, dated UX, and lack of advanced risk-based prioritization.
6. **Design for 7, architect for 70.** The initial UX optimizes for the daily workflows of a 7-person AppSec team. RBAC and multi-tenancy support future expansion to Vulnerability Management, SOC, and development teams.

---

## 2. Problem Statement

### 2.1 Current State

The application security team at this large enterprise currently operates with three separate commercial scanning tools:

- **SonarQube** for Static Application Security Testing (SAST)
- **JFrog Xray** for Software Composition Analysis (SCA)
- **Tenable WAS** for Dynamic Application Security Testing (DAST)

Each tool operates in isolation with its own console, output format, severity model, and workflow. The team of approximately 7 people manages the application security posture for the enterprise's entire application portfolio.

### 2.2 Pain Points

The following pain points drive the need for this platform, validated by both internal experience and industry research:

**Tool fragmentation:** Three separate consoles, three different severity models, three different output formats. There is no single pane of glass. Security professionals juggle multiple tools daily, creating operational overhead and increasing the risk of missing critical vulnerabilities.

**Alert overload:** The combined output from all scanners generates thousands of findings. Without automated deduplication and correlation, the 7-person team cannot effectively triage this volume. Industry data shows that 177 raw alerts can typically collapse to 92 unique issues, of which only 9 require prioritization — but achieving that reduction requires correlation intelligence that doesn't exist today.

**Inconsistent severity:** SonarQube, Xray, and Tenable WAS each rate severity differently. There is no consistent way to compare a SAST critical versus an SCA critical versus a DAST high. CVSS scores alone are insufficient — they don't account for business context, asset criticality, or exploitability in the specific environment.

**Spreadsheet-driven processes:** Without a centralized platform, the team resorts to exporting CSV/JSON from scanners, manually deduplicating in spreadsheets, and tracking remediation via email or disconnected ticketing. This is error-prone, time-consuming, and doesn't scale.

**No remediation lifecycle:** Individual scanners detect vulnerabilities but don't track remediation end-to-end. There is no unified view of what has been found, assigned, accepted as risk, mitigated, or verified as fixed. There is no enforcement of remediation SLAs.

**Reporting gaps:** Executive and compliance reporting requires aggregated metrics across all scanner types. Producing a unified security posture report means manually combining data from multiple tools.

**Knowledge loss:** When team members leave or scanners change, institutional knowledge about findings, triage decisions, risk acceptances, and remediation context is lost.

### 2.3 Desired Future State

A single platform that:

- Ingests findings from any SAST, SCA, or DAST tool automatically
- Normalizes all findings into a common data model
- Deduplicates and correlates findings across tools and categories
- Prioritizes based on risk, business context, exploitability and asset criticality
- Manages the complete finding lifecycle from discovery to verified remediation
- Enforces SLAs and governance policies
- Provides unified dashboards and compliance reporting
- Integrates with existing workflow tools (ServiceNow, CI/CD pipelines)
- Serves as the permanent organizational record for application security

---

## 3. Vision and Objectives

### 3.1 Product Vision

To be the single source of truth for application security across the enterprise — a platform that transforms fragmented scanner outputs into actionable, risk-prioritized intelligence and drives findings to resolution through automated workflows.

### 3.2 Strategic Objectives

| #   | Objective                                   | Measurable Outcome                                                                                  |
| --- | ------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| O1  | **Eliminate tool fragmentation**            | Single pane of glass replacing 3+ separate scanner consoles                                         |
| O2  | **Reduce finding noise by 80%+**            | Deduplication and correlation reduce actionable findings from thousands to hundreds                 |
| O3  | **Enable risk-based prioritization**        | Every finding scored with business context,asset criticality, not just CVSS                         |
| O4  | **Automate remediation workflows**          | Findings allow to create tickets, track SLAs, and verify fixes                                      |
| O5  | **Establish continuous posture monitoring** | Real-time security posture dashboard across the entire application portfolio                        |
| O6  | **Ensure compliance readiness**             | Audit-ready reporting with full decision trail                                                      |
| O7  | **Achieve vendor independence**             | Platform operates with any combination of SAST, SCA, and DAST tools and potentially other AST tools |

### 3.3 Success Criteria (12-Month)

- All three scanner tools (SonarQube, Xray, Tenable WAS) integrated and ingesting findings automatically
- Mean time to triage a new finding reduced by 60%
- Zero findings "lost" between tools — 100% of scanner output tracked in the platform
- Executive security posture report generated in minutes, not days
- Full audit trail for every finding from discovery through disposition
- At least one additional scanner tool integrated beyond the initial three (demonstrating vendor-agnostic design)

---

## 4. Scope and Boundaries

### 4.1 In Scope

**Core Platform Capabilities:**

- Common finding data model with three-tier architecture (core + category-specific + extensible metadata)
- Pluggable ingestion framework with parsers for SonarQube (SAST), JFrog Xray (SCA), and Tenable WAS (DAST)
- Deduplication engine (intra-tool and cross-tool)
- Correlation engine (cross-category finding linkage)
- Severity normalization and risk-based prioritization with business context and
  exploitability
- Finding lifecycle management (state machine from New through Closed)
- Asset and application inventory with ownership, criticality, and business context
- SBOM integration for SCA correlation
- Remediation guidance templates by CWE/vulnerability type
- AI/ML-assisted triage and false positive detection (local only due to data
  confidentiality)
- Workflow automation (ticket creation, assignment, notification, SLA tracking)
- Bidirectional integration with ServiceNow and/or Jira
- Unified dashboards and reporting (operational, executive, compliance)
- Continuous security posture monitoring
- Role-based access control (RBAC)
- Full audit trail
- RESTful API for all operations

**Governance and Compliance:**

- Risk-based governance framework
- Security policy definition and enforcement
- SLA management by severity and asset criticality
- Compliance reporting (configurable for regulatory frameworks)
- Risk acceptance workflow with approval chain

### 4.2 Out of Scope (Initial Release)

The following are explicitly out of scope for the initial release but the architecture must not preclude them:

- Running or triggering scans directly (the platform consumes results, it does not replace scanner tools)
- Runtime application monitoring or protection (RASP/WAF integration)
- Threat intelligence feed integration (architecture should support future enrichment)
- Policy-as-code enforcement in CI/CD gates
- Developer security training integration
- Multi-tenant operation for external customers
- Mobile application interface

### 4.3 Architectural Extensibility Requirements

Even though the items in Section 4.2 are out of scope for initial release, the architecture MUST support their future addition through:

- Plugin/extension architecture for new data sources (including runtime telemetry, threat intel feeds)
- Extensible data model (the metadata layer must accommodate new field types without schema changes)
- Event-driven architecture enabling future consumers (ML models, policy engines, training platforms)
- API versioning strategy to support backward compatibility as the platform evolves

---

## 5. Target Users and Personas

### 5.1 Primary Users (Initial Release)

**Persona 1: AppSec Analyst**

- Team: Application Security (~7 people)
- Daily activities: Triage new findings, correlate across tools, assign to development teams, track remediation, validate fixes
- Key needs: Fast triage workflow, clear prioritization, cross-tool correlation view, ability to annotate and classify findings
- Pain points: Tool-switching, manual deduplication, inconsistent severity across tools, no unified tracking

**Persona 2: AppSec Team Lead / Manager**

- Team: Application Security
- Daily activities: Monitor team workload, review security posture trends, prepare executive reports, manage SLAs, approve risk acceptances
- Key needs: Dashboard with posture overview, SLA compliance view, trend analysis, executive reporting, risk acceptance workflow
- Pain points: No single view of posture, manual report creation, no SLA enforcement

### 5.2 Secondary Users (Near-Term Expansion)

**Persona 3: Development Team Lead**

- Team: Various development teams
- Activities: Receive assigned findings, understand remediation requirements, track fix progress, request re-validation
- Key needs: Clear remediation guidance, minimal friction, integration with their existing workflow tools (ServiceNow/Jira), ability to dispute or request clarification
- Pain points: Unclear priorities, incomplete vulnerability descriptions, disconnected ticketing

**Persona 4: CISO / Security Executive**

- Activities: Review organizational security posture, understand risk trends, make resource allocation decisions, report to board
- Key needs: High-level dashboards, risk trending over time, compliance status, benchmark metrics
- Interaction: Weekly/monthly dashboard review; not daily operational use

### 5.3 Future Users (Architecture Must Support)

**Persona 5: Vulnerability Management Team**

- Would expand the platform beyond AppSec to infrastructure and network vulnerability management

**Persona 6: SOC Analyst**

- Would consume finding data as context for incident investigation and threat hunting

**Persona 7: Compliance / Audit Team**

- Would use the platform for evidence gathering and compliance reporting

### 5.4 RBAC Model

| Role                    | Permissions                                                                            | Personas                              |
| ----------------------- | -------------------------------------------------------------------------------------- | ------------------------------------- |
| **Platform Admin**      | Full system configuration, user management, parser management, integration setup       | AppSec Team Lead                      |
| **AppSec Analyst**      | Full CRUD on findings, correlation, triage, assignment, risk acceptance submission     | AppSec Analyst                        |
| **AppSec Manager**      | All Analyst permissions + approve risk acceptances, manage SLAs, access all reports    | AppSec Team Lead                      |
| **Developer**           | View assigned findings, update remediation status, add comments, request re-validation | Dev Team Lead                         |
| **Executive**           | Read-only dashboards and reports                                                       | CISO                                  |
| **Auditor**             | Read-only access to all findings, decisions, and audit trail                           | Compliance Team                       |
| **API Service Account** | Programmatic access scoped to specific operations (ingestion, status updates)          | CI/CD pipelines, scanner integrations |

---

## 6. Functional Requirements

### 6.1 Finding Ingestion (FR-ING)

| ID         | Requirement                | Priority | Description                                                                                                                                                                                   |
| ---------- | -------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-ING-001 | Pluggable parser framework | Must     | The platform must provide a parser plugin architecture that allows new scanner integrations to be added without modifying core platform code. Parser framework must be configurable           |
| FR-ING-002 | SonarQube parser           | Must     | Parse and ingest SAST findings from SonarQube, including all fields defined in the SAST-specific data model (Section 7). Must support both API-based polling and webhook-triggered ingestion. |
| FR-ING-003 | JFrog Xray parser          | Must     | Parse and ingest SCA findings from JFrog Xray, including package dependencies, CVE references, fixed versions, and license information.                                                       |
| FR-ING-004 | Tenable WAS parser         | Must     | Parse and ingest DAST findings from Tenable WAS, including target URLs, HTTP methods, parameters, request/response evidence, and OWASP categorization.                                        |
| FR-ING-005 | Batch import               | Must     | Support bulk import of findings via file upload (JSON, CSV, XML, SARIF formats).                                                                                                              |
| FR-ING-006 | API-based ingestion        | Must     | Expose a documented REST API endpoint for external systems to push findings directly.                                                                                                         |
| FR-ING-007 | Scheduled polling          | Should   | Support scheduled automatic polling of scanner APIs at configurable intervals.                                                                                                                |
| FR-ING-008 | Ingestion audit log        | Must     | Every ingestion event must be logged with timestamp, source, record count, success/failure status, and error details.                                                                         |
| FR-ING-009 | Raw finding preservation   | Must     | The original scanner output must be stored verbatim alongside the normalized finding, ensuring full traceability to the source.                                                               |
| FR-ING-010 | Ingestion validation       | Must     | Incoming findings must be validated against the data model schema. Invalid records must be quarantined with clear error reporting, not silently dropped.                                      |
| FR-ING-011 | Incremental ingestion      | Must     | Support delta/incremental imports to avoid reprocessing the entire scanner dataset on each sync.                                                                                              |
| FR-ING-012 | SARIF support              | Must     | Native support for SARIF (Static Analysis Results Interchange Format) as an import format, enabling any SARIF-compliant tool to integrate without a custom parser.                            |

### 6.2 Common Finding Data Model (FR-CDM)

| ID         | Requirement            | Priority | Description                                                                                                                                                                                                                     |
| ---------- | ---------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-CDM-001 | Three-tier data model  | Must     | The finding data model must implement three layers: Core (universal fields), Category-Specific (SAST/SCA/DAST fields), and Extensible Metadata (key-value pairs for tool-specific attributes). Full specification in Section 7. |
| FR-CDM-002 | Severity normalization | Must     | All tool-specific severity ratings must be mapped to a unified 5-level scale: Critical, High, Medium, Low, Info. The original tool severity must be preserved in a separate field.                                              |
| FR-CDM-003 | Vulnerability taxonomy | Must     | Findings must be mapped to CWE identifiers where applicable. CVE identifiers must be captured for known vulnerabilities (especially SCA and DAST). OWASP category mapping must be supported.                                    |
| FR-CDM-004 | Finding fingerprint    | Must     | Each finding must have a computed fingerprint/hash enabling deduplication. The fingerprint algorithm must be configurable per finding category (SAST, SCA, DAST) since identity is determined by different attributes for each. |
| FR-CDM-005 | Schema extensibility   | Must     | The extensible metadata layer must allow new key-value attributes to be added without database schema changes.                                                                                                                  |
| FR-CDM-006 | Data retention         | Must     | Finding data must support configurable retention policies. Historical findings must be archivable without deletion (for audit and trend analysis).                                                                              |
| FR-CDM-007 | Relationships          | Must     | The data model must support explicit relationships between findings (correlations, duplicates, parent-child for grouped findings).                                                                                              |

### 6.3 Deduplication (FR-DDP)

| ID         | Requirement                 | Priority | Description                                                                                                                                                                                                           |
| ---------- | --------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-DDP-001 | Intra-tool deduplication    | Must     | Identify and merge duplicate findings from the same scanner tool across successive scan runs (e.g., the same SonarQube finding appearing in consecutive scans).                                                       |
| FR-DDP-002 | Cross-tool deduplication    | Must     | Identify and link duplicate or overlapping findings from different scanner tools (e.g., the same SQL injection found by both SAST and DAST).                                                                          |
| FR-DDP-003 | Configurable matching rules | Must     | Deduplication matching criteria must be configurable. Default rules must be provided per finding category, with the ability to tune thresholds and add custom rules.                                                  |
| FR-DDP-004 | Merge vs. link              | Must     | The system must support both merging (consolidating duplicates into a single finding) and linking (maintaining separate findings with an explicit duplicate relationship). The default behavior must be configurable. |
| FR-DDP-005 | Deduplication audit         | Must     | All deduplication decisions must be logged and auditable. Users must be able to review and override automatic deduplication decisions.                                                                                |
| FR-DDP-006 | Deduplication metrics       | Must     | The platform must report deduplication effectiveness metrics: total raw findings ingested vs. unique findings after deduplication, broken down by tool and category.                                                  |

### 6.4 Correlation Engine (FR-COR)

| ID         | Requirement                | Priority | Description                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------- | -------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-COR-001 | Cross-category correlation | Must     | The engine must identify and link related findings across SAST, SCA, and DAST categories but also within the same platform (i.e. both infra and intra correlations). For example: a SAST finding identifying use of a vulnerable function that is also flagged as a vulnerable dependency by SCA. Or multiple SQLi vulnerabilities found by SAST in same file or different files but with the same underlying issues and that require the same logic fix |
| FR-COR-002 | Correlation rules          | Must     | Correlation must be rule-based with configurable matching criteria. Default rules must be provided, with the ability to add custom correlation rules.                                                                                                                                                                                                                                                                                                    |
| FR-COR-003 | Correlation confidence     | Must     | Each correlation must include a confidence score (High, Medium, Low) indicating the strength of the relationship.                                                                                                                                                                                                                                                                                                                                        |
| FR-COR-004 | Correlation visualization  | Must     | Correlated findings must be visually linked in the UI, showing the relationship graph between related findings across tools. The UI must have a unique feature of correlation graph view by application/asset                                                                                                                                                                                                                                            |
| FR-COR-005 | Asset-based correlation    | Must     | Findings must be correlatable by the asset/application they affect, enabling a unified vulnerability view per application.                                                                                                                                                                                                                                                                                                                               |
| FR-COR-006 | Manual correlation         | Must     | Analysts must be able to manually create, confirm, or reject correlations suggested by the engine.                                                                                                                                                                                                                                                                                                                                                       |

### 6.5 Risk-Based Prioritization (FR-RSK)

| ID         | Requirement                 | Priority | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ---------- | --------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-RSK-001 | Composite risk score        | Must     | Every finding must receive a composite risk score that goes beyond CVSS to incorporate: normalized severity, asset/application criticality, business impact, exploitability evidence, exposure context (internet-facing vs. internal), regulatory compliance and data sensitivity of the affected application.                                                                                                                                                                                     |
| FR-RSK-002 | Asset criticality tiers     | Must     | Applications/assets must be classifiable into criticality tiers (e.g., Tier 1 — business-critical, customer-facing; Tier 2 — internal operational; Tier 3 — development/non-production). Criticality must influence the composite risk score. Asset/Application criticality is determined by at least: data types, Critical or Important functions by DORA, public exposure (Internet facing), and other factors. Its scale is on 6 levels: Very High, High, Medium High, Medium, Medium Low, Low. |
| FR-RSK-003 | Business context enrichment | Must     | Findings must be enrichable with business context: business unit ownership, regulatory scope (PCI, GDPR, etc.), data classification, revenue impact potential.                                                                                                                                                                                                                                                                                                                                     |
| FR-RSK-004 | Exploitability awareness    | Must     | For SCA findings, the risk score must account for whether known exploits exist in the wild (EPSS, KEV catalog, or similar data sources).                                                                                                                                                                                                                                                                                                                                                           |
| FR-RSK-005 | Configurable scoring model  | Must     | The risk scoring algorithm and weights must be configurable by the AppSec team. Different organizations may weight factors differently.                                                                                                                                                                                                                                                                                                                                                            |
| FR-RSK-006 | Priority override           | Must     | Analysts must be able to manually override the computed priority with a documented justification. Overrides must be auditable.                                                                                                                                                                                                                                                                                                                                                                     |
| FR-RSK-007 | Risk trending               | Must     | The platform must track risk score changes over time per finding, per application, and across the portfolio.                                                                                                                                                                                                                                                                                                                                                                                       |

### 6.6 Finding Lifecycle Management (FR-LCM)

| ID         | Requirement              | Priority | Description                                                                                                                                                                                                                                                                                                                                                                                     |
| ---------- | ------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-LCM-001 | Lifecycle state machine  | Must     | Each finding must follow a defined lifecycle: New -> Confirmed -> In Remediation -> Mitigated -> Verified -> Closed. Additional terminal states: False Positive, Accepted Risk, Won't Fix. The risk score and calculated/normalized severity combined with asset criticality determine the remediation timing matrix (i.e. Critical issue on very High asset criticality --> 30 days, etc etc ) |
| FR-LCM-002 | State transitions        | Must     | Each transition must be governed by rules: who can perform the transition, what conditions must be met, what approvals are required (especially for Accepted Risk).                                                                                                                                                                                                                             |
| FR-LCM-003 | Risk acceptance workflow | Must     | Moving a finding to "Accepted Risk" must require a formal risk acceptance process: justification, approval by designated authority (based on severity/criticality), expiration date, and periodic re-review.                                                                                                                                                                                    |
| FR-LCM-004 | Re-opening               | Must     | Findings that were Closed or Mitigated must automatically re-open if the same vulnerability reappears in a subsequent scan.                                                                                                                                                                                                                                                                     |
| FR-LCM-005 | SLA enforcement          | Must     | Remediation SLAs must be definable by severity and asset criticality tier. The platform must track SLA compliance, send notifications before SLA breach, and flag overdue findings.                                                                                                                                                                                                             |
| FR-LCM-006 | Comments and annotations | Must     | Every finding must support threaded comments and annotations, enabling collaboration between AppSec analysts and developers.                                                                                                                                                                                                                                                                    |
| FR-LCM-007 | Finding history          | Must     | Complete history of all state changes, comments, assignments, and modifications must be maintained as an immutable audit trail.                                                                                                                                                                                                                                                                 |
| FR-LCM-008 | Bulk operations          | Must     | Users must be able to perform bulk actions on findings (bulk assign, bulk status change, bulk tag) with appropriate RBAC controls.                                                                                                                                                                                                                                                              |

### 6.7 Workflow Automation (FR-WFA)

| ID         | Requirement            | Priority | Description                                                                                                                                                                                                                                                         |
| ---------- | ---------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-WFA-001 | ServiceNow integration | Must     | Bidirectional integration with ServiceNow: auto-create tickets/incidents from findings, sync status updates back to the platform, link findings to ServiceNow CIs. This could be difficult to implement as I do not have access to SNOW in my local dev environment |
| FR-WFA-002 | Jira integration       | Must     | Bidirectional integration with Jira: auto-create issues from findings, sync status updates, support configurable project/issue-type mapping. This could be difficult to implement as I do not have access to Jira in my local dev environment                       |
| FR-WFA-003 | Automated assignment   | Must     | Findings must be automatically assignable based on configurable rules: by application owner, by team, by Organizationl Unit, by finding category, by asset criticality tier.                                                                                        |
| FR-WFA-004 | Notification engine    | Must     | Configurable notifications via email and integration with messaging platforms. Notifications for: new critical findings, SLA approaching breach, SLA breached, risk acceptance expiring, status changes.                                                            |
| FR-WFA-005 | Automation rules       | Should   | Support configurable automation rules (if-then logic): e.g., "If finding is Critical AND application is Tier 1, THEN auto-create ServiceNow P1 incident AND notify AppSec manager."                                                                                 |
| FR-WFA-006 | Remediation guidance   | Must     | Findings must be augmented with remediation guidance templates, configurable by CWE or vulnerability type. Guidance must be editable by the AppSec team.                                                                                                            |

### 6.8 Dashboards, Reporting, and Analytics (FR-RPT)

| ID         | Requirement           | Priority | Description                                                                                                                                                                                               |
| ---------- | --------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-RPT-001 | Operational dashboard | Must     | Real-time dashboard for AppSec analysts showing: open findings by severity, SLA status, recent ingestion activity, findings requiring triage, assigned workload per analyst.                              |
| FR-RPT-002 | Posture dashboard     | Must     | Executive security posture dashboard showing: portfolio-wide risk score and trend, findings by category and severity over time, top riskiest applications, SLA compliance rate, mean time to remediation. |
| FR-RPT-003 | Application risk view | Must     | Per-application dashboard showing: all findings across all scanner categories, risk score and trend, open vs. closed over time, SLA compliance, SBOM summary (for SCA).                                   |
| FR-RPT-004 | Compliance reporting  | Must     | Configurable compliance reports mapped to regulatory frameworks. Export to PDF and CSV.                                                                                                                   |
| FR-RPT-005 | Trend analysis        | Must     | Historical trend analysis for: finding volume, severity distribution, mean time to remediation, SLA compliance, risk score trajectory — at portfolio, application, and team levels.                       |
| FR-RPT-006 | Custom reports        | Should   | Users must be able to create custom reports with configurable filters, groupings, and visualizations.                                                                                                     |
| FR-RPT-007 | Scheduled reports     | Should   | Reports must be schedulable for automatic generation and distribution (email).                                                                                                                            |
| FR-RPT-008 | Data export           | Must     | All report data must be exportable via API and in standard formats (CSV, JSON, PDF).                                                                                                                      |

### 6.9 Asset and Application Inventory (FR-AST)

| ID         | Requirement                  | Priority | Description                                                                                                                                                                                              |
| ---------- | ---------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-AST-001 | Application registry         | Must     | Central registry of all applications with: name, identifier, description, technology stack, deployment environment(s), business unit, owner(s), criticality tier, data classification, regulatory scope. |
| FR-AST-002 | Ownership mapping            | Must     | Each application must have designated owners: business owner, technical owner, security champion. Ownership must drive automated finding assignment.                                                     |
| FR-AST-003 | Finding aggregation by asset | Must     | All findings across all scanner categories must be aggregatable and viewable by application/asset.                                                                                                       |
| FR-AST-004 | SBOM association             | Must     | Applications must be associable with their Software Bill of Materials. SCA findings must link to specific SBOM components.                                                                               |
| FR-AST-005 | Asset import                 | Must     | Support bulk import of asset/application data from external sources (CMDB, ServiceNow CI, CSV, Excel).                                                                                                   |
| FR-AST-006 | Asset risk score             | Must     | Each application must have a computed risk score based on its aggregate findings, criticality tier, and business context.                                                                                |

---

## 7. Common Finding Data Model

This section specifies the three-tier data model that is the foundation of the entire platform. The model is informed by market analysis of DefectDojo, ArmorCode, Kondukto/Invicti, and industry standards (SARIF, CycloneDX, OCSF, VEX).

### 7.1 Design Principles

1. **Comprehensive yet flexible.** The core and category-specific layers capture the broadest common denominator across tools. The extensible metadata layer accommodates anything tool-specific without schema changes.
2. **Raw preservation.** The original scanner output is always stored alongside the normalized finding.
3. **Fingerprint-driven identity.** Each finding category has a defined fingerprint algorithm for deduplication.
4. **Relationship-aware.** The model explicitly supports relationships: duplicate-of, correlated-with, child-of (for grouped findings).
5. **Temporal.** First-seen, last-seen, and state-change timestamps enable trend analysis and age tracking.

### 7.2 Core Layer (Universal Fields)

These fields apply to every finding regardless of source tool or category.

| Field                  | Type          | Required | Description                                                                                              |
| ---------------------- | ------------- | -------- | -------------------------------------------------------------------------------------------------------- |
| `id`                   | UUID          | Auto     | Platform-generated unique identifier                                                                     |
| `source_tool`          | String        | Yes      | Name of the originating scanner (e.g., "SonarQube", "JFrog Xray", "Tenable WAS")                         |
| `source_tool_version`  | String        | No       | Version of the scanner that produced the finding                                                         |
| `source_finding_id`    | String        | Yes      | The finding's identifier in the source tool (for traceability)                                           |
| `finding_category`     | Enum          | Yes      | SAST, SCA, DAST                                                                                          |
| `title`                | String        | Yes      | Normalized finding title/summary                                                                         |
| `description`          | Text          | Yes      | Detailed description of the vulnerability                                                                |
| `normalized_severity`  | Enum          | Yes      | Critical, High, Medium, Low, Info                                                                        |
| `original_severity`    | String        | Yes      | Severity as reported by the source tool (preserved verbatim)                                             |
| `cvss_score`           | Float         | No       | CVSS base score (v3.1 or v4 where available)                                                             |
| `cvss_vector`          | String        | No       | CVSS vector string                                                                                       |
| `cwe_ids`              | Array[String] | No       | CWE identifier(s) (e.g., ["CWE-89", "CWE-564"])                                                          |
| `cve_ids`              | Array[String] | No       | CVE identifier(s) (e.g., ["CVE-2024-1234"])                                                              |
| `owasp_category`       | String        | No       | OWASP Top 10 or OWASP category mapping                                                                   |
| `status`               | Enum          | Yes      | New, Confirmed, In_Remediation, Mitigated, Verified, Closed, False_Positive, Accepted_Risk, Wont_Fix     |
| `composite_risk_score` | Float         | Computed | Platform-computed risk score incorporating severity, asset criticality, business context, exploitability |
| `confidence`           | Enum          | No       | High, Medium, Low — confidence in the finding's accuracy                                                 |
| `fingerprint`          | String        | Computed | Deduplication hash (algorithm varies by category)                                                        |
| `application_id`       | FK (UUID)     | Yes      | Reference to the application/asset in the asset registry                                                 |
| `remediation_owner`    | String        | Yes      | Person or team assigned for remediation                                                                  |
| `office_owner`         | String        | Yes      | Office owner of the asset/application                                                                    |
| `office_manager`       | String        | Yes      | Office manager of the asset/application                                                                  |
| `first_seen`           | Timestamp     | Auto     | When this finding was first ingested                                                                     |
| `last_seen`            | Timestamp     | Auto     | When this finding was most recently seen in a scan                                                       |
| `status_changed_at`    | Timestamp     | Auto     | When the status was last changed                                                                         |
| `created_at`           | Timestamp     | Auto     | Record creation timestamp                                                                                |
| `updated_at`           | Timestamp     | Auto     | Record last update timestamp                                                                             |
| `sla_due_date`         | Timestamp     | Computed | Remediation deadline based on severity and asset criticality                                             |
| `sla_status`           | Enum          | Computed | On_Track, At_Risk, Breached                                                                              |
| `tags`                 | Array[String] | No       | User-defined tags for filtering and grouping                                                             |
| `remediation_guidance` | Text          | No       | Remediation instructions (from template or manual entry)                                                 |
| `raw_finding`          | JSON          | Yes      | Complete original scanner output, stored as JSON blob                                                    |

### 7.3 SAST-Specific Layer

These fields apply when `finding_category = SAST`. Informed by SonarQube output attributes.

| Field                   | Type          | Required | Description                                                                             |
| ----------------------- | ------------- | -------- | --------------------------------------------------------------------------------------- |
| `file_path`             | String        | Yes      | Path to the affected source file                                                        |
| `line_number_start`     | Integer       | No       | Starting line number of the vulnerability                                               |
| `line_number_end`       | Integer       | No       | Ending line number (for multi-line findings)                                            |
| `project`               | String        | Yes      | Project identifier in the source tool                                                   |
| `rule_name`             | String        | Yes      | Human-readable rule name from the scanner                                               |
| `rule_id`               | String        | Yes      | Machine-readable rule identifier from the scanner                                       |
| `issue_type`            | String        | No       | Type classification from the scanner (e.g., SonarQube: VULNERABILITY, SECURITY_HOTSPOT) |
| `branch`                | String        | No       | Branch where the finding was detected (e.g., dev, main, prod)                           |
| `source_url`            | String        | No       | URL to the finding in the source scanner's UI                                           |
| `scanner_creation_date` | Timestamp     | No       | When the scanner first detected this finding                                            |
| `baseline_date`         | Timestamp     | No       | Baseline/cutoff date for new vs. existing findings                                      |
| `last_analysis_date`    | Timestamp     | No       | When the most recent analysis was performed                                             |
| `code_snippet`          | Text          | No       | Relevant code excerpt showing the vulnerability                                         |
| `taint_source`          | String        | No       | Source of tainted data (for taint analysis findings)                                    |
| `taint_sink`            | String        | No       | Sink where tainted data reaches (for taint analysis findings)                           |
| `language`              | String        | No       | Programming language of the affected code                                               |
| `framework`             | String        | No       | Framework in use (if detected by scanner)                                               |
| `scanner_description`   | Text          | No       | Vulnerability description as provided by the scanner                                    |
| `scanner_tags`          | Array[String] | No       | Tags assigned by the scanner                                                            |

### 7.4 SCA-Specific Layer

These fields apply when `finding_category = SCA`.

| Field               | Type    | Required | Description                                                                                  |
| ------------------- | ------- | -------- | -------------------------------------------------------------------------------------------- |
| `package_name`      | String  | Yes      | Name of the vulnerable package/library                                                       |
| `package_version`   | String  | Yes      | Version of the vulnerable package                                                            |
| `package_type`      | String  | No       | Package ecosystem (npm, Maven, PyPI, NuGet, etc.)                                            |
| `fixed_version`     | String  | No       | Version that resolves the vulnerability (if known)                                           |
| `dependency_type`   | Enum    | No       | Direct, Transitive                                                                           |
| `dependency_path`   | String  | No       | Full dependency chain (e.g., app -> lib-a -> lib-b:vulnerable)                               |
| `license`           | String  | No       | License of the vulnerable package                                                            |
| `license_risk`      | Enum    | No       | License compliance risk level (if applicable)                                                |
| `sbom_reference`    | String  | No       | Reference to the SBOM component                                                              |
| `epss_score`        | Float   | No       | Exploit Prediction Scoring System score                                                      |
| `known_exploited`   | Boolean | No       | Whether the vulnerability appears in known-exploited-vulnerability catalogs (e.g., CISA KEV) |
| `exploit_maturity`  | Enum    | No       | Proof_of_Concept, Functional, Weaponized, Unknown                                            |
| `affected_artifact` | String  | No       | The specific build artifact or container image affected                                      |

### 7.5 DAST-Specific Layer

These fields apply when `finding_category = DAST`.

| Field                     | Type    | Required | Description                                                    |
| ------------------------- | ------- | -------- | -------------------------------------------------------------- |
| `target_url`              | String  | Yes      | URL of the affected endpoint                                   |
| `http_method`             | String  | No       | HTTP method (GET, POST, PUT, etc.)                             |
| `parameter`               | String  | No       | The specific parameter or injection point                      |
| `attack_vector`           | String  | No       | Description of the attack vector used                          |
| `request_evidence`        | Text    | No       | HTTP request that demonstrated the vulnerability               |
| `response_evidence`       | Text    | No       | HTTP response that confirmed the vulnerability                 |
| `authentication_required` | Boolean | No       | Whether the endpoint requires authentication                   |
| `authentication_context`  | String  | No       | Description of the authentication context used during the scan |
| `web_application_name`    | String  | No       | Name of the web application in the scanner                     |
| `scan_policy`             | String  | No       | Scan policy/profile used                                       |

### 7.6 Extensible Metadata Layer

| Field      | Type                 | Description                                                                                                                                             |
| ---------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `metadata` | JSON / Key-Value Map | Flexible store for any tool-specific attributes not captured in the core or category-specific layers. No schema changes required to add new attributes. |

### 7.7 Fingerprint Algorithms

Each finding category uses a different fingerprint algorithm because identity is determined by different attributes:

- **SAST fingerprint:** Hash of (application_id + file_path + rule_id + line_number_start + branch)
- **SCA fingerprint:** Hash of (application_id + package_name + package_version + cve_id)
- **DAST fingerprint:** Hash of (application_id + target_url + http_method + parameter + cwe_id)

Fingerprint algorithms must be configurable and overridable per scanner integration.

### 7.8 Data Model Relationships

| Relationship Type | Description                                                                | Example                                                                                                                                    |
| ----------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `duplicate_of`    | Finding is a duplicate of another finding (from deduplication)             | SonarQube finding X is a duplicate of SonarQube finding Y from a previous scan                                                             |
| `correlated_with` | Finding is related to another finding across categories (from correlation) | SAST finding for SQL injection correlated with DAST finding for same injection point                                                       |
| `grouped_under`   | Finding is part of a logical group                                         | Multiple SCA findings for the same vulnerable library version or multiple SAST findings for the same vulnerability across same application |
| `superseded_by`   | Finding has been replaced by a newer detection                             | Scanner re-categorized or re-scored a finding                                                                                              |

---

## 8. Integration Architecture

### 8.1 Integration Patterns

The platform must support three integration patterns:

**Pattern 1: Pull (Scheduled Polling)**
The platform actively queries scanner APIs at configurable intervals to retrieve new or updated findings.

- Primary pattern for SonarQube (via Web API), JFrog Xray (via REST API)
- Configurable polling interval per integration (minimum 15 minutes)
- Must track last-poll state to enable incremental/delta retrieval

**Pattern 2: Push (Webhook/API)**
External systems push findings to the platform via its REST API or webhook endpoints.

- Primary pattern for CI/CD pipeline integrations
- Tenable WAS scan completion triggers can push results
- Generic API endpoint accepts findings in the common data model format or SARIF

**Pattern 3: File Import (Batch)**
Manual or automated file-based import. During our development phase this will be our primary usage pattern because I will not have accesss to actual scanners API (Pattern 1) and allow external systems to push findings to this platform. Pattern 1 and Pattern 2 should be developed the same though as essential integration paths.

- Supported formats: JSON, CSV, XML, SARIF
- Useful for ad-hoc imports, migration from legacy systems, or tools without API access
- File upload via UI and API

### 8.2 Initial Scanner Integrations

#### 8.2.1 SonarQube (SAST)

- **File Import and API:** File Import (and later SonarQube Web API (REST)).
  Ideally the ingestion should have two options initially: one via API call to external tool (Sonarqube in this case) directly from UI and also schedulable via batch, retrieve response, parse, normalize, store, etc. The second via File upload.
- **Authentication:** RBAC on our platform, User token or system token for API
  pattern
- **Key endpoints:** `/api/issues/search`, `/api/hotspots/search`, `/api/projects/search`
- **Ingestion approach:** Pull-based polling; retrieve issues filtered by type (VULNERABILITY, SECURITY_HOTSPOT), project, and since-date for incremental sync
- **Mapping considerations:** SonarQube severity (BLOCKER, CRITICAL, MAJOR, MINOR, INFO) must be mapped to the platform's 5-level scale. SonarQube issue types (VULNERABILITY vs. SECURITY_HOTSPOT) must both be ingested with the type preserved in the SAST-specific layer.

#### 8.2.2 JFrog Xray (SCA)

- **File Import and API:** File import (and later Xray REST API). See SAST
  considerations
- **Authentication:** RBAC on our platform for import file, API key or access token
- **Key endpoints:** Violations API, scan results, component details
- **Ingestion approach:** Pull-based polling for violations; webhook-triggered on new violation detection
- **Mapping considerations:** Xray severity mapping, CVE cross-referencing, dependency path extraction, fixed version identification

#### 8.2.3 Tenable WAS (DAST)

- **File Import and API:** File import (and later Tenable.io WAS API (REST)).
  See SAST considerations
- **Authentication:** RBAC on our platform for import file, API keys (access key + secret key)
- **Key endpoints:** Scan results, vulnerability listing, scan configurations
- **Ingestion approach:** Pull-based triggered after scan completion; can also use export APIs for bulk retrieval
- **Mapping considerations:** Tenable plugin severity mapping, OWASP category mapping, request/response evidence extraction

### 8.3 Outbound Integrations

#### 8.3.1 ServiceNow (cannot be tested during development because I do not have access to SNOW)

- **Pattern:** Bidirectional REST API integration
- **Outbound:** Auto-create incidents or change requests from findings; attach finding details, remediation guidance, and risk score
- **Inbound:** Sync ticket status back to finding lifecycle; map ServiceNow states to finding states
- **CI mapping:** Link findings to ServiceNow Configuration Items for asset correlation

#### 8.3.2 Jira (cannot be tested during development because I do not have access to Jira)

- **Pattern:** Bidirectional REST API integration
- **Outbound:** Auto-create issues from findings; configurable project and issue-type mapping
- **Inbound:** Sync issue status back to finding lifecycle
- **Field mapping:** Configurable mapping between finding attributes and Jira fields

#### 8.3.3 Notification Channels

- Email (SMTP)
- Webhook (generic, for integration with Slack, Microsoft Teams, or custom endpoints)

---

## 9. Ingestion and Parser Framework

### 9.1 Parser Plugin Architecture

The parser framework is the primary extension point for adding new scanner integrations. It must follow a plugin architecture that allows new parsers to be developed and deployed independently of the core platform.

**Each parser plugin must implement:**

1. **Connection configuration:** How to authenticate and connect to the scanner (API keys, tokens, URLs) and how to import scanner results file properly managing all its attributes and data
2. **Data retrieval:** How to fetch findings from the scanner (API calls, file parsing)
3. **Field mapping:** How to map scanner-specific fields to the common data model (core + category-specific layers)
4. **Severity mapping:** How to translate the scanner's severity model to the platform's 5-level scale
5. **Fingerprint computation:** How to compute the deduplication fingerprint for findings from this scanner
6. **Incremental state:** How to track last-sync state for delta retrieval

**Parser development must be documented** with a parser developer guide, including:

- Parser interface specification
- Sample parser implementation (reference parser)
- Field mapping template
- Testing guidelines and test data formats

### 9.2 Ingestion Pipeline

The ingestion pipeline processes findings through the following stages:

1. **Retrieval:** Parser fetches raw findings from the scanner
2. **Validation:** Raw findings are validated for completeness and format
3. **Normalization:** Fields are mapped to the common data model
4. **Fingerprint computation:** Deduplication hash is computed
5. **Deduplication check:** Finding is compared against existing findings
6. **Enrichment:** Finding is enriched with application context, risk score, remediation guidance
7. **Storage:** Finding is persisted to the database
8. **Notification:** If the finding meets notification rules, alerts are dispatched
9. **Workflow trigger:** If the finding meets automation rules, workflow actions are executed

Each stage must be independently monitorable and the pipeline must handle failures gracefully (retry, quarantine, alert).

---

## 10. Correlation and Deduplication Engine

### 10.1 Deduplication Strategy

**Intra-tool deduplication** occurs when the same scanner reports the same finding across successive scans. The fingerprint algorithm identifies the match and updates the existing finding's `last_seen` timestamp rather than creating a new record.

**Cross-tool deduplication** occurs when different scanners report the same underlying vulnerability. This is harder because different tools describe the same issue differently. Cross-tool dedup relies on shared identifiers (CVE, CWE) combined with location matching.

### 10.2 Correlation Strategy

Correlation goes beyond deduplication to identify related (but not identical) findings. This applies to both findings by different scanners (i.e. SAST vs SCA, SAST vs DAST, etc) and findings within the same scanner. Examples:

- A SAST finding identifying use of a vulnerable function in a file, correlated with an SCA finding identifying the vulnerable library that contains that function
- A DAST finding for a SQL injection on an endpoint, correlated with a SAST finding for unsanitized input in the handler code for that endpoint
- Multiple SCA findings for different CVEs in the same package version, grouped as related

Correlation rules must be configurable. Initial rules should include (this set of rules does not have any criteria applicable for SAST, we must absolutely enforce correlation criteria taking into account that platform too!):

- Same CVE across different tools
- Same CWE on the same application
- SCA vulnerable package matched to SAST file imports of that package
- DAST endpoint matched to SAST handler by URL-to-code mapping (requires application inventory metadata)

### 10.3 Correlation Confidence Model

Each correlation is assigned a confidence level:

- **High:** Strong evidence of same vulnerability (matching CVE + same application; identical CWE + same file/endpoint)
- **Medium:** Likely related (same CWE + same application but different location; same package ecosystem + similar vulnerability type)
- **Low:** Possibly related (same broad category on same application; requires human review)

---

## 11. Risk-Based Prioritization

### 11.1 Composite Risk Score Model

The composite risk score is a weighted calculation that produces a normalized score (0-100) for each finding:

**Input Factors:**

| Factor              | Weight (Default) | Source                                                                      | Description                                                                                                                                                             |
| ------------------- | ---------------- | --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Normalized Severity | 30%              | Finding data model                                                          | Critical=100, High=80, Medium=50, Low=25, Info=5                                                                                                                        |
| Asset Criticality   | 25%              | Application inventory                                                       | See asset criticality 6 levels scale.Eventually remap to Tiers. Tier 1=100, Tier 2=60, Tier 3=30                                                                        |
| Exploitability      | 20%              | SCA: EPSS/KEV; DAST: confirmed exploitable; SAST: taint analysis confidence | Known-exploited=100, Functional exploit=80, PoC=50, Theoretical=20                                                                                                      |
| Exposure            | 15%              | Application inventory                                                       | This dimenstion is already included in the determination of the asset criticality. Evaluate if double enforce it. Internet-facing=100, DMZ=70, Internal=40, Dev/Test=15 |
| Data Sensitivity    | 10%              | Application inventory                                                       | This dimension is already included in the determination of the asset criticality. Evaluate if double enforce it. PII/Financial=100, Internal-confidential=60, Public=20 |

**Calculation:** `Composite Score = Sum(Factor_Score * Weight)`

All factors and weights must be configurable by the AppSec team. The scoring model must support adding new factors without code changes.

### 11.2 Priority Levels

Based on the composite risk score:

| Score Range | Priority      | Expected Action                               |
| ----------- | ------------- | --------------------------------------------- |
| 80-100      | P1 — Critical | Immediate remediation; SLA: defined by policy |
| 60-79       | P2 — High     | Urgent remediation; SLA: defined by policy    |
| 40-59       | P3 — Medium   | Planned remediation; SLA: defined by policy   |
| 20-39       | P4 — Low      | Backlog; address in regular maintenance       |
| 0-19        | P5 — Info     | Track only; no remediation required           |

---

## 12. Workflow and Lifecycle Management

### 12.1 Finding Lifecycle State Machine

```
                    +---> False_Positive
                    |
  New ---> Confirmed ---> In_Remediation ---> Mitigated ---> Verified ---> Closed
                    |                                                        ^
                    +---> Accepted_Risk (with expiry) ---------> re-review --+
                    |
                    +---> Wont_Fix
```

### 12.2 State Transition Rules

| From           | To             | Who                       | Conditions                                                                                                             |
| -------------- | -------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| New            | Confirmed      | AppSec Analyst+           | All findings imported in the platform are confirmed by default                                                         |
| New            | False Positive | AppSec Analyst+           | Analyst determines finding is not valid; requires justification                                                        |
| Confirmed      | In Remediation | AppSec Analyst+           | Finding assigned to development team; ticket created                                                                   |
| Confirmed      | Accepted Risk  | AppSec Manager (approval) | Risk acceptance submitted with justification by remediation_owner; approval required based on severity                 |
| Confirmed      | Wont Fix       | AppSec Manager (approval) | Decision not to fix by remediation_owner; requires justification and approval                                          |
| In Remediation | Mitigated      | Developer                 | Developer marks fix as implemented                                                                                     |
| Mitigated      | Verified       | AppSec Analyst+           | Fix verified (manually or via re-scan. Ideally on next import/findings parsing, that record is not longer in the list) |
| Verified       | Closed         | Auto or Analyst           | Finding resolved                                                                                                       |
| Accepted Risk  | Confirmed      | Auto                      | Risk acceptance expires; finding returns to Confirmed for re-review                                                    |
| Closed         | New            | Auto                      | Same vulnerability reappears in subsequent scan                                                                        |

### 12.3 SLA Framework

| Finding Priority | Tier 1 Asset SLA | Tier 2 Asset SLA | Tier 3 Asset SLA |
| ---------------- | ---------------- | ---------------- | ---------------- |
| P1 — Critical    | 72 hours         | 7 days           | 14 days          |
| P2 — High        | 7 days           | 14 days          | 30 days          |
| P3 — Medium      | 30 days          | 60 days          | 90 days          |
| P4 — Low         | 90 days          | 180 days         | Best effort      |
| P5 — Info        | N/A              | N/A              | N/A              |

SLA values must be fully configurable. SLA clock starts when a finding enters "Confirmed" status.

---

## 13. Dashboards, Reporting, and Analytics

### 13.1 Operational Dashboard (AppSec Analyst)

- Findings requiring triage (New status, sorted by risk score)
- My assigned findings and their SLA status
- Recent ingestion activity (last 24h: findings ingested, deduplicated, errors)
- Open findings by severity and category (SAST/SCA/DAST)
- SLA compliance snapshot (on-track, at-risk, breached)
- Top 10 riskiest applications
- Vulnerability chain/correlation per application/asset (i.e. sqli by SAST,
  confirmed by DAST, etc)

### 13.2 Security Posture Dashboard (Executive)

- Portfolio-wide composite risk score and 30/60/90-day trend
- Finding volume trend by severity (stacked area chart)
- SLA compliance rate over time
- Mean time to remediation by severity
- Top 10 riskiest applications with drill-down
- Findings opened vs. closed trend (burndown)
- Scanner coverage: applications scanned by each tool category
- Risk acceptance summary (count, severity distribution, upcoming expirations)

### 13.3 Application Risk View

- Per-application page showing all findings across all categories
- Application metadata (owner, criticality, business unit, tech stack)
- Application risk score and trend
- SBOM summary with vulnerable component count
- Findings breakdown by category, severity, and status
- SLA compliance for this application
- Remediation velocity (mean time to fix)

### 13.4 Compliance Reports

- Findings by regulatory scope (PCI, GDPR, etc.)
- Risk acceptance register with approval details
- SLA compliance evidence
- Audit trail export
- Finding disposition summary (how findings were resolved)

---

## 14. Asset and Application Inventory

### 14.1 Application Record Structure

| Field                    | Type          | Required | Description                                                                                                     |
| ------------------------ | ------------- | -------- | --------------------------------------------------------------------------------------------------------------- |
| `app_id`                 | UUID          | Auto     | Unique identifier                                                                                               |
| `app_name`               | String        | Yes      | Application name                                                                                                |
| `app_code`               | String        | Yes      | Short code/identifier used across tools                                                                         |
| `description`            | Text          | No       | Application description                                                                                         |
| `criticality_tier`       | Enum          | Yes      | Tier_1, Tier_2, Tier_3                                                                                          |
| `business_unit`          | String        | Yes      | Owning business unit                                                                                            |
| `business_owner`         | String        | Yes      | Business owner (name/email)                                                                                     |
| `technical_owner`        | String        | Yes      | Technical owner (name/email)                                                                                    |
| `security_champion`      | String        | No       | Designated security champion                                                                                    |
| `technology_stack`       | Array[String] | No       | Technologies used (Java, Python, React, etc.)                                                                   |
| `deployment_environment` | Array[Enum]   | No       | Production, Staging, Development                                                                                |
| `exposure`               | Enum          | Yes      | Internet_Facing, DMZ, Internal, Dev_Test                                                                        |
| `data_classification`    | Enum          | Yes      | Public, Internal, Confidential, Restricted                                                                      |
| `regulatory_scope`       | Array[String] | No       | Applicable regulations (PCI-DSS, GDPR, HIPAA, etc.)                                                             |
| `repository_urls`        | Array[String] | No       | Source code repository URLs                                                                                     |
| `scanner_project_ids`    | JSON          | No       | Mapping of scanner names to their project identifiers (e.g., {"SonarQube": "project-key", "Xray": "repo-name"}) |
| `status`                 | Enum          | Yes      | Active, Deprecated, Decommissioned                                                                              |

The application record structure must be configurable and adjustable depending on the file structure of the import.

### 14.2 Scanner-to-Application Mapping

The `scanner_project_ids` field is critical — it enables the platform to automatically associate ingested findings with the correct application record. When a parser ingests a finding from SonarQube project "payment-service", it looks up which application has `scanner_project_ids.SonarQube = "payment-service"` and sets the `application_id` accordingly.

---

## 15. Compliance and Governance

### 15.1 Audit Trail Requirements

Every action in the platform must be recorded in an immutable audit log:

- Finding creation, update, and deletion
- Status transitions with actor, timestamp, and justification
- Risk acceptance submissions and approvals
- Assignment changes
- Configuration changes (SLA policies, scoring weights, parser configurations)
- User access events (login, permission changes)
- Report generation

The audit trail must be exportable and must support retention policies compliant with the organization's data governance requirements.

### 15.2 Risk Acceptance Governance

| Severity      | Approval Authority | Maximum Acceptance Duration | Review Requirement  |
| ------------- | ------------------ | --------------------------- | ------------------- |
| P1 — Critical | CISO or delegate   | 90 days                     | Monthly re-review   |
| P2 — High     | AppSec Manager     | 180 days                    | Quarterly re-review |
| P3 — Medium   | AppSec Team Lead   | 365 days                    | Annual re-review    |
| P4 — Low      | AppSec Analyst     | 365 days                    | Annual re-review    |

All parameters must be configurable.

---

## 16. Non-Functional Requirements

### 16.1 Performance

| Metric                             | Target                                                       |
| ---------------------------------- | ------------------------------------------------------------ |
| Finding ingestion throughput       | Minimum 1,000 findings/minute sustained                      |
| Dashboard load time                | Under 3 seconds for standard views                           |
| API response time (single finding) | Under 500ms (p95)                                            |
| API response time (search/list)    | Under 2 seconds (p95) for up to 10,000 results               |
| Concurrent users                   | 25 simultaneous users without degradation                    |
| Report generation                  | Under 30 seconds for standard reports covering 100K findings |

### 16.2 Scalability

- The platform must support at least 2 million findings in the database without performance degradation
- Horizontal scalability for the ingestion pipeline (add workers to handle more scanner integrations)
- Database must support partitioning/archival strategies for historical data

### 16.3 Availability

- Target availability: 99.5% during business hours (measured monthly)
- Planned maintenance windows: off-hours with advance notification
- Recovery Time Objective (RTO): 4 hours
- Recovery Point Objective (RPO): 1 hour

### 16.4 Usability

- The platform must be accessible via modern web browsers (Chrome, Firefox, Edge — latest two major versions)
- Responsive design supporting desktop (primary) and tablet (secondary) form factors
- Accessibility compliance with WCAG 2.1 Level AA
- UI must support light and dark themes
- UI must support english and italian language

### 16.5 Maintainability

- Codebase must follow established coding standards with automated linting
- All application code, regardless of the language and the feature, must be
  written with a strong secure coding focus and NEVER inotroduce any vulnerability
- Minimum 80% unit test coverage for core business logic (data model, deduplication, correlation, risk scoring)
- Integration tests for all parser plugins
- Automated CI/CD pipeline for builds, tests, and deployments
- Comprehensive API documentation (OpenAPI/Swagger)

---

## 17. Security Requirements

### 17.1 Authentication and Authorization

- Initial development with username + password authentication (and optional MFA
  second factor) following the most secure best practices currently available
- Later we will integrate with the enterprise identity provider (SAML 2.0 / OIDC) for user authentication, allowing domain users to login with their domain credentials (we must already architect the RBAC and authorization roles accordingly)
- API authentication via API keys or OAuth 2.0 tokens
- Role-based access control as defined in Section 5.4
- Session management with configurable timeout
- Multi-factor authentication support (later delegated to enterprise IdP,
  initially with Third parties authenticators like Google authenticator, etc)

### 17.2 Data Protection

- All data encrypted at rest (AES-256 or equivalent)
- All data encrypted in transit (TLS 1.2+). Also on local development
  environment both frontend and backend must enforce https (with self-signed certificates)
- Sensitive fields (API keys, credentials for scanner integrations) encrypted with application-level encryption
- Database access restricted to application service accounts
- No finding data or credentials stored in application logs

### 17.3 Security Logging

- All authentication events logged
- All authorization failures logged
- All administrative actions logged
- Logs must be exportable to enterprise SIEM
- Log retention per organizational policy

---

## 18. Technology and Architecture

### 18.1 High-Level Architecture

```
+------------------+     +------------------+     +------------------+
|   SonarQube      |     |   JFrog Xray     |     |   Tenable WAS    |
|   (SAST)         |     |   (SCA)          |     |   (DAST)         |
+--------+---------+     +--------+---------+     +--------+---------+
         |                        |                        |
         v                        v                        v
+--------+------------------------+------------------------+---------+
|                     INGESTION LAYER                                |
|  +------------+  +------------+  +------------+  +------------+   |
|  | SonarQube  |  | Xray       |  | Tenable    |  | Generic    |   |
|  | Parser     |  | Parser     |  | Parser     |  | SARIF/API  |   |
|  +------------+  +------------+  +------------+  +------------+   |
+--------------------------------------------------------------------+
         |
         v
+--------------------------------------------------------------------+
|                     PROCESSING LAYER                               |
|  +----------------+  +----------------+  +------------------+     |
|  | Normalization  |  | Deduplication  |  | Correlation      |     |
|  | Engine         |  | Engine         |  | Engine           |     |
|  +----------------+  +----------------+  +------------------+     |
|  +----------------+  +----------------+                           |
|  | Risk Scoring   |  | Enrichment     |                           |
|  | Engine         |  | Engine         |                           |
|  +----------------+  +----------------+                           |
+--------------------------------------------------------------------+
         |
         v
+--------------------------------------------------------------------+
|                     DATA LAYER                                     |
|  +---------------------+  +---------------------+                 |
|  | Relational DB       |  | Document Store      |                 |
|  | (Findings, Assets,  |  | (Raw findings,      |                 |
|  |  Relationships,     |  |  Metadata, Audit)   |                 |
|  |  Workflow state)     |  |                     |                 |
|  +---------------------+  +---------------------+                 |
+--------------------------------------------------------------------+
         |
         v
+--------------------------------------------------------------------+
|                     APPLICATION LAYER                              |
|  +----------------+  +----------------+  +------------------+     |
|  | REST API       |  | Workflow       |  | Notification     |     |
|  | (OpenAPI)      |  | Engine         |  | Engine           |     |
|  +----------------+  +----------------+  +------------------+     |
+--------------------------------------------------------------------+
         |
         v
+--------------------------------------------------------------------+
|                     PRESENTATION LAYER                             |
|  +----------------+  +----------------+  +------------------+     |
|  | Web UI         |  | Dashboards     |  | Report Generator |     |
|  | (SPA)          |  | & Analytics    |  |                  |     |
|  +----------------+  +----------------+  +------------------+     |
+--------------------------------------------------------------------+
         |
         v
+--------------------------------------------------------------------+
|                     EXTERNAL INTEGRATIONS                          |
|  +----------------+  +----------------+  +------------------+     |
|  | ServiceNow     |  | Jira           |  | Email / Webhooks |     |
|  | (Bidirectional)|  | (Bidirectional)|  |                  |     |
|  +----------------+  +----------------+  +------------------+     |
+--------------------------------------------------------------------+
```

### 18.2 Technology Recommendations

These are recommendations to be validated during the technical design phase:

| Layer                     | Recommended Options                                            | Rationale                                                                           |
| ------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **Backend API**           | Rust with Axum                                                 | Maximum security and performance                                                    |
| **Frontend**              | React or Angular                                               | Modern SPA frameworks with strong enterprise adoption                               |
| **Database (structured)** | PostgreSQL                                                     | Robust, open-source, JSON support for flexible metadata, DefectDojo uses PostgreSQL |
| **Database (documents)**  | PostgreSQL JSONB                                               | JSONB keeps a single database                                                       |
| **Message Queue**         | RabbitMQ or Redis Streams                                      | For async ingestion pipeline processing                                             |
| **Caching**               | Redis                                                          | API response caching, session management                                            |
| **Containerization**      | Docker + Kubernetes (or Docker Compose for initial deployment) | Standard for enterprise deployment. Evaluate Nginx container too.                   |
| **CI/CD**                 | Jenkins, GitLab CI, or GitHub Actions                          | Per enterprise standard                                                             |
| **API Documentation**     | OpenAPI 3.0 (Swagger)                                          | Industry standard for REST API documentation                                        |

---

## 19. Deployment and Infrastructure

### 19.1 Deployment Model

The platform will be deployed on-premises within the enterprise's infrastructure (or private cloud), consistent with the organization's data sovereignty and security requirements.

### 19.2 Environment Strategy

| Environment | Purpose                                       | Data                                             |
| ----------- | --------------------------------------------- | ------------------------------------------------ |
| Development | Feature development and unit testing          | Synthetic/anonymized test data                   |
| Staging/QA  | Integration testing, UAT, performance testing | Copy of production data (anonymized if required) |
| Production  | Live operational use                          | Real scanner findings and application data       |

### 19.3 Infrastructure Requirements

- Application servers: minimum 2 instances for redundancy (behind load balancer)
- Database: primary + standby replica for high availability
- Storage: sufficient for raw finding storage (estimate based on finding volume and retention policy)
- Network: access to scanner tool APIs, ServiceNow/Jira APIs, email relay, enterprise IdP
- Backup: daily database backups with tested restore procedure

---

## 20. Roadmap and Phasing

### Phase 1: Foundation (Months 1-4)

**Objective:** Core platform with first scanner integration

- Common finding data model implementation
- Ingestion framework and SonarQube parser
- Basic deduplication (intra-tool)
- Finding lifecycle management (state machine)
- Asset/application inventory (manual entry)
- Basic web UI (finding list, detail view, status management)
- REST API (core CRUD operations)
- RBAC (basic roles)
- Database and infrastructure setup

**Exit Criteria:** SonarQube findings ingested, deduplicated, browsable, and manageable through the UI and API.

### Phase 2: Multi-Scanner and Correlation (Months 5-8)

**Objective:** Full SAST + SCA + DAST coverage with correlation

- JFrog Xray parser (SCA)
- Tenable WAS parser (DAST)
- Cross-tool deduplication
- Correlation engine (initial rule set)
- Severity normalization across all three tools
- Risk-based prioritization (composite risk score)
- ServiceNow bidirectional integration
- SLA framework implementation
- Operational dashboard
- Notification engine

**Exit Criteria:** All three scanner tools integrated. Cross-tool correlation operational. Findings auto-assigned with SLA tracking. ServiceNow tickets created automatically.

### Phase 3: Governance and Reporting (Months 9-12)

**Objective:** Full governance framework and enterprise reporting

- Executive security posture dashboard
- Application risk view
- Compliance reporting
- Risk acceptance workflow with approval chain
- Jira integration
- Audit trail and export
- SBOM integration
- Remediation guidance templates
- Advanced correlation rules
- Custom report builder
- Trend analysis and analytics
- Scheduled reports

**Exit Criteria:** Full audit-ready reporting. Risk acceptance governance operational. Executive dashboards live. Platform is the single source of truth for AppSec.

### Phase 4: Maturation and Expansion (Months 13+)

**Objective:** Optimization and preparation for broader adoption

- Parser developer guide and additional scanner integrations
- Performance optimization and scaling
- SARIF native support
- Advanced automation rules
- Expanded RBAC for Vulnerability Management and SOC teams
- Runtime context integration (architecture readiness)
- Threat intelligence enrichment (architecture readiness)
- AI-assisted triage exploration

---

## 21. Success Metrics and KPIs

### 21.1 Platform Adoption

| KPI                          | Target                 | Measurement                                                 |
| ---------------------------- | ---------------------- | ----------------------------------------------------------- |
| Daily active users           | 7 (full AppSec team)   | Login analytics                                             |
| Findings managed in platform | 100% of scanner output | Comparison of scanner finding counts vs. platform ingestion |
| Scanner integrations active  | 3+                     | Integration monitoring                                      |

### 21.2 Operational Efficiency

| KPI                                                           | Target                                | Measurement                      |
| ------------------------------------------------------------- | ------------------------------------- | -------------------------------- |
| Mean time to triage (new finding to confirmed/false positive) | Reduce by 60% from baseline           | Finding lifecycle timestamps     |
| Deduplication ratio                                           | 30%+ reduction in actionable findings | Raw ingested vs. unique findings |
| Manual spreadsheet/email tracking                             | Eliminated                            | Team survey                      |
| Time to generate executive report                             | Under 5 minutes                       | Before/after comparison          |

### 21.3 Security Posture

| KPI                                      | Target                                          | Measurement                         |
| ---------------------------------------- | ----------------------------------------------- | ----------------------------------- |
| SLA compliance rate                      | 90%+                                            | SLA tracking                        |
| Mean time to remediation (Critical/High) | Reduce by 40% from baseline                     | Finding lifecycle timestamps        |
| Risk acceptance coverage                 | 100% of accepted risks documented with approval | Audit trail                         |
| Finding re-open rate                     | Under 10%                                       | Re-opened findings vs. total closed |

---

## 22. Risks and Mitigations

| #   | Risk                                            | Impact   | Likelihood | Mitigation                                                                                                            |
| --- | ----------------------------------------------- | -------- | ---------- | --------------------------------------------------------------------------------------------------------------------- |
| R1  | **Data model insufficient for future tools**    | High     | Medium     | Three-tier model with extensible metadata layer; validate model against 5+ scanner output formats before finalizing   |
| R2  | **Correlation false positives/negatives**       | Medium   | High       | Start with conservative correlation rules; confidence scoring; manual override capability; iterative tuning           |
| R3  | **Scanner API changes break parsers**           | Medium   | High       | Abstract parser interface; version-pinned API clients; integration tests run on schedule; alert on ingestion failures |
| R4  | **Scale issues with large finding volumes**     | High     | Medium     | Database indexing strategy; archival policies; load testing during Phase 2; pagination on all API endpoints           |
| R5  | **Low user adoption**                           | High     | Low        | Involve AppSec team in UX design; iterate on feedback; ensure platform reduces work rather than adding it             |
| R6  | **Integration complexity with ServiceNow/Jira** | Medium   | Medium     | Prototype integration early; handle edge cases (custom fields, workflow states); configurable field mapping           |
| R7  | **Scope creep toward ASPM features**            | Medium   | High       | Clear phase boundaries; architecture supports future extension but initial delivery stays focused                     |
| R8  | **Key person dependency**                       | Medium   | Medium     | Documentation-first approach; parser developer guide; infrastructure-as-code; knowledge sharing within team           |
| R9  | **Security of the security platform**           | Critical | Low        | Follow enterprise security standards; pen-test the platform; encrypt all sensitive data; audit logging                |

---

## 23. Open Questions and Decisions

| #   | Question                                                                                          | Impact | Status                   | Decision                                                                                    |
| --- | ------------------------------------------------------------------------------------------------- | ------ | ------------------------ | ------------------------------------------------------------------------------------------- |
| Q1  | Which technology stack for the backend (Python/Django vs. Java/Spring Boot)?                      | High   | Open                     | To be decided during technical design phase                                                 |
| Q2  | PostgreSQL JSONB vs. separate Elasticsearch for raw finding storage and search?                   | Medium | Open                     | Depends on search requirements and operational complexity tolerance                         |
| Q3  | Should the platform host its own SBOM storage or integrate with an external SBOM management tool? | Medium | Open                     | Depends on enterprise SBOM strategy                                                         |
| Q4  | SLA framework: fixed SLAs or configurable per business unit?                                      | Low    | Leaning configurable     | Validate with stakeholders                                                                  |
| Q5  | Deployment: Docker Compose (simpler) vs. Kubernetes (more scalable) for initial release?          | Medium | Open                     | Depends on enterprise infrastructure and team Kubernetes maturity                           |
| Q6  | How to handle findings for applications not yet in the asset inventory?                           | Medium | Open                     | Options: quarantine, auto-create application record, reject                                 |
| Q7  | Risk scoring model: should weights be global or configurable per business unit?                   | Low    | Leaning global initially | Start global, evaluate per-BU customization later                                           |
| Q8  | What is the data retention policy for findings and raw scanner output?                            | Medium | Open                     | Must align with enterprise data governance                                                  |
| Q9  | Should the Jira integration target Jira Cloud, Jira Data Center, or both?                         | Low    | Open                     | Depends on enterprise Jira deployment                                                       |
| Q10 | How to handle scanner tools that don't provide stable finding identifiers across scans?           | High   | Open                     | Fingerprint algorithm must be robust enough to handle this; may need scanner-specific logic |

---

## 24. Appendices

### Appendix A: Glossary

| Term  | Definition                                         |
| ----- | -------------------------------------------------- |
| ASOC  | Application Security Orchestration and Correlation |
| ASPM  | Application Security Posture Management            |
| SAST  | Static Application Security Testing                |
| SCA   | Software Composition Analysis                      |
| DAST  | Dynamic Application Security Testing               |
| CWE   | Common Weakness Enumeration                        |
| CVE   | Common Vulnerabilities and Exposures               |
| CVSS  | Common Vulnerability Scoring System                |
| EPSS  | Exploit Prediction Scoring System                  |
| KEV   | Known Exploited Vulnerabilities (CISA catalog)     |
| SBOM  | Software Bill of Materials                         |
| SARIF | Static Analysis Results Interchange Format         |
| OCSF  | Open Cybersecurity Schema Framework                |
| VEX   | Vulnerability Exploitability eXchange              |
| SLA   | Service Level Agreement                            |
| RBAC  | Role-Based Access Control                          |
| SSDLC | Secure Software Development Lifecycle              |

### Appendix B: Referenced Documents

- ASOC Market Research v1 (companion document)
- DefectDojo documentation (https://defectdojo.github.io/django-DefectDojo/)
- OWASP Top 10 (https://owasp.org/www-project-top-ten/)
- SARIF Specification (https://docs.oasis-open.org/sarif/)
- CycloneDX Specification (https://cyclonedx.org/)
- NIST Cybersecurity Framework
- Gartner Innovation Insight: Application Security Posture Management (Jan 2025)

### Appendix C: Finding Lifecycle State Diagram

```
  +-----------+
  |   NEW     |
  +-----+-----+
        |
        v
  +-----+-----+     +------------------+
  | CONFIRMED  +---->+ FALSE_POSITIVE   |
  +-----+-----+     +------------------+
        |
        +----------->+------------------+
        |            | ACCEPTED_RISK    +---(expires)---> CONFIRMED
        |            +------------------+
        |
        +----------->+------------------+
        |            | WONT_FIX         |
        |            +------------------+
        v
  +-----+----------+
  | IN_REMEDIATION |
  +-----+----------+
        |
        v
  +-----+-----+
  | MITIGATED  |
  +-----+-----+
        |
        v
  +-----+-----+
  | VERIFIED   |
  +-----+-----+
        |
        v
  +-----+-----+
  |  CLOSED    +---(re-detected)---> NEW
  +-----------+
```

### Appendix D: SonarQube Severity Mapping (Reference)

| SonarQube Severity | Platform Normalized Severity |
| ------------------ | ---------------------------- |
| BLOCKER            | Critical                     |
| CRITICAL           | High                         |
| MAJOR              | Medium                       |
| MINOR              | Low                          |
| INFO               | Informational                |

_Note: This mapping is configurable and should be validated with the AppSec team._

### Appendix E: Composite Risk Score Calculation Example

**Scenario:** SQL Injection (CWE-89) found by SonarQube in the payment-service application.

| Factor                   | Value                                      | Score | Weight | Weighted Score    |
| ------------------------ | ------------------------------------------ | ----- | ------ | ----------------- |
| Normalized Severity      | High                                       | 80    | 30%    | 24.0              |
| Asset Criticality        | Tier 1 (payment-service)                   | 100   | 25%    | 25.0              |
| Exploitability           | Taint analysis confirmed (High confidence) | 80    | 20%    | 16.0              |
| Exposure                 | Internet-facing                            | 100   | 15%    | 15.0              |
| Data Sensitivity         | PII + Financial data                       | 100   | 10%    | 10.0              |
| **Composite Risk Score** |                                            |       |        | **90.0**          |
| **Priority**             |                                            |       |        | **P1 — Critical** |

This finding would be scored P1 despite "only" being a SAST High severity, because the business context (Tier 1 asset, internet-facing, handling financial data) elevates its actual risk significantly.

---

_End of Document_

_This PRD is a living document and will be updated as design decisions are made and requirements are refined through stakeholder review and technical design._
