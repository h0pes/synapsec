# ASOC Market Research — Foundation for PRD

**Document Purpose:** Comprehensive market research on Application Security Orchestration and Correlation (ASOC) to inform the Product Requirements Document for a custom-built ASOC platform.

**Date:** February 2026

---

## 1. Market Definition and Scope

### 1.1 What is ASOC?

Application Security Orchestration and Correlation (ASOC) is a cybersecurity approach that automates the integration, management, and correlation of multiple application security testing tools and their findings throughout the software development lifecycle. ASOC platforms serve as a centralized command center that connects disparate security tools (SAST, DAST, SCA, and others), normalizes and correlates their outputs, deduplicates findings, and enables prioritized remediation workflows.

The two core pillars of ASOC are:

- **Orchestration:** Automating the coordination and management of different security tools — ensuring they work together efficiently and consistently across the SDLC. This includes scan scheduling, pipeline integration, and workflow automation.
- **Correlation:** Aggregating and analyzing data from different security tools to identify patterns, prioritize vulnerabilities, and reduce false positives. Correlation links related security findings from different sources to provide a comprehensive view of risk.

### 1.2 ASOC vs. ASPM — Market Context

ASOC is widely considered the precursor to Application Security Posture Management (ASPM). Gartner has effectively retired the standalone ASOC category, folding its capabilities into the broader ASPM definition. However, the distinction matters for our purposes:

| Dimension         | ASOC                                                                     | ASPM                                                             |
| ----------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------- |
| **Core Focus**    | Tool orchestration, finding correlation, workflow automation             | Continuous posture monitoring, risk-based governance, compliance |
| **Scope**         | Pre-production (development/testing pipeline)                            | Full lifecycle — code to cloud to runtime                        |
| **Approach**      | Primarily reactive — orchestrate responses to discovered vulnerabilities | Proactive — continuous monitoring and preventive measures        |
| **Context**       | Correlates findings by technical attributes (CWE, CVE, location)         | Adds business context, asset criticality, threat intelligence    |
| **Scaling Model** | Scales through people and process                                        | Scales through automation and correlation                        |
| **Maturity**      | Established, well-understood patterns                                    | Evolving, still being defined by the market                      |

**Key takeaway for our project:** Our platform's core scope is ASOC (orchestration + correlation for SAST, SCA, DAST), but the architecture should be designed with ASPM extensibility in mind — not as a current deliverable, but as a natural evolution path.
**Important Note**: continuous posture monitoring, risk-based governance and compliance, full SSDLC coverage, adding business context, asset criticality MUST ALL BE CRITERIA AND CAPABILITIES BUILT INTO OUR PROJECT (despite they are classified more on the ASPM than ASOC side. In fact it could be convenient to drop this distinction and focus on core concepts beyond labels)

### 1.3 Market Evolution Timeline

- **Mid-2010s:** ASOC emerges to address security tool sprawl and alert overload in enterprises
- **2020-2022:** ASOC gains traction; Gartner begins recognizing the category
- **2023:** Gartner places ASPM at "Peak of Inflated Expectations" in the Hype Cycle for Application Security; ASOC is described as the predecessor
- **2024:** ASPM moves toward "Trough of Disillusionment" — fast movement indicating market still defining the category; Gartner calls ASPM "Transformational" and recommends it for orgs with diverse dev teams and wide tooling
- **2025:** Gartner predicts 80% of organizations in regulated verticals using AppSec testing will incorporate ASPM by 2027 (up from 29% in 2025). Invicti acquires Kondukto, signaling ASOC/ASPM vendor consolidation
- **2026 (current):** Market continues consolidating; standalone ASOC vendors are either evolving into ASPM or being acquired

---

## 2. Market Size and Growth

### 2.1 Broader Security Orchestration Market

- The global Security Automation and Orchestration AI market was valued at **$3.6 billion in 2024**, forecast to reach **$18.5 billion by 2033** (CAGR ~20.1%).
- The SOAR (Security Orchestration, Automation and Response) market was estimated at **$1.72 billion in 2024**, projected to reach **$4.11 billion by 2030** (CAGR 15.8%).
- North America holds approximately **35-38%** of the global market.
- Large enterprises held **51-68%** of the 2024 market, depending on the segment.
- Cloud-based deployments accounted for ~55% of new deployments in 2024, growing at ~16.6% CAGR.

### 2.2 Application Security Specific

- Gartner estimated that only **5%** of security teams had an ASPM tool in 2023.
- By 2025, that figure was estimated at **29%** for regulated verticals.
- By 2027, Gartner projects **80%** adoption in regulated verticals using AppSec testing.
- The average global data breach cost hit **$4.88 million in 2024** (IBM) — a major driver for investment.
- Enterprise implementation costs for comprehensive security orchestration range from **$500K to $1.5M** (platform licenses, professional services, change management).

### 2.3 Relevance to Our Project

The market is large and growing rapidly, but commercial ASOC/ASPM tools come with significant licensing costs. For a large enterprise already investing in commercial scanning tools (SonarQube, Xray, Tenable WAS), building a custom ASOC layer can be strategically justified:

- Avoids vendor lock-in to a specific ASPM vendor
- Preserves flexibility to integrate any scanner
- Tailored to internal workflows and governance models
- Lower total cost of ownership for a focused 7-person team vs. enterprise ASPM licensing

---

## 3. Competitive Landscape

### 3.1 Commercial ASOC/ASPM Vendors

#### Tier 1 — Market Leaders (ASPM with ASOC capabilities)

| Vendor                      | Key Characteristics                                                                                                      | Integrations                      | Pricing Model                          |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------ | --------------------------------- | -------------------------------------- |
| **ArmorCode**               | Unified AppSecOps platform (ASPM + UVM + ASOC); vendor-agnostic; AI-powered prioritization; Gartner-recognized           | 160+ security tools               | Custom/contact sales; enterprise-grade |
| **Apiiro**                  | Risk Graph-based; deep code analysis; SSCS capabilities; Gartner #1 in ASPM Critical Capabilities 2025                   | Broad DevSecOps ecosystem         | Custom/enterprise                      |
| **Cycode**                  | Complete ASPM; proprietary scanners + 3rd-party integrations; Risk Intelligence Graph (RIG); Software Supply Chain focus | Broad; code-to-cloud              | Custom/enterprise                      |
| **CrowdStrike Falcon ASPM** | Part of the Falcon platform; cloud-native focus; integrates with broader endpoint/cloud security portfolio               | CrowdStrike ecosystem + 3rd-party | Platform-based pricing                 |

#### Tier 2 — ASOC-Focused / Mid-Market

| Vendor                               | Key Characteristics                                                                                                        | Integrations                        | Pricing Model                          |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- | -------------------------------------- |
| **Invicti ASPM** (formerly Kondukto) | Acquired by Invicti in 2025; quick setup; strong deduplication; 25+ built-in open-source scanners; SBOM locator            | Broad; Jira, Slack, CI/CD tools     | Custom; available on AWS Marketplace   |
| **Hexway ASOC**                      | Universal DevSecOps platform; vulnerability deduplication; Jira integration; positions itself as "better than open source" | Limited (Semgrep, TruffleHog noted) | Custom; targets startups to enterprise |
| **Phoenix Security**                 | ASOC + Risk + Automated actions; pioneering since 2020; risk-based approach                                                | Multiple scanner categories         | Custom                                 |
| **Nucleus Security**                 | Vulnerability management focus; asset-centric approach; risk-based prioritization                                          | Broad vuln management ecosystem     | Custom                                 |
| **Code Dx**                          | ASOC-native platform; centralize and harmonize AppSec testing across pipelines; automation-first                           | Broad scanner support               | Custom                                 |

#### Tier 3 — Adjacent / Platform Plays

| Vendor                  | Key Characteristics                                                                      | Notes                                     |
| ----------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------- |
| **Mend.io**             | SCA-first, expanding to ASPM; consolidation + standardization focus                      | Strong in open-source risk                |
| **OX Security**         | "Active ASPM" with VibeSec; code-to-cloud; supply chain focus                            | Claims 177 alerts to 9 prioritized issues |
| **Legit Security**      | ASPM focus; SDLC-wide coverage; software supply chain                                    | Transitioning market from ASOC to ASPM    |
| **Aikido Security**     | All-in-one platform with built-in scanners (SAST, DAST, SCA, IaC, container)             | Developer-oriented                        |
| **Ivanti Neurons ASPM** | Full-stack visibility; unified scan data; risk-based remediation                         | Enterprise-grade                          |
| **GitLab**              | Built-in DevSecOps with security scanning; not a pure ASOC but covers some orchestration | Mostly for GitLab-native shops            |

### 3.2 Open Source Alternatives

| Tool           | Description                                                                                                                                                                                                             | Maturity                               | Limitations                                                                                                                                                                |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DefectDojo** | The most prominent open-source ASOC/vulnerability management tool. OWASP Flagship Project. 4,500+ GitHub stars, 30M+ downloads. Integrates with 150+ security tools. Bi-directional Jira sync. Docker-based deployment. | High — started 2013, open-sourced 2015 | UI dated (Pro version available); scaling challenges at enterprise volume; limited correlation intelligence; community support only (Pro available for commercial support) |
| **ASPIA**      | Open-source tool for consolidating assets and correlating vulnerability data from scanning tools                                                                                                                        | Low-Medium                             | Less mature; smaller community                                                                                                                                             |
| **Faraday**    | Collaborative pentest and vulnerability management platform                                                                                                                                                             | Medium                                 | More pentest-focused than ASOC                                                                                                                                             |

**VERY IMPORTANT: DefectDojo deserves special attention** as it represents the closest open-source analog to what we are building. Its strengths (broad parser support, Jira integration, deduplication algorithms) and weaknesses (limited correlation intelligence, scaling at enterprise grade, UI/UX, lack of advanced risk-based prioritization) directly inform the gap our platform should fill.

### 3.3 Key Differentiators Across the Market

Based on analysis of the competitive landscape, the following capabilities differentiate leaders from followers:

1. **Breadth of scanner integration** — Leaders support 150-200+ tools; laggards are locked to specific vendors
2. **Correlation quality** — Moving beyond simple deduplication to cross-tool, cross-category correlation (e.g., linking a SAST finding to an SCA finding on the same component)
3. **Risk-based prioritization** — Going beyond CVSS to incorporate business context, asset criticality, exploitability, and threat intelligence
4. **Workflow automation** — Automated ticket creation, SLA enforcement, fix validation, developer notification
5. **Developer experience** — Minimal friction; integration with developer tools (ServiceNoew, Jira, IDEs, CI/CD)
6. **Reporting and compliance** — Executive dashboards, trend analysis, regulatory compliance evidence
7. **Scalability** — Handling the volume of findings from large enterprise application portfolios

---

## 4. Enterprise Pain Points (Why Build an ASOC)

Based on market research, the following pain points drive ASOC adoption — and are directly relevant to a ~7-person AppSec team at a large enterprise:

### 4.1 Tool Fatigue and Fragmentation

Enterprises run an average of 45+ security tools but struggle to link more than one-fifth of them through robust two-way APIs. Each tool has its own dashboard, alert format, severity scoring, and workflow. Security professionals juggle 10+ tools daily. This creates operational overhead and increases the risk of missing critical vulnerabilities.

**Our context:** The team uses SonarQube (SAST), JFrog Xray (SCA), and Tenable WAS (DAST) — three separate consoles, three different output formats, three different severity models. There is no single pane of glass.

### 4.2 Alert Overload and Noise

A typical enterprise can generate thousands of security findings daily across all scanners. Without correlation and deduplication, teams are overwhelmed. The Cycode State of ASPM 2024 Report found that 78% of CISOs believe their AppSec attack paths are "unmanageable." OX Security demonstrated that 177 raw alerts can typically collapse to 92 unique issues, of which only 9 require prioritization — but reaching that reduction requires correlation intelligence.

**Our context:** A 7-person team cannot manually triage thousands of findings. Automated deduplication and prioritization is essential for the team to function.

### 4.3 Inconsistent Severity and Prioritization

Each scanner uses its own severity model. SonarQube, Xray, and Tenable WAS each rate severity differently. Without normalization, the team has no consistent way to compare a SAST critical vs. an SCA critical vs. a DAST high. CVSS alone is insufficient — it doesn't account for business context, asset criticality, or exploitability in the specific environment.

### 4.4 Manual Correlation and Spreadsheet Hell

Without an ASOC, teams often resort to exporting CSV/JSON from scanners, manually deduplicating in spreadsheets, and tracking remediation via email or disconnected ticketing. This is error-prone, time-consuming, and doesn't scale.

### 4.5 Lack of Remediation Tracking and SLA Enforcement

Individual scanners detect vulnerabilities but don't track remediation lifecycle. There's no unified view of what's been found, assigned, accepted, mitigated, or verified as fixed — and no enforcement of remediation SLAs.

### 4.6 Reporting Gaps

Executive and compliance reporting requires aggregated metrics across all scanner types. Without an ASOC, producing a unified security posture report means manually combining data from multiple tools — a time-consuming and error-prone process.

### 4.7 Knowledge Retention

When team members leave or scanners change, institutional knowledge about findings, decisions, and context is lost. An ASOC serves as the organizational memory for application security.

---

## 5. Core ASOC Capabilities (Market Consensus)

Based on analysis of commercial vendors, open-source tools, and analyst reports, the following capabilities represent the market consensus for what an ASOC platform must deliver:

### 5.1 Must-Have (Core ASOC)

| #   | Capability                       | Description                                                                                                  |
| --- | -------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| 1   | **Multi-tool ingestion**         | Ingest findings from any SAST, SCA, and DAST tool via parsers/connectors; vendor-agnostic design             |
| 2   | **Common finding data model**    | Normalize all findings into a unified schema regardless of source tool                                       |
| 3   | **Deduplication**                | Identify and merge duplicate findings — both within a single tool and across tools                           |
| 4   | **Cross-tool correlation**       | Link related findings across scanner categories (e.g., SAST + SCA pointing to the same vulnerable component) |
| 5   | **Severity normalization**       | Map tool-specific severity ratings to a unified severity scale                                               |
| 6   | **Finding lifecycle management** | Track status: New, Confirmed, In Remediation, Mitigated, Verified, Closed / False Positive / Accepted Risk   |
| 7   | **Workflow automation**          | Automated ticket creation (e.g., Jira), assignment, notification, and SLA tracking                           |
| 8   | **Dashboards and reporting**     | Unified security posture view; trend analysis; executive summaries; compliance reporting                     |
| 9   | **Role-based access control**    | Different views/permissions for AppSec team, developers, management                                          |
| 10  | **API-first architecture**       | RESTful API for all operations; enables CI/CD integration and automation                                     |
| 11  | **Risk-based prioritization**    | Go beyond severity to incorporate asset criticality, business impact, exploitability                         |
| 12  | **SBOM integration**             | Software Bill of Materials awareness for SCA correlation                                                     |
| 13  | **Remediation guidance**         | Consistent remediation advice by CWE/vulnerability type; templated guidance                                  |

### 5.2 Should-Have (Enhanced ASOC)

| #   | Capability                      | Description                                                                    |
| --- | ------------------------------- | ------------------------------------------------------------------------------ |
| 14  | **CI/CD pipeline integration**  | Trigger scans, ingest results, and enforce gates directly from build pipelines |
| 15  | **Fix verification**            | Automated re-scan or validation to confirm that remediation was effective      |
| 16  | **Asset/application inventory** | Central registry of applications, their tech stacks, owners, and risk profiles |
| 17  | **SLA management**              | Define and enforce remediation timelines by severity; track compliance         |
| 18  | **Audit trail**                 | Full history of actions, status changes, and decisions for compliance          |

### 5.3 Nice-to-Have (ASPM Extension Path)

| #   | Capability                          | Description                                                                 |
| --- | ----------------------------------- | --------------------------------------------------------------------------- |
| 19  | **Runtime context**                 | Incorporate runtime/production data to inform prioritization                |
| 20  | **Threat intelligence integration** | Enrich findings with external threat intel feeds                            |
| 21  | **Business context mapping**        | Link applications to business units, revenue impact, data sensitivity       |
| 22  | **Policy-as-code**                  | Codified security policies enforced across the SDLC                         |
| 23  | **Developer training loop**         | Personalized security training based on developer vulnerability patterns    |
| 24  | **AI-assisted triage**              | ML-based false positive detection, auto-classification, priority suggestion |

---

## 6. The Common Finding Data Model — Market Approaches

This is the central architectural challenge. Every vendor approaches it differently, and no open standard has achieved universal adoption.

### 6.1 The Problem

Each scanner produces findings in its own proprietary format with different:

- Field names and structures
- Severity scoring systems (CVSS v2, v3, v3.1, v4, tool-specific scales)
- Vulnerability identifiers (CWE, CVE, tool-internal IDs, OWASP categories)
- Location descriptions (file + line for SAST; package + version for SCA; URL + parameter for DAST)
- Confidence levels and evidence formats
- Metadata and context

A SAST finding from SonarQube looks nothing like an SCA finding from Xray or a DAST finding from Tenable WAS — yet they all need to coexist in a unified model that enables correlation, deduplication, and consistent prioritization.

### 6.2 How the Market Approaches This

**DefectDojo's approach:** Uses a hierarchical model (Product, Engagement, Test, Finding) with a common Finding model. Each imported finding gets mapped to core fields (title, severity, CWE, description, file_path, line, component_name, component_version, etc.). Parser plugins handle the translation from tool-specific formats. Stores raw data alongside normalized fields.

**ArmorCode's approach:** Normalizes across 160+ tools; uses AI-powered correlation to link findings. Groups findings into "unified findings" that aggregate multiple tool observations of the same issue.

**Kondukto/Invicti ASPM approach:** Hierarchical views with deduplication at ingestion. Security scores derived from normalized data. Preserves tool-specific data while presenting a unified view.

**Common patterns across vendors:**

- Two-tier model: core normalized fields + flexible/extensible metadata
- Preservation of the original raw finding for traceability
- CWE as the primary cross-tool vulnerability taxonomy
- CVE as the primary identifier for known vulnerabilities (especially SCA)
- CVSS as a baseline severity reference, with platform-specific risk scoring layered on top
- Finding "fingerprint" or hash for deduplication (combining location + vulnerability type + component)

### 6.3 Proposed Model Structure (High-Level)

Based on market analysis, the common finding data model should have:

**Core Layer (Universal across all finding types):**

- Platform-generated unique ID
- Source tool identifier and version
- Finding category (SAST / SCA / DAST)
- Title / summary
- Description
- Normalized severity (Critical / High / Medium / Low / Info)
- Original tool severity (preserved as-is)
- CVSS score and vector (where available)
- CWE reference(s)
- CVE reference(s) (where applicable)
- Status / lifecycle state
- First seen / last seen timestamps
- Affected application / asset reference
- Confidence level
- Hash/fingerprint for deduplication

**Category-Specific Layer:**

_SAST-specific:_

- File path and line number(s)
- Project
- Rule name from the scanner
- Tag
- Vulnerability description from the scanner
- Issue type (i.e. Sonarqube has both VULNERABILITY and SECURITY_HOTSPOT)
- Branch (dev/prod)
- URL (the url to the issue on the platform)
- Creation date
- Baseline date
- Last analysis
- Code snippet / evidence
- Source and sink (for taint analysis)
- Language / framework
- Rule ID from the scanner

_SCA-specific:_

- Package name and version (vulnerable)
- Fixed version (if known)
- Dependency path (direct vs. transitive)
- License information
- SBOM reference
- Exploitability data (known exploits in the wild)

_DAST-specific:_

- Target URL / endpoint
- HTTP method
- Parameter / injection point
- Request/response evidence
- Authentication context
- OWASP category

**Extensible Metadata Layer:**

- Key-value store for tool-specific attributes not captured above
- Tags / labels
- Custom risk factors
- Business context annotations
- Raw finding payload (original scanner output, stored as JSON blob)

### 6.4 Open Standards to Consider

- **SARIF (Static Analysis Results Interchange Format):** OASIS standard for expressing static analysis results. Supported by many SAST tools. Could serve as an intermediate format.
- **CycloneDX / SPDX:** SBOM standards that could inform the SCA data model.
- **OCSF (Open Cybersecurity Schema Framework):** Emerging schema for security data normalization; worth monitoring.
- **VEX (Vulnerability Exploitability eXchange):** Standard for communicating whether a product is affected by a vulnerability.

---

## 7. Technology and Architecture Patterns

### 7.1 Common Architecture Patterns in ASOC Platforms

Based on analysis of commercial and open-source platforms:

**Ingestion Layer:**

- Parser/connector plugins per tool (most common pattern)
- API-based ingestion (scanners push findings via REST API)
- File-based import (CSV, JSON, XML, SARIF upload)
- Webhook triggers from CI/CD pipelines

**Processing Layer:**

- Normalization engine (maps tool-specific formats to common model)
- Deduplication engine (fingerprint-based matching)
- Correlation engine (links findings across tools/categories)
- Severity normalization / risk scoring engine

**Storage Layer:**

- Relational database for structured finding data and relationships
- Document store for raw findings and flexible metadata
- Time-series or event store for audit trail and trend analysis

**Presentation Layer:**

- Web-based dashboard (single pane of glass)
- REST API for programmatic access
- Integration hooks (Jira, Slack, email, CI/CD)

**Workflow Layer:**

- Finding lifecycle state machine
- Automated routing and assignment rules
- SLA enforcement and alerting
- Ticketing system integration (bidirectional)

### 7.2 Deployment Models in the Market

- On-premises: 55.64% of the security orchestration market in 2024 (declining)
- Cloud/SaaS: Growing at 16.6% CAGR; 55% of new deployments
- Hybrid: Increasingly common in large enterprises with data sovereignty requirements
- Container-based (Docker/Kubernetes): Standard for modern deployments (DefectDojo uses Docker Compose)

---

## 8. Key Risks and Challenges

### 8.1 Data Model Complexity

The common finding data model is the single hardest design challenge. Too rigid and it cannot accommodate new tools; too flexible and it loses its ability to enable meaningful correlation and reporting. Every vendor that has been acquired or struggled has faced this challenge.

### 8.2 Integration Maintenance

Tool integration fragility was ASOC's most persistent operational challenge according to Palo Alto Networks' analysis. Scanner APIs change frequently, output formats evolve, and maintaining parsers requires ongoing investment. The platform must be designed to make adding and updating parsers low-friction.

### 8.3 Correlation Accuracy

False positive rates increase when correlating vulnerabilities from tools using different detection approaches. A SAST finding and a DAST finding may describe the same vulnerability in completely different terms. Achieving reliable cross-tool correlation is technically difficult and requires careful heuristic design.

### 8.4 Scale

Enterprise AppSec programs can generate tens of thousands of findings per scan cycle. The platform must handle this volume for ingestion, deduplication, and querying without degrading performance.

### 8.5 User Adoption

90% of CISOs say security-development team relationships need improvement (Cycode 2024). The platform must be intuitive enough for a small AppSec team and not add friction to developer workflows.

---

## 9. Strategic Recommendations for the PRD

Based on this market research, the following strategic directions are recommended:

1. **Build ASOC-first, ASPM-ready.** The core platform delivers orchestration and correlation for SAST, SCA, and DAST. Architecture decisions should anticipate ASPM extension (runtime context, business risk scoring, policy-as-code) must be included in the initial scope.

2. **Vendor-agnostic by design.** The parser/connector layer must be pluggable. Start with SonarQube, Xray, and Tenable WAS as the first three implementations, but the ingestion framework should make adding new tools straightforward for the team.

3. **Invest heavily in the common data model.** This is the foundation everything else builds on. Allocate significant design effort upfront. Use the two-tier model (core normalized fields + extensible metadata) and preserve raw findings.

4. **Learn from DefectDojo, don't replicate it.** DefectDojo is the most mature open-source analog. Study its parser architecture, data model, and Jira integration — but address its weaknesses: limited correlation intelligence, dated UX, and lack of advanced risk-based prioritization.

5. **Design for a 7-person team first.** The initial UX should optimize for the daily workflows of a small, expert AppSec team. Multi-team expansion (Vuln Management, SOC) is a future concern — design the RBAC model to support it, but don't over-engineer the initial UX.

6. **Prioritize deduplication and correlation quality.** This is where the real value lies for the team. Reducing noise from thousands of findings to the set that actually matters is the core value proposition.

7. **API-first architecture.** Everything must be API-accessible. This enables CI/CD integration, automation, and future extensibility without being constrained by the UI.

---

## 10. Appendix — Vendor Quick Reference

### Commercial Vendors Mentioned

| Vendor                     | Category        | Website           | Notable                                    |
| -------------------------- | --------------- | ----------------- | ------------------------------------------ |
| ArmorCode                  | ASPM + ASOC     | armorcode.com     | 160+ integrations; Gartner-recognized      |
| Apiiro                     | ASPM            | apiiro.com        | Gartner #1 ASPM Critical Capabilities 2025 |
| Cycode                     | ASPM            | cycode.com        | Complete ASPM; Risk Intelligence Graph     |
| CrowdStrike Falcon ASPM    | ASPM            | crowdstrike.com   | Part of Falcon platform                    |
| Invicti ASPM (ex-Kondukto) | ASOC/ASPM       | invicti.com       | Acquired Kondukto 2025; proof-based DAST   |
| Hexway ASOC                | ASOC            | hexway.io         | Targets small-to-enterprise                |
| Phoenix Security           | ASOC/ASPM       | phoenix.security  | Risk-based ASOC pioneer                    |
| Nucleus Security           | Vuln Management | nucleussec.com    | Asset-centric approach                     |
| Code Dx                    | ASOC            | codedx.com        | Automation-first ASOC                      |
| OX Security                | ASPM            | ox.security       | Active ASPM; VibeSec                       |
| Legit Security             | ASPM            | legitsecurity.com | SDLC-wide; supply chain                    |
| Aikido Security            | All-in-one      | aikido.dev        | Built-in scanners + ASPM                   |
| Mend.io                    | SCA/ASPM        | mend.io           | SCA-first, expanding                       |
| Ivanti Neurons ASPM        | ASPM            | ivanti.com        | Enterprise-grade                           |
| Hackuity                   | Vuln Ops        | hackuity.io       | True Risk Score (TRS)                      |

### Open Source

| Tool       | Website        | GitHub Stars | License      |
| ---------- | -------------- | ------------ | ------------ |
| DefectDojo | defectdojo.com | 4,500+       | BSD-3-Clause |
| ASPIA      | —              | —            | Open source  |
| Faraday    | —              | —            | Open source  |

---

_This document serves as the market research foundation for the ASOC PRD. It should be reviewed and validated before proceeding to requirements definition._
