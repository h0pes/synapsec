# Phase 3a: Interactive Graph Visualization + UI Redesign

## Goal

Deliver the interactive attack chain graph (hard requirement) and a full UI redesign
pass that elevates SynApSec from functional to first-class. Phase 3 is split into
sub-phases; this is the first.

## Phase 3 Sub-Phase Breakdown

| Sub-Phase | Focus |
|-----------|-------|
| **3a (this)** | Graph visualization + UI redesign + category filters + data export + dashboard charts |
| 3b | Governance workflows + reporting + analytics |
| 3c | Enterprise SSO (SAML/OIDC) + SBOM import/analysis |

## Approach

**Graph-First, Then Polish.** Build the React Flow attack chain graph first (hardest,
most complex piece), then do the full UI redesign pass. The graph's visual language
(node colors, edge styles) informs the design system used across all pages.

## Technology Choices

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Graph visualization | React Flow v12 | Purpose-built for node-edge diagrams, MIT, React-native, works with TailwindCSS |
| Charts/analytics | Recharts | Most popular React chart lib, composable, easy to theme |
| Table filtering | TanStack Table column filters | Native feature, Excel-like inline filters per column header |
| Export format | CSV | Universal, opens in Excel. PDF deferred to 3b |

---

## 1. Interactive Attack Chain Graph

### Location

New view on the Attack Chain Detail page (`/attack-chains/:appId`). Augments the
existing card view — users toggle between **Cards** and **Graph** view modes.

### Data Source

The existing `GET /api/v1/attack-chains/:appId` response already returns the required
shape. Each correlation group's findings become nodes and relationships become edges.
**No backend changes needed** for the graph itself.

### Node Design

- Each finding is a node, colored by category:
  - **Blue** = SAST
  - **Purple** = SCA
  - **Teal** = DAST
- Node size scales with severity (Critical largest → Info smallest)
- Node label: finding title (truncated) + severity badge
- Click a node → slide-out panel with full finding detail + link to `/findings/:id`

### Edge Design

- Edges represent correlation relationships
- **Solid line** = High confidence
- **Dashed line** = Medium confidence
- **Dotted line** = Low confidence
- Edge label: correlation rule name on hover
- Click an edge → tooltip with rule details and confidence score

### Layout

- **Default:** Dagre (hierarchical left-to-right) — shows attack chain flow direction
- **Alternative:** Force-directed (toggle), better for exploratory analysis
- React Flow built-in zoom/pan/fit-to-view controls

### Controls

- **Risk score threshold slider** — client-side filter, shows only groups with
  `group_risk_score >= N`
- **Category toggle checkboxes** — show/hide SAST/SCA/DAST nodes
- **Minimap** — React Flow built-in, for orientation in larger graphs
- **Layout toggle** — switch between Dagre and force-directed

### Uncorrelated Findings

Shown as disconnected nodes in a separate cluster (bottom-right), with muted styling
to visually distinguish them from correlated attack chains.

### Test Data Requirement

Current seed data does not produce correlations (no matching CVE/CWE across tools for
the same app). We need to craft specific seed data with:
- Same CVE in both SCA (JFrog Xray) and DAST (Tenable WAS) for one app
- Same CWE in both SAST (SonarQube) and DAST for one app
- Multiple SAST findings with same rule_id across files (intra-tool correlation)

This will produce actual correlation groups to visualize in the graph.

---

## 2. Category-Specific Column Filters

### Approach

Replace the generic filter bar with **inline column-header filters** (TanStack Table
native feature). Each column header has a small filter widget (text input, dropdown,
or date-range picker) directly beneath it. Global text search bar remains above the
table.

### All Tab (Common Cross-Category Fields)

Columns: Title, Severity, Status, Category, Source, First Seen.
Filters: text search on title, dropdown for severity/status/category/source.

### SAST Tab

| Column | DB Field | Filter Type |
|--------|----------|-------------|
| App Code | `applications.app_code` | Searchable dropdown |
| Project | `finding_sast.project` | Searchable text |
| Rule Key | `finding_sast.rule_id` | Searchable text |
| Rule Name | `finding_sast.rule_name` | Searchable text |
| Issue ID | `findings.source_finding_id` | Text |
| Severity | `findings.normalized_severity` | Dropdown |
| Issue Type | `finding_sast.issue_type` | Dropdown (Vulnerability/Security Hotspot) |
| Component | `finding_sast.file_path` | Searchable text |
| Branch | `finding_sast.branch` | Dropdown (populated from data) |
| Created | `finding_sast.scanner_creation_date` | Date range |
| Baseline Date | `finding_sast.baseline_date` | Date range |
| Last Analysis | `finding_sast.last_analysis_date` | Date range |
| Quality Gate | `finding_sast.quality_gate` | Dropdown (Passed/Failed) |

### SCA Tab

| Column | DB Field | Filter Type |
|--------|----------|-------------|
| CVE | `findings.cve_ids` | Searchable text |
| Summary | `findings.title` | Searchable text |
| Severity | `findings.normalized_severity` | Dropdown |
| Vulnerable Component | `finding_sca.package_name + package_version` | Searchable text |
| Physical Path | `finding_sca.affected_artifact` | Searchable text |
| Impacted Artifact | `finding_sca.build_project` | Searchable text |
| Dependency Path | `finding_sca.dependency_path` | Searchable text |
| Published | via `findings.first_seen_at` | Date range |
| Scan Time | `findings.created_at` | Date range |
| Issue ID | `findings.source_finding_id` | Text |
| Package Type | `finding_sca.package_type` | Dropdown (maven/npm/pypi) |
| Has Fix | `finding_sca.fixed_version IS NOT NULL` | Dropdown (Yes/No) |

### DAST Tab

| Column | DB Field | Filter Type |
|--------|----------|-------------|
| Plugin | `findings.source_finding_id` | Text |
| Severity | `findings.normalized_severity` | Dropdown |
| IP Address | via `finding_dast.target_url` | Searchable text |
| URL | `finding_dast.target_url` | Searchable text |
| Port | via `finding_dast.target_url` | Text |
| Exploitable | via `finding_dast.attack_vector` | Dropdown (Yes/No) |
| DNS Name | `finding_dast.web_application_name` | Searchable text |
| First Discovered | `findings.first_seen_at` | Date range |
| Last Observed | `findings.last_seen_at` | Date range |
| Risk Factor | `findings.normalized_severity` | Dropdown |

### Backend Support

New optional query parameters on `GET /api/v1/findings`:
- SAST: `branch`, `rule_id`, `project`, `issue_type`, `quality_gate`,
  `created_from`, `created_to`, `baseline_from`, `baseline_to`
- SCA: `package_type`, `package_name`, `has_fix`, `published_from`, `published_to`
- DAST: `target_url`, `parameter`, `exploitable`, `dns_name`,
  `discovered_from`, `discovered_to`

The service layer adds WHERE clauses with JOINs to category tables only when relevant
params are present. No performance impact when filters are unused.

---

## 3. Data Export

### UX

One **"Export CSV"** button in the Findings page header (next to the findings count).

### Behavior

- Downloads **all findings matching current filters** (ignores pagination)
- On **category tabs**: CSV includes all category-specific fields (full detailed record)
- On **"All" tab**: CSV includes common cross-category fields
- Streaming response for large datasets

### Backend

New endpoint: `GET /api/v1/findings/export`
- Accepts same filter params as the list endpoint + `category` param
- Returns `Content-Type: text/csv` with `Content-Disposition: attachment; filename=...`
- Streams rows to avoid memory issues with large result sets

---

## 4. Dashboard Enhancement

### New Recharts Widgets

Added to the existing dashboard layout:

| Widget | Chart Type | Data Source |
|--------|-----------|-------------|
| Severity distribution | Donut/pie chart | Severity counts from `/dashboard/stats` |
| Findings by source tool | Bar chart | Source tool breakdown (minor stats endpoint extension) |
| Top 5 riskiest apps | Horizontal bar chart | Already in `/dashboard/stats` top_risky_apps |
| SLA compliance | Radial/gauge chart | Already in `/dashboard/stats` sla_summary |

### Existing Stat Cards

Refreshed with better typography, color-coded severity indicators, and subtle visual
improvements as part of the UI polish pass.

### Backend

Minor extension to `/api/v1/dashboard/stats`: add `findings_by_source` field returning
counts grouped by `source_tool`.

---

## 5. Full UI Redesign Pass

### Design System Foundation

- **Color palette:** Custom semantic colors (not default shadcn/ui gray). Category
  colors consistent with graph: SAST blue, SCA purple, DAST teal.
- **Typography:** Inter or similar professional sans-serif. Tighter heading hierarchy.
- **Spacing:** 8px grid system.
- **Depth:** Subtle card shadows, border treatments, refined hover states.
- **Themes:** Both light and dark equally polished via CSS variables.

### Component Restyling

| Component | Enhancement |
|-----------|-------------|
| Sidebar | Accent bar active indicator, refined icons, smooth collapse animation |
| Data tables | Row hover states, subtle alternating tints, sticky headers, inline column filters |
| Cards/widgets | Subtle gradients or glass on hover, consistent border radius |
| Badges | Distinctive per-category color system (SAST/SCA/DAST + severity) |
| Buttons | Refined primary/secondary/ghost variants, consistent sizing |
| Page headers | Consistent pattern: title + subtitle + right-aligned actions |

### Pages Touched

All existing pages receive the redesign:
- Dashboard, Findings, Finding Detail
- Applications, Application Detail
- Attack Chains (graph + card views)
- Correlation, Deduplication
- Ingestion, Triage Queue, Unmapped Apps
- Login page

### Accessibility

WCAG 2.1 Level AA:
- Sufficient color contrast in both themes
- Focus indicators on all interactive elements
- Aria labels on buttons, links, and custom controls
- Keyboard navigation for graph (arrow keys to traverse nodes)

---

## Import Format Reference

| Scanner | Import Format | Export from Findings |
|---------|--------------|-------------------|
| SonarQube (SAST) | CSV | CSV |
| JFrog Xray (SCA) | JSON | CSV |
| Tenable WAS (DAST) | CSV | CSV |

---

## What Is NOT in Phase 3a

Deferred to later sub-phases:
- Risk governance workflows (Risk_Accepted, Deferred_Remediation) → 3b
- Executive reporting, PDF export, scheduled reports → 3b
- Trend analysis / time-series charts → 3b
- Enterprise SSO (SAML/OIDC) → 3c
- SBOM import and analysis → 3c
- Remediation guidance templates → 3b
- Bulk historical data import → 3b
- Advanced correlation rules → 3b
