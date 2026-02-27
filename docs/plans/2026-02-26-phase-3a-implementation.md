# Phase 3a: Interactive Graph Visualization + UI Redesign — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Deliver the interactive attack chain graph (React Flow), category-specific column filters, CSV/JSON data export, Recharts dashboard widgets, and a full UI redesign across all 13 pages.

**Architecture:** Graph-First, Then Polish. Build the React Flow attack chain graph first (hardest piece), then category tables with inline filters, export, dashboard charts, and finally a comprehensive UI redesign pass using the `frontend-design` plugin. Backend changes (seed data, API extensions, export endpoint) come first to unblock frontend work.

**Tech Stack:** Rust/Axum (backend), React 19 + TypeScript (frontend), React Flow v12 (`@xyflow/react`), dagre (`@dagrejs/dagre`), Recharts, TanStack Table v8 column filters, TailwindCSS v4, shadcn/ui. **All new dependencies must be pinned to the latest stable version at time of installation — no exceptions.**

**Design doc:** `docs/plans/2026-02-26-phase-3a-design.md`

---

## Block 1: Backend Foundation (Tasks 1–5)

---

### Task 1: Craft correlated seed data and update seed script

**Files:**
- Create: `backend/tests/fixtures/correlation_sast_seed.csv`
- Create: `backend/tests/fixtures/correlation_sca_seed.json`
- Create: `backend/tests/fixtures/correlation_dast_seed.csv`
- Modify: `backend/src/bin/seed.rs`

**Context:** Current seed data (`sonarqube_sample.json`, `jfrog_xray_seed.json`, `tenable_was_seed.csv`) does not produce correlations because no findings share CVE/CWE across tools for the same app. The correlation engine needs matching identifiers to create relationships. After seeding, the correlation engine must be triggered to build the relationship graph.

**Step 1: Create SAST fixture (`correlation_sast_seed.csv`)**

Create a SonarQube CSV export with findings for app **PAYM1** that share CWE IDs with the DAST fixture below. Include:
- 3 findings with CWE-79 (XSS) — different files, same `rule_id` (`javascript:S5131`) to trigger CR-4 (intra-tool clustering)
- 2 findings with CWE-89 (SQL Injection)
- 1 finding with CWE-22 (Path Traversal)

Use the existing SonarQube CSV column format. Set `project` to `paym1-frontend` and `paym1-backend`. Set `branch` to `main`.

**Step 2: Create SCA fixture (`correlation_sca_seed.json`)**

Create a JFrog Xray JSON export with findings for app **PAYM1** that share CVE IDs with the DAST fixture:
- 2 findings with CVE-2024-38816 (Spring Framework path traversal)
- 1 finding with CVE-2024-22262 (Spring URL parsing)
- 1 finding with CVE-2023-44487 (HTTP/2 rapid reset)

Use the existing Xray JSON structure from `jfrog_xray_seed.json` as template. Set artifact paths to contain `paym1`.

**Step 3: Create DAST fixture (`correlation_dast_seed.csv`)**

Create a Tenable WAS CSV export with findings for app **PAYM1** that share CWE/CVE with the above:
- 2 findings with CWE-79 (matching SAST) — different URLs
- 1 finding with CWE-89 (matching SAST)
- 1 finding with CVE-2024-38816 (matching SCA)
- 1 finding with CWE-22 (matching SAST)

Use the existing Tenable WAS CSV column format from `tenable_was_seed.csv`.

**Step 4: Update seed script to ingest correlation fixtures**

In `backend/src/bin/seed.rs`, add a new function `seed_correlation_findings()` called after the existing seed functions. This function:
1. Checks if correlation fixtures have already been ingested (via `ingestion_logs` check for `file_name = 'correlation_sast_seed.csv'`)
2. If not, ingests all three correlation fixtures using the existing ingestion pipeline
3. After ingestion, calls the correlation engine for PAYM1's `application_id`

To trigger correlation, reuse the same logic as `POST /api/v1/correlations/run/:app_id`:
```rust
use crate::services::correlation::run_correlation_for_app;
// After ingestion:
let paym1 = sqlx::query_scalar!("SELECT id FROM applications WHERE app_code = 'PAYM1'")
    .fetch_one(&pool).await?;
run_correlation_for_app(&pool, paym1).await?;
```

**Step 5: Verify**

```bash
cd backend && cargo run --bin seed
# Expected: "Seeding correlation fixtures..." + "Correlation engine: X relationships created for PAYM1"
```

Then verify relationships exist:
```bash
# Via psql or API call
curl -k https://localhost:3000/api/v1/attack-chains/PAYM1_APP_ID -H "Authorization: Bearer $TOKEN"
# Expected: chains[] with multiple findings per chain, relationship_count > 0
```

**Commit:** `feat: add correlated seed data for attack chain graph testing`

---

### Task 2: Extend attack chain API with relationship edges

**Files:**
- Modify: `backend/src/services/attack_chains.rs`
- Modify: `frontend/src/types/attack-chains.ts`

**Context:** The current `AttackChain` struct returns `findings[]` and `relationship_count` but not the actual edges. The graph needs `source_finding_id → target_finding_id` with relationship type and confidence score to draw edges.

**Step 1: Add `ChainRelationship` struct**

In `backend/src/services/attack_chains.rs`, add:
```rust
#[derive(Debug, Serialize)]
pub struct ChainRelationship {
    pub id: Uuid,
    pub source_finding_id: Uuid,
    pub target_finding_id: Uuid,
    pub relationship_type: String,
    pub confidence_score: Option<f32>,
    pub correlation_rule_id: Option<Uuid>,
    pub rule_name: Option<String>,
}
```

**Step 2: Add `relationships` field to `AttackChain`**

```rust
pub struct AttackChain {
    pub group_id: Uuid,
    pub findings: Vec<ChainFinding>,
    pub relationships: Vec<ChainRelationship>,  // NEW
    pub tool_coverage: Vec<String>,
    pub max_severity: String,
    pub relationship_count: i64,
}
```

**Step 3: Fetch relationships in `get_by_app()`**

After fetching findings and building chains via union-find, fetch all relationships for the app's findings:
```sql
SELECT fr.id, fr.source_finding_id, fr.target_finding_id,
       fr.relationship_type, fr.confidence_score, fr.correlation_rule_id,
       cr.name as rule_name
FROM finding_relationships fr
LEFT JOIN correlation_rules cr ON cr.id = fr.correlation_rule_id
WHERE fr.source_finding_id = ANY($1) OR fr.target_finding_id = ANY($1)
```

Where `$1` is the array of all finding IDs for this app. Then distribute relationships into their respective `AttackChain` groups based on which chain contains the source/target finding.

**Step 4: Update frontend types**

In `frontend/src/types/attack-chains.ts`, add:
```typescript
export interface ChainRelationship {
  id: string
  source_finding_id: string
  target_finding_id: string
  relationship_type: string
  confidence_score: number | null
  correlation_rule_id: string | null
  rule_name: string | null
}
```

Add `relationships: ChainRelationship[]` to the `AttackChain` interface.

**Step 5: Verify**

```bash
cd backend && cargo test
cd backend && cargo clippy
```

**Commit:** `feat: include relationship edges in attack chain API response`

---

### Task 3: Add `findings_by_source` to dashboard stats

**Files:**
- Modify: `backend/src/services/dashboard.rs`
- Modify: `backend/src/routes/dashboard.rs` (if response type is defined there)
- Modify: `frontend/src/types/finding.ts` or `frontend/src/api/dashboard.ts` (dashboard stats type)

**Context:** Dashboard stats endpoint (`GET /api/v1/dashboard/stats`) returns `DashboardStats` with severity counts, SLA summary, recent ingestions, top risky apps. Need to add `findings_by_source` field with counts grouped by `source_tool`.

**Step 1: Add struct and query**

In `backend/src/services/dashboard.rs`, add to `DashboardStats`:
```rust
pub findings_by_source: Vec<SourceToolCount>,
```

Add:
```rust
#[derive(Debug, Serialize)]
pub struct SourceToolCount {
    pub source_tool: String,
    pub count: i64,
}
```

Add query (run in parallel with existing queries via `tokio::try_join!`):
```sql
SELECT source_tool, COUNT(*) as count
FROM findings
WHERE status NOT IN ('Closed', 'False_Positive', 'Invalidated')
GROUP BY source_tool
ORDER BY count DESC
```

**Step 2: Update frontend types**

Add `findings_by_source: { source_tool: string; count: number }[]` to the dashboard stats type used by `DashboardPage.tsx`.

**Step 3: Verify**

```bash
cd backend && cargo test
cd backend && cargo clippy
```

**Commit:** `feat: add findings_by_source to dashboard stats endpoint`

---

### Task 4: Add category-specific filter parameters to findings endpoint

**Files:**
- Modify: `backend/src/models/finding.rs` (extend `FindingFilters`)
- Modify: `backend/src/services/finding.rs` (extend WHERE clause builder)
- Modify: `backend/src/routes/findings.rs` (extract new query params)

**Context:** The current `FindingFilters` supports: `severity`, `status`, `category`, `application_id`, `source_tool`, `sla_status`, `search`, `include_category_data`. Need to add category-specific filters that trigger JOINs to `finding_sast`, `finding_sca`, `finding_dast` tables.

**Step 1: Extend `FindingFilters` struct**

```rust
pub struct FindingFilters {
    // Existing fields...
    pub severity: Option<SeverityLevel>,
    pub status: Option<FindingStatus>,
    pub category: Option<FindingCategory>,
    pub application_id: Option<Uuid>,
    pub source_tool: Option<String>,
    pub sla_status: Option<SlaStatus>,
    pub search: Option<String>,
    pub include_category_data: Option<bool>,

    // SAST-specific
    pub branch: Option<String>,
    pub rule_id: Option<String>,
    pub project: Option<String>,
    pub issue_type: Option<String>,
    pub quality_gate: Option<String>,
    pub sast_created_from: Option<DateTime<Utc>>,
    pub sast_created_to: Option<DateTime<Utc>>,
    pub baseline_from: Option<DateTime<Utc>>,
    pub baseline_to: Option<DateTime<Utc>>,

    // SCA-specific
    pub package_type: Option<String>,
    pub package_name: Option<String>,
    pub has_fix: Option<bool>,
    pub published_from: Option<DateTime<Utc>>,
    pub published_to: Option<DateTime<Utc>>,

    // DAST-specific
    pub target_url: Option<String>,
    pub exploitable: Option<bool>,
    pub dns_name: Option<String>,
    pub discovered_from: Option<DateTime<Utc>>,
    pub discovered_to: Option<DateTime<Utc>>,
}
```

**Step 2: Add helper methods**

```rust
impl FindingFilters {
    pub fn has_sast_filters(&self) -> bool {
        self.branch.is_some() || self.rule_id.is_some() || self.project.is_some()
            || self.issue_type.is_some() || self.quality_gate.is_some()
            || self.sast_created_from.is_some() || self.sast_created_to.is_some()
            || self.baseline_from.is_some() || self.baseline_to.is_some()
    }

    pub fn has_sca_filters(&self) -> bool {
        self.package_type.is_some() || self.package_name.is_some()
            || self.has_fix.is_some()
            || self.published_from.is_some() || self.published_to.is_some()
    }

    pub fn has_dast_filters(&self) -> bool {
        self.target_url.is_some() || self.exploitable.is_some()
            || self.dns_name.is_some()
            || self.discovered_from.is_some() || self.discovered_to.is_some()
    }
}
```

**Step 3: Extend WHERE clause builder in finding service**

In `list_with_category()`, after the existing conditions, add conditional JOINs and WHERE clauses:

```rust
// Dynamic JOINs — only join category tables when their filters are active
// (list_with_category already LEFT JOINs all three tables, so just add WHERE clauses)

if filters.has_sast_filters() {
    if let Some(branch) = &filters.branch {
        param_index += 1;
        conditions.push(format!("fs.branch = ${param_index}"));
    }
    if let Some(rule_id) = &filters.rule_id {
        param_index += 1;
        conditions.push(format!("fs.rule_id = ${param_index}"));
    }
    if let Some(project) = &filters.project {
        param_index += 1;
        conditions.push(format!("fs.project ILIKE ${param_index}"));
        // bind format!("%{project}%")
    }
    if let Some(issue_type) = &filters.issue_type {
        param_index += 1;
        conditions.push(format!("fs.issue_type = ${param_index}"));
    }
    if let Some(quality_gate) = &filters.quality_gate {
        param_index += 1;
        conditions.push(format!("fs.quality_gate = ${param_index}"));
    }
    if let Some(from) = &filters.sast_created_from {
        param_index += 1;
        conditions.push(format!("fs.scanner_creation_date >= ${param_index}"));
    }
    if let Some(to) = &filters.sast_created_to {
        param_index += 1;
        conditions.push(format!("fs.scanner_creation_date <= ${param_index}"));
    }
    // baseline_from, baseline_to similarly
}

// SCA filters (fc = finding_sca alias)
if filters.has_sca_filters() {
    if let Some(package_type) = &filters.package_type {
        param_index += 1;
        conditions.push(format!("fc.package_type = ${param_index}"));
    }
    if let Some(package_name) = &filters.package_name {
        param_index += 1;
        conditions.push(format!("fc.package_name ILIKE ${param_index}"));
    }
    if let Some(has_fix) = &filters.has_fix {
        if *has_fix {
            conditions.push("fc.fixed_version IS NOT NULL".to_string());
        } else {
            conditions.push("fc.fixed_version IS NULL".to_string());
        }
    }
    // published_from, published_to on findings.first_seen_at
}

// DAST filters (fd = finding_dast alias)
if filters.has_dast_filters() {
    if let Some(target_url) = &filters.target_url {
        param_index += 1;
        conditions.push(format!("fd.target_url ILIKE ${param_index}"));
    }
    if let Some(exploitable) = &filters.exploitable {
        if *exploitable {
            conditions.push("fd.attack_vector IS NOT NULL AND fd.attack_vector != ''".to_string());
        } else {
            conditions.push("(fd.attack_vector IS NULL OR fd.attack_vector = '')".to_string());
        }
    }
    if let Some(dns_name) = &filters.dns_name {
        param_index += 1;
        conditions.push(format!("fd.web_application_name ILIKE ${param_index}"));
    }
    // discovered_from, discovered_to on findings.first_seen_at
}
```

**Step 4: Extract new query params in route handler**

In `backend/src/routes/findings.rs`, extend the query parameter extraction for the `list` handler to include all new filter fields. Use `Option<String>` for query params and parse into the correct types.

**Step 5: Verify**

```bash
cd backend && cargo test
cd backend && cargo clippy
```

Test with curl:
```bash
curl -k "https://localhost:3000/api/v1/findings?category=SAST&branch=main&include_category_data=true" \
  -H "Authorization: Bearer $TOKEN"
```

**Commit:** `feat: add category-specific filter parameters to findings endpoint`

---

### Task 5: Implement findings export endpoint (CSV + JSON)

**Files:**
- Create: `backend/src/routes/export.rs`
- Modify: `backend/src/routes/mod.rs` (add export module)
- Modify: `backend/src/main.rs` (mount export route)

**Context:** New endpoint `GET /api/v1/findings/export` that accepts the same filter params as the list endpoint plus `format=csv|json`. Streams the response to handle large datasets.

**Step 1: Create export route handler**

In `backend/src/routes/export.rs`:
```rust
use axum::{extract::{Query, State}, response::Response, body::Body};
use crate::{errors::AppError, middleware::auth::CurrentUser, models::finding::FindingFilters, AppState};

#[derive(Deserialize)]
pub struct ExportParams {
    #[serde(flatten)]
    pub filters: FindingFilters,
    pub format: Option<String>, // "csv" or "json", defaults to "csv"
}

pub async fn export_findings(
    State(state): State<AppState>,
    CurrentUser(user): CurrentUser,
    Query(params): Query<ExportParams>,
) -> Result<Response, AppError> {
    let format = params.format.as_deref().unwrap_or("csv");

    // Fetch ALL findings matching filters (no pagination)
    let findings = crate::services::finding::list_all_for_export(&state.db, &params.filters).await?;

    match format {
        "json" => {
            let json_bytes = serde_json::to_vec_pretty(&findings)
                .map_err(|_| AppError::Internal("JSON serialization failed".into()))?;
            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .header("Content-Disposition", "attachment; filename=\"findings_export.json\"")
                .body(Body::from(json_bytes))
                .unwrap())
        }
        _ => {
            // CSV: write header + rows using csv crate
            let mut wtr = csv::Writer::from_writer(Vec::new());
            // Write CSV header and rows based on category
            for finding in &findings {
                wtr.serialize(finding)?;
            }
            let csv_bytes = wtr.into_inner().map_err(|_| AppError::Internal("CSV write failed".into()))?;
            Ok(Response::builder()
                .header("Content-Type", "text/csv")
                .header("Content-Disposition", "attachment; filename=\"findings_export.csv\"")
                .body(Body::from(csv_bytes))
                .unwrap())
        }
    }
}
```

**Step 2: Add `list_all_for_export` to finding service**

In `backend/src/services/finding.rs`, add a function that reuses the same WHERE clause builder as `list_with_category` but omits `LIMIT`/`OFFSET`:
```rust
pub async fn list_all_for_export(
    pool: &PgPool,
    filters: &FindingFilters,
) -> Result<Vec<FindingSummaryWithCategory>, sqlx::Error> {
    // Same query as list_with_category but without pagination
    // Returns all matching rows
}
```

**Step 3: Mount the route**

In `backend/src/main.rs`, add the export route alongside finding routes:
```rust
.route("/findings/export", get(routes::export::export_findings))
```

Make sure this route is placed **before** the `/findings/{id}` route to avoid path conflicts.

**Step 4: Verify**

```bash
cd backend && cargo test
cd backend && cargo clippy
```

Test:
```bash
curl -k "https://localhost:3000/api/v1/findings/export?format=csv&category=SAST" \
  -H "Authorization: Bearer $TOKEN" -o findings.csv
curl -k "https://localhost:3000/api/v1/findings/export?format=json" \
  -H "Authorization: Bearer $TOKEN" -o findings.json
```

**Commit:** `feat: add findings export endpoint with CSV and JSON support`

---

## Block 2: Frontend — Graph Visualization (Tasks 6–9)

---

### Task 6: Install React Flow, dagre, Recharts, and new shadcn components

**Files:**
- Modify: `frontend/package.json`
- Create: `frontend/src/components/ui/tooltip.tsx` (via shadcn)
- Create: `frontend/src/components/ui/popover.tsx` (via shadcn)
- Create: `frontend/src/components/ui/slider.tsx` (via shadcn)
- Create: `frontend/src/components/ui/checkbox.tsx` (via shadcn)

**Step 1: Install npm packages**

```bash
cd frontend
npm install @xyflow/react @dagrejs/dagre recharts
npm install -D @types/dagre
```

**Step 2: Install shadcn components**

```bash
cd frontend
npx shadcn@latest add tooltip popover slider checkbox
```

If `shadcn` CLI is not configured, manually create the components following the shadcn/ui patterns already in `src/components/ui/`.

**Step 3: Add React Flow CSS import**

In `frontend/src/index.css`, add at the top (after tailwind import):
```css
@import '@xyflow/react/dist/style.css';
```

**Step 4: Verify**

```bash
cd frontend && npx tsc --noEmit
cd frontend && npm run dev
# Confirm no errors in console
```

**Commit:** `chore: install React Flow, dagre, Recharts and new shadcn components`

---

### Task 7: Build graph data transformation and custom components

**Files:**
- Create: `frontend/src/components/attack-chains/graph/transform.ts`
- Create: `frontend/src/components/attack-chains/graph/FindingNode.tsx`
- Create: `frontend/src/components/attack-chains/graph/CorrelationEdge.tsx`
- Create: `frontend/src/components/attack-chains/graph/layout.ts`

**Context:** Transform `AppAttackChainDetail` API response into React Flow nodes and edges. Each `ChainFinding` becomes a node, each `ChainRelationship` becomes an edge. Uncorrelated findings become standalone nodes in a separate cluster.

**Step 1: Create data transformation (`transform.ts`)**

```typescript
import type { Node, Edge } from '@xyflow/react'
import type { AppAttackChainDetail, AttackChain, ChainFinding, ChainRelationship } from '@/types/attack-chains'

export interface FindingNodeData {
  finding: ChainFinding
  isUncorrelated: boolean
}

const CATEGORY_COLORS = {
  SAST: { bg: '#3b82f6', border: '#2563eb' },  // blue
  SCA:  { bg: '#8b5cf6', border: '#7c3aed' },  // purple
  DAST: { bg: '#14b8a6', border: '#0d9488' },  // teal
}

const SEVERITY_SIZES = {
  Critical: { width: 220, height: 80 },
  High:     { width: 200, height: 72 },
  Medium:   { width: 180, height: 64 },
  Low:      { width: 160, height: 56 },
  Info:     { width: 140, height: 48 },
}

export function transformToGraph(
  detail: AppAttackChainDetail,
  filters: { minRiskScore: number; categories: Set<string> }
): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = []
  const edges: Edge[] = []

  // Process correlated chains
  for (const chain of detail.chains) {
    for (const finding of chain.findings) {
      if (!filters.categories.has(finding.finding_category)) continue
      const size = SEVERITY_SIZES[finding.normalized_severity as keyof typeof SEVERITY_SIZES] ?? SEVERITY_SIZES.Medium
      nodes.push({
        id: finding.id,
        type: 'finding',
        data: { finding, isUncorrelated: false } satisfies FindingNodeData,
        position: { x: 0, y: 0 }, // dagre will set this
        style: { width: size.width, height: size.height },
      })
    }
    for (const rel of chain.relationships) {
      edges.push({
        id: rel.id,
        source: rel.source_finding_id,
        target: rel.target_finding_id,
        type: 'correlation',
        data: {
          confidence: rel.confidence_score,
          ruleName: rel.rule_name,
          relationshipType: rel.relationship_type,
        },
      })
    }
  }

  // Process uncorrelated findings
  for (const finding of detail.uncorrelated_findings) {
    if (!filters.categories.has(finding.finding_category)) continue
    nodes.push({
      id: finding.id,
      type: 'finding',
      data: { finding: { ...finding, status: finding.status }, isUncorrelated: true } satisfies FindingNodeData,
      position: { x: 0, y: 0 },
      style: { width: 160, height: 56 },
    })
  }

  return { nodes, edges }
}
```

**Step 2: Create dagre layout utility (`layout.ts`)**

```typescript
import dagre from '@dagrejs/dagre'
import type { Node, Edge } from '@xyflow/react'

export type LayoutDirection = 'LR' | 'TB'

export function applyDagreLayout(
  nodes: Node[],
  edges: Edge[],
  direction: LayoutDirection = 'LR'
): Node[] {
  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: direction, nodesep: 50, ranksep: 80 })

  for (const node of nodes) {
    const w = (node.style?.width as number) ?? 180
    const h = (node.style?.height as number) ?? 64
    g.setNode(node.id, { width: w, height: h })
  }
  for (const edge of edges) {
    g.setEdge(edge.source, edge.target)
  }

  dagre.layout(g)

  return nodes.map((node) => {
    const pos = g.node(node.id)
    return { ...node, position: { x: pos.x - (pos.width / 2), y: pos.y - (pos.height / 2) } }
  })
}
```

**Step 3: Create custom node component (`FindingNode.tsx`)**

A React Flow custom node that displays:
- Category color (left border accent)
- Finding title (truncated to ~40 chars)
- Severity badge
- Source tool label

Use `Handle` components from `@xyflow/react` for edge connection points.

**Step 4: Create custom edge component (`CorrelationEdge.tsx`)**

- Solid stroke for confidence >= 0.8
- Dashed stroke for confidence >= 0.5
- Dotted stroke for confidence < 0.5
- Show rule name on hover via Tooltip

**Step 5: Verify**

```bash
cd frontend && npx tsc --noEmit
```

**Commit:** `feat: add graph data transformation, layout, and custom node/edge components`

---

### Task 8: Integrate graph view into AttackChainDetailPage

**Files:**
- Create: `frontend/src/components/attack-chains/graph/AttackChainGraph.tsx`
- Modify: `frontend/src/pages/AttackChainDetailPage.tsx`
- Modify: `frontend/public/locales/en/translation.json`
- Modify: `frontend/public/locales/it/translation.json`

**Context:** Current `AttackChainDetailPage` shows a flat card list. Add a toggle between **Cards** and **Graph** view modes. The graph view uses React Flow with the components from Task 7.

**Step 1: Create `AttackChainGraph.tsx`**

Main graph container component:
```typescript
import { ReactFlow, Background, Controls, MiniMap, ReactFlowProvider } from '@xyflow/react'
import { FindingNode } from './FindingNode'
import { CorrelationEdge } from './CorrelationEdge'
import { transformToGraph } from './transform'
import { applyDagreLayout } from './layout'

const nodeTypes = { finding: FindingNode }
const edgeTypes = { correlation: CorrelationEdge }

interface AttackChainGraphProps {
  detail: AppAttackChainDetail
  onNodeClick: (findingId: string) => void
}

export function AttackChainGraph({ detail, onNodeClick }: AttackChainGraphProps) {
  const [layout, setLayout] = useState<'LR' | 'TB'>('LR')
  const [minRiskScore, setMinRiskScore] = useState(0)
  const [categories, setCategories] = useState(new Set(['SAST', 'SCA', 'DAST']))

  const { nodes: rawNodes, edges } = useMemo(
    () => transformToGraph(detail, { minRiskScore, categories }),
    [detail, minRiskScore, categories]
  )
  const nodes = useMemo(() => applyDagreLayout(rawNodes, edges, layout), [rawNodes, edges, layout])

  return (
    <ReactFlowProvider>
      {/* Controls panel: slider, category checkboxes, layout toggle */}
      <GraphControlsPanel
        minRiskScore={minRiskScore}
        onRiskScoreChange={setMinRiskScore}
        categories={categories}
        onCategoriesChange={setCategories}
        layout={layout}
        onLayoutChange={setLayout}
      />
      <div style={{ height: '600px' }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onNodeClick={(_, node) => onNodeClick(node.id)}
          fitView
        >
          <Background />
          <Controls />
          <MiniMap />
        </ReactFlow>
      </div>
    </ReactFlowProvider>
  )
}
```

**Step 2: Add Cards/Graph toggle to `AttackChainDetailPage`**

Add a view mode state (`'cards' | 'graph'`) and a toggle group in the page header. When `graph` is selected, render `<AttackChainGraph>` instead of the existing card list.

**Step 3: Add node click → Sheet panel**

When a node is clicked, open a `<Sheet>` slide-out panel showing the finding's full details (title, severity, category, status, description) with a link to `/findings/:id`.

**Step 4: Add i18n keys**

Add to both EN and IT translation files:
```json
"attackChains": {
  "viewCards": "Cards",
  "viewGraph": "Graph",
  "graphControls": {
    "riskThreshold": "Min Risk Score",
    "categories": "Categories",
    "layout": "Layout",
    "hierarchical": "Hierarchical",
    "forceDirected": "Force-directed"
  }
}
```

**Step 5: Verify**

```bash
cd frontend && npx tsc --noEmit
cd frontend && npm run dev
# Navigate to /attack-chains/:appId, toggle to Graph view
# Verify nodes render with correct colors, edges connect findings
```

**Commit:** `feat: add interactive attack chain graph view with React Flow`

---

### Task 9: Add graph controls and polish interactions

**Files:**
- Create: `frontend/src/components/attack-chains/graph/GraphControlsPanel.tsx`
- Modify: `frontend/src/components/attack-chains/graph/AttackChainGraph.tsx`
- Modify: `frontend/src/components/attack-chains/graph/FindingNode.tsx`

**Context:** Add the controls panel (risk score slider, category checkboxes, layout toggle) and polish interactions (edge hover tooltips, keyboard navigation).

**Step 1: Build `GraphControlsPanel`**

A horizontal panel above the graph with:
- **Risk score slider** (0–100) using shadcn `<Slider>`
- **Category checkboxes** (SAST/SCA/DAST) using shadcn `<Checkbox>`, colored to match category
- **Layout toggle** (Hierarchical / Force-directed) using two `<Button>` variants

**Step 2: Add edge hover tooltip**

On the custom `CorrelationEdge`, show a tooltip on hover with:
- Rule name
- Confidence score (as percentage)
- Relationship type

Use shadcn `<Tooltip>` wrapping the edge label.

**Step 3: Add keyboard navigation**

Add `onKeyDown` handler to the ReactFlow container:
- Arrow keys to move between nodes (focus next/prev in tab order)
- Enter to open the finding sheet panel
- Escape to close the sheet panel

**Step 4: Force-directed layout**

When layout is toggled to force-directed, use React Flow's built-in force simulation or apply a simple force-directed positioning algorithm. If complex, keep dagre as only layout for now and mark force-directed as future enhancement.

**Step 5: Verify**

```bash
cd frontend && npx tsc --noEmit
# Manual testing: adjust slider, toggle categories, verify graph updates
```

**Commit:** `feat: add graph controls panel with risk slider, category filters, and layout toggle`

---

## Block 3: Frontend — Category Tables & Export (Tasks 10–15)

---

### Task 10: Build reusable inline column filter components

**Files:**
- Create: `frontend/src/components/findings/filters/TextColumnFilter.tsx`
- Create: `frontend/src/components/findings/filters/SelectColumnFilter.tsx`
- Create: `frontend/src/components/findings/filters/DateRangeColumnFilter.tsx`
- Create: `frontend/src/components/findings/filters/index.ts`

**Context:** TanStack Table supports inline column filters rendered in the header row. We need three reusable filter widgets that sit beneath column headers: text input, dropdown select, and date range picker. These use server-side filtering (`manualFiltering: true`) — filter values are collected and sent as API query params.

**Step 1: Create `TextColumnFilter`**

A small `<Input>` component (compact size) that debounces input (300ms) and calls `column.setFilterValue(value)`:
```typescript
interface TextColumnFilterProps {
  column: Column<any, unknown>
  placeholder?: string
}
```

**Step 2: Create `SelectColumnFilter`**

A compact `<Select>` dropdown with options passed as props. Includes an "All" option that clears the filter:
```typescript
interface SelectColumnFilterProps {
  column: Column<any, unknown>
  options: { label: string; value: string }[]
}
```

**Step 3: Create `DateRangeColumnFilter`**

Two date inputs (from/to) using native `<input type="date">` (simple, no heavy calendar dependency needed). Sets filter value as `{ from: string, to: string }`:
```typescript
interface DateRangeColumnFilterProps {
  column: Column<any, unknown>
}
```

**Step 4: Export all from index**

```typescript
export { TextColumnFilter } from './TextColumnFilter'
export { SelectColumnFilter } from './SelectColumnFilter'
export { DateRangeColumnFilter } from './DateRangeColumnFilter'
```

**Step 5: Verify**

```bash
cd frontend && npx tsc --noEmit
```

**Commit:** `feat: add reusable inline column filter components for TanStack Table`

---

### Task 11: SAST category table with column filters

**Files:**
- Create: `frontend/src/components/findings/SastTable.tsx`
- Modify: `frontend/src/pages/FindingsPage.tsx`
- Modify: `frontend/src/api/findings.ts`

**Context:** Replace the inline SAST table in `FindingsPage.tsx` with a proper TanStack Table using all SAST-specific columns from the design doc and inline column filters. Server-side filtering: filter values are sent as query params to the API.

**Step 1: Create `SastTable.tsx`**

Full TanStack Table component with columns defined per the design doc:

| Column | accessor | Filter |
|--------|----------|--------|
| App Code | `category_data.project` (mapped) | TextColumnFilter |
| Project | `category_data.project` | TextColumnFilter |
| Rule Key | `category_data.rule_id` | TextColumnFilter |
| Rule Name | `category_data.rule_name` (from detail or raw) | TextColumnFilter |
| Issue ID | `source_finding_id` | TextColumnFilter |
| Severity | `normalized_severity` | SelectColumnFilter (Critical/High/Medium/Low/Info) |
| Issue Type | `category_data.issue_type` | SelectColumnFilter (Vulnerability/Security Hotspot) |
| Component | `category_data.file_path` | TextColumnFilter |
| Branch | `category_data.branch` | SelectColumnFilter (populated from data) |

Configure TanStack Table with:
```typescript
const table = useReactTable({
  data: findings,
  columns,
  state: { columnFilters, sorting },
  onColumnFiltersChange: setColumnFilters,
  onSortingChange: setSortingState,
  manualFiltering: true,  // server-side
  manualSorting: true,
  getCoreRowModel: getCoreRowModel(),
})
```

Render filter widgets in the header row beneath each column header using `header.column.getCanFilter()` check.

**Step 2: Wire up filter state to API calls**

In `FindingsPage.tsx`, when `columnFilters` change on the SAST table, extract filter values and pass them as additional params to the `listFindingsWithCategory()` API call:
```typescript
const sastFilterParams = useMemo(() => {
  const params: Record<string, string> = {}
  for (const filter of columnFilters) {
    if (filter.id === 'branch') params.branch = filter.value as string
    if (filter.id === 'rule_id') params.rule_id = filter.value as string
    // ... etc
  }
  return params
}, [columnFilters])
```

**Step 3: Update API client**

In `frontend/src/api/findings.ts`, extend `listFindingsWithCategory` to accept additional filter params:
```typescript
export function listFindingsWithCategory(
  filters: FindingListFilters = {},
  page = 1,
  perPage = 25,
  categoryFilters: Record<string, string> = {}
): Promise<PagedResult<FindingSummaryWithCategory>> {
  const params: Record<string, string> = { ... }
  // Merge categoryFilters into params
  Object.assign(params, categoryFilters)
  return apiGet<PagedResult<FindingSummaryWithCategory>>('/findings', params)
}
```

**Step 4: Verify**

```bash
cd frontend && npx tsc --noEmit
# Manual: navigate to Findings > SAST tab, verify columns render, filters work
```

**Commit:** `feat: add SAST category table with inline column filters`

---

### Task 12: SCA category table with column filters

**Files:**
- Create: `frontend/src/components/findings/ScaTable.tsx`
- Modify: `frontend/src/pages/FindingsPage.tsx`

**Context:** Same pattern as Task 11, but for SCA-specific columns per the design doc.

**Columns:**

| Column | accessor | Filter |
|--------|----------|--------|
| CVE | `cve_ids` | TextColumnFilter |
| Summary | `title` | TextColumnFilter |
| Severity | `normalized_severity` | SelectColumnFilter |
| Vulnerable Component | `category_data.package_name + package_version` | TextColumnFilter |
| Physical Path | `category_data.affected_artifact` | TextColumnFilter |
| Impacted Artifact | `category_data.build_project` | TextColumnFilter |
| Dependency Path | `category_data.dependency_path` | TextColumnFilter |
| Published | `first_seen_at` | DateRangeColumnFilter |
| Scan Time | `created_at` | DateRangeColumnFilter |
| Issue ID | `source_finding_id` | TextColumnFilter |
| Package Type | `category_data.package_type` | SelectColumnFilter (maven/npm/pypi) |
| Has Fix | `category_data.fixed_version IS NOT NULL` | SelectColumnFilter (Yes/No) |

Wire filter state to API params: `package_type`, `package_name`, `has_fix`, `published_from`, `published_to`.

**Verify:**
```bash
cd frontend && npx tsc --noEmit
```

**Commit:** `feat: add SCA category table with inline column filters`

---

### Task 13: DAST category table with column filters

**Files:**
- Create: `frontend/src/components/findings/DastTable.tsx`
- Modify: `frontend/src/pages/FindingsPage.tsx`

**Context:** Same pattern as Tasks 11-12, for DAST-specific columns.

**Columns:**

| Column | accessor | Filter |
|--------|----------|--------|
| Plugin | `source_finding_id` | TextColumnFilter |
| Severity | `normalized_severity` | SelectColumnFilter |
| IP Address | derived from `category_data.target_url` | TextColumnFilter |
| URL | `category_data.target_url` | TextColumnFilter |
| Port | derived from `category_data.target_url` | TextColumnFilter |
| Exploitable | derived from `category_data.attack_vector` | SelectColumnFilter (Yes/No) |
| DNS Name | `category_data.web_application_name` | TextColumnFilter |
| First Discovered | `first_seen_at` | DateRangeColumnFilter |
| Last Observed | `last_seen_at` | DateRangeColumnFilter |
| Risk Factor | `normalized_severity` | SelectColumnFilter |

Wire filter state to API params: `target_url`, `exploitable`, `dns_name`, `discovered_from`, `discovered_to`.

**Verify:**
```bash
cd frontend && npx tsc --noEmit
```

**Commit:** `feat: add DAST category table with inline column filters`

---

### Task 14: Improve "All" tab with inline filters and global search

**Files:**
- Modify: `frontend/src/components/findings/FindingList.tsx`
- Modify: `frontend/src/components/findings/FindingFilters.tsx`
- Modify: `frontend/src/pages/FindingsPage.tsx`

**Context:** The "All" tab currently uses `FindingList` (TanStack Table) with a separate filter bar above. Migrate to inline column-header filters (same pattern as category tables) while keeping the global text search bar above the table. Remove the old `FindingFilters` component — its functionality is absorbed by inline filters + search bar.

**Step 1:** Add inline filters to `FindingList` columns: text on Title, dropdowns on Severity/Status/Category/Source.

**Step 2:** Keep global search `<Input>` above the table, wired to the `search` API param.

**Step 3:** Remove or simplify `FindingFilters.tsx` — may still be used as a search-only bar.

**Verify:**
```bash
cd frontend && npx tsc --noEmit
```

**Commit:** `feat: add inline column filters to All findings tab`

---

### Task 15: Export dropdown with CSV/JSON download

**Files:**
- Create: `frontend/src/components/findings/ExportButton.tsx`
- Modify: `frontend/src/api/findings.ts`
- Modify: `frontend/src/pages/FindingsPage.tsx`

**Context:** Add an "Export" dropdown button in the Findings page header that downloads all findings matching current filters in CSV or JSON format.

**Step 1: Add export API function**

In `frontend/src/api/findings.ts`:
```typescript
export async function exportFindings(
  filters: Record<string, string>,
  format: 'csv' | 'json'
): Promise<Blob> {
  const params = new URLSearchParams({ ...filters, format })
  const token = authStore.getAccessToken()
  const response = await fetch(`/api/v1/findings/export?${params}`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!response.ok) throw new Error('Export failed')
  return response.blob()
}
```

**Step 2: Create `ExportButton.tsx`**

A `<DropdownMenu>` with two items: "Export CSV" and "Export JSON". On click:
1. Call `exportFindings()` with current filters + format
2. Create a blob URL and trigger download via hidden `<a>` element

```typescript
function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
```

**Step 3: Add to FindingsPage header**

Place `<ExportButton>` next to the findings count, passing current filter state and active category tab.

**Step 4: Add i18n keys**

```json
"findings": {
  "export": "Export",
  "exportCsv": "Export CSV",
  "exportJson": "Export JSON"
}
```

**Verify:**
```bash
cd frontend && npx tsc --noEmit
# Manual: click Export > CSV, verify file downloads with correct content
```

**Commit:** `feat: add findings export with CSV and JSON format options`

---

## Block 4: Dashboard Charts (Task 16)

---

### Task 16: Add Recharts dashboard widgets

**Files:**
- Create: `frontend/src/components/dashboard/SeverityChart.tsx`
- Create: `frontend/src/components/dashboard/SourceToolChart.tsx`
- Create: `frontend/src/components/dashboard/TopAppsChart.tsx`
- Create: `frontend/src/components/dashboard/SlaChart.tsx`
- Modify: `frontend/src/pages/DashboardPage.tsx`

**Context:** Add four Recharts widgets to the dashboard below the existing stat cards. Data sources are the dashboard stats API (already extended in Task 3 with `findings_by_source`).

**Step 1: Severity distribution donut chart (`SeverityChart.tsx`)**

```typescript
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts'

const SEVERITY_COLORS = {
  Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#3b82f6', Info: '#6b7280'
}

export function SeverityChart({ counts }: { counts: SeverityCounts }) {
  const data = Object.entries(counts)
    .filter(([_, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  return (
    <ResponsiveContainer width="100%" height={300}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={60} outerRadius={100}>
          {data.map((entry) => (
            <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name as keyof typeof SEVERITY_COLORS]} />
          ))}
        </Pie>
        <Tooltip /><Legend />
      </PieChart>
    </ResponsiveContainer>
  )
}
```

**Step 2: Findings by source tool bar chart (`SourceToolChart.tsx`)**

Vertical bar chart using `<BarChart>` from Recharts. Data from `findings_by_source`.

**Step 3: Top 5 riskiest apps horizontal bar chart (`TopAppsChart.tsx`)**

Horizontal `<BarChart>` with `layout="vertical"`. Data from `top_risky_apps`.

**Step 4: SLA compliance radial chart (`SlaChart.tsx`)**

`<RadialBarChart>` showing on_track / at_risk / breached as concentric arcs with color coding (green/yellow/red).

**Step 5: Integrate into `DashboardPage.tsx`**

Add a new row below existing cards:
```typescript
<div className="grid gap-6 md:grid-cols-2">
  <Card><CardHeader><CardTitle>Severity Distribution</CardTitle></CardHeader>
    <CardContent><SeverityChart counts={stats.severity_counts} /></CardContent>
  </Card>
  <Card><CardHeader><CardTitle>Findings by Source</CardTitle></CardHeader>
    <CardContent><SourceToolChart data={stats.findings_by_source} /></CardContent>
  </Card>
  <Card><CardHeader><CardTitle>Riskiest Applications</CardTitle></CardHeader>
    <CardContent><TopAppsChart apps={stats.top_risky_apps} /></CardContent>
  </Card>
  <Card><CardHeader><CardTitle>SLA Compliance</CardTitle></CardHeader>
    <CardContent><SlaChart summary={stats.sla_summary} /></CardContent>
  </Card>
</div>
```

**Step 6: Add i18n keys for chart titles**

**Verify:**
```bash
cd frontend && npx tsc --noEmit
# Manual: verify charts render with seed data on dashboard
```

**Commit:** `feat: add Recharts dashboard widgets for severity, source, apps, and SLA`

---

## Block 5: UI Redesign (Tasks 17–23)

> **Important:** For all UI redesign tasks, the implementer should invoke the
> `frontend-design` plugin to generate distinctive, production-grade component code.
> Reference inspirations: GitNexus (modern dev tool aesthetic) and Sirius (clean
> enterprise dashboard). The goal is top-class visual quality, not generic AI aesthetics.

---

### Task 17: Design system foundation

**Files:**
- Modify: `frontend/src/index.css`
- Create: `frontend/src/lib/colors.ts` (optional: semantic color constants for JS)

**Context:** TailwindCSS v4 config lives entirely in `src/index.css` via CSS custom properties and `@theme inline`. Current palette is default shadcn/ui gray. Need custom semantic colors with category colors (SAST blue, SCA purple, DAST teal) and severity colors.

**Step 1: Define new color palette**

Replace the default oklch values in `:root` and `.dark` with a custom palette. Define:

```css
:root {
  /* Category colors */
  --color-sast: oklch(0.59 0.2 255);        /* blue */
  --color-sca: oklch(0.55 0.25 290);        /* purple */
  --color-dast: oklch(0.65 0.17 175);       /* teal */

  /* Severity colors */
  --color-severity-critical: oklch(0.55 0.25 25);  /* deep red */
  --color-severity-high: oklch(0.65 0.2 45);       /* orange */
  --color-severity-medium: oklch(0.75 0.15 85);    /* yellow */
  --color-severity-low: oklch(0.6 0.15 250);       /* blue */
  --color-severity-info: oklch(0.6 0 0);            /* gray */

  /* Override primary, accent, etc. with non-gray brand colors */
  /* ... invoke frontend-design for the full palette */
}
```

**Step 2: Typography**

Add Inter font import and set as default:
```css
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
```

Update `--font-sans` in the theme to use Inter. Define a tighter heading scale.

**Step 3: Spacing**

Establish 8px grid: ensure all spacing utilities align to multiples of 8px (Tailwind's default `space-2` = 8px already works).

**Step 4: Depth and surfaces**

Define card shadow variables, border radius consistency, and hover elevation transitions:
```css
:root {
  --shadow-card: 0 1px 3px 0 rgb(0 0 0 / 0.06), 0 1px 2px -1px rgb(0 0 0 / 0.06);
  --shadow-card-hover: 0 4px 12px 0 rgb(0 0 0 / 0.08);
}
```

**Verify:**
```bash
cd frontend && npm run dev
# Verify new colors and typography apply across the app
```

**Commit:** `feat: establish design system foundation with custom colors, typography, and spacing`

---

### Task 18: Sidebar and layout redesign

**Files:**
- Modify: `frontend/src/components/layout/Sidebar.tsx`
- Modify: `frontend/src/components/layout/AppLayout.tsx`
- Modify: `frontend/src/components/layout/Header.tsx`

**Context:** Current sidebar is functional but plain. Redesign with:
- Accent bar indicator on active nav item (vertical colored bar on left edge)
- Refined Lucide icons with consistent sizing
- Smooth collapse/expand animation (CSS transition on width)
- Better visual hierarchy between primary and secondary nav sections
- Header: subtle bottom border, refined user menu

Invoke `frontend-design` plugin for the sidebar component to get a polished implementation.

**Verify:**
```bash
cd frontend && npx tsc --noEmit
# Manual: verify sidebar animation, active indicators, collapsed state
```

**Commit:** `feat: redesign sidebar with accent indicators and smooth animations`

---

### Task 19: Data tables and pagination global restyling

**Files:**
- Modify: `frontend/src/components/ui/table.tsx`
- Create: `frontend/src/components/ui/pagination.tsx` (or inline in pages)

**Context:** Restyle all data tables with:
- Row hover states (subtle background tint)
- Subtle alternating row tints (even/odd)
- Sticky headers (CSS `position: sticky`)
- Refined header typography (uppercase, smaller, muted color)
- Better pagination controls (page numbers, not just prev/next)

These changes apply globally since all tables use the shadcn `<Table>` primitive.

**Verify:**
```bash
cd frontend && npx tsc --noEmit
# Manual: verify tables across Findings, Applications, Attack Chains pages
```

**Commit:** `feat: restyle data tables with hover states, sticky headers, and improved pagination`

---

### Task 20: Cards, badges, buttons, and page headers restyling

**Files:**
- Modify: `frontend/src/components/ui/card.tsx`
- Modify: `frontend/src/components/ui/badge.tsx`
- Modify: `frontend/src/components/ui/button.tsx`
- Modify: `frontend/src/components/findings/SeverityBadge.tsx`
- Modify: `frontend/src/components/findings/FindingStatusBadge.tsx`

**Context:** Restyle core components:
- **Cards:** Subtle hover elevation transitions, consistent border radius, refined padding
- **Badges:** Distinctive per-category color system (SAST blue, SCA purple, DAST teal), severity-specific colors
- **Buttons:** Refined primary/secondary/ghost variants with consistent sizing and transitions
- **Page headers:** Consistent pattern across all pages: title + subtitle on left, action buttons on right

Create a reusable `<PageHeader>` component:
```typescript
interface PageHeaderProps {
  title: string
  subtitle?: string
  children?: React.ReactNode  // right-aligned actions
}
```

**Commit:** `feat: restyle cards, badges, buttons, and add PageHeader component`

---

### Task 21: Login and Dashboard pages redesign

**Files:**
- Modify: `frontend/src/pages/LoginPage.tsx`
- Modify: `frontend/src/pages/DashboardPage.tsx`

**Context:** Apply the new design system to Login and Dashboard pages.

- **Login:** Centered card with branding, subtle background pattern or gradient, refined form styling. Invoke `frontend-design` for a distinctive login page.
- **Dashboard:** Reorganize stat cards and chart widgets into a cohesive grid layout. Add consistent card styling, proper spacing, and ensure the four Recharts widgets from Task 16 integrate visually.

**Commit:** `feat: redesign Login and Dashboard pages`

---

### Task 22: Findings and Finding Detail pages redesign

**Files:**
- Modify: `frontend/src/pages/FindingsPage.tsx`
- Modify: `frontend/src/pages/FindingDetailPage.tsx`

**Context:**
- **Findings:** Restyle tab navigation, table layout, filter components, export button placement. Ensure category tabs have distinctive color accents matching category colors.
- **Finding Detail:** Restyle the detail layout — finding header (title + severity + status), tabbed sections (details, comments, history, raw data), transition dialog. Apply consistent card/section styling.

**Commit:** `feat: redesign Findings and Finding Detail pages`

---

### Task 23: Remaining pages redesign

**Files:**
- Modify: `frontend/src/pages/ApplicationsPage.tsx`
- Modify: `frontend/src/pages/ApplicationDetailPage.tsx`
- Modify: `frontend/src/pages/AttackChainsPage.tsx`
- Modify: `frontend/src/pages/AttackChainDetailPage.tsx`
- Modify: `frontend/src/pages/IngestionPage.tsx`
- Modify: `frontend/src/pages/TriageQueuePage.tsx`
- Modify: `frontend/src/pages/UnmappedAppsPage.tsx`
- Modify: `frontend/src/pages/DeduplicationPage.tsx`
- Modify: `frontend/src/pages/CorrelationPage.tsx`

**Context:** Apply design system to all remaining 9 pages. By this point, the design system foundation (Task 17), component restyling (Tasks 18-20), and core pages (Tasks 21-22) establish the visual language. These pages should follow the same patterns:

- Use `<PageHeader>` for consistent header layout
- Apply table restyling (already done globally)
- Ensure cards, badges, buttons use the new variants
- Fix any hardcoded strings → i18n

Group the work by visual similarity:
1. **Table-centric pages** (Applications, Attack Chains List, Triage, Unmapped, Dedup): Apply consistent table headers, row actions, and filter layouts
2. **Detail pages** (Application Detail, Attack Chain Detail): Apply consistent section cards, metadata grids, and action button placement
3. **Form-centric pages** (Ingestion, Correlation): Restyle forms, file upload area, rule management cards

**Commit:** `feat: redesign remaining pages (applications, attack chains, ingestion, triage, unmapped, dedup, correlation)`

---

## Block 6: Accessibility (Task 24)

---

### Task 24: WCAG AA accessibility pass

**Files:**
- Multiple files across `frontend/src/`

**Context:** Ensure WCAG 2.1 Level AA compliance across the entire application.

**Step 1: Color contrast audit**

Use browser dev tools (Firefox Accessibility Inspector) or `axe-core` to verify:
- All text meets 4.5:1 contrast ratio (normal text) or 3:1 (large text)
- Both light and dark themes pass
- Category colors (blue/purple/teal) have sufficient contrast against backgrounds

Fix any failing contrasts by adjusting the design system CSS variables from Task 17.

**Step 2: Focus indicators**

Ensure all interactive elements have visible focus indicators:
- Add `focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2` to buttons, links, inputs
- Verify focus is visible in both themes
- Test tab navigation through all pages

**Step 3: Aria labels**

Add `aria-label` or `aria-labelledby` to:
- Icon-only buttons (sidebar collapse, theme toggle, etc.)
- Custom controls (graph slider, category checkboxes)
- Data table sort buttons
- Navigation landmarks (`<nav>`, `<main>`, `<aside>`)

**Step 4: Keyboard navigation for graph**

Ensure the React Flow graph is keyboard accessible:
- Arrow keys traverse between nodes
- Enter/Space opens the finding detail panel
- Tab moves focus between graph controls
- Escape closes the detail panel

**Step 5: Screen reader testing**

Navigate key flows with a screen reader (Firefox + NVDA or similar):
- Login → Dashboard → Findings → Finding Detail
- Attack Chains → Graph view

**Verify:**
```bash
# Run axe-core audit (if available)
npx axe-linter src/
# Or manual Firefox Accessibility Inspector audit
```

**Commit:** `feat: add WCAG AA accessibility support across all pages`

---

## Summary

| Block | Tasks | Focus |
|-------|-------|-------|
| 1. Backend Foundation | 1–5 | Seed data, API edges, filters, export |
| 2. Graph Visualization | 6–9 | React Flow, dagre layout, controls |
| 3. Category Tables & Export | 10–15 | TanStack column filters, CSV/JSON export |
| 4. Dashboard Charts | 16 | Recharts widgets |
| 5. UI Redesign | 17–23 | Design system, all 13 pages |
| 6. Accessibility | 24 | WCAG AA compliance |

**Total: 24 tasks**
