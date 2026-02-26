//! Attack chain analysis service.
//!
//! Provides per-application correlation group summaries showing
//! cross-tool finding relationships, severity breakdowns, and
//! tool coverage for security posture assessment.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::pagination::{PagedResult, Pagination};

/// Application-level attack chain summary.
#[derive(Debug, Serialize)]
pub struct AppAttackChainSummary {
    pub application_id: Uuid,
    pub app_name: String,
    pub app_code: String,
    pub correlation_group_count: i64,
    pub total_findings: i64,
    pub correlated_findings: i64,
    pub uncorrelated_findings: i64,
    pub tool_coverage: Vec<String>,
    pub severity_breakdown: SeverityBreakdown,
    pub risk_score: Option<f64>,
}

/// Severity count breakdown.
#[derive(Debug, Serialize)]
pub struct SeverityBreakdown {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
}

/// Detailed attack chains for a single application.
#[derive(Debug, Serialize)]
pub struct AppAttackChainDetail {
    pub application_id: Uuid,
    pub app_name: String,
    pub app_code: String,
    pub chains: Vec<AttackChain>,
    pub uncorrelated_findings: Vec<UncorrelatedFinding>,
}

/// A single attack chain (correlation group).
#[derive(Debug, Serialize)]
pub struct AttackChain {
    pub group_id: Uuid,
    pub findings: Vec<ChainFinding>,
    pub relationships: Vec<ChainRelationship>,
    pub tool_coverage: Vec<String>,
    pub max_severity: String,
    pub relationship_count: i64,
}

/// Relationship edge within an attack chain.
#[derive(Debug, Serialize)]
pub struct ChainRelationship {
    pub id: Uuid,
    pub source_finding_id: Uuid,
    pub target_finding_id: Uuid,
    pub relationship_type: String,
    pub confidence: Option<String>,
}

/// Finding within an attack chain.
#[derive(Debug, Serialize)]
pub struct ChainFinding {
    pub id: Uuid,
    pub title: String,
    pub source_tool: String,
    pub finding_category: String,
    pub normalized_severity: String,
    pub status: String,
}

/// Uncorrelated finding summary.
#[derive(Debug, Serialize)]
pub struct UncorrelatedFinding {
    pub id: Uuid,
    pub title: String,
    pub source_tool: String,
    pub finding_category: String,
    pub normalized_severity: String,
    pub status: String,
}

/// Query filters for attack chains.
#[derive(Debug, Deserialize)]
pub struct AttackChainFilters {
    pub branch: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal row types for sqlx queries
// ---------------------------------------------------------------------------

/// Row for application summary with finding counts and severity breakdown.
#[derive(Debug, sqlx::FromRow)]
struct AppSummaryRow {
    application_id: Uuid,
    app_name: String,
    app_code: String,
    total_findings: i64,
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
    info: i64,
    avg_risk_score: Option<f64>,
}

/// Row for tool coverage per application.
#[derive(Debug, sqlx::FromRow)]
struct ToolCoverageRow {
    source_tool: String,
}

/// Row for correlation group count per application.
#[derive(Debug, sqlx::FromRow)]
struct CorrelationCountRow {
    correlated_findings: i64,
    group_count: i64,
}

/// Row for a finding in a chain or uncorrelated.
#[derive(Debug, sqlx::FromRow)]
struct FindingRow {
    id: Uuid,
    title: String,
    source_tool: String,
    finding_category: String,
    normalized_severity: String,
    status: String,
}

/// Row for a relationship edge (union-find grouping).
#[derive(Debug, sqlx::FromRow)]
struct RelationshipEdge {
    source_finding_id: Uuid,
    target_finding_id: Uuid,
}

/// Row for a detailed relationship edge (API response).
#[derive(Debug, sqlx::FromRow)]
struct DetailedRelationshipEdge {
    id: Uuid,
    source_finding_id: Uuid,
    target_finding_id: Uuid,
    relationship_type: String,
    confidence: Option<String>,
}

/// Row for an application lookup.
#[derive(Debug, sqlx::FromRow)]
struct AppRow {
    app_name: String,
    app_code: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// List applications ranked by correlation group count, with summaries.
pub async fn list_summaries(
    pool: &PgPool,
    filters: &AttackChainFilters,
    pagination: &Pagination,
) -> Result<PagedResult<AppAttackChainSummary>, AppError> {
    // Step 1: Count total applications with findings
    let total = if filters.branch.is_some() {
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(DISTINCT f.application_id)
            FROM findings f
            JOIN finding_sast fs ON fs.finding_id = f.id
            WHERE f.application_id IS NOT NULL
              AND fs.branch = $1
            "#,
        )
        .bind(filters.branch.as_deref())
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(DISTINCT application_id)
            FROM findings
            WHERE application_id IS NOT NULL
            "#,
        )
        .fetch_one(pool)
        .await?
    };

    // Step 2: Fetch application summaries with severity breakdown
    let app_rows = if filters.branch.is_some() {
        sqlx::query_as::<_, AppSummaryRow>(
            r#"
            SELECT
                f.application_id,
                a.app_name,
                a.app_code,
                COUNT(f.id) AS total_findings,
                COALESCE(SUM(CASE WHEN f.normalized_severity::text = 'Critical' THEN 1 ELSE 0 END), 0) AS critical,
                COALESCE(SUM(CASE WHEN f.normalized_severity::text = 'High'     THEN 1 ELSE 0 END), 0) AS high,
                COALESCE(SUM(CASE WHEN f.normalized_severity::text = 'Medium'   THEN 1 ELSE 0 END), 0) AS medium,
                COALESCE(SUM(CASE WHEN f.normalized_severity::text = 'Low'      THEN 1 ELSE 0 END), 0) AS low,
                COALESCE(SUM(CASE WHEN f.normalized_severity::text = 'Info'     THEN 1 ELSE 0 END), 0) AS info,
                AVG(f.composite_risk_score::double precision) AS avg_risk_score
            FROM findings f
            JOIN applications a ON a.id = f.application_id
            JOIN finding_sast fs ON fs.finding_id = f.id
            WHERE f.application_id IS NOT NULL
              AND fs.branch = $1
            GROUP BY f.application_id, a.app_name, a.app_code
            ORDER BY COUNT(f.id) DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(filters.branch.as_deref())
        .bind(pagination.limit())
        .bind(pagination.offset())
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, AppSummaryRow>(
            r#"
            SELECT
                f.application_id,
                a.app_name,
                a.app_code,
                COUNT(f.id) AS total_findings,
                COALESCE(SUM(CASE WHEN f.normalized_severity::text = 'Critical' THEN 1 ELSE 0 END), 0) AS critical,
                COALESCE(SUM(CASE WHEN f.normalized_severity::text = 'High'     THEN 1 ELSE 0 END), 0) AS high,
                COALESCE(SUM(CASE WHEN f.normalized_severity::text = 'Medium'   THEN 1 ELSE 0 END), 0) AS medium,
                COALESCE(SUM(CASE WHEN f.normalized_severity::text = 'Low'      THEN 1 ELSE 0 END), 0) AS low,
                COALESCE(SUM(CASE WHEN f.normalized_severity::text = 'Info'     THEN 1 ELSE 0 END), 0) AS info,
                AVG(f.composite_risk_score::double precision) AS avg_risk_score
            FROM findings f
            JOIN applications a ON a.id = f.application_id
            WHERE f.application_id IS NOT NULL
            GROUP BY f.application_id, a.app_name, a.app_code
            ORDER BY COUNT(f.id) DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(pagination.limit())
        .bind(pagination.offset())
        .fetch_all(pool)
        .await?
    };

    // Step 3: For each application, fetch tool coverage and correlation counts
    let mut summaries = Vec::with_capacity(app_rows.len());
    for row in app_rows {
        let tools = sqlx::query_as::<_, ToolCoverageRow>(
            "SELECT DISTINCT source_tool FROM findings WHERE application_id = $1",
        )
        .bind(row.application_id)
        .fetch_all(pool)
        .await?;

        let tool_coverage: Vec<String> = tools.into_iter().map(|t| t.source_tool).collect();

        let corr = sqlx::query_as::<_, CorrelationCountRow>(
            r#"
            SELECT
                COUNT(DISTINCT f.id) AS correlated_findings,
                COUNT(DISTINCT fr.source_finding_id) AS group_count
            FROM findings f
            JOIN finding_relationships fr
              ON (fr.source_finding_id = f.id OR fr.target_finding_id = f.id)
            WHERE f.application_id = $1
              AND fr.relationship_type::text IN ('correlated_with', 'grouped_under')
            "#,
        )
        .bind(row.application_id)
        .fetch_one(pool)
        .await?;

        let uncorrelated = row.total_findings - corr.correlated_findings;

        summaries.push(AppAttackChainSummary {
            application_id: row.application_id,
            app_name: row.app_name,
            app_code: row.app_code,
            correlation_group_count: corr.group_count,
            total_findings: row.total_findings,
            correlated_findings: corr.correlated_findings,
            uncorrelated_findings: uncorrelated.max(0),
            tool_coverage,
            severity_breakdown: SeverityBreakdown {
                critical: row.critical,
                high: row.high,
                medium: row.medium,
                low: row.low,
                info: row.info,
            },
            risk_score: row.avg_risk_score,
        });
    }

    // Re-sort by correlation group count descending, then total findings
    summaries.sort_by(|a, b| {
        b.correlation_group_count
            .cmp(&a.correlation_group_count)
            .then_with(|| b.total_findings.cmp(&a.total_findings))
    });

    Ok(PagedResult::new(summaries, total, pagination))
}

/// Get detailed attack chains for one application.
pub async fn get_by_app(
    pool: &PgPool,
    app_id: Uuid,
    filters: &AttackChainFilters,
) -> Result<AppAttackChainDetail, AppError> {
    // Step 1: Get the application
    let app = sqlx::query_as::<_, AppRow>(
        "SELECT app_name, app_code FROM applications WHERE id = $1",
    )
    .bind(app_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Application {app_id} not found")))?;

    // Step 2: Get all findings for this application (with optional branch filter)
    let all_findings = if let Some(ref branch) = filters.branch {
        sqlx::query_as::<_, FindingRow>(
            r#"
            SELECT
                f.id,
                f.title,
                f.source_tool,
                f.finding_category::text AS finding_category,
                f.normalized_severity::text AS normalized_severity,
                f.status::text AS status
            FROM findings f
            JOIN finding_sast fs ON fs.finding_id = f.id
            WHERE f.application_id = $1
              AND fs.branch = $2
            "#,
        )
        .bind(app_id)
        .bind(branch)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, FindingRow>(
            r#"
            SELECT
                f.id,
                f.title,
                f.source_tool,
                f.finding_category::text AS finding_category,
                f.normalized_severity::text AS normalized_severity,
                f.status::text AS status
            FROM findings f
            WHERE f.application_id = $1
            "#,
        )
        .bind(app_id)
        .fetch_all(pool)
        .await?
    };

    if all_findings.is_empty() {
        return Ok(AppAttackChainDetail {
            application_id: app_id,
            app_name: app.app_name,
            app_code: app.app_code,
            chains: vec![],
            uncorrelated_findings: vec![],
        });
    }

    // Step 3: Get all relationships for findings in this application
    let finding_ids: Vec<Uuid> = all_findings.iter().map(|f| f.id).collect();

    let edges = sqlx::query_as::<_, RelationshipEdge>(
        r#"
        SELECT source_finding_id, target_finding_id
        FROM finding_relationships
        WHERE relationship_type::text IN ('correlated_with', 'grouped_under')
          AND (source_finding_id = ANY($1) OR target_finding_id = ANY($1))
        "#,
    )
    .bind(&finding_ids)
    .fetch_all(pool)
    .await?;

    // Step 3b: Fetch detailed relationship edges for the API response
    let detailed_edges = sqlx::query_as::<_, DetailedRelationshipEdge>(
        r#"
        SELECT fr.id,
               fr.source_finding_id,
               fr.target_finding_id,
               fr.relationship_type::text AS relationship_type,
               fr.confidence::text AS confidence
        FROM finding_relationships fr
        WHERE (fr.source_finding_id = ANY($1) OR fr.target_finding_id = ANY($1))
          AND fr.relationship_type IN ('correlated_with', 'grouped_under')
        "#,
    )
    .bind(&finding_ids)
    .fetch_all(pool)
    .await?;

    // Step 4: Build connected components (chains) via union-find
    let chains = build_chains(&all_findings, &edges);

    // Step 5: Separate into correlated chains and uncorrelated findings
    let mut attack_chains = Vec::new();
    let mut uncorrelated = Vec::new();

    for chain_findings in chains {
        if chain_findings.len() == 1 {
            let f = &chain_findings[0];
            uncorrelated.push(UncorrelatedFinding {
                id: f.id,
                title: f.title.clone(),
                source_tool: f.source_tool.clone(),
                finding_category: f.finding_category.clone(),
                normalized_severity: f.normalized_severity.clone(),
                status: f.status.clone(),
            });
        } else {
            let group_id = chain_findings[0].id;
            let tool_coverage: Vec<String> = chain_findings
                .iter()
                .map(|f| f.source_tool.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            let max_severity = chain_findings
                .iter()
                .map(|f| severity_rank(&f.normalized_severity))
                .max()
                .map(|rank| severity_label(rank).to_string())
                .unwrap_or_else(|| "Info".to_string());

            // Collect relationships belonging to this chain
            let chain_ids: std::collections::HashSet<Uuid> =
                chain_findings.iter().map(|f| f.id).collect();

            let relationships: Vec<ChainRelationship> = detailed_edges
                .iter()
                .filter(|e| {
                    chain_ids.contains(&e.source_finding_id)
                        && chain_ids.contains(&e.target_finding_id)
                })
                .map(|e| ChainRelationship {
                    id: e.id,
                    source_finding_id: e.source_finding_id,
                    target_finding_id: e.target_finding_id,
                    relationship_type: e.relationship_type.clone(),
                    confidence: e.confidence.clone(),
                })
                .collect();

            let relationship_count = relationships.len() as i64;

            let findings: Vec<ChainFinding> = chain_findings
                .iter()
                .map(|f| ChainFinding {
                    id: f.id,
                    title: f.title.clone(),
                    source_tool: f.source_tool.clone(),
                    finding_category: f.finding_category.clone(),
                    normalized_severity: f.normalized_severity.clone(),
                    status: f.status.clone(),
                })
                .collect();

            attack_chains.push(AttackChain {
                group_id,
                findings,
                relationships,
                tool_coverage,
                max_severity,
                relationship_count,
            });
        }
    }

    // Sort chains by max severity then by finding count
    attack_chains.sort_by(|a, b| {
        severity_rank(&b.max_severity)
            .cmp(&severity_rank(&a.max_severity))
            .then_with(|| b.findings.len().cmp(&a.findings.len()))
    });

    Ok(AppAttackChainDetail {
        application_id: app_id,
        app_name: app.app_name,
        app_code: app.app_code,
        chains: attack_chains,
        uncorrelated_findings: uncorrelated,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build connected components from findings and relationship edges.
///
/// Returns groups of findings where each group represents one chain.
fn build_chains<'a>(
    findings: &'a [FindingRow],
    edges: &[RelationshipEdge],
) -> Vec<Vec<&'a FindingRow>> {
    use std::collections::HashMap;

    // Build index: finding_id -> position
    let id_to_idx: HashMap<Uuid, usize> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| (f.id, i))
        .collect();

    // Union-Find
    let n = findings.len();
    let mut parent: Vec<usize> = (0..n).collect();
    let mut rank: Vec<usize> = vec![0; n];

    fn find(parent: &mut [usize], x: usize) -> usize {
        if parent[x] != x {
            parent[x] = find(parent, parent[x]);
        }
        parent[x]
    }

    fn union(parent: &mut [usize], rank: &mut [usize], x: usize, y: usize) {
        let rx = find(parent, x);
        let ry = find(parent, y);
        if rx == ry {
            return;
        }
        if rank[rx] < rank[ry] {
            parent[rx] = ry;
        } else if rank[rx] > rank[ry] {
            parent[ry] = rx;
        } else {
            parent[ry] = rx;
            rank[rx] += 1;
        }
    }

    for edge in edges {
        if let (Some(&ix), Some(&iy)) = (
            id_to_idx.get(&edge.source_finding_id),
            id_to_idx.get(&edge.target_finding_id),
        ) {
            union(&mut parent, &mut rank, ix, iy);
        }
    }

    // Group findings by root
    let mut groups: HashMap<usize, Vec<&FindingRow>> = HashMap::new();
    for (i, finding) in findings.iter().enumerate() {
        let root = find(&mut parent, i);
        groups.entry(root).or_default().push(finding);
    }

    groups.into_values().collect()
}

/// Rank severity for sorting (higher = more severe).
fn severity_rank(severity: &str) -> u8 {
    match severity {
        "Critical" => 5,
        "High" => 4,
        "Medium" => 3,
        "Low" => 2,
        "Info" => 1,
        _ => 0,
    }
}

/// Convert severity rank back to label.
fn severity_label(rank: u8) -> &'static str {
    match rank {
        5 => "Critical",
        4 => "High",
        3 => "Medium",
        2 => "Low",
        1 => "Info",
        _ => "Info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_rank_ordering() {
        assert!(severity_rank("Critical") > severity_rank("High"));
        assert!(severity_rank("High") > severity_rank("Medium"));
        assert!(severity_rank("Medium") > severity_rank("Low"));
        assert!(severity_rank("Low") > severity_rank("Info"));
    }

    #[test]
    fn severity_label_round_trip() {
        for label in &["Critical", "High", "Medium", "Low", "Info"] {
            assert_eq!(severity_label(severity_rank(label)), *label);
        }
    }

    #[test]
    fn build_chains_no_edges() {
        let findings = vec![
            FindingRow {
                id: Uuid::new_v4(),
                title: "F1".to_string(),
                source_tool: "sonarqube".to_string(),
                finding_category: "SAST".to_string(),
                normalized_severity: "High".to_string(),
                status: "New".to_string(),
            },
            FindingRow {
                id: Uuid::new_v4(),
                title: "F2".to_string(),
                source_tool: "jfrog_xray".to_string(),
                finding_category: "SCA".to_string(),
                normalized_severity: "Medium".to_string(),
                status: "New".to_string(),
            },
        ];

        let chains = build_chains(&findings, &[]);
        // Each finding is its own group
        assert_eq!(chains.len(), 2);
        for chain in &chains {
            assert_eq!(chain.len(), 1);
        }
    }

    #[test]
    fn build_chains_with_edges() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();

        let findings = vec![
            FindingRow {
                id: id1,
                title: "F1".to_string(),
                source_tool: "sonarqube".to_string(),
                finding_category: "SAST".to_string(),
                normalized_severity: "High".to_string(),
                status: "New".to_string(),
            },
            FindingRow {
                id: id2,
                title: "F2".to_string(),
                source_tool: "jfrog_xray".to_string(),
                finding_category: "SCA".to_string(),
                normalized_severity: "Critical".to_string(),
                status: "New".to_string(),
            },
            FindingRow {
                id: id3,
                title: "F3".to_string(),
                source_tool: "tenable_was".to_string(),
                finding_category: "DAST".to_string(),
                normalized_severity: "Low".to_string(),
                status: "Confirmed".to_string(),
            },
        ];

        let edges = vec![
            RelationshipEdge {
                source_finding_id: id1,
                target_finding_id: id2,
            },
        ];

        let chains = build_chains(&findings, &edges);
        // Two groups: {F1, F2} and {F3}
        assert_eq!(chains.len(), 2);

        let big_chain = chains.iter().find(|c| c.len() == 2).unwrap();
        let ids: std::collections::HashSet<Uuid> = big_chain.iter().map(|f| f.id).collect();
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));

        let lone = chains.iter().find(|c| c.len() == 1).unwrap();
        assert_eq!(lone[0].id, id3);
    }

    #[test]
    fn build_chains_transitive() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();

        let findings = vec![
            FindingRow {
                id: id1,
                title: "F1".to_string(),
                source_tool: "sonarqube".to_string(),
                finding_category: "SAST".to_string(),
                normalized_severity: "High".to_string(),
                status: "New".to_string(),
            },
            FindingRow {
                id: id2,
                title: "F2".to_string(),
                source_tool: "jfrog_xray".to_string(),
                finding_category: "SCA".to_string(),
                normalized_severity: "Medium".to_string(),
                status: "New".to_string(),
            },
            FindingRow {
                id: id3,
                title: "F3".to_string(),
                source_tool: "tenable_was".to_string(),
                finding_category: "DAST".to_string(),
                normalized_severity: "Critical".to_string(),
                status: "New".to_string(),
            },
        ];

        // F1-F2 and F2-F3 should all be in one chain
        let edges = vec![
            RelationshipEdge {
                source_finding_id: id1,
                target_finding_id: id2,
            },
            RelationshipEdge {
                source_finding_id: id2,
                target_finding_id: id3,
            },
        ];

        let chains = build_chains(&findings, &edges);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].len(), 3);
    }

    #[test]
    fn severity_breakdown_fields() {
        let breakdown = SeverityBreakdown {
            critical: 3,
            high: 5,
            medium: 10,
            low: 2,
            info: 1,
        };
        let json = serde_json::to_value(&breakdown).unwrap();
        assert_eq!(json["critical"], 3);
        assert_eq!(json["high"], 5);
        assert_eq!(json["medium"], 10);
        assert_eq!(json["low"], 2);
        assert_eq!(json["info"], 1);
    }

    #[test]
    fn attack_chain_filters_deserialize() {
        let json = r#"{"branch": "main"}"#;
        let filters: AttackChainFilters = serde_json::from_str(json).unwrap();
        assert_eq!(filters.branch.as_deref(), Some("main"));

        let json_empty = r#"{}"#;
        let filters_empty: AttackChainFilters = serde_json::from_str(json_empty).unwrap();
        assert!(filters_empty.branch.is_none());
    }
}
