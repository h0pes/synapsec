import type { Node, Edge } from '@xyflow/react'
import type {
  AppAttackChainDetail,
  ChainFinding,
  UncorrelatedFinding,
} from '@/types/attack-chains'

/** Data payload carried by each finding node in the graph. */
export type FindingNodeData = {
  finding: ChainFinding | UncorrelatedFinding
  isUncorrelated: boolean
  chainGroupId: string | null
}

/** Data payload carried by each correlation edge. */
export type CorrelationEdgeData = {
  relationshipType: string
  confidence: string | null
}

/** Custom node type used throughout the attack-chain graph. */
export type FindingNode = Node<FindingNodeData, 'finding'>

/** Custom edge type used throughout the attack-chain graph. */
export type CorrelationEdge = Edge<CorrelationEdgeData, 'correlation'>

/**
 * Category-to-color mapping for node accent borders.
 * SAST = blue, SCA = purple, DAST = teal -- matches the project-wide convention
 * visible in AttackChainDetailPage and SeverityBadge.
 */
export const CATEGORY_COLORS: Record<string, { bg: string; border: string }> = {
  SAST: { bg: '#3b82f6', border: '#2563eb' },
  SCA:  { bg: '#8b5cf6', border: '#7c3aed' },
  DAST: { bg: '#14b8a6', border: '#0d9488' },
}

/**
 * Severity-dependent node dimensions.
 * Higher-severity findings are rendered larger to draw visual attention.
 */
export const SEVERITY_SIZES: Record<string, { width: number; height: number }> = {
  Critical: { width: 220, height: 80 },
  High:     { width: 200, height: 72 },
  Medium:   { width: 180, height: 64 },
  Low:      { width: 160, height: 56 },
  Info:     { width: 140, height: 48 },
}

/** Fallback dimensions when severity is not recognized. */
const DEFAULT_SIZE = { width: 180, height: 64 }

/** Optional filters for the graph transformation. */
export type TransformFilters = {
  /** Only include findings whose severity rank meets this threshold (1–5). */
  minRiskScore?: number
  /** Only include findings whose finding_category is in this set. */
  categories?: Set<string>
}

/** Severity ordering for risk-score-based chain filtering. */
const SEVERITY_RANK: Record<string, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Info: 1,
}

function severityRank(severity: string): number {
  return SEVERITY_RANK[severity] ?? 0
}

/**
 * Map a minRiskScore (1-5 scale matching severity rank) to filter chains.
 * A chain passes the filter when its max_severity rank >= minRiskScore.
 */
function chainPassesRiskFilter(maxSeverity: string, minRiskScore: number): boolean {
  return severityRank(maxSeverity) >= minRiskScore
}

function sizeForSeverity(severity: string): { width: number; height: number } {
  return SEVERITY_SIZES[severity] ?? DEFAULT_SIZE
}

/**
 * Transform an `AppAttackChainDetail` API response into React Flow nodes and edges.
 *
 * Each `ChainFinding` becomes a node (type = 'finding').
 * Each `ChainRelationship` becomes an edge (type = 'correlation').
 * Uncorrelated findings become standalone nodes with `isUncorrelated: true`.
 */
export function transformAttackChainData(
  detail: AppAttackChainDetail,
  filters?: TransformFilters,
): { nodes: FindingNode[]; edges: CorrelationEdge[] } {
  const nodes: FindingNode[] = []
  const edges: CorrelationEdge[] = []

  // -- Correlated chains --
  for (const chain of detail.chains) {
    // Apply risk-score filter at chain level
    if (
      filters?.minRiskScore != null &&
      !chainPassesRiskFilter(chain.max_severity, filters.minRiskScore)
    ) {
      continue
    }

    for (const finding of chain.findings) {
      // Apply category filter at finding level
      if (filters?.categories && filters.categories.size > 0) {
        if (!filters.categories.has(finding.finding_category)) {
          continue
        }
      }

      const size = sizeForSeverity(finding.normalized_severity)

      nodes.push({
        id: finding.id,
        type: 'finding',
        position: { x: 0, y: 0 }, // Will be set by layout engine
        data: {
          finding,
          isUncorrelated: false,
          chainGroupId: chain.group_id,
        },
        ariaLabel: `${finding.title} - ${finding.normalized_severity}`,
        width: size.width,
        height: size.height,
      })
    }

    // Build a set of node IDs currently in the graph for this chain
    // so we only create edges between nodes that exist after filtering
    const nodeIds = new Set(nodes.map((n) => n.id))

    for (const rel of chain.relationships) {
      if (!nodeIds.has(rel.source_finding_id) || !nodeIds.has(rel.target_finding_id)) {
        continue
      }

      edges.push({
        id: rel.id,
        type: 'correlation',
        source: rel.source_finding_id,
        target: rel.target_finding_id,
        data: {
          relationshipType: rel.relationship_type,
          confidence: rel.confidence,
        },
      })
    }
  }

  // -- Uncorrelated findings --
  for (const finding of detail.uncorrelated_findings) {
    // Apply risk-score filter at individual finding level
    if (
      filters?.minRiskScore != null &&
      severityRank(finding.normalized_severity) < filters.minRiskScore
    ) {
      continue
    }

    if (filters?.categories && filters.categories.size > 0) {
      if (!filters.categories.has(finding.finding_category)) {
        continue
      }
    }

    const size = sizeForSeverity(finding.normalized_severity)

    nodes.push({
      id: finding.id,
      type: 'finding',
      position: { x: 0, y: 0 },
      data: {
        finding,
        isUncorrelated: true,
        chainGroupId: null,
      },
      ariaLabel: `${finding.title} - ${finding.normalized_severity}`,
      width: size.width,
      height: size.height,
    })
  }

  return { nodes, edges }
}
