import type { FindingSummary } from '@/types/finding'

export type ConfidenceLevel = 'High' | 'Medium' | 'Low'
export type RelationshipType = 'duplicate_of' | 'correlated_with' | 'grouped_under'

export type CorrelationRule = {
  id: string
  name: string
  description: string | null
  rule_type: string
  conditions: Record<string, unknown>
  confidence: ConfidenceLevel
  is_active: boolean
  priority: number
  created_by: string | null
  created_at: string
  updated_at: string
}

export type CorrelationGroup = {
  id: string
  primary_finding_id: string
  member_count: number
  tool_coverage: string[]
  created_at: string
}

export type CorrelationGroupDetail = {
  group: CorrelationGroup
  members: FindingSummary[]
}

export type CreateCorrelationRule = {
  name: string
  description?: string
  rule_type: string
  conditions: Record<string, unknown>
  confidence?: ConfidenceLevel
  priority?: number
}

export type UpdateCorrelationRule = {
  name?: string
  description?: string
  rule_type?: string
  conditions?: Record<string, unknown>
  confidence?: ConfidenceLevel
  is_active?: boolean
  priority?: number
}

export type FindingRelationship = {
  id: string
  source_finding_id: string
  target_finding_id: string
  relationship_type: RelationshipType
  confidence: ConfidenceLevel | null
  created_by: string | null
  created_at: string
  notes: string | null
}

export type CreateRelationshipRequest = {
  source_finding_id: string
  target_finding_id: string
  relationship_type: RelationshipType
  confidence?: ConfidenceLevel
  notes?: string
}

export type CorrelationRunResult = {
  new_relationships: number
  total_findings_analyzed: number
}
