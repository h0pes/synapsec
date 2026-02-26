export type DedupStats = {
  total_duplicate_relationships: number
  pending_review: number
  confirmed: number
  rejected: number
  total_ingestions: number
  last_ingestion_at: string | null
}

export type PendingReview = {
  relationship_id: string
  source_finding_id: string
  source_title: string
  source_tool: string
  target_finding_id: string
  target_title: string
  target_tool: string
  confidence: string | null
  created_at: string
}

export type DedupDecision = {
  id: string
  finding_id: string
  action: string
  field_changed: string | null
  old_value: string | null
  new_value: string | null
  actor_name: string | null
  created_at: string
}
