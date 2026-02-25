export type SeverityBreakdown = {
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export type AppAttackChainSummary = {
  application_id: string
  app_name: string
  app_code: string
  correlation_group_count: number
  total_findings: number
  correlated_findings: number
  uncorrelated_findings: number
  tool_coverage: string[]
  severity_breakdown: SeverityBreakdown
  risk_score: number | null
}

export type ChainFinding = {
  id: string
  title: string
  source_tool: string
  finding_category: string
  normalized_severity: string
  status: string
}

export type AttackChain = {
  group_id: string
  findings: ChainFinding[]
  tool_coverage: string[]
  max_severity: string
  relationship_count: number
}

export type UncorrelatedFinding = {
  id: string
  title: string
  source_tool: string
  finding_category: string
  normalized_severity: string
  status: string
}

export type AppAttackChainDetail = {
  application_id: string
  app_name: string
  app_code: string
  chains: AttackChain[]
  uncorrelated_findings: UncorrelatedFinding[]
}

export type AttackChainFilters = {
  branch?: string
}
