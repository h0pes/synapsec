export type FindingCategory = 'SAST' | 'SCA' | 'DAST'

export type FindingStatus =
  | 'New'
  | 'Confirmed'
  | 'In_Remediation'
  | 'Mitigated'
  | 'Verified'
  | 'Closed'
  | 'False_Positive_Requested'
  | 'False_Positive'
  | 'Risk_Accepted'
  | 'Deferred_Remediation'
  | 'Invalidated'

export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'

export type SlaStatus = 'On_Track' | 'At_Risk' | 'Breached'

export type FindingSummary = {
  id: string
  source_tool: string
  finding_category: FindingCategory
  title: string
  normalized_severity: SeverityLevel
  status: FindingStatus
  composite_risk_score: number | null
  application_id: string | null
  first_seen: string
  last_seen: string
  sla_status: SlaStatus | null
  fingerprint: string
}

export type FindingDetail = {
  id: string
  source_tool: string
  source_tool_version: string | null
  source_finding_id: string
  finding_category: FindingCategory
  title: string
  description: string
  normalized_severity: SeverityLevel
  original_severity: string
  cvss_score: number | null
  cvss_vector: string | null
  cwe_ids: string[]
  cve_ids: string[]
  owasp_category: string | null
  status: FindingStatus
  composite_risk_score: number | null
  confidence: string | null
  fingerprint: string
  application_id: string | null
  remediation_owner: string | null
  first_seen: string
  last_seen: string
  tags: string[]
  remediation_guidance: string | null
  raw_finding: unknown
  metadata: Record<string, unknown>
  sast: SastDetail | null
  sca: ScaDetail | null
  dast: DastDetail | null
}

export type SastDetail = {
  file_path: string
  line_number_start: number | null
  line_number_end: number | null
  project: string
  rule_name: string
  rule_id: string
  issue_type: string | null
  branch: string | null
  code_snippet: string | null
  language: string | null
}

export type ScaDetail = {
  package_name: string
  package_version: string
  package_type: string | null
  fixed_version: string | null
  dependency_type: string | null
  epss_score: number | null
  known_exploited: boolean
  exploit_maturity: string | null
}

export type DastDetail = {
  target_url: string
  http_method: string | null
  parameter: string | null
  attack_vector: string | null
  request_evidence: string | null
  response_evidence: string | null
}

export type FindingHistory = {
  id: string
  finding_id: string
  action: string
  field_changed: string | null
  old_value: string | null
  new_value: string | null
  actor_name: string
  justification: string | null
  created_at: string
}

export type FindingComment = {
  id: string
  finding_id: string
  author_name: string
  content: string
  created_at: string
}

export type PagedResult<T> = {
  items: T[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export type FindingFilters = {
  severity?: SeverityLevel
  status?: FindingStatus
  category?: FindingCategory
  application_id?: string
  source_tool?: string
  sla_status?: SlaStatus
  search?: string
}
