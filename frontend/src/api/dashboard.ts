import { apiGet } from './client'

export type DashboardStats = {
  triage_count: number
  unmapped_apps_count: number
  severity_counts: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  sla_summary: {
    on_track: number
    at_risk: number
    breached: number
  }
  recent_ingestions: {
    id: string
    source_tool: string
    file_name: string | null
    total_records: number
    new_findings: number
    status: string
    completed_at: string | null
  }[]
  top_risky_apps: {
    id: string
    app_name: string
    app_code: string
    finding_count: number
    critical_count: number
    high_count: number
  }[]
  findings_by_source: {
    source_tool: string
    count: number
  }[]
}

/** GET /dashboard/stats — fetch dashboard statistics. */
export function getStats(): Promise<DashboardStats> {
  return apiGet<DashboardStats>('/dashboard/stats')
}
