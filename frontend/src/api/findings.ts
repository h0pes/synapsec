import { apiGet, apiGetBlob, apiPost, apiPut, apiPatch } from './client'
import type {
  FindingSummary,
  FindingSummaryWithCategory,
  FindingDetail,
  FindingFilters,
  FindingHistory,
  FindingComment,
  PagedResult,
} from '@/types/finding'

/** GET /findings — list findings with filters and pagination. */
export function listFindings(
  filters: FindingFilters = {},
  page = 1,
  perPage = 25,
): Promise<PagedResult<FindingSummary>> {
  const params: Record<string, string> = {
    page: String(page),
    per_page: String(perPage),
  }
  if (filters.severity) params.severity = filters.severity
  if (filters.status) params.status = filters.status
  if (filters.category) params.category = filters.category
  if (filters.application_id) params.application_id = filters.application_id
  if (filters.source_tool) params.source_tool = filters.source_tool
  if (filters.sla_status) params.sla_status = filters.sla_status
  if (filters.search) params.search = filters.search

  return apiGet<PagedResult<FindingSummary>>('/findings', params)
}

/** GET /findings — list findings with category-specific data included. */
export function listFindingsWithCategory(
  filters: FindingFilters = {},
  page = 1,
  perPage = 25,
  categoryFilters: Record<string, string> = {},
): Promise<PagedResult<FindingSummaryWithCategory>> {
  const params: Record<string, string> = {
    page: String(page),
    per_page: String(perPage),
    include_category_data: 'true',
  }
  if (filters.severity) params.severity = filters.severity
  if (filters.status) params.status = filters.status
  if (filters.category) params.category = filters.category
  if (filters.application_id) params.application_id = filters.application_id
  if (filters.source_tool) params.source_tool = filters.source_tool
  if (filters.sla_status) params.sla_status = filters.sla_status
  if (filters.search) params.search = filters.search

  // Merge category-specific filter params (e.g., branch, rule_id, package_name, target_url)
  for (const [key, value] of Object.entries(categoryFilters)) {
    if (value) params[key] = value
  }

  return apiGet<PagedResult<FindingSummaryWithCategory>>('/findings', params)
}

/** GET /findings/:id — get finding with category-specific details. */
export function getFinding(id: string): Promise<FindingDetail> {
  return apiGet<FindingDetail>(`/findings/${id}`)
}

/** PUT /findings/:id — update finding. */
export function updateFinding(
  id: string,
  body: Record<string, unknown>,
): Promise<FindingDetail> {
  return apiPut<FindingDetail>(`/findings/${id}`, body)
}

/** PATCH /findings/:id/status — update finding status. */
export function updateFindingStatus(
  id: string,
  status: string,
  justification?: string,
): Promise<void> {
  return apiPatch<void>(`/findings/${id}/status`, { status, justification })
}

/** GET /findings/:id/comments — list finding comments. */
export function listComments(id: string): Promise<FindingComment[]> {
  return apiGet<FindingComment[]>(`/findings/${id}/comments`)
}

/** POST /findings/:id/comments — add a comment. */
export function addComment(id: string, content: string): Promise<FindingComment> {
  return apiPost<FindingComment>(`/findings/${id}/comments`, { content })
}

/** GET /findings/:id/history — get finding history. */
export function getHistory(id: string): Promise<FindingHistory[]> {
  return apiGet<FindingHistory[]>(`/findings/${id}/history`)
}

/** POST /findings/bulk/status — bulk status update. */
export function bulkUpdateStatus(
  findingIds: string[],
  status: string,
  justification?: string,
): Promise<{ updated: number; total: number }> {
  return apiPost('/findings/bulk/status', {
    finding_ids: findingIds,
    status,
    justification,
  })
}

/** POST /findings/bulk/assign — bulk assign. */
export function bulkAssign(
  findingIds: string[],
  remediationOwner: string,
): Promise<{ updated: number; total: number }> {
  return apiPost('/findings/bulk/assign', {
    finding_ids: findingIds,
    remediation_owner: remediationOwner,
  })
}

/** GET /findings/export — download findings as CSV or JSON blob. */
export function exportFindings(
  filters: Record<string, string>,
  format: 'csv' | 'json',
): Promise<Blob> {
  return apiGetBlob('/findings/export', { ...filters, format })
}

/** POST /findings/bulk/tag — bulk tag. */
export function bulkTag(
  findingIds: string[],
  tags: string[],
): Promise<{ updated: number; total: number }> {
  return apiPost('/findings/bulk/tag', {
    finding_ids: findingIds,
    tags,
  })
}
