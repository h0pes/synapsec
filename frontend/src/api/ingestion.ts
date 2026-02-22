import { apiGet, apiUpload } from './client'
import type { PagedResult } from '@/types/application'

export type IngestionStatus = 'Completed' | 'Partial' | 'Failed'

export type IngestionLogSummary = {
  id: string
  source_tool: string
  ingestion_type: string
  file_name: string | null
  total_records: number
  new_findings: number
  updated_findings: number
  duplicates: number
  errors: number
  quarantined: number
  status: IngestionStatus
  started_at: string
  completed_at: string | null
  initiated_by: string | null
}

export type IngestionLog = IngestionLogSummary & {
  error_details: unknown | null
}

export type IngestionResult = {
  ingestion_log_id: string
  total_parsed: number
  new_findings: number
  updated_findings: number
  duplicates: number
  errors: number
  quarantined: number
}

/** POST /ingestion/upload — upload a file for ingestion. */
export function uploadFile(
  file: File,
  parserType: string,
  format: string,
): Promise<IngestionResult> {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('parser_type', parserType)
  formData.append('format', format)
  return apiUpload<IngestionResult>('/ingestion/upload', formData)
}

/** GET /ingestion/history — list past ingestions. */
export function listHistory(
  page = 1,
  perPage = 25,
): Promise<PagedResult<IngestionLogSummary>> {
  return apiGet<PagedResult<IngestionLogSummary>>('/ingestion/history', {
    page: String(page),
    per_page: String(perPage),
  })
}

/** GET /ingestion/:id — get ingestion log details. */
export function getLog(id: string): Promise<IngestionLog> {
  return apiGet<IngestionLog>(`/ingestion/${id}`)
}
