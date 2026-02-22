import { apiGet, apiPost, apiPut } from './client'
import type {
  Application,
  ApplicationSummary,
  CreateApplication,
  PagedResult,
} from '@/types/application'

/** GET /applications — list applications with pagination. */
export function listApplications(
  params: Record<string, string> = {},
  page = 1,
  perPage = 25,
): Promise<PagedResult<ApplicationSummary>> {
  return apiGet<PagedResult<ApplicationSummary>>('/applications', {
    page: String(page),
    per_page: String(perPage),
    ...params,
  })
}

/** GET /applications/:id — get application by ID. */
export function getApplication(id: string): Promise<Application> {
  return apiGet<Application>(`/applications/${id}`)
}

/** GET /applications/code/:code — get application by app_code. */
export function getApplicationByCode(code: string): Promise<Application> {
  return apiGet<Application>(`/applications/code/${code}`)
}

/** POST /applications — create application. */
export function createApplication(body: CreateApplication): Promise<Application> {
  return apiPost<Application>('/applications', body)
}

/** PUT /applications/:id — update application. */
export function updateApplication(
  id: string,
  body: Record<string, unknown>,
): Promise<Application> {
  return apiPut<Application>(`/applications/${id}`, body)
}

/** POST /applications/import — bulk import from JSON array. */
export function importBulk(
  apps: CreateApplication[],
): Promise<{ created: number; updated: number; errors: unknown[] }> {
  return apiPost('/applications/import', apps)
}

/** GET /applications/unverified — list unverified stubs. */
export function listUnverified(
  page = 1,
  perPage = 25,
): Promise<PagedResult<ApplicationSummary>> {
  return apiGet<PagedResult<ApplicationSummary>>('/applications/unverified', {
    page: String(page),
    per_page: String(perPage),
  })
}
