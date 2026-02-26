import { apiGet, apiPost, apiPut, apiDelete } from './client'
import type {
  CorrelationRule,
  CorrelationGroup,
  CorrelationGroupDetail,
  CreateCorrelationRule,
  UpdateCorrelationRule,
  FindingRelationship,
  CreateRelationshipRequest,
  CorrelationRunResult,
} from '@/types/correlation'
import type { PagedResult } from '@/types/finding'

/** GET /correlations/groups — list correlation groups with optional application filter. */
export function listGroups(
  applicationId?: string,
  page = 1,
  perPage = 25,
): Promise<PagedResult<CorrelationGroup>> {
  const params: Record<string, string> = {
    page: String(page),
    per_page: String(perPage),
  }
  if (applicationId) params.application_id = applicationId

  return apiGet<PagedResult<CorrelationGroup>>('/correlations/groups', params)
}

/** GET /correlations/groups/:id — get correlation group detail with members. */
export function getGroup(groupId: string): Promise<CorrelationGroupDetail> {
  return apiGet<CorrelationGroupDetail>(`/correlations/groups/${groupId}`)
}

/** GET /correlations/rules — list all correlation rules. */
export function listRules(): Promise<CorrelationRule[]> {
  return apiGet<CorrelationRule[]>('/correlations/rules')
}

/** POST /correlations/rules — create a new correlation rule. */
export function createRule(body: CreateCorrelationRule): Promise<CorrelationRule> {
  return apiPost<CorrelationRule>('/correlations/rules', body)
}

/** PUT /correlations/rules/:id — update an existing correlation rule. */
export function updateRule(id: string, body: UpdateCorrelationRule): Promise<CorrelationRule> {
  return apiPut<CorrelationRule>(`/correlations/rules/${id}`, body)
}

/** POST /correlations/run/:app_id — run correlation engine for an application. */
export function runCorrelation(appId: string): Promise<CorrelationRunResult> {
  return apiPost<CorrelationRunResult>(`/correlations/run/${appId}`, {})
}

/** POST /relationships — create a manual finding relationship. */
export function createRelationship(body: CreateRelationshipRequest): Promise<FindingRelationship> {
  return apiPost<FindingRelationship>('/relationships', body)
}

/** DELETE /relationships/:id — delete a finding relationship. */
export function deleteRelationship(id: string): Promise<void> {
  return apiDelete<void>(`/relationships/${id}`)
}
