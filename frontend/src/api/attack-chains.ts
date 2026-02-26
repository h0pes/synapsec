import { apiGet } from './client'
import type {
  AppAttackChainSummary,
  AppAttackChainDetail,
  AttackChainFilters,
} from '@/types/attack-chains'
import type { PagedResult } from '@/types/finding'

/** GET /attack-chains — list attack chain summaries for all applications. */
export function listAttackChains(
  filters: AttackChainFilters = {},
  page = 1,
  perPage = 25,
): Promise<PagedResult<AppAttackChainSummary>> {
  const params: Record<string, string> = {
    page: String(page),
    per_page: String(perPage),
  }
  if (filters.branch) params.branch = filters.branch

  return apiGet<PagedResult<AppAttackChainSummary>>('/attack-chains', params)
}

/** GET /attack-chains/:app_id — get detailed attack chains for a specific application. */
export function getAttackChainsByApp(
  appId: string,
  filters: AttackChainFilters = {},
): Promise<AppAttackChainDetail> {
  const params: Record<string, string> = {}
  if (filters.branch) params.branch = filters.branch

  const hasParams = Object.keys(params).length > 0
  return apiGet<AppAttackChainDetail>(
    `/attack-chains/${appId}`,
    hasParams ? params : undefined,
  )
}
