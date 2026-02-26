import { apiGet, apiPost } from './client'
import type { DedupStats, PendingReview, DedupDecision } from '@/types/deduplication'
import type { PagedResult } from '@/types/finding'

/** GET /deduplication/stats — get deduplication statistics. */
export function getStats(): Promise<DedupStats> {
  return apiGet<DedupStats>('/deduplication/stats')
}

/** GET /deduplication/pending — list pending duplicate reviews. */
export function listPending(
  page = 1,
  perPage = 25,
): Promise<PagedResult<PendingReview>> {
  const params: Record<string, string> = {
    page: String(page),
    per_page: String(perPage),
  }

  return apiGet<PagedResult<PendingReview>>('/deduplication/pending', params)
}

/** GET /deduplication/history — list deduplication decision history. */
export function listHistory(
  page = 1,
  perPage = 25,
): Promise<PagedResult<DedupDecision>> {
  const params: Record<string, string> = {
    page: String(page),
    per_page: String(perPage),
  }

  return apiGet<PagedResult<DedupDecision>>('/deduplication/history', params)
}

/** POST /deduplication/:relationship_id/confirm — confirm a duplicate relationship. */
export function confirm(relationshipId: string): Promise<void> {
  return apiPost<void>(`/deduplication/${relationshipId}/confirm`, {})
}

/** POST /deduplication/:relationship_id/reject — reject a duplicate relationship. */
export function reject(relationshipId: string): Promise<void> {
  return apiPost<void>(`/deduplication/${relationshipId}/reject`, {})
}
