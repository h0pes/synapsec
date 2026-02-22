import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { SortingState } from '@tanstack/react-table'
import { Button } from '@/components/ui/button'
import { FindingList } from '@/components/findings/FindingList'
import { FindingFiltersPanel } from '@/components/findings/FindingFilters'
import * as findingsApi from '@/api/findings'
import type { FindingFilters, FindingSummary } from '@/types/finding'

export function FindingsPage() {
  const { t } = useTranslation()
  const [findings, setFindings] = useState<FindingSummary[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [filters, setFilters] = useState<FindingFilters>({})
  const [sorting, setSorting] = useState<SortingState>([])
  const [loading, setLoading] = useState(false)

  const perPage = 25

  const fetchFindings = useCallback(async () => {
    setLoading(true)
    try {
      const result = await findingsApi.listFindings(filters, page, perPage)
      setFindings(result.items)
      setTotal(result.total)
      setTotalPages(result.total_pages)
    } catch {
      // Error handled by API client
    } finally {
      setLoading(false)
    }
  }, [filters, page])

  useEffect(() => {
    fetchFindings()
  }, [fetchFindings])

  function handleFiltersChange(newFilters: FindingFilters) {
    setFilters(newFilters)
    setPage(1)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t('nav.findings')}</h1>
        <span className="text-sm text-muted-foreground">
          {total} {total === 1 ? 'finding' : 'findings'}
        </span>
      </div>

      <FindingFiltersPanel filters={filters} onChange={handleFiltersChange} />

      {loading ? (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          {t('common.loading')}
        </div>
      ) : (
        <>
          <FindingList
            findings={findings}
            sorting={sorting}
            onSortingChange={setSorting}
          />

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">
                Page {page} of {totalPages}
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
