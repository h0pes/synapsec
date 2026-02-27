import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useSearch } from '@tanstack/react-router'
import type { SortingState } from '@tanstack/react-table'
import { Button } from '@/components/ui/button'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { FindingList } from '@/components/findings/FindingList'
import { FindingFiltersPanel } from '@/components/findings/FindingFilters'
import { SastTable } from '@/components/findings/SastTable'
import { ScaTable } from '@/components/findings/ScaTable'
import { DastTable } from '@/components/findings/DastTable'
import * as findingsApi from '@/api/findings'
import type {
  FindingCategory,
  FindingFilters,
  FindingSummary,
  FindingSummaryWithCategory,
} from '@/types/finding'

type TabValue = 'all' | 'sast' | 'sca' | 'dast'

const VALID_TABS: ReadonlySet<string> = new Set(['all', 'sast', 'sca', 'dast'])

const TAB_TO_CATEGORY: Record<string, FindingCategory> = {
  sast: 'SAST',
  sca: 'SCA',
  dast: 'DAST',
}

function parseTab(raw: string | undefined): TabValue {
  if (raw && VALID_TABS.has(raw.toLowerCase())) {
    return raw.toLowerCase() as TabValue
  }
  return 'all'
}

export function FindingsPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const searchParams = useSearch({ strict: false }) as { tab?: string }
  const activeTab = parseTab(searchParams.tab)

  const [findings, setFindings] = useState<FindingSummary[]>([])
  const [categoryFindings, setCategoryFindings] = useState<FindingSummaryWithCategory[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [filters, setFilters] = useState<FindingFilters>({})
  const [sorting, setSorting] = useState<SortingState>([])
  const [loading, setLoading] = useState(false)
  const perPage = 25

  // Per-tab category filter state (column-level filters from inline table headers)
  const [sastCategoryFilters, setSastCategoryFilters] = useState<Record<string, string>>({})
  const [scaCategoryFilters, setScaCategoryFilters] = useState<Record<string, string>>({})
  const [dastCategoryFilters, setDastCategoryFilters] = useState<Record<string, string>>({})

  const activeCategoryFilters = useMemo(
    () =>
      activeTab === 'sast'
        ? sastCategoryFilters
        : activeTab === 'sca'
          ? scaCategoryFilters
          : activeTab === 'dast'
            ? dastCategoryFilters
            : {},
    [activeTab, sastCategoryFilters, scaCategoryFilters, dastCategoryFilters],
  )

  const fetchFindings = useCallback(async () => {
    setLoading(true)
    try {
      const category = TAB_TO_CATEGORY[activeTab]
      if (activeTab === 'all') {
        const result = await findingsApi.listFindings(filters, page, perPage)
        setFindings(result.items)
        setCategoryFindings([])
        setTotal(result.total)
        setTotalPages(result.total_pages)
      } else {
        const categoryFilters: FindingFilters = { ...filters, category }
        const result = await findingsApi.listFindingsWithCategory(
          categoryFilters,
          page,
          perPage,
          activeCategoryFilters,
        )
        setCategoryFindings(result.items)
        setFindings([])
        setTotal(result.total)
        setTotalPages(result.total_pages)
      }
    } catch {
      // Error handled by API client
    } finally {
      setLoading(false)
    }
  }, [filters, page, activeTab, activeCategoryFilters])

  useEffect(() => {
    fetchFindings()
  }, [fetchFindings])

  function handleTabChange(value: string) {
    const tab = value as TabValue
    setPage(1)
    void navigate({
      to: '/findings',
      search: tab === 'all' ? {} : { tab },
      replace: true,
    })
  }

  function handleFiltersChange(newFilters: FindingFilters) {
    setFilters(newFilters)
    setPage(1)
  }

  function handleRowClick(id: string) {
    void navigate({ to: '/findings/$id', params: { id } })
  }

  const handleSastFiltersChange = useCallback((newFilters: Record<string, string>) => {
    setSastCategoryFilters(newFilters)
    setPage(1)
  }, [])

  const handleScaFiltersChange = useCallback((newFilters: Record<string, string>) => {
    setScaCategoryFilters(newFilters)
    setPage(1)
  }, [])

  const handleDastFiltersChange = useCallback((newFilters: Record<string, string>) => {
    setDastCategoryFilters(newFilters)
    setPage(1)
  }, [])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t('nav.findings')}</h1>
        <span className="text-sm text-muted-foreground">
          {total} {total === 1 ? t('common.finding') : t('common.findings')}
        </span>
      </div>

      <Tabs value={activeTab} onValueChange={handleTabChange}>
        <TabsList>
          <TabsTrigger value="all">{t('findings.tabs.all')}</TabsTrigger>
          <TabsTrigger value="sast">{t('findings.tabs.sast')}</TabsTrigger>
          <TabsTrigger value="sca">{t('findings.tabs.sca')}</TabsTrigger>
          <TabsTrigger value="dast">{t('findings.tabs.dast')}</TabsTrigger>
        </TabsList>

        <FindingFiltersPanel filters={filters} onChange={handleFiltersChange} hideCategory={activeTab !== 'all'} />

        {loading ? (
          <div className="flex h-64 items-center justify-center text-muted-foreground">
            {t('common.loading')}
          </div>
        ) : (
          <>
            <TabsContent value="all">
              <FindingList
                findings={findings}
                sorting={sorting}
                onSortingChange={setSorting}
              />
            </TabsContent>

            <TabsContent value="sast">
              <SastTable
                findings={categoryFindings}
                onRowClick={handleRowClick}
                onFiltersChange={handleSastFiltersChange}
                sorting={sorting}
                onSortingChange={setSorting}
              />
            </TabsContent>

            <TabsContent value="sca">
              <ScaTable
                findings={categoryFindings}
                onRowClick={handleRowClick}
                onFiltersChange={handleScaFiltersChange}
                sorting={sorting}
                onSortingChange={setSorting}
              />
            </TabsContent>

            <TabsContent value="dast">
              <DastTable
                findings={categoryFindings}
                onRowClick={handleRowClick}
                onFiltersChange={handleDastFiltersChange}
                sorting={sorting}
                onSortingChange={setSorting}
              />
            </TabsContent>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">
                  {t('common.page')} {page} {t('common.of')} {totalPages}
                </span>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page <= 1}
                    onClick={() => setPage((p) => p - 1)}
                  >
                    {t('common.previous')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page >= totalPages}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    {t('common.next')}
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </Tabs>
    </div>
  )
}
