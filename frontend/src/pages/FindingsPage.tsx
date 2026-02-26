import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate, useSearch } from '@tanstack/react-router'
import type { SortingState } from '@tanstack/react-table'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { FindingList } from '@/components/findings/FindingList'
import { FindingFiltersPanel } from '@/components/findings/FindingFilters'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import { FindingStatusBadge } from '@/components/findings/FindingStatusBadge'
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
  }, [filters, page, activeTab])

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
              />
            </TabsContent>

            <TabsContent value="sca">
              <ScaTable
                findings={categoryFindings}
                onRowClick={handleRowClick}
              />
            </TabsContent>

            <TabsContent value="dast">
              <DastTable
                findings={categoryFindings}
                onRowClick={handleRowClick}
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

/* ---------- SAST category table ---------- */

function SastTable({
  findings,
  onRowClick,
}: {
  findings: FindingSummaryWithCategory[]
  onRowClick: (id: string) => void
}) {
  const { t } = useTranslation()

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead style={{ width: 280 }}>{t('findings.columns.title')}</TableHead>
            <TableHead style={{ width: 100 }}>{t('findings.columns.severity')}</TableHead>
            <TableHead style={{ width: 140 }}>{t('findings.columns.status')}</TableHead>
            <TableHead style={{ width: 120 }}>{t('findings.columns.source')}</TableHead>
            <TableHead style={{ width: 100 }}>{t('findings.columns.firstSeen')}</TableHead>
            <TableHead style={{ width: 200 }}>{t('findings.columns.filePath')}</TableHead>
            <TableHead style={{ width: 60 }}>{t('findings.columns.lineNumber')}</TableHead>
            <TableHead style={{ width: 120 }}>{t('findings.columns.ruleId')}</TableHead>
            <TableHead style={{ width: 120 }}>{t('findings.columns.project')}</TableHead>
            <TableHead style={{ width: 90 }}>{t('findings.columns.language')}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {findings.length === 0 ? (
            <TableRow>
              <TableCell colSpan={10} className="h-32 text-center text-muted-foreground">
                {t('findings.noFindings')}
              </TableCell>
            </TableRow>
          ) : (
            findings.map((f) => (
              <TableRow
                key={f.id}
                className="cursor-pointer"
                onClick={() => onRowClick(f.id)}
              >
                <TableCell className="font-medium">{f.title}</TableCell>
                <TableCell>
                  <SeverityBadge severity={f.normalized_severity} />
                </TableCell>
                <TableCell>
                  <FindingStatusBadge status={f.status} />
                </TableCell>
                <TableCell>{f.source_tool}</TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {new Date(f.first_seen).toLocaleDateString()}
                </TableCell>
                <TableCell className="max-w-[200px] truncate font-mono text-xs" title={f.category_data?.file_path}>
                  {f.category_data?.file_path ?? '-'}
                </TableCell>
                <TableCell className="font-mono text-sm">
                  {f.category_data?.line_number ?? '-'}
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {f.category_data?.rule_id ?? '-'}
                </TableCell>
                <TableCell>{f.category_data?.project ?? '-'}</TableCell>
                <TableCell>
                  {f.category_data?.language ? (
                    <Badge variant="outline">{f.category_data.language}</Badge>
                  ) : (
                    '-'
                  )}
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  )
}

/* ---------- SCA category table ---------- */

function ScaTable({
  findings,
  onRowClick,
}: {
  findings: FindingSummaryWithCategory[]
  onRowClick: (id: string) => void
}) {
  const { t } = useTranslation()

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead style={{ width: 280 }}>{t('findings.columns.title')}</TableHead>
            <TableHead style={{ width: 100 }}>{t('findings.columns.severity')}</TableHead>
            <TableHead style={{ width: 140 }}>{t('findings.columns.status')}</TableHead>
            <TableHead style={{ width: 120 }}>{t('findings.columns.source')}</TableHead>
            <TableHead style={{ width: 100 }}>{t('findings.columns.firstSeen')}</TableHead>
            <TableHead style={{ width: 140 }}>{t('findings.columns.packageName')}</TableHead>
            <TableHead style={{ width: 100 }}>{t('findings.columns.packageVersion')}</TableHead>
            <TableHead style={{ width: 110 }}>{t('findings.columns.fixedVersion')}</TableHead>
            <TableHead style={{ width: 110 }}>{t('findings.columns.dependencyType')}</TableHead>
            <TableHead style={{ width: 110 }}>{t('findings.columns.knownExploited')}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {findings.length === 0 ? (
            <TableRow>
              <TableCell colSpan={10} className="h-32 text-center text-muted-foreground">
                {t('findings.noFindings')}
              </TableCell>
            </TableRow>
          ) : (
            findings.map((f) => (
              <TableRow
                key={f.id}
                className="cursor-pointer"
                onClick={() => onRowClick(f.id)}
              >
                <TableCell className="font-medium">{f.title}</TableCell>
                <TableCell>
                  <SeverityBadge severity={f.normalized_severity} />
                </TableCell>
                <TableCell>
                  <FindingStatusBadge status={f.status} />
                </TableCell>
                <TableCell>{f.source_tool}</TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {new Date(f.first_seen).toLocaleDateString()}
                </TableCell>
                <TableCell className="font-mono text-sm">
                  {f.category_data?.package_name ?? '-'}
                </TableCell>
                <TableCell className="font-mono text-sm">
                  {f.category_data?.package_version ?? '-'}
                </TableCell>
                <TableCell className="font-mono text-sm">
                  {f.category_data?.fixed_version ?? (
                    <span className="text-muted-foreground">-</span>
                  )}
                </TableCell>
                <TableCell>
                  {f.category_data?.dependency_type ? (
                    <Badge variant="outline">{f.category_data.dependency_type}</Badge>
                  ) : (
                    '-'
                  )}
                </TableCell>
                <TableCell>
                  {f.category_data?.known_exploited != null ? (
                    f.category_data.known_exploited ? (
                      <Badge className="bg-red-600 text-white">{t('findings.yes')}</Badge>
                    ) : (
                      <span className="text-muted-foreground">{t('findings.no')}</span>
                    )
                  ) : (
                    '-'
                  )}
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  )
}

/* ---------- DAST category table ---------- */

function DastTable({
  findings,
  onRowClick,
}: {
  findings: FindingSummaryWithCategory[]
  onRowClick: (id: string) => void
}) {
  const { t } = useTranslation()

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead style={{ width: 280 }}>{t('findings.columns.title')}</TableHead>
            <TableHead style={{ width: 100 }}>{t('findings.columns.severity')}</TableHead>
            <TableHead style={{ width: 140 }}>{t('findings.columns.status')}</TableHead>
            <TableHead style={{ width: 120 }}>{t('findings.columns.source')}</TableHead>
            <TableHead style={{ width: 100 }}>{t('findings.columns.firstSeen')}</TableHead>
            <TableHead style={{ width: 250 }}>{t('findings.columns.targetUrl')}</TableHead>
            <TableHead style={{ width: 140 }}>{t('findings.columns.parameter')}</TableHead>
            <TableHead style={{ width: 180 }}>{t('findings.columns.webAppName')}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {findings.length === 0 ? (
            <TableRow>
              <TableCell colSpan={8} className="h-32 text-center text-muted-foreground">
                {t('findings.noFindings')}
              </TableCell>
            </TableRow>
          ) : (
            findings.map((f) => (
              <TableRow
                key={f.id}
                className="cursor-pointer"
                onClick={() => onRowClick(f.id)}
              >
                <TableCell className="font-medium">{f.title}</TableCell>
                <TableCell>
                  <SeverityBadge severity={f.normalized_severity} />
                </TableCell>
                <TableCell>
                  <FindingStatusBadge status={f.status} />
                </TableCell>
                <TableCell>{f.source_tool}</TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {new Date(f.first_seen).toLocaleDateString()}
                </TableCell>
                <TableCell className="max-w-[250px] truncate font-mono text-xs" title={f.category_data?.target_url}>
                  {f.category_data?.target_url ?? '-'}
                </TableCell>
                <TableCell className="font-mono text-sm">
                  {f.category_data?.parameter ?? '-'}
                </TableCell>
                <TableCell>
                  {f.category_data?.web_application_name ?? '-'}
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  )
}
