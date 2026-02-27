import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from '@tanstack/react-router'
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from '@tanstack/react-table'
import { ArrowUpDown } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { TablePagination } from '@/components/ui/table-pagination'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { PageHeader } from '@/components/ui/page-header'
import {
  TOOL_BADGE_STYLES,
  TOOL_CATEGORY_LABELS,
} from '@/lib/findings'
import { SEVERITY_STYLES } from '@/components/findings/SeverityBadge'
import * as attackChainsApi from '@/api/attack-chains'
import type { AppAttackChainSummary } from '@/types/attack-chains'

export function AttackChainsPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [apps, setApps] = useState<AppAttackChainSummary[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [sorting, setSorting] = useState<SortingState>([
    { id: 'risk_score', desc: true },
  ])
  const [loading, setLoading] = useState(false)

  const perPage = 25

  const fetchData = useCallback(async () => {
    setLoading(true)
    try {
      const result = await attackChainsApi.listAttackChains({}, page, perPage)
      setApps(result.items)
      setTotal(result.total)
      setTotalPages(result.total_pages)
    } catch {
      // Error handled by API client
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const columns: ColumnDef<AppAttackChainSummary>[] = [
    {
      accessorKey: 'app_name',
      header: ({ column }) => (
        <Button variant="ghost" onClick={() => column.toggleSorting()}>
          {t('attackChains.columns.application')} <ArrowUpDown className="ml-1 h-3 w-3" />
        </Button>
      ),
      cell: ({ row }) => (
        <div>
          <span className="font-medium">{row.original.app_name}</span>
          <span className="ml-2 font-mono text-xs text-muted-foreground">
            {row.original.app_code}
          </span>
        </div>
      ),
    },
    {
      accessorKey: 'risk_score',
      header: ({ column }) => (
        <Button variant="ghost" onClick={() => column.toggleSorting()}>
          {t('attackChains.columns.riskScore')} <ArrowUpDown className="ml-1 h-3 w-3" />
        </Button>
      ),
      cell: ({ row }) => {
        const score = row.original.risk_score
        return score != null ? (
          <span className="font-mono text-sm font-semibold">{score.toFixed(1)}</span>
        ) : (
          <span className="text-muted-foreground">-</span>
        )
      },
    },
    {
      accessorKey: 'correlation_group_count',
      header: ({ column }) => (
        <Button variant="ghost" onClick={() => column.toggleSorting()}>
          {t('attackChains.columns.attackChains')} <ArrowUpDown className="ml-1 h-3 w-3" />
        </Button>
      ),
      cell: ({ row }) => (
        <span className="font-mono text-sm">{row.original.correlation_group_count}</span>
      ),
    },
    {
      accessorKey: 'tool_coverage',
      header: t('attackChains.columns.toolCoverage'),
      enableSorting: false,
      cell: ({ row }) => (
        <div className="flex flex-wrap gap-1">
          {row.original.tool_coverage.map((tool) => (
            <Badge
              key={tool}
              variant="outline"
              className={TOOL_BADGE_STYLES[tool] ?? 'bg-gray-100 text-gray-800'}
            >
              {TOOL_CATEGORY_LABELS[tool] ?? tool}
            </Badge>
          ))}
        </div>
      ),
    },
    {
      accessorKey: 'severity_breakdown',
      header: t('attackChains.columns.severity'),
      enableSorting: false,
      cell: ({ row }) => {
        const bd = row.original.severity_breakdown
        const items: { key: SeverityLevel; count: number }[] = [
          { key: 'Critical', count: bd.critical },
          { key: 'High', count: bd.high },
          { key: 'Medium', count: bd.medium },
          { key: 'Low', count: bd.low },
          { key: 'Info', count: bd.info },
        ]
        return (
          <div className="flex flex-wrap gap-1">
            {items
              .filter((i) => i.count > 0)
              .map((i) => (
                <Badge key={i.key} className={SEVERITY_STYLES[i.key]}>
                  {i.count} {i.key}
                </Badge>
              ))}
          </div>
        )
      },
    },
    {
      accessorKey: 'uncorrelated_findings',
      header: ({ column }) => (
        <Button variant="ghost" onClick={() => column.toggleSorting()}>
          {t('attackChains.columns.uncorrelated')} <ArrowUpDown className="ml-1 h-3 w-3" />
        </Button>
      ),
      cell: ({ row }) => (
        <span className="font-mono text-sm">{row.original.uncorrelated_findings}</span>
      ),
    },
  ]

  const table = useReactTable({
    data: apps,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })

  return (
    <div className="space-y-4">
      <PageHeader title={t('attackChains.title')}>
        <span className="text-sm text-muted-foreground">
          {total} {total === 1 ? t('attackChains.applicationSingular') : t('attackChains.applicationPlural')}
        </span>
      </PageHeader>

      {loading ? (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          {t('common.loading')}
        </div>
      ) : (
        <>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                {table.getHeaderGroups().map((hg) => (
                  <TableRow key={hg.id}>
                    {hg.headers.map((header) => (
                      <TableHead key={header.id}>
                        {header.isPlaceholder
                          ? null
                          : flexRender(header.column.columnDef.header, header.getContext())}
                      </TableHead>
                    ))}
                  </TableRow>
                ))}
              </TableHeader>
              <TableBody>
                {table.getRowModel().rows.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={columns.length} className="h-24 text-center">
                      {t('common.noResults')}
                    </TableCell>
                  </TableRow>
                ) : (
                  table.getRowModel().rows.map((row) => (
                    <TableRow
                      key={row.id}
                      className="cursor-pointer"
                      onClick={() =>
                        navigate({
                          to: '/attack-chains/$appId',
                          params: { appId: row.original.application_id },
                        })
                      }
                    >
                      {row.getVisibleCells().map((cell) => (
                        <TableCell key={cell.id}>
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          {totalPages > 1 && (
            <TablePagination page={page} totalPages={totalPages} onPageChange={setPage} />
          )}
        </>
      )}
    </div>
  )
}
