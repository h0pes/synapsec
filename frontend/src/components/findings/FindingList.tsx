import { useMemo, useEffect, useState, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  type ColumnDef,
  type ColumnFiltersState,
  type SortingState,
  type OnChangeFn,
} from '@tanstack/react-table'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from './SeverityBadge'
import { FindingStatusBadge } from './FindingStatusBadge'
import { SelectColumnFilter } from '@/components/findings/filters'
import type { FindingSummary } from '@/types/finding'

const SEVERITY_OPTIONS: readonly { value: string; label: string }[] = [
  { value: 'Critical', label: 'Critical' },
  { value: 'High', label: 'High' },
  { value: 'Medium', label: 'Medium' },
  { value: 'Low', label: 'Low' },
  { value: 'Info', label: 'Info' },
]

const STATUS_OPTIONS: readonly { value: string; label: string }[] = [
  { value: 'New', label: 'New' },
  { value: 'Confirmed', label: 'Confirmed' },
  { value: 'In_Remediation', label: 'In Remediation' },
  { value: 'Mitigated', label: 'Mitigated' },
  { value: 'Verified', label: 'Verified' },
  { value: 'Closed', label: 'Closed' },
  { value: 'False_Positive', label: 'False Positive' },
  { value: 'Risk_Accepted', label: 'Risk Accepted' },
]

const CATEGORY_OPTIONS: readonly { value: string; label: string }[] = [
  { value: 'SAST', label: 'SAST' },
  { value: 'SCA', label: 'SCA' },
  { value: 'DAST', label: 'DAST' },
]

/**
 * Maps TanStack Table column filter state to backend API query parameter names.
 */
function mapFiltersToApiParams(columnFilters: ColumnFiltersState): Record<string, string> {
  const params: Record<string, string> = {}

  for (const filter of columnFilters) {
    switch (filter.id) {
      case 'normalized_severity':
        params.severity = filter.value as string
        break
      case 'status':
        params.status = filter.value as string
        break
      case 'finding_category':
        params.category = filter.value as string
        break
    }
  }

  return params
}

interface FindingListProps {
  findings: FindingSummary[]
  onRowClick: (id: string) => void
  onFiltersChange: (filters: Record<string, string>) => void
  sorting: SortingState
  onSortingChange: OnChangeFn<SortingState>
}

export function FindingList({
  findings,
  onRowClick,
  onFiltersChange,
  sorting,
  onSortingChange,
}: FindingListProps) {
  const { t } = useTranslation()
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([])
  const prevParamsRef = useRef<string>('')

  // Propagate column filter changes to parent as API params
  useEffect(() => {
    const params = mapFiltersToApiParams(columnFilters)
    const serialized = JSON.stringify(params)
    if (serialized !== prevParamsRef.current) {
      prevParamsRef.current = serialized
      onFiltersChange(params)
    }
  }, [columnFilters, onFiltersChange])

  const columns = useMemo<ColumnDef<FindingSummary>[]>(
    () => [
      {
        accessorKey: 'title',
        header: t('findings.columns.title'),
        cell: ({ row }) => (
          <span className="font-medium">{row.original.title}</span>
        ),
        size: 350,
        enableColumnFilter: false,
      },
      {
        accessorKey: 'normalized_severity',
        header: t('findings.columns.severity'),
        cell: ({ row }) => (
          <SeverityBadge severity={row.original.normalized_severity} />
        ),
        size: 100,
        enableColumnFilter: true,
        meta: { filterVariant: 'select', filterOptions: SEVERITY_OPTIONS },
      },
      {
        accessorKey: 'status',
        header: t('findings.columns.status'),
        cell: ({ row }) => (
          <FindingStatusBadge status={row.original.status} />
        ),
        size: 140,
        enableColumnFilter: true,
        meta: { filterVariant: 'select', filterOptions: STATUS_OPTIONS },
      },
      {
        accessorKey: 'finding_category',
        header: t('findings.columns.category'),
        cell: ({ row }) => (
          <Badge variant="outline">{row.original.finding_category}</Badge>
        ),
        size: 80,
        enableColumnFilter: true,
        meta: { filterVariant: 'select', filterOptions: CATEGORY_OPTIONS },
      },
      {
        accessorKey: 'source_tool',
        header: t('findings.columns.source'),
        size: 120,
        enableColumnFilter: false,
      },
      {
        accessorKey: 'composite_risk_score',
        header: t('findings.columns.risk'),
        cell: ({ row }) => {
          const score = row.original.composite_risk_score
          return score != null ? (
            <span className="font-mono text-sm">{score.toFixed(1)}</span>
          ) : (
            <span className="text-muted-foreground">-</span>
          )
        },
        size: 70,
        enableColumnFilter: false,
      },
      {
        accessorKey: 'first_seen',
        header: t('findings.columns.firstSeen'),
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {new Date(row.original.first_seen).toLocaleDateString()}
          </span>
        ),
        size: 100,
        enableColumnFilter: false,
      },
    ],
    [t],
  )

  const table = useReactTable({
    data: findings,
    columns,
    state: { columnFilters, sorting },
    onColumnFiltersChange: setColumnFilters,
    onSortingChange,
    manualFiltering: true,
    manualSorting: true,
    getCoreRowModel: getCoreRowModel(),
  })

  const handleRowClick = useCallback(
    (id: string) => onRowClick(id),
    [onRowClick],
  )

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          {table.getHeaderGroups().map((headerGroup) => (
            <TableRow key={headerGroup.id}>
              {headerGroup.headers.map((header) => (
                <TableHead
                  key={header.id}
                  className="cursor-pointer select-none"
                  onClick={header.column.getToggleSortingHandler()}
                  style={{ width: header.getSize() }}
                >
                  <div className="flex items-center gap-1">
                    {flexRender(header.column.columnDef.header, header.getContext())}
                    {header.column.getIsSorted() === 'asc' && ' \u2191'}
                    {header.column.getIsSorted() === 'desc' && ' \u2193'}
                  </div>
                </TableHead>
              ))}
            </TableRow>
          ))}
          {/* Filter row */}
          <TableRow>
            {table.getHeaderGroups()[0].headers.map((header) => (
              <TableHead key={`filter-${header.id}`} className="px-2 py-1">
                {header.column.getCanFilter() ? (
                  renderColumnFilter(header.column)
                ) : null}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows.length === 0 ? (
            <TableRow>
              <TableCell
                colSpan={columns.length}
                className="h-32 text-center text-muted-foreground"
              >
                {t('findings.noFindings')}
              </TableCell>
            </TableRow>
          ) : (
            table.getRowModel().rows.map((row) => (
              <TableRow
                key={row.id}
                className="cursor-pointer"
                onClick={() => handleRowClick(row.original.id)}
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
  )
}

/** Render the appropriate filter widget based on column meta.filterVariant */
function renderColumnFilter(column: ReturnType<ReturnType<typeof useReactTable>['getHeaderGroups']>[0]['headers'][0]['column']) {
  const meta = column.columnDef.meta as
    | { filterVariant?: string; filterOptions?: readonly { value: string; label: string }[] }
    | undefined

  switch (meta?.filterVariant) {
    case 'select':
      return (
        <SelectColumnFilter
          column={column}
          options={meta.filterOptions ?? []}
        />
      )
    default:
      return null
  }
}
