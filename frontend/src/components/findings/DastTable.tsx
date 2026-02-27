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
import { SeverityBadge } from './SeverityBadge'
import { FindingStatusBadge } from './FindingStatusBadge'
import {
  TextColumnFilter,
  SelectColumnFilter,
  DateRangeColumnFilter,
} from '@/components/findings/filters'
import type { FindingSummaryWithCategory } from '@/types/finding'

interface DateRangeFilterValue {
  from: string
  to: string
}

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

/**
 * Maps TanStack Table column filter state to backend API query parameter names.
 *
 * Column accessor names (e.g., 'category_data.target_url') are mapped to the
 * flat query parameter names the backend expects (e.g., 'target_url').
 * Date range filters are split into separate _from and _to params.
 */
function mapFiltersToApiParams(columnFilters: ColumnFiltersState): Record<string, string> {
  const params: Record<string, string> = {}

  for (const filter of columnFilters) {
    switch (filter.id) {
      case 'title':
        params.search = filter.value as string
        break
      case 'normalized_severity':
        params.severity = filter.value as string
        break
      case 'status':
        params.status = filter.value as string
        break
      case 'category_data.target_url':
        params.target_url = filter.value as string
        break
      case 'category_data.web_application_name':
        params.dns_name = filter.value as string
        break
      case 'first_seen': {
        const range = filter.value as DateRangeFilterValue | undefined
        if (range?.from) params.discovered_from = range.from
        if (range?.to) params.discovered_to = range.to
        break
      }
    }
  }

  return params
}

interface DastTableProps {
  findings: FindingSummaryWithCategory[]
  onRowClick: (id: string) => void
  onFiltersChange: (filters: Record<string, string>) => void
  sorting: SortingState
  onSortingChange: OnChangeFn<SortingState>
}

export function DastTable({
  findings,
  onRowClick,
  onFiltersChange,
  sorting,
  onSortingChange,
}: DastTableProps) {
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

  const columns = useMemo<ColumnDef<FindingSummaryWithCategory>[]>(
    () => [
      {
        accessorKey: 'title',
        header: t('findings.columns.title'),
        cell: ({ row }) => (
          <span className="font-medium">{row.original.title}</span>
        ),
        size: 280,
        enableColumnFilter: true,
        meta: { filterVariant: 'text' },
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
        id: 'category_data.target_url',
        accessorFn: (row) => row.category_data?.target_url ?? '',
        header: t('findings.columns.targetUrl'),
        cell: ({ row }) => (
          <span
            className="max-w-[250px] truncate font-mono text-xs"
            title={row.original.category_data?.target_url}
          >
            {row.original.category_data?.target_url ?? '-'}
          </span>
        ),
        size: 250,
        enableColumnFilter: true,
        meta: { filterVariant: 'text' },
      },
      {
        id: 'category_data.parameter',
        accessorFn: (row) => row.category_data?.parameter ?? '',
        header: t('findings.columns.parameter'),
        cell: ({ row }) => (
          <span className="font-mono text-sm">
            {row.original.category_data?.parameter ?? '-'}
          </span>
        ),
        size: 140,
        enableColumnFilter: false,
      },
      {
        id: 'category_data.web_application_name',
        accessorFn: (row) => row.category_data?.web_application_name ?? '',
        header: t('findings.columns.webAppName'),
        cell: ({ row }) => row.original.category_data?.web_application_name ?? '-',
        size: 180,
        enableColumnFilter: true,
        meta: { filterVariant: 'text' },
      },
      {
        id: 'category_data.http_method',
        accessorFn: (row) => row.category_data?.http_method ?? '',
        header: t('findings.columns.httpMethod'),
        cell: ({ row }) =>
          row.original.category_data?.http_method ? (
            <span className="font-mono text-sm font-semibold">
              {row.original.category_data.http_method}
            </span>
          ) : (
            '-'
          ),
        size: 100,
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
        size: 170,
        enableColumnFilter: true,
        meta: { filterVariant: 'dateRange' },
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
    <div className="rounded-md border shadow-[var(--shadow-card)]">
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
                className="cursor-pointer transition-colors hover:bg-muted/50"
                role="link"
                tabIndex={0}
                onClick={() => handleRowClick(row.original.id)}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleRowClick(row.original.id) } }}
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
    case 'text':
      return <TextColumnFilter column={column} />
    case 'select':
      return (
        <SelectColumnFilter
          column={column}
          options={meta.filterOptions ?? []}
        />
      )
    case 'dateRange':
      return <DateRangeColumnFilter column={column} />
    default:
      return null
  }
}
