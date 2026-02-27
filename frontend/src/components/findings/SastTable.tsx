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
 * Column accessor names (e.g., 'category_data.branch') are mapped to the
 * flat query parameter names the backend expects (e.g., 'branch').
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
      case 'category_data.rule_id':
        params.rule_id = filter.value as string
        break
      case 'category_data.project':
        params.project = filter.value as string
        break
      case 'category_data.branch':
        params.branch = filter.value as string
        break
      case 'first_seen': {
        const range = filter.value as DateRangeFilterValue | undefined
        if (range?.from) params.sast_created_from = range.from
        if (range?.to) params.sast_created_to = range.to
        break
      }
    }
  }

  return params
}

interface SastTableProps {
  findings: FindingSummaryWithCategory[]
  onRowClick: (id: string) => void
  onFiltersChange: (filters: Record<string, string>) => void
  sorting: SortingState
  onSortingChange: OnChangeFn<SortingState>
}

export function SastTable({
  findings,
  onRowClick,
  onFiltersChange,
  sorting,
  onSortingChange,
}: SastTableProps) {
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
        id: 'category_data.file_path',
        accessorFn: (row) => row.category_data?.file_path ?? '',
        header: t('findings.columns.filePath'),
        cell: ({ row }) => (
          <span
            className="max-w-[200px] truncate font-mono text-xs"
            title={row.original.category_data?.file_path}
          >
            {row.original.category_data?.file_path ?? '-'}
          </span>
        ),
        size: 200,
        enableColumnFilter: false,
      },
      {
        id: 'category_data.line_number',
        accessorFn: (row) => row.category_data?.line_number ?? null,
        header: t('findings.columns.lineNumber'),
        cell: ({ row }) => (
          <span className="font-mono text-sm">
            {row.original.category_data?.line_number ?? '-'}
          </span>
        ),
        size: 60,
        enableColumnFilter: false,
      },
      {
        id: 'category_data.rule_id',
        accessorFn: (row) => row.category_data?.rule_id ?? '',
        header: t('findings.columns.ruleId'),
        cell: ({ row }) => (
          <span className="font-mono text-xs">
            {row.original.category_data?.rule_id ?? '-'}
          </span>
        ),
        size: 120,
        enableColumnFilter: true,
        meta: { filterVariant: 'text' },
      },
      {
        id: 'category_data.project',
        accessorFn: (row) => row.category_data?.project ?? '',
        header: t('findings.columns.project'),
        cell: ({ row }) => row.original.category_data?.project ?? '-',
        size: 120,
        enableColumnFilter: true,
        meta: { filterVariant: 'text' },
      },
      {
        id: 'category_data.branch',
        accessorFn: (row) => row.category_data?.branch ?? '',
        header: t('findings.columns.branch'),
        cell: ({ row }) => row.original.category_data?.branch ?? '-',
        size: 100,
        enableColumnFilter: true,
        meta: { filterVariant: 'text' },
      },
      {
        id: 'category_data.language',
        accessorFn: (row) => row.category_data?.language ?? '',
        header: t('findings.columns.language'),
        cell: ({ row }) =>
          row.original.category_data?.language ? (
            <Badge variant="outline">{row.original.category_data.language}</Badge>
          ) : (
            '-'
          ),
        size: 90,
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
