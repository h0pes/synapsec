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

const PACKAGE_TYPE_OPTIONS: readonly { value: string; label: string }[] = [
  { value: 'maven', label: 'Maven' },
  { value: 'npm', label: 'npm' },
  { value: 'pypi', label: 'PyPI' },
  { value: 'nuget', label: 'NuGet' },
  { value: 'go', label: 'Go' },
  { value: 'cargo', label: 'Cargo' },
  { value: 'gem', label: 'Gem' },
  { value: 'docker', label: 'Docker' },
]

const KNOWN_EXPLOITED_OPTIONS: readonly { value: string; label: string }[] = [
  { value: 'true', label: 'Yes' },
  { value: 'false', label: 'No' },
]

/**
 * Maps TanStack Table column filter state to backend API query parameter names.
 *
 * Column accessor names (e.g., 'category_data.package_name') are mapped to the
 * flat query parameter names the backend expects (e.g., 'package_name').
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
      case 'category_data.package_name':
        params.package_name = filter.value as string
        break
      case 'category_data.package_version':
        params.package_version = filter.value as string
        break
      case 'category_data.fixed_version':
        // has_fix is the backend param: if a fixed_version filter text is set, we send has_fix=true
        params.has_fix = 'true'
        break
      case 'category_data.package_type':
        params.package_type = filter.value as string
        break
      case 'category_data.known_exploited':
        params.known_exploited = filter.value as string
        break
      case 'category_data.dependency_type':
        params.dependency_type = filter.value as string
        break
      case 'first_seen': {
        const range = filter.value as DateRangeFilterValue | undefined
        if (range?.from) params.published_from = range.from
        if (range?.to) params.published_to = range.to
        break
      }
    }
  }

  return params
}

interface ScaTableProps {
  findings: FindingSummaryWithCategory[]
  onRowClick: (id: string) => void
  onFiltersChange: (filters: Record<string, string>) => void
  sorting: SortingState
  onSortingChange: OnChangeFn<SortingState>
}

export function ScaTable({
  findings,
  onRowClick,
  onFiltersChange,
  sorting,
  onSortingChange,
}: ScaTableProps) {
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
        id: 'category_data.package_name',
        accessorFn: (row) => row.category_data?.package_name ?? '',
        header: t('findings.columns.packageName'),
        cell: ({ row }) => (
          <span className="font-mono text-sm">
            {row.original.category_data?.package_name ?? '-'}
          </span>
        ),
        size: 140,
        enableColumnFilter: true,
        meta: { filterVariant: 'text' },
      },
      {
        id: 'category_data.package_version',
        accessorFn: (row) => row.category_data?.package_version ?? '',
        header: t('findings.columns.packageVersion'),
        cell: ({ row }) => (
          <span className="font-mono text-sm">
            {row.original.category_data?.package_version ?? '-'}
          </span>
        ),
        size: 100,
        enableColumnFilter: true,
        meta: { filterVariant: 'text' },
      },
      {
        id: 'category_data.fixed_version',
        accessorFn: (row) => row.category_data?.fixed_version ?? '',
        header: t('findings.columns.fixedVersion'),
        cell: ({ row }) => (
          <span className="font-mono text-sm">
            {row.original.category_data?.fixed_version ?? (
              <span className="text-muted-foreground">-</span>
            )}
          </span>
        ),
        size: 110,
        enableColumnFilter: true,
        meta: { filterVariant: 'text' },
      },
      {
        id: 'category_data.package_type',
        accessorFn: (row) => row.category_data?.package_type ?? '',
        header: t('findings.columns.packageType'),
        cell: ({ row }) =>
          row.original.category_data?.package_type ? (
            <Badge variant="outline">{row.original.category_data.package_type}</Badge>
          ) : (
            '-'
          ),
        size: 100,
        enableColumnFilter: true,
        meta: { filterVariant: 'select', filterOptions: PACKAGE_TYPE_OPTIONS },
      },
      {
        id: 'category_data.known_exploited',
        accessorFn: (row) =>
          row.category_data?.known_exploited != null
            ? String(row.category_data.known_exploited)
            : '',
        header: t('findings.columns.knownExploited'),
        cell: ({ row }) => {
          const exploited = row.original.category_data?.known_exploited
          if (exploited == null) return '-'
          return exploited ? (
            <Badge className="bg-red-600 text-white">{t('findings.yes')}</Badge>
          ) : (
            <span className="text-muted-foreground">{t('findings.no')}</span>
          )
        },
        size: 110,
        enableColumnFilter: true,
        meta: { filterVariant: 'select', filterOptions: KNOWN_EXPLOITED_OPTIONS },
      },
      {
        id: 'category_data.dependency_type',
        accessorFn: (row) => row.category_data?.dependency_type ?? '',
        header: t('findings.columns.dependencyType'),
        cell: ({ row }) =>
          row.original.category_data?.dependency_type ? (
            <Badge variant="outline">{row.original.category_data.dependency_type}</Badge>
          ) : (
            '-'
          ),
        size: 110,
        enableColumnFilter: true,
        meta: { filterVariant: 'text' },
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
