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
import * as applicationsApi from '@/api/applications'
import type { ApplicationSummary, AssetCriticality, AppStatus } from '@/types/application'

const CRITICALITY_COLORS: Record<AssetCriticality, string> = {
  Very_High: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
  High: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  Medium_High: 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200',
  Medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
  Medium_Low: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  Low: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
}

const STATUS_COLORS: Record<AppStatus, string> = {
  Active: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  Deprecated: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
  Decommissioned: 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200',
}

const columns: ColumnDef<ApplicationSummary>[] = [
  {
    accessorKey: 'app_code',
    header: ({ column }) => (
      <Button variant="ghost" onClick={() => column.toggleSorting()}>
        Code <ArrowUpDown className="ml-1 h-3 w-3" />
      </Button>
    ),
    cell: ({ row }) => (
      <span className="font-mono text-sm">{row.getValue('app_code')}</span>
    ),
  },
  {
    accessorKey: 'app_name',
    header: ({ column }) => (
      <Button variant="ghost" onClick={() => column.toggleSorting()}>
        Name <ArrowUpDown className="ml-1 h-3 w-3" />
      </Button>
    ),
  },
  {
    accessorKey: 'criticality',
    header: 'Criticality',
    cell: ({ row }) => {
      const val = row.getValue<AssetCriticality | null>('criticality')
      if (!val) return <span className="text-muted-foreground">-</span>
      return (
        <Badge variant="outline" className={CRITICALITY_COLORS[val]}>
          {val.replace(/_/g, ' ')}
        </Badge>
      )
    },
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) => {
      const val = row.getValue<AppStatus>('status')
      return (
        <Badge variant="outline" className={STATUS_COLORS[val]}>
          {val}
        </Badge>
      )
    },
  },
  {
    accessorKey: 'business_unit',
    header: 'Business Unit',
    cell: ({ row }) =>
      row.getValue('business_unit') || (
        <span className="text-muted-foreground">-</span>
      ),
  },
  {
    accessorKey: 'is_verified',
    header: 'Verified',
    cell: ({ row }) =>
      row.getValue('is_verified') ? (
        <Badge variant="outline" className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
          Verified
        </Badge>
      ) : (
        <Badge variant="outline" className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
          Unverified
        </Badge>
      ),
  },
]

export function ApplicationsPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [applications, setApplications] = useState<ApplicationSummary[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [sorting, setSorting] = useState<SortingState>([])
  const [loading, setLoading] = useState(false)

  const perPage = 25

  const fetchApplications = useCallback(async () => {
    setLoading(true)
    try {
      const result = await applicationsApi.listApplications({}, page, perPage)
      setApplications(result.items)
      setTotal(result.total)
      setTotalPages(result.total_pages)
    } catch {
      // Error handled by API client
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => {
    fetchApplications()
  }, [fetchApplications])

  const table = useReactTable({
    data: applications,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t('nav.applications')}</h1>
        <span className="text-sm text-muted-foreground">
          {total} {total === 1 ? 'application' : 'applications'}
        </span>
      </div>

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
                      No applications found
                    </TableCell>
                  </TableRow>
                ) : (
                  table.getRowModel().rows.map((row) => (
                    <TableRow
                      key={row.id}
                      className="cursor-pointer"
                      onClick={() =>
                        navigate({ to: '/applications/$id', params: { id: row.original.id } })
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
