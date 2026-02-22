import { useMemo } from 'react'
import { useNavigate } from '@tanstack/react-router'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
  type ColumnDef,
  type SortingState,
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
import type { FindingSummary } from '@/types/finding'

type Props = {
  findings: FindingSummary[]
  sorting: SortingState
  onSortingChange: (sorting: SortingState) => void
}

export function FindingList({ findings, sorting, onSortingChange }: Props) {
  const navigate = useNavigate()

  const columns = useMemo<ColumnDef<FindingSummary>[]>(
    () => [
      {
        accessorKey: 'title',
        header: 'Title',
        cell: ({ row }) => (
          <span className="font-medium">{row.original.title}</span>
        ),
        size: 350,
      },
      {
        accessorKey: 'normalized_severity',
        header: 'Severity',
        cell: ({ row }) => (
          <SeverityBadge severity={row.original.normalized_severity} />
        ),
        size: 100,
      },
      {
        accessorKey: 'status',
        header: 'Status',
        cell: ({ row }) => (
          <FindingStatusBadge status={row.original.status} />
        ),
        size: 140,
      },
      {
        accessorKey: 'finding_category',
        header: 'Category',
        cell: ({ row }) => (
          <Badge variant="outline">{row.original.finding_category}</Badge>
        ),
        size: 80,
      },
      {
        accessorKey: 'source_tool',
        header: 'Source',
        size: 120,
      },
      {
        accessorKey: 'composite_risk_score',
        header: 'Risk',
        cell: ({ row }) => {
          const score = row.original.composite_risk_score
          return score != null ? (
            <span className="font-mono text-sm">{score.toFixed(1)}</span>
          ) : (
            <span className="text-muted-foreground">-</span>
          )
        },
        size: 70,
      },
      {
        accessorKey: 'first_seen',
        header: 'First Seen',
        cell: ({ row }) => (
          <span className="text-sm text-muted-foreground">
            {new Date(row.original.first_seen).toLocaleDateString()}
          </span>
        ),
        size: 100,
      },
    ],
    [],
  )

  const table = useReactTable({
    data: findings,
    columns,
    state: { sorting },
    onSortingChange: (updater) => {
      const next = typeof updater === 'function' ? updater(sorting) : updater
      onSortingChange(next)
    },
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    manualSorting: false,
  })

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
                    {flexRender(
                      header.column.columnDef.header,
                      header.getContext(),
                    )}
                    {header.column.getIsSorted() === 'asc' && ' \u2191'}
                    {header.column.getIsSorted() === 'desc' && ' \u2193'}
                  </div>
                </TableHead>
              ))}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows.length === 0 ? (
            <TableRow>
              <TableCell
                colSpan={columns.length}
                className="h-32 text-center text-muted-foreground"
              >
                No findings found
              </TableCell>
            </TableRow>
          ) : (
            table.getRowModel().rows.map((row) => (
              <TableRow
                key={row.id}
                className="cursor-pointer"
                onClick={() =>
                  navigate({ to: '/findings/$id', params: { id: row.original.id } })
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
  )
}
