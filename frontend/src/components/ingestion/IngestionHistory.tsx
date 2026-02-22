import { useCallback, useEffect, useState } from 'react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import * as ingestionApi from '@/api/ingestion'
import type { IngestionLogSummary, IngestionLog, IngestionStatus } from '@/api/ingestion'

const STATUS_COLORS: Record<IngestionStatus, string> = {
  Completed: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  Partial: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
  Failed: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
}

type Props = {
  refreshTrigger: number
}

export function IngestionHistory({ refreshTrigger }: Props) {
  const [logs, setLogs] = useState<IngestionLogSummary[]>([])
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [loading, setLoading] = useState(false)
  const [selectedLog, setSelectedLog] = useState<IngestionLog | null>(null)

  const fetchHistory = useCallback(async () => {
    setLoading(true)
    try {
      const result = await ingestionApi.listHistory(page)
      setLogs(result.items)
      setTotalPages(result.total_pages)
    } catch {
      // handled by client
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => {
    fetchHistory()
  }, [fetchHistory, refreshTrigger])

  async function handleRowClick(id: string) {
    try {
      const log = await ingestionApi.getLog(id)
      setSelectedLog(log)
    } catch {
      // handled by client
    }
  }

  return (
    <div className="space-y-4">
      {loading ? (
        <div className="flex h-32 items-center justify-center text-muted-foreground">
          Loading...
        </div>
      ) : logs.length === 0 ? (
        <div className="flex h-32 items-center justify-center text-muted-foreground">
          No ingestion history yet
        </div>
      ) : (
        <>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Source</TableHead>
                  <TableHead>File</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Total</TableHead>
                  <TableHead className="text-right">New</TableHead>
                  <TableHead className="text-right">Updated</TableHead>
                  <TableHead className="text-right">Dupes</TableHead>
                  <TableHead className="text-right">Errors</TableHead>
                  <TableHead>Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.map((log) => (
                  <TableRow
                    key={log.id}
                    className="cursor-pointer"
                    onClick={() => handleRowClick(log.id)}
                  >
                    <TableCell className="font-medium">{log.source_tool}</TableCell>
                    <TableCell className="max-w-[200px] truncate text-sm">
                      {log.file_name || '-'}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={STATUS_COLORS[log.status]}>
                        {log.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">{log.total_records}</TableCell>
                    <TableCell className="text-right">{log.new_findings}</TableCell>
                    <TableCell className="text-right">{log.updated_findings}</TableCell>
                    <TableCell className="text-right">{log.duplicates}</TableCell>
                    <TableCell className="text-right">
                      {log.errors > 0 ? (
                        <span className="text-destructive">{log.errors}</span>
                      ) : (
                        log.errors
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {log.completed_at
                        ? new Date(log.completed_at).toLocaleString()
                        : 'In progress'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

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

      {/* Error detail dialog */}
      {selectedLog && (
        <Dialog open onOpenChange={() => setSelectedLog(null)}>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>
                Ingestion Details — {selectedLog.source_tool}
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-3 text-sm">
              <div className="grid grid-cols-2 gap-4">
                <div><span className="font-medium">File:</span> {selectedLog.file_name || '-'}</div>
                <div><span className="font-medium">Type:</span> {selectedLog.ingestion_type}</div>
                <div><span className="font-medium">Status:</span>{' '}
                  <Badge variant="outline" className={STATUS_COLORS[selectedLog.status]}>
                    {selectedLog.status}
                  </Badge>
                </div>
                <div><span className="font-medium">Initiated by:</span> {selectedLog.initiated_by || '-'}</div>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div><span className="font-medium">Total:</span> {selectedLog.total_records}</div>
                <div><span className="font-medium">New:</span> {selectedLog.new_findings}</div>
                <div><span className="font-medium">Updated:</span> {selectedLog.updated_findings}</div>
                <div><span className="font-medium">Duplicates:</span> {selectedLog.duplicates}</div>
                <div><span className="font-medium">Errors:</span> {selectedLog.errors}</div>
                <div><span className="font-medium">Quarantined:</span> {selectedLog.quarantined}</div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div><span className="font-medium">Started:</span> {new Date(selectedLog.started_at).toLocaleString()}</div>
                <div><span className="font-medium">Completed:</span>{' '}
                  {selectedLog.completed_at ? new Date(selectedLog.completed_at).toLocaleString() : 'In progress'}
                </div>
              </div>
              {selectedLog.error_details != null && (
                <div>
                  <span className="font-medium">Error Details:</span>
                  <pre className="mt-1 max-h-64 overflow-auto rounded bg-muted p-3 text-xs">
                    {String(JSON.stringify(selectedLog.error_details, null, 2))}
                  </pre>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  )
}
