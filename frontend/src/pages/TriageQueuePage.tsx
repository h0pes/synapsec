import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from '@tanstack/react-router'
import { CheckCircle, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { TablePagination } from '@/components/ui/table-pagination'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import * as findingsApi from '@/api/findings'
import type { FindingSummary } from '@/types/finding'

export function TriageQueuePage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [findings, setFindings] = useState<FindingSummary[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [loading, setLoading] = useState(false)

  const perPage = 25

  const fetchQueue = useCallback(async () => {
    setLoading(true)
    try {
      const result = await findingsApi.listFindings(
        { status: 'New' },
        page,
        perPage,
      )
      setFindings(result.items)
      setTotal(result.total)
      setTotalPages(result.total_pages)
    } catch {
      // handled by client
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => {
    fetchQueue()
  }, [fetchQueue])

  async function handleConfirm(id: string) {
    try {
      await findingsApi.updateFindingStatus(id, 'Confirmed')
      setFindings((prev) => prev.filter((f) => f.id !== id))
      setTotal((n) => n - 1)
    } catch {
      // handled by client
    }
  }

  async function handleFalsePositive(id: string) {
    try {
      await findingsApi.updateFindingStatus(id, 'False_Positive_Requested', 'Marked from triage queue')
      setFindings((prev) => prev.filter((f) => f.id !== id))
      setTotal((n) => n - 1)
    } catch {
      // handled by client
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t('nav.triage')}</h1>
        <span className="text-sm text-muted-foreground">
          {total} {total === 1 ? 'finding' : 'findings'} awaiting triage
        </span>
      </div>

      {loading ? (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          {t('common.loading')}
        </div>
      ) : findings.length === 0 ? (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          No findings awaiting triage
        </div>
      ) : (
        <>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Title</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead className="text-right">Risk Score</TableHead>
                  <TableHead>First Seen</TableHead>
                  <TableHead className="w-[140px]">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.map((f) => (
                  <TableRow key={f.id}>
                    <TableCell
                      className="max-w-[300px] cursor-pointer truncate font-medium hover:underline"
                      onClick={() =>
                        navigate({ to: '/findings/$id', params: { id: f.id } })
                      }
                    >
                      {f.title}
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={f.normalized_severity} />
                    </TableCell>
                    <TableCell>{f.finding_category}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {f.source_tool}
                    </TableCell>
                    <TableCell className="text-right font-mono text-sm">
                      {f.composite_risk_score?.toFixed(1) ?? '-'}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(f.first_seen).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Confirm"
                          onClick={() => handleConfirm(f.id)}
                        >
                          <CheckCircle className="h-4 w-4 text-green-600" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Request False Positive"
                          onClick={() => handleFalsePositive(f.id)}
                        >
                          <XCircle className="h-4 w-4 text-orange-600" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
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
