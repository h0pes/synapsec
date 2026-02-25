import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  CheckCircle,
  Copy,
  GitCompareArrows,
  History,
  Loader2,
  XCircle,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import * as dedupApi from '@/api/deduplication'
import type { DedupStats, PendingReview, DedupDecision } from '@/types/deduplication'

const PER_PAGE = 10

export function DeduplicationPage() {
  const { t } = useTranslation()

  // Stats
  const [stats, setStats] = useState<DedupStats | null>(null)
  const [statsLoading, setStatsLoading] = useState(true)

  // Pending review table
  const [pending, setPending] = useState<PendingReview[]>([])
  const [pendingTotal, setPendingTotal] = useState(0)
  const [pendingPage, setPendingPage] = useState(1)
  const [pendingTotalPages, setPendingTotalPages] = useState(1)
  const [pendingLoading, setPendingLoading] = useState(true)

  // Decision history table
  const [history, setHistory] = useState<DedupDecision[]>([])
  const [historyTotal, setHistoryTotal] = useState(0)
  const [historyPage, setHistoryPage] = useState(1)
  const [historyTotalPages, setHistoryTotalPages] = useState(1)
  const [historyLoading, setHistoryLoading] = useState(true)

  // In-flight action tracking — prevents double-clicks
  const [actionInFlight, setActionInFlight] = useState<string | null>(null)

  // --- Fetch functions ---

  const fetchStats = useCallback(async () => {
    setStatsLoading(true)
    try {
      const data = await dedupApi.getStats()
      setStats(data)
    } catch {
      // handled by client
    } finally {
      setStatsLoading(false)
    }
  }, [])

  const fetchPending = useCallback(async () => {
    setPendingLoading(true)
    try {
      const result = await dedupApi.listPending(pendingPage, PER_PAGE)
      setPending(result.items)
      setPendingTotal(result.total)
      setPendingTotalPages(result.total_pages)
    } catch {
      // handled by client
    } finally {
      setPendingLoading(false)
    }
  }, [pendingPage])

  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true)
    try {
      const result = await dedupApi.listHistory(historyPage, PER_PAGE)
      setHistory(result.items)
      setHistoryTotal(result.total)
      setHistoryTotalPages(result.total_pages)
    } catch {
      // handled by client
    } finally {
      setHistoryLoading(false)
    }
  }, [historyPage])

  useEffect(() => {
    fetchStats()
  }, [fetchStats])

  useEffect(() => {
    fetchPending()
  }, [fetchPending])

  useEffect(() => {
    fetchHistory()
  }, [fetchHistory])

  // --- Actions ---

  async function handleConfirm(relationshipId: string) {
    setActionInFlight(relationshipId)
    try {
      await dedupApi.confirm(relationshipId)
      // Refresh stats and pending list after action
      await Promise.all([fetchStats(), fetchPending(), fetchHistory()])
    } catch {
      // handled by client
    } finally {
      setActionInFlight(null)
    }
  }

  async function handleReject(relationshipId: string) {
    setActionInFlight(relationshipId)
    try {
      await dedupApi.reject(relationshipId)
      // Refresh stats and pending list after action
      await Promise.all([fetchStats(), fetchPending(), fetchHistory()])
    } catch {
      // handled by client
    } finally {
      setActionInFlight(null)
    }
  }

  // --- Helpers ---

  function confidenceBadgeVariant(confidence: string | null): 'default' | 'secondary' | 'destructive' | 'outline' {
    if (!confidence) return 'outline'
    const lower = confidence.toLowerCase()
    if (lower === 'high') return 'default'
    if (lower === 'medium') return 'secondary'
    return 'outline'
  }

  function actionBadgeClass(action: string): string {
    const lower = action.toLowerCase()
    if (lower === 'confirmed' || lower === 'confirm') {
      return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
    }
    if (lower === 'rejected' || lower === 'reject') {
      return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
    }
    return ''
  }

  // --- Loading state ---

  if (statsLoading && pendingLoading && historyLoading) {
    return (
      <div className="flex h-64 items-center justify-center text-muted-foreground">
        {t('common.loading')}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t('dedup.title')}</h1>

      {/* Section 1 — Statistics cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              {t('dedup.stats.totalDuplicates')}
            </CardTitle>
            <Copy className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {stats?.total_duplicate_relationships ?? 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              {t('dedup.stats.pendingReview')}
            </CardTitle>
            <GitCompareArrows className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600">
              {stats?.pending_review ?? 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              {t('dedup.stats.confirmed')}
            </CardTitle>
            <CheckCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">
              {stats?.confirmed ?? 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              {t('dedup.stats.rejected')}
            </CardTitle>
            <XCircle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">
              {stats?.rejected ?? 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              {t('dedup.stats.totalIngestions')}
            </CardTitle>
            <History className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {stats?.total_ingestions ?? 0}
            </div>
            {stats?.last_ingestion_at && (
              <p className="text-xs text-muted-foreground">
                {t('dedup.stats.lastIngestion')}{' '}
                {new Date(stats.last_ingestion_at).toLocaleDateString()}
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <Separator />

      {/* Section 2 — Pending Review table */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">{t('dedup.pending.title')}</h2>
          <span className="text-sm text-muted-foreground">
            {pendingTotal} {pendingTotal === 1 ? t('dedup.pending.pair') : t('dedup.pending.pairs')}
          </span>
        </div>

        {pendingLoading ? (
          <div className="flex h-32 items-center justify-center text-muted-foreground">
            {t('common.loading')}
          </div>
        ) : pending.length === 0 ? (
          <div className="flex h-32 items-center justify-center text-muted-foreground">
            {t('dedup.pending.noPending')}
          </div>
        ) : (
          <>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('dedup.pending.findingA')}</TableHead>
                    <TableHead>{t('dedup.pending.findingB')}</TableHead>
                    <TableHead>{t('dedup.pending.confidence')}</TableHead>
                    <TableHead>{t('dedup.pending.created')}</TableHead>
                    <TableHead className="w-[140px]">{t('dedup.pending.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pending.map((item) => (
                    <TableRow key={item.relationship_id}>
                      <TableCell>
                        <div>
                          <p className="max-w-[240px] truncate font-medium">{item.source_title}</p>
                          <p className="text-xs text-muted-foreground">{item.source_tool}</p>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div>
                          <p className="max-w-[240px] truncate font-medium">{item.target_title}</p>
                          <p className="text-xs text-muted-foreground">{item.target_tool}</p>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={confidenceBadgeVariant(item.confidence)}>
                          {item.confidence ?? t('dedup.pending.unknown')}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(item.created_at).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            title={t('dedup.actions.confirm')}
                            disabled={actionInFlight === item.relationship_id}
                            onClick={() => handleConfirm(item.relationship_id)}
                          >
                            {actionInFlight === item.relationship_id ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <CheckCircle className="h-4 w-4 text-green-600" />
                            )}
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            title={t('dedup.actions.reject')}
                            disabled={actionInFlight === item.relationship_id}
                            onClick={() => handleReject(item.relationship_id)}
                          >
                            {actionInFlight === item.relationship_id ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              <XCircle className="h-4 w-4 text-red-600" />
                            )}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>

            {pendingTotalPages > 1 && (
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">
                  {t('dedup.pagination.page')} {pendingPage} {t('dedup.pagination.of')} {pendingTotalPages}
                </span>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={pendingPage <= 1}
                    onClick={() => setPendingPage((p) => p - 1)}
                  >
                    {t('dedup.pagination.previous')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={pendingPage >= pendingTotalPages}
                    onClick={() => setPendingPage((p) => p + 1)}
                  >
                    {t('dedup.pagination.next')}
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      <Separator />

      {/* Section 3 — Decision History table */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">{t('dedup.history.title')}</h2>
          <span className="text-sm text-muted-foreground">
            {historyTotal} {historyTotal === 1 ? t('dedup.history.decision') : t('dedup.history.decisions')}
          </span>
        </div>

        {historyLoading ? (
          <div className="flex h-32 items-center justify-center text-muted-foreground">
            {t('common.loading')}
          </div>
        ) : history.length === 0 ? (
          <div className="flex h-32 items-center justify-center text-muted-foreground">
            {t('dedup.history.noHistory')}
          </div>
        ) : (
          <>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('dedup.history.action')}</TableHead>
                    <TableHead>{t('dedup.history.field')}</TableHead>
                    <TableHead>{t('dedup.history.oldValue')}</TableHead>
                    <TableHead>{t('dedup.history.newValue')}</TableHead>
                    <TableHead>{t('dedup.history.actor')}</TableHead>
                    <TableHead>{t('dedup.history.date')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {history.map((item) => (
                    <TableRow key={item.id}>
                      <TableCell>
                        <Badge variant="outline" className={actionBadgeClass(item.action)}>
                          {item.action}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm">
                        {item.field_changed ?? '-'}
                      </TableCell>
                      <TableCell className="max-w-[180px] truncate text-sm text-muted-foreground">
                        {item.old_value ?? '-'}
                      </TableCell>
                      <TableCell className="max-w-[180px] truncate text-sm">
                        {item.new_value ?? '-'}
                      </TableCell>
                      <TableCell className="text-sm">
                        {item.actor_name ?? t('dedup.history.system')}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(item.created_at).toLocaleDateString()}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>

            {historyTotalPages > 1 && (
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">
                  {t('dedup.pagination.page')} {historyPage} {t('dedup.pagination.of')} {historyTotalPages}
                </span>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={historyPage <= 1}
                    onClick={() => setHistoryPage((p) => p - 1)}
                  >
                    {t('dedup.pagination.previous')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={historyPage >= historyTotalPages}
                    onClick={() => setHistoryPage((p) => p + 1)}
                  >
                    {t('dedup.pagination.next')}
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
