import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useParams, useNavigate } from '@tanstack/react-router'
import { ArrowLeft, Clock, MessageSquare, History } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import { FindingStatusBadge } from '@/components/findings/FindingStatusBadge'
import { FindingTransitionDialog } from '@/components/findings/FindingTransitionDialog'
import * as findingsApi from '@/api/findings'
import type {
  FindingDetail,
  FindingHistory,
  FindingComment,
  FindingStatus,
} from '@/types/finding'

/** Valid next statuses from a given status (mirrors backend lifecycle). */
const TRANSITIONS: Partial<Record<FindingStatus, FindingStatus[]>> = {
  New: ['Confirmed'],
  Confirmed: [
    'In_Remediation',
    'False_Positive',
    'False_Positive_Requested',
    'Risk_Accepted',
    'Deferred_Remediation',
  ],
  False_Positive_Requested: ['False_Positive', 'Confirmed'],
  Deferred_Remediation: ['In_Remediation'],
  In_Remediation: ['Mitigated'],
  Mitigated: ['Verified'],
  Verified: ['Closed'],
  Risk_Accepted: ['Confirmed'],
  Closed: ['New'],
}

export function FindingDetailPage() {
  const { t } = useTranslation()
  const { id } = useParams({ strict: false })
  const navigate = useNavigate()
  const [finding, setFinding] = useState<FindingDetail | null>(null)
  const [history, setHistory] = useState<FindingHistory[]>([])
  const [comments, setComments] = useState<FindingComment[]>([])
  const [newComment, setNewComment] = useState('')
  const [transitionTarget, setTransitionTarget] = useState<FindingStatus | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchData = useCallback(async () => {
    if (!id) return
    setLoading(true)
    try {
      const [f, h, c] = await Promise.all([
        findingsApi.getFinding(id),
        findingsApi.getHistory(id),
        findingsApi.listComments(id),
      ])
      setFinding(f)
      setHistory(h)
      setComments(c)
    } catch {
      // handled by client
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  async function handleTransition(data: {
    justification?: string
  }) {
    if (!finding || !transitionTarget) return
    try {
      await findingsApi.updateFindingStatus(
        finding.id,
        transitionTarget,
        data.justification,
      )
      setTransitionTarget(null)
      fetchData()
    } catch {
      // toast
    }
  }

  async function handleAddComment() {
    if (!finding || !newComment.trim()) return
    try {
      const comment = await findingsApi.addComment(finding.id, newComment)
      setComments((prev) => [...prev, comment])
      setNewComment('')
    } catch {
      // toast
    }
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-start gap-4">
          <div className="skeleton h-10 w-10 rounded-md" />
          <div className="flex-1 space-y-2">
            <div className="skeleton h-7 w-2/3" />
            <div className="skeleton h-5 w-1/3" />
          </div>
        </div>
        <div className="skeleton h-[200px] rounded-xl" />
        <div className="skeleton h-[150px] rounded-xl" />
        <div className="skeleton h-[200px] rounded-xl" />
      </div>
    )
  }

  if (!finding) {
    return <div className="text-center text-muted-foreground">{t('findingDetail.notFound')}</div>
  }

  const validTransitions = TRANSITIONS[finding.status] ?? []

  return (
    <div className="space-y-6 animate-in">
      {/* Back button + title */}
      <div className="flex items-start gap-4">
        <Button variant="ghost" size="icon" aria-label={t('common.back')} onClick={() => navigate({ to: '/findings' })}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold">{finding.title}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.normalized_severity} />
            <FindingStatusBadge status={finding.status} />
            <Badge variant="outline">{finding.finding_category}</Badge>
            <span className="text-sm text-muted-foreground">{finding.source_tool}</span>
            {finding.composite_risk_score != null && (
              <span className="text-sm font-mono">{t('findingDetail.risk')}: {finding.composite_risk_score.toFixed(1)}</span>
            )}
          </div>
        </div>
      </div>

      {/* Status transitions */}
      {validTransitions.length > 0 && (
        <div className="space-y-2">
          <p className="text-sm font-medium text-muted-foreground">{t('findingDetail.transitions')}</p>
          <div className="flex flex-wrap gap-2">
            {validTransitions.map((target) => (
              <Button
                key={target}
                variant="outline"
                size="sm"
                onClick={() => setTransitionTarget(target)}
              >
                {t(`findings.status.${target}`)}
              </Button>
            ))}
          </div>
        </div>
      )}

      {/* Core info */}
      <Card className="animate-in stagger-1">
        <CardHeader>
          <CardTitle>{t('findingDetail.details')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p>{finding.description}</p>
          <Separator />
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div><span className="font-medium">{t('findingDetail.originalSeverity')}:</span> {finding.original_severity}</div>
            <div><span className="font-medium">{t('findingDetail.sourceFindingId')}:</span> {finding.source_finding_id}</div>
            <div><span className="font-medium">{t('findingDetail.fingerprint')}:</span> <code className="text-xs">{finding.fingerprint.slice(0, 16)}...</code></div>
            <div><span className="font-medium">{t('findingDetail.firstSeen')}:</span> {new Date(finding.first_seen).toLocaleString()}</div>
            <div><span className="font-medium">{t('findingDetail.lastSeen')}:</span> {new Date(finding.last_seen).toLocaleString()}</div>
            {finding.remediation_owner && <div><span className="font-medium">{t('findingDetail.owner')}:</span> {finding.remediation_owner}</div>}
            {finding.cwe_ids.length > 0 && (
              <div><span className="font-medium">{t('findingDetail.cwe')}:</span> {finding.cwe_ids.join(', ')}</div>
            )}
            {finding.cve_ids.length > 0 && (
              <div><span className="font-medium">{t('findingDetail.cve')}:</span> {finding.cve_ids.join(', ')}</div>
            )}
            {finding.owasp_category && (
              <div><span className="font-medium">{t('findingDetail.owasp')}:</span> {finding.owasp_category}</div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Category-specific info */}
      {finding.sast && (
        <Card className="animate-in stagger-2 border-l-4 border-l-sast">
          <CardHeader><CardTitle>{t('findingDetail.sastDetails')}</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-2 gap-4 text-sm">
            <div><span className="font-medium">{t('findingDetail.file')}:</span> {finding.sast.file_path}</div>
            <div><span className="font-medium">{t('findingDetail.lines')}:</span> {finding.sast.line_number_start}{finding.sast.line_number_end ? `-${finding.sast.line_number_end}` : ''}</div>
            <div><span className="font-medium">{t('findingDetail.rule')}:</span> {finding.sast.rule_name} ({finding.sast.rule_id})</div>
            <div><span className="font-medium">{t('findingDetail.project')}:</span> {finding.sast.project}</div>
            {finding.sast.branch && <div><span className="font-medium">{t('findingDetail.branch')}:</span> {finding.sast.branch}</div>}
            {finding.sast.language && <div><span className="font-medium">{t('findingDetail.language')}:</span> {finding.sast.language}</div>}
            {finding.sast.code_snippet && (
              <div className="col-span-2">
                <span className="font-medium">{t('findingDetail.codeSnippet')}:</span>
                <pre className="mt-1 rounded bg-muted p-3 text-xs overflow-x-auto">{finding.sast.code_snippet}</pre>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {finding.sca && (
        <Card className="animate-in stagger-2 border-l-4 border-l-sca">
          <CardHeader><CardTitle>{t('findingDetail.scaDetails')}</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-2 gap-4 text-sm">
            <div><span className="font-medium">{t('findingDetail.package')}:</span> {finding.sca.package_name}@{finding.sca.package_version}</div>
            {finding.sca.fixed_version && <div><span className="font-medium">{t('findingDetail.fixedVersion')}:</span> {finding.sca.fixed_version}</div>}
            {finding.sca.dependency_type && <div><span className="font-medium">{t('findingDetail.dependency')}:</span> {finding.sca.dependency_type}</div>}
            {finding.sca.epss_score != null && <div><span className="font-medium">{t('findingDetail.epss')}:</span> {finding.sca.epss_score}</div>}
            <div><span className="font-medium">{t('findingDetail.knownExploited')}:</span> {finding.sca.known_exploited ? t('common.yes') : t('common.no')}</div>
          </CardContent>
        </Card>
      )}

      {finding.dast && (
        <Card className="animate-in stagger-2 border-l-4 border-l-dast">
          <CardHeader><CardTitle>{t('findingDetail.dastDetails')}</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-2 gap-4 text-sm">
            <div><span className="font-medium">{t('findingDetail.url')}:</span> {finding.dast.target_url}</div>
            {finding.dast.http_method && <div><span className="font-medium">{t('findingDetail.method')}:</span> {finding.dast.http_method}</div>}
            {finding.dast.parameter && <div><span className="font-medium">{t('findingDetail.parameter')}:</span> {finding.dast.parameter}</div>}
          </CardContent>
        </Card>
      )}

      {/* Tabs: Comments + History + Raw */}
      <Tabs defaultValue="comments" className="animate-in stagger-3">
        <TabsList>
          <TabsTrigger value="comments" className="gap-1">
            <MessageSquare className="h-3 w-3" /> {t('findingDetail.comments')} ({comments.length})
          </TabsTrigger>
          <TabsTrigger value="history" className="gap-1">
            <History className="h-3 w-3" /> {t('findingDetail.history')} ({history.length})
          </TabsTrigger>
          <TabsTrigger value="raw">{t('findingDetail.rawFinding')}</TabsTrigger>
        </TabsList>

        <TabsContent value="comments" className="space-y-4">
          {comments.map((c, idx) => (
            <div key={c.id} className={`animate-in rounded border p-3 ${idx < 8 ? `stagger-${idx + 1}` : ''}`}>
              <div className="flex items-center gap-2 text-sm">
                <span className="font-medium">{c.author_name}</span>
                <span className="text-muted-foreground">{new Date(c.created_at).toLocaleString()}</span>
              </div>
              <p className="mt-1 text-sm">{c.content}</p>
            </div>
          ))}
          <div className="flex gap-2">
            <Input
              placeholder={t('findingDetail.addComment')}
              value={newComment}
              onChange={(e) => setNewComment(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAddComment()}
            />
            <Button onClick={handleAddComment} disabled={!newComment.trim()}>
              {t('findingDetail.send')}
            </Button>
          </div>
        </TabsContent>

        <TabsContent value="history" className="space-y-2">
          {history.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('findingDetail.noHistory')}</p>
          ) : (
            history.map((h) => (
              <div key={h.id} className="flex items-start gap-3 rounded border p-3">
                <Clock className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
                <div className="text-sm">
                  <span className="font-medium">{h.actor_name}</span>{' '}
                  {h.action}: {h.field_changed && `${h.old_value} → ${h.new_value}`}
                  {h.justification && (
                    <span className="text-muted-foreground"> — {h.justification}</span>
                  )}
                  <div className="text-xs text-muted-foreground">
                    {new Date(h.created_at).toLocaleString()}
                  </div>
                </div>
              </div>
            ))
          )}
        </TabsContent>

        <TabsContent value="raw">
          <pre className="max-h-96 overflow-auto rounded bg-muted p-4 text-xs">
            {JSON.stringify(finding.raw_finding, null, 2)}
          </pre>
        </TabsContent>
      </Tabs>

      {/* Transition dialog */}
      {transitionTarget && (
        <FindingTransitionDialog
          open
          onClose={() => setTransitionTarget(null)}
          targetStatus={transitionTarget}
          onConfirm={handleTransition}
        />
      )}
    </div>
  )
}
