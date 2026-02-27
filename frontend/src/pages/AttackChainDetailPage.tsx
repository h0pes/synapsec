import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useParams, useNavigate } from '@tanstack/react-router'
import { ArrowLeft, Link2, LayoutList, Network } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import { AttackChainGraph } from '@/components/attack-chains/graph/AttackChainGraph'
import {
  normalizeSeverity,
  TOOL_BADGE_STYLES,
  TOOL_CATEGORY_LABELS,
  CATEGORY_BADGE_STYLES,
} from '@/lib/findings'
import * as attackChainsApi from '@/api/attack-chains'
import type { AppAttackChainDetail, AttackChain } from '@/types/attack-chains'

type ViewMode = 'cards' | 'graph'

/** Derive a human-readable title for an attack chain. */
function chainTitle(chain: AttackChain): string {
  if (chain.findings.length > 0) {
    return chain.findings[0].title
  }
  return chain.group_id
}

export function AttackChainDetailPage() {
  const { t } = useTranslation()
  const { appId } = useParams({ strict: false })
  const navigate = useNavigate()
  const [detail, setDetail] = useState<AppAttackChainDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [viewMode, setViewMode] = useState<ViewMode>('cards')

  const fetchDetail = useCallback(async () => {
    if (!appId) return
    setLoading(true)
    try {
      const data = await attackChainsApi.getAttackChainsByApp(appId)
      setDetail(data)
    } catch {
      // Error handled by API client
    } finally {
      setLoading(false)
    }
  }, [appId])

  useEffect(() => {
    fetchDetail()
  }, [fetchDetail])

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center text-muted-foreground">
        {t('common.loading')}
      </div>
    )
  }

  if (!detail) {
    return (
      <div className="text-center text-muted-foreground">
        {t('attackChains.detail.notFound')}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start gap-4">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => navigate({ to: '/attack-chains' })}
        >
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold">{detail.app_name}</h1>
            <span className="font-mono text-sm text-muted-foreground">
              {detail.app_code}
            </span>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            {t('attackChains.detail.chainCount', { count: detail.chains.length })}
            {' \u00B7 '}
            {t('attackChains.detail.uncorrelatedCount', { count: detail.uncorrelated_findings.length })}
          </p>
        </div>

        {/* Cards / Graph toggle */}
        <div className="inline-flex rounded-md border">
          <Button
            variant={viewMode === 'cards' ? 'default' : 'ghost'}
            size="sm"
            className="gap-1.5 rounded-r-none"
            onClick={() => setViewMode('cards')}
          >
            <LayoutList className="h-4 w-4" />
            {t('attackChains.viewCards')}
          </Button>
          <Button
            variant={viewMode === 'graph' ? 'default' : 'ghost'}
            size="sm"
            className="gap-1.5 rounded-l-none"
            onClick={() => setViewMode('graph')}
          >
            <Network className="h-4 w-4" />
            {t('attackChains.viewGraph')}
          </Button>
        </div>
      </div>

      {/* Graph View */}
      {viewMode === 'graph' && (
        <AttackChainGraph detail={detail} />
      )}

      {/* Cards View */}
      {viewMode === 'cards' && (
        <>
          {/* Attack Chain Cards */}
          {detail.chains.length > 0 && (
            <div className="space-y-4">
              <h2 className="text-lg font-semibold">{t('attackChains.detail.chainsTitle')}</h2>
              {detail.chains.map((chain) => (
                <Card key={chain.group_id}>
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between gap-4">
                      <CardTitle className="text-base leading-snug">
                        {chainTitle(chain)}
                      </CardTitle>
                      <div className="flex shrink-0 items-center gap-2">
                        <SeverityBadge severity={normalizeSeverity(chain.max_severity)} />
                        {chain.tool_coverage.map((tool) => (
                          <Badge
                            key={tool}
                            variant="outline"
                            className={TOOL_BADGE_STYLES[tool] ?? 'bg-gray-100 text-gray-800'}
                          >
                            {TOOL_CATEGORY_LABELS[tool] ?? tool}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <div className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
                      <Link2 className="h-3 w-3" />
                      {t('attackChains.detail.relationships', { count: chain.relationship_count })}
                      {' \u00B7 '}
                      {t('attackChains.detail.findings', { count: chain.findings.length })}
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {chain.findings.map((finding) => (
                        <div
                          key={finding.id}
                          className="flex items-center gap-3 rounded-md border px-3 py-2 text-sm"
                        >
                          <Badge
                            variant="outline"
                            className={CATEGORY_BADGE_STYLES[finding.finding_category] ?? ''}
                          >
                            {finding.finding_category}
                          </Badge>
                          <SeverityBadge severity={normalizeSeverity(finding.normalized_severity)} />
                          <span className="flex-1 truncate">{finding.title}</span>
                          <span className="shrink-0 text-xs text-muted-foreground">
                            {TOOL_CATEGORY_LABELS[finding.source_tool] ?? finding.source_tool}
                          </span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {/* Uncorrelated Findings */}
          {detail.uncorrelated_findings.length > 0 && (
            <div className="space-y-3">
              <h2 className="text-lg font-semibold">
                {t('attackChains.detail.uncorrelatedTitle')}
                <span className="ml-2 text-sm font-normal text-muted-foreground">
                  ({detail.uncorrelated_findings.length})
                </span>
              </h2>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t('attackChains.detail.columnTitle')}</TableHead>
                      <TableHead>{t('attackChains.detail.columnSeverity')}</TableHead>
                      <TableHead>{t('attackChains.detail.columnCategory')}</TableHead>
                      <TableHead>{t('attackChains.detail.columnSource')}</TableHead>
                      <TableHead>{t('attackChains.detail.columnStatus')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {detail.uncorrelated_findings.map((f) => (
                      <TableRow key={f.id}>
                        <TableCell className="max-w-[300px] truncate font-medium">
                          {f.title}
                        </TableCell>
                        <TableCell>
                          <SeverityBadge severity={normalizeSeverity(f.normalized_severity)} />
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={CATEGORY_BADGE_STYLES[f.finding_category] ?? ''}
                          >
                            {f.finding_category}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {TOOL_CATEGORY_LABELS[f.source_tool] ?? f.source_tool}
                        </TableCell>
                        <TableCell className="text-sm">{f.status}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
          )}

          {detail.chains.length === 0 && detail.uncorrelated_findings.length === 0 && (
            <div className="flex h-32 items-center justify-center text-muted-foreground">
              {t('attackChains.detail.noData')}
            </div>
          )}
        </>
      )}
    </div>
  )
}
