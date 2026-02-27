import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from '@tanstack/react-router'
import {
  AlertTriangle,
  Clock,
  FileWarning,
  Shield,
  TrendingUp,
  Upload,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { PageHeader } from '@/components/ui/page-header'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import { SeverityChart } from '@/components/dashboard/SeverityChart'
import { SourceToolChart } from '@/components/dashboard/SourceToolChart'
import { TopAppsChart } from '@/components/dashboard/TopAppsChart'
import { SlaChart } from '@/components/dashboard/SlaChart'
import * as dashboardApi from '@/api/dashboard'
import type { DashboardStats } from '@/api/dashboard'

export function DashboardPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchStats = useCallback(async () => {
    setLoading(true)
    try {
      const data = await dashboardApi.getStats()
      setStats(data)
    } catch {
      // handled by client
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchStats()
  }, [fetchStats])

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="skeleton h-8 w-48" />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="skeleton h-[120px] rounded-xl" />
          ))}
        </div>
        <div className="grid gap-6 md:grid-cols-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="skeleton h-[300px] rounded-xl" />
          ))}
        </div>
      </div>
    )
  }

  if (!stats) {
    return (
      <div className="space-y-4">
        <PageHeader title={t('nav.dashboard')} />
        <p className="text-muted-foreground">{t('dashboard.loadError')}</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader title={t('nav.dashboard')} />

      {/* Summary cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card
          className="animate-in stagger-1 card-interactive cursor-pointer transition-colors hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring"
          role="button"
          tabIndex={0}
          onClick={() => navigate({ to: '/triage' })}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigate({ to: '/triage' }) } }}
        >
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('dashboard.awaitingTriage')}</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.triage_count}</div>
            <p className="text-xs text-muted-foreground">{t('dashboard.findingsInNewStatus')}</p>
          </CardContent>
        </Card>

        <Card
          className="animate-in stagger-2 card-interactive cursor-pointer transition-colors hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring"
          role="button"
          tabIndex={0}
          onClick={() => navigate({ to: '/unmapped' })}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigate({ to: '/unmapped' }) } }}
        >
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('dashboard.unmappedApps')}</CardTitle>
            <FileWarning className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.unmapped_apps_count}</div>
            <p className="text-xs text-muted-foreground">{t('dashboard.unverifiedApplications')}</p>
          </CardContent>
        </Card>

        <Card className="animate-in stagger-3 card-interactive">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('dashboard.slaStatus')}</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline gap-3">
              <span className="text-2xl font-bold text-green-600">{stats.sla_summary.on_track}</span>
              <span className="text-sm text-yellow-600">{stats.sla_summary.at_risk} {t('dashboard.sla.atRisk')}</span>
              <span className="text-sm text-destructive">{stats.sla_summary.breached} {t('dashboard.sla.breached')}</span>
            </div>
          </CardContent>
        </Card>

        <Card
          className="animate-in stagger-4 card-interactive cursor-pointer transition-colors hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring"
          role="button"
          tabIndex={0}
          onClick={() => navigate({ to: '/findings' })}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigate({ to: '/findings' }) } }}
        >
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">{t('dashboard.openFindings')}</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              <SeverityBadge severity="Critical" count={stats.severity_counts.critical} />
              <SeverityBadge severity="High" count={stats.severity_counts.high} />
              <SeverityBadge severity="Medium" count={stats.severity_counts.medium} />
              <SeverityBadge severity="Low" count={stats.severity_counts.low} />
              <SeverityBadge severity="Info" count={stats.severity_counts.info} />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Chart widgets */}
      <div className="grid gap-6 md:grid-cols-2">
        <Card className="animate-in stagger-5">
          <CardHeader>
            <CardTitle>{t('dashboard.charts.severityDistribution')}</CardTitle>
          </CardHeader>
          <CardContent>
            <SeverityChart counts={stats.severity_counts} />
          </CardContent>
        </Card>

        <Card className="animate-in stagger-6">
          <CardHeader>
            <CardTitle>{t('dashboard.charts.findingsBySource')}</CardTitle>
          </CardHeader>
          <CardContent>
            <SourceToolChart data={stats.findings_by_source} />
          </CardContent>
        </Card>

        <Card className="animate-in stagger-7">
          <CardHeader>
            <CardTitle>{t('dashboard.charts.riskiestApps')}</CardTitle>
          </CardHeader>
          <CardContent>
            <TopAppsChart apps={stats.top_risky_apps} />
          </CardContent>
        </Card>

        <Card className="animate-in stagger-8">
          <CardHeader>
            <CardTitle>{t('dashboard.charts.slaCompliance')}</CardTitle>
          </CardHeader>
          <CardContent>
            <SlaChart summary={stats.sla_summary} />
          </CardContent>
        </Card>
      </div>

      {/* Bottom row */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* Recent ingestions */}
        <Card className="animate-in">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Upload className="h-4 w-4" /> {t('dashboard.recentImports')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {stats.recent_ingestions.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t('dashboard.noRecentImports')}</p>
            ) : (
              <div className="space-y-3">
                {stats.recent_ingestions.map((ing) => (
                  <div
                    key={ing.id}
                    className="card-interactive flex items-center justify-between rounded-lg border p-3"
                  >
                    <div>
                      <p className="text-sm font-medium">{ing.source_tool}</p>
                      <p className="text-xs text-muted-foreground">
                        {ing.file_name || t('dashboard.noFile')} — {ing.total_records} {t('dashboard.records')}, {ing.new_findings} {t('dashboard.new')}
                      </p>
                    </div>
                    <div className="text-right">
                      <Badge
                        variant="outline"
                        className={
                          ing.status === 'Completed'
                            ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                            : ing.status === 'Failed'
                              ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                              : ''
                        }
                      >
                        {t(`dashboard.ingestionStatus.${ing.status}`, ing.status)}
                      </Badge>
                      {ing.completed_at && (
                        <p className="mt-1 text-xs text-muted-foreground">
                          {new Date(ing.completed_at).toLocaleDateString()}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Top risky apps */}
        <Card className="animate-in">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-4 w-4" /> {t('dashboard.riskiestApplications')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {stats.top_risky_apps.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t('dashboard.noApplicationData')}</p>
            ) : (
              <div className="space-y-3">
                {stats.top_risky_apps.map((app) => (
                  <div
                    key={app.id}
                    role="button"
                    tabIndex={0}
                    className="card-interactive flex cursor-pointer items-center justify-between rounded-lg border p-3 transition-colors hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring"
                    onClick={() =>
                      navigate({ to: '/applications/$id', params: { id: app.id } })
                    }
                    onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigate({ to: '/applications/$id', params: { id: app.id } }) } }}
                  >
                    <div>
                      <p className="text-sm font-medium">{app.app_name}</p>
                      <p className="font-mono text-xs text-muted-foreground">{app.app_code}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      {app.critical_count > 0 && (
                        <Badge variant="outline" className="bg-severity-critical/10 text-severity-critical">
                          {app.critical_count} {t('dashboard.severity.critical')}
                        </Badge>
                      )}
                      {app.high_count > 0 && (
                        <Badge variant="outline" className="bg-severity-high/10 text-severity-high">
                          {app.high_count} {t('dashboard.severity.high')}
                        </Badge>
                      )}
                      <span className="text-sm text-muted-foreground">
                        {app.finding_count} {t('dashboard.total')}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
