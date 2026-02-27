import { useTranslation } from 'react-i18next'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts'

type TopRiskyApp = {
  id: string
  app_name: string
  app_code: string
  finding_count: number
  critical_count: number
  high_count: number
}

interface TopAppsChartProps {
  apps: TopRiskyApp[]
}

export function TopAppsChart({ apps }: TopAppsChartProps) {
  const { t } = useTranslation()

  if (apps.length === 0) {
    return (
      <div className="flex h-[300px] items-center justify-center text-sm text-muted-foreground">
        {t('common.noResults')}
      </div>
    )
  }

  const chartData = apps.map((app) => ({
    name: app.app_code,
    critical: app.critical_count,
    high: app.high_count,
    other: Math.max(0, app.finding_count - app.critical_count - app.high_count),
  }))

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={chartData} layout="vertical">
        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
        <XAxis type="number" allowDecimals={false} className="text-xs" />
        <YAxis type="category" dataKey="name" width={80} className="text-xs" />
        <Tooltip />
        <Bar dataKey="critical" stackId="a" fill="#ef4444" name={t('dashboard.severity.critical')} />
        <Bar dataKey="high" stackId="a" fill="#f97316" name={t('dashboard.severity.high')} />
        <Bar dataKey="other" stackId="a" fill="#6b7280" name={t('dashboard.other')} radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}
