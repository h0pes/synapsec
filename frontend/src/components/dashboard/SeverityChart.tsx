import { useTranslation } from 'react-i18next'
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from 'recharts'

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#3b82f6',
  Info: '#6b7280',
}

type SeverityCounts = {
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

interface SeverityChartProps {
  counts: SeverityCounts
}

export function SeverityChart({ counts }: SeverityChartProps) {
  const { t } = useTranslation()

  const data = [
    { name: t('dashboard.severity.critical'), value: counts.critical, key: 'Critical' },
    { name: t('dashboard.severity.high'), value: counts.high, key: 'High' },
    { name: t('dashboard.severity.medium'), value: counts.medium, key: 'Medium' },
    { name: t('dashboard.severity.low'), value: counts.low, key: 'Low' },
    { name: t('dashboard.severity.info'), value: counts.info, key: 'Info' },
  ].filter((d) => d.value > 0)

  if (data.length === 0) {
    return (
      <div className="flex h-[300px] items-center justify-center text-sm text-muted-foreground">
        {t('common.noResults')}
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          innerRadius={60}
          outerRadius={100}
          paddingAngle={2}
        >
          {data.map((entry) => (
            <Cell
              key={entry.key}
              fill={SEVERITY_COLORS[entry.key]}
            />
          ))}
        </Pie>
        <Tooltip />
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  )
}
