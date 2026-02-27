import { useTranslation } from 'react-i18next'
import {
  RadialBarChart,
  RadialBar,
  Legend,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'

type SlaSummary = {
  on_track: number
  at_risk: number
  breached: number
}

interface SlaChartProps {
  summary: SlaSummary
}

export function SlaChart({ summary }: SlaChartProps) {
  const { t } = useTranslation()
  const total = summary.on_track + summary.at_risk + summary.breached

  if (total === 0) {
    return (
      <div className="flex h-[300px] items-center justify-center text-sm text-muted-foreground">
        {t('common.noResults')}
      </div>
    )
  }

  const data = [
    {
      name: t('dashboard.sla.breached'),
      value: summary.breached,
      fill: '#ef4444',
    },
    {
      name: t('dashboard.sla.atRisk'),
      value: summary.at_risk,
      fill: '#eab308',
    },
    {
      name: t('dashboard.sla.onTrack'),
      value: summary.on_track,
      fill: '#22c55e',
    },
  ]

  return (
    <ResponsiveContainer width="100%" height={300}>
      <RadialBarChart
        innerRadius="30%"
        outerRadius="90%"
        data={data}
        startAngle={180}
        endAngle={0}
      >
        <RadialBar
          dataKey="value"
          background={{ fill: 'hsl(var(--muted))' }}
          cornerRadius={4}
        />
        <Tooltip />
        <Legend
          iconType="circle"
          wrapperStyle={{ fontSize: '12px' }}
        />
      </RadialBarChart>
    </ResponsiveContainer>
  )
}
