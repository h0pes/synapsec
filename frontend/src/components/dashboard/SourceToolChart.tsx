import { useTranslation } from 'react-i18next'
import {
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts'
import { TOOL_DISPLAY_NAMES, TOOL_CATEGORY_LABELS } from '@/lib/findings'

const CATEGORY_COLORS: Record<string, string> = {
  SAST: '#3b82f6',
  SCA: '#8b5cf6',
  DAST: '#14b8a6',
}

type FindingsBySource = {
  source_tool: string
  count: number
}

interface SourceToolChartProps {
  data: FindingsBySource[]
}

export function SourceToolChart({ data }: SourceToolChartProps) {
  const { t } = useTranslation()

  if (data.length === 0) {
    return (
      <div className="flex h-[300px] items-center justify-center text-sm text-muted-foreground">
        {t('common.noResults')}
      </div>
    )
  }

  const chartData = data.map((d) => ({
    name: TOOL_DISPLAY_NAMES[d.source_tool] ?? d.source_tool,
    count: d.count,
    fill: CATEGORY_COLORS[TOOL_CATEGORY_LABELS[d.source_tool] ?? ''] ?? '#6b7280',
  }))

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
        <XAxis dataKey="name" className="text-xs" />
        <YAxis allowDecimals={false} className="text-xs" />
        <Tooltip />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {chartData.map((entry) => (
            <Cell key={entry.name} fill={entry.fill} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
