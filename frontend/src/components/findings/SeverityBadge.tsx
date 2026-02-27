import { Badge } from '@/components/ui/badge'
import type { SeverityLevel } from '@/types/finding'

const SEVERITY_STYLES: Record<SeverityLevel, string> = {
  Critical: 'bg-severity-critical text-white',
  High: 'bg-severity-high text-white',
  Medium: 'bg-severity-medium text-black',
  Low: 'bg-severity-low text-white',
  Info: 'bg-severity-info text-white',
}

export function SeverityBadge({ severity, count }: { severity: SeverityLevel; count?: number }) {
  return (
    <Badge className={SEVERITY_STYLES[severity]}>
      {count != null ? `${count} ${severity}` : severity}
    </Badge>
  )
}
