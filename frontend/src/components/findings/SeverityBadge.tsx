import { Badge } from '@/components/ui/badge'
import type { SeverityLevel } from '@/types/finding'

const SEVERITY_STYLES: Record<SeverityLevel, string> = {
  Critical: 'bg-red-600 text-white hover:bg-red-700',
  High: 'bg-orange-500 text-white hover:bg-orange-600',
  Medium: 'bg-yellow-500 text-black hover:bg-yellow-600',
  Low: 'bg-blue-500 text-white hover:bg-blue-600',
  Info: 'bg-gray-400 text-white hover:bg-gray-500',
}

export function SeverityBadge({ severity, count }: { severity: SeverityLevel; count?: number }) {
  return (
    <Badge className={SEVERITY_STYLES[severity]}>
      {count != null ? `${count} ${severity}` : severity}
    </Badge>
  )
}
