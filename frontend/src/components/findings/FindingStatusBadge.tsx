import { useTranslation } from 'react-i18next'
import { Badge } from '@/components/ui/badge'
import type { FindingStatus } from '@/types/finding'

const STATUS_STYLES: Record<FindingStatus, string> = {
  New: 'border-blue-400/50 bg-blue-50 text-blue-700 dark:bg-blue-950/50 dark:text-blue-300',
  Confirmed: 'border-purple-400/50 bg-purple-50 text-purple-700 dark:bg-purple-950/50 dark:text-purple-300',
  In_Remediation: 'border-amber-400/50 bg-amber-50 text-amber-700 dark:bg-amber-950/50 dark:text-amber-300',
  Mitigated: 'border-cyan-400/50 bg-cyan-50 text-cyan-700 dark:bg-cyan-950/50 dark:text-cyan-300',
  Verified: 'border-teal-400/50 bg-teal-50 text-teal-700 dark:bg-teal-950/50 dark:text-teal-300',
  Closed: 'border-green-400/50 bg-green-50 text-green-700 dark:bg-green-950/50 dark:text-green-300',
  False_Positive_Requested: 'border-rose-400/50 bg-rose-50 text-rose-700 dark:bg-rose-950/50 dark:text-rose-300',
  False_Positive: 'border-gray-400/50 bg-gray-50 text-gray-700 dark:bg-gray-800/50 dark:text-gray-300',
  Risk_Accepted: 'border-orange-400/50 bg-orange-50 text-orange-700 dark:bg-orange-950/50 dark:text-orange-300',
  Deferred_Remediation: 'border-indigo-400/50 bg-indigo-50 text-indigo-700 dark:bg-indigo-950/50 dark:text-indigo-300',
  Invalidated: 'border-red-400/50 bg-red-50 text-red-700 dark:bg-red-950/50 dark:text-red-300',
}

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  const { t } = useTranslation()
  return (
    <Badge variant="outline" className={STATUS_STYLES[status]}>
      {t(`findings.status.${status}`)}
    </Badge>
  )
}
