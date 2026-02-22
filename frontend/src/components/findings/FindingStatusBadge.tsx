import { Badge } from '@/components/ui/badge'
import type { FindingStatus } from '@/types/finding'

const STATUS_STYLES: Record<FindingStatus, string> = {
  New: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  Confirmed: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
  In_Remediation: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
  Mitigated: 'bg-cyan-100 text-cyan-800 dark:bg-cyan-900 dark:text-cyan-200',
  Verified: 'bg-teal-100 text-teal-800 dark:bg-teal-900 dark:text-teal-200',
  Closed: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  False_Positive_Requested: 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200',
  False_Positive: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200',
  Risk_Accepted: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  Deferred_Remediation: 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900 dark:text-indigo-200',
  Invalidated: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
}

const STATUS_LABELS: Record<FindingStatus, string> = {
  New: 'New',
  Confirmed: 'Confirmed',
  In_Remediation: 'In Remediation',
  Mitigated: 'Mitigated',
  Verified: 'Verified',
  Closed: 'Closed',
  False_Positive_Requested: 'FP Requested',
  False_Positive: 'False Positive',
  Risk_Accepted: 'Risk Accepted',
  Deferred_Remediation: 'Deferred',
  Invalidated: 'Invalidated',
}

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return (
    <Badge variant="outline" className={STATUS_STYLES[status]}>
      {STATUS_LABELS[status]}
    </Badge>
  )
}
