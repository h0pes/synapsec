import { memo } from 'react'
import { Handle, Position } from '@xyflow/react'
import type { NodeProps } from '@xyflow/react'
import { cn } from '@/lib/utils'
import { CATEGORY_COLORS } from './transform'
import type { FindingNode as FindingNodeType } from './transform'

/** Maximum number of characters for the finding title before truncation. */
const TITLE_MAX_LENGTH = 40

const SEVERITY_BADGE_STYLES: Record<string, string> = {
  Critical: 'bg-red-600 text-white',
  High:     'bg-orange-500 text-white',
  Medium:   'bg-yellow-500 text-black',
  Low:      'bg-blue-500 text-white',
  Info:     'bg-gray-400 text-white',
}

/** Map source_tool identifiers to short human-readable labels. */
const TOOL_LABELS: Record<string, string> = {
  sonarqube:   'SonarQube',
  jfrog_xray:  'JFrog Xray',
  tenable_was: 'Tenable WAS',
}

function truncateTitle(title: string): string {
  if (title.length <= TITLE_MAX_LENGTH) return title
  return title.slice(0, TITLE_MAX_LENGTH - 1) + '\u2026'
}

/**
 * Custom React Flow node component for rendering a finding in the attack-chain graph.
 *
 * Displays:
 * - Left border accent colored by finding category (SAST/SCA/DAST)
 * - Finding title (truncated)
 * - Severity badge
 * - Source tool label
 * - Connection handles for edges
 */
function FindingNodeComponent({ data }: NodeProps<FindingNodeType>) {
  const { finding, isUncorrelated } = data
  const categoryColors = CATEGORY_COLORS[finding.finding_category]
  const borderColor = categoryColors?.border ?? '#6b7280'
  const severityStyle = SEVERITY_BADGE_STYLES[finding.normalized_severity] ?? 'bg-gray-400 text-white'
  const toolLabel = TOOL_LABELS[finding.source_tool] ?? finding.source_tool

  return (
    <>
      {/* Incoming edge handle */}
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border-2 !border-white !bg-gray-400 dark:!border-gray-800"
      />

      <div
        className={cn(
          'flex min-w-0 flex-col gap-1 rounded-lg border bg-card px-3 py-2 shadow-sm',
          'transition-shadow hover:shadow-md',
          isUncorrelated && 'border-dashed opacity-75',
        )}
        style={{ borderLeftWidth: 4, borderLeftColor: borderColor }}
      >
        {/* Title */}
        <span
          className="truncate text-xs font-medium leading-tight text-card-foreground"
          title={finding.title}
        >
          {truncateTitle(finding.title)}
        </span>

        {/* Severity + Source */}
        <div className="flex items-center gap-1.5">
          <span
            className={cn(
              'inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-medium leading-none',
              severityStyle,
            )}
          >
            {finding.normalized_severity}
          </span>
          <span className="text-[10px] text-muted-foreground">{toolLabel}</span>
        </div>
      </div>

      {/* Outgoing edge handle */}
      <Handle
        type="source"
        position={Position.Right}
        className="!h-2.5 !w-2.5 !border-2 !border-white !bg-gray-400 dark:!border-gray-800"
      />
    </>
  )
}

export const FindingNode = memo(FindingNodeComponent)
