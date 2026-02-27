import { memo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { BaseEdge, getBezierPath } from '@xyflow/react'
import type { EdgeProps } from '@xyflow/react'
import type { CorrelationEdge as CorrelationEdgeType } from './transform'

/** Neutral gray for edge strokes, consistent in light and dark themes. */
const EDGE_COLOR = '#94a3b8' // slate-400

/** Width of the foreignObject that hosts the label and tooltip. */
const LABEL_OBJECT_WIDTH = 140

/** Height of the foreignObject that hosts the label and tooltip. */
const LABEL_OBJECT_HEIGHT = 20

/**
 * Map confidence levels to SVG stroke-dasharray values:
 * - High:   solid line (no dash)
 * - Medium: dashed (5,5)
 * - Low:    dotted (2,3)
 * - null:   dotted (2,3) -- unknown confidence treated as low
 */
function strokeDashArrayForConfidence(confidence: string | null): string | undefined {
  switch (confidence) {
    case 'High':
      return undefined // solid
    case 'Medium':
      return '5,5'    // dashed
    case 'Low':
    default:
      return '2,3'    // dotted
  }
}

/**
 * Custom React Flow edge component for rendering correlation relationships.
 *
 * Visual encoding:
 * - Solid stroke for high-confidence correlations
 * - Dashed stroke for medium-confidence correlations
 * - Dotted stroke for low or unknown confidence
 * - Neutral gray color for all edges
 * - Hoverable label at midpoint showing relationship type with tooltip
 */
function CorrelationEdgeComponent({
  id,
  sourceX,
  sourceY,
  sourcePosition,
  targetX,
  targetY,
  targetPosition,
  data,
  markerEnd,
}: EdgeProps<CorrelationEdgeType>) {
  const { t } = useTranslation()
  const [hovered, setHovered] = useState(false)

  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  })

  const confidence = data?.confidence ?? null
  const dashArray = strokeDashArrayForConfidence(confidence)
  const relationshipType = data?.relationshipType

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          stroke: EDGE_COLOR,
          strokeWidth: 1.5,
          strokeDasharray: dashArray,
        }}
      />
      {/* Relationship type label at the midpoint of the edge, with tooltip on hover */}
      {relationshipType && (
        <foreignObject
          x={labelX - LABEL_OBJECT_WIDTH / 2}
          y={labelY - LABEL_OBJECT_HEIGHT / 2}
          width={LABEL_OBJECT_WIDTH}
          height={LABEL_OBJECT_HEIGHT}
          className="overflow-visible"
        >
          <div
            className="relative flex items-center justify-center"
            onMouseEnter={() => setHovered(true)}
            onMouseLeave={() => setHovered(false)}
          >
            <span className="cursor-default rounded bg-background/80 px-1 py-0.5 text-[9px] text-muted-foreground backdrop-blur-sm">
              {relationshipType}
            </span>

            {/* Tooltip shown on hover */}
            {hovered && (
              <div
                className="absolute bottom-full left-1/2 z-50 mb-1.5 -translate-x-1/2 whitespace-nowrap rounded-md bg-foreground px-2.5 py-1 text-xs text-background shadow-md"
                role="tooltip"
              >
                <div className="font-medium">{relationshipType}</div>
                {confidence && (
                  <div className="text-background/70">
                    {t('attackChains.edgeTooltip.confidence')}: {confidence}
                  </div>
                )}
                {/* Arrow pointing down */}
                <div className="absolute left-1/2 top-full -translate-x-1/2 border-4 border-transparent border-t-foreground" />
              </div>
            )}
          </div>
        </foreignObject>
      )}
    </>
  )
}

export const CorrelationEdge = memo(CorrelationEdgeComponent)
