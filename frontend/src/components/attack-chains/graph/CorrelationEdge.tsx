import { memo } from 'react'
import { BaseEdge, getBezierPath } from '@xyflow/react'
import type { EdgeProps } from '@xyflow/react'
import type { CorrelationEdge as CorrelationEdgeType } from './transform'

/** Neutral gray for edge strokes, consistent in light and dark themes. */
const EDGE_COLOR = '#94a3b8' // slate-400

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
      {/* Relationship type label at the midpoint of the edge */}
      {relationshipType && (
        <foreignObject
          x={labelX - 40}
          y={labelY - 10}
          width={80}
          height={20}
          className="pointer-events-none overflow-visible"
        >
          <div className="flex items-center justify-center">
            <span className="rounded bg-background/80 px-1 py-0.5 text-[9px] text-muted-foreground backdrop-blur-sm">
              {relationshipType}
            </span>
          </div>
        </foreignObject>
      )}
    </>
  )
}

export const CorrelationEdge = memo(CorrelationEdgeComponent)
