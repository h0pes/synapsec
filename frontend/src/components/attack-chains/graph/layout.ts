import dagre from '@dagrejs/dagre'
import type { Node, Edge } from '@xyflow/react'

export type LayoutDirection = 'LR' | 'TB'

/** Default gap between nodes in the horizontal axis. */
const NODE_SEP = 50
/** Default gap between ranks (layers) in the layout. */
const RANK_SEP = 80

/** Fallback dimensions when a node has no explicit width/height. */
const DEFAULT_WIDTH = 180
const DEFAULT_HEIGHT = 64

/**
 * Apply a dagre automatic layout to position React Flow nodes.
 *
 * Dagre computes a layered (hierarchical) graph layout that works well
 * for directed acyclic graphs like attack-chain correlation graphs.
 *
 * @param nodes - React Flow nodes (positions will be overwritten)
 * @param edges - React Flow edges (used by dagre for rank computation)
 * @param direction - 'LR' (left-to-right) or 'TB' (top-to-bottom)
 * @returns A new array of nodes with updated positions
 */
export function applyDagreLayout(
  nodes: Node[],
  edges: Edge[],
  direction: LayoutDirection = 'LR',
): Node[] {
  const g = new dagre.graphlib.Graph()

  g.setGraph({
    rankdir: direction,
    nodesep: NODE_SEP,
    ranksep: RANK_SEP,
    marginx: 20,
    marginy: 20,
  })

  // Required for dagre to not throw on edges with missing nodes
  g.setDefaultEdgeLabel(() => ({}))

  for (const node of nodes) {
    g.setNode(node.id, {
      width: node.width ?? node.measured?.width ?? DEFAULT_WIDTH,
      height: node.height ?? node.measured?.height ?? DEFAULT_HEIGHT,
    })
  }

  for (const edge of edges) {
    g.setEdge(edge.source, edge.target)
  }

  dagre.layout(g)

  return nodes.map((node) => {
    const dagreNode = g.node(node.id)
    const width = node.width ?? node.measured?.width ?? DEFAULT_WIDTH
    const height = node.height ?? node.measured?.height ?? DEFAULT_HEIGHT

    // dagre returns center coordinates; React Flow uses top-left origin
    return {
      ...node,
      position: {
        x: dagreNode.x - width / 2,
        y: dagreNode.y - height / 2,
      },
    }
  })
}
