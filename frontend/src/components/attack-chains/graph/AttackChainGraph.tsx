import { useMemo, useState, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from '@tanstack/react-router'
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  ReactFlowProvider,
} from '@xyflow/react'
import type { NodeMouseHandler } from '@xyflow/react'
import { ExternalLink } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/findings/SeverityBadge'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet'
import {
  normalizeSeverity,
  TOOL_DISPLAY_NAMES,
  CATEGORY_BADGE_STYLES,
} from '@/lib/findings'
import { FindingNode } from './FindingNode'
import { CorrelationEdge } from './CorrelationEdge'
import { transformAttackChainData } from './transform'
import { applyDagreLayout } from './layout'
import type { LayoutDirection } from './layout'
import type { FindingNode as FindingNodeType } from './transform'
import type { AppAttackChainDetail, ChainFinding, UncorrelatedFinding } from '@/types/attack-chains'

const nodeTypes = { finding: FindingNode }
const edgeTypes = { correlation: CorrelationEdge }

interface AttackChainGraphProps {
  detail: AppAttackChainDetail
}

function AttackChainGraphInner({ detail }: AttackChainGraphProps) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [layout, setLayout] = useState<LayoutDirection>('LR')
  const [selectedFinding, setSelectedFinding] = useState<(ChainFinding | UncorrelatedFinding) | null>(null)
  const [sheetOpen, setSheetOpen] = useState(false)

  const { nodes: rawNodes, edges } = useMemo(
    () => transformAttackChainData(detail),
    [detail],
  )

  const nodes = useMemo(
    () => applyDagreLayout(rawNodes, edges, layout),
    [rawNodes, edges, layout],
  )

  const handleNodeClick: NodeMouseHandler<FindingNodeType> = useCallback((_event, node) => {
    setSelectedFinding(node.data.finding)
    setSheetOpen(true)
  }, [])

  const handleViewFinding = useCallback(() => {
    if (selectedFinding) {
      navigate({ to: '/findings/$id', params: { id: selectedFinding.id } })
    }
  }, [navigate, selectedFinding])

  return (
    <div className="space-y-3">
      {/* Layout toggle */}
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium text-muted-foreground">
          {t('attackChains.graphControls.layout')}:
        </span>
        <div className="inline-flex rounded-md border">
          <Button
            variant={layout === 'LR' ? 'default' : 'ghost'}
            size="sm"
            className="rounded-r-none"
            onClick={() => setLayout('LR')}
          >
            {t('attackChains.graphControls.hierarchical')}
          </Button>
          <Button
            variant={layout === 'TB' ? 'default' : 'ghost'}
            size="sm"
            className="rounded-l-none"
            onClick={() => setLayout('TB')}
          >
            {t('attackChains.graphControls.forceDirected')}
          </Button>
        </div>
      </div>

      {/* Graph canvas */}
      <div className="rounded-md border" style={{ height: '600px' }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onNodeClick={handleNodeClick}
          fitView
        >
          <Background />
          <Controls />
          <MiniMap
            zoomable
            pannable
            className="!bg-background !border !border-border !rounded-md"
          />
        </ReactFlow>
      </div>

      {/* Finding detail sheet */}
      <Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
        <SheetContent side="right">
          <SheetHeader>
            <SheetTitle>{t('attackChains.findingPanel.title')}</SheetTitle>
            <SheetDescription className="sr-only">
              {t('attackChains.findingPanel.title')}
            </SheetDescription>
          </SheetHeader>
          {selectedFinding && (
            <div className="space-y-4 px-4">
              {/* Title */}
              <p className="text-sm font-medium leading-snug">
                {selectedFinding.title}
              </p>

              {/* Severity */}
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">
                  {t('attackChains.findingPanel.severity')}
                </span>
                <SeverityBadge severity={normalizeSeverity(selectedFinding.normalized_severity)} />
              </div>

              {/* Category */}
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">
                  {t('attackChains.findingPanel.category')}
                </span>
                <Badge
                  variant="outline"
                  className={CATEGORY_BADGE_STYLES[selectedFinding.finding_category] ?? ''}
                >
                  {selectedFinding.finding_category}
                </Badge>
              </div>

              {/* Source */}
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">
                  {t('attackChains.findingPanel.source')}
                </span>
                <span className="text-sm">
                  {TOOL_DISPLAY_NAMES[selectedFinding.source_tool] ?? selectedFinding.source_tool}
                </span>
              </div>

              {/* Status */}
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">
                  {t('attackChains.findingPanel.status')}
                </span>
                <span className="text-sm">{selectedFinding.status}</span>
              </div>

              {/* View Finding link */}
              <Button
                variant="outline"
                className="mt-4 w-full"
                onClick={handleViewFinding}
              >
                <ExternalLink className="mr-2 h-4 w-4" />
                {t('attackChains.findingPanel.viewFinding')}
              </Button>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  )
}

export function AttackChainGraph({ detail }: AttackChainGraphProps) {
  return (
    <ReactFlowProvider>
      <AttackChainGraphInner detail={detail} />
    </ReactFlowProvider>
  )
}
