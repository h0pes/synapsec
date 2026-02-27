import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Slider } from '@/components/ui/slider'
import { CATEGORY_BADGE_STYLES } from '@/lib/findings'
import { CATEGORY_COLORS } from './transform'
import type { LayoutDirection } from './layout'

/** Categories available for graph filtering, ordered consistently. */
const FILTER_CATEGORIES = ['SAST', 'SCA', 'DAST'] as const

/** Labels mapping severity rank (1-5) to human-readable severity names. */
const RISK_LABELS: Record<number, string> = {
  1: 'Info',
  2: 'Low',
  3: 'Medium',
  4: 'High',
  5: 'Critical',
}

interface GraphControlsPanelProps {
  /** Current minimum risk score filter (1-5 severity rank scale). */
  minRiskScore: number
  /** Callback to update the minimum risk score filter. */
  onMinRiskScoreChange: (value: number) => void
  /** Set of currently active finding categories. */
  activeCategories: Set<string>
  /** Callback to toggle a finding category on/off. */
  onToggleCategory: (category: string) => void
  /** Current layout direction. */
  layout: LayoutDirection
  /** Callback to change layout direction. */
  onLayoutChange: (direction: LayoutDirection) => void
}

export function GraphControlsPanel({
  minRiskScore,
  onMinRiskScoreChange,
  activeCategories,
  onToggleCategory,
  layout,
  onLayoutChange,
}: GraphControlsPanelProps) {
  const { t } = useTranslation()

  return (
    <div className="flex flex-wrap items-center gap-6 rounded-md border bg-card px-4 py-3">
      {/* Risk score slider */}
      <div className="flex items-center gap-3">
        <span className="text-sm font-medium text-muted-foreground whitespace-nowrap">
          {t('attackChains.graphControls.riskThreshold')}:
        </span>
        <div className="flex items-center gap-2">
          <Slider
            min={1}
            max={5}
            step={1}
            value={[minRiskScore]}
            onValueChange={([value]) => onMinRiskScoreChange(value)}
            className="w-28"
          />
          <span className="min-w-[4.5rem] text-sm font-medium tabular-nums">
            {minRiskScore} ({RISK_LABELS[minRiskScore] ?? ''})
          </span>
        </div>
      </div>

      {/* Category checkboxes */}
      <div className="flex items-center gap-3">
        <span className="text-sm font-medium text-muted-foreground whitespace-nowrap">
          {t('attackChains.graphControls.categories')}:
        </span>
        <div className="flex items-center gap-3">
          {FILTER_CATEGORIES.map((category) => {
            const colors = CATEGORY_COLORS[category]
            const isChecked = activeCategories.has(category)

            return (
              <label
                key={category}
                className="flex cursor-pointer items-center gap-1.5"
              >
                <Checkbox
                  checked={isChecked}
                  onCheckedChange={() => onToggleCategory(category)}
                  className={
                    isChecked
                      ? `border-transparent data-[state=checked]:border-transparent`
                      : undefined
                  }
                  style={
                    isChecked && colors
                      ? { backgroundColor: colors.bg, borderColor: colors.bg }
                      : undefined
                  }
                />
                <span
                  className={`rounded-sm px-1.5 py-0.5 text-xs font-medium ${CATEGORY_BADGE_STYLES[category] ?? ''}`}
                >
                  {category}
                </span>
              </label>
            )
          })}
        </div>
      </div>

      {/* Layout toggle */}
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium text-muted-foreground whitespace-nowrap">
          {t('attackChains.graphControls.layout')}:
        </span>
        <div className="inline-flex rounded-md border">
          <Button
            variant={layout === 'LR' ? 'default' : 'ghost'}
            size="sm"
            className="rounded-r-none"
            onClick={() => onLayoutChange('LR')}
          >
            {t('attackChains.graphControls.hierarchical')}
          </Button>
          <Button
            variant={layout === 'TB' ? 'default' : 'ghost'}
            size="sm"
            className="rounded-l-none"
            onClick={() => onLayoutChange('TB')}
          >
            {t('attackChains.graphControls.forceDirected')}
          </Button>
        </div>
      </div>
    </div>
  )
}
