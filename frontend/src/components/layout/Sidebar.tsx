import { useTranslation } from 'react-i18next'
import { useRouter, useRouterState } from '@tanstack/react-router'
import {
  LayoutDashboard,
  Search,
  Building2,
  Upload,
  ListChecks,
  AlertCircle,
  Shield,
  ChevronLeft,
  Link2,
  Copy,
  GitCompareArrows,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'

type NavItem = {
  labelKey: string
  path: string
  icon: React.ElementType
}

/** Above-the-line: daily analyst workflow. */
const PRIMARY_NAV: NavItem[] = [
  { labelKey: 'nav.dashboard', path: '/', icon: LayoutDashboard },
  { labelKey: 'nav.findings', path: '/findings', icon: Search },
  { labelKey: 'nav.applications', path: '/applications', icon: Building2 },
  { labelKey: 'nav.attack_chains', path: '/attack-chains', icon: Link2 },
  { labelKey: 'nav.triage', path: '/triage', icon: ListChecks },
]

/** Below-the-line: pipeline operations & data quality. */
const SECONDARY_NAV: NavItem[] = [
  { labelKey: 'nav.ingestion', path: '/ingestion', icon: Upload },
  { labelKey: 'nav.deduplication', path: '/deduplication', icon: Copy },
  { labelKey: 'nav.correlation', path: '/correlations', icon: GitCompareArrows },
  { labelKey: 'nav.unmapped', path: '/unmapped', icon: AlertCircle },
]

type SidebarProps = {
  collapsed: boolean
  onToggle: () => void
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const { t } = useTranslation()
  const router = useRouter()
  const currentPath = useRouterState({ select: (s) => s.location.pathname })

  function renderNavItem(item: NavItem) {
    const active =
      item.path === '/'
        ? currentPath === '/'
        : currentPath.startsWith(item.path)
    return (
      <a
        key={item.path}
        href={item.path}
        onClick={(e) => {
          e.preventDefault()
          router.navigate({ to: item.path })
        }}
        className={cn(
          'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
          active
            ? 'bg-sidebar-accent text-sidebar-accent-foreground'
            : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground',
          collapsed && 'justify-center px-2',
        )}
        title={collapsed ? t(item.labelKey) : undefined}
      >
        <item.icon className="h-4 w-4 shrink-0" />
        {!collapsed && <span>{t(item.labelKey)}</span>}
      </a>
    )
  }

  return (
    <aside
      className={cn(
        'flex h-screen flex-col border-r bg-sidebar text-sidebar-foreground transition-all duration-200',
        collapsed ? 'w-16' : 'w-60',
      )}
    >
      {/* Logo */}
      <div className="flex h-14 items-center gap-2 px-4">
        <Shield className="h-6 w-6 shrink-0 text-sidebar-primary" />
        {!collapsed && (
          <span className="text-lg font-semibold tracking-tight">
            SynApSec
          </span>
        )}
      </div>

      <Separator />

      {/* Navigation */}
      <nav className="flex-1 px-2 py-3">
        {/* Primary: analyst workflow */}
        <div className="space-y-1">
          {PRIMARY_NAV.map(renderNavItem)}
        </div>

        {/* Separator between primary and secondary */}
        <Separator className="my-3" />

        {/* Secondary: pipeline operations */}
        <div className="space-y-1">
          {SECONDARY_NAV.map(renderNavItem)}
        </div>
      </nav>

      {/* Collapse toggle */}
      <div className="border-t p-2">
        <Button
          variant="ghost"
          size="icon"
          className={cn('w-full', !collapsed && 'justify-end')}
          onClick={onToggle}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          <ChevronLeft
            className={cn(
              'h-4 w-4 transition-transform',
              collapsed && 'rotate-180',
            )}
          />
        </Button>
      </div>
    </aside>
  )
}
