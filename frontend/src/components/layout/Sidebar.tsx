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

  function isActive(item: NavItem) {
    return item.path === '/'
      ? currentPath === '/'
      : currentPath.startsWith(item.path)
  }

  function renderNavItem(item: NavItem) {
    const active = isActive(item)
    return (
      <a
        key={item.path}
        href={item.path}
        onClick={(e) => {
          e.preventDefault()
          router.navigate({ to: item.path })
        }}
        className={cn(
          'group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all duration-150',
          active
            ? 'bg-primary/10 text-primary'
            : 'text-muted-foreground hover:bg-accent hover:text-foreground',
          collapsed && 'justify-center px-2',
        )}
        title={collapsed ? t(item.labelKey) : undefined}
        aria-label={collapsed ? t(item.labelKey) : undefined}
      >
        {/* Active accent bar */}
        {active && (
          <span className="absolute top-1.5 bottom-1.5 left-0 w-[3px] rounded-r-full bg-primary" />
        )}
        <item.icon aria-hidden="true" className={cn(
          'h-[18px] w-[18px] shrink-0 transition-colors',
          active ? 'text-primary' : 'text-muted-foreground group-hover:text-foreground',
        )} />
        {!collapsed && (
          <span className="truncate">{t(item.labelKey)}</span>
        )}
      </a>
    )
  }

  return (
    <aside
      className={cn(
        'flex h-screen flex-col border-r border-sidebar-border bg-sidebar transition-[width] duration-200 ease-in-out',
        collapsed ? 'w-[60px]' : 'w-[240px]',
      )}
      aria-label={t('nav.sidebar')}
    >
      {/* Logo */}
      <div className="flex h-14 items-center gap-2.5 overflow-hidden px-4">
        <Shield className="h-6 w-6 shrink-0 text-primary" />
        <span className={cn(
          'text-base font-semibold tracking-tight text-foreground transition-opacity duration-150',
          collapsed ? 'opacity-0' : 'opacity-100',
        )}>
          SynApSec
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-2 pt-2" aria-label={t('nav.mainNavigation')}>
        {/* Primary: analyst workflow */}
        {!collapsed && (
          <p className="mb-1.5 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/60">
            {t('nav.findings')}
          </p>
        )}
        <div className="space-y-0.5">
          {PRIMARY_NAV.map(renderNavItem)}
        </div>

        {/* Divider */}
        <div className="my-3 border-t border-sidebar-border" />

        {/* Secondary: pipeline operations */}
        {!collapsed && (
          <p className="mb-1.5 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/60">
            {t('nav.pipeline')}
          </p>
        )}
        <div className="space-y-0.5">
          {SECONDARY_NAV.map(renderNavItem)}
        </div>
      </nav>

      {/* Collapse toggle */}
      <div className="border-t border-sidebar-border p-2">
        <Button
          variant="ghost"
          size="icon"
          className={cn(
            'h-8 w-full text-muted-foreground hover:text-foreground',
            !collapsed && 'justify-end',
          )}
          onClick={onToggle}
          aria-label={collapsed ? t('nav.expandSidebar') : t('nav.collapseSidebar')}
          aria-expanded={!collapsed}
        >
          <ChevronLeft
            aria-hidden="true"
            className={cn(
              'h-4 w-4 transition-transform duration-200',
              collapsed && 'rotate-180',
            )}
          />
        </Button>
      </div>
    </aside>
  )
}
