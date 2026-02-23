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
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'

type NavItem = {
  labelKey: string
  path: string
  icon: React.ElementType
}

const NAV_ITEMS: NavItem[] = [
  { labelKey: 'nav.dashboard', path: '/', icon: LayoutDashboard },
  { labelKey: 'nav.findings', path: '/findings', icon: Search },
  { labelKey: 'nav.applications', path: '/applications', icon: Building2 },
  { labelKey: 'nav.ingestion', path: '/ingestion', icon: Upload },
  { labelKey: 'nav.triage', path: '/triage', icon: ListChecks },
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
      <nav className="flex-1 space-y-1 px-2 py-3">
        {NAV_ITEMS.map((item) => {
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
        })}
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
