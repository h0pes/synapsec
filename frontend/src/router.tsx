import {
  createRouter,
  createRootRoute,
  createRoute,
  redirect,
} from '@tanstack/react-router'
import { AppLayout } from '@/components/layout/AppLayout'
import { LoginPage } from '@/pages/LoginPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { FindingsPage } from '@/pages/FindingsPage'
import { FindingDetailPage } from '@/pages/FindingDetailPage'
import { ApplicationsPage } from '@/pages/ApplicationsPage'
import { ApplicationDetailPage } from '@/pages/ApplicationDetailPage'
import { IngestionPage } from '@/pages/IngestionPage'
import { TriageQueuePage } from '@/pages/TriageQueuePage'
import { UnmappedAppsPage } from '@/pages/UnmappedAppsPage'
import { DeduplicationPage } from '@/pages/DeduplicationPage'
import { AttackChainsPage } from '@/pages/AttackChainsPage'
import { AttackChainDetailPage } from '@/pages/AttackChainDetailPage'
import { authStore } from '@/stores/authStore'

// Root route — wraps everything
const rootRoute = createRootRoute()

// Login route — no layout
const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: LoginPage,
  beforeLoad: () => {
    if (authStore.isAuthenticated()) {
      throw redirect({ to: '/' })
    }
  },
})

// Authenticated layout route
const layoutRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: 'authenticated',
  component: AppLayout,
  beforeLoad: () => {
    if (!authStore.isAuthenticated()) {
      throw redirect({ to: '/login' })
    }
  },
})

// Dashboard (index)
const dashboardRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/',
  component: DashboardPage,
})

// Findings list
type FindingsSearchParams = {
  tab?: string
}

const findingsRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/findings',
  component: FindingsPage,
  validateSearch: (search: Record<string, unknown>): FindingsSearchParams => ({
    tab: typeof search.tab === 'string' ? search.tab : undefined,
  }),
})

// Finding detail
const findingDetailRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/findings/$id',
  component: FindingDetailPage,
})

// Applications list
const applicationsRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/applications',
  component: ApplicationsPage,
})

// Application detail
const applicationDetailRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/applications/$id',
  component: ApplicationDetailPage,
})

// Ingestion
const ingestionRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/ingestion',
  component: IngestionPage,
})

// Triage queue
const triageRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/triage',
  component: TriageQueuePage,
})

// Unmapped apps
const unmappedRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/unmapped',
  component: UnmappedAppsPage,
})

// Deduplication
const deduplicationRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/deduplication',
  component: DeduplicationPage,
})

// Attack Chains list
const attackChainsRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/attack-chains',
  component: AttackChainsPage,
})

// Attack Chain detail (per application)
const attackChainDetailRoute = createRoute({
  getParentRoute: () => layoutRoute,
  path: '/attack-chains/$appId',
  component: AttackChainDetailPage,
})

// Build route tree
const routeTree = rootRoute.addChildren([
  loginRoute,
  layoutRoute.addChildren([
    dashboardRoute,
    findingsRoute,
    findingDetailRoute,
    applicationsRoute,
    applicationDetailRoute,
    ingestionRoute,
    triageRoute,
    unmappedRoute,
    deduplicationRoute,
    attackChainsRoute,
    attackChainDetailRoute,
  ]),
])

export const router = createRouter({ routeTree })

// Type safety for router
declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
