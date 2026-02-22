import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from '@tanstack/react-router'
import { CheckCircle, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import * as applicationsApi from '@/api/applications'
import type { ApplicationSummary } from '@/types/application'

export function UnmappedAppsPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [apps, setApps] = useState<ApplicationSummary[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [loading, setLoading] = useState(false)

  const perPage = 25

  const fetchUnverified = useCallback(async () => {
    setLoading(true)
    try {
      const result = await applicationsApi.listUnverified(page, perPage)
      setApps(result.items)
      setTotal(result.total)
      setTotalPages(result.total_pages)
    } catch {
      // handled by client
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => {
    fetchUnverified()
  }, [fetchUnverified])

  async function handleVerify(id: string) {
    try {
      await applicationsApi.updateApplication(id, { is_verified: true })
      setApps((prev) => prev.filter((a) => a.id !== id))
      setTotal((n) => n - 1)
    } catch {
      // handled by client
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold">{t('nav.unmapped')}</h1>
          <Badge variant="outline" className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
            <AlertTriangle className="mr-1 h-3 w-3" />
            {total} unverified
          </Badge>
        </div>
      </div>

      <p className="text-sm text-muted-foreground">
        These applications were auto-created from scanner project names during ingestion.
        Review and verify them, or merge with existing applications.
      </p>

      {loading ? (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          {t('common.loading')}
        </div>
      ) : apps.length === 0 ? (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          No unmapped applications
        </div>
      ) : (
        <>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>App Code</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Business Unit</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="w-[120px]">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {apps.map((app) => (
                  <TableRow key={app.id}>
                    <TableCell className="font-mono text-sm">{app.app_code}</TableCell>
                    <TableCell
                      className="cursor-pointer font-medium hover:underline"
                      onClick={() =>
                        navigate({ to: '/applications/$id', params: { id: app.id } })
                      }
                    >
                      {app.app_name}
                    </TableCell>
                    <TableCell>
                      {app.business_unit || (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(app.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleVerify(app.id)}
                      >
                        <CheckCircle className="mr-1 h-3 w-3" />
                        Verify
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">
                Page {page} of {totalPages}
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
