import { useCallback, useEffect, useState } from 'react'
import { useParams, useNavigate } from '@tanstack/react-router'
import { ArrowLeft, Shield, Building2, User, Code2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import * as applicationsApi from '@/api/applications'
import type { Application, AssetCriticality, AppStatus } from '@/types/application'

const CRITICALITY_COLORS: Record<AssetCriticality, string> = {
  Very_High: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
  High: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  Medium_High: 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200',
  Medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
  Medium_Low: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  Low: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
}

const STATUS_COLORS: Record<AppStatus, string> = {
  Active: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  Deprecated: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
  Decommissioned: 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200',
}

export function ApplicationDetailPage() {
  const { id } = useParams({ strict: false })
  const navigate = useNavigate()
  const [app, setApp] = useState<Application | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchApp = useCallback(async () => {
    if (!id) return
    setLoading(true)
    try {
      const data = await applicationsApi.getApplication(id)
      setApp(data)
    } catch {
      // handled by client
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => {
    fetchApp()
  }, [fetchApp])

  if (loading) {
    return <div className="flex h-64 items-center justify-center text-muted-foreground">Loading...</div>
  }

  if (!app) {
    return <div className="text-center text-muted-foreground">Application not found</div>
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate({ to: '/applications' })}>
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold">{app.app_name}</h1>
            <span className="font-mono text-sm text-muted-foreground">{app.app_code}</span>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Badge variant="outline" className={STATUS_COLORS[app.status]}>
              {app.status}
            </Badge>
            {app.criticality && (
              <Badge variant="outline" className={CRITICALITY_COLORS[app.criticality]}>
                {app.criticality.replace(/_/g, ' ')}
              </Badge>
            )}
            <Badge variant="outline">Tier {app.tier}</Badge>
            {app.is_verified ? (
              <Badge variant="outline" className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                Verified
              </Badge>
            ) : (
              <Badge variant="outline" className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
                Unverified
              </Badge>
            )}
          </div>
        </div>
      </div>

      {/* Description */}
      {app.description && (
        <Card>
          <CardContent className="pt-6">
            <p>{app.description}</p>
          </CardContent>
        </Card>
      )}

      {/* Ownership */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-4 w-4" /> Ownership
          </CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="font-medium">Business Owner:</span>{' '}
            {app.business_owner || <span className="text-muted-foreground">-</span>}
          </div>
          <div>
            <span className="font-medium">Technical Owner:</span>{' '}
            {app.technical_owner || <span className="text-muted-foreground">-</span>}
          </div>
          <div>
            <span className="font-medium">Security Champion:</span>{' '}
            {app.security_champion || <span className="text-muted-foreground">-</span>}
          </div>
          <div>
            <span className="font-medium">Business Unit:</span>{' '}
            {app.business_unit || <span className="text-muted-foreground">-</span>}
          </div>
        </CardContent>
      </Card>

      {/* Technical Details */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Code2 className="h-4 w-4" /> Technical Details
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="font-medium">Exposure:</span>{' '}
              {app.exposure || <span className="text-muted-foreground">-</span>}
            </div>
            <div>
              <span className="font-medium">Data Classification:</span>{' '}
              {app.data_classification || <span className="text-muted-foreground">-</span>}
            </div>
          </div>
          {app.technology_stack.length > 0 && (
            <div>
              <span className="font-medium">Technology Stack:</span>
              <div className="mt-1 flex flex-wrap gap-1">
                {app.technology_stack.map((tech) => (
                  <Badge key={tech} variant="secondary">{tech}</Badge>
                ))}
              </div>
            </div>
          )}
          {app.deployment_environment.length > 0 && (
            <div>
              <span className="font-medium">Deployment Environments:</span>
              <div className="mt-1 flex flex-wrap gap-1">
                {app.deployment_environment.map((env) => (
                  <Badge key={env} variant="secondary">{env}</Badge>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Organizational */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Building2 className="h-4 w-4" /> Organizational
          </CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="font-medium">SSA Code:</span>{' '}
            {app.ssa_code || <span className="text-muted-foreground">-</span>}
          </div>
          <div>
            <span className="font-medium">SSA Name:</span>{' '}
            {app.ssa_name || <span className="text-muted-foreground">-</span>}
          </div>
          <div>
            <span className="font-medium">Effective Office Owner:</span>{' '}
            {app.effective_office_owner || <span className="text-muted-foreground">-</span>}
          </div>
          <div>
            <span className="font-medium">Effective Office Name:</span>{' '}
            {app.effective_office_name || <span className="text-muted-foreground">-</span>}
          </div>
        </CardContent>
      </Card>

      {/* Compliance */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-4 w-4" /> Compliance
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 text-sm">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="font-medium">DORA FEI:</span>{' '}
              {app.is_dora_fei ? 'Yes' : 'No'}
            </div>
            <div>
              <span className="font-medium">GDPR Subject:</span>{' '}
              {app.is_gdpr_subject ? 'Yes' : 'No'}
            </div>
            <div>
              <span className="font-medium">PCI Data:</span>{' '}
              {app.has_pci_data ? 'Yes' : 'No'}
            </div>
            <div>
              <span className="font-medium">PSD2 Relevant:</span>{' '}
              {app.is_psd2_relevant ? 'Yes' : 'No'}
            </div>
          </div>
          {app.regulatory_scope.length > 0 && (
            <div>
              <span className="font-medium">Regulatory Scope:</span>
              <div className="mt-1 flex flex-wrap gap-1">
                {app.regulatory_scope.map((reg) => (
                  <Badge key={reg} variant="secondary">{reg}</Badge>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Timestamps */}
      <Separator />
      <div className="flex gap-6 text-xs text-muted-foreground">
        <span>Created: {new Date(app.created_at).toLocaleString()}</span>
        <span>Updated: {new Date(app.updated_at).toLocaleString()}</span>
      </div>
    </div>
  )
}
