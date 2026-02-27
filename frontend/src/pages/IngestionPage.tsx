import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { CheckCircle2 } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { PageHeader } from '@/components/ui/page-header'
import { FileUpload } from '@/components/ingestion/FileUpload'
import { IngestionHistory } from '@/components/ingestion/IngestionHistory'
import type { IngestionResult } from '@/api/ingestion'

export function IngestionPage() {
  const { t } = useTranslation()
  const [refreshTrigger, setRefreshTrigger] = useState(0)
  const [lastResult, setLastResult] = useState<IngestionResult | null>(null)

  function handleComplete(result: IngestionResult) {
    setLastResult(result)
    setRefreshTrigger((n) => n + 1)
  }

  return (
    <div className="space-y-6">
      <PageHeader title={t('nav.ingestion')} />

      <div className="grid gap-6 lg:grid-cols-2">
        <FileUpload onComplete={handleComplete} />

        {/* Result summary */}
        {lastResult && (
          <Card>
            <CardContent className="flex items-start gap-4 pt-6">
              <CheckCircle2 className="mt-0.5 h-6 w-6 shrink-0 text-green-600" />
              <div className="space-y-2">
                <p className="font-medium">Import Complete</p>
                <div className="grid grid-cols-2 gap-x-8 gap-y-1 text-sm">
                  <span>Total parsed:</span>
                  <span className="font-mono">{lastResult.total_parsed}</span>
                  <span>New findings:</span>
                  <span className="font-mono text-green-600">{lastResult.new_findings}</span>
                  <span>Updated:</span>
                  <span className="font-mono text-blue-600">{lastResult.updated_findings}</span>
                  <span>Duplicates:</span>
                  <span className="font-mono text-muted-foreground">{lastResult.duplicates}</span>
                  <span>Errors:</span>
                  <span className={`font-mono ${lastResult.errors > 0 ? 'text-destructive' : ''}`}>
                    {lastResult.errors}
                  </span>
                  <span>Quarantined:</span>
                  <span className="font-mono">{lastResult.quarantined}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* History */}
      <div>
        <h2 className="mb-4 text-lg font-semibold">Import History</h2>
        <IngestionHistory refreshTrigger={refreshTrigger} />
      </div>
    </div>
  )
}
