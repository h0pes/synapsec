import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Download, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import * as findingsApi from '@/api/findings'

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

interface ExportButtonProps {
  filters: Record<string, string>
}

export function ExportButton({ filters }: ExportButtonProps) {
  const { t } = useTranslation()
  const [exporting, setExporting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleExport(format: 'csv' | 'json') {
    setExporting(true)
    setError(null)
    try {
      const blob = await findingsApi.exportFindings(filters, format)
      const ts = new Date().toISOString().slice(0, 16).replace('T', '_').replace(':', '-')
      downloadBlob(blob, `findings_export_${ts}.${format}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Export failed')
    } finally {
      setExporting(false)
    }
  }

  return (
    <div className="flex items-center gap-2">
      {error && (
        <span className="text-xs text-destructive">{error}</span>
      )}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" disabled={exporting}>
            {exporting
              ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
              : <Download className="mr-1.5 h-4 w-4" />}
            {t('findings.export')}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onClick={() => handleExport('csv')}>
            {t('findings.exportCsv')}
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => handleExport('json')}>
            {t('findings.exportJson')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}
