import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Download } from 'lucide-react'
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
  a.click()
  URL.revokeObjectURL(url)
}

interface ExportButtonProps {
  filters: Record<string, string>
}

export function ExportButton({ filters }: ExportButtonProps) {
  const { t } = useTranslation()
  const [exporting, setExporting] = useState(false)

  async function handleExport(format: 'csv' | 'json') {
    setExporting(true)
    try {
      const blob = await findingsApi.exportFindings(filters, format)
      const ext = format === 'csv' ? 'csv' : 'json'
      downloadBlob(blob, `findings_export.${ext}`)
    } catch {
      // Error already thrown by exportFindings
    } finally {
      setExporting(false)
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" disabled={exporting}>
          <Download className="mr-1.5 h-4 w-4" />
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
  )
}
