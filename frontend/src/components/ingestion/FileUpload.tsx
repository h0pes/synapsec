import { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Upload, FileText, X, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import * as ingestionApi from '@/api/ingestion'
import type { IngestionResult } from '@/api/ingestion'

type Props = {
  onComplete: (result: IngestionResult) => void
}

export function FileUpload({ onComplete }: Props) {
  const { t } = useTranslation()
  const [file, setFile] = useState<File | null>(null)
  const [parserType, setParserType] = useState('sonarqube')
  const [format, setFormat] = useState('json')
  const [uploading, setUploading] = useState(false)
  const [dragOver, setDragOver] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleFile = useCallback((f: File) => {
    setFile(f)
    setError(null)
  }, [])

  function handleDrop(e: React.DragEvent) {
    e.preventDefault()
    setDragOver(false)
    const dropped = e.dataTransfer.files[0]
    if (dropped) handleFile(dropped)
  }

  function handleFileInput(e: React.ChangeEvent<HTMLInputElement>) {
    const selected = e.target.files?.[0]
    if (selected) handleFile(selected)
  }

  async function handleUpload() {
    if (!file) return
    setUploading(true)
    setError(null)
    try {
      const result = await ingestionApi.uploadFile(file, parserType, format)
      setFile(null)
      onComplete(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('ingestion.title')}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Drop zone */}
        <div
          className={`relative flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-8 transition-colors ${
            dragOver
              ? 'border-primary bg-primary/5'
              : 'border-muted-foreground/25 hover:border-muted-foreground/50'
          }`}
          onDragOver={(e) => {
            e.preventDefault()
            setDragOver(true)
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
        >
          {file ? (
            <div className="flex items-center gap-3">
              <FileText className="h-8 w-8 text-muted-foreground" />
              <div>
                <p className="font-medium">{file.name}</p>
                <p className="text-sm text-muted-foreground">
                  {(file.size / 1024).toFixed(1)} KB
                </p>
              </div>
              <Button
                variant="ghost"
                size="icon"
                aria-label={t('ingestion.clearFile')}
                onClick={() => setFile(null)}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
          ) : (
            <>
              <Upload className="mb-2 h-8 w-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground">
                {t('ingestion.dragDropText')}{' '}
                <label className="cursor-pointer font-medium text-primary underline-offset-4 hover:underline">
                  {t('ingestion.browse')}
                  <input
                    type="file"
                    className="hidden"
                    accept=".json,.csv,.xml,.sarif"
                    onChange={handleFileInput}
                  />
                </label>
              </p>
              <p className="mt-1 text-xs text-muted-foreground">
                {t('ingestion.supportedFormats')}
              </p>
            </>
          )}
        </div>

        {/* Options */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label>{t('ingestion.parserType')}</Label>
            <Select value={parserType} onValueChange={setParserType}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="sonarqube">SonarQube</SelectItem>
                <SelectItem value="sarif">SARIF</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>{t('ingestion.format')}</Label>
            <Select value={format} onValueChange={setFormat}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="json">JSON</SelectItem>
                <SelectItem value="csv">CSV</SelectItem>
                <SelectItem value="sarif">SARIF</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Error */}
        {error && (
          <p className="text-sm text-destructive">{error}</p>
        )}

        {/* Upload button */}
        <Button
          className="w-full"
          disabled={!file || uploading}
          onClick={handleUpload}
        >
          {uploading ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              {t('ingestion.uploading')}
            </>
          ) : (
            <>
              <Upload className="mr-2 h-4 w-4" />
              {t('ingestion.upload')}
            </>
          )}
        </Button>
      </CardContent>
    </Card>
  )
}
