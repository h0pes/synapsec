import { useTranslation } from 'react-i18next'

export function IngestionPage() {
  const { t } = useTranslation()

  return (
    <div>
      <h1 className="text-2xl font-bold">{t('nav.ingestion')}</h1>
    </div>
  )
}
