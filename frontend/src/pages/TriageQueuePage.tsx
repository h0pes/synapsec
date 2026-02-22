import { useTranslation } from 'react-i18next'

export function TriageQueuePage() {
  const { t } = useTranslation()

  return (
    <div>
      <h1 className="text-2xl font-bold">{t('nav.triage')}</h1>
    </div>
  )
}
