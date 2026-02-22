import { useTranslation } from 'react-i18next'

export function ApplicationsPage() {
  const { t } = useTranslation()

  return (
    <div>
      <h1 className="text-2xl font-bold">{t('nav.applications')}</h1>
    </div>
  )
}
