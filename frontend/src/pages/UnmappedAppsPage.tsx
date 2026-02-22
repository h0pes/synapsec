import { useTranslation } from 'react-i18next'

export function UnmappedAppsPage() {
  const { t } = useTranslation()

  return (
    <div>
      <h1 className="text-2xl font-bold">{t('nav.unmapped')}</h1>
    </div>
  )
}
