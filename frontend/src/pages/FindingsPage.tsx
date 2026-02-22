import { useTranslation } from 'react-i18next'

export function FindingsPage() {
  const { t } = useTranslation()

  return (
    <div>
      <h1 className="text-2xl font-bold">{t('nav.findings')}</h1>
    </div>
  )
}
