import { useTranslation } from 'react-i18next'

export function DashboardPage() {
  const { t } = useTranslation()

  return (
    <div>
      <h1 className="text-2xl font-bold">{t('nav.dashboard')}</h1>
      <p className="mt-2 text-muted-foreground">
        {t('app.subtitle')}
      </p>
    </div>
  )
}
