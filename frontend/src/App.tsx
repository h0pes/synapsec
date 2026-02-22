import { useTranslation } from 'react-i18next'

function App() {
  const { t } = useTranslation()

  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="text-center">
        <h1 className="text-4xl font-bold">{t('app.title')}</h1>
        <p className="mt-2 text-muted-foreground">{t('app.subtitle')}</p>
      </div>
    </div>
  )
}

export default App
