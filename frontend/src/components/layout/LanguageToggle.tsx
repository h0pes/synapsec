import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Languages } from 'lucide-react'

const LANGUAGES = [
  { code: 'en', label: 'EN' },
  { code: 'it', label: 'IT' },
] as const

export function LanguageToggle() {
  const { i18n } = useTranslation()

  const current = i18n.language
  const next = LANGUAGES.find((l) => l.code !== current) ?? LANGUAGES[0]

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => i18n.changeLanguage(next.code)}
      aria-label={`Switch language to ${next.label}`}
      title={next.label}
    >
      <Languages className="h-4 w-4" />
    </Button>
  )
}
