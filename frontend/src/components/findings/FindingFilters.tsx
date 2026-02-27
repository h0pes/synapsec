import { useTranslation } from 'react-i18next'
import { Search } from 'lucide-react'
import { Input } from '@/components/ui/input'

type Props = {
  search: string
  onSearchChange: (search: string) => void
}

export function FindingSearchBar({ search, onSearchChange }: Props) {
  const { t } = useTranslation()

  return (
    <div className="relative w-64">
      <Search className="absolute top-2.5 left-3 h-4 w-4 text-muted-foreground" />
      <Input
        placeholder={t('common.search') + '...'}
        value={search}
        onChange={(e) => onSearchChange(e.target.value)}
        className="pl-9"
      />
    </div>
  )
}
