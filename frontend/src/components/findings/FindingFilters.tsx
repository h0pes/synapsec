import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { Search } from 'lucide-react'
import { Input } from '@/components/ui/input'

type Props = {
  search: string
  onSearchChange: (search: string) => void
}

export function FindingSearchBar({ search, onSearchChange }: Props) {
  const { t } = useTranslation()
  const [localSearch, setLocalSearch] = useState(search)

  // Debounce: propagate to parent after 300ms of inactivity
  useEffect(() => {
    const timeout = setTimeout(() => {
      if (localSearch !== search) {
        onSearchChange(localSearch)
      }
    }, 300)
    return () => clearTimeout(timeout)
  }, [localSearch, onSearchChange, search])

  // Sync from parent when search is cleared externally
  useEffect(() => {
    setLocalSearch(search)
  }, [search])

  return (
    <div className="relative w-64">
      <Search className="absolute top-2.5 left-3 h-4 w-4 text-muted-foreground" />
      <Input
        placeholder={t('common.search') + '...'}
        value={localSearch}
        onChange={(e) => setLocalSearch(e.target.value)}
        className="pl-9"
      />
    </div>
  )
}
