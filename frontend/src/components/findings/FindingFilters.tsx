import { useTranslation } from 'react-i18next'
import { Search, X } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { FindingFilters as Filters } from '@/types/finding'

type Props = {
  filters: Filters
  onChange: (filters: Filters) => void
}

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'] as const
const STATUSES = [
  'New', 'Confirmed', 'In_Remediation', 'Mitigated', 'Verified',
  'Closed', 'False_Positive', 'Risk_Accepted', 'Deferred_Remediation',
] as const
const CATEGORIES = ['SAST', 'SCA', 'DAST'] as const

export function FindingFiltersPanel({ filters, onChange }: Props) {
  const { t } = useTranslation()

  const hasActiveFilters = filters.severity || filters.status || filters.category || filters.search

  return (
    <div className="flex flex-wrap items-center gap-3">
      {/* Search */}
      <div className="relative w-64">
        <Search className="absolute top-2.5 left-3 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder={t('common.search') + '...'}
          value={filters.search ?? ''}
          onChange={(e) => onChange({ ...filters, search: e.target.value || undefined })}
          className="pl-9"
        />
      </div>

      {/* Severity */}
      <Select
        value={filters.severity ?? '__all__'}
        onValueChange={(v) => onChange({ ...filters, severity: v === '__all__' ? undefined : v as Filters['severity'] })}
      >
        <SelectTrigger className="w-36">
          <SelectValue placeholder="Severity" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="__all__">All Severities</SelectItem>
          {SEVERITIES.map((s) => (
            <SelectItem key={s} value={s}>{s}</SelectItem>
          ))}
        </SelectContent>
      </Select>

      {/* Status */}
      <Select
        value={filters.status ?? '__all__'}
        onValueChange={(v) => onChange({ ...filters, status: v === '__all__' ? undefined : v as Filters['status'] })}
      >
        <SelectTrigger className="w-44">
          <SelectValue placeholder="Status" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="__all__">All Statuses</SelectItem>
          {STATUSES.map((s) => (
            <SelectItem key={s} value={s}>{s.replace(/_/g, ' ')}</SelectItem>
          ))}
        </SelectContent>
      </Select>

      {/* Category */}
      <Select
        value={filters.category ?? '__all__'}
        onValueChange={(v) => onChange({ ...filters, category: v === '__all__' ? undefined : v as Filters['category'] })}
      >
        <SelectTrigger className="w-32">
          <SelectValue placeholder="Category" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="__all__">All Categories</SelectItem>
          {CATEGORIES.map((c) => (
            <SelectItem key={c} value={c}>{c}</SelectItem>
          ))}
        </SelectContent>
      </Select>

      {/* Clear filters */}
      {hasActiveFilters && (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => onChange({})}
        >
          <X className="mr-1 h-3 w-3" />
          Clear
        </Button>
      )}
    </div>
  )
}
