import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import type { Column } from '@tanstack/react-table'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

/**
 * Sentinel value representing "no filter" / show all items.
 * Radix Select requires a non-empty string for SelectItem value,
 * so we use '__all__' consistent with FindingFilters.tsx.
 */
const ALL_VALUE = '__all__'

interface SelectOption {
  value: string
  label: string
}

interface SelectColumnFilterProps<TData> {
  column: Column<TData, unknown>
  options: readonly SelectOption[]
  placeholder?: string
}

export function SelectColumnFilter<TData>({
  column,
  options,
  placeholder,
}: SelectColumnFilterProps<TData>) {
  const { t } = useTranslation()

  const currentValue = (column.getFilterValue() as string) ?? ALL_VALUE

  const handleChange = useCallback(
    (selected: string) => {
      column.setFilterValue(selected === ALL_VALUE ? undefined : selected)
    },
    [column],
  )

  return (
    <Select value={currentValue} onValueChange={handleChange}>
      <SelectTrigger size="sm" className="h-7 w-full text-xs">
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL_VALUE}>
          {t('common.all', 'All')}
        </SelectItem>
        {options.map((opt) => (
          <SelectItem key={opt.value} value={opt.value}>
            {opt.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
