import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import type { Column } from '@tanstack/react-table'
import { Input } from '@/components/ui/input'

interface DateRangeFilterValue {
  from: string
  to: string
}

interface DateRangeColumnFilterProps<TData> {
  column: Column<TData, unknown>
}

export function DateRangeColumnFilter<TData>({
  column,
}: DateRangeColumnFilterProps<TData>) {
  const { t } = useTranslation()
  const filterValue = column.getFilterValue() as DateRangeFilterValue | undefined

  const handleFromChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const from = e.target.value
      const to = filterValue?.to ?? ''
      // Clear filter entirely when both dates are empty
      column.setFilterValue(from || to ? { from, to } : undefined)
    },
    [column, filterValue?.to],
  )

  const handleToChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const from = filterValue?.from ?? ''
      const to = e.target.value
      column.setFilterValue(from || to ? { from, to } : undefined)
    },
    [column, filterValue?.from],
  )

  return (
    <div className="flex items-center gap-1">
      <Input
        type="date"
        value={filterValue?.from ?? ''}
        onChange={handleFromChange}
        aria-label={t('common.from', 'From')}
        className="h-7 text-xs"
      />
      <Input
        type="date"
        value={filterValue?.to ?? ''}
        onChange={handleToChange}
        aria-label={t('common.to', 'To')}
        className="h-7 text-xs"
      />
    </div>
  )
}
