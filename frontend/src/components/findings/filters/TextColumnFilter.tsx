import { useState, useEffect, useCallback } from 'react'
import type { Column } from '@tanstack/react-table'
import { Input } from '@/components/ui/input'

/** Debounce delay in milliseconds to prevent excessive API calls for server-side filtering */
const DEBOUNCE_MS = 300

interface TextColumnFilterProps<TData> {
  column: Column<TData, unknown>
  placeholder?: string
}

/**
 * A debounced text input filter for TanStack Table column headers.
 *
 * Maintains local input state for responsive typing and debounces
 * the propagation to `column.setFilterValue()`. External changes
 * (e.g., clearing all filters) sync back to the local input via
 * the internal `DebouncedInput` component.
 */
export function TextColumnFilter<TData>({
  column,
  placeholder = '',
}: TextColumnFilterProps<TData>) {
  const columnFilterValue = (column.getFilterValue() as string) ?? ''

  return (
    <DebouncedInput
      value={columnFilterValue}
      onChange={(value) => column.setFilterValue(value || undefined)}
      placeholder={placeholder}
    />
  )
}

interface DebouncedInputProps {
  value: string
  onChange: (value: string) => void
  placeholder: string
}

function DebouncedInput({ value, onChange, placeholder }: DebouncedInputProps) {
  const [inputValue, setInputValue] = useState(value)

  // Sync local state when the external value changes (e.g., filter reset)
  useEffect(() => {
    setInputValue(value)
  }, [value])

  // Debounced callback to parent
  useEffect(() => {
    const timeout = setTimeout(() => {
      if (inputValue !== value) {
        onChange(inputValue)
      }
    }, DEBOUNCE_MS)

    return () => clearTimeout(timeout)
  }, [inputValue, onChange, value])

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setInputValue(e.target.value)
    },
    [],
  )

  return (
    <Input
      value={inputValue}
      onChange={handleChange}
      placeholder={placeholder}
      className="h-7 text-xs"
    />
  )
}
