import { useTranslation } from 'react-i18next'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from '@/components/ui/button'

type TablePaginationProps = {
  page: number
  totalPages: number
  onPageChange: (page: number) => void
}

/**
 * Generate the array of page numbers to display, using `null` for ellipsis gaps.
 *
 * Rules:
 * - If totalPages <= 7: show all pages
 * - If page <= 3: show [1,2,3,4,5,...,last]
 * - If page >= totalPages-2: show [1,...,last-4,last-3,last-2,last-1,last]
 * - Otherwise: show [1,...,page-1,page,page+1,...,last]
 */
function getPageNumbers(page: number, totalPages: number): (number | null)[] {
  if (totalPages <= 7) {
    return Array.from({ length: totalPages }, (_, i) => i + 1)
  }

  if (page <= 3) {
    return [1, 2, 3, 4, 5, null, totalPages]
  }

  if (page >= totalPages - 2) {
    return [1, null, totalPages - 4, totalPages - 3, totalPages - 2, totalPages - 1, totalPages]
  }

  return [1, null, page - 1, page, page + 1, null, totalPages]
}

export function TablePagination({ page, totalPages, onPageChange }: TablePaginationProps) {
  const { t } = useTranslation()
  const pages = getPageNumbers(page, totalPages)

  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-muted-foreground">
        {t('common.page')} {page} {t('common.of')} {totalPages}
      </span>
      <div className="flex items-center gap-1">
        <Button
          variant="outline"
          size="icon-sm"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
          aria-label={t('common.previous')}
        >
          <ChevronLeft className="h-4 w-4" />
        </Button>

        {pages.map((p, idx) =>
          p === null ? (
            <span key={`ellipsis-${idx}`} className="flex h-8 w-8 items-center justify-center text-sm text-muted-foreground">
              ...
            </span>
          ) : (
            <Button
              key={p}
              variant={p === page ? 'default' : 'outline'}
              size="icon-sm"
              onClick={() => onPageChange(p)}
              aria-current={p === page ? 'page' : undefined}
            >
              {p}
            </Button>
          ),
        )}

        <Button
          variant="outline"
          size="icon-sm"
          disabled={page >= totalPages}
          onClick={() => onPageChange(page + 1)}
          aria-label={t('common.next')}
        >
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  )
}
