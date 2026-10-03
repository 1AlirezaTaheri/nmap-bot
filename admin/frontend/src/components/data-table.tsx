import * as React from 'react'
import { ArrowDown, ArrowUp, ChevronsUpDown } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Card } from './ui'
import { TableSkeleton, EmptyState } from './feedback'
import { formatNumber } from '@/lib/utils'

export type SortDirection = 'asc' | 'desc'

export interface Column<T> {
  key: string
  header: string
  /** Cell renderer. */
  cell: (row: T) => React.ReactNode
  /** Value used for client-side sorting. */
  sortValue?: (row: T) => string | number
  sortable?: boolean
  className?: string
  headerClassName?: string
}

export interface DataTableProps<T> {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string | number
  loading?: boolean
  emptyTitle?: string
  emptyDescription?: string
  onRowClick?: (row: T) => void
  sortKey?: string | null
  sortDirection?: SortDirection
  onSortChange?: (key: string | null) => void
  className?: string
}

/** Local sort so callers do not have to re-sort on every render. */
function compare(a: string | number, b: string | number, dir: SortDirection): number {
  const result = typeof a === 'number' && typeof b === 'number'
    ? a - b
    : String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' })
  return dir === 'asc' ? result : -result
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading = false,
  emptyTitle = 'Nothing here yet',
  emptyDescription,
  onRowClick,
  sortKey,
  sortDirection = 'asc',
  onSortChange,
  className,
}: DataTableProps<T>): JSX.Element {
  const sorted = React.useMemo(() => {
    if (!sortKey) return rows
    const column = columns.find((c) => c.key === sortKey)
    if (!column?.sortValue) return rows
    const accessor = column.sortValue
    return [...rows].sort((a, b) => compare(accessor(a), accessor(b), sortDirection))
  }, [rows, sortKey, sortDirection, columns])

  function toggleSort(column: Column<T>): void {
    if (!column.sortable || !onSortChange) return
    if (sortKey === column.key) {
      onSortChange(null) // third click clears the sort
    } else {
      onSortChange(column.key)
    }
  }

  if (loading) return <Card className={className}><TableSkeleton cols={columns.length} /></Card>

  if (rows.length === 0) {
    return (
      <Card className={className}>
        <EmptyState title={emptyTitle} {...(emptyDescription ? { description: emptyDescription } : {})} />
      </Card>
    )
  }

  return (
    <Card className={cn('overflow-hidden', className)}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-border">
              {columns.map((column) => (
                <th
                  key={column.key}
                  className={cn(
                    'whitespace-nowrap px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-muted',
                    column.headerClassName,
                    column.sortable && 'cursor-pointer select-none hover:text-fg',
                  )}
                  onClick={column.sortable ? () => toggleSort(column) : undefined}
                  aria-sort={
                    sortKey === column.key
                      ? sortDirection === 'asc'
                        ? 'ascending'
                        : 'descending'
                      : 'none'
                  }
                >
                  <span className="inline-flex items-center gap-1">
                    {column.header}
                    {column.sortable ? (
                      sortKey === column.key ? (
                        sortDirection === 'asc' ? (
                          <ArrowUp className="h-3 w-3 text-primary" />
                        ) : (
                          <ArrowDown className="h-3 w-3 text-primary" />
                        )
                      ) : (
                        <ChevronsUpDown className="h-3 w-3 opacity-40" />
                      )
                    ) : null}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((row) => (
              <tr
                key={rowKey(row)}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                className={cn(
                  'border-b border-border/60 last:border-0 transition-colors',
                  onRowClick && 'cursor-pointer hover:bg-elevated',
                )}
              >
                {columns.map((column) => (
                  <td key={column.key} className={cn('px-4 py-3 align-middle', column.className)}>
                    {column.cell(row)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

export interface PaginationProps {
  page: number
  pageSize: number
  total: number
  onPageChange: (page: number) => void
  className?: string
}

export function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
  className,
}: PaginationProps): JSX.Element | null {
  const pages = Math.max(1, Math.ceil(total / Math.max(1, pageSize)))
  if (pages <= 1) return null
  const from = (page - 1) * pageSize + 1
  const to = Math.min(page * pageSize, total)

  return (
    <div className={cn('flex items-center justify-between gap-3 text-sm', className)}>
      <p className="text-xs text-muted">
        Showing <span className="tabular-nums text-fg">{formatNumber(from)}</span>–
        <span className="tabular-nums text-fg">{formatNumber(to)}</span> of{' '}
        <span className="tabular-nums text-fg">{formatNumber(total)}</span>
      </p>
      <div className="flex items-center gap-1">
        <button
          className="rounded-md border border-border px-2.5 py-1 text-xs text-fg transition-colors hover:bg-elevated disabled:opacity-40"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
        >
          Previous
        </button>
        <span className="px-2 text-xs tabular-nums text-muted">
          {page} / {pages}
        </span>
        <button
          className="rounded-md border border-border px-2.5 py-1 text-xs text-fg transition-colors hover:bg-elevated disabled:opacity-40"
          disabled={page >= pages}
          onClick={() => onPageChange(page + 1)}
        >
          Next
        </button>
      </div>
    </div>
  )
}