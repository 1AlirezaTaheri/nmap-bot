import * as React from 'react'
import {
  ArrowDown,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  ChevronsUpDown,
  GripVertical,
  Settings2,
  type LucideIcon,
} from 'lucide-react'
import { cn, formatNumber } from '@/lib/utils'
import { Card } from './ui'
import { TableSkeleton, EmptyState } from './feedback'
import { Button, Popover, PopoverContent, PopoverTrigger, Checkbox } from './ui'

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
  /** Hidden by default; the operator re-enables it from the columns menu. */
  hidden?: boolean
  /** A column may not be hidden (e.g. the one that identifies the row). */
  keepVisible?: boolean
  /** Initial width in px. Columns without one share the remaining space. */
  width?: number
  /** Allow the operator to drag this column wider or narrower. */
  resizable?: boolean
}

export interface SortSpec {
  key: string
  direction: SortDirection
}

export interface DataTableProps<T> {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string | number
  loading?: boolean
  emptyTitle?: string
  emptyDescription?: string
  emptyIcon?: LucideIcon
  onRowClick?: (row: T) => void
  sortKey?: string | null
  sortDirection?: SortDirection
  onSortChange?: (key: string | null) => void
  className?: string

  /* --- new, all optional so existing call sites are unaffected --- */

  /** Column visibility menu. Omit to render no menu. */
  showColumnToggle?: boolean
  /** Multi-column sort state. Shift-clicking a header adds to it. */
  multiSort?: boolean
  sortSpecs?: readonly SortSpec[]
  onSortSpecsChange?: (specs: readonly SortSpec[]) => void
  /** Client-side row selection. */
  selectable?: boolean
  selectedKeys?: ReadonlySet<string | number>
  onSelectedKeysChange?: (keys: ReadonlySet<string | number>) => void
  /** Sticky header for long tables. */
  stickyHeader?: boolean
  /** Caption announced to screen readers; also shown visually when set. */
  caption?: string
}

/** Local sort so callers do not have to re-sort on every render. */
function compare(a: string | number, b: string | number, dir: SortDirection): number {
  const result = typeof a === 'number' && typeof b === 'number'
    ? a - b
    : String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' })
  return dir === 'asc' ? result : -result
}

/* -------------------------------------------------------------------------- */
/* Pagination                                                                */
/* -------------------------------------------------------------------------- */

export interface PaginationProps {
  page: number
  pageSize: number
  total: number
  onPageChange: (page: number) => void
  className?: string
  /** Called when the operator picks a different page size. */
  onPageSizeChange?: (pageSize: number) => void
  pageSizeOptions?: readonly number[]
}

const DEFAULT_PAGE_SIZES = [10, 25, 50, 100] as const

export function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = DEFAULT_PAGE_SIZES,
  className,
}: PaginationProps): JSX.Element | null {
  const pages = Math.max(1, Math.ceil(total / Math.max(1, pageSize)))
  if (pages <= 1 && !onPageSizeChange) return null

  const from = (page - 1) * pageSize + 1
  const to = Math.min(page * pageSize, total)

  // A short window around the current page, with the ends pinned. Renders as
  // `1 … 4 5 6 … 20` rather than twenty numbers.
  const window = new Set<number>([1, pages])
  for (let offset = -1; offset <= 1; offset += 1) {
    const candidate = page + offset
    if (candidate >= 1 && candidate <= pages) window.add(candidate)
  }
  const visible = [...window].sort((a, b) => a - b)

  return (
    <div
      className={cn(
        'flex flex-col items-center justify-between gap-3 text-sm sm:flex-row',
        className,
      )}
    >
      <p className="text-xs text-muted">
        {total === 0 ? (
          'No rows'
        ) : (
          <>
            Showing <span className="tabular-nums text-fg">{formatNumber(from)}</span>–
            <span className="tabular-nums text-fg">{formatNumber(to)}</span> of{' '}
            <span className="tabular-nums text-fg">{formatNumber(total)}</span>
          </>
        )}
      </p>

      <div className="flex items-center gap-2">
        {onPageSizeChange ? (
          <label className="flex items-center gap-1.5 text-xs text-muted">
            <span className="sr-only sm:not-sr-only">Rows</span>
            <select
              value={pageSize}
              onChange={(event) => onPageSizeChange(Number(event.target.value))}
              aria-label="Rows per page"
              className="rounded-md border border-input bg-bg px-2 py-1 text-xs text-fg outline-none focus:border-primary focus:ring-2 focus:ring-primary/25"
            >
              {pageSizeOptions.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
        ) : null}

        <nav className="flex items-center gap-1" aria-label="Pagination">
          <Button
            variant="outline"
            size="sm"
            className="h-8 px-2"
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
            aria-label="Previous page"
          >
            <ChevronLeft className="h-4 w-4" aria-hidden />
            <span className="sr-only">Previous</span>
          </Button>

          {visible.map((number, index) => {
            const previous = visible[index - 1]
            const gap = previous !== undefined && number - previous > 1
            return (
              <React.Fragment key={number}>
                {gap ? (
                  <span className="px-1 text-xs text-faint" aria-hidden>
                    …
                  </span>
                ) : null}
                <button
                  type="button"
                  onClick={() => onPageChange(number)}
                  aria-current={number === page ? 'page' : undefined}
                  aria-label={`Page ${number}`}
                  className={cn(
                    'h-8 min-w-8 rounded-md px-2 text-xs tabular-nums transition-colors',
                    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
                    number === page
                      ? 'bg-primary text-primary-fg'
                      : 'border border-border text-fg hover:bg-elevated',
                  )}
                >
                  {number}
                </button>
              </React.Fragment>
            )
          })}

          <Button
            variant="outline"
            size="sm"
            className="h-8 px-2"
            disabled={page >= pages}
            onClick={() => onPageChange(page + 1)}
            aria-label="Next page"
          >
            <ChevronRight className="h-4 w-4" aria-hidden />
            <span className="sr-only">Next</span>
          </Button>
        </nav>
      </div>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Column menu                                                               */
/* -------------------------------------------------------------------------- */

function ColumnMenu<T>({
  columns,
  hidden,
  onToggle,
  onReset,
}: {
  columns: Column<T>[]
  hidden: ReadonlySet<string>
  onToggle: (key: string) => void
  onReset: () => void
}): JSX.Element {
  const toggleable = columns.filter((column) => !column.keepVisible)

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" aria-label="Choose columns">
          <Settings2 className="h-4 w-4" aria-hidden />
          Columns
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-56">
        <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-faint">
          Visible columns
        </p>
        <ul className="max-h-64 space-y-1 overflow-y-auto">
          {toggleable.map((column) => (
            <li key={column.key}>
              <label className="flex cursor-pointer items-center gap-2 rounded-sm px-1 py-1 text-sm text-fg hover:bg-elevated">
                <Checkbox
                  checked={!hidden.has(column.key)}
                  onCheckedChange={() => onToggle(column.key)}
                  aria-label={`Toggle ${column.header}`}
                />
                <span className="truncate">{column.header}</span>
              </label>
            </li>
          ))}
        </ul>
        <Button variant="ghost" size="sm" className="mt-2 w-full" onClick={onReset}>
          Reset to default
        </Button>
      </PopoverContent>
    </Popover>
  )
}

/* -------------------------------------------------------------------------- */
/* DataTable                                                                 */
/* -------------------------------------------------------------------------- */

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading = false,
  emptyTitle = 'Nothing here yet',
  emptyDescription,
  emptyIcon,
  onRowClick,
  sortKey,
  sortDirection = 'asc',
  onSortChange,
  className,
  showColumnToggle = false,
  multiSort = false,
  sortSpecs,
  onSortSpecsChange,
  selectable = false,
  selectedKeys,
  onSelectedKeysChange,
  stickyHeader = false,
  caption,
}: DataTableProps<T>): JSX.Element {
  // Column visibility is local so a page does not have to own it. Keyed by
  // column key, not index, so reordering columns does not lose state.
  const [hidden, setHidden] = React.useState<ReadonlySet<string>>(() => {
    const initial = columns.filter((c) => c.hidden).map((c) => c.key)
    return new Set(initial)
  })

  // Drop hidden keys for columns that no longer exist, so removing a column
  // does not leave a stale entry behind forever.
  React.useEffect(() => {
    const present = new Set(columns.map((c) => c.key))
    setHidden((previous) => {
      const next = new Set([...previous].filter((key) => present.has(key)))
      return next.size === previous.size ? previous : next
    })
  }, [columns])

  const [widths, setWidths] = React.useState<Readonly<Record<string, number>>>({})

  // Effective sort: multi-sort specs when provided, else the single-key props.
  const effectiveSpecs: readonly SortSpec[] = React.useMemo(() => {
    if (multiSort && sortSpecs && sortSpecs.length > 0) return sortSpecs
    if (sortKey) return [{ key: sortKey, direction: sortDirection }]
    return []
  }, [multiSort, sortSpecs, sortKey, sortDirection])

  const visible = columns.filter((column) => !hidden.has(column.key))

  const sorted = React.useMemo(() => {
    if (effectiveSpecs.length === 0) return rows
    const accessors = effectiveSpecs.map((spec) => ({
      column: columns.find((c) => c.key === spec.key),
      direction: spec.direction,
    }))
    if (accessors.some((a) => !a.column?.sortValue)) return rows

    return [...rows].sort((a, b) => {
      for (const { column, direction } of accessors) {
        if (!column?.sortValue) continue
        const result = compare(column.sortValue(a), column.sortValue(b), direction)
        // Only fall through to the next column on a tie, which is what makes
        // the sort stable across multiple keys.
        if (result !== 0) return result
      }
      return 0
    })
  }, [rows, effectiveSpecs, columns])

  function handleSort(column: Column<T>, additive: boolean): void {
    if (!column.sortable) return

    if (!multiSort) {
      // Original behaviour: click toggles, a third click clears.
      if (!onSortChange) return
      if (sortKey !== column.key) {
        onSortChange(column.key)
      } else if (sortDirection === 'asc') {
        // Already ascending: flip by re-emitting the same key with desc. The
        // parent owns direction, so this keeps the old contract of "same key
        // means flipped" rather than inventing a new callback.
        onSortChange(column.key)
        window.setTimeout(() => onSortChange(null), 0)
      } else {
        onSortChange(null)
      }
      return
    }

    if (!onSortSpecsChange) return
    const existing = effectiveSpecs.find((spec) => spec.key === column.key)
    let next: SortSpec[]
    if (!existing) {
      // Shift-click appends; a plain click replaces, which is the convention
      // users have from every file manager and table they have used.
      next = additive
        ? [...effectiveSpecs, { key: column.key, direction: 'asc' }]
        : [{ key: column.key, direction: 'asc' }]
    } else if (existing.direction === 'asc') {
      next = effectiveSpecs.map((spec) =>
        spec.key === column.key ? { ...spec, direction: 'desc' as const } : spec,
      )
    } else {
      next = effectiveSpecs.filter((spec) => spec.key !== column.key)
    }
    onSortSpecsChange(next)
  }

  function toggleColumn(key: string): void {
    setHidden((previous) => {
      const next = new Set(previous)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const selection = selectedKeys ?? new Set<string | number>()

  function toggleRow(key: string | number): void {
    if (!onSelectedKeysChange) return
    const next = new Set(selection)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    onSelectedKeysChange(next)
  }

  function toggleAllVisible(): void {
    if (!onSelectedKeysChange) return
    const next = new Set(selection)
    const allSelected = sorted.every((row) => next.has(rowKey(row)))
    for (const row of sorted) {
      const key = rowKey(row)
      if (allSelected) next.delete(key)
      else next.add(key)
    }
    onSelectedKeysChange(next)
  }

  function startResize(event: React.PointerEvent, key: string): void {
    event.preventDefault()
    event.stopPropagation()
    const startX = event.clientX
    const startWidth = widths[key] ?? 0

    function onMove(move: PointerEvent): void {
      const next = Math.max(72, startWidth + (move.clientX - startX))
      setWidths((previous) => ({ ...previous, [key]: next }))
    }
    function onUp(): void {
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerup', onUp)
    }
    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onUp)
  }

  const hasHeader = showColumnToggle || (selectable && onSelectedKeysChange)

  if (loading) {
    return (
      <Card className={className}>
        <TableSkeleton cols={visible.length} />
      </Card>
    )
  }

  if (rows.length === 0) {
    return (
      <Card className={className}>
        <EmptyState
          title={emptyTitle}
          {...(emptyDescription ? { description: emptyDescription } : {})}
          {...(emptyIcon ? { icon: emptyIcon } : {})}
        />
      </Card>
    )
  }

  return (
    <Card className={cn('overflow-hidden', className)}>
      {hasHeader ? (
        <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-2.5">
          {selectable && onSelectedKeysChange ? (
            <label className="flex cursor-pointer items-center gap-2 text-xs text-muted">
              <Checkbox
                checked={sorted.length > 0 && sorted.every((row) => selection.has(rowKey(row)))}
                onCheckedChange={toggleAllVisible}
                aria-label="Select all rows on this page"
              />
              {selection.size > 0
                ? `${selection.size} selected`
                : 'Select all'}
            </label>
          ) : (
            <span />
          )}
          {showColumnToggle ? (
            <ColumnMenu
              columns={columns}
              hidden={hidden}
              onToggle={toggleColumn}
              onReset={() => {
                setHidden(new Set(columns.filter((c) => c.hidden).map((c) => c.key)))
                setWidths({})
              }}
            />
          ) : null}
        </div>
      ) : null}

      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          {caption ? <caption className="sr-only">{caption}</caption> : null}
          <thead className={cn(stickyHeader && 'sticky top-0 z-10 bg-surface')}>
            <tr className="border-b border-border">
              {selectable && onSelectedKeysChange ? (
                <th scope="col" className="w-10 px-4 py-3">
                  <span className="sr-only">Select</span>
                </th>
              ) : null}
              {visible.map((column) => {
                const spec = effectiveSpecs.find((s) => s.key === column.key)
                const width = widths[column.key] ?? column.width
                return (
                  <th
                    key={column.key}
                    scope="col"
                    style={width ? { width } : undefined}
                    aria-sort={
                      spec
                        ? spec.direction === 'asc'
                          ? 'ascending'
                          : 'descending'
                        : 'none'
                    }
                    className={cn(
                      'px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-muted',
                      column.headerClassName,
                      column.sortable &&
                        'cursor-pointer select-none hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
                    )}
                    onClick={
                      column.sortable
                        ? (event: React.MouseEvent) =>
                            handleSort(column, event.shiftKey)
                        : undefined
                    }
                  >
                    <span className="inline-flex items-center gap-1">
                      {column.header}
                      {column.sortable ? (
                        spec ? (
                          spec.direction === 'asc' ? (
                            <ArrowUp className="h-3 w-3 text-primary" aria-hidden />
                          ) : (
                            <ArrowDown className="h-3 w-3 text-primary" aria-hidden />
                          )
                        ) : (
                          <ChevronsUpDown className="h-3 w-3 opacity-40" aria-hidden />
                        )
                      ) : null}
                      {/* Sort ordinal, so a multi-column sort is legible. */}
                      {multiSort && spec ? (
                        <span className="text-[10px] tabular-nums text-primary">
                          {effectiveSpecs.findIndex((s) => s.key === column.key) + 1}
                        </span>
                      ) : null}
                    </span>
                    {column.resizable ? (
                      <span
                        role="separator"
                        aria-orientation="vertical"
                        aria-label={`Resize ${column.header} column`}
                        onPointerDown={(event) => startResize(event, column.key)}
                        onClick={(event) => event.stopPropagation()}
                        className="ml-1 inline-flex h-4 w-2 cursor-col-resize items-center justify-center text-faint hover:text-primary"
                      >
                        <GripVertical className="h-3 w-3" aria-hidden />
                      </span>
                    ) : null}
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody>
            {sorted.map((row) => {
              const key = rowKey(row)
              const isSelected = selection.has(key)
              return (
                <tr
                  key={key}
                  aria-selected={selectable ? isSelected : undefined}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  className={cn(
                    'border-b border-border/60 transition-colors last:border-0',
                    isSelected && 'bg-primary-soft/40',
                    onRowClick && !isSelected && 'cursor-pointer hover:bg-elevated',
                  )}
                >
                  {selectable && onSelectedKeysChange ? (
                    <td className="px-4 py-3 align-middle">
                      <Checkbox
                        checked={isSelected}
                        onCheckedChange={() => toggleRow(key)}
                        onClick={(event) => event.stopPropagation()}
                        aria-label={`Select row ${String(key)}`}
                      />
                    </td>
                  ) : null}
                  {visible.map((column) => (
                    <td
                      key={column.key}
                      className={cn('px-4 py-3 align-middle', column.className)}
                    >
                      {column.cell(row)}
                    </td>
                  ))}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Card>
  )
}