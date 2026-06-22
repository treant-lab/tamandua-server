/**
 * DataTablePagination - first / prev / numbers / next / last + page-size
 *
 * Mirrors the hand-rolled pagination patterns already used across pages
 * (AuditLog, Cases, Users) so the migration is mechanical. Uses the
 * BaseUI <Select> for page-size picking.
 */

import * as React from 'react'
import type { Table } from '@tanstack/react-table'
import { ChevronFirst, ChevronLast, ChevronLeft, ChevronRight } from 'lucide-react'
import { Select, SelectItem } from './Select'

interface DataTablePaginationProps<TData> {
  table: Table<TData>
  /** Show "Showing X-Y of Z" summary. Default: true. */
  showSummary?: boolean
  /** Page size options. Default: [25, 50, 100, 250]. */
  pageSizeOptions?: number[]
  /** Total row count (server-paginated only — when manualPagination=true). */
  totalRows?: number
}

const BTN_STYLE: React.CSSProperties = {
  all: 'unset',
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  width: '2rem',
  height: '2rem',
  borderRadius: 'var(--r-sm)',
  border: '1px solid var(--border)',
  background: 'var(--surface)',
  color: 'var(--fg)',
  cursor: 'pointer',
  fontSize: 'var(--font-size-sm, 0.875rem)',
}

const BTN_DISABLED_STYLE: React.CSSProperties = {
  opacity: 0.4,
  cursor: 'not-allowed',
}

const BTN_ACTIVE_STYLE: React.CSSProperties = {
  background: 'var(--surface-2, var(--surface))',
  borderColor: 'var(--accent, var(--fg))',
  fontWeight: 600,
}

export function DataTablePagination<TData>({
  table,
  showSummary = true,
  pageSizeOptions = [25, 50, 100, 250],
  totalRows,
}: DataTablePaginationProps<TData>) {
  const pageIndex = table.getState().pagination.pageIndex
  const pageSize = table.getState().pagination.pageSize
  const pageCount = table.getPageCount()
  const total = totalRows ?? table.getFilteredRowModel().rows.length

  const start = total === 0 ? 0 : pageIndex * pageSize + 1
  const end = Math.min(total, (pageIndex + 1) * pageSize)

  // Build a windowed page-number list: [1] ... [p-1] [p] [p+1] ... [N]
  const numbers = React.useMemo(() => {
    const out: Array<number | 'ellipsis'> = []
    const cur = pageIndex + 1
    const n = pageCount
    if (n <= 7) {
      for (let i = 1; i <= n; i++) out.push(i)
      return out
    }
    out.push(1)
    if (cur > 4) out.push('ellipsis')
    const lo = Math.max(2, cur - 1)
    const hi = Math.min(n - 1, cur + 1)
    for (let i = lo; i <= hi; i++) out.push(i)
    if (cur < n - 3) out.push('ellipsis')
    out.push(n)
    return out
  }, [pageIndex, pageCount])

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 'var(--spacing-3)',
        padding: 'var(--spacing-3) var(--spacing-4)',
        borderTop: '1px solid var(--border)',
        flexWrap: 'wrap',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--spacing-3)',
          color: 'var(--muted)',
          fontSize: 'var(--font-size-sm, 0.875rem)',
        }}
      >
        {showSummary && (
          <span>
            Showing {start}-{end} of {total}
          </span>
        )}
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--spacing-2)' }}>
          Rows per page
          <Select
            value={String(pageSize)}
            onValueChange={(v) => table.setPageSize(Number(v))}
          >
            {pageSizeOptions.map((s) => (
              <SelectItem key={s} value={String(s)}>
                {s}
              </SelectItem>
            ))}
          </Select>
        </span>
      </div>

      <nav
        aria-label="Pagination"
        style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--spacing-1)' }}
      >
        <button
          type="button"
          aria-label="First page"
          onClick={() => table.setPageIndex(0)}
          disabled={!table.getCanPreviousPage()}
          style={{ ...BTN_STYLE, ...(!table.getCanPreviousPage() ? BTN_DISABLED_STYLE : {}) }}
        >
          <ChevronFirst size={14} aria-hidden />
        </button>
        <button
          type="button"
          aria-label="Previous page"
          onClick={() => table.previousPage()}
          disabled={!table.getCanPreviousPage()}
          style={{ ...BTN_STYLE, ...(!table.getCanPreviousPage() ? BTN_DISABLED_STYLE : {}) }}
        >
          <ChevronLeft size={14} aria-hidden />
        </button>
        {numbers.map((n, i) =>
          n === 'ellipsis' ? (
            <span
              key={`e-${i}`}
              aria-hidden
              style={{ padding: '0 var(--spacing-1)', color: 'var(--muted)' }}
            >
              …
            </span>
          ) : (
            <button
              key={n}
              type="button"
              aria-label={`Page ${n}`}
              aria-current={n === pageIndex + 1 ? 'page' : undefined}
              onClick={() => table.setPageIndex(n - 1)}
              style={{
                ...BTN_STYLE,
                ...(n === pageIndex + 1 ? BTN_ACTIVE_STYLE : {}),
              }}
            >
              {n}
            </button>
          ),
        )}
        <button
          type="button"
          aria-label="Next page"
          onClick={() => table.nextPage()}
          disabled={!table.getCanNextPage()}
          style={{ ...BTN_STYLE, ...(!table.getCanNextPage() ? BTN_DISABLED_STYLE : {}) }}
        >
          <ChevronRight size={14} aria-hidden />
        </button>
        <button
          type="button"
          aria-label="Last page"
          onClick={() => table.setPageIndex(Math.max(0, pageCount - 1))}
          disabled={!table.getCanNextPage()}
          style={{ ...BTN_STYLE, ...(!table.getCanNextPage() ? BTN_DISABLED_STYLE : {}) }}
        >
          <ChevronLast size={14} aria-hidden />
        </button>
      </nav>
    </div>
  )
}
