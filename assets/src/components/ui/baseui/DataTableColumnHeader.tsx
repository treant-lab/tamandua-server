/**
 * DataTableColumnHeader - sortable header cell
 *
 * Used internally by DataTable. Renders the column label, sort indicator,
 * and (if `headerTooltip` is set in column.meta) a Tooltip wrapper.
 */

import * as React from 'react'
import type { Header } from '@tanstack/react-table'
import { ChevronDown, ChevronUp, ChevronsUpDown } from 'lucide-react'
import { Tooltip } from './Tooltip'

interface DataTableColumnHeaderProps<TData> {
  header: Header<TData, unknown>
}

export function DataTableColumnHeader<TData>({
  header,
}: DataTableColumnHeaderProps<TData>) {
  if (header.isPlaceholder) return null
  const column = header.column
  const canSort = column.getCanSort()
  const sortDir = column.getIsSorted()
  const align = (column.columnDef.meta?.align ?? 'start') as 'start' | 'center' | 'end'
  const tooltip = column.columnDef.meta?.headerTooltip

  const label = typeof column.columnDef.header === 'function'
    ? column.columnDef.header(header.getContext())
    : (column.columnDef.header as React.ReactNode)

  const inner = (
    <button
      type="button"
      onClick={canSort ? column.getToggleSortingHandler() : undefined}
      disabled={!canSort}
      aria-label={canSort ? `Sort by ${typeof label === 'string' ? label : column.id}` : undefined}
      style={{
        all: 'unset',
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--spacing-1)',
        cursor: canSort ? 'pointer' : 'default',
        color: 'var(--fg-2, var(--muted))',
        fontSize: 'var(--font-size-xs, 0.75rem)',
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
        width: '100%',
        justifyContent:
          align === 'end' ? 'flex-end' : align === 'center' ? 'center' : 'flex-start',
      }}
    >
      <span>{label}</span>
      {canSort && (
        sortDir === 'asc' ? (
          <ChevronUp size={12} aria-hidden />
        ) : sortDir === 'desc' ? (
          <ChevronDown size={12} aria-hidden />
        ) : (
          <ChevronsUpDown size={12} aria-hidden style={{ opacity: 0.5 }} />
        )
      )}
    </button>
  )

  return tooltip ? <Tooltip content={tooltip}>{inner}</Tooltip> : inner
}
