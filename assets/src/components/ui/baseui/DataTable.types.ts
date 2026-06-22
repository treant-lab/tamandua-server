/**
 * DataTable public types
 *
 * Extends TanStack Table v8 ColumnDef with Tamandua-specific meta:
 *   - align          → text alignment inside cells (start | center | end)
 *   - width          → fixed pixel width (overrides flex)
 *   - minWidth       → minimum pixel width
 *   - maxWidth       → maximum pixel width
 *   - truncate       → ellipsize overflowing text (default true)
 *   - hidden         → omit column from render (kept in state for toggling)
 *   - isRowHeader    → render as <th scope="row"> (a11y for screen readers)
 *   - swallowRowClick→ click on this cell does NOT trigger onRowClick
 *   - skipKeyboardNav→ skip this cell when arrow-navigating
 *   - headerTooltip  → tooltip text shown on the column header
 */

import type { ColumnDef, RowData } from '@tanstack/react-table'

declare module '@tanstack/react-table' {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface ColumnMeta<TData extends RowData, TValue> {
    align?: 'start' | 'center' | 'end'
    width?: number
    minWidth?: number
    maxWidth?: number
    truncate?: boolean
    hidden?: boolean
    isRowHeader?: boolean
    swallowRowClick?: boolean
    skipKeyboardNav?: boolean
    headerTooltip?: string
  }
}

export type TamanduaColumnDef<TData, TValue = unknown> = ColumnDef<TData, TValue>

export type DataTableDensity = 'compact' | 'comfortable' | 'spacious'

export type DataTableLoadingState = 'idle' | 'loading' | 'refreshing' | 'error'

export interface DataTablePaginationState {
  pageIndex: number
  pageSize: number
}

export interface DataTableSortingItem {
  id: string
  desc: boolean
}
