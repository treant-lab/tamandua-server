/**
 * DataTable - Headless table primitive on top of TanStack Table v8
 *
 * Phase A: sorting + pagination + filtering with client-side defaults and
 * `manualSorting` / `manualFiltering` / `manualPagination` escape hatches
 * for server-driven tables (Cases, Users, AuditLog, eventually Alerts).
 *
 * Phases B-E (selection, virtualization, expanding, column resize) are
 * intentionally NOT here — see DATATABLE_DESIGN.md §11.
 *
 * Usage (client mode):
 *   <DataTable
 *     data={rows}
 *     columns={columns}
 *     getRowId={(r) => r.id}
 *     enableSorting
 *   />
 *
 * Usage (server-paged):
 *   <DataTable
 *     data={rows}
 *     columns={columns}
 *     getRowId={(r) => r.id}
 *     manualPagination
 *     pageCount={totalPages}
 *     pagination={{ pageIndex: page - 1, pageSize: perPage }}
 *     onPaginationChange={({ pageIndex }) => setPage(pageIndex + 1)}
 *     totalRows={total}
 *     loadingState={loading ? 'loading' : 'idle'}
 *   />
 */

import * as React from 'react'
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table'
import type {
  ColumnFiltersState,
  PaginationState,
  Row,
  SortingState,
  Updater,
} from '@tanstack/react-table'
import { cn } from '@/lib/utils'
import { DataTableColumnHeader } from './DataTableColumnHeader'
import { DataTablePagination } from './DataTablePagination'
import { DataTableEmptyState } from './DataTableEmptyState'
import { DataTableSkeleton } from './DataTableSkeleton'
import { useControllable } from './useControllable'
import type {
  DataTableDensity,
  DataTableLoadingState,
  TamanduaColumnDef,
} from './DataTable.types'

interface DataTableProps<TData> {
  data: TData[]
  columns: TamanduaColumnDef<TData, unknown>[]
  /** Stable row identity — required for selection + key stability. */
  getRowId?: (row: TData, index: number) => string

  // Sorting
  enableSorting?: boolean
  manualSorting?: boolean
  sorting?: SortingState
  defaultSorting?: SortingState
  onSortingChange?: (next: SortingState) => void

  // Filtering
  manualFiltering?: boolean
  columnFilters?: ColumnFiltersState
  defaultColumnFilters?: ColumnFiltersState
  onColumnFiltersChange?: (next: ColumnFiltersState) => void
  globalFilter?: string
  onGlobalFilterChange?: (next: string) => void

  // Pagination
  enablePagination?: boolean
  manualPagination?: boolean
  pageCount?: number
  pagination?: PaginationState
  defaultPagination?: PaginationState
  onPaginationChange?: (next: PaginationState) => void
  totalRows?: number
  pageSizeOptions?: number[]

  // Interaction
  onRowClick?: (row: TData) => void

  // Presentation
  density?: DataTableDensity
  stickyHeader?: boolean
  loadingState?: DataTableLoadingState
  emptyState?: React.ReactNode
  className?: string
  ariaLabel?: string
}

const DENSITY_PADDING: Record<DataTableDensity, string> = {
  compact: 'var(--spacing-1) var(--spacing-3)',
  comfortable: 'var(--spacing-2) var(--spacing-3)',
  spacious: 'var(--spacing-3) var(--spacing-4)',
}

const NO_OP_PAGE_COUNT = -1

export function DataTable<TData>({
  data,
  columns,
  getRowId,
  enableSorting = false,
  manualSorting = false,
  sorting: sortingProp,
  defaultSorting,
  onSortingChange,
  manualFiltering = false,
  columnFilters: columnFiltersProp,
  defaultColumnFilters,
  onColumnFiltersChange,
  globalFilter,
  onGlobalFilterChange,
  enablePagination = true,
  manualPagination = false,
  pageCount,
  pagination: paginationProp,
  defaultPagination,
  onPaginationChange,
  totalRows,
  pageSizeOptions,
  onRowClick,
  density = 'comfortable',
  stickyHeader = false,
  loadingState = 'idle',
  emptyState,
  className,
  ariaLabel,
}: DataTableProps<TData>) {
  const [sorting, setSorting] = useControllable<SortingState>({
    controlled: sortingProp,
    defaultValue: defaultSorting ?? [],
    onChange: onSortingChange,
  })

  const [columnFilters, setColumnFilters] = useControllable<ColumnFiltersState>({
    controlled: columnFiltersProp,
    defaultValue: defaultColumnFilters ?? [],
    onChange: onColumnFiltersChange,
  })

  const [pagination, setPagination] = useControllable<PaginationState>({
    controlled: paginationProp,
    defaultValue: defaultPagination ?? { pageIndex: 0, pageSize: 25 },
    onChange: onPaginationChange,
  })

  // TanStack's `onXChange` props receive a TanStack Updater<T> (T | (prev) => T).
  // Our useControllable setters accept the same shape, so we can forward directly.
  const handleSortingChange = React.useCallback(
    (updater: Updater<SortingState>) => {
      setSorting((prev) =>
        typeof updater === 'function' ? (updater as (p: SortingState) => SortingState)(prev) : updater,
      )
    },
    [setSorting],
  )

  const handleColumnFiltersChange = React.useCallback(
    (updater: Updater<ColumnFiltersState>) => {
      setColumnFilters((prev) =>
        typeof updater === 'function'
          ? (updater as (p: ColumnFiltersState) => ColumnFiltersState)(prev)
          : updater,
      )
    },
    [setColumnFilters],
  )

  const handlePaginationChange = React.useCallback(
    (updater: Updater<PaginationState>) => {
      setPagination((prev) =>
        typeof updater === 'function'
          ? (updater as (p: PaginationState) => PaginationState)(prev)
          : updater,
      )
    },
    [setPagination],
  )

  const handleGlobalFilterChange = React.useCallback(
    (updater: unknown) => {
      // TanStack passes either a value or an updater fn here. We only care
      // about the resolved string because we don't track previous globalFilter
      // inside the table (it's owned by the consumer in controlled mode).
      const next =
        typeof updater === 'function'
          ? (updater as (prev: string) => string)(globalFilter ?? '')
          : (updater as string)
      onGlobalFilterChange?.(next ?? '')
    },
    [globalFilter, onGlobalFilterChange],
  )

  const table = useReactTable<TData>({
    data,
    columns,
    getRowId,
    state: {
      sorting,
      columnFilters,
      pagination,
      ...(globalFilter !== undefined ? { globalFilter } : {}),
    },
    enableSorting,
    manualSorting,
    manualFiltering,
    manualPagination,
    pageCount: manualPagination ? (pageCount ?? NO_OP_PAGE_COUNT) : undefined,
    onSortingChange: handleSortingChange,
    onColumnFiltersChange: handleColumnFiltersChange,
    onPaginationChange: handlePaginationChange,
    onGlobalFilterChange: onGlobalFilterChange ? handleGlobalFilterChange : undefined,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: enableSorting && !manualSorting ? getSortedRowModel() : undefined,
    getFilteredRowModel: !manualFiltering ? getFilteredRowModel() : undefined,
    getPaginationRowModel:
      enablePagination && !manualPagination ? getPaginationRowModel() : undefined,
  })

  const rows = table.getRowModel().rows
  const visibleColumns = table.getVisibleLeafColumns()
  const columnCount = visibleColumns.length
  const isLoading = loadingState === 'loading'
  const isEmpty = !isLoading && rows.length === 0

  const handleRowClick = React.useCallback(
    (e: React.MouseEvent<HTMLTableRowElement>, row: Row<TData>) => {
      if (!onRowClick) return
      const target = e.target as HTMLElement
      // Don't fire when clicking interactive children or columns that opted out.
      if (target.closest('button, a, input, select, [role="menu"], [data-swallow-row-click="true"]')) {
        return
      }
      onRowClick(row.original)
    },
    [onRowClick],
  )

  return (
    <div
      className={cn(className)}
      style={{
        position: 'relative',
        border: '1px solid var(--border)',
        borderRadius: 'var(--r-md)',
        background: 'var(--surface)',
        overflow: 'hidden',
      }}
    >
      <div style={{ overflowX: 'auto' }}>
        <table
          role="grid"
          aria-label={ariaLabel}
          aria-rowcount={totalRows ?? rows.length}
          aria-busy={isLoading || undefined}
          style={{
            width: '100%',
            borderCollapse: 'separate',
            borderSpacing: 0,
            tableLayout: 'auto',
          }}
        >
          <thead
            style={{
              position: stickyHeader ? 'sticky' : 'static',
              top: stickyHeader ? 0 : undefined,
              zIndex: stickyHeader ? 'var(--z-sticky, 200)' : undefined,
              background: 'var(--surface-2, var(--surface))',
            }}
          >
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id} role="row">
                {hg.headers.map((header) => {
                  const meta = header.column.columnDef.meta
                  const width = meta?.width
                  return (
                    <th
                      key={header.id}
                      role="columnheader"
                      aria-sort={
                        header.column.getIsSorted() === 'asc'
                          ? 'ascending'
                          : header.column.getIsSorted() === 'desc'
                            ? 'descending'
                            : header.column.getCanSort()
                              ? 'none'
                              : undefined
                      }
                      style={{
                        padding: DENSITY_PADDING[density],
                        textAlign:
                          meta?.align === 'end' ? 'right' : meta?.align === 'center' ? 'center' : 'left',
                        borderBottom: '1px solid var(--hairline, var(--border))',
                        width: width ? `${width}px` : undefined,
                        minWidth: meta?.minWidth ? `${meta.minWidth}px` : undefined,
                        maxWidth: meta?.maxWidth ? `${meta.maxWidth}px` : undefined,
                        whiteSpace: 'nowrap',
                      }}
                    >
                      <DataTableColumnHeader header={header} />
                    </th>
                  )
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {isLoading && rows.length === 0 ? (
              <tr role="row">
                <td colSpan={columnCount} style={{ padding: 0 }}>
                  <DataTableSkeleton rows={8} columns={columnCount} />
                </td>
              </tr>
            ) : isEmpty ? (
              <tr role="row">
                <td colSpan={columnCount} style={{ padding: 0 }}>
                  {emptyState ?? <DataTableEmptyState />}
                </td>
              </tr>
            ) : (
              rows.map((row, idx) => (
                <tr
                  key={row.id}
                  role="row"
                  aria-rowindex={idx + 1}
                  onClick={(e) => handleRowClick(e, row)}
                  style={{
                    cursor: onRowClick ? 'pointer' : 'default',
                    borderBottom: '1px solid var(--hairline, var(--border))',
                  }}
                >
                  {row.getVisibleCells().map((cell) => {
                    const meta = cell.column.columnDef.meta
                    const truncate = meta?.truncate ?? true
                    const isRowHeader = meta?.isRowHeader
                    const Cell = isRowHeader ? 'th' : 'td'
                    return (
                      <Cell
                        key={cell.id}
                        {...(isRowHeader ? { scope: 'row' } : {})}
                        data-swallow-row-click={meta?.swallowRowClick || undefined}
                        style={{
                          padding: DENSITY_PADDING[density],
                          textAlign:
                            meta?.align === 'end'
                              ? 'right'
                              : meta?.align === 'center'
                                ? 'center'
                                : 'left',
                          color: 'var(--fg)',
                          fontSize: 'var(--font-size-sm, 0.875rem)',
                          width: meta?.width ? `${meta.width}px` : undefined,
                          maxWidth: meta?.maxWidth ? `${meta.maxWidth}px` : undefined,
                          minWidth: meta?.minWidth ? `${meta.minWidth}px` : undefined,
                          overflow: truncate ? 'hidden' : undefined,
                          textOverflow: truncate ? 'ellipsis' : undefined,
                          whiteSpace: truncate ? 'nowrap' : undefined,
                          fontWeight: isRowHeader ? 500 : undefined,
                        }}
                      >
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </Cell>
                    )
                  })}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      {enablePagination && !isEmpty && (
        <DataTablePagination
          table={table}
          totalRows={totalRows}
          pageSizeOptions={pageSizeOptions}
        />
      )}
    </div>
  )
}

export default DataTable
