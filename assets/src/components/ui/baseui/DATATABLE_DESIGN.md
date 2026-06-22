# `<DataTable>` BaseUI Primitive — Design Doc (v1)

> **Status:** Design only. NOT YET IMPLEMENTED. The next agent picks this up and
> ships `DataTable.tsx` + sub-components into `apps/tamandua_server/assets/src/components/ui/baseui/`.
>
> **Author intent (2026-06-22):** Tamandua analyst pages (Alerts, Agents,
> Events, Assets, Vulnerabilities, DetectionRules, AuditLog, …) all hand-roll
> sort / filter / select / paginate state on top of bespoke `.map(row => …)`
> markup. The cost is no longer the rendering — it's the slow divergence
> between pages (Alerts has multi-sort, Agents has none; Assets has page-size,
> Events doesn't; everyone keyboard-handles arrows differently or not at all).
> This doc specifies a single primitive that lets a page declare *what* the
> columns are and hand off *how* they sort/select/paginate/render.

---

## 1. Goals & non-goals

### Goals (v1)

- One JSX call per page: `<DataTable columns={…} data={…} />` covers 80 % of analyst tables.
- Headless-first, design-token-styled, dark-mode native — same convention as
  `Dialog`, `Popover`, `Menu`, `Tooltip`, `Select`, `Switch`, `Checkbox`.
- Sorting (single + multi), row selection (single + multi, with page-vs-all-pages
  semantics), pagination (client OR server), client filtering, expanding rows,
  optional virtualization, loading / empty / skeleton states.
- WCAG 2.1 AA `role="grid"` keyboard model.
- Drop-in replacement for the Alerts.tsx hand-rolled table without losing
  *any* feature it currently has (chevron sort, multi-select w/ bulk actions,
  per-row action popover, page-size selector, page-number paginator).

### Non-goals (v1) — explicit scope cuts

| Feature                             | Why deferred                                                                       |
| ----------------------------------- | ---------------------------------------------------------------------------------- |
| Column drag-reordering              | Needs `dnd-kit`; ~6 kB; no current page asks for it.                               |
| Column visibility toggle UI         | The TanStack `columnVisibility` state model is supported via `meta.hidden`, but the *picker UI* (menu, persistence) ships in a later wave. |
| Saved views (named filter+sort sets) | Belongs to a cross-cutting "Saved Views" feature with backend persistence.        |
| Inline editing of cells             | Needs a forms strategy. Not on the analyst console roadmap.                        |
| Tree / grouped data (`subRows`)     | TanStack supports it; we do not consume it anywhere yet.                           |
| Server-side filter *builder UI*     | We expose `manualFiltering` so the page can wire its own builder; we don't ship one. |
| Column pinning                      | Stretch; can land in v1.1 if needed (TanStack supports it).                        |
| Responsive "stack on mobile" mode   | Analyst console is desktop-first per `MainLayout`. Defer.                          |

---

## 2. Dependencies to add

```jsonc
// apps/tamandua_server/assets/package.json (dependencies)
"@tanstack/react-table":  "^8.21.3",   // latest v8 stable (npm, 2026-06)
"@tanstack/react-virtual": "^3.14.3"   // latest v3 stable (npm, 2026-06)
```

**Bundle-size note (minified+brotli, measured against current `app.js`):**

| Package                     | min+gz  | min+br  | Tree-shake? |
| --------------------------- | ------- | ------- | ----------- |
| `@tanstack/react-table` 8.x | ~14 kB  | ~12 kB  | Yes — row-model functions (`getSortedRowModel`, etc.) are individually importable; importing none of them gives a core-only ~6 kB footprint. |
| `@tanstack/react-virtual` 3 | ~5 kB   | ~4 kB   | Yes — only paid for when a page sets `virtualize`. |

Combined worst case (~17 kB br) is acceptable given it replaces ~600 LOC of
duplicated table logic across 12+ pages.

**Why v8 and not v9 prerelease:** v9 is in active development as of June 2026
and reorganises the type system; we adopt v8.21.3 (stable, ~1 year of bug
fixes, React 18 + 19 compatible) and revisit v9 once it ships GA.

**No new transitive runtime deps** other than `goober`-style internal helpers
that TanStack ships pre-bundled.

---

## 3. Public API

### 3.1 `<DataTable<TData>>` props

```ts
import type {
  ColumnDef,
  ColumnFiltersState,
  ExpandedState,
  PaginationState,
  Row,
  RowSelectionState,
  SortingState,
  TableMeta,
} from '@tanstack/react-table'

export interface DataTableProps<TData> {
  // -------------------------------------------------------------------------
  // REQUIRED
  // -------------------------------------------------------------------------

  /** The visible rows. Treated as the authoritative dataset. */
  data: TData[]

  /** Column definitions. See §3.2 for our extended `meta` shape. */
  columns: TamanduaColumnDef<TData>[]

  // -------------------------------------------------------------------------
  // IDENTITY
  // -------------------------------------------------------------------------

  /**
   * How to derive a stable row ID. Required if the dataset can shuffle / paginate
   * server-side and we want selection to survive. Falls back to row index.
   *
   * @example getRowId={(alert) => alert.id}
   */
  getRowId?: (row: TData, index: number, parent?: Row<TData>) => string

  // -------------------------------------------------------------------------
  // SORTING
  // -------------------------------------------------------------------------

  enableSorting?: boolean            // default: true
  enableMultiSort?: boolean          // default: false; shift-click stacks sorts
  manualSorting?: boolean            // default: false; true = server-side
  /** Initial sort if uncontrolled. */
  defaultSorting?: SortingState
  /** Controlled sort. If provided, `onSortingChange` must also be provided. */
  sorting?: SortingState
  onSortingChange?: (next: SortingState) => void

  // -------------------------------------------------------------------------
  // FILTERING (column-level; the toolbar's free-text search is a column filter)
  // -------------------------------------------------------------------------

  manualFiltering?: boolean          // default: false; true = server-side
  defaultColumnFilters?: ColumnFiltersState
  columnFilters?: ColumnFiltersState
  onColumnFiltersChange?: (next: ColumnFiltersState) => void

  /** Global (cross-column) free-text filter. */
  globalFilter?: string
  onGlobalFilterChange?: (next: string) => void

  // -------------------------------------------------------------------------
  // SELECTION
  // -------------------------------------------------------------------------

  enableRowSelection?: boolean | ((row: Row<TData>) => boolean)   // default: false
  /** 'single' = radio-style; 'multi' = checkbox-style. Default: 'multi'. */
  selectionMode?: 'single' | 'multi'
  defaultRowSelection?: RowSelectionState
  rowSelection?: RowSelectionState
  onRowSelectionChange?: (next: RowSelectionState) => void

  /**
   * Fired when user clicks "select all across pages" affordance. The table
   * itself only knows the current page. When `true`, callers should treat
   * subsequent bulk actions as "all matching the current filter" rather than
   * the explicit row IDs.
   */
  onSelectAllAcrossPagesChange?: (selectAllAcrossPages: boolean) => void

  // -------------------------------------------------------------------------
  // PAGINATION
  // -------------------------------------------------------------------------

  enablePagination?: boolean         // default: true
  manualPagination?: boolean         // default: false; true = server-side
  /** For server-side: total row count across all pages. */
  rowCount?: number
  defaultPagination?: PaginationState   // { pageIndex: 0, pageSize: 25 }
  pagination?: PaginationState
  onPaginationChange?: (next: PaginationState) => void
  pageSizeOptions?: readonly number[]   // default: [25, 50, 100]

  // -------------------------------------------------------------------------
  // EXPANDING
  // -------------------------------------------------------------------------

  enableExpanding?: boolean          // default: false
  defaultExpanded?: ExpandedState
  expanded?: ExpandedState
  onExpandedChange?: (next: ExpandedState) => void
  /** Renders below an expanded row. Receives the row's original data. */
  renderSubRow?: (row: Row<TData>) => React.ReactNode

  // -------------------------------------------------------------------------
  // COLUMN OPTIONS
  // -------------------------------------------------------------------------

  enableColumnResize?: boolean       // default: false
  /** Initial widths keyed by column id. Honored only when resize is enabled. */
  defaultColumnSizing?: Record<string, number>

  // -------------------------------------------------------------------------
  // INTERACTION
  // -------------------------------------------------------------------------

  /** Click on row body (NOT on checkbox / action cell). */
  onRowClick?: (row: Row<TData>, event: React.MouseEvent) => void
  /** Per-row CSS class. Useful for `isNew` flash, `isMuted`, severity-tinted backgrounds. */
  rowClassName?: (row: Row<TData>) => string | undefined
  /** Per-row style override. Same caveat. */
  rowStyle?: (row: Row<TData>) => React.CSSProperties | undefined

  // -------------------------------------------------------------------------
  // LAYOUT / DENSITY
  // -------------------------------------------------------------------------

  /** Vertical padding & font size for cells. Default: 'comfortable'. */
  density?: 'compact' | 'comfortable'
  stickyHeader?: boolean             // default: true
  /** Caps table height; when set, body scrolls. Required for virtualize. */
  maxHeight?: string | number

  // -------------------------------------------------------------------------
  // VIRTUALIZATION
  // -------------------------------------------------------------------------

  virtualize?: boolean               // default: false
  estimatedRowHeight?: number        // default: density === 'compact' ? 36 : 44
  virtualOverscan?: number           // default: 10

  // -------------------------------------------------------------------------
  // STATES
  // -------------------------------------------------------------------------

  loading?: boolean
  /** Rendered when `loading === true`. Defaults to <DataTableSkeleton rows=10 />. */
  loadingState?: React.ReactNode
  /** Rendered when data.length === 0 AND !loading. Defaults to <DataTableEmptyState />. */
  emptyState?: React.ReactNode

  // -------------------------------------------------------------------------
  // ESCAPE HATCHES
  // -------------------------------------------------------------------------

  /** Passthrough to TanStack `meta`. Useful for handing callbacks into `cell` renderers. */
  meta?: TableMeta<TData>

  /** Style hooks. */
  className?: string
  containerClassName?: string
  containerStyle?: React.CSSProperties

  /** Accessible name. Required when no visible `<caption>`-equivalent exists. */
  'aria-label'?: string
  'aria-labelledby'?: string
}
```

### 3.2 Extended column definition

We extend TanStack's `ColumnDef<TData>` via its `meta` slot — *no fork*, fully
upgrade-compatible.

```ts
import type { ColumnDef as TanstackColumnDef } from '@tanstack/react-table'

/** Tamandua-specific column metadata. Lives on `column.columnDef.meta`. */
export interface TamanduaColumnMeta {
  /** Horizontal cell alignment. Default: 'start'. */
  align?: 'start' | 'center' | 'end'
  /** Fixed pixel width. Mutually exclusive with `enableColumnResize`. */
  width?: number | string
  /** Min width when resizable. */
  minWidth?: number
  /** Max width when resizable. */
  maxWidth?: number
  /** Single-line ellipsis with title-attr fallback. Default: false. */
  truncate?: boolean
  /** Hide this column from the rendered grid (still in the model). */
  hidden?: boolean
  /** Render as a sticky-left "row header" with bolder font. */
  isRowHeader?: boolean
  /** Skip this cell when `onRowClick` fires (e.g. cells containing buttons). */
  swallowRowClick?: boolean
  /** Skip this cell from keyboard arrow nav (mostly for action cells). */
  skipKeyboardNav?: boolean
  /** Header-only tooltip explaining the column. */
  headerTooltip?: React.ReactNode
}

export type TamanduaColumnDef<TData, TValue = unknown> =
  TanstackColumnDef<TData, TValue> & {
    meta?: TamanduaColumnMeta
  }
```

### 3.3 Sub-component exports

```ts
// barrel: components/ui/baseui/index.ts
export {
  DataTable,
  DataTableToolbar,
  DataTablePagination,
  DataTableColumnHeader,
  DataTableEmptyState,
  DataTableSkeleton,
  useDataTableContext, // for advanced rendering inside `cell`
} from './DataTable'

export type {
  DataTableProps,
  TamanduaColumnDef,
  TamanduaColumnMeta,
} from './DataTable'

// Re-export TanStack types so consumers don't depend on the package directly
// at call sites (keeps the abstraction clean if we ever swap implementations).
export type {
  ColumnDef,
  Row,
  SortingState,
  RowSelectionState,
  PaginationState,
  ColumnFiltersState,
  ExpandedState,
} from '@tanstack/react-table'
```

#### `<DataTableToolbar>`

```tsx
<DataTableToolbar
  searchPlaceholder="Search alerts…"
  onSearchChange={setGlobalFilter}
  // Right-aligned slot for filter chips, "+ Add", refresh, export.
  actions={<>
    <RefreshButton />
    <ExportDropdown />
  </>}
/>
```

#### `<DataTablePagination>`

Renders rows-per-page selector + First/Prev/page numbers/Next/Last + "Showing
X–Y of Z" caption. Reads pagination state from the parent table context
(produced by `<DataTable>` via `useDataTableContext`).

```tsx
<DataTable …>
  {/*
    By default <DataTablePagination> is rendered automatically when
    enablePagination is true. To override layout (e.g. put it in a sticky
    sidebar), pass enablePagination={false} and render manually:
  */}
</DataTable>
<DataTablePagination />   {/* picks up context */}
```

#### `<DataTableColumnHeader>`

Helper for `column.header` renderers — handles aria-sort, the chevron, and the
optional `headerTooltip`.

```tsx
columns = [{
  accessorKey: 'severity',
  header: ({ column }) => <DataTableColumnHeader column={column} label="Severity" />,
}]
```

#### `<DataTableEmptyState>` / `<DataTableSkeleton>`

Sensible defaults; both are overridable via `loadingState` / `emptyState`
props. Skeleton accepts `rows?: number` (default 10) and renders shimmer rows
matching the current density.

---

## 4. Internal architecture

### 4.1 State ownership — uncontrolled-first with controlled escape hatches

For every state slice (`sorting`, `rowSelection`, `pagination`, `columnFilters`,
`globalFilter`, `expanded`):

1. If the caller passes the **controlled** prop (e.g. `sorting`), we route
   TanStack `state` to it and call the matching `onXxxChange` handler.
2. If the caller passes only the **default** prop (e.g. `defaultSorting`), we
   hold local state with `useState` initialised from that default.
3. If the caller passes neither, we still hold local state, initialised from
   our hard-coded baseline (e.g. `[]` for sorting, `{ pageIndex: 0, pageSize: 25 }`
   for pagination).

This mirrors React's `<input value=… defaultValue=…>` contract and is what every
modern controlled-component library does. **Rationale:** Alerts.tsx will want
controlled sort + selection (the URL has to mirror them); Events.tsx will want
*nothing* controlled. Both must be one-liners.

```tsx
// Sketch — actual impl will collapse this with a small helper hook.
function useControllable<T>(controlled: T | undefined, defaultValue: T, onChange?: (next: T) => void) {
  const [internal, setInternal] = React.useState<T>(defaultValue)
  const isControlled = controlled !== undefined
  const value = isControlled ? (controlled as T) : internal
  const set = React.useCallback((updater: T | ((prev: T) => T)) => {
    const next = typeof updater === 'function'
      ? (updater as (prev: T) => T)(value)
      : updater
    if (!isControlled) setInternal(next)
    onChange?.(next)
  }, [isControlled, onChange, value])
  return [value, set] as const
}
```

We instantiate TanStack via:

```tsx
const table = useReactTable<TData>({
  data,
  columns,
  getRowId,
  state: { sorting, rowSelection, pagination, columnFilters, globalFilter, expanded, columnSizing },
  onSortingChange:       (updater) => setSorting(typeof updater === 'function' ? updater(sorting) : updater),
  onRowSelectionChange:  (updater) => setRowSelection(typeof updater === 'function' ? updater(rowSelection) : updater),
  onPaginationChange:    (updater) => setPagination(typeof updater === 'function' ? updater(pagination) : updater),
  onColumnFiltersChange: (updater) => setColumnFilters(typeof updater === 'function' ? updater(columnFilters) : updater),
  onGlobalFilterChange:  (updater) => setGlobalFilter(typeof updater === 'function' ? updater(globalFilter) : updater),
  onExpandedChange:      (updater) => setExpanded(typeof updater === 'function' ? updater(expanded) : updater),
  enableMultiSort,
  enableRowSelection,
  enableExpanding,
  enableColumnResizing: enableColumnResize,
  manualSorting,
  manualFiltering,
  manualPagination,
  rowCount,
  getCoreRowModel:      getCoreRowModel(),
  getSortedRowModel:    manualSorting    ? undefined : getSortedRowModel(),
  getFilteredRowModel:  manualFiltering  ? undefined : getFilteredRowModel(),
  getPaginationRowModel: manualPagination || !enablePagination ? undefined : getPaginationRowModel(),
  getExpandedRowModel:  enableExpanding  ? getExpandedRowModel() : undefined,
  meta,
})
```

### 4.2 Selection model

TanStack's native `RowSelectionState` is `Record<string, boolean>` keyed by row
ID (the `getRowId` result). We do **not** invent a parallel `Set<string>`; we
expose it directly via `onRowSelectionChange`. A small `selectedRowIds`
convenience getter is exposed off the context:

```ts
const ctx = useDataTableContext<Alert>()
ctx.selectedRowIds       // string[]
ctx.selectedRowCount     // number
ctx.allRowsOnPageSelected // boolean
ctx.selectAllAcrossPages  // boolean  (state; see below)
ctx.toggleSelectAllAcrossPages: () => void
```

**Page-vs-all-pages semantics:**

The header checkbox lives in a synthetic "select" column (rendered by the
table itself, not declared by the caller) and has THREE states:

- `unchecked` — no rows selected.
- `indeterminate` — *some* rows on the current page selected.
- `checked` — *all rows on the current page* selected.

Clicking it from `unchecked` selects every row currently visible on the page.

When `all rows on current page selected AND data is paginated AND there are
more pages`, a banner appears below the header row:

> All 25 alerts on this page are selected.  **Select all 1,247 alerts matching this filter.**

Clicking the banner flips `selectAllAcrossPages` to `true`. The DataTable
itself doesn't know what "all matching" *means* server-side; it just sets the
flag, fires `onSelectAllAcrossPagesChange(true)`, and the page's bulk-action
handler is responsible for issuing the right API call (with the filter, not
the row IDs).

This is the standard Gmail / Linear / Sentry pattern.

### 4.3 Virtualization integration

`@tanstack/react-virtual` 3.14.3 integrates against the **rows** array
returned by TanStack Table — it has nothing to do with the column model.

```tsx
const rows = table.getRowModel().rows
const scrollRef = React.useRef<HTMLDivElement>(null)

const virtualizer = useVirtualizer({
  count: rows.length,
  getScrollElement: () => scrollRef.current,
  estimateSize: () => estimatedRowHeight,
  overscan: virtualOverscan,
  // measureElement lets dynamic row heights resolve after layout.
  measureElement: typeof window !== 'undefined' && navigator.userAgent.includes('Firefox')
    ? (el) => el?.getBoundingClientRect().height ?? estimatedRowHeight
    : undefined,
})

const virtualRows = virtualizer.getVirtualItems()
const totalSize = virtualizer.getTotalSize()
const paddingTop    = virtualRows.length > 0 ? virtualRows[0].start : 0
const paddingBottom = virtualRows.length > 0 ? totalSize - virtualRows[virtualRows.length - 1].end : 0
```

Body markup when virtualized:

```tsx
<div ref={scrollRef} style={{ maxHeight, overflow: 'auto' }}>
  <table role="grid">
    <thead> … sticky header … </thead>
    <tbody role="rowgroup">
      {paddingTop > 0 && (
        <tr aria-hidden="true"><td colSpan={visibleColCount} style={{ height: paddingTop, padding: 0, border: 0 }} /></tr>
      )}
      {virtualRows.map((vRow) => {
        const row = rows[vRow.index]
        return (
          <DataTableRow
            key={row.id}
            row={row}
            data-index={vRow.index}
            ref={virtualizer.measureElement}
          />
        )
      })}
      {paddingBottom > 0 && (
        <tr aria-hidden="true"><td colSpan={visibleColCount} style={{ height: paddingBottom, padding: 0, border: 0 }} /></tr>
      )}
    </tbody>
  </table>
</div>
```

**Rules:**

- `virtualize` requires `maxHeight` to be set; we `console.warn` if not.
- Virtualization disables `enablePagination` automatically (mutually exclusive
  UX — virt scroll = infinite-feeling list, pagination = explicit pages).
- React 19 users: we pass `useFlushSync: false` to silence the documented
  scroll warning.

### 4.4 Component-tree shape

```
<DataTable>
  <DataTableContext.Provider value={{ table, density, selectAllAcrossPages, … }}>
    <div className="dt-root">
      {toolbar ?? null}              {/* slot for <DataTableToolbar> if user composed it */}
      <div className="dt-scroll" ref={scrollRef}>
        <table role="grid" aria-rowcount={…} aria-colcount={…}>
          <thead role="rowgroup"> … <DataTableHeaderRow /> … </thead>
          <tbody role="rowgroup">
            {loading ? loadingState
              : rows.length === 0 ? emptyState
              : virtualize ? <VirtualBody/> : <PaginatedBody/>}
          </tbody>
        </table>
      </div>
      {enablePagination && !virtualize && <DataTablePagination />}
    </div>
  </DataTableContext.Provider>
</DataTable>
```

`DataTableContext` is internal; `useDataTableContext` is exported only for
power users who write custom `cell` renderers (e.g. an action menu that needs
to refresh after a bulk op).

---

## 5. Styling

### 5.1 Convention (matches existing wrappers)

- **Inline `style` on the hardcoded structure** (root, scroll wrapper, table,
  thead, tbody, tr, th, td). Inline styles use design tokens via CSS
  custom-property references — never raw hex values — except for the same
  `var(--token, fallback)` belt-and-braces pattern used in `Dialog` /
  `Popover` / `Menu` (`'var(--z-modal, 500)'`).
- **`className` passthrough** at three slots: `className` (table), `containerClassName`
  (outermost wrapper), and `rowClassName(row)` callback. All run through `cn()`
  from `@/lib/utils`.
- **No Tailwind utility classes added by the primitive itself**, *except*
  layout-only ones we already see in `Dialog.tsx` (`'fixed inset-0'`,
  `'flex items-center'`). Color, spacing, typography come from tokens.

### 5.2 Design-token reference (exhaustive)

Every token the implementation will read:

| Token                            | Purpose                                          |
| -------------------------------- | ------------------------------------------------ |
| `--surface`                      | Header background, popover backgrounds           |
| `--surface-2` (with fallback)    | Hovered row background                           |
| `--bg`                           | Default cell background                          |
| `--fg`                           | Primary cell text                                |
| `--fg-2` (fallback `--muted`)    | Secondary text inside cells                      |
| `--muted`                        | Header label, pagination caption, empty-state text |
| `--border`                       | All horizontal cell separators, header underline, container outline |
| `--accent` / `--emerald-400`     | Sort indicator active state, selected-row left rail, selected-row tint |
| `--crit`, `--warn`               | Inherited via cell renderers; primitive does not consume directly |
| `--r-sm`                         | Cell focus outline radius, checkbox radius       |
| `--r-md`                         | Outer container radius, dropdown radii           |
| `--spacing-1`                    | Compact-density vertical row padding             |
| `--spacing-2`                    | Comfortable-density vertical row padding, gap between toolbar items |
| `--spacing-3`                    | Horizontal cell padding (both densities)         |
| `--spacing-4`                    | Toolbar block padding, pagination block padding  |
| `--spacing-5`                    | Empty-state vertical padding                     |
| `--font-size-xs` (fallback `0.75rem`) | Pagination caption                          |
| `--font-size-sm` (fallback `0.875rem`) | Body cells, header labels                  |
| `--font-size-md` (fallback `1rem`)     | Row-header cells when `meta.isRowHeader` |
| `--z-sticky` (fallback `100`)    | Sticky header z-index (NEW — see §5.5)          |
| `--z-popover` (fallback `600`)   | Per-row Menu / Popover when raised inside a cell (inherited from Menu wrapper, not set by table) |

If `--z-sticky` is not yet defined in the project's token CSS, the
implementation **MUST** add it to `tokens.css` (or wherever `--z-modal*`,
`--z-popover`, `--z-tooltip` live) with value `100`. The current ladder
(`modal-backdrop 400` / `modal 500` / `popover 600` / `tooltip 700`) leaves
`100` free for in-page sticky layers — a sticky table header MUST sit below
popovers and modals.

### 5.3 Density

```ts
const PADDING_Y = {
  compact:     'var(--spacing-1)',  // ~4 px
  comfortable: 'var(--spacing-2)',  // ~8 px
}
const FONT_SIZE = {
  compact:     'var(--font-size-xs, 0.75rem)',
  comfortable: 'var(--font-size-sm, 0.875rem)',
}
// Horizontal padding stays --spacing-3 in both modes (predictable column lines).
```

### 5.4 Visual states (concrete inline-style sketches)

```tsx
// Header cell — never tints; sticky when stickyHeader.
const headerCellStyle: React.CSSProperties = {
  background: 'var(--surface)',
  borderBottom: '1px solid var(--border)',
  color: 'var(--muted)',
  fontWeight: 600,
  fontSize: 'var(--font-size-xs, 0.75rem)',
  textTransform: 'uppercase',
  letterSpacing: '0.04em',
  padding: `var(--spacing-2) var(--spacing-3)`,
  textAlign: meta.align ?? 'start',
  position: stickyHeader ? 'sticky' : 'static',
  top: stickyHeader ? 0 : undefined,
  zIndex: stickyHeader ? 'var(--z-sticky, 100)' : undefined,
}

// Data row — base.
const rowStyle: React.CSSProperties = {
  borderBottom: '1px solid var(--border)',
  cursor: onRowClick ? 'pointer' : 'default',
  transition: 'background-color 80ms ease',
}

// Data row — hovered.
//   background: 'var(--surface-2, rgba(255,255,255,0.03))'

// Data row — selected.
//   background: 'rgba(47, 196, 113, 0.08)'   /* same emerald as Switch/Checkbox */
//   boxShadow: 'inset 3px 0 0 0 var(--emerald-400, #2fc471)'   /* left rail */

// Data row — focused (keyboard).
//   outline: '2px solid var(--accent, #3b82f6)'
//   outlineOffset: '-2px'
//   (also applied to focused gridcell for cell-level focus)

// Data row — `isNew` flash (callers pass via rowClassName).
//   We expose a single CSS class `.dt-row-new` defined inline in <style> tag
//   shipped by the component (see §5.6) that animates a one-time emerald
//   background-flash for ~1.6 s. Callers add it via rowClassName.
```

### 5.5 Sticky header z-index

`--z-sticky: 100` — strictly below `--z-modal-backdrop (400)`, `--z-popover
(600)`, and `--z-tooltip (700)`. Sticky table headers therefore never
occlude a tooltip on a header column, never sit above a row-action popover,
and dive cleanly beneath any modal that opens from the table.

### 5.6 Sort indicator pattern

Lucide chevrons; column-header is a button when sortable.

```tsx
import { ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react'

function SortIndicator({ direction }: { direction: false | 'asc' | 'desc' }) {
  if (direction === 'asc')  return <ChevronUp   size={14} aria-hidden />
  if (direction === 'desc') return <ChevronDown size={14} aria-hidden />
  return <ChevronsUpDown size={14} aria-hidden style={{ opacity: 0.4 }} />
}

// In <DataTableColumnHeader>:
<button
  type="button"
  onClick={column.getToggleSortingHandler()}
  aria-sort={
    column.getIsSorted() === 'asc'  ? 'ascending'  :
    column.getIsSorted() === 'desc' ? 'descending' : 'none'
  }
  style={{
    appearance: 'none', background: 'none', border: 'none',
    color: 'inherit', font: 'inherit',
    display: 'inline-flex', alignItems: 'center', gap: 'var(--spacing-1)',
    cursor: column.getCanSort() ? 'pointer' : 'default',
    padding: 0,
  }}
>
  {label}
  {column.getCanSort() && <SortIndicator direction={column.getIsSorted()} />}
  {enableMultiSort && column.getSortIndex() >= 0 && (
    <sub style={{ color: 'var(--muted)' }}>{column.getSortIndex() + 1}</sub>
  )}
</button>
```

When multi-sort is on, the subscript shows the sort priority (1, 2, 3…)
matching the Linear / Notion convention.

### 5.7 Shipped CSS

The primitive ships a small `<style>` block (or inline-`<style>` injected on
first mount, like Sonner does) for the few things inline styles can't express:

- `:hover` on rows
- `:focus-visible` outlines
- `.dt-row-new` keyframe flash
- column-resize handle hover/active state (only when `enableColumnResize`)

No global selectors — all scoped under `.dt-root[data-dt-id="…"]`.

---

## 6. Accessibility

### 6.1 ARIA roles

Strict adherence to the WAI-ARIA Authoring Practices [grid pattern]
(<https://www.w3.org/WAI/ARIA/apg/patterns/grid/>):

```html
<div class="dt-root" role="grid"
     aria-rowcount="1247"     <!-- total rows in dataset, not just visible -->
     aria-colcount="7"
     aria-multiselectable="true">
  <div role="rowgroup">      <!-- header -->
    <div role="row" aria-rowindex="1">
      <div role="columnheader" aria-sort="descending" aria-colindex="1">Severity</div>
      …
    </div>
  </div>
  <div role="rowgroup">      <!-- body -->
    <div role="row"
         aria-rowindex="42"
         aria-selected="true"
         aria-expanded="false">
      <div role="gridcell" aria-colindex="1">critical</div>
      …
    </div>
  </div>
</div>
```

Notes:

- We use semantic `<table><thead><tbody>` under the hood for screen-reader
  reliability, *and* we set the ARIA roles redundantly. (Safari + VoiceOver
  drops native table semantics when `display: grid` is applied; setting
  `role="grid"` explicitly keeps the pattern consistent.)
- `aria-rowcount` reflects the **total** row count (`rowCount` prop or
  `data.length` if client-side), not the visible page. `aria-rowindex` is
  1-based and indexes into the *full* dataset (page offset added).
- When virtualization is on, padding-spacer rows carry `aria-hidden="true"`.
- The "select-all-across-pages" banner is `role="status" aria-live="polite"`
  so it announces when shown.

### 6.2 Keyboard model

Per APG grid pattern, focus moves between cells (not rows). The table holds
exactly one tab stop; once inside, the user navigates by arrows.

| Key                 | Action                                                          |
| ------------------- | --------------------------------------------------------------- |
| `Tab` / `Shift+Tab` | Enter / exit table. Focus lands on the first non-`skipKeyboardNav` cell of the first row (or the last focused cell when re-entering). |
| `ArrowUp` / `ArrowDown` | Move focus one row in the column.                          |
| `ArrowLeft` / `ArrowRight` | Move focus one column in the row.                       |
| `Home` / `End`      | First / last cell *in the current row*.                          |
| `Ctrl+Home` / `Ctrl+End` | First cell of first row / last cell of last row.            |
| `PageUp` / `PageDown` | Move focus by `visibleRowCount - 1`.                           |
| `Enter`             | Activates a focused interactive cell (link, button) OR fires `onRowClick` when focus is on a non-interactive cell. |
| `Space`             | Toggles selection on the focused row (when `enableRowSelection`). |
| `Shift+ArrowUp/Down` | Extends selection range (multi-select mode).                   |
| `Shift+Space`       | Selects the entire row from the focused gridcell.                |
| `Ctrl+A` (`⌘A`)    | Selects all rows on the current page (matches header-checkbox behaviour). |
| `Escape`            | If a popover-inside-cell is open, closes it. Otherwise no-op (we do NOT clear selection on Escape — too risky for analysts). |

When `enableExpanding` and the row has subRows:

- `ArrowRight` on an unexpanded row expands it.
- `ArrowLeft` on an expanded row collapses it.

### 6.3 Focus management under virtualization

Critical correctness concern. When a row scrolls out of view, React unmounts
it — naive focus management would teleport the focus ring to `document.body`.

Strategy:

1. Track `focusedCell: { rowId, colId } | null` in component state.
2. After every render, if the focused cell's row is mounted, ensure that DOM
   element has focus (`.focus({ preventScroll: true })`).
3. If the focused cell's row is *not* currently virtualized in, call
   `virtualizer.scrollToIndex(rowIndex, { align: 'auto' })` to bring it back
   on `ArrowUp`/`Down`/`Home`/`End`/etc. — only the keypress handler triggers
   a scroll, scroll-by-mouse never moves focus.
4. As a final fallback, if focus is genuinely lost after a re-render, return
   it to a hidden `<div tabIndex={-1}>` inside `<thead>` so Tab still escapes
   cleanly.

### 6.4 Selection a11y

- Checkbox cells render the existing `<Checkbox>` baseui wrapper — preserves
  the consistent emerald look + native `<button role="checkbox">` semantics.
- Header checkbox supports the indeterminate state via `aria-checked="mixed"`.
- `aria-selected` is set on the `<tr role="row">`.

### 6.5 Reduced motion

The `.dt-row-new` flash, the hover transition, and any scroll-into-view from
keyboard navigation respect `@media (prefers-reduced-motion: reduce)` —
animations become instantaneous, transitions become `none`.

---

## 7. Worked example — column defs

A realistic column-set for the Alerts page, illustrating every documented
feature:

```tsx
import { useMemo } from 'react'
import { ChevronRight, MoreHorizontal } from 'lucide-react'
import {
  DataTable, DataTableColumnHeader, Menu, MenuItem,
  type TamanduaColumnDef,
} from '@/components/ui/baseui'
import type { Alert } from '@/types'
import { formatDate } from '@/lib/utils'

interface AlertsTableProps {
  alerts: Alert[]
  onAck: (id: string) => void
  onCreateExclusion: (id: string) => void
}

export function AlertsTable({ alerts, onAck, onCreateExclusion }: AlertsTableProps) {
  const columns = useMemo<TamanduaColumnDef<Alert>[]>(() => [
    {
      id: 'severity',
      accessorKey: 'severity',
      header: ({ column }) => <DataTableColumnHeader column={column} label="Severity" />,
      cell: ({ getValue }) => (
        <span className={getSeverityBadgeClass(getValue<string>())}>
          {getValue<string>()}
        </span>
      ),
      meta: { width: 96, align: 'start' },
    },
    {
      id: 'title',
      accessorKey: 'title',
      header: ({ column }) => <DataTableColumnHeader column={column} label="Alert" />,
      cell: ({ row }) => (
        <div>
          <div style={{ fontWeight: 600 }}>{row.original.title}</div>
          <div style={{ fontSize: 'var(--font-size-xs, 0.75rem)', color: 'var(--muted)' }}>
            {row.original.description}
          </div>
        </div>
      ),
      meta: { isRowHeader: true, truncate: true },
    },
    {
      id: 'agent',
      accessorKey: 'agent_hostname',
      header: 'Host',
      meta: { width: 180, truncate: true },
    },
    {
      id: 'mitre',
      accessorFn: (alert) => alert.mitre_techniques?.join(', ') ?? '',
      header: 'MITRE',
      enableSorting: false,
      meta: { width: 160, truncate: true, headerTooltip: 'Mapped ATT&CK techniques' },
    },
    {
      id: 'threat_score',
      accessorKey: 'threat_score',
      header: ({ column }) => <DataTableColumnHeader column={column} label="Risk" />,
      meta: { align: 'end', width: 80 },
    },
    {
      id: 'created_at',
      accessorKey: 'created_at',
      header: ({ column }) => <DataTableColumnHeader column={column} label="Created" />,
      cell: ({ getValue }) => formatDate(getValue<string>()),
      meta: { width: 180 },
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <Menu trigger={<button aria-label="Row actions" className="btn-sentinel-icon">
          <MoreHorizontal size={16} />
        </button>}>
          <MenuItem onSelect={() => onAck(row.original.id)}>Acknowledge</MenuItem>
          <MenuItem onSelect={() => onCreateExclusion(row.original.id)}>Create exclusion…</MenuItem>
        </Menu>
      ),
      enableSorting: false,
      meta: { width: 40, align: 'end', swallowRowClick: true, skipKeyboardNav: true },
    },
  ], [onAck, onCreateExclusion])

  return (
    <DataTable
      aria-label="Alerts"
      data={alerts}
      columns={columns}
      getRowId={(a) => a.id}
      enableSorting
      enableMultiSort
      enableRowSelection
      density="compact"
      stickyHeader
      defaultSorting={[{ id: 'created_at', desc: true }]}
      pageSizeOptions={[25, 50, 100]}
      onRowClick={(row) => router.visit(`/alerts/${row.original.id}`)}
    />
  )
}
```

---

## 8. Migration ergonomics

### 8.1 Alerts.tsx — before (current, ~elided)

```tsx
// State (Alerts.tsx:139–146)
const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set())
const [sortBy, setSortBy] = useState<'created_at'|'severity'|'threat_score'>('created_at')
const [sortOrder, setSortOrder] = useState<'asc'|'desc'>('desc')
const [currentPage, setCurrentPage] = useState(1)
const [pageSize, setPageSize] = useState(25)

// Sorting + filtering done in a useMemo (~30 LOC)
const filteredAlerts = useMemo(() => {
  let result = effectiveAlerts.filter(/* … filters … */)
  result.sort((a, b) => {
    switch (sortBy) {
      case 'severity':     return severityWeight(b.severity) - severityWeight(a.severity)
      case 'threat_score': return (b.threat_score ?? 0) - (a.threat_score ?? 0)
      case 'created_at':   return new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    }
  })
  if (sortOrder === 'asc') result.reverse()
  return result
}, [/* deps */])

// Header cells (Alerts.tsx:760–800) — three SortableHeader instances with
// duplicated onClick { if (sortBy === field) toggle dir; else set field } logic.

// Row rendering (Alerts.tsx:820–838)
{paginatedAlerts.map((alert) => (
  <AlertRow
    key={alert.id}
    alert={alert}
    isNew={isNewAlert(alert.id)}
    isSelected={selectedAlerts.has(alert.id)}
    onSelect={() => toggleSelectAlert(alert.id)}
    onCreateExclusion={() => createExclusionFromAlert(alert.id)}
    onAcknowledge={() => acknowledgeAlert(alert.id) /* + optimistic update */}
  />
))}

// Pagination (Alerts.tsx:843–920) — ~80 LOC of hand-rolled First/Prev/page-numbers/Next/Last
```

### 8.2 Alerts.tsx — after

```tsx
// State — just the selection set lives here, the rest is internal.
const [rowSelection, setRowSelection] = useState<RowSelectionState>({})
const selectedAlertIds = useMemo(() => Object.keys(rowSelection), [rowSelection])

<DataTable
  aria-label="Alerts"
  data={effectiveAlerts}
  columns={alertColumns}           // see §7 above
  getRowId={(a) => a.id}
  enableSorting enableMultiSort enableRowSelection
  defaultSorting={[{ id: 'created_at', desc: true }]}
  rowSelection={rowSelection}
  onRowSelectionChange={setRowSelection}
  rowClassName={(row) => isNewAlert(row.original.id) ? 'dt-row-new' : undefined}
  pageSizeOptions={[25, 50, 100]}
  density="compact"
/>

// BulkActionBar reads selectedAlertIds — unchanged.
```

### 8.3 Feature-by-feature mapping

| Current Alerts.tsx feature              | Maps to                                                                                | Effort  |
| --------------------------------------- | -------------------------------------------------------------------------------------- | ------- |
| Sortable severity / created_at / threat_score | `header: ({ column }) => <DataTableColumnHeader column={column} label="…" />`     | 1:1     |
| Sort order toggle on header click       | `column.getToggleSortingHandler()` (built into `<DataTableColumnHeader>`)              | 1:1     |
| Multi-sort via shift-click              | `enableMultiSort` prop                                                                 | NEW (gained for free) |
| `selectedAlerts: Set<string>`           | `rowSelection: RowSelectionState` (object keyed by ID)                                 | Trivial — derive `selectedAlertIds = Object.keys(rowSelection)` |
| Select-all header checkbox              | Synthetic "select" column rendered by DataTable                                        | 1:1     |
| "Select all across pages" banner        | `onSelectAllAcrossPagesChange` callback                                                | NEW     |
| Per-row checkbox + row click            | Built-in selection column + `onRowClick`                                               | 1:1     |
| Per-row "Acknowledge" / "Create exclusion" Popover | Column with `cell: ({ row }) => <Menu>…</Menu>`; `meta: { swallowRowClick: true, skipKeyboardNav: true }` | Explicit migration — extracted from `<AlertRow>` into a `cell` renderer |
| Page-size selector                       | `pageSizeOptions` prop, rendered by `<DataTablePagination>`                            | 1:1     |
| First/Prev/page-numbers/Next/Last       | `<DataTablePagination>`                                                                | 1:1 — ~80 LOC of hand-rolled markup deleted |
| `isNew={isNewAlert(id)}` flash          | `rowClassName={(row) => isNewAlert(row.original.id) ? 'dt-row-new' : undefined}`       | 1:1     |
| Severity badge in cell                  | Cell renderer (`cell: ({ getValue }) => <span class={severityBadgeClass(getValue())}>`) | 1:1     |
| Client-side filter chain                 | Either keep external (pass already-filtered `data`) OR move into column filters        | Caller's choice — recommend keep external for v1 to minimise diff |
| Keyboard arrow navigation between rows   | Built into DataTable                                                                   | NEW (gained for free) |

### 8.4 Smaller-page sketch — Exclusions / DetectionRules / AuditLog

For a page that today has ~5 columns, no selection, no pagination, just sort:

```tsx
// Before: ~120 LOC of useState + sort callback + .map.
// After:
<DataTable
  aria-label="Detection rules"
  data={rules}
  columns={[
    { accessorKey: 'name',     header: 'Rule' },
    { accessorKey: 'severity', header: 'Severity' },
    { accessorKey: 'enabled',  header: 'Enabled', cell: ({ getValue }) => <Switch checked={getValue<boolean>()} disabled /> },
    { accessorKey: 'updated_at', header: 'Updated', cell: ({ getValue }) => formatDate(getValue<string>()) },
  ]}
  getRowId={(r) => r.id}
  enableSorting
  enablePagination={false}
  density="compact"
/>
```

---

## 9. LOC estimates

> Rough order-of-magnitude — implementation LOC, not counting blank lines or comments.

| File                            | Estimated LOC | Notes                                                            |
| ------------------------------- | ------------- | ---------------------------------------------------------------- |
| `DataTable.tsx`                 | ~380          | Main component, hooks, virtualization branch, keyboard handler, ARIA wiring |
| `DataTableContext.ts`           | ~25           | React context + `useDataTableContext` hook                       |
| `DataTableToolbar.tsx`          | ~60           | Search input + actions slot                                      |
| `DataTablePagination.tsx`       | ~90           | First/Prev/numbers/Next/Last + page-size <Select>                |
| `DataTableColumnHeader.tsx`     | ~55           | Sortable header button + chevron + multi-sort subscript + tooltip |
| `DataTableEmptyState.tsx`       | ~30           | Default empty state                                              |
| `DataTableSkeleton.tsx`         | ~40           | Density-aware shimmer                                            |
| `DataTable.styles.ts`           | ~50           | Shared `<style>` block injected once per mount                   |
| `DataTable.types.ts`            | ~40           | Public types + re-exports                                         |
| `useControllable.ts` (local)    | ~20           | The controlled/uncontrolled helper from §4.1                     |
| **Subtotal — implementation**   | **~790**      |                                                                  |
| `DataTable.test.tsx` (Vitest/RTL) | ~250        | Sort + selection + pagination + a11y assertions (not in scope of design but counted) |
| **Total including tests**       | **~1040**     |                                                                  |

For comparison — Alerts.tsx alone shrinks by ~200 LOC; Agents.tsx and Events.tsx
each by ~150. Net codebase delta after migrating 3–4 pages: roughly break-even,
with the win compounding as more pages adopt.

---

## 10. Open questions

These are the design choices where reasonable engineers will disagree. The
next agent should resolve each consciously, not by default.

1. **Default for `manualSorting` / `manualPagination` / `manualFiltering`?**
   Current proposal: all `false` (client-side). But Alerts already paginates
   *client*-side over ~5k rows from the initial Inertia payload — if we ever
   move to server-side cursor pagination, every existing call site needs
   updating. **Alternative:** make `manualPagination` *opt-out* (default
   `true`) and require callers to set it explicitly. **Recommendation:**
   stick with client-side defaults — that's what 100 % of current usage is —
   and document the server-side recipe in this doc.

2. **Controlled vs uncontrolled by default?**
   Proposal: uncontrolled-first. But Alerts.tsx wants `sortBy` in URL state
   today. **Alternative:** require *all* state to be passed explicitly (no
   `default*` props). **Recommendation:** keep uncontrolled-first per
   React-idiomatic component conventions; pages that want URL-state pass
   controlled props.

3. **Should `<DataTablePagination>` be rendered automatically when
   `enablePagination` is true, or composition-only?**
   Proposal: automatic + overridable by passing `enablePagination={false}` and
   rendering manually. **Alternative:** composition-only (caller always
   composes). **Recommendation:** automatic — matches Material/Mantine; users
   wanting custom placement opt out, which is rare.

4. **Selection state shape — `RowSelectionState` (TanStack-native object) vs
   `Set<string>` (idiomatic in current Alerts.tsx)?**
   Proposal: pass through TanStack's `RowSelectionState`. **Alternative:**
   wrap and expose `Set<string>` only. **Recommendation:** TanStack-native —
   simpler, fewer adapters; callers do `Object.keys(rowSelection)` once.

5. **Should `virtualize` and `enablePagination` ever coexist?**
   Proposal: mutually exclusive (the doc warns and prefers virtualization).
   **Alternative:** allow both — virtualize within a page. **Recommendation:**
   mutually exclusive for v1; revisit if a use case appears.

6. **Where do column filter UIs live?**
   Proposal: out of scope (caller renders chips above the table and writes
   to `columnFilters` controlled state). **Alternative:** ship a built-in
   per-header filter affordance (header-menu, like Excel). **Recommendation:**
   keep out — pages have wildly different filter UIs (text, multi-select,
   date range, IP-CIDR); a generic affordance underwhelms all of them.

7. **Default `density`?**
   Proposal: `'comfortable'`. **Alternative:** `'compact'` to match Alerts
   today. **Recommendation:** `'comfortable'` — Alerts.tsx is an outlier; most
   pages have wider rows. Alerts explicitly passes `density="compact"`.

8. **Should we ship `getFacetedRowModel` (for filter dropdowns with counts)?**
   Proposal: yes, optionally. **Alternative:** defer to v1.1. **Recommendation:**
   defer — adds ~2 kB and zero callers ask for it yet.

9. **Re-export TanStack types directly, or wrap?**
   Proposal: re-export (so call sites are clean). **Alternative:** wrap with
   our own types to allow future implementation swaps. **Recommendation:**
   re-export — `ColumnDef`, `Row`, etc. are de-facto industry standard now.
   We can always introduce wrappers later without breaking call sites.

10. **Server-side selection: how does `selectAllAcrossPages` reconcile with
    `rowSelection`?**
    Proposal: they are orthogonal — `selectAllAcrossPages: true` does not
    mutate `rowSelection`; the caller's bulk-action handler reads both flags
    and chooses. **Alternative:** auto-fill `rowSelection` with every visible
    row when the flag flips. **Recommendation:** keep orthogonal — auto-filling
    is misleading because the caller may have millions of rows and we never
    know them all.

---

## 11. Implementation order (suggested phases)

For the agent picking this up — a sequencing that lands value early:

1. **Phase A** — `useControllable`, types, context, `DataTable` shell with
   sort + filter + pagination (client only), `<DataTableColumnHeader>`,
   `<DataTablePagination>`, `<DataTableEmptyState>`, `<DataTableSkeleton>`.
   Wire to one read-only page (e.g. AuditLog) as smoke test. — *~500 LOC*
2. **Phase B** — Selection (page + across-pages semantics), `enableRowSelection`,
   header checkbox column, banner. Migrate Alerts.tsx selection. — *~120 LOC*
3. **Phase C** — Virtualization. Add to Events.tsx (which today hand-rolls
   a windowed list and is the highest-volume table). — *~80 LOC*
4. **Phase D** — Expanding, `renderSubRow`. Optional; only if a consuming
   page demands. — *~50 LOC*
5. **Phase E** — Column resize, `enableColumnResize`. Optional; ship when first
   asked. — *~50 LOC*

Each phase is a separate PR; each is shippable on its own.

---

## 12. Out-of-band concerns

- **SSR / Inertia hydration:** `useReactTable` is fully client-side; first
  paint after Inertia hand-off includes an empty table flash for ~1 frame.
  Acceptable — same as the current Alerts page.
- **Strict Mode double-effects:** TanStack handles this correctly; virtualizer
  is also Strict-Mode safe in 3.14.x.
- **React 19 + Compiler:** TanStack Table v8 README warns about React Compiler
  incompatibility. We are on React 18.3.1 — no concern today; revisit at
  React 19 + Compiler adoption time.
- **Testing:** Component ships with Vitest + Testing Library tests covering:
  sort toggles, multi-sort, single + multi selection, pagination
  navigation, keyboard arrow nav, virtualization (mocked scrollHeight),
  controlled/uncontrolled parity. Playwright e2e tests cover the Alerts page
  end-to-end with a real `<DataTable>`.

---

*End of design.*

*Sources consulted:* TanStack Table v8 docs (v8.21.3, June 2026), TanStack
Virtual v3 docs (v3.14.3, June 2026), W3C ARIA Authoring Practices "Grid"
pattern, existing `baseui/` wrappers in this same folder, Alerts.tsx
(`apps/tamandua_server/assets/src/pages/Alerts.tsx`), Agents.tsx.
