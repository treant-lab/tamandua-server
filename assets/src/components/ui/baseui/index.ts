/**
 * @base-ui/react wrappers
 *
 * Each wrapper fixes Tamandua design tokens (var(--surface), var(--border),
 * --r-md, --spacing-*, --z-*) so the unstyled BaseUI primitives render with
 * the project's dark-mode-first look without per-call styling.
 *
 * Adoption policy (Wave 1):
 *   - Dialog   → replace bare .modal-overlay / .modal-content pairs
 *   - Popover  → replace ad-hoc dropdowns built with useState + portals
 *   - Menu     → replace custom action lists; gives keyboard nav + a11y
 *   - Tooltip  → replace title="" or hand-rolled hover popovers
 *   - Select   → replace native <select> in forms (consistent dark mode)
 *   - Switch   → replace <input type="checkbox"> for binary toggles
 *   - Checkbox → replace <input type="checkbox"> for multi-select / opt-in
 *
 * Do NOT swap existing .btn-sentinel-*, .card-sentinel-*, .badge-sentinel-*
 * — those are already tokenized and the swap has no a11y / UX upside.
 */

export { Dialog, DialogFooter } from './Dialog'
export { Popover } from './Popover'
export { Menu, MenuItem, MenuSeparator } from './Menu'
export { Tooltip } from './Tooltip'
export { Select, SelectItem } from './Select'
export { Switch } from './Switch'
export { Checkbox } from './Checkbox'
export { DataTable } from './DataTable'
export { DataTableColumnHeader } from './DataTableColumnHeader'
export { DataTablePagination } from './DataTablePagination'
export { DataTableEmptyState } from './DataTableEmptyState'
export { DataTableSkeleton } from './DataTableSkeleton'
export { useControllable } from './useControllable'
export type {
  TamanduaColumnDef,
  DataTableDensity,
  DataTableLoadingState,
  DataTablePaginationState,
  DataTableSortingItem,
} from './DataTable.types'
