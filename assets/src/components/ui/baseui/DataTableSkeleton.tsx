/**
 * DataTableSkeleton - shimmer placeholder rows during initial load
 *
 * Used by DataTable when `loadingState === 'loading'` and `data.length === 0`.
 * Renders N rows of shimmering grey blocks matching the column count.
 */

interface DataTableSkeletonProps {
  rows?: number
  columns?: number
}

export function DataTableSkeleton({ rows = 8, columns = 6 }: DataTableSkeletonProps) {
  return (
    <div
      role="status"
      aria-busy="true"
      aria-live="polite"
      style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-1)' }}
    >
      {Array.from({ length: rows }).map((_, r) => (
        <div
          key={r}
          style={{
            display: 'grid',
            gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))`,
            gap: 'var(--spacing-3)',
            padding: 'var(--spacing-2) var(--spacing-4)',
          }}
        >
          {Array.from({ length: columns }).map((_, c) => (
            <div
              key={c}
              style={{
                height: '0.75rem',
                borderRadius: 'var(--r-sm)',
                background: 'var(--surface-2, var(--surface))',
                opacity: 0.4 + ((r + c) % 3) * 0.15,
              }}
            />
          ))}
        </div>
      ))}
      <span style={{ position: 'absolute', left: -10000 }}>Loading rows…</span>
    </div>
  )
}
