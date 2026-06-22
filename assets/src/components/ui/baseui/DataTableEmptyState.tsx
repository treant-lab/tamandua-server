/**
 * DataTableEmptyState - default empty-state block
 *
 * Used when `data.length === 0` and `loadingState !== 'loading'`. Consumers
 * can override entirely by passing `emptyState={<custom />}` to <DataTable />.
 */

import * as React from 'react'
import { Shield } from 'lucide-react'

interface DataTableEmptyStateProps {
  title?: string
  description?: string
  icon?: React.ReactNode
  action?: React.ReactNode
}

export function DataTableEmptyState({
  title = 'No results',
  description = 'Try adjusting filters or refresh.',
  icon,
  action,
}: DataTableEmptyStateProps) {
  return (
    <div
      role="status"
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 'var(--spacing-2)',
        padding: 'var(--spacing-6) var(--spacing-4)',
        color: 'var(--muted)',
        textAlign: 'center',
      }}
    >
      <div style={{ color: 'var(--subtle, var(--muted))' }}>
        {icon ?? <Shield size={32} aria-hidden />}
      </div>
      <div style={{ color: 'var(--fg)', fontWeight: 600 }}>{title}</div>
      <div style={{ fontSize: 'var(--font-size-sm, 0.875rem)', maxWidth: '24rem' }}>
        {description}
      </div>
      {action && <div style={{ marginTop: 'var(--spacing-2)' }}>{action}</div>}
    </div>
  )
}
