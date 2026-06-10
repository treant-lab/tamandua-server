/**
 * EmptyState - Centered empty state display with optional actions and suggestions
 *
 * Features:
 * - Centered layout
 * - Muted icon
 * - Primary and secondary action buttons
 * - Optional "While you wait" suggestion cards
 */

import type { LucideIcon } from 'lucide-react'
import {
  ArrowRight,
  Lightbulb,
  Database,
  Search,
  Shield,
  Monitor,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface EmptyStateAction {
  label: string
  href?: string
  onClick?: () => void
  primary?: boolean
}

interface EmptyStateSuggestion {
  title: string
  description: string
  href: string
}

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  description: string
  actions?: EmptyStateAction[]
  suggestions?: EmptyStateSuggestion[]
  className?: string
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  actions,
  suggestions,
  className,
}: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center py-12 px-4', className)}>
      {/* Icon */}
      <div
        className="p-4 rounded-2xl mb-6"
        style={{ backgroundColor: 'var(--surface-2)' }}
      >
        <Icon
          className="h-12 w-12"
          style={{ color: 'var(--muted)' }}
          strokeWidth={1.5}
        />
      </div>

      {/* Title */}
      <h3
        className="text-lg font-semibold mb-2 text-center"
        style={{ color: 'var(--fg)' }}
      >
        {title}
      </h3>

      {/* Description */}
      <p
        className="text-sm text-center max-w-md mb-6"
        style={{ color: 'var(--muted)' }}
      >
        {description}
      </p>

      {/* Action buttons */}
      {actions && actions.length > 0 && (
        <div className="flex flex-wrap items-center justify-center gap-3 mb-8">
          {actions.map((action, index) => {
            const isPrimary = action.primary ?? index === 0

            const buttonClasses = cn(
              'inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors',
              isPrimary
                ? 'btn-sentinel-primary'
                : 'btn-sentinel-secondary'
            )

            const buttonStyle = isPrimary
              ? {
                  backgroundColor: 'var(--emerald-500)',
                  color: 'white',
                }
              : {
                  backgroundColor: 'var(--surface-2)',
                  color: 'var(--fg)',
                  border: '1px solid var(--border)',
                }

            if (action.href) {
              return (
                <a
                  key={index}
                  href={action.href}
                  className={buttonClasses}
                  style={buttonStyle}
                >
                  {action.label}
                  {isPrimary && <ArrowRight className="h-4 w-4" />}
                </a>
              )
            }

            return (
              <button
                key={index}
                onClick={action.onClick}
                className={buttonClasses}
                style={buttonStyle}
              >
                {action.label}
                {isPrimary && <ArrowRight className="h-4 w-4" />}
              </button>
            )
          })}
        </div>
      )}

      {/* Suggestions section */}
      {suggestions && suggestions.length > 0 && (
        <div className="w-full max-w-2xl">
          <div
            className="flex items-center gap-2 mb-4"
            style={{ color: 'var(--muted)' }}
          >
            <Lightbulb className="h-4 w-4" />
            <span className="text-xs font-medium uppercase tracking-wide">
              While you wait
            </span>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {suggestions.map((suggestion, index) => (
              <a
                key={index}
                href={suggestion.href}
                className="group p-4 rounded-lg transition-all"
                style={{
                  backgroundColor: 'var(--surface)',
                  border: '1px solid var(--border)',
                }}
              >
                <h4
                  className="text-sm font-medium mb-1 group-hover:text-[var(--emerald-400)] transition-colors"
                  style={{ color: 'var(--fg)' }}
                >
                  {suggestion.title}
                </h4>
                <p
                  className="text-xs line-clamp-2"
                  style={{ color: 'var(--muted)' }}
                >
                  {suggestion.description}
                </p>
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// Pre-configured empty states for common scenarios
export function NoDataEmptyState({
  title = 'No data found',
  description = 'There is no data to display at this time.',
  onRefresh,
  className,
}: {
  title?: string
  description?: string
  onRefresh?: () => void
  className?: string
}) {
  return (
    <EmptyState
      icon={Database}
      title={title}
      description={description}
      actions={
        onRefresh
          ? [{ label: 'Refresh', onClick: onRefresh, primary: true }]
          : undefined
      }
      className={className}
    />
  )
}

export function NoResultsEmptyState({
  searchQuery,
  onClear,
  className,
}: {
  searchQuery?: string
  onClear?: () => void
  className?: string
}) {
  return (
    <EmptyState
      icon={Search}
      title="No results found"
      description={
        searchQuery
          ? `No results match "${searchQuery}". Try adjusting your search or filters.`
          : 'No results match your current filters. Try adjusting your criteria.'
      }
      actions={
        onClear
          ? [{ label: 'Clear filters', onClick: onClear }]
          : undefined
      }
      className={className}
    />
  )
}

export function NoAlertsEmptyState({ className }: { className?: string }) {
  return (
    <EmptyState
      icon={Shield}
      title="No alerts"
      description="All clear. There are no active security alerts at this time."
      className={className}
    />
  )
}

export function NoAgentsEmptyState({
  onDeploy,
  className,
}: {
  onDeploy?: () => void
  className?: string
}) {
  return (
    <EmptyState
      icon={Monitor}
      title="No agents connected"
      description="Deploy agents to your endpoints to start collecting telemetry and detecting threats."
      actions={[
        { label: 'Deploy Agent', onClick: onDeploy, primary: true },
        { label: 'View Documentation', href: '/docs/agent-deployment' },
      ]}
      suggestions={[
        {
          title: 'Windows Deployment',
          description: 'Deploy the agent via MSI installer or PowerShell script.',
          href: '/docs/agent-deployment/windows',
        },
        {
          title: 'Linux Deployment',
          description: 'Use package managers or the shell installer script.',
          href: '/docs/agent-deployment/linux',
        },
        {
          title: 'macOS Deployment',
          description: 'Deploy via PKG installer or Homebrew.',
          href: '/docs/agent-deployment/macos',
        },
      ]}
      className={className}
    />
  )
}

export default EmptyState
