/**
 * FilterPills - Horizontal list of pill-shaped filter buttons
 *
 * Features:
 * - Horizontal list of pill buttons
 * - Active state with emerald background
 * - Count badge support
 * - Severity variant uses severity colors (crit/high/med/low)
 */

import { cn } from '@/lib/utils'

interface FilterOption {
  label: string
  value: string
  count?: number
}

interface FilterPillsProps {
  options: FilterOption[]
  value: string
  onChange: (value: string) => void
  variant?: 'default' | 'severity'
  className?: string
}

// Severity color mappings
const severityColors: Record<string, { bg: string; text: string; activeBg: string; activeText: string }> = {
  critical: {
    bg: 'var(--crit-bg)',
    text: 'var(--crit)',
    activeBg: 'var(--crit)',
    activeText: 'white',
  },
  crit: {
    bg: 'var(--crit-bg)',
    text: 'var(--crit)',
    activeBg: 'var(--crit)',
    activeText: 'white',
  },
  high: {
    bg: 'var(--high-bg)',
    text: 'var(--high)',
    activeBg: 'var(--high)',
    activeText: 'white',
  },
  medium: {
    bg: 'var(--med-bg)',
    text: 'var(--med)',
    activeBg: 'var(--med)',
    activeText: 'white',
  },
  med: {
    bg: 'var(--med-bg)',
    text: 'var(--med)',
    activeBg: 'var(--med)',
    activeText: 'white',
  },
  low: {
    bg: 'var(--low-bg)',
    text: 'var(--low)',
    activeBg: 'var(--low)',
    activeText: 'white',
  },
  info: {
    bg: 'var(--med-bg)',
    text: 'var(--med)',
    activeBg: 'var(--med)',
    activeText: 'white',
  },
}

function getSeverityStyle(severity: string, isActive: boolean) {
  const lowerSeverity = severity.toLowerCase()
  const colors = severityColors[lowerSeverity]

  if (!colors) {
    return {
      backgroundColor: isActive ? 'var(--emerald-500)' : 'var(--surface-2)',
      color: isActive ? 'white' : 'var(--fg-2)',
    }
  }

  return {
    backgroundColor: isActive ? colors.activeBg : colors.bg,
    color: isActive ? colors.activeText : colors.text,
  }
}

export function FilterPills({
  options,
  value,
  onChange,
  variant = 'default',
  className,
}: FilterPillsProps) {
  return (
    <div className={cn('flex flex-wrap gap-2', className)}>
      {options.map((option) => {
        const isActive = option.value === value

        const style =
          variant === 'severity'
            ? getSeverityStyle(option.value, isActive)
            : {
                backgroundColor: isActive ? 'var(--emerald-500)' : 'var(--surface-2)',
                color: isActive ? 'white' : 'var(--fg-2)',
              }

        return (
          <button
            key={option.value}
            onClick={() => onChange(option.value)}
            className={cn(
              'inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium transition-all',
              'border',
              isActive
                ? 'border-transparent'
                : 'border-[var(--border)] hover:border-[var(--border-strong)] hover:bg-[var(--surface-3)]'
            )}
            style={style}
          >
            <span>{option.label}</span>
            {option.count !== undefined && (
              <span
                className={cn(
                  'px-1.5 py-0.5 rounded-full text-xs font-semibold',
                  isActive
                    ? 'bg-white/20'
                    : 'bg-[var(--surface-3)]'
                )}
                style={{
                  color: isActive ? 'inherit' : 'var(--muted)',
                }}
              >
                {option.count}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

// Pre-configured severity filter pills
export function SeverityFilterPills({
  value,
  onChange,
  counts,
  showAll = true,
  className,
}: {
  value: string
  onChange: (value: string) => void
  counts?: Record<string, number>
  showAll?: boolean
  className?: string
}) {
  const options: FilterOption[] = [
    ...(showAll ? [{ label: 'All', value: 'all', count: counts?.all }] : []),
    { label: 'Critical', value: 'critical', count: counts?.critical },
    { label: 'High', value: 'high', count: counts?.high },
    { label: 'Medium', value: 'medium', count: counts?.medium },
    { label: 'Low', value: 'low', count: counts?.low },
  ]

  return (
    <FilterPills
      options={options}
      value={value}
      onChange={onChange}
      variant="severity"
      className={className}
    />
  )
}

export default FilterPills
