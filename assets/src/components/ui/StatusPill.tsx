/**
 * StatusPill - Compact status indicator with optional animated dot
 *
 * Features:
 * - Animated dot for 'ok' status (pulse)
 * - Colors from design tokens
 * - Compact inline display
 */

import { cn } from '@/lib/utils'

type StatusType = 'ok' | 'warn' | 'err' | 'pending'

interface StatusPillProps {
  status: StatusType
  label: string
  showDot?: boolean
  className?: string
}

const statusStyles: Record<StatusType, {
  bg: string
  text: string
  dot: string
  border: string
}> = {
  ok: {
    bg: 'var(--emerald-glow)',
    text: 'var(--emerald-400)',
    dot: 'var(--emerald-400)',
    border: 'rgba(47, 196, 113, 0.25)',
  },
  warn: {
    bg: 'var(--high-bg)',
    text: 'var(--high)',
    dot: 'var(--high)',
    border: 'rgba(245, 165, 36, 0.25)',
  },
  err: {
    bg: 'var(--crit-bg)',
    text: 'var(--crit)',
    dot: 'var(--crit)',
    border: 'rgba(240, 80, 110, 0.25)',
  },
  pending: {
    bg: 'var(--med-bg)',
    text: 'var(--med)',
    dot: 'var(--med)',
    border: 'rgba(91, 156, 242, 0.25)',
  },
}

export function StatusPill({
  status,
  label,
  showDot = true,
  className,
}: StatusPillProps) {
  const styles = statusStyles[status]

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium',
        className
      )}
      style={{
        backgroundColor: styles.bg,
        color: styles.text,
        border: `1px solid ${styles.border}`,
      }}
    >
      {showDot && (
        <span
          className={cn(
            'h-1.5 w-1.5 rounded-full',
            status === 'ok' && 'animate-pulse'
          )}
          style={{ backgroundColor: styles.dot }}
        />
      )}
      <span>{label}</span>
    </span>
  )
}

// Convenient preset status pills
export function OnlineStatus({ className }: { className?: string }) {
  return <StatusPill status="ok" label="Online" className={className} />
}

export function OfflineStatus({ className }: { className?: string }) {
  return <StatusPill status="err" label="Offline" className={className} />
}

export function DegradedStatus({ className }: { className?: string }) {
  return <StatusPill status="warn" label="Degraded" className={className} />
}

export function PendingStatus({ className }: { className?: string }) {
  return <StatusPill status="pending" label="Pending" className={className} />
}

// Health status mapping utility
export function HealthStatusPill({
  health,
  className,
}: {
  health: 'healthy' | 'degraded' | 'unhealthy' | 'unknown'
  className?: string
}) {
  const statusMap: Record<string, StatusType> = {
    healthy: 'ok',
    degraded: 'warn',
    unhealthy: 'err',
    unknown: 'pending',
  }

  const labelMap: Record<string, string> = {
    healthy: 'Healthy',
    degraded: 'Degraded',
    unhealthy: 'Unhealthy',
    unknown: 'Unknown',
  }

  return (
    <StatusPill
      status={statusMap[health] || 'pending'}
      label={labelMap[health] || 'Unknown'}
      className={className}
    />
  )
}

export default StatusPill
