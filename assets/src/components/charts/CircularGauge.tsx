/**
 * CircularGauge Component
 *
 * A circular progress indicator using SVG with stroke-dasharray for the arc.
 * Supports multiple sizes, automatic color based on value, and customizable labels.
 */

import { useMemo } from 'react'
import { cn } from '@/lib/utils'

// ============================================================================
// Types
// ============================================================================

export interface CircularGaugeProps {
  /** Value from 0 to 100 */
  value: number
  /** Size variant */
  size?: 'sm' | 'md' | 'lg'
  /** Label displayed below the value */
  label?: string
  /** Sublabel displayed below the label */
  sublabel?: string
  /** Color theme - 'auto' determines color based on value */
  color?: 'emerald' | 'warning' | 'danger' | 'auto'
  /** Additional CSS classes */
  className?: string
}

// ============================================================================
// Constants
// ============================================================================

const SIZE_CONFIG = {
  sm: {
    size: 80,
    strokeWidth: 6,
    fontSize: 20,
    labelSize: 10,
    sublabelSize: 8,
  },
  md: {
    size: 120,
    strokeWidth: 8,
    fontSize: 28,
    labelSize: 12,
    sublabelSize: 10,
  },
  lg: {
    size: 160,
    strokeWidth: 10,
    fontSize: 36,
    labelSize: 14,
    sublabelSize: 11,
  },
}

const COLOR_CONFIG = {
  emerald: {
    stroke: '#10b981',
    gradient: ['#10b981', '#34d399'],
    glow: 'rgba(16, 185, 129, 0.4)',
  },
  warning: {
    stroke: '#f59e0b',
    gradient: ['#f59e0b', '#fbbf24'],
    glow: 'rgba(245, 158, 11, 0.4)',
  },
  danger: {
    stroke: '#ef4444',
    gradient: ['#ef4444', '#f87171'],
    glow: 'rgba(239, 68, 68, 0.4)',
  },
}

// ============================================================================
// Helper Functions
// ============================================================================

function getAutoColor(value: number): 'emerald' | 'warning' | 'danger' {
  if (value >= 80) return 'emerald'
  if (value >= 60) return 'warning'
  return 'danger'
}

// ============================================================================
// Main Component
// ============================================================================

export function CircularGauge({
  value,
  size = 'md',
  label,
  sublabel,
  color = 'auto',
  className,
}: CircularGaugeProps) {
  // Clamp value between 0 and 100
  const clampedValue = Math.max(0, Math.min(100, value))

  // Get size configuration
  const config = SIZE_CONFIG[size]

  // Determine color
  const colorKey = color === 'auto' ? getAutoColor(clampedValue) : color
  const colorConfig = COLOR_CONFIG[colorKey]

  // Calculate SVG dimensions and arc
  const center = config.size / 2
  const radius = (config.size - config.strokeWidth) / 2
  const circumference = 2 * Math.PI * radius

  // Calculate stroke dasharray for progress
  const progressOffset = useMemo(() => {
    const progress = clampedValue / 100
    return circumference - progress * circumference
  }, [clampedValue, circumference])

  // Unique IDs for gradients
  const gradientId = useMemo(
    () => `gauge-gradient-${Math.random().toString(36).slice(2, 9)}`,
    []
  )
  const glowId = useMemo(
    () => `gauge-glow-${Math.random().toString(36).slice(2, 9)}`,
    []
  )

  return (
    <div className={cn('inline-flex flex-col items-center', className)}>
      <svg
        width={config.size}
        height={config.size}
        viewBox={`0 0 ${config.size} ${config.size}`}
        className="transform -rotate-90"
      >
        <defs>
          {/* Gradient for the progress arc */}
          <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor={colorConfig.gradient[0]} />
            <stop offset="100%" stopColor={colorConfig.gradient[1]} />
          </linearGradient>

          {/* Glow filter */}
          <filter id={glowId} x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Background circle */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="#334155"
          strokeWidth={config.strokeWidth}
          strokeLinecap="round"
        />

        {/* Progress arc */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={`url(#${gradientId})`}
          strokeWidth={config.strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={progressOffset}
          filter={`url(#${glowId})`}
          style={{
            transition: 'stroke-dashoffset 0.5s ease-out',
          }}
        />

        {/* Inner decorative circle */}
        <circle
          cx={center}
          cy={center}
          r={radius - config.strokeWidth - 4}
          fill="none"
          stroke="#1e293b"
          strokeWidth={1}
        />
      </svg>

      {/* Center content (positioned absolutely over the SVG) */}
      <div
        className="absolute flex flex-col items-center justify-center"
        style={{
          width: config.size,
          height: config.size,
          marginTop: -config.size,
        }}
      >
        {/* Value */}
        <span
          className="font-bold text-white"
          style={{ fontSize: config.fontSize }}
        >
          {Math.round(clampedValue)}
        </span>

        {/* Label */}
        {label && (
          <span
            className="text-slate-400 font-medium"
            style={{ fontSize: config.labelSize }}
          >
            {label}
          </span>
        )}

        {/* Sublabel */}
        {sublabel && (
          <span
            className="text-slate-500"
            style={{ fontSize: config.sublabelSize }}
          >
            {sublabel}
          </span>
        )}
      </div>

      {/* Labels below the gauge (if not using center positioning) */}
      {/* Uncomment below if you prefer labels outside the gauge */}
      {/*
      {label && (
        <span
          className="text-slate-400 font-medium mt-2"
          style={{ fontSize: config.labelSize }}
        >
          {label}
        </span>
      )}
      {sublabel && (
        <span
          className="text-slate-500 mt-0.5"
          style={{ fontSize: config.sublabelSize }}
        >
          {sublabel}
        </span>
      )}
      */}
    </div>
  )
}

export default CircularGauge
