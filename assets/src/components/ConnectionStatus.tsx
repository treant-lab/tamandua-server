/**
 * Connection Status Indicator Component
 *
 * Displays WebSocket connection state with visual indicator and optional details.
 */

import { Wifi, WifiOff, Loader2, AlertCircle } from 'lucide-react'
import { cn } from '../lib/utils'
import type { WebSocketConnectionState } from '../types'

interface ConnectionStatusProps {
  state: WebSocketConnectionState
  showText?: boolean
  className?: string
  size?: 'sm' | 'md' | 'lg'
}

export function ConnectionStatus({
  state,
  showText = true,
  className,
  size = 'sm'
}: ConnectionStatusProps) {
  const sizeClasses = {
    sm: 'h-3 w-3',
    md: 'h-4 w-4',
    lg: 'h-5 w-5'
  }

  const textSizeClasses = {
    sm: 'text-xs',
    md: 'text-sm',
    lg: 'text-base'
  }

  const getIcon = () => {
    const iconClass = sizeClasses[size]

    switch (state) {
      case 'connected':
        return <Wifi className={cn(iconClass, 'text-green-500')} />
      case 'connecting':
        return <Loader2 className={cn(iconClass, 'text-yellow-500 animate-spin')} />
      case 'errored':
        return <AlertCircle className={cn(iconClass, 'text-red-500')} />
      default:
        return <WifiOff className={cn(iconClass, 'text-slate-500')} />
    }
  }

  const getText = () => {
    switch (state) {
      case 'connected':
        return 'Live'
      case 'connecting':
        return 'Connecting...'
      case 'errored':
        return 'Connection error'
      default:
        return 'Offline'
    }
  }

  const getTextColor = () => {
    switch (state) {
      case 'connected':
        return 'text-green-500'
      case 'connecting':
        return 'text-yellow-500'
      case 'errored':
        return 'text-red-500'
      default:
        return 'text-slate-500'
    }
  }

  return (
    <div className={cn('flex items-center gap-1.5', className)}>
      {getIcon()}
      {showText && (
        <span className={cn(textSizeClasses[size], getTextColor())}>
          {getText()}
        </span>
      )}
    </div>
  )
}

// Dot-only indicator (minimal)
export function ConnectionDot({
  state,
  className,
  size = 'sm'
}: Omit<ConnectionStatusProps, 'showText'>) {
  const sizeClasses = {
    sm: 'h-2 w-2',
    md: 'h-2.5 w-2.5',
    lg: 'h-3 w-3'
  }

  const getColor = () => {
    switch (state) {
      case 'connected':
        return 'bg-green-500'
      case 'connecting':
        return 'bg-yellow-500 animate-pulse'
      case 'errored':
        return 'bg-red-500'
      default:
        return 'bg-slate-500'
    }
  }

  return (
    <span
      className={cn(
        'inline-block rounded-full',
        sizeClasses[size],
        getColor(),
        className
      )}
      title={getText(state)}
    />
  )
}

function getText(state: WebSocketConnectionState): string {
  switch (state) {
    case 'connected':
      return 'Connected - receiving live updates'
    case 'connecting':
      return 'Connecting to server...'
    case 'errored':
      return 'Connection error - retrying...'
    default:
      return 'Disconnected from live updates'
  }
}

// Badge-style indicator
export function ConnectionBadge({
  state,
  className
}: Omit<ConnectionStatusProps, 'showText' | 'size'>) {
  const getStyles = () => {
    switch (state) {
      case 'connected':
        return 'bg-green-500/10 text-green-500 border-green-500/20'
      case 'connecting':
        return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'
      case 'errored':
        return 'bg-red-500/10 text-red-500 border-red-500/20'
      default:
        return 'bg-slate-500/10 text-slate-500 border-slate-500/20'
    }
  }

  return (
    <div
      className={cn(
        'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-xs font-medium',
        getStyles(),
        className
      )}
    >
      <ConnectionDot state={state} size="sm" />
      <span>{getText(state).split(' - ')[0]}</span>
    </div>
  )
}
