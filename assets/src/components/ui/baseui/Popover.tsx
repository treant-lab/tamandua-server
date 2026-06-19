/**
 * Popover - Floating panel anchored to a trigger
 *
 * Wraps @base-ui/react/popover.
 * Use for: rich tooltips with interactive content, action panels, filter
 * builders. For simple menus prefer <Menu>. For pure text on hover prefer
 * <Tooltip>.
 *
 * Usage:
 *   <Popover trigger={<button>Open</button>}>
 *     <p>Anything renderable.</p>
 *   </Popover>
 */

import * as React from 'react'
import { Popover as BasePopover } from '@base-ui/react/popover'
import { cn } from '@/lib/utils'

interface PopoverProps {
  trigger: React.ReactNode
  children: React.ReactNode
  /** Default side relative to trigger. */
  side?: 'top' | 'right' | 'bottom' | 'left'
  /** Pixel gap between trigger and popup. Default: 6. */
  sideOffset?: number
  className?: string
  /** Controlled open state (optional). */
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

export function Popover({
  trigger,
  children,
  side = 'bottom',
  sideOffset = 6,
  className,
  open,
  onOpenChange,
}: PopoverProps) {
  return (
    <BasePopover.Root open={open} onOpenChange={onOpenChange}>
      <BasePopover.Trigger render={trigger as React.ReactElement} />
      <BasePopover.Portal>
        <BasePopover.Positioner side={side} sideOffset={sideOffset}>
          <BasePopover.Popup
            className={cn(className)}
            style={{
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--r-md)',
              boxShadow: '0 12px 28px rgba(0, 0, 0, 0.4)',
              color: 'var(--fg)',
              padding: 'var(--spacing-3) var(--spacing-4)',
              minWidth: '12rem',
              maxWidth: '24rem',
              zIndex: 'var(--z-popover, 600)',
            }}
          >
            {children}
          </BasePopover.Popup>
        </BasePopover.Positioner>
      </BasePopover.Portal>
    </BasePopover.Root>
  )
}

export default Popover
