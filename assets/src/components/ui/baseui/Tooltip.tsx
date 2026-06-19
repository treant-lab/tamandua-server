/**
 * Tooltip - Short hover/focus text label
 *
 * Wraps @base-ui/react/tooltip. Use for explanatory short text
 * (1 line ideally, 2 max). For interactive content use <Popover>.
 *
 * Usage:
 *   <Tooltip content="Mark this alert as False Positive">
 *     <button>FP</button>
 *   </Tooltip>
 */

import * as React from 'react'
import { Tooltip as BaseTooltip } from '@base-ui/react/tooltip'

interface TooltipProps {
  content: React.ReactNode
  children: React.ReactElement
  side?: 'top' | 'right' | 'bottom' | 'left'
  /** Delay before showing, in ms. Default: 200. */
  delay?: number
}

export function Tooltip({ content, children, side = 'top', delay = 200 }: TooltipProps) {
  return (
    <BaseTooltip.Provider delay={delay}>
      <BaseTooltip.Root>
        <BaseTooltip.Trigger render={children} />
        <BaseTooltip.Portal>
          <BaseTooltip.Positioner side={side} sideOffset={6}>
            <BaseTooltip.Popup
              style={{
                background: 'var(--bg)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--r-sm)',
                padding: 'var(--spacing-1) var(--spacing-2)',
                fontSize: 'var(--font-size-xs, 0.75rem)',
                color: 'var(--fg)',
                maxWidth: '18rem',
                zIndex: 'var(--z-tooltip, 700)',
                boxShadow: '0 4px 12px rgba(0, 0, 0, 0.35)',
              }}
            >
              {content}
            </BaseTooltip.Popup>
          </BaseTooltip.Positioner>
        </BaseTooltip.Portal>
      </BaseTooltip.Root>
    </BaseTooltip.Provider>
  )
}

export default Tooltip
