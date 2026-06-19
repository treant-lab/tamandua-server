/**
 * Menu - Accessible dropdown menu (button + list of actions)
 *
 * Wraps @base-ui-components/react/menu. Provides keyboard navigation,
 * type-ahead, escape-to-close, and aria-menu semantics.
 *
 * Usage:
 *   <Menu trigger={<button>Actions</button>}>
 *     <MenuItem onSelect={kill}>Kill process</MenuItem>
 *     <MenuItem onSelect={quarantine}>Quarantine</MenuItem>
 *     <MenuSeparator />
 *     <MenuItem onSelect={ignore} destructive>Ignore alert</MenuItem>
 *   </Menu>
 */

import * as React from 'react'
import { Menu as BaseMenu } from '@base-ui-components/react/menu'
import { cn } from '@/lib/utils'

interface MenuProps {
  trigger: React.ReactNode
  children: React.ReactNode
  side?: 'top' | 'right' | 'bottom' | 'left'
  align?: 'start' | 'center' | 'end'
  className?: string
}

export function Menu({ trigger, children, side = 'bottom', align = 'start', className }: MenuProps) {
  return (
    <BaseMenu.Root>
      <BaseMenu.Trigger render={trigger as React.ReactElement} />
      <BaseMenu.Portal>
        <BaseMenu.Positioner side={side} align={align} sideOffset={4}>
          <BaseMenu.Popup
            className={cn(className)}
            style={{
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--r-md)',
              boxShadow: '0 12px 28px rgba(0, 0, 0, 0.4)',
              padding: 'var(--spacing-1)',
              minWidth: '10rem',
              zIndex: 'var(--z-popover, 600)',
              listStyle: 'none',
              margin: 0,
            }}
          >
            {children}
          </BaseMenu.Popup>
        </BaseMenu.Positioner>
      </BaseMenu.Portal>
    </BaseMenu.Root>
  )
}

interface MenuItemProps {
  children: React.ReactNode
  onSelect?: () => void
  disabled?: boolean
  destructive?: boolean
}

export function MenuItem({ children, onSelect, disabled, destructive }: MenuItemProps) {
  return (
    <BaseMenu.Item
      onClick={onSelect}
      disabled={disabled}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--spacing-2)',
        padding: 'var(--spacing-2) var(--spacing-3)',
        borderRadius: 'var(--r-sm)',
        cursor: disabled ? 'not-allowed' : 'pointer',
        color: destructive ? 'var(--crit)' : 'var(--fg)',
        opacity: disabled ? 0.5 : 1,
        fontSize: 'var(--font-size-sm, 0.875rem)',
        outline: 'none',
      }}
    >
      {children}
    </BaseMenu.Item>
  )
}

export function MenuSeparator() {
  return (
    <BaseMenu.Separator
      style={{
        height: '1px',
        background: 'var(--border)',
        margin: 'var(--spacing-1) 0',
        border: 'none',
      }}
    />
  )
}

export default Menu
