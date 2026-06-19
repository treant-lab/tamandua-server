/**
 * Select - Accessible single-choice dropdown
 *
 * Wraps @base-ui/react/select. Replaces native <select> in
 * forms where we want consistent styling, keyboard nav, and dark-mode
 * compatibility (native <select> in dark mode is OS-styled and ugly).
 *
 * Usage:
 *   <Select value={severity} onValueChange={setSeverity} placeholder="Severity">
 *     {SEVERITIES.map(s => (
 *       <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>
 *     ))}
 *   </Select>
 */

import * as React from 'react'
import { Select as BaseSelect } from '@base-ui/react/select'
import { cn } from '@/lib/utils'

interface SelectProps {
  value?: string
  defaultValue?: string
  onValueChange?: (value: string) => void
  placeholder?: string
  disabled?: boolean
  children: React.ReactNode
  className?: string
  /** Triggers full-width fill. Default: false. */
  fullWidth?: boolean
}

export function Select({
  value,
  defaultValue,
  onValueChange,
  placeholder = 'Select…',
  disabled,
  children,
  className,
  fullWidth,
}: SelectProps) {
  return (
    <BaseSelect.Root value={value} defaultValue={defaultValue} onValueChange={onValueChange} disabled={disabled}>
      <BaseSelect.Trigger
        className={cn(className)}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 'var(--spacing-2)',
          background: 'var(--bg)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--r-sm)',
          padding: 'var(--spacing-2) var(--spacing-3)',
          fontSize: 'var(--font-size-sm, 0.875rem)',
          color: 'var(--fg)',
          cursor: disabled ? 'not-allowed' : 'pointer',
          opacity: disabled ? 0.6 : 1,
          width: fullWidth ? '100%' : 'auto',
          minWidth: '8rem',
        }}
      >
        <BaseSelect.Value placeholder={placeholder} />
        <BaseSelect.Icon style={{ color: 'var(--muted)' }}>▾</BaseSelect.Icon>
      </BaseSelect.Trigger>
      <BaseSelect.Portal>
        <BaseSelect.Positioner sideOffset={4}>
          <BaseSelect.Popup
            style={{
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--r-md)',
              boxShadow: '0 12px 28px rgba(0, 0, 0, 0.4)',
              padding: 'var(--spacing-1)',
              maxHeight: '20rem',
              overflowY: 'auto',
              zIndex: 'var(--z-popover, 600)',
              minWidth: '12rem',
            }}
          >
            {children}
          </BaseSelect.Popup>
        </BaseSelect.Positioner>
      </BaseSelect.Portal>
    </BaseSelect.Root>
  )
}

interface SelectItemProps {
  value: string
  children: React.ReactNode
  disabled?: boolean
}

export function SelectItem({ value, children, disabled }: SelectItemProps) {
  return (
    <BaseSelect.Item
      value={value}
      disabled={disabled}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--spacing-2)',
        padding: 'var(--spacing-2) var(--spacing-3)',
        borderRadius: 'var(--r-sm)',
        fontSize: 'var(--font-size-sm, 0.875rem)',
        color: 'var(--fg)',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        outline: 'none',
      }}
    >
      <BaseSelect.ItemIndicator style={{ width: '1rem', display: 'inline-flex', justifyContent: 'center' }}>
        ✓
      </BaseSelect.ItemIndicator>
      <BaseSelect.ItemText>{children}</BaseSelect.ItemText>
    </BaseSelect.Item>
  )
}

export default Select
