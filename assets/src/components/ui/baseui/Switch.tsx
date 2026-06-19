/**
 * Switch - Boolean toggle control
 *
 * Wraps @base-ui/react/switch. Use for binary settings
 * (availability toggle, feature flags). Prefer this over <Checkbox>
 * when the action takes effect immediately and is reversible.
 *
 * Usage:
 *   <Switch checked={available} onCheckedChange={setAvailable} label="Available" />
 */

import * as React from 'react'
import { Switch as BaseSwitch } from '@base-ui/react/switch'

interface SwitchProps {
  checked?: boolean
  defaultChecked?: boolean
  onCheckedChange?: (checked: boolean) => void
  disabled?: boolean
  label?: React.ReactNode
  /** Accessible name when no visible label is rendered. */
  'aria-label'?: string
  className?: string
}

export function Switch({
  checked,
  defaultChecked,
  onCheckedChange,
  disabled,
  label,
  className,
  ...rest
}: SwitchProps) {
  const node = (
    <BaseSwitch.Root
      checked={checked}
      defaultChecked={defaultChecked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      className={className}
      aria-label={!label ? rest['aria-label'] : undefined}
      style={{
        position: 'relative',
        display: 'inline-flex',
        alignItems: 'center',
        width: '2.25rem',
        height: '1.25rem',
        borderRadius: '999px',
        background: checked ? 'var(--emerald-400, #2fc471)' : 'var(--border)',
        border: 'none',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        transition: 'background 120ms ease',
        padding: 0,
      }}
    >
      <BaseSwitch.Thumb
        style={{
          display: 'block',
          width: '1rem',
          height: '1rem',
          borderRadius: '50%',
          background: '#fff',
          transform: `translateX(${checked ? '1.125rem' : '0.125rem'})`,
          transition: 'transform 120ms ease',
          boxShadow: '0 1px 3px rgba(0, 0, 0, 0.3)',
        }}
      />
    </BaseSwitch.Root>
  )

  if (!label) return node

  return (
    <label
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--spacing-2)',
        cursor: disabled ? 'not-allowed' : 'pointer',
        fontSize: 'var(--font-size-sm, 0.875rem)',
        color: 'var(--fg)',
      }}
    >
      {node}
      <span>{label}</span>
    </label>
  )
}

export default Switch
