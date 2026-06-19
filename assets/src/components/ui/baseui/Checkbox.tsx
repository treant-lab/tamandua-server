/**
 * Checkbox - Multi-select / opt-in control
 *
 * Wraps @base-ui-components/react/checkbox. Use for forms where the
 * user must confirm/opt-in or multi-select. For an immediate-effect
 * binary toggle, prefer <Switch>.
 *
 * Usage:
 *   <Checkbox checked={createRule} onCheckedChange={setCreateRule}
 *             label="Create suppression rule" />
 */

import * as React from 'react'
import { Checkbox as BaseCheckbox } from '@base-ui-components/react/checkbox'

interface CheckboxProps {
  checked?: boolean
  defaultChecked?: boolean
  onCheckedChange?: (checked: boolean) => void
  disabled?: boolean
  label?: React.ReactNode
  'aria-label'?: string
  className?: string
}

export function Checkbox({
  checked,
  defaultChecked,
  onCheckedChange,
  disabled,
  label,
  className,
  ...rest
}: CheckboxProps) {
  const node = (
    <BaseCheckbox.Root
      checked={checked}
      defaultChecked={defaultChecked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      className={className}
      aria-label={!label ? rest['aria-label'] : undefined}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '1.125rem',
        height: '1.125rem',
        borderRadius: 'var(--r-sm)',
        background: checked ? 'var(--emerald-400, #2fc471)' : 'var(--bg)',
        border: `1px solid ${checked ? 'var(--emerald-400, #2fc471)' : 'var(--border)'}`,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        transition: 'background 120ms ease, border-color 120ms ease',
        padding: 0,
      }}
    >
      <BaseCheckbox.Indicator style={{ color: '#0a0e10', display: 'inline-flex', alignItems: 'center' }}>
        ✓
      </BaseCheckbox.Indicator>
    </BaseCheckbox.Root>
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

export default Checkbox
