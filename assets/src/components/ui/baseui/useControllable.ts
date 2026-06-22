/**
 * useControllable - controlled-or-uncontrolled state escape hatch
 *
 * Used by DataTable sub-state (sorting, filters, selection, pagination):
 *
 *   const [sorting, setSorting] = useControllable({
 *     controlled: props.sorting,
 *     defaultValue: props.defaultSorting ?? [],
 *     onChange: props.onSortingChange,
 *   })
 *
 * If `controlled` is undefined, behaves like useState(defaultValue).
 * If `controlled` is defined, the consumer owns state; setter calls onChange.
 */

import * as React from 'react'

interface UseControllableArgs<T> {
  controlled: T | undefined
  defaultValue: T
  onChange?: (next: T) => void
}

export function useControllable<T>({
  controlled,
  defaultValue,
  onChange,
}: UseControllableArgs<T>): [T, (next: T | ((prev: T) => T)) => void] {
  const [internal, setInternal] = React.useState<T>(defaultValue)
  const isControlled = controlled !== undefined
  const value = isControlled ? (controlled as T) : internal

  const set = React.useCallback(
    (next: T | ((prev: T) => T)) => {
      const resolved =
        typeof next === 'function' ? (next as (prev: T) => T)(value) : next
      if (!isControlled) {
        setInternal(resolved)
      }
      onChange?.(resolved)
    },
    [isControlled, onChange, value],
  )

  return [value, set]
}
