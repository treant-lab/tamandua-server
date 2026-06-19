/**
 * Dialog - Accessible modal dialog wrapping @base-ui/react
 *
 * Why this wrapper:
 * - Centralizes design tokens (var(--surface), var(--border), --r-md, --z-modal*)
 *   so swapping the underlying primitive later is a single-folder refactor.
 * - BaseUI provides focus-trap, escape-to-close, scroll-lock and aria-modal
 *   semantics that the old .modal-overlay / .modal-content pair did not.
 *
 * Usage:
 *   <Dialog open={open} onOpenChange={setOpen} title="..." description="...">
 *     <YourFormBody />
 *     <DialogFooter>
 *       <button onClick={() => setOpen(false)}>Cancel</button>
 *       <button onClick={submit}>Confirm</button>
 *     </DialogFooter>
 *   </Dialog>
 */

import * as React from 'react'
import { Dialog as BaseDialog } from '@base-ui/react/dialog'
import { cn } from '@/lib/utils'

interface DialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title?: React.ReactNode
  description?: React.ReactNode
  children: React.ReactNode
  /** Max width in CSS units (default: 32rem). */
  maxWidth?: string
  className?: string
  /** Hide the visual close (X) button in the header. Default: false. */
  hideCloseButton?: boolean
}

export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  maxWidth = '32rem',
  className,
  hideCloseButton = false,
}: DialogProps) {
  return (
    <BaseDialog.Root open={open} onOpenChange={onOpenChange}>
      <BaseDialog.Portal>
        <BaseDialog.Backdrop
          className="fixed inset-0"
          style={{
            background: 'rgba(0, 0, 0, 0.55)',
            backdropFilter: 'blur(2px)',
            zIndex: 'var(--z-modal-backdrop, 400)',
          }}
        />
        <BaseDialog.Popup
          className={cn('fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2', className)}
          style={{
            width: `min(${maxWidth}, calc(100vw - 2rem))`,
            maxHeight: 'calc(100vh - 2rem)',
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--r-md)',
            boxShadow: '0 24px 48px rgba(0, 0, 0, 0.45)',
            color: 'var(--fg)',
            zIndex: 'var(--z-modal, 500)',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
          }}
        >
          {(title || !hideCloseButton) && (
            <header
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                gap: 'var(--spacing-4)',
                padding: 'var(--spacing-5) var(--spacing-6)',
                borderBottom: '1px solid var(--border)',
              }}
            >
              <div style={{ minWidth: 0 }}>
                {title && (
                  <BaseDialog.Title
                    style={{
                      margin: 0,
                      fontSize: 'var(--font-size-lg, 1.125rem)',
                      fontWeight: 600,
                      color: 'var(--fg)',
                    }}
                  >
                    {title}
                  </BaseDialog.Title>
                )}
                {description && (
                  <BaseDialog.Description
                    style={{
                      margin: 'var(--spacing-1) 0 0',
                      fontSize: 'var(--font-size-sm, 0.875rem)',
                      color: 'var(--muted)',
                    }}
                  >
                    {description}
                  </BaseDialog.Description>
                )}
              </div>
              {!hideCloseButton && (
                <BaseDialog.Close
                  aria-label="Close dialog"
                  style={{
                    appearance: 'none',
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--muted)',
                    cursor: 'pointer',
                    padding: 'var(--spacing-1)',
                    borderRadius: 'var(--r-sm)',
                    lineHeight: 1,
                  }}
                >
                  ×
                </BaseDialog.Close>
              )}
            </header>
          )}
          <div
            style={{
              padding: 'var(--spacing-5) var(--spacing-6)',
              overflowY: 'auto',
              flex: 1,
            }}
          >
            {children}
          </div>
        </BaseDialog.Popup>
      </BaseDialog.Portal>
    </BaseDialog.Root>
  )
}

/** Footer slot. Use for action buttons; right-aligned with token spacing. */
export function DialogFooter({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div
      className={cn(className)}
      style={{
        display: 'flex',
        justifyContent: 'flex-end',
        gap: 'var(--spacing-3)',
        padding: 'var(--spacing-4) var(--spacing-6)',
        borderTop: '1px solid var(--border)',
        background: 'var(--bg)',
      }}
    >
      {children}
    </div>
  )
}

export default Dialog
