/**
 * BaseUIShowcase - Visual + a11y smoke page for the BaseUI wrappers
 *
 * Not linked from the main nav. Used by developers to verify a wrapper
 * renders, animates, and behaves correctly with the project's design
 * tokens before adopting it in production pages.
 *
 * Mount via the Inertia router (e.g. /_dev/baseui-showcase if a route is
 * wired). Safe to leave in builds — adds < 5 KB to the lazy chunk.
 */

import { useState } from 'react'
import { Head } from '@inertiajs/react'
import {
  Dialog,
  DialogFooter,
  Popover,
  Menu,
  MenuItem,
  MenuSeparator,
  Tooltip,
  Select,
  SelectItem,
  Switch,
  Checkbox,
} from '@/components/ui/baseui'

export default function BaseUIShowcase() {
  const [dialogOpen, setDialogOpen] = useState(false)
  const [severity, setSeverity] = useState<string>('high')
  const [available, setAvailable] = useState(true)
  const [createRule, setCreateRule] = useState(false)

  return (
    <>
      <Head title="BaseUI Showcase" />
      <main
        style={{
          maxWidth: '52rem',
          margin: '0 auto',
          padding: 'var(--spacing-8) var(--spacing-6)',
          color: 'var(--fg)',
        }}
      >
        <h1 style={{ fontSize: 'var(--font-size-2xl, 1.5rem)', marginBottom: 'var(--spacing-2)' }}>
          BaseUI Wrappers — Wave 1
        </h1>
        <p style={{ color: 'var(--muted)', marginBottom: 'var(--spacing-8)' }}>
          Visual smoke test for the seven wrappers under{' '}
          <code>src/components/ui/baseui/</code>. All primitives must render
          with project tokens (no Material/MUI/MUI-Joy defaults).
        </p>

        <Section title="Dialog">
          <button
            className="btn-sentinel"
            onClick={() => setDialogOpen(true)}
            style={fallbackButton()}
          >
            Open dialog
          </button>
          <Dialog
            open={dialogOpen}
            onOpenChange={setDialogOpen}
            title="Confirm action"
            description="This dialog has focus-trap, escape-to-close, and aria-modal semantics provided by BaseUI."
          >
            <p>Form body goes here. Token-scoped surface + border + radius.</p>
            <DialogFooter>
              <button onClick={() => setDialogOpen(false)} style={fallbackButton()}>
                Cancel
              </button>
              <button
                onClick={() => setDialogOpen(false)}
                style={{ ...fallbackButton(), background: 'var(--emerald-400, #2fc471)', color: '#0a0e10' }}
              >
                Confirm
              </button>
            </DialogFooter>
          </Dialog>
        </Section>

        <Section title="Popover">
          <Popover trigger={<button style={fallbackButton()}>Open popover</button>}>
            <strong>Rich content panel</strong>
            <p style={{ margin: 'var(--spacing-1) 0 0', color: 'var(--muted)' }}>
              Use Popover for interactive content. For pure text use Tooltip.
            </p>
          </Popover>
        </Section>

        <Section title="Menu">
          <Menu trigger={<button style={fallbackButton()}>Actions ▾</button>}>
            <MenuItem onSelect={() => console.log('kill')}>Kill process</MenuItem>
            <MenuItem onSelect={() => console.log('quarantine')}>Quarantine</MenuItem>
            <MenuSeparator />
            <MenuItem destructive onSelect={() => console.log('ignore')}>
              Ignore alert
            </MenuItem>
          </Menu>
        </Section>

        <Section title="Tooltip">
          <Tooltip content="Mark this alert as False Positive (writes VerdictFeedbackLog).">
            <button style={fallbackButton()}>Hover me</button>
          </Tooltip>
        </Section>

        <Section title="Select">
          <Select value={severity} onValueChange={setSeverity} placeholder="Severity">
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </Select>
          <span style={{ marginLeft: 'var(--spacing-3)', color: 'var(--muted)' }}>
            Current: {severity}
          </span>
        </Section>

        <Section title="Switch">
          <Switch
            checked={available}
            onCheckedChange={setAvailable}
            label={available ? 'Available' : 'Unavailable'}
          />
        </Section>

        <Section title="Checkbox">
          <Checkbox
            checked={createRule}
            onCheckedChange={setCreateRule}
            label="Create suppression rule"
          />
        </Section>
      </main>
    </>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section
      style={{
        marginBottom: 'var(--spacing-6)',
        padding: 'var(--spacing-5)',
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--r-md)',
      }}
    >
      <h2
        style={{
          fontSize: 'var(--font-size-sm, 0.875rem)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
          color: 'var(--muted)',
          margin: '0 0 var(--spacing-3)',
        }}
      >
        {title}
      </h2>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-3)', flexWrap: 'wrap' }}>
        {children}
      </div>
    </section>
  )
}

/** Minimal token-driven button used in the showcase to avoid coupling the
 *  page to .btn-sentinel-* class definitions while wrappers stabilize. */
function fallbackButton(): React.CSSProperties {
  return {
    appearance: 'none',
    background: 'var(--bg)',
    color: 'var(--fg)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--r-sm)',
    padding: 'var(--spacing-2) var(--spacing-3)',
    fontSize: 'var(--font-size-sm, 0.875rem)',
    cursor: 'pointer',
  }
}
