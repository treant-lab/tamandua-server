import { AlertTriangle, Eye, FileCode, Network, ShieldCheck } from 'lucide-react'
import { cn } from '@/lib/utils'
import { hasAIEvidence, networkVisibilityIsDegraded, summarizeAIEvidence } from '@/lib/aiEvidence'

interface Props {
  sources: unknown | unknown[]
  compact?: boolean
  className?: string
}

export default function AIEvidenceSummary({ sources, compact = false, className }: Props) {
  const summary = summarizeAIEvidence(...(Array.isArray(sources) ? sources : [sources]))
  if (!hasAIEvidence(summary)) return null

  const degraded = networkVisibilityIsDegraded(summary)
  const visibilityFacts = [
    summary.networkVisibilityState && `Network visibility: ${humanize(summary.networkVisibilityState)}`,
    summary.tlsFingerprintsAvailable !== undefined && `TLS fingerprints: ${summary.tlsFingerprintsAvailable ? 'available' : 'not available'}`,
    summary.certificateVisibility && `Certificate visibility: ${humanize(summary.certificateVisibility)}`,
  ].filter(Boolean) as string[]

  if (compact) {
    return (
      <div className={cn('mt-1 flex flex-wrap gap-1.5', className)} data-testid="ai-evidence-summary">
        {degraded && <Badge tone="warning">Degraded network visibility</Badge>}
        {!degraded && summary.networkVisibilityState && <Badge tone="muted">Network: {humanize(summary.networkVisibilityState)}</Badge>}
        {summary.aiNetworkRisk && <Badge tone="danger">AI risk: {humanize(summary.aiNetworkRisk)}</Badge>}
        {summary.aiEvidenceLimit && <Badge tone="muted">Limit: {humanize(summary.aiEvidenceLimit)}</Badge>}
        {summary.tlsFingerprintsAvailable !== undefined && <Badge tone="muted">TLS fingerprints: {summary.tlsFingerprintsAvailable ? 'available' : 'not available'}</Badge>}
        {summary.certificateVisibility && <Badge tone="muted">Certificates: {humanize(summary.certificateVisibility)}</Badge>}
        {summary.artifactType && <Badge tone="muted">Artifact: {humanize(summary.artifactType)}</Badge>}
        {summary.riskIndicators.slice(0, 2).map(value => <Badge key={value} tone="warning">{humanize(value)}</Badge>)}
        {summary.matchedPatterns.slice(0, 2).map(value => <Badge key={value} tone="danger">Pattern: {humanize(value)}</Badge>)}
        {summary.redactedPreview && <Badge tone="muted">Preview: {truncate(summary.redactedPreview)}</Badge>}
      </div>
    )
  }

  return (
    <section
      className={cn('rounded-lg border p-4', degraded ? 'border-yellow-500/30 bg-yellow-500/10' : 'border-[var(--border)] bg-[var(--surface-2)]', className)}
      data-testid="ai-evidence-summary"
    >
      <div className="flex items-center gap-2">
        {degraded ? <AlertTriangle className="h-4 w-4 text-yellow-300" /> : <Network className="h-4 w-4 text-[var(--muted)]" />}
        <h4 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>
          {degraded ? 'Degraded network visibility' : 'AI / network evidence'}
        </h4>
      </div>
      {degraded && (
        <p className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>
          Network metadata is limited. TLS fingerprints, certificates, or payload visibility are shown only when explicitly reported.
        </p>
      )}

      <div className="mt-3 space-y-2 text-xs" style={{ color: 'var(--fg-2)' }}>
        {summary.aiNetworkRisk && <Fact icon={AlertTriangle} label="AI network risk" value={humanize(summary.aiNetworkRisk)} />}
        {summary.aiEvidenceLimit && <Fact icon={Eye} label="Evidence limit" value={humanize(summary.aiEvidenceLimit)} />}
        {visibilityFacts.map(value => <Fact key={value} icon={ShieldCheck} value={value} />)}
        {summary.artifactType && <Fact icon={FileCode} label="Artifact type" value={humanize(summary.artifactType)} />}
        {summary.riskIndicators.length > 0 && <Fact icon={AlertTriangle} label="Risk indicators" value={summary.riskIndicators.map(humanize).join(', ')} />}
        {summary.matchedPatterns.length > 0 && <Fact icon={FileCode} label="Matched patterns" value={summary.matchedPatterns.map(humanize).join(', ')} />}
        {summary.redactedPreview && <Fact icon={Eye} label="Redacted preview" value={summary.redactedPreview} mono />}
      </div>
    </section>
  )
}

function Fact({ icon: Icon, label, value, mono = false }: { icon: typeof Network; label?: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start gap-2">
      <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0" style={{ color: 'var(--muted)' }} />
      <span className={cn('break-words', mono && 'font-mono')}>
        {label && <span style={{ color: 'var(--muted)' }}>{label}: </span>}{value}
      </span>
    </div>
  )
}

function Badge({ children, tone }: { children: React.ReactNode; tone: 'warning' | 'danger' | 'muted' }) {
  return (
    <span className={cn(
      'rounded px-1.5 py-0.5 text-[10px]',
      tone === 'warning' && 'bg-yellow-500/15 text-yellow-300',
      tone === 'danger' && 'bg-red-500/15 text-red-300',
      tone === 'muted' && 'bg-slate-500/15 text-slate-400',
    )}>
      {children}
    </span>
  )
}

function humanize(value: string): string {
  return value.replace(/_/g, ' ')
}

function truncate(value: string): string {
  return value.length > 48 ? `${value.slice(0, 45)}...` : value
}
