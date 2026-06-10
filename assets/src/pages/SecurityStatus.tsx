import { Head } from '@inertiajs/react'
import { useState } from 'react'
import {
  CheckCircle2,
  Copy,
  ExternalLink,
  Lock,
  RadioTower,
  Shield,
  Activity,
  Clock,
} from 'lucide-react'
import { MainLayout } from '@/layouts/MainLayout'
import { cn } from '@/lib/utils'

// ============================================================================
// Types
// ============================================================================

type PostureStatus = 'Clean' | 'Watch' | 'Investigate'

interface EndpointPosture {
  host: string
  role: string
  score: number
  lastCritical: string | null
  lastHealth: string
  posture: PostureStatus
}

interface AgentSummary {
  id?: string
  hostname?: string
  name?: string
  status?: string
  os?: string
  lastSeen?: string | null
  last_seen_at?: string | null
}

interface HealthAttestationView {
  verified: boolean
  autoAnchorInterval: number
  tenant: string
  trustScore: number
  cleanFor: string
  onlineAgents: { online: number; total: number }
  openCritical24h: number
  txHash: string
  fullTxHash: string
  slot: number
  solscanUrl: string
}

interface SecurityStatusProps {
  agents?: AgentSummary[]
  solanaEnabled?: boolean
  lastAttestation?: HealthAttestationView | null
}

// ============================================================================
// Utility Functions
// ============================================================================

function getScoreColor(score: number): string {
  if (score >= 90) return 'var(--emerald-400)'
  if (score >= 70) return 'var(--high)'
  return 'var(--crit)'
}

function getScoreColorClass(score: number): string {
  if (score >= 90) return 'text-emerald-400'
  if (score >= 70) return 'text-amber-400'
  return 'text-red-400'
}

function getPostureBadgeStyle(posture: PostureStatus): { bg: string; text: string; border: string } {
  switch (posture) {
    case 'Clean':
      return {
        bg: 'rgba(47, 196, 113, 0.15)',
        text: 'var(--emerald-400)',
        border: 'rgba(47, 196, 113, 0.3)',
      }
    case 'Watch':
      return {
        bg: 'rgba(245, 165, 36, 0.15)',
        text: 'var(--high)',
        border: 'rgba(245, 165, 36, 0.3)',
      }
    case 'Investigate':
      return {
        bg: 'rgba(240, 80, 110, 0.15)',
        text: 'var(--crit)',
        border: 'rgba(240, 80, 110, 0.3)',
      }
  }
}

function formatNumber(num: number): string {
  return num.toLocaleString('en-US')
}

function copyToClipboard(text: string): void {
  navigator.clipboard.writeText(text)
}

// ============================================================================
// Components
// ============================================================================

// Circular Trust Score Gauge
function FleetTrustGauge({ score }: { score: number }) {
  const circumference = 2 * Math.PI * 54 // radius = 54
  const offset = circumference - (score / 100) * circumference
  const scoreColor = getScoreColor(score)

  return (
    <div className="flex flex-col items-center">
      <p className="text-xs uppercase tracking-widest mb-4" style={{ color: 'var(--subtle)' }}>
        Fleet Trust Score
      </p>
      <div className="relative w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
          {/* Background circle */}
          <circle
            cx="60"
            cy="60"
            r="54"
            fill="none"
            stroke="var(--surface-3)"
            strokeWidth="10"
          />
          {/* Progress circle */}
          <circle
            cx="60"
            cy="60"
            r="54"
            fill="none"
            stroke={scoreColor}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="trust-gauge-fill"
            style={{ filter: `drop-shadow(0 0 8px ${scoreColor})` }}
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-bold" style={{ color: 'var(--fg)' }}>
            {score}
          </span>
          <span className="text-lg" style={{ color: 'var(--muted)' }}>/100</span>
        </div>
      </div>
    </div>
  )
}

// Status Pills Row
function StatusPills({
  cleanDuration,
  agentsOnline,
  responseLatency,
}: {
  cleanDuration: { days: number; hours: number }
  agentsOnline: { online: number; total: number }
  responseLatency: string
}) {
  return (
    <div className="flex flex-wrap gap-2 mt-4">
      <span
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium"
        style={{
          background: 'rgba(47, 196, 113, 0.15)',
          color: 'var(--emerald-400)',
          border: '1px solid rgba(47, 196, 113, 0.3)',
        }}
      >
        <Shield className="h-3.5 w-3.5" />
        Clean for {cleanDuration.days}d {cleanDuration.hours}h
      </span>
      <span
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium"
        style={{
          background: 'rgba(47, 196, 113, 0.15)',
          color: 'var(--emerald-400)',
          border: '1px solid rgba(47, 196, 113, 0.3)',
        }}
      >
        <Activity className="h-3.5 w-3.5" />
        {agentsOnline.online} / {agentsOnline.total} agents online
      </span>
      <span
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium"
        style={{
          background: 'rgba(47, 196, 113, 0.15)',
          color: 'var(--emerald-400)',
          border: '1px solid rgba(47, 196, 113, 0.3)',
        }}
      >
        <Clock className="h-3.5 w-3.5" />
        Live response {responseLatency}
      </span>
    </div>
  )
}

// Endpoint Posture Table
function EndpointPostureTable({ endpoints }: { endpoints: EndpointPosture[] }) {
  return (
    <div className="card-sentinel mt-6">
      <div className="card-sentinel-header">
        <h3 className="card-sentinel-title">Endpoint posture - per host</h3>
      </div>
      <div className="overflow-x-auto -mx-4 px-4">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--hairline)' }}>
              <th className="text-left py-3 px-2 text-xs uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Host</th>
              <th className="text-left py-3 px-2 text-xs uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Role</th>
              <th className="text-left py-3 px-2 text-xs uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Score</th>
              <th className="text-left py-3 px-2 text-xs uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Last Critical</th>
              <th className="text-left py-3 px-2 text-xs uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Last Health</th>
              <th className="text-left py-3 px-2 text-xs uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Posture</th>
            </tr>
          </thead>
          <tbody>
            {endpoints.map((endpoint) => {
              const postureStyle = getPostureBadgeStyle(endpoint.posture)
              return (
                <tr key={endpoint.host} style={{ borderBottom: '1px solid var(--hairline)' }}>
                  <td className="py-3 px-2 font-medium" style={{ color: 'var(--fg)' }}>{endpoint.host}</td>
                  <td className="py-3 px-2" style={{ color: 'var(--muted)' }}>{endpoint.role}</td>
                  <td className={cn('py-3 px-2 font-semibold', getScoreColorClass(endpoint.score))}>
                    {endpoint.score}
                  </td>
                  <td className="py-3 px-2" style={{ color: 'var(--muted)' }}>
                    {endpoint.lastCritical || '\u2014'}
                  </td>
                  <td className="py-3 px-2" style={{ color: 'var(--muted)' }}>{endpoint.lastHealth}</td>
                  <td className="py-3 px-2">
                    <span
                      className="inline-flex px-2.5 py-1 rounded text-xs font-medium"
                      style={{
                        background: postureStyle.bg,
                        color: postureStyle.text,
                        border: `1px solid ${postureStyle.border}`,
                      }}
                    >
                      {endpoint.posture}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// Last Health Attestation Card
function LastAttestationCard({
  attestation,
}: {
  attestation: HealthAttestationView | null
}) {
  const [copied, setCopied] = useState(false)

  if (!attestation) {
    return (
      <div className="card-sentinel">
        <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Last health attestation</h3>
        <p className="mt-3 text-sm" style={{ color: 'var(--muted)' }}>
          No on-chain health attestation has been published yet.
        </p>
      </div>
    )
  }

  const handleCopyTxHash = () => {
    copyToClipboard(attestation.fullTxHash)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="card-sentinel">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Last health attestation</h3>
        <span
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium"
          style={{
            background: 'rgba(47, 196, 113, 0.15)',
            color: 'var(--emerald-400)',
            border: '1px solid rgba(47, 196, 113, 0.3)',
          }}
        >
          <CheckCircle2 className="h-3.5 w-3.5" />
          Verified
        </span>
      </div>

      <p className="text-xs mb-5" style={{ color: 'var(--muted)' }}>
        Auto-anchored every {attestation.autoAnchorInterval} seconds
      </p>

      <div className="space-y-4">
        <div>
          <p className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>Tenant</p>
          <p className="text-sm font-mono" style={{ color: 'var(--fg-2)' }}>{attestation.tenant}</p>
        </div>

        <div>
          <p className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>Trust Score</p>
          <p className="text-sm font-semibold" style={{ color: 'var(--emerald-400)' }}>{attestation.trustScore}</p>
        </div>

        <div>
          <p className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>Clean For</p>
          <p className="text-sm" style={{ color: 'var(--fg-2)' }}>{attestation.cleanFor}</p>
        </div>

        <div>
          <p className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>Online Agents</p>
          <p className="text-sm" style={{ color: 'var(--fg-2)' }}>
            {attestation.onlineAgents.online} / {attestation.onlineAgents.total}
          </p>
        </div>

        <div>
          <p className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>Open Critical 24H</p>
          <p className="text-sm font-semibold" style={{ color: attestation.openCritical24h === 0 ? 'var(--emerald-400)' : 'var(--crit)' }}>
            {attestation.openCritical24h}
          </p>
        </div>

        <div>
          <p className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>TX Hash</p>
          <div className="flex items-center gap-2">
            <p className="text-sm font-mono" style={{ color: 'var(--fg-2)' }}>{attestation.txHash}</p>
            <button
              onClick={handleCopyTxHash}
              className="p-1 rounded hover:bg-white/5 transition-colors"
              title="Copy full hash"
            >
              <Copy className="h-3.5 w-3.5" style={{ color: copied ? 'var(--emerald-400)' : 'var(--muted)' }} />
            </button>
          </div>
        </div>

        <div>
          <p className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>Slot</p>
          <p className="text-sm font-mono" style={{ color: 'var(--fg-2)' }}>{formatNumber(attestation.slot)}</p>
        </div>
      </div>

      <div className="flex gap-2 mt-6">
        <a
          href={attestation.solscanUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="btn-sentinel btn-sentinel-secondary flex-1 justify-center"
        >
          <ExternalLink className="h-4 w-4" />
          Open in Solscan
        </a>
        <button
          onClick={() => {
            const proofBundle = JSON.stringify({
              txHash: attestation.fullTxHash,
              slot: attestation.slot,
              tenant: attestation.tenant,
              trustScore: attestation.trustScore,
              cleanFor: attestation.cleanFor,
              onlineAgents: attestation.onlineAgents,
              openCritical24h: attestation.openCritical24h,
            }, null, 2)
            copyToClipboard(proofBundle)
          }}
          className="btn-sentinel btn-sentinel-outline flex-1 justify-center"
        >
          <Copy className="h-4 w-4" />
          Copy proof bundle
        </button>
      </div>

      <div
        className="flex items-start gap-2 mt-4 p-3 rounded-lg"
        style={{
          background: 'var(--surface-2)',
          border: '1px solid var(--hairline)',
        }}
      >
        <Lock className="h-4 w-4 mt-0.5 flex-shrink-0" style={{ color: 'var(--subtle)' }} />
        <p className="text-xs" style={{ color: 'var(--muted)' }}>
          Attestation excludes PII. Only aggregate posture metrics are published on-chain.
        </p>
      </div>
    </div>
  )
}

// Oracle Consumers Section
function OracleConsumersSection() {
  return (
    <div className="card-sentinel mt-4">
      <div className="flex items-center gap-2 mb-2">
        <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Oracle consumers</h3>
        <span
          className="inline-flex px-2 py-0.5 rounded text-xs font-medium"
          style={{
            background: 'rgba(91, 156, 242, 0.15)',
            color: 'var(--med)',
            border: '1px solid rgba(91, 156, 242, 0.3)',
          }}
        >
          Roadmap
        </span>
      </div>

      <p className="text-xs mb-4" style={{ color: 'var(--muted)' }}>
        On-chain programs can gate high-value operations on real-time endpoint posture via the Tamandua Security Oracle.
      </p>

      <div
        className="rounded-lg p-4 font-mono text-xs overflow-x-auto"
        style={{
          background: 'var(--surface-2)',
          border: '1px solid var(--hairline)',
        }}
      >
        <pre style={{ color: 'var(--fg-2)' }}>
          <span style={{ color: 'var(--subtle)' }}>// Example consumer (Anchor)</span>
          {'\n'}
          <span style={{ color: 'var(--sol-cyan)' }}>let</span> posture = oracle::read_posture(ctx, tenant);
          {'\n'}
          <span style={{ color: 'var(--sol-cyan)' }}>require!</span>(posture.score &gt;= <span style={{ color: 'var(--emerald-400)' }}>80</span>, ErrCode::EndpointRisk);
          {'\n'}
          <span style={{ color: 'var(--sol-cyan)' }}>require!</span>(posture.fresh_secs &lt;= <span style={{ color: 'var(--emerald-400)' }}>300</span>, ErrCode::Stale);
          {'\n'}
          <span style={{ color: 'var(--sol-cyan)' }}>require!</span>(posture.open_critical_24h == <span style={{ color: 'var(--emerald-400)' }}>0</span>, ErrCode::Critical);
        </pre>
      </div>

      <div className="flex items-center gap-2 mt-4">
        <span
          className="inline-flex px-2 py-0.5 rounded text-xs font-medium"
          style={{
            background: 'var(--surface-3)',
            color: 'var(--muted)',
            border: '1px solid var(--hairline)',
          }}
        >
          Anchor program v0.2
        </span>
        <span
          className="inline-flex px-2 py-0.5 rounded text-xs font-medium"
          style={{
            background: 'rgba(148, 99, 226, 0.15)',
            color: '#a78bfa',
            border: '1px solid rgba(148, 99, 226, 0.3)',
          }}
        >
          Devnet
        </span>
      </div>
    </div>
  )
}

// ============================================================================
// Main Component
// ============================================================================

export default function SecurityStatus({
  agents = [],
  solanaEnabled = false,
  lastAttestation = null,
}: SecurityStatusProps) {
  const onlineCount = agents.filter((agent) => String(agent.status || '').toLowerCase() === 'online').length
  const totalAgents = agents.length
  const fleetTrustScore = totalAgents === 0 ? 0 : Math.round((onlineCount / totalAgents) * 100)
  const endpointPosture = agents.map((agent): EndpointPosture => {
    const online = String(agent.status || '').toLowerCase() === 'online'
    return {
      host: agent.hostname || agent.name || agent.id || 'unknown',
      role: agent.os || 'Endpoint',
      score: online ? 100 : 60,
      lastCritical: null,
      lastHealth: agent.lastSeen || agent.last_seen_at || '-',
      posture: online ? 'Clean' : 'Investigate',
    }
  })
  const healthAttestation =
    lastAttestation ||
    (solanaEnabled
      ? null
      : null)

  return (
    <MainLayout title="On-chain Security Status">
      <Head title="Security Status" />

      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <h1 className="text-2xl font-semibold" style={{ color: 'var(--fg)' }}>
              On-chain security status
            </h1>
            <p className="text-sm mt-1 max-w-xl" style={{ color: 'var(--muted)' }}>
              The Tamandua Security Oracle. Anyone can verify your endpoint posture before a high-value action.
            </p>
          </div>

          <button className="btn-sentinel btn-sentinel-primary">
            <RadioTower className="h-4 w-4" />
            Generate health attestation
          </button>
        </div>

        {/* Main Content Grid */}
        <div className="grid gap-6 lg:grid-cols-[1fr_380px]">
          {/* Left Column - Main Content */}
          <div className="space-y-6">
            {/* Fleet Trust Score Section */}
            <div className="card-sentinel">
              <div className="flex flex-col lg:flex-row lg:items-center gap-6">
                {/* Gauge */}
                <div className="flex-shrink-0">
                  <FleetTrustGauge score={fleetTrustScore} />
                </div>

                {/* Description and Pills */}
                <div className="flex-1">
                  <p className="text-sm" style={{ color: 'var(--muted)' }}>
                    Composite of clean uptime, ingestion health, response readiness, and time since last critical detection.
                  </p>
                  <StatusPills
                    cleanDuration={{ days: 0, hours: 0 }}
                    agentsOnline={{ online: onlineCount, total: totalAgents }}
                    responseLatency="not measured"
                  />
                </div>
              </div>
            </div>

            {/* Endpoint Posture Table */}
            <EndpointPostureTable endpoints={endpointPosture} />
          </div>

          {/* Right Column - Sidebar */}
          <div className="space-y-4">
            <LastAttestationCard attestation={healthAttestation} />
            <OracleConsumersSection />
          </div>
        </div>
      </div>

      {/* Custom styles for trust gauge animation */}
      <style>{`
        @keyframes gauge-fill {
          from {
            stroke-dashoffset: 339.29;
          }
        }

        .trust-gauge-fill {
          animation: gauge-fill 1.2s ease-out forwards;
        }
      `}</style>
    </MainLayout>
  )
}
