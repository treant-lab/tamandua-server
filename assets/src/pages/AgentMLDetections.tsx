import { Head } from '@inertiajs/react'
import {
  AlertTriangle,
  Brain,
  Cpu,
  ExternalLink,
  FileSearch,
  HardDrive,
  ShieldCheck,
} from 'lucide-react'
import { MainLayout } from '@/layouts/MainLayout'
import { cn, formatDate } from '@/lib/utils'

interface AgentMLDetection {
  id: string
  alert_id: string
  agent_id?: string
  severity?: string
  status?: string
  title?: string
  description?: string
  prediction?: string
  malware_family?: string
  confidence?: number | string | null
  threat_score?: number | string | null
  model_runtime?: string
  model_name?: string
  model_version?: string
  file_path?: string
  file_hash?: string
  rule_name?: string
  inserted_at?: string
}

interface AgentMLSummary {
  total: number
  open: number
  onnx: number
  high_confidence: number
  last_seen_at?: string | null
}

interface AgentMLDetectionsProps {
  detections?: AgentMLDetection[]
  summary?: AgentMLSummary
}

const severityClasses: Record<string, string> = {
  critical: 'badge-sentinel badge-sentinel-critical',
  high: 'badge-sentinel badge-sentinel-high',
  medium: 'badge-sentinel badge-sentinel-medium',
  low: 'badge-sentinel badge-sentinel-low',
  info: 'badge-sentinel badge-sentinel-info',
}

function formatScore(value: number | string | null | undefined): string {
  const numeric = Number(value)
  if (!Number.isFinite(numeric)) return '--'
  return numeric <= 1 ? `${Math.round(numeric * 100)}%` : `${Math.round(numeric)}`
}

function shortHash(value?: string): string {
  if (!value) return '--'
  return value.length > 18 ? `${value.slice(0, 10)}...${value.slice(-6)}` : value
}

function runtimeLabel(detection: AgentMLDetection): string {
  return String(detection.model_runtime || '').toLowerCase() === 'onnx' ? 'ONNX' : 'ML'
}

export default function AgentMLDetections({
  detections = [],
  summary = { total: 0, open: 0, onnx: 0, high_confidence: 0 },
}: AgentMLDetectionsProps) {
  return (
    <MainLayout title="Agent ML Detections">
      <Head title="Agent ML Detections - Tamandua EDR" />

      <div className="space-y-6">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
              Agent ML Detections
            </h1>
            <p className="mt-1 text-sm" style={{ color: 'var(--muted)' }}>
              Endpoint ML and ONNX detections normalized from alert metadata.
            </p>
          </div>
          <a href="/app/alerts?source=ml" className="btn-sentinel btn-sentinel-secondary">
            <AlertTriangle className="h-4 w-4" />
            Filtered Alerts
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
        </div>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
          <MetricCard icon={Brain} label="Total Detections" value={summary.total} />
          <MetricCard icon={AlertTriangle} label="Open" value={summary.open} tone="warning" />
          <MetricCard icon={Cpu} label="ONNX Runtime" value={summary.onnx} tone="success" />
          <MetricCard icon={ShieldCheck} label="High Confidence" value={summary.high_confidence} />
        </div>

        <div className="card-sentinel overflow-hidden rounded-xl">
          <div className="flex items-center justify-between border-b p-4" style={{ borderColor: 'var(--border)' }}>
            <div>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
                Detection Feed
              </h2>
              <p className="text-xs" style={{ color: 'var(--muted)' }}>
                {summary.last_seen_at ? `Last seen ${formatDate(summary.last_seen_at)}` : 'Waiting for agent ML alerts'}
              </p>
            </div>
            <a href="/live/ml-processes" className="btn-sentinel btn-sentinel-ghost">
              <Cpu className="h-4 w-4" />
              ML Processes
            </a>
          </div>

          {detections.length === 0 ? (
            <div className="p-12 text-center">
              <FileSearch className="mx-auto mb-3 h-10 w-10 opacity-50" style={{ color: 'var(--muted)' }} />
              <p className="font-medium" style={{ color: 'var(--fg)' }}>No agent ML detections yet</p>
              <p className="mx-auto mt-1 max-w-xl text-sm" style={{ color: 'var(--muted)' }}>
                This view fills when endpoint telemetry creates alerts with ML, ONNX, prediction, or model metadata.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b text-left text-xs uppercase tracking-wide" style={{ borderColor: 'var(--border)', color: 'var(--muted)' }}>
                    <th className="px-4 py-3">Detection</th>
                    <th className="px-4 py-3">Model</th>
                    <th className="px-4 py-3">File</th>
                    <th className="px-4 py-3">Agent</th>
                    <th className="px-4 py-3">Time</th>
                    <th className="px-4 py-3"></th>
                  </tr>
                </thead>
                <tbody>
                  {detections.map((detection) => (
                    <tr key={detection.id} className="border-b" style={{ borderColor: 'var(--hairline)' }}>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className={severityClasses[String(detection.severity || 'info').toLowerCase()] || severityClasses.info}>
                            {String(detection.severity || 'info').toUpperCase()}
                          </span>
                          <span className="badge-sentinel badge-sentinel-pill">{runtimeLabel(detection)}</span>
                        </div>
                        <div className="mt-2 font-medium" style={{ color: 'var(--fg)' }}>
                          {detection.prediction || detection.title || 'ML detection'}
                        </div>
                        <div className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>
                          Confidence {formatScore(detection.confidence)} · Threat {formatScore(detection.threat_score)}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm" style={{ color: 'var(--fg-2)' }}>
                        <div>{detection.model_name || runtimeLabel(detection)}</div>
                        <div className="text-xs" style={{ color: 'var(--muted)' }}>
                          {detection.model_version || detection.rule_name || 'unversioned'}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm" style={{ color: 'var(--fg-2)' }}>
                        <div className="flex max-w-sm items-center gap-2 truncate">
                          <HardDrive className="h-3.5 w-3.5 flex-shrink-0" style={{ color: 'var(--muted)' }} />
                          <span className="truncate">{detection.file_path || '--'}</span>
                        </div>
                        <div className="mt-1 font-mono text-xs" style={{ color: 'var(--muted)' }}>
                          {shortHash(detection.file_hash)}
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs" style={{ color: 'var(--muted)' }}>
                        {detection.agent_id || '--'}
                      </td>
                      <td className="px-4 py-3 text-sm" style={{ color: 'var(--fg-2)' }}>
                        {detection.inserted_at ? formatDate(detection.inserted_at) : '--'}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <a href={`/app/alerts/${detection.alert_id}`} className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon">
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  )
}

function MetricCard({
  icon: Icon,
  label,
  value,
  tone = 'default',
}: {
  icon: React.ElementType
  label: string
  value: number
  tone?: 'default' | 'success' | 'warning'
}) {
  const colors = {
    default: 'var(--primary)',
    success: 'var(--emerald-400)',
    warning: 'var(--warn)',
  }

  return (
    <div className="card-sentinel rounded-xl p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs" style={{ color: 'var(--muted)' }}>{label}</p>
          <p className="mt-1 text-2xl font-bold" style={{ color: 'var(--fg)' }}>{value.toLocaleString()}</p>
        </div>
        <div
          className={cn('flex h-10 w-10 items-center justify-center rounded-lg')}
          style={{ backgroundColor: 'var(--surface-elevated)', color: colors[tone] }}
        >
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  )
}
