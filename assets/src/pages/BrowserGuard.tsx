import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  Ban,
  CheckCircle2,
  Clock,
  Database,
  Eye,
  Globe,
  Key,
  Lock,
  Puzzle,
  Radio,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Wifi,
  XCircle,
} from 'lucide-react'
import { cn } from '@/lib/utils'

type Status = 'healthy' | 'warning' | 'critical' | 'offline' | 'unknown'
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

interface HealthItem {
  label: string
  status: Status
  detail?: string
  last_seen?: string
}

interface ManagedPolicy {
  name: string
  browser: string
  status: Status
  value: string
  scope?: string
  updated_at?: string
}

interface NativeBridge {
  host: string
  status: Status
  version?: string
  agents?: number
  last_heartbeat?: string
}

interface DnrRule {
  id: string
  name: string
  action: string
  condition: string
  enabled: boolean
  hits: number
  severity: Severity
}

interface ExtensionInventoryItem {
  id: string
  name: string
  browser: string
  version: string
  publisher?: string
  install_type: string
  risk: Severity
  hosts?: string[]
  permissions?: string[]
  last_seen?: string
}

interface BypassItem {
  id: string
  target: string
  reason: string
  owner?: string
  expires_at?: string
  status: Status
}

interface BrowserEvent {
  id: string
  timestamp: string
  severity: Severity
  browser: string
  host?: string
  title: string
  detail?: string
}

interface BrowserGuardProps {
  page_title?: string
  data_source?: 'backend' | 'degraded' | string
  degradation_notes?: string[]
  health?: HealthItem[]
  managed_policies?: ManagedPolicy[]
  native_bridge?: NativeBridge
  dnr_rules?: DnrRule[]
  extension_inventory?: ExtensionInventoryItem[]
  bypasses?: BypassItem[]
  browser_events?: BrowserEvent[]
}

const fallbackHealth: HealthItem[] = [
  { label: 'Extension heartbeat', status: 'warning', detail: 'No browser extension heartbeat has been reported yet', last_seen: 'not reported' },
  { label: 'Managed policy', status: 'warning', detail: 'Managed browser policy telemetry has not been reported yet' },
  { label: 'Native messaging bridge', status: 'warning', detail: 'Waiting for endpoint agent bridge telemetry' },
  { label: 'DNR enforcement telemetry', status: 'warning', detail: 'DNR rule hit counters have not been reported yet' },
]

const fallbackPolicies: ManagedPolicy[] = []

const fallbackBridge: NativeBridge = {
  host: 'com.tamandua.browser_guard',
  status: 'warning',
  version: 'pending',
  agents: 0,
  last_heartbeat: 'not reported',
}

const fallbackDnrRules: DnrRule[] = []

const fallbackInventory: ExtensionInventoryItem[] = []

const fallbackBypasses: BypassItem[] = []

const fallbackEvents: BrowserEvent[] = []

const statusStyles: Record<Status, { label: string; icon: typeof CheckCircle2; className: string }> = {
  healthy: { label: 'Healthy', icon: CheckCircle2, className: 'text-[var(--emerald-400)] bg-[var(--emerald-400)]/10 border-[var(--emerald-400)]/25' },
  warning: { label: 'Needs data', icon: AlertCircle, className: 'text-[var(--high)] bg-[var(--high)]/10 border-[var(--high)]/25' },
  critical: { label: 'Critical', icon: XCircle, className: 'text-[var(--crit)] bg-[var(--crit)]/10 border-[var(--crit)]/25' },
  offline: { label: 'Offline', icon: XCircle, className: 'text-[var(--crit)] bg-[var(--crit)]/10 border-[var(--crit)]/25' },
  unknown: { label: 'Unknown', icon: AlertCircle, className: 'text-[var(--muted)] bg-[var(--surface)] border-[var(--border)]' },
}

const severityStyles: Record<Severity, string> = {
  critical: 'text-[var(--crit)] bg-[var(--crit)]/10 border-[var(--crit)]/25',
  high: 'text-[var(--high)] bg-[var(--high)]/10 border-[var(--high)]/25',
  medium: 'text-[var(--med)] bg-[var(--med)]/10 border-[var(--med)]/25',
  low: 'text-[var(--emerald-400)] bg-[var(--emerald-400)]/10 border-[var(--emerald-400)]/25',
  info: 'text-cyan-300 bg-cyan-500/10 border-cyan-500/25',
}

function safeArray<T>(value: T[] | undefined, fallback: T[]): T[] {
  return Array.isArray(value) ? value : fallback
}

function normalizeStatus(value: string | undefined): Status {
  if (value === 'healthy' || value === 'warning' || value === 'critical' || value === 'offline') return value
  return 'unknown'
}

function StatusBadge({ status }: { status: Status }) {
  const config = statusStyles[normalizeStatus(status)]
  const Icon = config.icon
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium', config.className)}>
      <Icon className="h-3.5 w-3.5" />
      {config.label}
    </span>
  )
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={cn('inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium capitalize', severityStyles[severity] || severityStyles.info)}>
      {severity}
    </span>
  )
}

function StatCard({ icon: Icon, label, value, detail, tone }: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  value: string | number
  detail: string
  tone: string
}) {
  return (
    <div className="card-sentinel p-4">
      <div className="flex items-start gap-3">
        <div className={cn('rounded-lg p-2.5', tone)}>
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0">
          <p className="text-2xl font-bold leading-tight text-[var(--fg)]">{value}</p>
          <p className="mt-0.5 text-xs text-[var(--muted)]">{label}</p>
          <p className="mt-1 truncate text-xs text-[var(--subtle)]">{detail}</p>
        </div>
      </div>
    </div>
  )
}

function SectionHeader({ icon: Icon, title, subtitle }: {
  icon: React.ComponentType<{ className?: string }>
  title: string
  subtitle?: string
}) {
  return (
    <div className="mb-4 flex items-start justify-between gap-3">
      <div className="min-w-0">
        <h2 className="flex items-center gap-2 text-base font-semibold text-[var(--fg)]">
          <Icon className="h-4 w-4 text-[var(--emerald-400)]" />
          {title}
        </h2>
        {subtitle && <p className="mt-1 text-xs text-[var(--muted)]">{subtitle}</p>}
      </div>
    </div>
  )
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="rounded-lg border border-dashed border-[var(--border)] bg-[var(--surface)]/30 p-4 text-sm text-[var(--muted)]">
      <span className="inline-flex items-center gap-2">
        <AlertCircle className="h-4 w-4 text-[var(--high)]" />
        {message}
      </span>
    </div>
  )
}

export default function BrowserGuard(props: BrowserGuardProps) {
  const health = safeArray(props.health, fallbackHealth)
  const policies = safeArray(props.managed_policies, fallbackPolicies)
  const bridge = props.native_bridge || fallbackBridge
  const dnrRules = safeArray(props.dnr_rules, fallbackDnrRules)
  const inventory = safeArray(props.extension_inventory, fallbackInventory)
  const bypasses = safeArray(props.bypasses, fallbackBypasses)
  const events = safeArray(props.browser_events, fallbackEvents)
  const degradationNotes = safeArray(props.degradation_notes, [])
  const healthyCount = health.filter(item => item.status === 'healthy').length
  const blockedHits = dnrRules.reduce((sum, rule) => sum + (Number(rule.hits) || 0), 0)
  const riskyExtensions = inventory.filter(item => item.risk === 'critical' || item.risk === 'high' || item.risk === 'medium').length

  return (
    <MainLayout title={props.page_title || 'Browser Guard'}>
      <Head title="Browser Guard - Tamandua EDR" />

      <div className="space-y-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-[var(--fg)]">Browser Guard</h1>
            <p className="mt-1 max-w-3xl text-sm text-[var(--muted)]">
              Extension posture, enterprise policy, native bridge, DNR protection, bypasses, and browser security events.
            </p>
          </div>
          <div className="flex items-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--muted)]">
            <Database className="h-4 w-4" />
            Source: {props.data_source === 'backend' ? 'backend telemetry' : 'degraded telemetry'}
          </div>
        </div>

        {degradationNotes.length > 0 && (
          <div className="rounded-lg border border-[var(--high)]/25 bg-[var(--high)]/10 p-4 text-sm text-[var(--fg-2)]">
            <div className="mb-2 flex items-center gap-2 font-medium text-[var(--fg)]">
              <AlertCircle className="h-4 w-4 text-[var(--high)]" />
              Degraded Browser Guard sources
            </div>
            <ul className="space-y-1 text-xs text-[var(--muted)]">
              {degradationNotes.map(note => <li key={note}>{note}</li>)}
            </ul>
          </div>
        )}

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          <StatCard icon={ShieldCheck} label="Health checks" value={`${healthyCount}/${health.length}`} detail="Extension, policy, bridge, DNR" tone="text-[var(--emerald-400)] bg-[var(--emerald-400)]/10" />
          <StatCard icon={Puzzle} label="Extensions inventoried" value={inventory.length} detail={`${riskyExtensions} need review`} tone="text-cyan-300 bg-cyan-500/10" />
          <StatCard icon={Ban} label="DNR rule hits" value={blockedHits} detail={`${dnrRules.filter(rule => rule.enabled).length} rules enabled`} tone="text-[var(--high)] bg-[var(--high)]/10" />
          <StatCard icon={AlertTriangle} label="Browser events" value={events.length} detail={`${bypasses.length} bypass records`} tone="text-[var(--crit)] bg-[var(--crit)]/10" />
        </div>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
          <div className="card-sentinel p-5 xl:col-span-2">
            <SectionHeader icon={Activity} title="Extension Health" subtitle="Defensive status cards tolerate missing backend telemetry." />
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              {health.map(item => (
                <div key={item.label} className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="font-medium text-[var(--fg)]">{item.label}</p>
                      {item.detail && <p className="mt-1 text-sm text-[var(--muted)]">{item.detail}</p>}
                    </div>
                    <StatusBadge status={item.status} />
                  </div>
                  {item.last_seen && (
                    <p className="mt-3 flex items-center gap-1.5 text-xs text-[var(--subtle)]">
                      <Clock className="h-3.5 w-3.5" />
                      {item.last_seen}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div className="card-sentinel p-5">
            <SectionHeader icon={Radio} title="Native Bridge" subtitle="Native messaging status from endpoint bridge telemetry." />
            <div className="space-y-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="font-medium text-[var(--fg)]">{bridge.host}</p>
                  <p className="text-sm text-[var(--muted)]">Version {bridge.version || 'unknown'}</p>
                </div>
                <StatusBadge status={bridge.status} />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg bg-[var(--surface)]/50 p-3">
                  <p className="text-xs text-[var(--muted)]">Reporting agents</p>
                  <p className="mt-1 text-xl font-semibold text-[var(--fg)]">{bridge.agents ?? 0}</p>
                </div>
                <div className="rounded-lg bg-[var(--surface)]/50 p-3">
                  <p className="text-xs text-[var(--muted)]">Heartbeat</p>
                  <p className="mt-1 text-sm font-medium text-[var(--fg)]">{bridge.last_heartbeat || 'N/A'}</p>
                </div>
              </div>
              <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-100">
                This panel reports native bridge telemetry only when an installed native host sends health events.
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
          <div className="card-sentinel p-5">
            <SectionHeader icon={Settings} title="Managed Policy" subtitle="Chrome and Edge enterprise policy posture." />
            <div className="space-y-3">
              {policies.length === 0 && <EmptyState message='No managed browser policy telemetry reported.' />}
              {policies.map(policy => (
                <div key={`${policy.browser}-${policy.name}`} className="flex items-start justify-between gap-3 rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
                  <div className="min-w-0">
                    <p className="truncate font-medium text-[var(--fg)]">{policy.name}</p>
                    <p className="mt-1 text-xs text-[var(--muted)]">{policy.browser} / {policy.scope || 'scope unknown'}</p>
                    <p className="mt-1 text-sm text-[var(--fg-2)]">{policy.value}</p>
                  </div>
                  <StatusBadge status={policy.status} />
                </div>
              ))}
            </div>
          </div>

          <div className="card-sentinel p-5">
            <SectionHeader icon={Shield} title="DNR Rules" subtitle="Declarative Net Request rules and match counters." />
            <div className="space-y-3">
              {dnrRules.length === 0 && <EmptyState message='No DNR rule telemetry or hit counters reported.' />}
              {dnrRules.map(rule => (
                <div key={rule.id} className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="font-medium text-[var(--fg)]">{rule.name}</p>
                      <p className="mt-1 text-xs text-[var(--muted)]">{rule.action} / {rule.condition}</p>
                    </div>
                    <SeverityBadge severity={rule.severity} />
                  </div>
                  <div className="mt-3 flex items-center justify-between text-xs text-[var(--muted)]">
                    <span className="flex items-center gap-1.5">
                      {rule.enabled ? <CheckCircle2 className="h-3.5 w-3.5 text-[var(--emerald-400)]" /> : <XCircle className="h-3.5 w-3.5 text-[var(--crit)]" />}
                      {rule.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                    <span>{rule.hits} hits</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="card-sentinel p-5">
          <SectionHeader icon={Puzzle} title="Extension Inventory" subtitle="Managed and user-installed browser extensions by risk." />
          {inventory.length === 0 && (
            <EmptyState message="No managed or user browser extension inventory reported." />
          )}
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="text-xs uppercase tracking-wider text-[var(--subtle)]">
                <tr className="border-b border-[var(--hairline)]">
                  <th className="pb-3 font-medium">Extension</th>
                  <th className="pb-3 font-medium">Browser</th>
                  <th className="pb-3 font-medium">Install</th>
                  <th className="pb-3 font-medium">Permissions</th>
                  <th className="pb-3 font-medium">Risk</th>
                  <th className="pb-3 font-medium">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--hairline)]">
                {inventory.map(item => (
                  <tr key={`${item.browser}-${item.id}`}>
                    <td className="py-3">
                      <p className="font-medium text-[var(--fg)]">{item.name}</p>
                      <p className="text-xs text-[var(--muted)]">{item.id} / {item.publisher || 'publisher unknown'}</p>
                    </td>
                    <td className="py-3 text-[var(--fg-2)]">{item.browser} {item.version}</td>
                    <td className="py-3 text-[var(--fg-2)]">{item.install_type}</td>
                    <td className="py-3 text-[var(--muted)]">{(item.permissions || []).slice(0, 3).join(', ') || 'none reported'}</td>
                    <td className="py-3"><SeverityBadge severity={item.risk} /></td>
                    <td className="py-3 text-[var(--muted)]">{item.last_seen || 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
          <div className="card-sentinel p-5">
            <SectionHeader icon={Key} title="Bypasses" subtitle="Temporary allow rules and policy exceptions." />
            <div className="space-y-3">
              {bypasses.length === 0 && <EmptyState message='No browser policy bypasses reported.' />}
              {bypasses.map(item => (
                <div key={item.id} className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="font-medium text-[var(--fg)]">{item.target}</p>
                      <p className="mt-1 text-sm text-[var(--muted)]">{item.reason}</p>
                    </div>
                    <StatusBadge status={item.status} />
                  </div>
                  <p className="mt-3 text-xs text-[var(--subtle)]">Owner {item.owner || 'unknown'} / expires {item.expires_at || 'N/A'}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="card-sentinel p-5">
            <SectionHeader icon={Globe} title="Browser Events" subtitle="Recent policy, bridge, DNR, and inventory activity." />
            <div className="space-y-3">
              {events.length === 0 && <EmptyState message='No browser guard events reported in the current telemetry window.' />}
              {events.map(event => (
                <div key={event.id} className="flex gap-3 rounded-lg border border-[var(--border)] bg-[var(--surface)]/40 p-3">
                  <div className="mt-0.5 rounded-lg bg-[var(--surface)] p-2">
                    {event.severity === 'critical' || event.severity === 'high' ? (
                      <ShieldAlert className="h-4 w-4 text-[var(--crit)]" />
                    ) : (
                      <Eye className="h-4 w-4 text-cyan-300" />
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-medium text-[var(--fg)]">{event.title}</p>
                      <SeverityBadge severity={event.severity} />
                    </div>
                    <p className="mt-1 text-sm text-[var(--muted)]">{event.detail || 'No detail reported'}</p>
                    <p className="mt-2 flex flex-wrap items-center gap-2 text-xs text-[var(--subtle)]">
                      <span className="flex items-center gap-1"><Wifi className="h-3.5 w-3.5" />{event.browser}</span>
                      <span className="flex items-center gap-1"><Server className="h-3.5 w-3.5" />{event.host || 'host unknown'}</span>
                      <span className="flex items-center gap-1"><Clock className="h-3.5 w-3.5" />{event.timestamp}</span>
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/50 px-4 py-3 text-xs text-[var(--muted)]">
          <span className="inline-flex items-center gap-2 text-[var(--fg-2)]">
            <Lock className="h-4 w-4" />
            Browser Guard uses tenant-scoped endpoint and extension telemetry. Missing native bridge, DNR, policy, or inventory feeds are shown as degraded instead of simulated.
          </span>
        </div>
      </div>
    </MainLayout>
  )
}
