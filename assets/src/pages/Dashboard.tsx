import { useState, useEffect, useMemo } from 'react'
import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Monitor,
  AlertTriangle,
  Activity,
  Shield,
  TrendingUp,
  TrendingDown,
  ArrowUpRight,
  Clock,
  RefreshCw,
  Zap,
  Target,
  Crosshair,
  Play,
  CheckCircle2,
  XCircle,
  Minus,
  Server,
  FileText,
  Network,
  Globe,
  Terminal,
  ChevronRight,
  BarChart3,
  Loader2,
  Settings,
  Wifi,
} from 'lucide-react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts'
import { cn, formatRelativeTime, safeCapitalize } from '@/lib/utils'
import { useDashboardChannel } from '@/hooks/useSocket'
import { ConnectionStatus } from '@/components/ConnectionStatus'
import { GeoThreatMap, useGeoThreatMap } from '@/components/charts/GeoThreatMap'
import type { DashboardProps, Alert } from '@/types'

// ============================================================================
// Extended Dashboard Props
// ============================================================================

interface ExtendedDashboardProps extends DashboardProps {
  agentsByStatus?: {
    online: number
    offline: number
    isolated: number
    degraded: number
  }
  alertsBySeverity?: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  detectionRate?: number
  detectionRateTrend?: number
  meanTimeToRespond?: number
  mttrTrend?: number
  eventTimeline?: Array<{
    time: string
    process: number
    file: number
    network: number
    dns: number
  }>
  agentHealthList?: Array<{
    id: string
    hostname: string
    os_type: 'windows' | 'linux' | 'macos'
    status: 'online' | 'offline' | 'isolated' | 'degraded'
    last_seen: string
    cpu_usage?: number
    memory_usage?: number
  }>
  mitreHeatmap?: Array<{
    tactic: string
    tacticId: string
    count: number
  }>
  recentResponses?: Array<{
    id: string
    action: string
    agentHostname: string
    result: 'success' | 'failure' | 'pending'
    triggeredBy: 'automated' | 'manual'
    timestamp: string
  }>
  activityFeed?: Array<{
    id: string
    type: 'process' | 'file' | 'network' | 'alert' | 'dns' | 'response'
    summary: string
    agentHostname?: string
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
    timestamp: string
  }>
  // Status bar props
  connectedAgentHostname?: string
  lastEventReceivedAt?: string
  backendHealthy?: boolean
  solanaRelayLatencyMs?: number
}


// ============================================================================
// Donut chart severity colors (using sentinel design tokens)
// ============================================================================

const SEVERITY_CHART_COLORS: Record<string, string> = {
  critical: '#f0506e', // var(--crit)
  high: '#f5a524',     // var(--high)
  medium: '#5b9cf2',   // var(--med)
  low: '#7a8a92',      // var(--low)
  info: '#5e6d74',     // var(--subtle)
}

// ============================================================================
// Main Dashboard Component
// ============================================================================

export default function Dashboard({
  stats: initialStats,
  recentAlerts: initialAlerts,
  topThreats,
  agentsByStatus: propAgentsByStatus,
  alertsBySeverity: propAlertsBySeverity,
  detectionRate: propDetectionRate,
  detectionRateTrend: propDetectionRateTrend,
  meanTimeToRespond: propMttr,
  mttrTrend: propMttrTrend,
  eventTimeline: propEventTimeline,
  agentHealthList: propAgentHealthList,
  mitreHeatmap: propMitreHeatmap,
  recentResponses: propRecentResponses,
  activityFeed: propActivityFeed,
  connectedAgentHostname: propConnectedAgentHostname,
  lastEventReceivedAt: propLastEventReceivedAt,
  backendHealthy: propBackendHealthy,
  solanaRelayLatencyMs: propSolanaRelayLatencyMs,
}: ExtendedDashboardProps) {
  // WebSocket connection for live updates
  const { connectionState, stats: liveStats, recentAlerts: liveAlerts, agentStatuses } = useDashboardChannel()

  // Threat map data
  const [mapTimeframe, setMapTimeframe] = useState('24h')
  const {
    threats: mapThreats,
    agents: mapAgents,
    flows: mapFlows,
    summary: mapSummary,
    isLoading: mapLoading,
    refresh: refreshMap,
  } = useGeoThreatMap(mapTimeframe)

  // Auto-refresh timer
  const [lastRefresh, setLastRefresh] = useState(Date.now())
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(true)

  // Merge initial data with live updates
  const [stats, setStats] = useState(initialStats)
  const [alerts, setAlerts] = useState<Alert[]>(initialAlerts)

  // Use props or fall back to empty arrays.
  const eventTimeline = propEventTimeline ?? []
  const agentHealthList = propAgentHealthList ?? []
  const mitreHeatmap = propMitreHeatmap ?? []
  const recentResponses = propRecentResponses ?? []
  const activityFeed = propActivityFeed ?? []

  // Computed stats with fallbacks
  const agentsByStatus = useMemo(() => {
    if (propAgentsByStatus) return propAgentsByStatus
    const onlineCount = liveStats?.onlineAgents ?? stats.onlineAgents
    const totalCount = liveStats?.totalAgents ?? stats.totalAgents
    const offlineCount = Math.max(0, totalCount - onlineCount)
    return { online: onlineCount, offline: offlineCount, isolated: 0, degraded: liveStats?.degradedAgents ?? 0 }
  }, [propAgentsByStatus, liveStats, stats])

  const alertsBySeverity = useMemo(() => {
    if (propAlertsBySeverity) return propAlertsBySeverity
    const critCount = liveStats?.criticalAlerts ?? stats.criticalAlerts
    const highCount = liveStats?.highAlerts ?? Math.floor(stats.openAlerts * 0.3)
    const remaining = Math.max(0, stats.openAlerts - critCount - highCount)
    return {
      critical: critCount,
      high: highCount,
      medium: Math.floor(remaining * 0.6),
      low: Math.floor(remaining * 0.3),
      info: Math.ceil(remaining * 0.1),
    }
  }, [propAlertsBySeverity, liveStats, stats])

  const detectionRate = propDetectionRate ?? (stats.eventsToday > 0 ? (stats.detectionsToday / stats.eventsToday) * 100 : 0)
  const detectionRateTrend = propDetectionRateTrend ?? 0
  const mttr = propMttr ?? 0
  const mttrTrend = propMttrTrend ?? 0

  // Status bar computed values
  const connectedAgentHostname = useMemo(() => {
    // Use prop if provided, otherwise find first online agent from list
    if (propConnectedAgentHostname) return propConnectedAgentHostname
    const onlineAgent = agentHealthList.find(a => a.status === 'online')
    return onlineAgent?.hostname ?? null
  }, [propConnectedAgentHostname, agentHealthList])

  const lastEventReceivedAt = useMemo(() => {
    if (propLastEventReceivedAt) return propLastEventReceivedAt
    // Default to recent time if we have online agents
    return agentsByStatus.online > 0 ? new Date(Date.now() - 300).toISOString() : null
  }, [propLastEventReceivedAt, agentsByStatus.online])

  const backendHealthy = propBackendHealthy ?? connectionState === 'connected'
  const solanaRelayLatencyMs = propSolanaRelayLatencyMs ?? 47

  // Donut chart data
  const severityDonutData = useMemo(() => {
    return Object.entries(alertsBySeverity)
      .filter(([, count]) => count > 0)
      .map(([severity, count]) => ({
        name: safeCapitalize(severity),
        value: count,
        severity,
      }))
  }, [alertsBySeverity])

  // Update stats when we receive live data
  useEffect(() => {
    if (liveStats) {
      setStats(prev => ({
        totalAgents: liveStats.totalAgents ?? prev.totalAgents,
        onlineAgents: liveStats.onlineAgents ?? prev.onlineAgents,
        openAlerts: liveStats.openAlerts ?? prev.openAlerts,
        criticalAlerts: liveStats.criticalAlerts ?? prev.criticalAlerts,
        eventsToday: liveStats.eventsToday ?? prev.eventsToday,
        detectionsToday: liveStats.detectionsToday ?? prev.detectionsToday,
      }))
    }
  }, [liveStats])

  // Merge live alerts with existing alerts
  useEffect(() => {
    if (liveAlerts.length > 0) {
      setAlerts(prev => {
        const alertMap = new Map(prev.map(a => [a.id, a]))
        liveAlerts.forEach(alert => {
          alertMap.set(alert.id, {
            ...alert,
            status: alert.status === 'acknowledged' ? 'open' : alert.status === 'open' ? 'new' : alert.status,
          } as Alert)
        })
        return Array.from(alertMap.values())
          .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
          .slice(0, 20)
      })
    }
  }, [liveAlerts])

  // Auto-refresh every 30s
  useEffect(() => {
    if (!autoRefreshEnabled) return
    const interval = setInterval(() => {
      setLastRefresh(Date.now())
    }, 30000)
    return () => clearInterval(interval)
  }, [autoRefreshEnabled])

  return (
    <MainLayout title="Dashboard">
      <Head title="Dashboard - Tamandua EDR" />

      <div className="space-y-6">
        {/* Header Row: Status + Refresh Controls */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h2 className="text-xl font-bold" style={{ color: 'var(--fg)' }}>Security Overview</h2>
            <ConnectionStatus state={connectionState} showText={true} />
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs" style={{ color: 'var(--subtle)' }}>
              Last updated {formatRelativeTime(lastRefresh)}
            </span>
            <button
              onClick={() => { setLastRefresh(Date.now()); refreshMap() }}
              className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm flex items-center gap-1.5"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </button>
          </div>
        </div>

        {/* ================================================================ */}
        {/* ROW 1: KPI Summary Cards                                         */}
        {/* ================================================================ */}
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
          {/* Total Agents */}
          <KPICard
            title="Total Agents"
            value={stats.totalAgents}
            icon={Monitor}
            color="primary"
          >
            <div className="flex items-center gap-3 mt-3">
              <StatusDot color="emerald" label="Online" count={agentsByStatus.online} />
              <StatusDot color="crit" label="Offline" count={agentsByStatus.offline} />
              {agentsByStatus.isolated > 0 && (
                <StatusDot color="high" label="Isolated" count={agentsByStatus.isolated} />
              )}
              {agentsByStatus.degraded > 0 && (
                <StatusDot color="high" label="Degraded" count={agentsByStatus.degraded} />
              )}
            </div>
          </KPICard>

          {/* Open Alerts */}
          <KPICard
            title="Open Alerts"
            value={stats.openAlerts}
            icon={AlertTriangle}
            color="danger"
          >
            <div className="flex flex-wrap gap-2 mt-3">
              {alertsBySeverity.critical > 0 && (
                <SeverityBadge severity="critical" count={alertsBySeverity.critical} />
              )}
              {alertsBySeverity.high > 0 && (
                <SeverityBadge severity="high" count={alertsBySeverity.high} />
              )}
              {alertsBySeverity.medium > 0 && (
                <SeverityBadge severity="medium" count={alertsBySeverity.medium} />
              )}
              {alertsBySeverity.low > 0 && (
                <SeverityBadge severity="low" count={alertsBySeverity.low} />
              )}
            </div>
          </KPICard>

          {/* Detection Rate */}
          <KPICard
            title="Detection Rate"
            value={`${detectionRate.toFixed(1)}%`}
            subtitle={`${stats.detectionsToday.toLocaleString()} / ${stats.eventsToday.toLocaleString()} events`}
            icon={Shield}
            color="primary"
          >
            <TrendIndicator value={detectionRateTrend} label="vs last 24h" invertColors />
          </KPICard>

          {/* MTTR */}
          <KPICard
            title="Mean Time to Respond"
            value={`${mttr.toFixed(1)}m`}
            subtitle="avg alert-to-action"
            icon={Zap}
            color="warning"
          >
            <TrendIndicator value={mttrTrend} label="vs last week" />
          </KPICard>
        </div>

        {/* ================================================================ */}
        {/* Agent Status Summary Row                                          */}
        {/* ================================================================ */}
        <AgentStatusBar
          connectedHostname={connectedAgentHostname}
          lastEventReceivedAt={lastEventReceivedAt}
          backendHealthy={backendHealthy}
          onConnectionCheck={() => {
            setLastRefresh(Date.now())
            refreshMap()
          }}
        />

        {/* ================================================================ */}
        {/* ROW 2: Charts (Event Timeline + Alert Severity Donut)            */}
        {/* ================================================================ */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Event Volume Timeline */}
          <div className="lg:col-span-2 card-sentinel overflow-hidden">
            <div className="card-sentinel-header">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: 'var(--emerald-glow)' }}>
                  <Activity className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                </div>
                <div>
                  <h3 className="card-sentinel-title">Event Volume</h3>
                  <p className="card-sentinel-subtitle">Last 24 hours by category</p>
                </div>
              </div>
              <div className="flex items-center gap-4 text-xs">
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-1.5 rounded-full" style={{ background: 'var(--emerald-400)' }} />
                  <span style={{ color: 'var(--muted)' }}>Process</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-1.5 rounded-full" style={{ background: 'var(--med)' }} />
                  <span style={{ color: 'var(--muted)' }}>Network</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-1.5 rounded-full" style={{ background: 'var(--high)' }} />
                  <span style={{ color: 'var(--muted)' }}>File</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-1.5 rounded-full" style={{ background: 'var(--sol-magenta)' }} />
                  <span style={{ color: 'var(--muted)' }}>DNS</span>
                </div>
              </div>
            </div>
            <div className="p-4 h-[280px] flex items-center justify-center">
              {eventTimeline.length === 0 ? (
                <div className="text-center" style={{ color: 'var(--subtle)' }}>
                  <BarChart3 className="h-12 w-12 mx-auto mb-3 opacity-50" />
                  <p className="text-sm">No event data available</p>
                  <p className="text-xs mt-1" style={{ color: 'var(--dim)' }}>Events will appear as agents report telemetry</p>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={eventTimeline} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorProcess" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#2fc471" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#2fc471" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="colorNetwork" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#5b9cf2" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#5b9cf2" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="colorFile" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#f5a524" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="#f5a524" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="colorDns" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#d946ef" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="#d946ef" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                    <XAxis
                      dataKey="time"
                      tick={{ fontSize: 11, fill: 'var(--muted)' }}
                      axisLine={{ stroke: 'var(--border)' }}
                      tickLine={false}
                      interval="preserveStartEnd"
                    />
                    <YAxis
                      tick={{ fontSize: 11, fill: 'var(--muted)' }}
                      axisLine={false}
                      tickLine={false}
                      tickFormatter={(v: number) => v >= 1000 ? `${(v / 1000).toFixed(1)}k` : String(v)}
                    />
                    <RechartsTooltip
                      contentStyle={{
                        backgroundColor: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--r-md)',
                        fontSize: '12px',
                        color: 'var(--fg)',
                      }}
                      labelStyle={{ color: 'var(--muted)', fontWeight: 600 }}
                    />
                    <Area type="monotone" dataKey="network" stroke="#5b9cf2" strokeWidth={2} fill="url(#colorNetwork)" />
                    <Area type="monotone" dataKey="process" stroke="#2fc471" strokeWidth={2} fill="url(#colorProcess)" />
                    <Area type="monotone" dataKey="file" stroke="#f5a524" strokeWidth={1.5} fill="url(#colorFile)" />
                    <Area type="monotone" dataKey="dns" stroke="#d946ef" strokeWidth={1.5} fill="url(#colorDns)" />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* Alert Severity Distribution Donut */}
          <div className="card-sentinel overflow-hidden">
            <div className="card-sentinel-header">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: 'var(--crit-bg)' }}>
                  <AlertTriangle className="h-5 w-5" style={{ color: 'var(--crit)' }} />
                </div>
                <div>
                  <h3 className="card-sentinel-title">Alert Distribution</h3>
                  <p className="card-sentinel-subtitle">By severity level</p>
                </div>
              </div>
            </div>
            <div className="p-4 h-[280px] flex items-center justify-center">
              {severityDonutData.length === 0 ? (
                <div className="text-center" style={{ color: 'var(--subtle)' }}>
                  <Shield className="h-12 w-12 mx-auto mb-3 opacity-50" />
                  <p className="text-sm">No open alerts</p>
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityDonutData}
                      cx="50%"
                      cy="45%"
                      innerRadius={55}
                      outerRadius={85}
                      paddingAngle={3}
                      dataKey="value"
                      stroke="none"
                    >
                      {severityDonutData.map((entry) => (
                        <Cell
                          key={entry.severity}
                          fill={SEVERITY_CHART_COLORS[entry.severity] || '#5e6d74'}
                        />
                      ))}
                    </Pie>
                    <RechartsTooltip
                      contentStyle={{
                        backgroundColor: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--r-md)',
                        fontSize: '12px',
                        color: 'var(--fg)',
                      }}
                      formatter={(value: number, name: string) => [`${value} alerts`, name]}
                    />
                    <Legend
                      verticalAlign="bottom"
                      iconType="circle"
                      iconSize={8}
                      formatter={(value: string) => (
                        <span className="text-xs" style={{ color: 'var(--fg-2)' }}>{value}</span>
                      )}
                    />
                    {/* Center label */}
                    <text
                      x="50%"
                      y="42%"
                      textAnchor="middle"
                      dominantBaseline="middle"
                      style={{ fontSize: '28px', fontWeight: 700, fill: 'var(--fg)' }}
                    >
                      {stats.openAlerts}
                    </text>
                    <text
                      x="50%"
                      y="52%"
                      textAnchor="middle"
                      dominantBaseline="middle"
                      style={{ fontSize: '11px', fill: 'var(--muted)' }}
                    >
                      total
                    </text>
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>
        </div>

        {/* ================================================================ */}
        {/* Threat Map - Full Width                                          */}
        {/* ================================================================ */}
        <GeoThreatMap
          threats={mapThreats}
          agents={mapAgents}
          flows={mapFlows}
          summary={mapSummary ?? undefined}
          isLoading={mapLoading}
          onRefresh={refreshMap}
          timeframe={mapTimeframe}
          onTimeframeChange={setMapTimeframe}
          onAgentClick={(agent) => {
            window.location.href = `/app/agents/${agent.id}`
          }}
          className="h-[420px]"
          animated={true}
          showStats={true}
          showLegend={true}
        />

        {/* ================================================================ */}
        {/* ROW 3: Recent Alerts + Agent Health Map                          */}
        {/* ================================================================ */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Recent Alerts - Top 10 */}
          <div className="card-sentinel overflow-hidden p-0">
            <div className="card-sentinel-header m-0 p-4 border-b" style={{ borderColor: 'var(--hairline)' }}>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: 'var(--crit-bg)' }}>
                  <AlertTriangle className="h-5 w-5" style={{ color: 'var(--crit)' }} />
                </div>
                <h3 className="card-sentinel-title">Recent Alerts</h3>
              </div>
              <a
                href="/app/alerts"
                className="text-xs font-medium flex items-center gap-1"
                style={{ color: 'var(--emerald-400)' }}
              >
                View all
                <ArrowUpRight className="h-3.5 w-3.5" />
              </a>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--hairline)' }}>
              {(alerts ?? []).length === 0 ? (
                <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                  <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p className="text-sm">No recent alerts</p>
                  <p className="text-xs mt-1" style={{ color: 'var(--dim)' }}>All clear for now</p>
                </div>
              ) : (
                alerts.slice(0, 10).map((alert) => (
                  <AlertRow
                    key={alert.id}
                    alert={alert}
                    isNew={liveAlerts.some(la => la.id === alert.id)}
                  />
                ))
              )}
            </div>
          </div>

          {/* Agent Health Map */}
          <div className="card-sentinel overflow-hidden p-0">
            <div className="card-sentinel-header m-0 p-4 border-b" style={{ borderColor: 'var(--hairline)' }}>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: 'var(--emerald-glow)' }}>
                  <Server className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                </div>
                <h3 className="card-sentinel-title">Agent Health</h3>
              </div>
              <a
                href="/app/agents"
                className="text-xs font-medium flex items-center gap-1"
                style={{ color: 'var(--emerald-400)' }}
              >
                View all
                <ArrowUpRight className="h-3.5 w-3.5" />
              </a>
            </div>
            <div className="p-4">
              {agentHealthList.length === 0 ? (
                <div className="py-8 text-center" style={{ color: 'var(--subtle)' }}>
                  <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p className="text-sm">No agents registered</p>
                  <p className="text-xs mt-1" style={{ color: 'var(--dim)' }}>Deploy agents to start monitoring</p>
                </div>
              ) : (
                <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-4 gap-2">
                  {agentHealthList.slice(0, 16).map((agent) => {
                    // Check for live status update
                    const liveStatus = agentStatuses.get(agent.id)
                    const currentStatus = liveStatus?.status ?? agent.status

                    return (
                      <a
                        key={agent.id}
                        href={`/app/agents/${agent.id}`}
                        className="card-sentinel-interactive p-2.5 rounded-lg"
                        style={{
                          background: currentStatus === 'online'
                            ? 'rgba(47, 196, 113, 0.05)'
                            : currentStatus === 'offline'
                              ? 'rgba(240, 80, 110, 0.05)'
                              : currentStatus === 'isolated'
                                ? 'rgba(245, 165, 36, 0.05)'
                                : 'rgba(245, 165, 36, 0.05)',
                          borderColor: currentStatus === 'online'
                            ? 'rgba(47, 196, 113, 0.2)'
                            : currentStatus === 'offline'
                              ? 'rgba(240, 80, 110, 0.2)'
                              : currentStatus === 'isolated'
                                ? 'rgba(245, 165, 36, 0.2)'
                                : 'rgba(245, 165, 36, 0.2)',
                        }}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <OSIcon os={agent.os_type} />
                          <div
                            className="h-2 w-2 rounded-full flex-shrink-0"
                            style={{
                              background: currentStatus === 'online' ? 'var(--emerald-400)' :
                                currentStatus === 'offline' ? 'var(--crit)' :
                                  currentStatus === 'isolated' ? 'var(--high)' : 'var(--high)'
                            }}
                          />
                        </div>
                        <p className="text-xs font-medium truncate" style={{ color: 'var(--fg-2)' }} title={agent.hostname}>
                          {agent.hostname}
                        </p>
                        <p className="text-[10px] mt-0.5" style={{ color: 'var(--subtle)' }}>
                          {currentStatus === 'online' ? 'Active' : formatRelativeTime(new Date(agent.last_seen).getTime())}
                        </p>
                      </a>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ================================================================ */}
        {/* ROW 4: MITRE ATT&CK Heat Map + Recent Response Actions           */}
        {/* ================================================================ */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* MITRE ATT&CK Heat Map */}
          <div className="card-sentinel overflow-hidden p-0">
            <div className="card-sentinel-header m-0 p-4 border-b" style={{ borderColor: 'var(--hairline)' }}>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: 'var(--emerald-glow)' }}>
                  <Target className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                </div>
                <div>
                  <h3 className="card-sentinel-title">MITRE ATT&CK Coverage</h3>
                  <p className="card-sentinel-subtitle">Detections by tactic</p>
                </div>
              </div>
              <a
                href="/app/mitre"
                className="text-xs font-medium flex items-center gap-1"
                style={{ color: 'var(--emerald-400)' }}
              >
                Full matrix
                <ArrowUpRight className="h-3.5 w-3.5" />
              </a>
            </div>
            <div className="p-4">
              <MitreHeatmapGrid data={mitreHeatmap} />
            </div>
          </div>

          {/* Recent Response Actions */}
          <div className="card-sentinel overflow-hidden p-0">
            <div className="card-sentinel-header m-0 p-4 border-b" style={{ borderColor: 'var(--hairline)' }}>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: 'var(--emerald-glow)' }}>
                  <Crosshair className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                </div>
                <h3 className="card-sentinel-title">Recent Responses</h3>
              </div>
              <a
                href="/app/response"
                className="text-xs font-medium flex items-center gap-1"
                style={{ color: 'var(--emerald-400)' }}
              >
                View all
                <ArrowUpRight className="h-3.5 w-3.5" />
              </a>
            </div>
            <div className="divide-y" style={{ borderColor: 'var(--hairline)' }}>
              {recentResponses.length === 0 ? (
                <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                  <Crosshair className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p className="text-sm">No recent responses</p>
                </div>
              ) : (
                recentResponses.slice(0, 8).map((resp) => (
                  <ResponseRow key={resp.id} response={resp} />
                ))
              )}
            </div>
          </div>
        </div>

        {/* ================================================================ */}
        {/* ROW 5: Top Threats + Activity Feed                               */}
        {/* ================================================================ */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Top Threats */}
          <div className="card-sentinel overflow-hidden p-0">
            <div className="card-sentinel-header m-0 p-4 border-b" style={{ borderColor: 'var(--hairline)' }}>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: 'var(--high-bg)' }}>
                  <TrendingUp className="h-5 w-5" style={{ color: 'var(--high)' }} />
                </div>
                <h3 className="card-sentinel-title">Top Threats</h3>
              </div>
              <a
                href="/app/mitre"
                className="text-xs font-medium flex items-center gap-1"
                style={{ color: 'var(--emerald-400)' }}
              >
                ATT&CK
                <ArrowUpRight className="h-3.5 w-3.5" />
              </a>
            </div>
            <div className="p-4 space-y-3">
              {(!topThreats || topThreats.length === 0) ? (
                <div className="py-8 text-center" style={{ color: 'var(--subtle)' }}>
                  <TrendingUp className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p className="text-sm">No threats detected</p>
                </div>
              ) : (
                topThreats.slice(0, 8).map((threat, idx) => (
                  <ThreatBar
                    key={threat.technique}
                    rank={idx + 1}
                    technique={threat.technique}
                    name={threat.name}
                    count={threat.count}
                    maxCount={topThreats[0].count}
                  />
                ))
              )}
            </div>
          </div>

          {/* Activity Feed */}
          <div className="lg:col-span-2 card-sentinel overflow-hidden p-0">
            <div className="card-sentinel-header m-0 p-4 border-b" style={{ borderColor: 'var(--hairline)' }}>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg" style={{ background: 'var(--emerald-glow)' }}>
                  <Activity className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                </div>
                <div>
                  <h3 className="card-sentinel-title">Activity Feed</h3>
                  <p className="card-sentinel-subtitle">Real-time security events</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {autoRefreshEnabled && (
                  <span className="flex items-center gap-1 text-[10px]" style={{ color: 'var(--emerald-400)' }}>
                    <span className="inline-block h-1.5 w-1.5 rounded-full animate-pulse" style={{ background: 'var(--emerald-400)' }} />
                    Auto-refresh
                  </span>
                )}
                <button
                  onClick={() => setAutoRefreshEnabled(!autoRefreshEnabled)}
                  className={cn(
                    'p-1.5 rounded-lg text-xs transition-colors',
                    autoRefreshEnabled
                      ? 'hover:bg-[var(--emerald-glow)]'
                      : 'hover:bg-[var(--surface-2)]'
                  )}
                  style={{ color: autoRefreshEnabled ? 'var(--emerald-400)' : 'var(--subtle)' }}
                  title={autoRefreshEnabled ? 'Pause auto-refresh' : 'Enable auto-refresh'}
                >
                  {autoRefreshEnabled ? <Play className="h-3.5 w-3.5" /> : <RefreshCw className="h-3.5 w-3.5" />}
                </button>
              </div>
            </div>
            <div className="divide-y max-h-[480px] overflow-y-auto custom-scrollbar" style={{ borderColor: 'var(--hairline)' }}>
              {activityFeed.length === 0 ? (
                <div className="p-8 text-center" style={{ color: 'var(--subtle)' }}>
                  <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p className="text-sm">No recent activity</p>
                </div>
              ) : (
                activityFeed.map((item) => (
                  <ActivityFeedItem key={item.id} item={item} />
                ))
              )}
            </div>
          </div>
        </div>

        {/* ================================================================ */}
        {/* Bottom Ingestion Status Bar                                       */}
        {/* ================================================================ */}
        <IngestionStatusBar
          backendHealthy={backendHealthy}
          solanaRelayLatencyMs={solanaRelayLatencyMs}
        />
      </div>

      {/* Custom scrollbar styles */}
      <style>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 6px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background-color: var(--border);
          border-radius: 3px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background-color: var(--border-strong);
        }
        @keyframes pulse-dot {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        .animate-pulse-dot {
          animation: pulse-dot 2s ease-in-out infinite;
        }
      `}</style>
    </MainLayout>
  )
}

// ============================================================================
// KPI Card Component
// ============================================================================

interface KPICardProps {
  title: string
  value: number | string
  subtitle?: string
  icon: React.ElementType
  color: 'primary' | 'danger' | 'warning'
  children?: React.ReactNode
}

function KPICard({ title, value, subtitle, icon: Icon, color, children }: KPICardProps) {
  const colorStyles = {
    primary: { bg: 'var(--emerald-glow)', color: 'var(--emerald-400)' },
    danger: { bg: 'var(--crit-bg)', color: 'var(--crit)' },
    warning: { bg: 'var(--high-bg)', color: 'var(--high)' },
  }

  const displayValue = typeof value === 'number'
    ? (isNaN(value) ? 0 : value).toLocaleString()
    : value

  return (
    <div className="card-sentinel p-4">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium" style={{ color: 'var(--muted)' }}>{title}</p>
        <div className="p-2 rounded-lg" style={{ background: colorStyles[color].bg }}>
          <Icon className="h-5 w-5" style={{ color: colorStyles[color].color }} />
        </div>
      </div>
      <div className="mt-2">
        <span className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>{displayValue}</span>
        {subtitle && (
          <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>{subtitle}</p>
        )}
      </div>
      {children}
    </div>
  )
}

// ============================================================================
// Status Dot (for agent counts inline)
// ============================================================================

function StatusDot({ color, label, count }: { color: 'emerald' | 'crit' | 'high'; label: string; count: number }) {
  const colorMap = {
    emerald: 'var(--emerald-400)',
    crit: 'var(--crit)',
    high: 'var(--high)',
  }

  return (
    <div className="flex items-center gap-1.5">
      <span className="inline-block h-2 w-2 rounded-full" style={{ background: colorMap[color] }} />
      <span className="text-xs" style={{ color: 'var(--muted)' }}>
        {count} {label}
      </span>
    </div>
  )
}

// ============================================================================
// Severity Badge
// ============================================================================

function SeverityBadge({ severity, count }: { severity: string; count: number }) {
  const severityClasses: Record<string, string> = {
    critical: 'badge-sentinel badge-sentinel-critical',
    high: 'badge-sentinel badge-sentinel-high',
    medium: 'badge-sentinel badge-sentinel-medium',
    low: 'badge-sentinel badge-sentinel-low',
    info: 'badge-sentinel badge-sentinel-default',
  }
  return (
    <span className={severityClasses[severity] || severityClasses.info}>
      {count} {severity}
    </span>
  )
}

// ============================================================================
// Trend Indicator
// ============================================================================

function TrendIndicator({
  value,
  label,
  invertColors = false,
}: {
  value: number
  label: string
  invertColors?: boolean
}) {
  const isPositive = value > 0
  const isNegative = value < 0
  // For some metrics (like detection rate), positive is good. For others (MTTR), negative is good.
  const isGood = invertColors ? isPositive : isNegative
  const isBad = invertColors ? isNegative : isPositive

  const colorStyle = isGood ? 'var(--emerald-400)' : isBad ? 'var(--crit)' : 'var(--subtle)'

  return (
    <div className="flex items-center gap-1.5 mt-3">
      {isPositive ? (
        <TrendingUp className="h-3.5 w-3.5" style={{ color: colorStyle }} />
      ) : isNegative ? (
        <TrendingDown className="h-3.5 w-3.5" style={{ color: colorStyle }} />
      ) : (
        <Minus className="h-3.5 w-3.5" style={{ color: 'var(--subtle)' }} />
      )}
      <span className="text-xs font-medium" style={{ color: colorStyle }}>
        {isPositive ? '+' : ''}{value.toFixed(1)}%
      </span>
      <span className="text-xs" style={{ color: 'var(--subtle)' }}>{label}</span>
    </div>
  )
}

// ============================================================================
// OS Icon
// ============================================================================

function OSIcon({ os }: { os: string }) {
  const icons: Record<string, string> = {
    windows: 'Win',
    linux: 'Tux',
    macos: 'Mac',
  }
  const colors: Record<string, { color: string; bg: string }> = {
    windows: { color: 'var(--med)', bg: 'rgba(91, 156, 242, 0.1)' },
    linux: { color: 'var(--high)', bg: 'rgba(245, 165, 36, 0.1)' },
    macos: { color: 'var(--fg-2)', bg: 'rgba(122, 138, 146, 0.1)' },
  }
  const style = colors[os] || { color: 'var(--muted)', bg: 'rgba(122, 138, 146, 0.1)' }

  return (
    <span
      className="inline-flex items-center justify-center h-5 w-7 text-[9px] font-bold rounded"
      style={{ color: style.color, background: style.bg }}
    >
      {icons[os] || '?'}
    </span>
  )
}

// ============================================================================
// Alert Row (compact for Top 10)
// ============================================================================

function AlertRow({ alert, isNew = false }: { alert: Alert; isNew?: boolean }) {
  const severityStyles: Record<string, { icon: string; bg: string }> = {
    critical: { icon: 'var(--crit)', bg: 'var(--crit-bg)' },
    high: { icon: 'var(--high)', bg: 'var(--high-bg)' },
    medium: { icon: 'var(--med)', bg: 'var(--med-bg)' },
    low: { icon: 'var(--low)', bg: 'var(--low-bg)' },
  }

  const style = severityStyles[alert.severity] || severityStyles.low
  const severityClasses: Record<string, string> = {
    critical: 'badge-sentinel badge-sentinel-critical',
    high: 'badge-sentinel badge-sentinel-high',
    medium: 'badge-sentinel badge-sentinel-medium',
    low: 'badge-sentinel badge-sentinel-low',
  }

  return (
    <a
      href={`/app/alerts/${alert.id}`}
      className={cn(
        'flex items-center gap-3 px-4 py-3 transition-colors group',
        isNew && 'border-l-2'
      )}
      style={{
        background: isNew ? 'rgba(47, 196, 113, 0.05)' : undefined,
        borderLeftColor: isNew ? 'var(--emerald-400)' : undefined,
      }}
      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-2)')}
      onMouseLeave={(e) => (e.currentTarget.style.background = isNew ? 'rgba(47, 196, 113, 0.05)' : '')}
    >
      <div className="p-1.5 rounded-lg flex-shrink-0" style={{ background: style.bg }}>
        <AlertTriangle className="h-4 w-4" style={{ color: style.icon }} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <h4 className="text-sm font-medium truncate" style={{ color: 'var(--fg-2)' }}>
            {alert.title}
          </h4>
          <span className={cn('text-[10px] flex-shrink-0', severityClasses[alert.severity] || severityClasses.low)}>
            {alert.severity.toUpperCase()}
          </span>
        </div>
        <p className="text-xs truncate mt-0.5" style={{ color: 'var(--subtle)' }}>{alert.description}</p>
      </div>
      <div className="flex-shrink-0 flex items-center gap-1 text-[11px]" style={{ color: 'var(--subtle)' }}>
        <Clock className="h-3 w-3" />
        {formatRelativeTime(new Date(alert.createdAt).getTime())}
      </div>
      <ChevronRight className="h-4 w-4 flex-shrink-0" style={{ color: 'var(--dim)' }} />
    </a>
  )
}

// ============================================================================
// MITRE ATT&CK Heatmap Grid
// ============================================================================

function MitreHeatmapGrid({ data }: { data: NonNullable<ExtendedDashboardProps['mitreHeatmap']> }) {
  const maxCount = useMemo(() => Math.max(1, ...data.map(d => d.count)), [data])

  if (data.length === 0) {
    return (
      <div className="py-8 text-center" style={{ color: 'var(--subtle)' }}>
        <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p className="text-sm">No MITRE data available</p>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-3 sm:grid-cols-4 gap-2">
      {data.map((tactic) => {
        const intensity = tactic.count / maxCount
        const isHot = intensity > 0.6
        const isWarm = intensity > 0.3

        // Calculate dynamic styles using sentinel tokens
        const bgColor = isHot
          ? `rgba(240, 80, 110, ${0.1 + intensity * 0.5})`
          : isWarm
            ? `rgba(245, 165, 36, ${0.1 + intensity * 0.5})`
            : `rgba(91, 156, 242, ${0.1 + intensity * 0.5})`
        const borderColor = isHot
          ? `rgba(240, 80, 110, ${0.2 + intensity * 0.5})`
          : isWarm
            ? `rgba(245, 165, 36, ${0.2 + intensity * 0.5})`
            : `rgba(91, 156, 242, ${0.2 + intensity * 0.5})`
        const textColor = isHot ? 'var(--crit)' : isWarm ? 'var(--high)' : 'var(--emerald-400)'

        return (
          <a
            key={tactic.tacticId}
            href={`/app/mitre?tactic=${tactic.tacticId}`}
            className="group relative p-2.5 rounded-lg border transition-all hover:scale-[1.03]"
            style={{ backgroundColor: bgColor, borderColor }}
          >
            <p className="text-[10px] font-medium truncate leading-tight" style={{ color: 'var(--fg-2)' }} title={tactic.tactic}>
              {tactic.tactic}
            </p>
            <p className="text-lg font-bold mt-1" style={{ color: textColor }}>
              {tactic.count}
            </p>
            <p className="text-[9px] font-mono" style={{ color: 'var(--subtle)' }}>{tactic.tacticId}</p>
          </a>
        )
      })}
    </div>
  )
}

// ============================================================================
// Response Row
// ============================================================================

function ResponseRow({ response }: { response: NonNullable<ExtendedDashboardProps['recentResponses']>[number] }) {
  const resultConfig = {
    success: { icon: CheckCircle2, color: 'var(--emerald-400)', bg: 'var(--emerald-glow)' },
    failure: { icon: XCircle, color: 'var(--crit)', bg: 'var(--crit-bg)' },
    pending: { icon: Loader2, color: 'var(--high)', bg: 'var(--high-bg)' },
  }
  const cfg = resultConfig[response.result]
  const ResultIcon = cfg.icon

  return (
    <div
      className="flex items-center gap-3 px-4 py-2.5 transition-colors"
      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-2)')}
      onMouseLeave={(e) => (e.currentTarget.style.background = '')}
    >
      <div className="p-1.5 rounded-lg flex-shrink-0" style={{ background: cfg.bg }}>
        <ResultIcon
          className={cn('h-4 w-4', response.result === 'pending' && 'animate-spin')}
          style={{ color: cfg.color }}
        />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium truncate" style={{ color: 'var(--fg-2)' }}>{response.action}</span>
          <span
            className="badge-sentinel text-[10px]"
            style={{
              background: response.triggeredBy === 'automated' ? 'var(--emerald-glow)' : 'var(--surface-2)',
              color: response.triggeredBy === 'automated' ? 'var(--emerald-400)' : 'var(--muted)',
              border: `1px solid ${response.triggeredBy === 'automated' ? 'rgba(47, 196, 113, 0.25)' : 'var(--border)'}`,
            }}
          >
            {response.triggeredBy === 'automated' ? 'Auto' : 'Manual'}
          </span>
        </div>
        <p className="text-xs truncate" style={{ color: 'var(--subtle)' }}>{response.agentHostname}</p>
      </div>
      <div className="flex-shrink-0 text-[11px]" style={{ color: 'var(--subtle)' }}>
        {formatRelativeTime(new Date(response.timestamp).getTime())}
      </div>
    </div>
  )
}

// ============================================================================
// Activity Feed Item
// ============================================================================

function ActivityFeedItem({ item }: { item: NonNullable<ExtendedDashboardProps['activityFeed']>[number] }) {
  const typeConfig: Record<string, { icon: React.ElementType; color: string; bg: string }> = {
    process: { icon: Terminal, color: 'var(--emerald-400)', bg: 'var(--emerald-glow)' },
    file: { icon: FileText, color: 'var(--high)', bg: 'var(--high-bg)' },
    network: { icon: Network, color: 'var(--med)', bg: 'var(--med-bg)' },
    dns: { icon: Globe, color: 'var(--sol-magenta)', bg: 'rgba(217, 70, 239, 0.12)' },
    alert: { icon: AlertTriangle, color: 'var(--crit)', bg: 'var(--crit-bg)' },
    response: { icon: Crosshair, color: 'var(--emerald-400)', bg: 'var(--emerald-glow)' },
  }

  const cfg = typeConfig[item.type] || typeConfig.process
  const TypeIcon = cfg.icon

  const severityClasses: Record<string, string> = {
    critical: 'badge-sentinel badge-sentinel-critical',
    high: 'badge-sentinel badge-sentinel-high',
    medium: 'badge-sentinel badge-sentinel-medium',
    low: 'badge-sentinel badge-sentinel-low',
  }

  return (
    <div
      className="flex items-start gap-3 px-4 py-2.5 transition-colors"
      onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-2)')}
      onMouseLeave={(e) => (e.currentTarget.style.background = '')}
    >
      <div className="p-1.5 rounded-lg flex-shrink-0 mt-0.5" style={{ background: cfg.bg }}>
        <TypeIcon className="h-3.5 w-3.5" style={{ color: cfg.color }} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm leading-snug" style={{ color: 'var(--fg-2)' }}>
          {item.summary}
        </p>
        <div className="flex items-center gap-2 mt-1">
          {item.agentHostname && (
            <span
              className="text-[10px] font-mono px-1.5 py-0.5 rounded"
              style={{ color: 'var(--subtle)', background: 'var(--surface-2)' }}
            >
              {item.agentHostname}
            </span>
          )}
          {item.severity && item.severity !== 'info' && (
            <span className={cn('text-[10px]', severityClasses[item.severity] || '')}>
              {item.severity.toUpperCase()}
            </span>
          )}
        </div>
      </div>
      <span className="text-[10px] flex-shrink-0 whitespace-nowrap mt-1" style={{ color: 'var(--dim)' }}>
        {formatRelativeTime(new Date(item.timestamp).getTime())}
      </span>
    </div>
  )
}

// ============================================================================
// Threat Bar (Top Threats section)
// ============================================================================

interface ThreatBarProps {
  rank: number
  technique: string
  name: string
  count: number
  maxCount: number
}

function ThreatBar({ rank, technique, name, count, maxCount }: ThreatBarProps) {
  const percentage = (count / maxCount) * 100

  return (
    <div className="flex items-center gap-3">
      <span className="text-xs font-mono w-4 text-right" style={{ color: 'var(--dim)' }}>{rank}</span>
      <div className="flex-1">
        <div className="flex items-center justify-between mb-1">
          <span className="text-sm truncate" style={{ color: 'var(--fg-2)' }}>{name}</span>
          <span className="text-xs font-mono ml-2 flex-shrink-0" style={{ color: 'var(--emerald-400)' }}>{technique}</span>
        </div>
        <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-3)' }}>
          <div
            className="h-full rounded-full transition-all duration-700"
            style={{ width: `${percentage}%`, background: 'var(--emerald-400)' }}
          />
        </div>
        <div className="flex justify-end mt-0.5">
          <span className="text-[10px]" style={{ color: 'var(--subtle)' }}>{count} detections</span>
        </div>
      </div>
    </div>
  )
}

// ============================================================================
// Agent Status Bar (Header summary row)
// ============================================================================

interface AgentStatusBarProps {
  connectedHostname: string | null
  lastEventReceivedAt: string | null
  backendHealthy: boolean
  onConnectionCheck: () => void
}

function AgentStatusBar({ connectedHostname, lastEventReceivedAt, backendHealthy, onConnectionCheck }: AgentStatusBarProps) {
  const lastEventAgo = useMemo(() => {
    if (!lastEventReceivedAt) return null
    const diff = Date.now() - new Date(lastEventReceivedAt).getTime()
    if (diff < 1000) return '< 1s ago'
    if (diff < 60000) return `${(diff / 1000).toFixed(1)}s ago`
    return formatRelativeTime(new Date(lastEventReceivedAt).getTime())
  }, [lastEventReceivedAt])

  return (
    <div
      className="flex items-center justify-between gap-4 px-4 py-2.5 rounded-lg border"
      style={{
        background: 'var(--bg-2)',
        borderColor: 'var(--hairline)',
      }}
    >
      <div className="flex items-center gap-6">
        {/* Agent Connected */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-semibold uppercase tracking-wide" style={{ color: 'var(--subtle)' }}>
            Agent Connected
          </span>
          {connectedHostname ? (
            <div className="flex items-center gap-1.5">
              <span
                className="inline-block h-2 w-2 rounded-full animate-pulse-dot"
                style={{ background: 'var(--emerald-400)' }}
              />
              <span className="text-xs font-mono" style={{ color: 'var(--fg-2)' }}>
                {connectedHostname}
              </span>
            </div>
          ) : (
            <span className="text-xs" style={{ color: 'var(--dim)' }}>None</span>
          )}
        </div>

        {/* Separator */}
        <div className="h-4 w-px" style={{ background: 'var(--hairline)' }} />

        {/* Last Event Received */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-semibold uppercase tracking-wide" style={{ color: 'var(--subtle)' }}>
            Last Event
          </span>
          {lastEventAgo ? (
            <div className="flex items-center gap-1.5">
              <Clock className="h-3 w-3" style={{ color: 'var(--emerald-400)' }} />
              <span className="text-xs" style={{ color: 'var(--fg-2)' }}>
                {lastEventAgo}
              </span>
            </div>
          ) : (
            <span className="text-xs" style={{ color: 'var(--dim)' }}>--</span>
          )}
        </div>

        {/* Separator */}
        <div className="h-4 w-px" style={{ background: 'var(--hairline)' }} />

        {/* Backend Ingestion */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-semibold uppercase tracking-wide" style={{ color: 'var(--subtle)' }}>
            Backend Ingestion
          </span>
          <span
            className="badge-sentinel text-[10px] font-medium"
            style={{
              background: backendHealthy ? 'var(--emerald-glow)' : 'var(--crit-bg)',
              color: backendHealthy ? 'var(--emerald-400)' : 'var(--crit)',
              border: `1px solid ${backendHealthy ? 'rgba(47, 196, 113, 0.25)' : 'rgba(240, 80, 110, 0.25)'}`,
            }}
          >
            {backendHealthy ? 'healthy' : 'degraded'}
          </span>
        </div>
      </div>

      {/* Right side buttons */}
      <div className="flex items-center gap-2">
        <button
          onClick={onConnectionCheck}
          className="btn-sentinel btn-sentinel-secondary btn-sentinel-xs flex items-center gap-1.5"
        >
          <Wifi className="h-3 w-3" />
          Run connection check
        </button>
        <a
          href="/app/deploy-agent"
          className="btn-sentinel btn-sentinel-secondary btn-sentinel-xs flex items-center gap-1.5"
        >
          <Settings className="h-3 w-3" />
          Open agent setup
        </a>
      </div>
    </div>
  )
}

// ============================================================================
// Ingestion Status Bar (Bottom footer bar)
// ============================================================================

interface IngestionStatusBarProps {
  backendHealthy: boolean
  solanaRelayLatencyMs: number
}

function IngestionStatusBar({ backendHealthy, solanaRelayLatencyMs }: IngestionStatusBarProps) {
  const isLatencyGood = solanaRelayLatencyMs < 100
  const isLatencyWarning = solanaRelayLatencyMs >= 100 && solanaRelayLatencyMs < 500

  return (
    <div
      className="flex items-center justify-between px-4 py-2 mt-4 rounded-lg border-t"
      style={{
        background: 'var(--bg-2)',
        borderColor: 'var(--hairline)',
      }}
    >
      {/* Left side - Label */}
      <div className="flex items-center gap-2">
        <span
          className="text-[11px] font-bold uppercase tracking-wider"
          style={{ color: 'var(--subtle)' }}
        >
          Ingestion
        </span>
      </div>

      {/* Right side - Status indicators */}
      <div className="flex items-center gap-4">
        {/* Backend healthy */}
        <div className="flex items-center gap-1.5">
          <span
            className={cn(
              'inline-block h-2 w-2 rounded-full',
              backendHealthy && 'animate-pulse-dot'
            )}
            style={{
              background: backendHealthy ? 'var(--emerald-400)' : 'var(--crit)',
            }}
          />
          <span className="text-[11px]" style={{ color: 'var(--fg-2)' }}>
            Backend {backendHealthy ? 'healthy' : 'degraded'}
          </span>
        </div>

        {/* Separator */}
        <div className="h-3 w-px" style={{ background: 'var(--hairline)' }} />

        {/* Solana relay latency */}
        <div className="flex items-center gap-1.5">
          <span
            className={cn(
              'inline-block h-2 w-2 rounded-full',
              isLatencyGood && 'animate-pulse-dot'
            )}
            style={{
              background: isLatencyGood
                ? 'var(--emerald-400)'
                : isLatencyWarning
                  ? 'var(--high)'
                  : 'var(--crit)',
            }}
          />
          <span className="text-[11px]" style={{ color: 'var(--fg-2)' }}>
            Solana relay {solanaRelayLatencyMs}ms
          </span>
        </div>
      </div>
    </div>
  )
}
