import { useState, useEffect, useMemo, useCallback } from 'react'
import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { ProcessTreeViewer, ProcessDetailsPanel } from '@/components/ProcessTreeViewer'
import {
  Monitor, RefreshCw, Search, ChevronDown, AlertTriangle,
  Globe, File, Share2, TreePine, Shield,
  ChevronUp, X, AlertCircle, Info, Filter,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import type { ProcessTreePageProps, ProcessNode, Agent } from '@/types'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function findNodeByPid(nodes: ProcessNode[], pid: number): ProcessNode | null {
  for (const node of nodes) {
    if (node.pid === pid) return node
    if (node.children) {
      const found = findNodeByPid(node.children, pid)
      if (found) return found
    }
  }
  return null
}

function countAll(nodes: ProcessNode[]): number {
  return nodes.reduce((sum, n) => sum + 1 + (n.children ? countAll(n.children) : 0), 0)
}

function countDetections(nodes: ProcessNode[]): number {
  return nodes.reduce((count, node) => {
    const nodeDetections = node.detections?.length || 0
    const childDetections = node.children ? countDetections(node.children) : 0
    return count + nodeDetections + childDetections
  }, 0)
}

function countElevated(nodes: ProcessNode[]): number {
  return nodes.reduce((count, node) => {
    const self = node.isElevated ? 1 : 0
    const children = node.children ? countElevated(node.children) : 0
    return count + self + children
  }, 0)
}

type SuspiciousFilter = 'all' | 'unsigned' | 'elevated' | 'detections'

function isSuspiciousNode(node: ProcessNode, filter: SuspiciousFilter): boolean {
  switch (filter) {
    case 'unsigned': return !node.isSigned
    case 'elevated': return !!node.isElevated
    case 'detections': return (node.detections?.length ?? 0) > 0
    default: return true
  }
}

function countUnsigned(nodes: ProcessNode[]): number {
  return nodes.reduce((count, node) => {
    const self = !node.isSigned ? 1 : 0
    const children = node.children ? countUnsigned(node.children) : 0
    return count + self + children
  }, 0)
}

function filterProcesses(nodes: ProcessNode[], query: string, suspiciousFilter: SuspiciousFilter = 'all'): ProcessNode[] {
  if (!query && suspiciousFilter === 'all') return nodes
  const lowerQuery = query.toLowerCase()

  const filterNode = (node: ProcessNode): ProcessNode | null => {
    const textMatches = !query || (
      (node.name || '').toLowerCase().includes(lowerQuery) ||
      (node.path || '').toLowerCase().includes(lowerQuery) ||
      (node.cmdline || '').toLowerCase().includes(lowerQuery) ||
      (node.user || '').toLowerCase().includes(lowerQuery) ||
      (node.companyName || '').toLowerCase().includes(lowerQuery) ||
      node.pid.toString().includes(query)
    )

    const suspiciousMatches = suspiciousFilter === 'all' || isSuspiciousNode(node, suspiciousFilter)

    const filteredChildren = (node.children || [])
      .map(filterNode)
      .filter((n): n is ProcessNode => n !== null)

    if ((textMatches && suspiciousMatches) || filteredChildren.length > 0) {
      return { ...node, children: filteredChildren }
    }
    return null
  }

  return nodes
    .map(filterNode)
    .filter((n): n is ProcessNode => n !== null)
}

/** Fetch children for a process via the API (for lazy loading) */
async function fetchProcessChildren(agentId: string, pid: number): Promise<ProcessNode[]> {
  const resp = await fetch(`/api/v1/agents/${agentId}/processes/${pid}/children`, {
    headers: { 'Accept': 'application/json' },
    credentials: 'same-origin',
  })
  if (!resp.ok) {
    throw new Error(`Failed to fetch children: ${resp.status}`)
  }
  const json = await resp.json()
  return (json.data || []) as ProcessNode[]
}

// ---------------------------------------------------------------------------
// Page Component
// ---------------------------------------------------------------------------

export default function ProcessTree({ agents, selectedAgent, processTree, treeMeta }: ProcessTreePageProps) {
  const [selectedProcess, setSelectedProcess] = useState<ProcessNode | null>(null)
  const [showAgentDropdown, setShowAgentDropdown] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [suspiciousFilter, setSuspiciousFilter] = useState<SuspiciousFilter>('all')
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [focusPid, setFocusPid] = useState<number | undefined>(undefined)
  const [detailsCollapsed, setDetailsCollapsed] = useState(false)

  const hasError = treeMeta?.error != null
  const isTruncated = treeMeta?.truncated === true
  const totalProcessesOnServer = treeMeta?.total_processes

  // Read pid from URL query params on mount and when processTree changes
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const pidParam = params.get('pid')
    if (pidParam && processTree) {
      const pid = parseInt(pidParam, 10)
      if (!isNaN(pid)) {
        setFocusPid(pid)
        setSearchQuery(pidParam)
        const node = findNodeByPid(processTree, pid)
        if (node) setSelectedProcess(node)
      }
    }
  }, [processTree])

  const handleAgentSelect = (agent: Agent) => {
    setShowAgentDropdown(false)
    setSelectedProcess(null)
    router.get('/app/process-tree', { agent_id: agent.id }, { preserveState: true })
  }

  const handleRefresh = () => {
    if (!selectedAgent) return
    setIsRefreshing(true)
    router.reload({
      only: ['processTree', 'treeMeta'],
      onFinish: () => setIsRefreshing(false)
    })
  }

  const handleProcessSelect = (process: ProcessNode) => {
    setSelectedProcess(process)
    if (detailsCollapsed) setDetailsCollapsed(false)
  }

  // Lazy-load handler: fetch children from the API when expanding a node
  const handleLoadChildren = useCallback(async (agentId: string, pid: number): Promise<ProcessNode[]> => {
    return fetchProcessChildren(agentId, pid)
  }, [])

  const filteredProcesses = useMemo(
    () => (processTree ? filterProcesses(processTree, searchQuery, suspiciousFilter) : []),
    [processTree, searchQuery, suspiciousFilter]
  )

  // Stats
  const loadedProcessCount = processTree ? countAll(processTree) : 0
  const totalDetections = processTree ? countDetections(processTree) : 0
  const totalElevated = processTree ? countElevated(processTree) : 0
  const totalUnsigned = processTree ? countUnsigned(processTree) : 0

  // Display string for process count
  const processCountDisplay = (() => {
    if (isTruncated && totalProcessesOnServer) {
      return `showing ${loadedProcessCount} of ${totalProcessesOnServer}`
    }
    return `${loadedProcessCount} processes`
  })()

  return (
    <MainLayout title="Process Tree">
      <Head title="Process Tree - Tamandua EDR" />

      <div className="flex flex-col h-[calc(100vh-8rem)]">
        {/* ================================================================ */}
        {/* Toolbar */}
        {/* ================================================================ */}
        <div
          className="flex items-center justify-between rounded-t-xl px-3 py-2 gap-3"
          style={{
            background: 'var(--surface)',
            border: '1px solid var(--hairline)',
          }}
        >
          {/* Left: Agent selector + search */}
          <div className="flex items-center gap-3">
            {/* Agent Selector */}
            <div className="relative">
              <button
                onClick={() => setShowAgentDropdown(!showAgentDropdown)}
                className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm transition-colors hover:opacity-80"
                style={{
                  background: 'var(--bg)',
                  border: '1px solid var(--hairline)',
                }}
              >
                <Monitor className="h-3.5 w-3.5" style={{ color: 'var(--muted)' }} />
                <span className="max-w-[140px] truncate" style={{ color: 'var(--fg)' }}>
                  {selectedAgent ? selectedAgent.hostname : 'Select Agent'}
                </span>
                <ChevronDown
                  className={cn(
                    'h-3.5 w-3.5 transition-transform',
                    showAgentDropdown && 'rotate-180'
                  )}
                  style={{ color: 'var(--muted)' }}
                />
              </button>

              {showAgentDropdown && (
                <div
                  className="absolute top-full left-0 mt-1 w-72 rounded-lg shadow-xl z-20 py-1 max-h-72 overflow-auto"
                  style={{
                    background: 'var(--surface)',
                    border: '1px solid var(--hairline)',
                  }}
                >
                  {agents.length === 0 ? (
                    <p className="px-3 py-2 text-sm" style={{ color: 'var(--muted)' }}>No agents available</p>
                  ) : (
                    agents.map((agent) => (
                      <button
                        key={agent.id}
                        onClick={() => handleAgentSelect(agent)}
                        className={cn(
                          'flex items-center gap-3 w-full px-3 py-2 text-sm text-left transition-colors hover:opacity-80',
                          selectedAgent?.id === agent.id && 'opacity-90'
                        )}
                        style={{
                          background: selectedAgent?.id === agent.id ? 'var(--bg)' : 'transparent',
                        }}
                      >
                        <div
                          className="h-2 w-2 rounded-full shrink-0"
                          style={{
                            background: agent.status === 'online'
                              ? 'var(--emerald-400)'
                              : agent.status === 'degraded'
                              ? 'var(--amber-400)'
                              : 'var(--muted)',
                          }}
                        />
                        <div className="flex-1 min-w-0">
                          <p className="truncate" style={{ color: 'var(--fg)' }}>{agent.hostname}</p>
                          <p className="text-xs" style={{ color: 'var(--muted)' }}>{agent.ip_address} -- {agent.os_type}</p>
                        </div>
                      </button>
                    ))
                  )}
                </div>
              )}
            </div>

            {/* Search */}
            {selectedAgent && (
              <div className="relative">
                <Search
                  className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5"
                  style={{ color: 'var(--muted)' }}
                />
                <input
                  type="text"
                  placeholder="Filter by name, PID, user, path..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="rounded-lg pl-8 pr-8 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-transparent w-72"
                  style={{
                    background: 'var(--bg)',
                    border: '1px solid var(--hairline)',
                    color: 'var(--fg)',
                  }}
                />
                {searchQuery && (
                  <button
                    onClick={() => setSearchQuery('')}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2"
                  >
                    <X className="h-3.5 w-3.5 hover:opacity-70" style={{ color: 'var(--muted)' }} />
                  </button>
                )}
              </div>
            )}

            {/* Suspicious filter chips */}
            {selectedAgent && processTree && (
              <div className="flex items-center gap-1">
                <Filter className="h-3 w-3 mr-0.5" style={{ color: 'var(--muted)' }} />
                {([
                  { value: 'all' as SuspiciousFilter, label: 'All', count: loadedProcessCount },
                  { value: 'detections' as SuspiciousFilter, label: 'Detections', count: totalDetections, colorVar: '--red-400' },
                  { value: 'unsigned' as SuspiciousFilter, label: 'Unsigned', count: totalUnsigned, colorVar: '--orange-400' },
                  { value: 'elevated' as SuspiciousFilter, label: 'Elevated', count: totalElevated, colorVar: '--amber-400' },
                ]).map(f => (
                  <button
                    key={f.value}
                    onClick={() => setSuspiciousFilter(f.value)}
                    className="px-2 py-1 rounded text-[11px] font-medium transition-colors"
                    style={{
                      background: suspiciousFilter === f.value
                        ? 'color-mix(in srgb, var(--blue-400) 20%, transparent)'
                        : 'var(--bg)',
                      color: suspiciousFilter === f.value
                        ? 'var(--blue-400)'
                        : 'var(--muted)',
                      border: suspiciousFilter === f.value
                        ? '1px solid color-mix(in srgb, var(--blue-400) 40%, transparent)'
                        : '1px solid var(--hairline)',
                    }}
                  >
                    {f.label}
                    {f.count > 0 && f.value !== 'all' && (
                      <span className="ml-1 font-mono" style={{ color: `var(${f.colorVar})` }}>{f.count}</span>
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Right: Stats + refresh */}
          <div className="flex items-center gap-4">
            {selectedAgent && processTree && (
              <>
                <div className="hidden md:flex items-center gap-4 text-xs" style={{ color: 'var(--muted)' }}>
                  <span className="flex items-center gap-1.5">
                    <TreePine className="h-3.5 w-3.5" />
                    {processCountDisplay}
                  </span>
                  {totalDetections > 0 && (
                    <span className="flex items-center gap-1.5" style={{ color: 'var(--red-400)' }}>
                      <AlertTriangle className="h-3.5 w-3.5" />
                      {totalDetections} detections
                    </span>
                  )}
                  {totalElevated > 0 && (
                    <span className="flex items-center gap-1.5" style={{ color: 'var(--amber-400)' }}>
                      <Shield className="h-3.5 w-3.5" />
                      {totalElevated} elevated
                    </span>
                  )}
                </div>

                <button
                  onClick={handleRefresh}
                  disabled={isRefreshing}
                  className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs text-white font-medium transition-colors disabled:opacity-50"
                  style={{ background: 'var(--blue-500)' }}
                >
                  <RefreshCw className={cn('h-3.5 w-3.5', isRefreshing && 'animate-spin')} />
                  Refresh
                </button>
              </>
            )}
          </div>
        </div>

        {/* ================================================================ */}
        {/* Truncation / Error banners */}
        {/* ================================================================ */}
        {selectedAgent && isTruncated && (
          <div
            className="flex items-center gap-2 px-3 py-1.5 text-xs"
            style={{
              background: 'color-mix(in srgb, var(--amber-400) 10%, transparent)',
              borderLeft: '1px solid color-mix(in srgb, var(--amber-400) 30%, transparent)',
              borderRight: '1px solid color-mix(in srgb, var(--amber-400) 30%, transparent)',
            }}
          >
            <Info className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--amber-400)' }} />
            <span style={{ color: 'var(--amber-400)' }}>
              Large process tree ({totalProcessesOnServer} processes). Showing top-level processes only.
              Click the expand arrow on any process to load its children on demand.
            </span>
          </div>
        )}

        {selectedAgent && hasError && (
          <div
            className="flex items-center gap-2 px-3 py-1.5 text-xs"
            style={{
              background: 'color-mix(in srgb, var(--red-400) 10%, transparent)',
              borderLeft: '1px solid color-mix(in srgb, var(--red-400) 30%, transparent)',
              borderRight: '1px solid color-mix(in srgb, var(--red-400) 30%, transparent)',
            }}
          >
            <AlertCircle className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--red-400)' }} />
            <span style={{ color: 'var(--red-400)' }}>
              {treeMeta?.error_message || 'An error occurred loading the process tree.'}
            </span>
            <button
              onClick={handleRefresh}
              className="underline ml-1"
              style={{ color: 'var(--blue-400)' }}
            >
              Retry
            </button>
          </div>
        )}

        {/* ================================================================ */}
        {/* Main content: tree + details */}
        {/* ================================================================ */}
        <div
          className="flex flex-1 min-h-0 rounded-b-xl overflow-hidden"
          style={{
            borderLeft: '1px solid var(--hairline)',
            borderRight: '1px solid var(--hairline)',
            borderBottom: '1px solid var(--hairline)',
          }}
        >
          {/* Left: Process Tree */}
          <div className="flex-1 flex flex-col min-w-0" style={{ background: 'var(--bg)' }}>
            {!selectedAgent ? (
              <div className="flex flex-col items-center justify-center flex-1" style={{ color: 'var(--muted)' }}>
                <Monitor className="h-14 w-14 mb-3 opacity-30" />
                <p className="text-sm font-medium">Select an Agent</p>
                <p className="text-xs mt-1 opacity-60">Choose an endpoint to inspect its process tree</p>
              </div>
            ) : hasError && (!processTree || processTree.length === 0) ? (
              <div className="flex flex-col items-center justify-center flex-1" style={{ color: 'var(--muted)' }}>
                <AlertCircle className="h-14 w-14 mb-3 opacity-40" style={{ color: 'var(--red-400)' }} />
                <p className="text-sm font-medium" style={{ color: 'var(--red-400)' }}>Failed to Load Process Tree</p>
                <p className="text-xs mt-1 max-w-sm text-center" style={{ color: 'var(--muted)' }}>
                  {treeMeta?.error_message || 'The process tree could not be loaded. This may happen when the agent has a very large number of processes.'}
                </p>
                <button
                  onClick={handleRefresh}
                  className="mt-3 flex items-center gap-1.5 rounded-lg px-4 py-2 text-xs text-white font-medium transition-colors"
                  style={{ background: 'var(--blue-500)' }}
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                  Try Again
                </button>
              </div>
            ) : (
              <ProcessTreeViewer
                processes={filteredProcesses}
                onSelectProcess={handleProcessSelect}
                selectedPid={selectedProcess?.pid}
                focusPid={focusPid}
                agentId={selectedAgent?.id}
                onLoadChildren={handleLoadChildren}
              />
            )}
          </div>

          {/* Right: Details panel */}
          {!detailsCollapsed && (
            <div
              className="w-[380px] flex flex-col shrink-0"
              style={{
                borderLeft: '1px solid var(--hairline)',
                background: 'var(--surface)',
              }}
            >
              {/* Panel header */}
              <div
                className="flex items-center justify-between px-3 py-2"
                style={{
                  borderBottom: '1px solid var(--hairline)',
                  background: 'var(--surface)',
                }}
              >
                <span className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--muted)' }}>
                  Process Details
                </span>
                <button
                  onClick={() => setDetailsCollapsed(true)}
                  className="p-1 rounded hover:opacity-70"
                  style={{ background: 'var(--bg)' }}
                  title="Collapse panel"
                >
                  <ChevronUp className="h-3.5 w-3.5 rotate-90" style={{ color: 'var(--muted)' }} />
                </button>
              </div>

              {/* Quick actions */}
              {selectedProcess && selectedAgent && (
                <div
                  className="px-3 py-2"
                  style={{
                    borderBottom: '1px solid var(--hairline)',
                    background: 'var(--bg)',
                  }}
                >
                  <div className="grid grid-cols-2 gap-1.5">
                    <ActionButton
                      onClick={() => router.visit(`/app/investigation/${selectedProcess.pid}?type=process&agent_id=${selectedAgent.id}`)}
                      icon={Share2}
                      label="View Graph"
                      color="blue"
                    />
                    <ActionButton
                      onClick={() => router.visit(`/app/network?agent_id=${selectedAgent.id}&pid=${selectedProcess.pid}`)}
                      icon={Globe}
                      label="Network"
                      color="emerald"
                    />
                    <ActionButton
                      onClick={() => router.visit(`/app/hunt?q=pid:${selectedProcess.pid}`)}
                      icon={Search}
                      label="Hunt PID"
                      color="orange"
                    />
                    {selectedProcess.sha256 && (
                      <ActionButton
                        onClick={() => router.visit(`/app/hunt?q=sha256:${selectedProcess.sha256}`)}
                        icon={File}
                        label="Hunt Hash"
                        color="purple"
                      />
                    )}
                  </div>
                </div>
              )}

              {/* Details */}
              <div className="flex-1 overflow-auto p-3">
                <ProcessDetailsPanel process={selectedProcess} />
              </div>
            </div>
          )}

          {/* Collapsed details toggle */}
          {detailsCollapsed && (
            <button
              onClick={() => setDetailsCollapsed(false)}
              className="w-8 flex items-center justify-center transition-colors hover:opacity-70"
              style={{
                borderLeft: '1px solid var(--hairline)',
                background: 'var(--surface)',
              }}
              title="Show details panel"
            >
              <ChevronDown className="h-4 w-4 -rotate-90" style={{ color: 'var(--muted)' }} />
            </button>
          )}
        </div>
      </div>
    </MainLayout>
  )
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function ActionButton({ onClick, icon: Icon, label, color }: {
  onClick: () => void
  icon: React.ElementType
  label: string
  color: string
}) {
  const colorVars: Record<string, { bg: string; border: string; text: string }> = {
    blue: {
      bg: 'color-mix(in srgb, var(--blue-400) 15%, transparent)',
      border: 'color-mix(in srgb, var(--blue-400) 20%, transparent)',
      text: 'var(--blue-400)',
    },
    emerald: {
      bg: 'color-mix(in srgb, var(--emerald-400) 15%, transparent)',
      border: 'color-mix(in srgb, var(--emerald-400) 20%, transparent)',
      text: 'var(--emerald-400)',
    },
    orange: {
      bg: 'color-mix(in srgb, var(--orange-400) 15%, transparent)',
      border: 'color-mix(in srgb, var(--orange-400) 20%, transparent)',
      text: 'var(--orange-400)',
    },
    purple: {
      bg: 'color-mix(in srgb, var(--purple-400) 15%, transparent)',
      border: 'color-mix(in srgb, var(--purple-400) 20%, transparent)',
      text: 'var(--purple-400)',
    },
  }

  const colors = colorVars[color] || colorVars.blue

  return (
    <button
      onClick={onClick}
      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-xs font-medium transition-colors hover:opacity-80"
      style={{
        background: colors.bg,
        border: `1px solid ${colors.border}`,
        color: colors.text,
      }}
    >
      <Icon className="h-3 w-3" />
      {label}
    </button>
  )
}
