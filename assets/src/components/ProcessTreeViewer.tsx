import { useState, useEffect, useRef, useCallback } from 'react'
import {
  ChevronRight,
  ChevronDown,
  AlertTriangle,
  Shield,
  ShieldCheck,
  ShieldOff,
  User,
  Clock,
  Terminal,
  FileCode,
  Cpu,
  Monitor,
  Cog,
  MemoryStick,
  Copy,
  Check,
  Package,
  Building2,
  Lock,
  Loader2,
} from 'lucide-react'
import { cn, formatRelativeTime, formatBytes } from '@/lib/utils'
import type { ProcessNode, Detection } from '@/types'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Derive a readable display name - never return "unknown" */
function displayName(node: ProcessNode): { primary: string; italic: boolean } {
  if (node.name && node.name !== '' && !node.name.startsWith('Process_')) {
    return { primary: node.name, italic: false }
  }
  if (node.path) {
    const segments = node.path.replace(/\\/g, '/').split('/')
    const last = segments[segments.length - 1]
    if (last) return { primary: last, italic: false }
  }
  return { primary: `System Process (PID: ${node.pid})`, italic: true }
}

/** Classify process type for icon/color */
type ProcessType = 'system' | 'service' | 'elevated' | 'user' | 'suspicious'

function classifyProcess(node: ProcessNode): ProcessType {
  const hasDetections = (node.detections?.length ?? 0) > 0
  if (hasDetections) return 'suspicious'

  const nameLower = (node.name || '').toLowerCase()
  const pathLower = (node.path || '').toLowerCase()

  // System processes
  const systemNames = ['system', 'idle', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'winlogon.exe', 'lsass.exe', 'services.exe', 'ntoskrnl', 'kernel_task',
    'launchd', 'systemd', 'init', 'kthreadd']
  if (systemNames.some(s => nameLower.includes(s)) || node.pid <= 4) {
    return 'system'
  }

  // Services
  const serviceNames = ['svchost.exe', 'spoolsv.exe', 'wuauserv', 'dllhost.exe',
    'taskhost.exe', 'msdtc.exe', 'searchindexer', 'wmiprvse.exe']
  const servicePaths = ['system32', '/usr/sbin', '/usr/libexec']
  if (serviceNames.some(s => nameLower.includes(s)) ||
      servicePaths.some(s => pathLower.includes(s))) {
    return 'service'
  }

  if (node.isElevated) return 'elevated'
  return 'user'
}

const processTypeConfig: Record<ProcessType, { icon: React.ElementType; color: string; bgColor: string }> = {
  system:     { icon: Monitor,       color: 'text-blue-400',    bgColor: 'bg-blue-500/15' },
  service:    { icon: Cog,           color: 'text-slate-400',   bgColor: 'bg-slate-600/30' },
  elevated:   { icon: Shield,        color: 'text-amber-400',   bgColor: 'bg-amber-500/15' },
  user:       { icon: User,          color: 'text-slate-300',   bgColor: 'bg-slate-700/50' },
  suspicious: { icon: AlertTriangle, color: 'text-red-400',     bgColor: 'bg-red-500/15' },
}

/** CPU bar color class */
function cpuColor(pct: number): string {
  if (pct > 30) return 'bg-red-500'
  if (pct > 5)  return 'bg-yellow-500'
  return 'bg-emerald-500'
}

/** Entropy interpretation */
function entropyLabel(e: number): { text: string; color: string } {
  if (e >= 7.2) return { text: 'Packed / encrypted', color: 'text-red-400' }
  if (e >= 6.5) return { text: 'Suspicious',         color: 'text-amber-400' }
  return { text: 'Normal', color: 'text-emerald-400' }
}

/** Check if a PID exists anywhere in a subtree */
function subtreeContainsPid(node: ProcessNode, pid: number): boolean {
  if (node.pid === pid) return true
  return node.children?.some(child => subtreeContainsPid(child, pid)) ?? false
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface ProcessTreeViewerProps {
  processes: ProcessNode[]
  onSelectProcess?: (process: ProcessNode) => void
  selectedPid?: number
  focusPid?: number
  agentId?: string
  onLoadChildren?: (agentId: string, pid: number) => Promise<ProcessNode[]>
}

interface ProcessNodeProps {
  node: ProcessNode
  depth: number
  onSelect?: (node: ProcessNode) => void
  selectedPid?: number
  focusPid?: number
  isLast: boolean
  parentLines: boolean[]  // which ancestor columns need a vertical connector
  agentId?: string
  onLoadChildren?: (agentId: string, pid: number) => Promise<ProcessNode[]>
}

// ---------------------------------------------------------------------------
// ProcessNodeItem -- a single row in the tree
// ---------------------------------------------------------------------------

function ProcessNodeItem({ node, depth, onSelect, selectedPid, focusPid, isLast, parentLines, agentId, onLoadChildren }: ProcessNodeProps) {
  const hasLoadedChildren = (node.children?.length ?? 0) > 0
  const hasRemoteChildren = (node.childCount ?? 0) > 0
  const hasChildren = hasLoadedChildren || hasRemoteChildren
  const hasDetections = (node.detections?.length ?? 0) > 0
  const detectionCount = node.detections?.length ?? 0
  const isSelected = selectedPid === node.pid
  const isFocused = focusPid === node.pid
  const nodeRef = useRef<HTMLDivElement>(null)
  const [lazyChildren, setLazyChildren] = useState<ProcessNode[]>([])
  const [isLoadingChildren, setIsLoadingChildren] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)

  // Effective children: loaded from server or already in the tree
  const effectiveChildren = hasLoadedChildren ? node.children : lazyChildren
  const hasEffectiveChildren = effectiveChildren.length > 0

  const shouldAutoExpand = focusPid !== undefined && hasLoadedChildren && node.pid !== focusPid &&
    node.children.some(child => subtreeContainsPid(child, focusPid))
  const [expanded, setExpanded] = useState(depth < 2 || shouldAutoExpand)

  useEffect(() => {
    if (focusPid !== undefined && hasLoadedChildren && node.pid !== focusPid &&
        node.children.some(child => subtreeContainsPid(child, focusPid))) {
      setExpanded(true)
    }
  }, [focusPid, node, hasLoadedChildren])

  useEffect(() => {
    if (isFocused && nodeRef.current) {
      nodeRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  }, [isFocused])

  // Lazy-load children when expanding a node that has remote children but no loaded children
  const handleToggleExpand = useCallback(async () => {
    const willExpand = !expanded
    setExpanded(willExpand)

    if (willExpand && hasRemoteChildren && !hasLoadedChildren && lazyChildren.length === 0 && onLoadChildren && agentId) {
      setIsLoadingChildren(true)
      setLoadError(null)
      try {
        const children = await onLoadChildren(agentId, node.pid)
        setLazyChildren(children)
      } catch (err) {
        setLoadError('Failed to load children')
      } finally {
        setIsLoadingChildren(false)
      }
    }
  }, [expanded, hasRemoteChildren, hasLoadedChildren, lazyChildren.length, onLoadChildren, agentId, node.pid])

  const pType = classifyProcess(node)
  const { icon: TypeIcon, color: typeColor, bgColor: typeBg } = processTypeConfig[pType]
  const { primary: nameText, italic: nameItalic } = displayName(node)

  // Row index for alternating background
  const rowEven = node.pid % 2 === 0

  return (
    <div className="select-none">
      {/* The row */}
      <div
        ref={nodeRef}
        className={cn(
          'group flex items-center h-[30px] cursor-pointer transition-colors text-[13px] leading-none border-l-2',
          isSelected
            ? 'bg-blue-600/20 border-l-blue-500'
            : isFocused
              ? 'bg-blue-500/10 border-l-blue-400 ring-1 ring-inset ring-blue-500/30'
              : hasDetections
                ? 'border-l-red-500/70 hover:bg-slate-700/60'
                : rowEven
                  ? 'border-l-transparent hover:bg-slate-700/40'
                  : 'border-l-transparent bg-slate-800/30 hover:bg-slate-700/40'
        )}
        onClick={() => onSelect?.(node)}
      >
        {/* Tree guide lines + expand toggle */}
        <div className="flex items-center shrink-0" style={{ width: `${depth * 18 + 28}px` }}>
          {/* Indentation guide lines */}
          {parentLines.map((showLine, idx) => (
            <span
              key={idx}
              className="inline-block w-[18px] h-[30px] relative shrink-0"
            >
              {showLine && (
                <span className="absolute left-[8px] top-0 bottom-0 w-px bg-slate-700/60" />
              )}
            </span>
          ))}

          {/* Current connector */}
          {depth > 0 && (
            <span className="inline-block w-[18px] h-[30px] relative shrink-0">
              {/* Vertical line from top (always, or half if last) */}
              <span className={cn(
                'absolute left-[8px] w-px bg-slate-700/60',
                isLast ? 'top-0 h-[15px]' : 'top-0 bottom-0'
              )} />
              {/* Horizontal branch */}
              <span className="absolute left-[8px] top-[14px] w-[9px] h-px bg-slate-700/60" />
            </span>
          )}

          {/* Expand/collapse */}
          <button
            onClick={(e) => { e.stopPropagation(); handleToggleExpand() }}
            className={cn(
              'flex items-center justify-center w-[16px] h-[16px] rounded shrink-0',
              hasChildren ? 'hover:bg-slate-600/60' : ''
            )}
          >
            {isLoadingChildren ? (
              <Loader2 className="h-3.5 w-3.5 text-blue-400 animate-spin" />
            ) : hasChildren ? (
              expanded
                ? <ChevronDown className="h-3.5 w-3.5 text-slate-400" />
                : <ChevronRight className="h-3.5 w-3.5 text-slate-400" />
            ) : (
              <span className="w-3.5" />
            )}
          </button>
        </div>

        {/* Icon */}
        <div className={cn('flex items-center justify-center w-5 h-5 rounded shrink-0 mr-1.5', typeBg)}>
          <TypeIcon className={cn('h-3.5 w-3.5', typeColor)} />
        </div>

        {/* Name + file description */}
        <div className="flex items-center gap-1.5 min-w-0 mr-2 flex-shrink" style={{ minWidth: '120px', maxWidth: '260px' }}>
          <span className={cn(
            'font-semibold truncate',
            nameItalic && 'italic',
            hasDetections ? 'text-red-300' : 'text-slate-100'
          )}>
            {nameText}
          </span>
          {node.fileDescription && (
            <span className="text-[11px] text-slate-500 truncate hidden group-hover:inline lg:inline">
              {node.fileDescription}
            </span>
          )}
        </div>

        {/* PID */}
        <span className="text-[11px] text-slate-500 font-mono w-[60px] shrink-0 text-right mr-3">
          {node.pid}
        </span>

        {/* Company name */}
        <span className="text-[11px] text-slate-500 truncate w-[110px] shrink-0 mr-2 hidden xl:block">
          {node.companyName || ''}
        </span>

        {/* CPU bar */}
        <div className="w-[56px] shrink-0 mr-2 flex items-center gap-1">
          {node.cpuUsage != null ? (
            <>
              <div className="flex-1 h-[4px] bg-slate-700/60 rounded-full overflow-hidden">
                <div
                  className={cn('h-full rounded-full', cpuColor(node.cpuUsage))}
                  style={{ width: `${Math.min(node.cpuUsage, 100)}%` }}
                />
              </div>
              <span className="text-[10px] text-slate-400 font-mono w-[28px] text-right">
                {node.cpuUsage.toFixed(0)}%
              </span>
            </>
          ) : (
            <span className="text-[10px] text-slate-600 font-mono">--</span>
          )}
        </div>

        {/* Memory */}
        <span className="text-[11px] text-slate-400 font-mono w-[64px] shrink-0 text-right mr-2">
          {node.memoryBytes != null ? formatBytes(node.memoryBytes, 1) : '--'}
        </span>

        {/* User */}
        <span className="text-[11px] text-slate-400 truncate w-[80px] shrink-0 mr-2 hidden lg:block">
          {node.user || ''}
        </span>

        {/* Badges */}
        <div className="flex items-center gap-1 ml-auto shrink-0 pr-2">
          {/* Child count badge for unexpanded nodes with remote children */}
          {hasRemoteChildren && !hasLoadedChildren && lazyChildren.length === 0 && (
            <span className="text-[10px] bg-slate-600/40 text-slate-400 px-1.5 py-px rounded font-mono leading-tight"
                  title={`${node.childCount} child processes`}>
              +{node.childCount}
            </span>
          )}
          {node.isElevated && (
            <span className="text-[10px] bg-amber-500/20 text-amber-400 px-1.5 py-px rounded font-medium leading-tight">
              ELEVATED
            </span>
          )}
          {node.isSigned ? (
            <span
              className="inline-flex items-center gap-0.5"
              title={node.signer ? `Signed: ${node.signer}` : 'Signed'}
            >
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" />
            </span>
          ) : (
            <span className="text-[10px] bg-red-500/15 text-red-400 px-1.5 py-px rounded font-medium leading-tight"
                  title="Binary is not digitally signed">
              UNSIGNED
            </span>
          )}
          {detectionCount > 0 && (
            <span className="text-[10px] bg-red-600/25 text-red-300 px-1.5 py-px rounded font-bold leading-tight">
              {detectionCount}
            </span>
          )}
        </div>
      </div>

      {/* Children */}
      {expanded && hasEffectiveChildren && (
        <div>
          {effectiveChildren.map((child, idx) => (
            <ProcessNodeItem
              key={child.pid}
              node={child}
              depth={depth + 1}
              onSelect={onSelect}
              selectedPid={selectedPid}
              focusPid={focusPid}
              isLast={idx === effectiveChildren.length - 1}
              parentLines={[...parentLines, !isLast]}
              agentId={agentId}
              onLoadChildren={onLoadChildren}
            />
          ))}
        </div>
      )}

      {/* Loading indicator for lazy children */}
      {expanded && isLoadingChildren && (
        <div className="flex items-center gap-2 pl-8 py-1.5" style={{ paddingLeft: `${(depth + 1) * 18 + 28 + 8}px` }}>
          <Loader2 className="h-3.5 w-3.5 text-blue-400 animate-spin" />
          <span className="text-xs text-slate-500">Loading child processes...</span>
        </div>
      )}

      {/* Error loading children */}
      {expanded && loadError && (
        <div className="flex items-center gap-2 pl-8 py-1.5" style={{ paddingLeft: `${(depth + 1) * 18 + 28 + 8}px` }}>
          <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
          <span className="text-xs text-red-400">{loadError}</span>
          <button
            onClick={(e) => { e.stopPropagation(); handleToggleExpand() }}
            className="text-xs text-blue-400 hover:text-blue-300 underline"
          >
            Retry
          </button>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Column header for the tree table
// ---------------------------------------------------------------------------

function TreeHeader() {
  return (
    <div className="flex items-center h-[26px] text-[11px] font-semibold text-slate-500 uppercase tracking-wider border-b border-slate-700/80 bg-slate-800/80 sticky top-0 z-10 px-1">
      <span className="flex-shrink" style={{ minWidth: '120px', maxWidth: '260px', marginLeft: '46px' }}>
        Process
      </span>
      <span className="w-[60px] shrink-0 text-right mr-3">PID</span>
      <span className="w-[110px] shrink-0 mr-2 hidden xl:block">Company</span>
      <span className="w-[56px] shrink-0 mr-2">CPU</span>
      <span className="w-[64px] shrink-0 text-right mr-2">Memory</span>
      <span className="w-[80px] shrink-0 mr-2 hidden lg:block">User</span>
      <span className="ml-auto pr-2">Status</span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// ProcessTreeViewer (exported)
// ---------------------------------------------------------------------------

export function ProcessTreeViewer({ processes, onSelectProcess, selectedPid, focusPid, agentId, onLoadChildren }: ProcessTreeViewerProps) {
  if (!processes || processes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-slate-500">
        <Cpu className="h-12 w-12 mb-4 opacity-40" />
        <p className="text-sm font-medium">No processes found</p>
        <p className="text-xs mt-1">Select an agent to view the process tree</p>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      <TreeHeader />
      <div className="flex-1 overflow-auto">
        {processes.map((process, idx) => (
          <ProcessNodeItem
            key={process.pid}
            node={process}
            depth={0}
            onSelect={onSelectProcess}
            selectedPid={selectedPid}
            focusPid={focusPid}
            isLast={idx === processes.length - 1}
            parentLines={[]}
            agentId={agentId}
            onLoadChildren={onLoadChildren}
          />
        ))}
      </div>
    </div>
  )
}


// ===========================================================================
// Process Details Panel
// ===========================================================================

interface ProcessDetailsPanelProps {
  process: ProcessNode | null
}

export function ProcessDetailsPanel({ process }: ProcessDetailsPanelProps) {
  if (!process) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-500">
        <FileCode className="h-10 w-10 mb-3 opacity-40" />
        <p className="text-sm font-medium">Select a process</p>
        <p className="text-xs mt-1">Click a row to view details</p>
      </div>
    )
  }

  const pType = classifyProcess(process)
  const { icon: TypeIcon, color: typeColor, bgColor: typeBg } = processTypeConfig[pType]
  const { primary: nameText, italic: nameItalic } = displayName(process)

  return (
    <div className="space-y-4 text-[13px]">
      {/* ---- Header ---- */}
      <div className="flex items-start gap-3 pb-3 border-b border-slate-700/70">
        <div className={cn('p-2.5 rounded-lg shrink-0', typeBg)}>
          <TypeIcon className={cn('h-6 w-6', typeColor)} />
        </div>
        <div className="min-w-0">
          <h3 className={cn(
            'text-base font-bold text-white truncate',
            nameItalic && 'italic'
          )}>
            {nameText}
          </h3>
          {process.fileDescription && (
            <p className="text-xs text-slate-400 mt-0.5 truncate">{process.fileDescription}</p>
          )}
          {process.path && (
            <p className="text-xs text-slate-500 mt-0.5 truncate font-mono">{process.path}</p>
          )}
        </div>
      </div>

      {/* ---- Info Grid ---- */}
      <div className="grid grid-cols-2 gap-x-3 gap-y-2">
        <GridItem label="PID" value={String(process.pid)} mono />
        <GridItem label="Parent PID" value={String(process.ppid)} mono />
        <GridItem label="User" value={process.user || 'Unknown'} icon={User} />
        <GridItem label="Started" value={formatRelativeTime(process.startTime)} subValue={process.startTime ? new Date(process.startTime).toLocaleString() : undefined} icon={Clock} />

        {/* CPU */}
        {process.cpuUsage != null && (
          <div className="col-span-2">
            <DetailLabel>CPU Usage</DetailLabel>
            <div className="flex items-center gap-2 mt-0.5">
              <div className="flex-1 h-[6px] bg-slate-700/60 rounded-full overflow-hidden">
                <div
                  className={cn('h-full rounded-full transition-all', cpuColor(process.cpuUsage))}
                  style={{ width: `${Math.min(process.cpuUsage, 100)}%` }}
                />
              </div>
              <span className="text-xs text-slate-300 font-mono w-10 text-right">
                {process.cpuUsage.toFixed(1)}%
              </span>
            </div>
          </div>
        )}

        {/* Memory */}
        {process.memoryBytes != null && (
          <GridItem label="Memory" value={formatBytes(process.memoryBytes)} icon={MemoryStick} />
        )}

        {/* PE Metadata */}
        {process.companyName && (
          <GridItem label="Company" value={process.companyName} icon={Building2} />
        )}
        {process.productName && (
          <GridItem label="Product" value={process.productName} icon={Package} />
        )}
        {process.fileVersion && (
          <GridItem label="Version" value={process.fileVersion} />
        )}

        {/* Signed */}
        <div>
          <DetailLabel>Signed</DetailLabel>
          <div className="flex items-center gap-1.5 mt-0.5">
            {process.isSigned ? (
              <>
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-500 shrink-0" />
                <span className="text-emerald-400 text-xs truncate">{process.signer || 'Yes'}</span>
              </>
            ) : (
              <>
                <ShieldOff className="h-3.5 w-3.5 text-red-400 shrink-0" />
                <span className="text-red-400 text-xs">Unsigned</span>
              </>
            )}
          </div>
        </div>

        {/* Elevated */}
        <div>
          <DetailLabel>Elevated</DetailLabel>
          <div className="flex items-center gap-1.5 mt-0.5">
            {process.isElevated ? (
              <>
                <Lock className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                <span className="text-amber-400 text-xs">Yes (Admin)</span>
              </>
            ) : (
              <span className="text-slate-400 text-xs">No</span>
            )}
          </div>
        </div>

        {/* Entropy */}
        {process.entropy != null && (
          <div className="col-span-2">
            <DetailLabel>Entropy</DetailLabel>
            <div className="flex items-center gap-2 mt-0.5">
              <div className="flex-1 h-[6px] bg-slate-700/60 rounded-full overflow-hidden">
                <div
                  className={cn(
                    'h-full rounded-full',
                    process.entropy >= 7.2 ? 'bg-red-500' : process.entropy >= 6.5 ? 'bg-amber-500' : 'bg-emerald-500'
                  )}
                  style={{ width: `${(process.entropy / 8) * 100}%` }}
                />
              </div>
              <span className="text-xs text-slate-300 font-mono w-8 text-right">
                {process.entropy.toFixed(2)}
              </span>
              <span className={cn('text-[10px]', entropyLabel(process.entropy).color)}>
                {entropyLabel(process.entropy).text}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* ---- Command Line ---- */}
      <div>
        <DetailLabel>Command Line</DetailLabel>
        <CopyableCommandLine value={process.cmdline} />
      </div>

      {/* ---- Full Path ---- */}
      {process.path && (
        <div>
          <DetailLabel>Full Path</DetailLabel>
          <div className="mt-1 p-2 bg-slate-900/80 rounded border border-slate-700/50 font-mono text-xs text-slate-400 break-all">
            {process.path}
          </div>
        </div>
      )}

      {/* ---- SHA256 ---- */}
      {process.sha256 && (
        <div>
          <DetailLabel>SHA256</DetailLabel>
          <CopyableHash hash={process.sha256} />
        </div>
      )}

      {/* ---- Detections ---- */}
      {process.detections && process.detections.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
            <DetailLabel>Detections ({process.detections.length})</DetailLabel>
          </div>
          <div className="space-y-2">
            {process.detections.map((detection, idx) => (
              <DetectionCard key={idx} detection={detection} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Sub-components used by the details panel
// ---------------------------------------------------------------------------

function DetailLabel({ children }: { children: React.ReactNode }) {
  return (
    <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
      {children}
    </p>
  )
}

function GridItem({ label, value, subValue, mono, icon: Icon }: {
  label: string
  value: string
  subValue?: string
  mono?: boolean
  icon?: React.ElementType
}) {
  return (
    <div className="p-2 bg-slate-800/60 rounded border border-slate-700/30">
      <DetailLabel>{label}</DetailLabel>
      <div className="flex items-center gap-1.5 mt-0.5">
        {Icon && <Icon className="h-3.5 w-3.5 text-slate-500 shrink-0" />}
        <span className={cn('text-xs text-slate-200 truncate', mono && 'font-mono')}>
          {value}
        </span>
      </div>
      {subValue && (
        <p className="text-[10px] text-slate-500 mt-0.5 truncate">{subValue}</p>
      )}
    </div>
  )
}

function CopyableHash({ hash }: { hash: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(hash).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }, [hash])

  return (
    <div
      className="mt-1 p-2 bg-slate-900/80 rounded border border-slate-700/50 font-mono text-[11px] text-slate-400 break-all flex items-start gap-2 cursor-pointer hover:border-slate-600/60 transition-colors group"
      onClick={handleCopy}
      title="Click to copy"
    >
      <span className="flex-1">{hash}</span>
      {copied ? (
        <Check className="h-3.5 w-3.5 text-emerald-400 shrink-0 mt-px" />
      ) : (
        <Copy className="h-3.5 w-3.5 text-slate-500 shrink-0 mt-px opacity-0 group-hover:opacity-100 transition-opacity" />
      )}
    </div>
  )
}

function CopyableCommandLine({ value }: { value?: string | null }) {
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)
  const command = (value || '').trim()
  const shouldCollapse = command.length > 260 || command.split(/\r?\n/).length > 3
  const visible = !shouldCollapse || expanded ? command : `${command.slice(0, 260).trimEnd()}...`

  const handleCopy = useCallback(() => {
    if (!command) return
    navigator.clipboard.writeText(command).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }, [command])

  if (!command) {
    return (
      <div className="mt-1 p-2 bg-slate-900/80 rounded border border-slate-700/50 text-xs text-slate-500">
        N/A
      </div>
    )
  }

  return (
    <div className="mt-1">
      <div className="p-2 bg-slate-900/80 rounded border border-slate-700/50 font-mono text-xs text-slate-300 whitespace-pre-wrap overflow-auto max-h-32 [overflow-wrap:anywhere] [word-break:normal]">
        <Terminal className="h-3.5 w-3.5 inline mr-1.5 text-slate-500 relative -top-px" />
        {visible}
      </div>
      <div className="mt-1 flex items-center gap-2">
        {shouldCollapse && (
          <button
            type="button"
            onClick={() => setExpanded(current => !current)}
            className="inline-flex items-center gap-1 text-[11px] text-cyan-300 hover:text-cyan-200"
          >
            {expanded ? <ChevronDown className="h-3 w-3 rotate-180" /> : <ChevronDown className="h-3 w-3" />}
            {expanded ? 'View less' : 'View more'}
          </button>
        )}
        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200"
        >
          {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
    </div>
  )
}

function DetectionCard({ detection }: { detection: Detection }) {
  const confidencePct = typeof detection.confidence === 'number'
    ? `${Math.round(detection.confidence * 100)}%`
    : null

  return (
    <div className="p-2.5 bg-red-900/15 border border-red-800/40 rounded">
      <div className="flex items-center justify-between mb-1.5">
        <span className="font-semibold text-xs text-red-300 truncate">{detection.ruleName}</span>
        <span className="text-[10px] bg-red-500/20 text-red-400 px-1.5 py-px rounded font-medium shrink-0 ml-2">
          {detection.type.toUpperCase()}
        </span>
      </div>
      <p className="text-xs text-slate-400 mb-1.5 leading-relaxed">{detection.description}</p>
      <div className="flex items-center gap-2 flex-wrap">
        {confidencePct && (
          <span className="text-[10px] bg-slate-700/60 text-slate-300 px-1.5 py-px rounded">
            Confidence: {confidencePct}
          </span>
        )}
        {detection.mitreTechniques.map((tech) => (
          <span
            key={tech}
            className="text-[10px] bg-slate-700/60 text-slate-300 px-1.5 py-px rounded"
          >
            {tech}
          </span>
        ))}
      </div>
    </div>
  )
}
