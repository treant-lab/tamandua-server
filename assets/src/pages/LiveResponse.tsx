/**
 * Live Response Page
 *
 * Interactive terminal session management for incident response.
 *
 * Features:
 * - Agent selector with status
 * - Terminal window with xterm.js
 * - Quick action buttons (common forensic commands)
 * - File browser integration with preview
 * - Session history and recordings
 * - Multi-session support (tabs)
 * - Session sharing
 * - Export functionality
 * - Supervisor approval mode
 */

import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import type { TerminalRef } from '@/components/Terminal'
import { useState, useRef, useCallback, useEffect, lazy, Suspense, type FormEvent } from 'react'

const Terminal = lazy(() => import('@/components/Terminal').then(m => ({ default: m.Terminal })))
import {
  Terminal as TerminalIcon,
  Monitor,
  ChevronDown,
  ChevronRight,
  Search,
  Activity,
  Network,
  FolderOpen,
  Hash,
  ClipboardList,
  Cpu,
  History,
  Play,
  X,
  Plus,
  User,
  Download,
  FileText,
  Shield,
  Loader2,
  Eye,
  Share2,
  Save,
  File,
  FileCode,
  FileImage,
  Archive,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Users,
  Database,
  RefreshCw,
  Settings,
  Pencil,
} from 'lucide-react'
import { cn, formatDate, formatBytes } from '@/lib/utils'
import { toast } from 'sonner'
import { Dialog, DialogFooter } from '@/components/ui/baseui'
import axios from 'axios'

// ============================================================================
// Types
// ============================================================================

interface Agent {
  id: string
  hostname: string
  status: string
  os_type: string
  ip_address?: string
  last_seen: string
  agent_version?: string
}

interface ShellSession {
  id: string
  session_id: string
  agent_id: string
  agent_hostname: string
  user_id: string
  user_email?: string
  started_at: string
  ended_at?: string
  status: string
  has_recording: boolean
}

interface Recording {
  session_id: string
  agent_id: string
  path: string
  size: number
  created_at: string
}

interface LiveResponseProps {
  agents?: Agent[]
  recentSessions?: ShellSession[]
  recordings?: Recording[]
  selectedAgent?: Agent
  agentId?: string
  builtinCommands?: BuiltinCommand[]
}

interface TabSession {
  id: string
  agentId: string
  hostname: string
  osType?: string
  title?: string
  sessionId: string | null
  status: 'connecting' | 'connected' | 'disconnected' | 'error'
  waitingForOutput?: boolean
  viewOnly?: boolean
}

interface FileEntry {
  name: string
  path: string
  is_directory: boolean
  size: number
  modified: number
  readonly: boolean
  permissions?: string
}

interface PendingApproval {
  command_id: string
  command: string
  reason: string
  requested_at: string
}

interface ActiveSession {
  session_id: string
  user_email?: string
  view_only: boolean
  joined_at: string
}

interface MobileCommandRecord {
  id: string
  command_type: string
  status: string
  payload?: Record<string, unknown>
  result?: Record<string, unknown>
  inserted_at?: string
  completed_at?: string
}

interface MobileOverviewPayload {
  linked?: boolean
  link_status?: {
    reason?: string
    expected_identifiers?: string[]
    remediation?: string
  }
  device?: {
    id?: string
    device_id?: string
  } | null
  command_device?: {
    id?: string
    device_id?: string
    platform?: string
    status?: string
  } | null
  command_identity?: {
    command_device_id?: string
    external_device_id?: string
    agent_machine_id?: string
    background_sync_device_id?: string
  } | null
  command_history?: MobileCommandRecord[]
}

function mobileOverviewCommandDeviceId(overview?: MobileOverviewPayload | null): string {
  return String(
    overview?.command_identity?.command_device_id ||
      overview?.command_device?.id ||
      overview?.command_device?.device_id ||
      overview?.command_identity?.background_sync_device_id ||
      overview?.device?.id ||
      overview?.device?.device_id ||
      ''
  ).trim()
}

function TerminalLoadingFallback() {
  return (
    <div className="h-full flex items-center justify-center" style={{ backgroundColor: 'var(--bg)' }}>
      <div className="flex items-center gap-3" style={{ color: 'var(--muted)' }}>
        <Loader2 className="h-5 w-5 animate-spin" style={{ color: 'var(--emerald-400)' }} />
        <span className="text-sm">Starting terminal session...</span>
      </div>
    </div>
  )
}

// ============================================================================
// Quick Actions / Built-in Commands
// ============================================================================

interface BuiltinCommand {
  id: string
  name: string
  icon: React.ComponentType<{ className?: string }>
  command: string
  args?: string[]
  description: string
  category: string
}

const quickActions: BuiltinCommand[] = [
  {
    id: 'ps',
    name: 'Process List',
    icon: Activity,
    command: 'ps',
    description: 'List all running processes',
    category: 'Process',
  },
  {
    id: 'netstat',
    name: 'Network',
    icon: Network,
    command: 'netstat',
    description: 'Show network connections',
    category: 'Network',
  },
  {
    id: 'autoruns',
    name: 'Autoruns',
    icon: Play,
    command: 'autoruns',
    description: 'List persistence mechanisms',
    category: 'System',
  },
  {
    id: 'services',
    name: 'Services',
    icon: Cpu,
    command: 'services',
    description: 'List system services',
    category: 'System',
  },
  {
    id: 'tasks',
    name: 'Tasks',
    icon: ClipboardList,
    command: 'tasks',
    description: 'List scheduled tasks',
    category: 'System',
  },
  {
    id: 'dns',
    name: 'DNS Cache',
    icon: Search,
    command: 'dns',
    description: 'Show DNS cache entries',
    category: 'Network',
  },
  {
    id: 'history',
    name: 'History',
    icon: History,
    command: 'history',
    description: 'Show command history',
    category: 'Session',
  },
  {
    id: 'help',
    name: 'Help',
    icon: FileText,
    command: 'help',
    description: 'Show available commands',
    category: 'Session',
  },
]

const LIVE_RESPONSE_TABS_KEY = 'tamandua.liveResponse.tabs.v1'

function canStartLiveResponse(agent: Agent | null | undefined): boolean {
  if (isMobileAgent(agent)) return mobileCanStart(agent)
  return agent?.status === 'online' || agent?.status === 'degraded'
}

function liveResponseStatusLabel(agent: Agent | null | undefined): string {
  if (!agent) return 'Select an agent'
  if (isMobileAgent(agent)) return 'Mobile live response uses managed queued endpoint commands; shell_execute is gated by privileged Android builds'
  if (agent.status === 'online') return 'Ready'
  if (agent.status === 'degraded') return 'Limited telemetry, shell may still be available'
  return 'Agent is offline'
}

function mobileCanStart(agent: Agent | null | undefined): boolean {
  return agent?.status === 'online' || agent?.status === 'degraded'
}

function isMobileAgent(agent: Agent | null | undefined): boolean {
  const os = String(agent?.os_type || '').toLowerCase()
  return os.includes('android') || os.includes('ios') || os.includes('iphone') || os.includes('ipad')
}

function isMobileTab(tab: TabSession | null | undefined): boolean {
  const os = String(tab?.osType || '').toLowerCase()
  return os.includes('android') || os.includes('ios') || os.includes('iphone') || os.includes('ipad')
}

// ============================================================================
// Sub-Components
// ============================================================================

function AgentSelector({
  agents,
  selectedAgent,
  onSelect,
}: {
  agents: Agent[]
  selectedAgent: Agent | null
  onSelect: (agent: Agent) => void
}) {
  const [isOpen, setIsOpen] = useState(false)
  const [search, setSearch] = useState('')

  const filtered = agents.filter(
    (a) =>
      a.hostname.toLowerCase().includes(search.toLowerCase()) ||
      a.id.toLowerCase().includes(search.toLowerCase()) ||
      (a.ip_address && a.ip_address.includes(search))
  )

  const onlineAgents = filtered.filter((a) => a.status === 'online')
  const degradedAgents = filtered.filter((a) => a.status === 'degraded')
  const offlineAgents = filtered.filter((a) => !canStartLiveResponse(a))

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between rounded-lg px-4 py-3 text-left transition-colors border"
        style={{
          backgroundColor: 'var(--surface)',
          borderColor: 'var(--border)',
        }}
      >
        <div className="flex items-center gap-3">
          <Monitor className="h-5 w-5" style={{ color: 'var(--muted)' }} />
          {selectedAgent ? (
            <div>
              <p className="font-medium" style={{ color: 'var(--fg)' }}>{selectedAgent.hostname}</p>
              <p className="text-xs" style={{ color: 'var(--muted)' }}>{selectedAgent.os_type}</p>
            </div>
          ) : (
            <span style={{ color: 'var(--muted)' }}>Select an agent...</span>
          )}
        </div>
        <ChevronDown
          className={cn('h-5 w-5 transition-transform', isOpen && 'rotate-180')}
          style={{ color: 'var(--muted)' }}
        />
      </button>

      {isOpen && (
        <div
          className="absolute top-full left-0 right-0 mt-2 rounded-lg shadow-xl z-50 max-h-96 overflow-hidden border"
          style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
        >
          {/* Search */}
          <div className="p-2 border-b" style={{ borderColor: 'var(--border)' }}>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search agents..."
                className="w-full rounded-lg pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-2 border"
                style={{
                  backgroundColor: 'var(--bg)',
                  borderColor: 'var(--border)',
                  color: 'var(--fg)',
                }}
                autoFocus
              />
            </div>
          </div>

          <div className="max-h-72 overflow-auto">
            {/* Online agents */}
            {onlineAgents.length > 0 && (
              <>
                <p
                  className="px-4 py-2 text-xs font-medium uppercase tracking-wider"
                  style={{ color: 'var(--muted)', backgroundColor: 'var(--surface)' }}
                >
                  Online ({onlineAgents.length})
                </p>
                {onlineAgents.map((agent) => (
                  <button
                    key={agent.id}
                    onClick={() => {
                      onSelect(agent)
                      setIsOpen(false)
                      setSearch('')
                    }}
                    className={cn(
                      'w-full flex items-center gap-3 px-4 py-3 transition-colors',
                      selectedAgent?.id === agent.id && 'bg-white/5'
                    )}
                    style={{ backgroundColor: selectedAgent?.id === agent.id ? 'var(--surface)' : 'transparent' }}
                  >
                    <div className="h-2.5 w-2.5 rounded-full animate-pulse" style={{ backgroundColor: 'var(--emerald-400)' }} />
                    <div className="flex-1 text-left">
                      <p style={{ color: 'var(--fg)' }}>{agent.hostname}</p>
                      <p className="text-xs" style={{ color: 'var(--muted)' }}>
                        {agent.os_type} {agent.ip_address && `- ${agent.ip_address}`}
                      </p>
                    </div>
                  </button>
                ))}
              </>
            )}

            {/* Degraded agents */}
            {degradedAgents.length > 0 && (
              <>
                <p
                  className="px-4 py-2 text-xs font-medium uppercase tracking-wider"
                  style={{ color: 'var(--muted)', backgroundColor: 'var(--surface)' }}
                >
                  Degraded ({degradedAgents.length})
                </p>
                {degradedAgents.map((agent) => (
                  <button
                    key={agent.id}
                    onClick={() => {
                      onSelect(agent)
                      setIsOpen(false)
                      setSearch('')
                    }}
                    className={cn(
                      'w-full flex items-center gap-3 px-4 py-3 transition-colors',
                      selectedAgent?.id === agent.id && 'bg-white/5'
                    )}
                    style={{ backgroundColor: selectedAgent?.id === agent.id ? 'var(--surface)' : 'transparent' }}
                  >
                    <div className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: 'var(--med)' }} />
                    <div className="flex-1 text-left">
                      <p style={{ color: 'var(--fg)' }}>{agent.hostname}</p>
                      <p className="text-xs" style={{ color: 'var(--muted)' }}>
                        {agent.os_type} {agent.ip_address && `- ${agent.ip_address}`}
                      </p>
                    </div>
                  </button>
                ))}
              </>
            )}

            {/* Offline agents */}
            {offlineAgents.length > 0 && (
              <>
                <p
                  className="px-4 py-2 text-xs font-medium uppercase tracking-wider"
                  style={{ color: 'var(--muted)', backgroundColor: 'var(--surface)' }}
                >
                  Offline ({offlineAgents.length})
                </p>
                {offlineAgents.map((agent) => (
                  <button
                    key={agent.id}
                    disabled
                    className="w-full flex items-center gap-3 px-4 py-3 opacity-50 cursor-not-allowed"
                  >
                    <div className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: 'var(--muted)' }} />
                    <div className="flex-1 text-left">
                      <p style={{ color: 'var(--muted)' }}>{agent.hostname}</p>
                      <p className="text-xs" style={{ color: 'var(--muted)' }}>{agent.os_type}</p>
                    </div>
                  </button>
                ))}
              </>
            )}

            {filtered.length === 0 && (
              <p className="px-4 py-8 text-center" style={{ color: 'var(--muted)' }}>No agents found</p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function SessionHistory({
  sessions,
  onPlayback,
  unavailableRecordings,
}: {
  sessions: ShellSession[]
  onPlayback: (session: ShellSession) => void
  unavailableRecordings: Set<string>
}) {
  if (sessions.length === 0) {
    return (
      <div className="p-8 text-center" style={{ color: 'var(--muted)' }}>
        <History className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No session history</p>
      </div>
    )
  }

  return (
    <div className="divide-y max-h-64 overflow-auto" style={{ borderColor: 'var(--border)' }}>
      {sessions.map((session) => (
        <div key={session.id} className="p-4 hover:bg-white/5 transition-colors">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2">
                <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{session.agent_hostname}</p>
                <span
                  className={cn(
                    'px-1.5 py-0.5 rounded text-xs',
                    session.status === 'active'
                      ? 'bg-emerald-500/20'
                      : 'bg-white/10'
                  )}
                  style={{ color: session.status === 'active' ? 'var(--emerald-400)' : 'var(--muted)' }}
                >
                  {session.status}
                </span>
              </div>
              <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                {formatDate(session.started_at)}
                {session.ended_at && ` - ${formatDate(session.ended_at)}`}
              </p>
              {session.user_email && (
                <p className="text-xs mt-0.5 flex items-center gap-1" style={{ color: 'var(--muted)' }}>
                  <User className="h-3 w-3" />
                  {session.user_email}
                </p>
              )}
            </div>
            {session.has_recording && session.status === 'ended' && !unavailableRecordings.has(session.session_id) && (
              <button
                onClick={() => onPlayback(session)}
                className="p-2 rounded-lg transition-colors hover:bg-white/10"
                style={{ color: 'var(--muted)' }}
                title="Playback recording"
              >
                <Play className="h-4 w-4" />
              </button>
            )}
            {session.has_recording && unavailableRecordings.has(session.session_id) && (
              <span className="text-xs" style={{ color: 'var(--muted)' }}>
                Recording unavailable
              </span>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

function FileBrowser({
  agentId,
  osType,
  onClose,
}: {
  agentId: string
  osType?: string
  onClose: () => void
}) {
  const initialPath = osType?.toLowerCase().includes('windows') ? 'C:\\' : '/'
  const [currentPath, setCurrentPath] = useState(initialPath)
  const [files, setFiles] = useState<FileEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [selectedFile, setSelectedFile] = useState<FileEntry | null>(null)
  const [previewContent, setPreviewContent] = useState<string | null>(null)
  const [previewMode, setPreviewMode] = useState<'text' | 'hex'>('text')
  const [fileAction, setFileAction] = useState<string | null>(null)
  const [pendingQuarantine, setPendingQuarantine] = useState<{ file: FileEntry; filePath: string } | null>(null)

  const buildFilePath = useCallback((file: FileEntry) => {
    if (file.path) return file.path
    if (currentPath === '/') return `/${file.name}`
    if (currentPath.endsWith('\\')) return `${currentPath}${file.name}`
    if (currentPath.includes('\\')) return `${currentPath}\\${file.name}`
    return `${currentPath}/${file.name}`
  }, [currentPath])

  const loadFiles = useCallback(async (path: string) => {
    setLoading(true)
    try {
      const response = await axios.get(`/api/v1/live-response/${agentId}/files`, {
        params: { path },
      })
      setFiles(response.data.data?.files || response.data.files || [])
      setCurrentPath(path)
    } catch (error: any) {
      toast.error(`Failed to load files: ${error.response?.data?.error || error.message}`)
    } finally {
      setLoading(false)
    }
  }, [agentId])

  useEffect(() => {
    loadFiles(initialPath)
  }, [initialPath, loadFiles])

  const navigateUp = () => {
    const normalized = currentPath.replace(/\\+$/, '')
    const separator = normalized.includes('\\') ? '\\' : '/'
    const root = separator === '\\' ? `${normalized.split('\\')[0]}\\` : '/'
    let parent = normalized.split(separator).slice(0, -1).join(separator) || root
    if (/^[a-z]:$/i.test(parent)) {
      parent = `${parent}\\`
    }
    loadFiles(parent)
  }

  const handleFileClick = (file: FileEntry) => {
    if (file.is_directory) {
      const newPath = buildFilePath(file)
      loadFiles(newPath)
    } else {
      setSelectedFile(file)
    }
  }

  const previewFile = async (file: FileEntry, mode: 'text' | 'hex') => {
    setPreviewMode(mode)
    try {
      const filePath = buildFilePath(file)
      const response = await axios.get(`/api/v1/live-response/${agentId}/files/download`, {
        params: { path: filePath },
        responseType: 'text',
      })
      if (mode === 'hex') {
        // Convert to hex dump
        const bytes = new TextEncoder().encode(response.data)
        let hex = ''
        for (let i = 0; i < Math.min(bytes.length, 1024); i += 16) {
          const row = bytes.slice(i, i + 16)
          const hexPart = Array.from(row)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join(' ')
          const asciiPart = Array.from(row)
            .map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.'))
            .join('')
          hex += `${i.toString(16).padStart(8, '0')}  ${hexPart.padEnd(48)}  ${asciiPart}\n`
        }
        setPreviewContent(hex)
      } else {
        setPreviewContent(response.data.slice(0, 65536)) // 64KB limit
      }
    } catch (error: any) {
      toast.error(`Failed to preview file: ${error.response?.data?.error || error.message}`)
    }
  }

  const hashFile = async (file: FileEntry) => {
    if (file.is_directory) return

    const filePath = buildFilePath(file)
    setFileAction(`hash:${filePath}`)
    try {
      const response = await axios.get(`/api/v1/live-response/${agentId}/files/hash`, {
        params: { path: filePath },
      })
      const data = response.data.data || response.data.result || response.data
      const hashText = [
        data.path ? `Path: ${data.path}` : `Path: ${filePath}`,
        data.size !== undefined ? `Size: ${formatBytes(Number(data.size) || 0)}` : null,
        data.sha256 ? `SHA256: ${data.sha256}` : null,
        data.sha1 ? `SHA1: ${data.sha1}` : null,
        data.md5 ? `MD5: ${data.md5}` : null,
      ].filter(Boolean).join('\n')

      setSelectedFile(file)
      setPreviewMode('text')
      setPreviewContent(hashText || JSON.stringify(data, null, 2))
      toast.success(`Hash calculated for ${file.name}`)
    } catch (error: any) {
      toast.error(`Failed to hash file: ${error.response?.data?.error || error.message}`)
    } finally {
      setFileAction(null)
    }
  }

  const downloadFile = async (file: FileEntry) => {
    if (file.is_directory) return

    const filePath = buildFilePath(file)
    setFileAction(`download:${filePath}`)
    try {
      const response = await axios.get(`/api/v1/live-response/${agentId}/files/download`, {
        params: { path: filePath },
        responseType: 'blob',
      })
      const blob = response.data instanceof Blob ? response.data : new Blob([response.data])
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = file.name
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
      toast.success(`Downloaded ${file.name}`)
    } catch (error: any) {
      toast.error(`Failed to download file: ${error.response?.data?.error || error.message}`)
    } finally {
      setFileAction(null)
    }
  }

  const quarantineFile = (file: FileEntry) => {
    const filePath = buildFilePath(file)
    setPendingQuarantine({ file, filePath })
  }

  const performQuarantine = async (file: FileEntry, filePath: string) => {
    setFileAction(`quarantine:${filePath}`)
    try {
      await axios.post(`/api/v1/response/quarantine`, {
        agent_id: agentId,
        path: filePath,
      })
      toast.success(`File quarantined: ${file.name}`)
      loadFiles(currentPath)
    } catch (error: any) {
      toast.error(`Failed to quarantine: ${error.response?.data?.error || error.message}`)
    } finally {
      setFileAction(null)
    }
  }

  const confirmQuarantine = async () => {
    const pending = pendingQuarantine
    setPendingQuarantine(null)
    if (!pending) return
    await performQuarantine(pending.file, pending.filePath)
  }

  const getFileIcon = (file: FileEntry) => {
    if (file.is_directory) return FolderOpen
    const ext = file.name.split('.').pop()?.toLowerCase()
    switch (ext) {
      case 'exe':
      case 'dll':
      case 'sys':
        return Cpu
      case 'txt':
      case 'log':
      case 'md':
        return FileText
      case 'js':
      case 'ts':
      case 'py':
      case 'rs':
      case 'c':
      case 'h':
        return FileCode
      case 'jpg':
      case 'png':
      case 'gif':
      case 'ico':
        return FileImage
      case 'zip':
      case 'tar':
      case 'gz':
      case '7z':
        return Archive
      case 'db':
      case 'sqlite':
        return Database
      default:
        return File
    }
  }

  return (
    <>
    <div
      className="rounded-xl border flex flex-col max-h-80"
      style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-2 border-b"
        style={{ backgroundColor: 'var(--bg)', borderColor: 'var(--border)' }}
      >
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <FolderOpen className="h-4 w-4 flex-shrink-0" style={{ color: 'var(--muted)' }} />
          <div className="flex items-center gap-1 overflow-auto">
            <button
              onClick={() => loadFiles(initialPath)}
              className="text-sm hover:underline flex-shrink-0"
              style={{ color: 'var(--emerald-400)' }}
            >
              {initialPath}
            </button>
            {currentPath !== '/' &&
              currentPath.replace(/\\/g, '/').split('/').filter(Boolean).map((part, i, arr) => (
                <span key={i} className="flex items-center">
                  <ChevronRight className="h-3 w-3" style={{ color: 'var(--muted)' }} />
                  <button
                    onClick={() =>
                      loadFiles(currentPath.includes('\\') ? arr.slice(0, i + 1).join('\\') + (i === 0 && part.endsWith(':') ? '\\' : '') : '/' + arr.slice(0, i + 1).join('/'))
                    }
                    className="text-sm hover:underline"
                    style={{ color: 'var(--emerald-400)' }}
                  >
                    {part}
                  </button>
                </span>
              ))}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={navigateUp}
            disabled={currentPath === '/' || /^[a-z]:\\?$/i.test(currentPath)}
            className="p-1.5 rounded transition-colors disabled:opacity-50 hover:bg-white/10"
            style={{ color: 'var(--muted)' }}
            title="Parent directory"
          >
            <ChevronDown className="h-4 w-4 rotate-90" />
          </button>
          <button
            onClick={() => loadFiles(currentPath)}
            className="p-1.5 rounded transition-colors hover:bg-white/10"
            style={{ color: 'var(--muted)' }}
            title="Refresh"
          >
            <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          </button>
          <button
            onClick={onClose}
            className="p-1.5 rounded transition-colors hover:bg-white/10"
            style={{ color: 'var(--muted)' }}
            title="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* File List */}
        <div className="flex-1 overflow-auto">
          {loading ? (
            <div className="p-8 text-center">
              <Loader2 className="h-6 w-6 mx-auto animate-spin" style={{ color: 'var(--emerald-400)' }} />
            </div>
          ) : files.length === 0 ? (
            <div className="p-8 text-center" style={{ color: 'var(--muted)' }}>
              <FolderOpen className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>Empty directory</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="text-xs sticky top-0" style={{ backgroundColor: 'var(--bg)', color: 'var(--muted)' }}>
                <tr>
                  <th className="text-left px-4 py-2">Name</th>
                  <th className="text-left px-4 py-2 w-24">Size</th>
                  <th className="text-left px-4 py-2 w-40">Modified</th>
                  <th className="text-right px-4 py-2 w-32">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {files.map((file, i) => {
                  const Icon = getFileIcon(file)
                  return (
                    <tr
                      key={i}
                      className={cn(
                        'hover:bg-white/5 cursor-pointer',
                        selectedFile?.name === file.name && 'bg-white/10'
                      )}
                      onClick={() => handleFileClick(file)}
                    >
                      <td className="px-4 py-2">
                        <div className="flex items-center gap-2">
                          <Icon
                            className="h-4 w-4"
                            style={{ color: file.is_directory ? 'var(--yellow-400, #facc15)' : 'var(--muted)' }}
                          />
                          <span className="text-sm truncate" style={{ color: 'var(--fg)' }}>{file.name}</span>
                        </div>
                      </td>
                      <td className="px-4 py-2 text-sm" style={{ color: 'var(--muted)' }}>
                        {file.is_directory ? '-' : formatBytes(file.size)}
                      </td>
                      <td className="px-4 py-2 text-sm" style={{ color: 'var(--muted)' }}>
                        {file.modified
                          ? formatDate(new Date(file.modified * 1000).toISOString())
                          : '-'}
                      </td>
                      <td className="px-4 py-2 text-right">
                        <div className="flex items-center justify-end gap-1">
                          {!file.is_directory && (
                            <>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  previewFile(file, 'text')
                                }}
                                className="p-1 rounded transition-colors hover:bg-white/10"
                                style={{ color: 'var(--muted)' }}
                                title="Preview (text)"
                              >
                                <Eye className="h-3 w-3" />
                              </button>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  previewFile(file, 'hex')
                                }}
                                className="p-1 rounded transition-colors hover:bg-white/10"
                                style={{ color: 'var(--muted)' }}
                                title="Preview (hex)"
                              >
                                <FileCode className="h-3 w-3" />
                              </button>
                            </>
                          )}
                          {!file.is_directory && (
                            <>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  hashFile(file)
                                }}
                                disabled={fileAction === `hash:${buildFilePath(file)}`}
                                className="p-1 rounded transition-colors hover:bg-white/10 disabled:opacity-50"
                                style={{ color: 'var(--muted)' }}
                                title="Calculate hash"
                              >
                                {fileAction === `hash:${buildFilePath(file)}` ? (
                                  <Loader2 className="h-3 w-3 animate-spin" />
                                ) : (
                                  <Hash className="h-3 w-3" />
                                )}
                              </button>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  downloadFile(file)
                                }}
                                disabled={fileAction === `download:${buildFilePath(file)}`}
                                className="p-1 rounded transition-colors hover:bg-white/10 disabled:opacity-50"
                                style={{ color: 'var(--muted)' }}
                                title="Download"
                              >
                                {fileAction === `download:${buildFilePath(file)}` ? (
                                  <Loader2 className="h-3 w-3 animate-spin" />
                                ) : (
                                  <Download className="h-3 w-3" />
                                )}
                              </button>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  quarantineFile(file)
                                }}
                                disabled={fileAction === `quarantine:${buildFilePath(file)}`}
                                className="p-1 rounded transition-colors hover:bg-red-500/20 disabled:opacity-50"
                                style={{ color: 'var(--red-400, #f87171)' }}
                                title="Quarantine"
                              >
                                {fileAction === `quarantine:${buildFilePath(file)}` ? (
                                  <Loader2 className="h-3 w-3 animate-spin" />
                                ) : (
                                  <Shield className="h-3 w-3" />
                                )}
                              </button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Preview Panel */}
        {previewContent !== null && (
          <div className="w-80 border-l flex flex-col" style={{ borderColor: 'var(--border)' }}>
            <div
              className="flex items-center justify-between px-3 py-2 border-b"
              style={{ backgroundColor: 'var(--bg)', borderColor: 'var(--border)' }}
            >
              <span className="text-xs font-medium" style={{ color: 'var(--muted)' }}>
                Preview ({previewMode})
              </span>
              <button
                onClick={() => setPreviewContent(null)}
                className="p-1 rounded hover:bg-white/10"
                style={{ color: 'var(--muted)' }}
              >
                <X className="h-3 w-3" />
              </button>
            </div>
            <pre
              className="flex-1 overflow-auto p-2 text-xs font-mono"
              style={{ backgroundColor: 'var(--bg)', color: 'var(--muted)' }}
            >
              {previewContent}
            </pre>
          </div>
        )}
      </div>
    </div>

    <Dialog
      open={!!pendingQuarantine}
      onOpenChange={(o) => !o && setPendingQuarantine(null)}
      title="Quarantine file"
      description={pendingQuarantine ? `Quarantine ${pendingQuarantine.filePath}? The file will be moved to the agent's quarantine vault and removed from its original location.` : ''}
    >
      <DialogFooter>
        <button
          type="button"
          className="btn-sentinel btn-sentinel-secondary"
          onClick={() => setPendingQuarantine(null)}
        >
          Cancel
        </button>
        <button
          type="button"
          className="btn-sentinel btn-sentinel-danger"
          onClick={confirmQuarantine}
        >
          Quarantine file
        </button>
      </DialogFooter>
    </Dialog>
    </>
  )
}

function ActiveSessionsPanel({
  sessions,
  currentSessionId,
  agentHostname,
}: {
  sessions: ActiveSession[]
  currentSessionId: string | null
  agentHostname?: string
}) {
  if (sessions.length === 0) return null

  return (
    <div
      className="rounded-xl border p-4"
      style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
    >
      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
        <Users className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
        Active Sessions ({sessions.length})
      </h3>
      {agentHostname && (
        <p className="text-xs mb-3" style={{ color: 'var(--muted)' }}>
          {agentHostname}
        </p>
      )}
      <div className="space-y-2">
        {sessions.map((session) => (
          <div
            key={session.session_id}
            className={cn(
              'flex items-center justify-between p-2 rounded-lg',
              session.session_id === currentSessionId
                ? 'border'
                : ''
            )}
            style={{
              backgroundColor: session.session_id === currentSessionId ? 'rgba(52, 211, 153, 0.1)' : 'var(--bg)',
              borderColor: session.session_id === currentSessionId ? 'var(--emerald-400)' : 'transparent',
            }}
          >
            <div className="flex items-center gap-2">
              {session.view_only ? (
                <Eye className="h-4 w-4" style={{ color: 'var(--muted)' }} />
              ) : (
                <TerminalIcon className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
              )}
              <span className="text-sm" style={{ color: 'var(--fg)' }}>{session.user_email}</span>
            </div>
            <div className="text-right">
              <span className="text-xs block" style={{ color: 'var(--muted)' }}>
                {session.view_only ? 'View Only' : 'Active'}
              </span>
              <span className="text-[10px] font-mono" style={{ color: 'var(--muted)' }}>
                {session.session_id.slice(0, 10)}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function SupervisorApprovalPanel({
  approvals,
  onApprove,
  onReject,
}: {
  approvals: PendingApproval[]
  onApprove: (commandId: string) => void
  onReject: (commandId: string) => void
}) {
  if (approvals.length === 0) return null

  return (
    <div
      className="rounded-xl p-4 border"
      style={{ backgroundColor: 'rgba(251, 146, 60, 0.1)', borderColor: 'rgba(251, 146, 60, 0.3)' }}
    >
      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--orange-400, #fb923c)' }}>
        <AlertTriangle className="h-4 w-4" />
        Pending Approvals ({approvals.length})
      </h3>
      <div className="space-y-3">
        {approvals.map((approval) => (
          <div
            key={approval.command_id}
            className="rounded-lg p-3"
            style={{ backgroundColor: 'var(--surface)' }}
          >
            <p className="text-sm font-mono mb-2" style={{ color: 'var(--fg)' }}>{approval.command}</p>
            <p className="text-xs mb-3" style={{ color: 'var(--muted)' }}>{approval.reason}</p>
            <div className="flex gap-2">
              <button
                onClick={() => onApprove(approval.command_id)}
                className="flex items-center gap-1 px-3 py-1.5 text-white text-sm font-medium rounded transition-colors"
                style={{ backgroundColor: 'var(--emerald-400)' }}
              >
                <CheckCircle className="h-3 w-3" />
                Approve
              </button>
              <button
                onClick={() => onReject(approval.command_id)}
                className="flex items-center gap-1 px-3 py-1.5 text-white text-sm font-medium rounded transition-colors"
                style={{ backgroundColor: 'var(--red-400, #f87171)' }}
              >
                <XCircle className="h-3 w-3" />
                Reject
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function MobileCommandTerminal({
  agent,
  queuedCommand,
  onQueuedCommandConsumed,
}: {
  agent: Agent
  queuedCommand?: string | null
  onQueuedCommandConsumed?: () => void
}) {
  const [overview, setOverview] = useState<MobileOverviewPayload | null>(null)
  const [lines, setLines] = useState<string[]>([
    'Tamandua Mobile Shell',
    'Mobile managed shell and response commands are available from the mobile endpoint panel',
    'Managed commands: help, posture, network, dns, apps, capabilities, collect_diagnostics',
    'shell_execute is disabled unless the Android build explicitly opts in and reports privileged shell capability',
  ])
  const [input, setInput] = useState('help')
  const [mode, setMode] = useState<'managed_shell' | 'shell_execute'>('managed_shell')
  const [loading, setLoading] = useState(false)

  const appendLines = useCallback((entries: string[]) => {
    setLines((prev) => [...prev, ...entries].slice(-300))
  }, [])

  const loadOverview = useCallback(async () => {
    const response = await axios.get(`/api/v1/mobile/agents/${agent.id}/overview`)
    const data = response.data?.data || null
    setOverview(data)
    return data as MobileOverviewPayload | null
  }, [agent.id])

  useEffect(() => {
    loadOverview().catch(() => {
      appendLines(['mobile> endpoint link unavailable'])
    })
  }, [appendLines, loadOverview])

  const pollCommand = useCallback(async (commandId: string): Promise<MobileCommandRecord | null> => {
    for (let attempt = 0; attempt < 18; attempt += 1) {
      const response = await axios.get(`/api/v1/mobile/v2/commands/${commandId}`)
      const command = response.data?.data as MobileCommandRecord
      if (command?.status === 'completed' || command?.status === 'failed') return command
      await new Promise((resolve) => window.setTimeout(resolve, 1500))
    }
    return null
  }, [])

  const executeMobileShell = useCallback(async (rawValue?: string, forcedMode?: 'managed_shell' | 'shell_execute') => {
    const raw = String(rawValue ?? input).trim()
    if (!raw) return

    const privileged = raw.startsWith('!')
    const commandType = forcedMode || (privileged ? 'shell_execute' : mode)
    const commandText = privileged ? raw.slice(1).trim() : raw
    const prompt = commandType === 'shell_execute' ? 'mobile#' : 'mobile>'
    let currentOverview = overview || (await loadOverview())
    let commandDeviceId = mobileOverviewCommandDeviceId(currentOverview)

    appendLines([`${prompt} ${commandText || raw}`])

    if (!commandDeviceId) {
      appendLines(['status: refreshing mobile endpoint link...'])
      try {
        currentOverview = await loadOverview()
        commandDeviceId = mobileOverviewCommandDeviceId(currentOverview)
      } catch (error: unknown) {
        const message =
          (error as { response?: { data?: { error?: string; message?: string } } })?.response?.data?.error ||
          (error as { response?: { data?: { message?: string } } })?.response?.data?.message ||
          (error as Error)?.message ||
          'mobile endpoint link refresh failed'
        appendLines([`status: ${message}`])
      }
    }

    if (!commandDeviceId) {
      const identifiers = currentOverview?.link_status?.expected_identifiers || []
      appendLines([
        'error: no linked mobile command device for this agent',
        ...(currentOverview?.link_status?.reason ? [`link status: ${currentOverview.link_status.reason}`] : []),
        ...(identifiers.length ? [`link identifiers tried: ${identifiers.join(', ')}`] : []),
        ...(currentOverview?.link_status?.remediation ? [currentOverview.link_status.remediation] : []),
      ])
      return
    }

    setLoading(true)
    try {
      const response = await axios.post('/api/v1/mobile/v2/commands', {
        device_id: commandDeviceId,
        command_type: commandType,
        payload: { command: commandText || raw },
      })
      const created = response.data?.data as MobileCommandRecord
      appendLines([`queued: ${created.id} (${commandType})`])

      const completed = await pollCommand(created.id)
      if (!completed) {
        appendLines(['status: still pending; mobile app has not returned a result yet'])
        return
      }

      appendLines(formatMobileCommandOutput(completed))
      loadOverview().catch(() => undefined)
    } catch (error: unknown) {
      const message =
        (error as { response?: { data?: { error?: string; message?: string } } })?.response?.data?.error ||
        (error as { response?: { data?: { message?: string } } })?.response?.data?.message ||
        (error as Error)?.message ||
        'mobile shell command failed'
      appendLines([`error: ${message}`])
    } finally {
      setLoading(false)
      setInput('')
    }
  }, [
    appendLines,
    input,
    loadOverview,
    mode,
    overview,
    pollCommand,
  ])

  const submit = (event: FormEvent) => {
    event.preventDefault()
    executeMobileShell()
  }

  useEffect(() => {
    if (!queuedCommand) return
    executeMobileShell(queuedCommand, queuedCommand.startsWith('!') ? 'shell_execute' : 'managed_shell')
    onQueuedCommandConsumed?.()
  }, [executeMobileShell, onQueuedCommandConsumed, queuedCommand])

  return (
    <div className="h-full flex flex-col" style={{ backgroundColor: '#050807', color: '#d7fbe8' }}>
      <div className="flex items-center justify-between px-4 py-2 border-b" style={{ borderColor: 'rgba(255,255,255,0.12)' }}>
        <div className="flex items-center gap-2 text-sm">
          <TerminalIcon className="h-4 w-4" />
          <span className="font-medium">{agent.hostname}</span>
          <span style={{ color: '#8fd7b0' }}>{overview?.command_device?.status || 'mobile endpoint'}</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setMode('managed_shell')}
            className={cn('px-2 py-1 rounded text-xs', mode === 'managed_shell' ? 'bg-emerald-500 text-black' : 'bg-white/10')}
          >
            Managed
          </button>
          <button
            onClick={() => setMode('shell_execute')}
            className={cn('px-2 py-1 rounded text-xs', mode === 'shell_execute' ? 'bg-orange-400 text-black' : 'bg-white/10')}
            title="Requires tamandua.endpoint.allow_privileged_shell=true and a reported privileged shell capability"
          >
            Privileged gated
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-4 font-mono text-sm whitespace-pre-wrap">
        {lines.map((line, index) => (
          <div key={`${index}-${line.slice(0, 24)}`}>{line}</div>
        ))}
        {loading && <div style={{ color: '#facc15' }}>waiting for mobile endpoint result...</div>}
      </div>

      <div className="px-4 py-2 border-t flex flex-wrap gap-2" style={{ borderColor: 'rgba(255,255,255,0.12)' }}>
        {['posture', 'network', 'dns', 'apps', 'capabilities', 'collect_diagnostics'].map((command) => (
          <button
            key={command}
            onClick={() => executeMobileShell(command, command.startsWith('!') ? 'shell_execute' : 'managed_shell')}
            disabled={loading}
            className="px-2 py-1 rounded text-xs bg-white/10 hover:bg-white/20 disabled:opacity-50"
          >
            {command}
          </button>
        ))}
      </div>

      <form onSubmit={submit} className="p-3 border-t flex items-center gap-2" style={{ borderColor: 'rgba(255,255,255,0.12)' }}>
        <span className="font-mono text-sm">{mode === 'shell_execute' ? 'mobile#' : 'mobile>'}</span>
        <input
          value={input}
          onChange={(event) => setInput(event.target.value)}
          disabled={loading}
          className="flex-1 bg-transparent outline-none font-mono text-sm"
          placeholder={mode === 'shell_execute' ? 'id' : 'posture'}
        />
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="px-3 py-1.5 rounded text-sm bg-emerald-500 text-black disabled:opacity-50"
        >
          Run
        </button>
      </form>
    </div>
  )
}

function formatMobileCommandOutput(command: MobileCommandRecord): string[] {
  const envelope = command.result || {}
  const nestedResult = envelope.result && typeof envelope.result === 'object'
    ? (envelope.result as Record<string, unknown>)
    : null
  const result = nestedResult || envelope
  const status = command.status || 'unknown'
  const output = result.output || result.stdout
  const stderr = result.stderr
  const reason = result.reason || result.error
  const exitCode = result.exit_code
  const shell = result.shell || result.strategy
  const attempts = Array.isArray(result.attempts) ? result.attempts : null

  const lines = [
    `status: ${status}${exitCode !== undefined ? ` exit=${exitCode}` : ''}${shell ? ` shell=${String(shell)}` : ''}`,
  ]

  if (typeof output === 'string' && output.trim()) {
    lines.push(output.trim())
  } else if (result && Object.keys(result).length > 0) {
    lines.push(JSON.stringify(result, null, 2))
  }

  if (typeof stderr === 'string' && stderr.trim()) lines.push(`stderr: ${stderr.trim()}`)
  if (attempts?.length) lines.push(`attempts: ${JSON.stringify(attempts, null, 2)}`)
  if (reason) lines.push(`reason: ${String(reason)}`)
  if (reason === 'privileged_shell_disabled') {
    lines.push('shell_execute requires explicit Android build opt-in: tamandua.endpoint.allow_privileged_shell=true')
    lines.push('use managed_shell commands for the default mobile response path')
  }

  return lines
}

function mobileQuickActionCommand(command: string): string {
  switch (command) {
    case 'ps':
      return 'posture'
    case 'netstat':
      return 'network'
    case 'autoruns':
    case 'services':
      return 'capabilities'
    case 'tasks':
      return 'collect_diagnostics'
    case 'dns':
      return 'dns'
    case 'history':
      return 'capabilities'
    case 'help':
      return 'help'
    default:
      return command
  }
}

// ============================================================================
// Main Component
// ============================================================================

export default function LiveResponse({
  agents = [],
  recentSessions = [],
  selectedAgent: initialSelectedAgent,
  agentId,
}: LiveResponseProps) {
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(
    initialSelectedAgent || null
  )
  const [tabs, setTabs] = useState<TabSession[]>([])
  const [activeTabId, setActiveTabId] = useState<string | null>(null)
  const [tabsRestored, setTabsRestored] = useState(false)
  const [editingTabId, setEditingTabId] = useState<string | null>(null)
  const [editingTabTitle, setEditingTabTitle] = useState('')
  const [playbackSession, setPlaybackSession] = useState<ShellSession | null>(null)
  const [playbackData, setPlaybackData] = useState<string | null>(null)
  const [isLoadingPlayback, setIsLoadingPlayback] = useState(false)
  const [unavailableRecordings, setUnavailableRecordings] = useState<Set<string>>(() => new Set())
  const [showFileBrowser, setShowFileBrowser] = useState(false)
  const [activeSessionsByAgent, setActiveSessionsByAgent] = useState<Record<string, ActiveSession[]>>({})
  const [pendingApprovals, setPendingApprovals] = useState<PendingApproval[]>([])
  const [mobileQueuedCommands, setMobileQueuedCommands] = useState<Record<string, string | null>>({})

  const terminalRefs = useRef<Map<string, TerminalRef>>(new Map())
  // Track if we're already starting a session to prevent race conditions
  const sessionStartingRef = useRef(false)

  const activeTab = tabs.find((t) => t.id === activeTabId)
  const selectedAgentSessions = selectedAgent
    ? activeSessionsByAgent[selectedAgent.id] || []
    : []
  const selectedAgentCurrentSessionId =
    selectedAgent && activeTab?.agentId === selectedAgent.id ? activeTab.sessionId : null

  useEffect(() => {
    if (tabsRestored) return

    if (typeof window === 'undefined') {
      setTabsRestored(true)
      return
    }

    try {
      const raw = window.localStorage.getItem(LIVE_RESPONSE_TABS_KEY)
      if (!raw) {
        setTabsRestored(true)
        return
      }

      const parsed = JSON.parse(raw)
      const onlineAgents = new Set(
        (agents || []).filter((agent) => agent.status === 'online').map((agent) => agent.id)
      )
      const restoredTabs: TabSession[] = Array.isArray(parsed?.tabs)
        ? parsed.tabs
            .filter((tab: Partial<TabSession>) => tab?.id && tab?.agentId && tab?.hostname)
            .map((tab: TabSession) => ({
              id: tab.id,
              agentId: tab.agentId,
              hostname: tab.hostname,
              osType: tab.osType,
              title: tab.title || tab.hostname,
              sessionId: tab.sessionId || null,
              status: onlineAgents.has(tab.agentId) ? 'connecting' : 'disconnected',
              waitingForOutput: false,
              viewOnly: Boolean(tab.viewOnly),
            }))
        : []

      if (restoredTabs.length > 0) {
        setTabs(restoredTabs)
        setActiveTabId(
          restoredTabs.some((tab) => tab.id === parsed?.activeTabId)
            ? parsed.activeTabId
            : restoredTabs[0].id
        )
      }
    } catch {
      window.localStorage.removeItem(LIVE_RESPONSE_TABS_KEY)
    } finally {
      setTabsRestored(true)
    }
  }, [agents, tabsRestored])

  useEffect(() => {
    if (!tabsRestored || typeof window === 'undefined') return

    const cacheableTabs = tabs.map((tab) => ({
      id: tab.id,
      agentId: tab.agentId,
      hostname: tab.hostname,
      osType: tab.osType,
      title: tab.title || tab.hostname,
      sessionId: tab.sessionId,
      status: tab.status,
      viewOnly: tab.viewOnly,
    }))

    window.localStorage.setItem(
      LIVE_RESPONSE_TABS_KEY,
      JSON.stringify({ tabs: cacheableTabs, activeTabId })
    )
  }, [activeTabId, tabs, tabsRestored])

  // Auto-start session if agentId is provided
  useEffect(() => {
    // Prevent duplicate session creation due to React's async state updates
    if (sessionStartingRef.current) return

    if (tabsRestored && agentId && selectedAgent && canStartLiveResponse(selectedAgent) && tabs.length === 0) {
      sessionStartingRef.current = true
      startSession()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agentId, selectedAgent?.id, selectedAgent?.status, tabs.length, tabsRestored])

  // Reset session-starting flag when tabs actually change
  useEffect(() => {
    if (tabs.length > 0) {
      sessionStartingRef.current = false
    }
  }, [tabs.length])

  // Start new session
  const startSession = useCallback((viewOnly = false) => {
    if (!selectedAgent) {
      toast.error('Please select an agent')
      return
    }

    if (!canStartLiveResponse(selectedAgent)) {
      toast.error('Agent is not available for live response')
      return
    }

    const tabId = `tab_${Date.now()}`
    const newTab: TabSession = {
      id: tabId,
      agentId: selectedAgent.id,
      hostname: selectedAgent.hostname,
      osType: selectedAgent.os_type,
      title: selectedAgent.hostname,
      sessionId: null,
      status: isMobileAgent(selectedAgent) ? 'connected' : 'connecting',
      waitingForOutput: false,
      viewOnly,
    }

    setTabs((prev) => [...prev, newTab])
    setActiveTabId(tabId)
  }, [selectedAgent])

  // Close tab
  const closeTab = useCallback((tabId: string) => {
    setTabs((prev) => {
      const newTabs = prev.filter((t) => t.id !== tabId)
      if (newTabs.length > 0 && tabId === activeTabId) {
        setActiveTabId(newTabs[newTabs.length - 1].id)
      } else if (newTabs.length === 0) {
        setActiveTabId(null)
      }
      return newTabs
    })

    const ref = terminalRefs.current.get(tabId)
    if (ref) {
      ref.terminate()
      terminalRefs.current.delete(tabId)
    }
  }, [activeTabId])

  const beginRenameTab = useCallback((tab: TabSession) => {
    setEditingTabId(tab.id)
    setEditingTabTitle(tab.title || tab.hostname)
  }, [])

  const commitRenameTab = useCallback(() => {
    if (!editingTabId) return

    const title = editingTabTitle.trim().slice(0, 48)
    if (title.length > 0) {
      setTabs((prev) =>
        prev.map((tab) => (tab.id === editingTabId ? { ...tab, title } : tab))
      )
    }

    setEditingTabId(null)
    setEditingTabTitle('')
  }, [editingTabId, editingTabTitle])

  const cancelRenameTab = useCallback(() => {
    setEditingTabId(null)
    setEditingTabTitle('')
  }, [])

  // Execute quick action
  const executeQuickAction = useCallback((action: BuiltinCommand) => {
    if (!activeTabId) {
      toast.error('No active session')
      return
    }

    const active = tabs.find((tab) => tab.id === activeTabId)
    if (isMobileTab(active)) {
      const mapped = mobileQuickActionCommand(action.command)
      setMobileQueuedCommands((prev) => ({ ...prev, [activeTabId]: mapped }))
      return
    }

    const ref = terminalRefs.current.get(activeTabId)
    if (ref) {
      ref.executeBuiltin(action.command, action.args)
    }
  }, [activeTabId, tabs])

  // Handle playback
  const handlePlayback = useCallback(async (session: ShellSession) => {
    setIsLoadingPlayback(true)
    setPlaybackSession(session)

    try {
      const response = await axios.get(`/api/v1/recordings/${session.session_id}/download`, {
        params: { format: 'raw' },
        responseType: 'text',
      })
      setPlaybackData(response.data)
    } catch (error: any) {
      const errorMessage =
        typeof error.response?.data === 'string'
          ? error.response.data
          : error.response?.data?.error || error.message
      if (error.response?.status === 404) {
        setUnavailableRecordings((prev) => new Set(prev).add(session.session_id))
        toast.warning('Recording is no longer available for this session')
      } else {
        toast.error(`Failed to load recording: ${errorMessage}`)
      }
      setPlaybackSession(null)
    } finally {
      setIsLoadingPlayback(false)
    }
  }, [])

  // Download transcript
  const downloadTranscript = useCallback(async () => {
    if (!playbackSession) return

    try {
      const response = await axios.get(`/api/v1/recordings/${playbackSession.session_id}/download`, {
        params: { format: 'raw' },
        responseType: 'text',
      })
      const blob = new Blob([response.data], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `recording_${playbackSession.session_id}.cast`
      a.click()
      URL.revokeObjectURL(url)
    } catch (error: any) {
      const errorMessage =
        typeof error.response?.data === 'string'
          ? error.response.data
          : error.response?.data?.error || error.message
      toast.error(`Failed to download recording: ${errorMessage}`)
    }
  }, [playbackSession])

  // Export current session
  const exportSession = useCallback(async (format: 'asciinema' | 'transcript' | 'json') => {
    if (!activeTabId) return

    const ref = terminalRefs.current.get(activeTabId)
    if (ref) {
      ref.exportSession(format)
      toast.info(`Exporting session as ${format}...`)
    }
  }, [activeTabId])

  // Share session
  const shareSession = useCallback(() => {
    if (!activeTabId) return

    const ref = terminalRefs.current.get(activeTabId)
    if (!ref) {
      toast.error('No active terminal session')
      return
    }

    const targetUserId = window.prompt('Target user ID to share this session with')
    if (!targetUserId?.trim()) return

    ref.shareSession(targetUserId.trim(), true)
  }, [activeTabId])

  // Handle supervisor approval
  const handleApproval = useCallback((commandId: string, approved: boolean) => {
    // This would be handled via supervisor channel
    setPendingApprovals((prev) => prev.filter((a) => a.command_id !== commandId))
    toast.success(approved ? 'Command approved' : 'Command rejected')
  }, [])

  return (
    <MainLayout title="Live Response">
      <Head title="Live Response - Tamandua EDR" />

      <div className="grid grid-cols-12 gap-6 h-[calc(100vh-12rem)]">
        {/* Left Sidebar - Agent Selection & Actions */}
        <div className="col-span-3 space-y-4 overflow-auto">
          {/* Agent Selector */}
          <div
            className="rounded-xl border p-4"
            style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
          >
            <h2 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
              <Monitor className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
              Target Agent
            </h2>
            <AgentSelector
              agents={agents || []}
              selectedAgent={selectedAgent}
              onSelect={setSelectedAgent}
            />
            <p className="mt-2 text-xs" style={{ color: 'var(--muted)' }}>
              {liveResponseStatusLabel(selectedAgent)}
            </p>
            <div className="flex gap-2 mt-4">
              <button
                onClick={() => startSession(false)}
                disabled={!canStartLiveResponse(selectedAgent)}
                className={cn(
                  'flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg font-medium transition-colors',
                  canStartLiveResponse(selectedAgent)
                    ? 'text-white'
                    : 'cursor-not-allowed opacity-50'
                )}
                style={{
                  backgroundColor: canStartLiveResponse(selectedAgent) ? 'var(--emerald-400)' : 'var(--surface)',
                  color: canStartLiveResponse(selectedAgent) ? 'var(--bg)' : 'var(--muted)',
                }}
              >
                <TerminalIcon className="h-4 w-4" />
                Shell
              </button>
              <button
                onClick={() => startSession(true)}
                disabled={!canStartLiveResponse(selectedAgent)}
                className={cn(
                  'flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg font-medium transition-colors',
                  canStartLiveResponse(selectedAgent)
                    ? ''
                    : 'cursor-not-allowed opacity-50'
                )}
                style={{
                  backgroundColor: 'var(--surface)',
                  color: canStartLiveResponse(selectedAgent) ? 'var(--fg)' : 'var(--muted)',
                }}
                title="View Only Mode"
              >
                <Eye className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Quick Actions */}
          <div
            className="rounded-xl border p-4"
            style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
          >
            <h2 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
              <Shield className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
              Quick Actions
            </h2>
            <div className="grid grid-cols-2 gap-2">
              {quickActions.map((action) => (
                <button
                  key={action.id}
                  onClick={() => executeQuickAction(action)}
                  disabled={!activeTabId}
                  className={cn(
                    'flex flex-col items-center gap-1 p-3 rounded-lg text-sm transition-colors',
                    activeTabId
                      ? 'hover:bg-white/10'
                      : 'cursor-not-allowed opacity-50'
                  )}
                  style={{
                    backgroundColor: 'var(--bg)',
                    color: activeTabId ? 'var(--muted)' : 'var(--muted)',
                  }}
                  title={action.description}
                >
                  <action.icon className="h-4 w-4" />
                  <span className="text-xs">{action.name}</span>
                </button>
              ))}
            </div>
          </div>

          {/* File Browser Toggle */}
          <div
            className="rounded-xl border p-4"
            style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
          >
            <h2 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
              <FolderOpen className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
              File Browser
            </h2>
            <button
              onClick={() => setShowFileBrowser(!showFileBrowser)}
              disabled={!activeTabId}
              className={cn(
                'w-full flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium transition-colors',
                activeTabId
                  ? 'hover:bg-white/10'
                  : 'cursor-not-allowed opacity-50'
              )}
              style={{
                backgroundColor: 'var(--bg)',
                color: activeTabId ? 'var(--fg)' : 'var(--muted)',
              }}
            >
              <FolderOpen className="h-4 w-4" />
              {showFileBrowser ? 'Hide Browser' : 'Open Browser'}
            </button>
          </div>

          {/* Session Actions */}
          {activeTabId && (
            <div
              className="rounded-xl border p-4"
              style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
            >
              <h2 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Settings className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                Session Actions
              </h2>
              <div className="space-y-2">
                <button
                  onClick={() => exportSession('transcript')}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors hover:bg-white/10"
                  style={{ backgroundColor: 'var(--bg)', color: 'var(--fg)' }}
                >
                  <Save className="h-4 w-4" />
                  Export Transcript
                </button>
                <button
                  onClick={() => exportSession('json')}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors hover:bg-white/10"
                  style={{ backgroundColor: 'var(--bg)', color: 'var(--fg)' }}
                >
                  <Download className="h-4 w-4" />
                  Export JSON
                </button>
                <button
                  onClick={shareSession}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors hover:bg-white/10"
                  style={{ backgroundColor: 'var(--bg)', color: 'var(--fg)' }}
                >
                  <Share2 className="h-4 w-4" />
                  Share Session
                </button>
              </div>
            </div>
          )}

          {/* Active Sessions */}
          <ActiveSessionsPanel
            sessions={selectedAgentSessions}
            currentSessionId={selectedAgentCurrentSessionId}
            agentHostname={selectedAgent?.hostname}
          />

          {/* Supervisor Approval Panel */}
          <SupervisorApprovalPanel
            approvals={pendingApprovals}
            onApprove={(id) => handleApproval(id, true)}
            onReject={(id) => handleApproval(id, false)}
          />

          {/* Session History */}
          <div
            className="rounded-xl border"
            style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
          >
            <div className="p-4 border-b" style={{ borderColor: 'var(--border)' }}>
              <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <History className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                Recent Sessions
              </h2>
            </div>
            <SessionHistory
              sessions={recentSessions || []}
              onPlayback={handlePlayback}
              unavailableRecordings={unavailableRecordings}
            />
          </div>
        </div>

        {/* Main Content - Terminal */}
        <div className="col-span-9 flex flex-col min-h-0">
          {/* Tabs */}
          {tabs.length > 0 && (
            <div className="flex items-center gap-1 mb-2 overflow-x-auto pb-1">
              {tabs.map((tab) => (
                <div
                  key={tab.id}
                  className={cn(
                    'flex items-center gap-2 px-3 py-2 rounded-t-lg text-sm font-medium transition-colors cursor-pointer',
                    tab.id === activeTabId
                      ? 'border border-b-0'
                      : 'hover:bg-white/5'
                  )}
                  style={{
                    backgroundColor: tab.id === activeTabId ? 'var(--surface)' : 'transparent',
                    borderColor: tab.id === activeTabId ? 'var(--border)' : 'transparent',
                    color: tab.id === activeTabId ? 'var(--fg)' : 'var(--muted)',
                  }}
                  onClick={() => setActiveTabId(tab.id)}
                >
                  <span
                    className={cn(
                      'h-2 w-2 rounded-full',
                      (tab.status === 'connecting' || tab.waitingForOutput) && 'animate-pulse'
                    )}
                    style={{
                      backgroundColor:
                        tab.status === 'connected'
                          ? 'var(--emerald-400)'
                          : tab.status === 'connecting' || tab.waitingForOutput
                            ? 'var(--yellow-400, #facc15)'
                            : tab.status === 'error'
                              ? 'var(--red-400, #f87171)'
                              : 'var(--muted)',
                    }}
                  />
                  {editingTabId === tab.id ? (
                    <input
                      value={editingTabTitle}
                      onChange={(e) => setEditingTabTitle(e.target.value)}
                      onClick={(e) => e.stopPropagation()}
                      onBlur={commitRenameTab}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault()
                          commitRenameTab()
                        } else if (e.key === 'Escape') {
                          e.preventDefault()
                          cancelRenameTab()
                        }
                      }}
                      className="w-36 bg-transparent border rounded px-1 py-0.5 text-sm outline-none"
                      style={{ borderColor: 'var(--border)', color: 'var(--fg)' }}
                      autoFocus
                    />
                  ) : (
                    <button
                      onDoubleClick={(e) => {
                        e.stopPropagation()
                        beginRenameTab(tab)
                      }}
                      className="max-w-44 truncate text-left"
                      title="Double-click to rename tab"
                    >
                      {tab.title || tab.hostname}
                    </button>
                  )}
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      beginRenameTab(tab)
                    }}
                    className="p-0.5 rounded hover:bg-white/10 transition-colors"
                    title="Rename tab"
                  >
                    <Pencil className="h-3 w-3" />
                  </button>
                  {tab.viewOnly && (
                    <Eye className="h-3 w-3" style={{ color: 'var(--muted)' }} />
                  )}
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      closeTab(tab.id)
                    }}
                    className="ml-1 p-0.5 rounded hover:bg-white/10 transition-colors"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </div>
              ))}
              <button
                onClick={() => startSession()}
                disabled={!canStartLiveResponse(selectedAgent)}
                className="p-2 rounded-lg transition-colors hover:bg-white/10 disabled:opacity-50 disabled:cursor-not-allowed"
                style={{ color: 'var(--muted)' }}
                title="New session"
              >
                <Plus className="h-4 w-4" />
              </button>
            </div>
          )}

          {/* File Browser Panel */}
          {showFileBrowser && activeTabId && activeTab && (
            <div className="mb-3 shrink-0">
              {isMobileTab(activeTab) ? (
                <div
                  className="rounded-xl border p-4 text-sm"
                  style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)', color: 'var(--muted)' }}
                >
                  Mobile file browsing is exposed through package/app inspection and diagnostics commands, not the host file browser.
                </div>
              ) : (
                <FileBrowser
                  agentId={activeTab.agentId}
                  osType={activeTab.osType}
                  onClose={() => setShowFileBrowser(false)}
                />
              )}
            </div>
          )}

          {/* Terminal Area */}
          <div
            className="flex-1 min-h-0 rounded-xl border overflow-hidden"
            style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border)' }}
          >
            {tabs.length === 0 && !playbackSession ? (
              <div className="h-full flex items-center justify-center">
                <div className="text-center">
                  <TerminalIcon className="h-16 w-16 mx-auto mb-4" style={{ color: 'var(--muted)', opacity: 0.5 }} />
                  <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--fg)' }}>No Active Sessions</h3>
                  <p className="mb-4" style={{ color: 'var(--muted)' }}>
                    Select an agent and start a shell session to begin
                  </p>
                  <button
                    onClick={() => startSession()}
                    disabled={!canStartLiveResponse(selectedAgent)}
                    className={cn(
                      'flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors mx-auto',
                      canStartLiveResponse(selectedAgent)
                        ? ''
                        : 'cursor-not-allowed opacity-50'
                    )}
                    style={{
                      backgroundColor: canStartLiveResponse(selectedAgent) ? 'var(--emerald-400)' : 'var(--surface)',
                      color: canStartLiveResponse(selectedAgent) ? 'var(--bg)' : 'var(--muted)',
                    }}
                  >
                    <TerminalIcon className="h-4 w-4" />
                    Start Session
                  </button>
                </div>
              </div>
            ) : playbackSession ? (
              <div className="h-full flex flex-col">
                <div
                  className="flex items-center justify-between px-4 py-2 border-b"
                  style={{ backgroundColor: 'var(--bg)', borderColor: 'var(--border)' }}
                >
                  <div className="flex items-center gap-3">
                    <Play className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                    <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                      Recording: {playbackSession.agent_hostname}
                    </span>
                    <span className="text-xs" style={{ color: 'var(--muted)' }}>
                      {formatDate(playbackSession.started_at)}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={downloadTranscript}
                      className="p-1.5 rounded transition-colors hover:bg-white/10"
                      style={{ color: 'var(--muted)' }}
                      title="Download transcript"
                    >
                      <Download className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => {
                        setPlaybackSession(null)
                        setPlaybackData(null)
                      }}
                      className="p-1.5 rounded transition-colors hover:bg-white/10"
                      style={{ color: 'var(--muted)' }}
                      title="Close playback"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                </div>
                <div className="flex-1">
                  {isLoadingPlayback ? (
                    <div className="h-full flex items-center justify-center">
                      <Loader2 className="h-8 w-8 animate-spin" style={{ color: 'var(--emerald-400)' }} />
                    </div>
                  ) : (
                    <Suspense fallback={<TerminalLoadingFallback />}>
                      <Terminal
                        agentId=""
                        readOnly
                        recordingData={playbackData || undefined}
                        className="h-full"
                      />
                    </Suspense>
                  )}
                </div>
              </div>
            ) : (
              <div className="h-full relative">
                {tabs.map((tab) => (
                  <div
                    key={tab.id}
                    className={cn('absolute inset-0', tab.id !== activeTabId && 'hidden')}
                  >
                    {isMobileTab(tab) ? (
                      <MobileCommandTerminal
                        agent={{
                          id: tab.agentId,
                          hostname: tab.hostname,
                          os_type: tab.osType || 'android',
                          status: 'online',
                          last_seen: '',
                        }}
                        queuedCommand={mobileQueuedCommands[tab.id]}
                        onQueuedCommandConsumed={() =>
                          setMobileQueuedCommands((prev) => ({ ...prev, [tab.id]: null }))
                        }
                      />
                    ) : (
                      <Suspense fallback={<TerminalLoadingFallback />}>
                        <Terminal
                          ref={(ref) => {
                            if (ref) {
                              terminalRefs.current.set(tab.id, ref)
                            }
                          }}
                          agentId={tab.agentId}
                          sessionId={tab.sessionId || undefined}
                          viewOnly={tab.viewOnly}
                          onConnectionStateChange={(state) => {
                            setTabs((prev) =>
                              prev.map((t) =>
                                t.id === tab.id
                                  ? {
                                      ...t,
                                      status:
                                        state === 'connected'
                                          ? 'connected'
                                          : state === 'connecting'
                                            ? 'connecting'
                                            : state === 'error'
                                              ? 'error'
                                              : 'disconnected',
                                    }
                                  : t
                              )
                            )
                          }}
                          onWaitingForOutputChange={(waiting) => {
                            setTabs((prev) =>
                              prev.map((t) =>
                                t.id === tab.id ? { ...t, waitingForOutput: waiting } : t
                              )
                            )
                          }}
                          onSessionStart={(sessionId) => {
                            setTabs((prev) =>
                              prev.map((t) =>
                                t.id === tab.id
                                  ? { ...t, sessionId, status: 'connected', waitingForOutput: true }
                                  : t
                              )
                            )
                          }}
                          onActiveSessions={(sessions) => {
                            setActiveSessionsByAgent((prev) => ({
                              ...prev,
                              [tab.agentId]: sessions.filter(
                                (session, index, all) =>
                                  session.session_id &&
                                  all.findIndex((candidate) => candidate.session_id === session.session_id) === index
                              ),
                            }))
                          }}
                          onShareToken={(token) => {
                            navigator.clipboard.writeText(token).catch(() => undefined)
                            toast.success('Share token copied to clipboard')
                          }}
                          onSupervisorRequired={(commandId, command) => {
                            setPendingApprovals((prev) => {
                              if (prev.some((approval) => approval.command_id === commandId)) {
                                return prev
                              }

                              return [
                                ...prev,
                                {
                                  command_id: commandId,
                                  command,
                                  reason: 'Supervisor approval required',
                                  requested_at: new Date().toISOString(),
                                },
                              ]
                            })
                          }}
                          onSessionEnd={(reason) => {
                            setTabs((prev) =>
                              prev.map((t) =>
                                t.id === tab.id
                                  ? { ...t, status: 'disconnected', waitingForOutput: false }
                                  : t
                              )
                            )
                            toast.info(`Session ended: ${reason}`)
                          }}
                          onError={(error) => {
                            setTabs((prev) =>
                              prev.map((t) =>
                                t.id === tab.id
                                  ? { ...t, status: 'error', waitingForOutput: false }
                                  : t
                              )
                            )
                            toast.error(error)
                          }}
                          className="h-full"
                        />
                      </Suspense>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

    </MainLayout>
  )
}
