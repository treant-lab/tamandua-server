import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Plug,
  Server,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Terminal,
  Clock,
  Activity,
  Wrench,
  Search,
  ChevronDown,
  ChevronRight,
  FileText,
  Loader2,
} from 'lucide-react'
import { useState } from 'react'
import axios from 'axios'
import { toast } from 'sonner'
import { cn } from '@/lib/utils'

interface MCPTool {
  name: string
  description: string
  inputSchema?: Record<string, unknown>
  requiredPermissions?: string[]
  lastUsed?: string
  usageCount?: number
}

interface MCPServer {
  id: string
  name: string
  endpoint?: string
  status: 'active' | 'connected' | 'disconnected' | 'error' | 'connecting'
  version?: string
  tools?: MCPTool[]
  startedAt?: string
  toolCount?: number
  contextProviderCount?: number
  totalRequests?: number
  successRate?: number
  lastHeartbeat?: string
  latencyMs?: number
  requestsToday?: number
  errorsToday?: number
}

interface ContextProvider {
  id?: string
  name: string
  type?: string
  description?: string
  status?: string
  resourceCount?: number
  parameters?: Record<string, unknown>
}

interface ConnectionLog {
  id: string
  serverId: string
  serverName: string
  timestamp: string
  event: 'connected' | 'disconnected' | 'error' | 'tool_call' | 'heartbeat'
  message: string
  details?: Record<string, unknown>
  clientId?: string
  method?: string
  status?: string
  durationMs?: number
  ipAddress?: string
}

interface MCPServersPageProps {
  servers?: MCPServer[]
  tools?: MCPTool[]
  contextProviders?: ContextProvider[]
  connectionLogs?: ConnectionLog[]
  stats?: {
    totalServers: number
    connectedServers: number
    totalTools: number
    requestsToday: number
    totalRequests?: number
    successfulRequests?: number
    failedRequests?: number
    actionsExecuted?: number
  }
}

// Default values
const defaultStats = {
  totalServers: 0,
  connectedServers: 0,
  totalTools: 0,
  requestsToday: 0,
}

export default function MCPServers({
  servers = [],
  tools: _tools = [],
  contextProviders = [],
  connectionLogs = [],
  stats = defaultStats,
}: MCPServersPageProps) {
  const [expandedServer, setExpandedServer] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [showLogs, setShowLogs] = useState(true)
  const [loading, setLoading] = useState<string | null>(null)
  const [schemaServer, setSchemaServer] = useState<MCPServer | null>(null)

  const handleTestConnection = async (serverId: string) => {
    setLoading(`test-${serverId}`)
    try {
      const res = await axios.post('/api/v1/mcp/rpc', {
        jsonrpc: '2.0',
        method: 'tools/list',
        params: {},
        id: Date.now(),
      })
      const toolCount = Array.isArray(res.data?.result?.tools) ? res.data.result.tools.length : undefined
      toast.success(toolCount === undefined ? 'MCP endpoint responded' : `MCP endpoint responded with ${toolCount} tools`)
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'MCP protocol check failed')
    } finally {
      setLoading(null)
    }
  }

  const handleRefreshAll = () => {
    router.reload()
  }

  const handleViewSchema = (server: MCPServer) => {
    setSchemaServer(schemaServer?.id === server.id ? null : server)
  }

  const normalizedServers = (servers.length > 0 ? servers : [{
    id: 'tamandua-mcp',
    name: 'Tamandua MCP Server',
    status: 'active' as const,
    toolCount: _tools.length,
    contextProviderCount: contextProviders.length,
    totalRequests: stats.totalRequests || 0,
    successRate: stats.totalRequests ? Math.round(((stats.successfulRequests || 0) / stats.totalRequests) * 1000) / 10 : 100,
  }]).map(server => ({
    ...server,
    endpoint: server.endpoint || '/api/v1/mcp/rpc',
    tools: server.tools || _tools,
  }))

  const visibleStats = {
    totalServers: stats.totalServers ?? normalizedServers.length,
    connectedServers: stats.connectedServers ?? normalizedServers.filter(s => s.status === 'active' || s.status === 'connected').length,
    totalTools: stats.totalTools ?? _tools.length,
    requestsToday: stats.requestsToday ?? stats.totalRequests ?? 0,
  }

  const filteredServers = normalizedServers.filter((server) =>
    server.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (server.endpoint || '').toLowerCase().includes(searchQuery.toLowerCase())
  )

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
      case 'connected': return 'text-green-400 bg-green-500/20'
      case 'disconnected': return 'text-[var(--muted)] bg-[var(--surface-raised)]'
      case 'error': return 'text-red-400 bg-red-500/20'
      case 'connecting': return 'text-yellow-400 bg-yellow-500/20'
      default: return 'text-[var(--muted)] bg-[var(--surface-raised)]'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
      case 'connected': return <CheckCircle className="h-4 w-4 text-green-400" />
      case 'error': return <XCircle className="h-4 w-4 text-red-400" />
      case 'connecting': return <RefreshCw className="h-4 w-4 text-yellow-400 animate-spin" />
      default: return <AlertTriangle className="h-4 w-4 text-[var(--muted)]" />
    }
  }

  const getEventColor = (event: string) => {
    switch (event) {
      case 'connected': return 'text-green-400'
      case 'disconnected': return 'text-[var(--muted)]'
      case 'error': return 'text-red-400'
      case 'tool_call': return 'text-blue-400'
      case 'heartbeat': return 'text-[var(--muted)]'
      default: return 'text-[var(--muted)]'
    }
  }

  return (
    <MainLayout title="MCP Server Management">
      <Head title="MCP Servers - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--muted)]">Total Servers</p>
                <p className="text-2xl font-bold text-[var(--fg)] mt-1">{visibleStats.totalServers}</p>
              </div>
              <div className="h-12 w-12 rounded-lg bg-blue-500/20 flex items-center justify-center">
                <Server className="h-6 w-6 text-blue-400" />
              </div>
            </div>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--muted)]">Connected</p>
                <p className="text-2xl font-bold text-[var(--fg)] mt-1">{visibleStats.connectedServers}</p>
              </div>
              <div className="h-12 w-12 rounded-lg bg-green-500/20 flex items-center justify-center">
                <CheckCircle className="h-6 w-6 text-green-400" />
              </div>
            </div>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--muted)]">Available Tools</p>
                <p className="text-2xl font-bold text-[var(--fg)] mt-1">{visibleStats.totalTools}</p>
              </div>
              <div className="h-12 w-12 rounded-lg bg-purple-500/20 flex items-center justify-center">
                <Wrench className="h-6 w-6 text-purple-400" />
              </div>
            </div>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--muted)]">Requests Today</p>
                <p className="text-2xl font-bold text-[var(--fg)] mt-1">{visibleStats.requestsToday.toLocaleString()}</p>
              </div>
              <div className="h-12 w-12 rounded-lg bg-yellow-500/20 flex items-center justify-center">
                <Activity className="h-6 w-6 text-yellow-400" />
              </div>
            </div>
          </div>
        </div>

        {/* Search and Add */}
        <div className="flex items-center gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
            <input
              type="text"
              placeholder="Search servers..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[var(--surface)] border border-[var(--border)] rounded-lg pl-10 pr-4 py-2 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
          </div>
        </div>

        {/* Servers List */}
        <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)]">
          <div className="p-6 border-b border-[var(--border)] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Plug className="h-5 w-5 text-primary-400" />
              <h2 className="text-lg font-semibold text-[var(--fg)]">MCP Servers</h2>
            </div>
            <button
              onClick={handleRefreshAll}
              className="flex items-center gap-2 text-sm text-[var(--muted)] hover:text-[var(--fg)]"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh All
            </button>
          </div>

          <div className="divide-y divide-[var(--border)]/50">
            {filteredServers.length === 0 ? (
              <div className="p-12 text-center text-[var(--muted)]">
                <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No MCP endpoint data available</p>
                <p className="text-sm mt-1">The page only shows the configured Tamandua MCP endpoint and observed protocol activity.</p>
              </div>
            ) : (
              filteredServers.map((server) => (
                <div key={server.id} className="p-4">
                  <div
                    onClick={() => setExpandedServer(expandedServer === server.id ? null : server.id)}
                    className="flex items-start gap-4 cursor-pointer"
                  >
                    <div className="mt-1">
                      {expandedServer === server.id ? (
                        <ChevronDown className="h-5 w-5 text-[var(--muted)]" />
                      ) : (
                        <ChevronRight className="h-5 w-5 text-[var(--muted)]" />
                      )}
                    </div>
                    <div className="h-12 w-12 rounded-lg bg-[var(--surface-raised)] flex items-center justify-center">
                      <Server className="h-6 w-6 text-[var(--muted)]" />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-[var(--fg)]">{server.name}</span>
                          {server.version && <span className="text-xs text-[var(--muted)]">v{server.version}</span>}
                        </div>
                        <div className="flex items-center gap-2">
                          {getStatusIcon(server.status)}
                          <span className={cn('text-xs px-2 py-0.5 rounded', getStatusColor(server.status))}>
                            {server.status}
                          </span>
                        </div>
                      </div>
                      <p className="text-sm text-[var(--muted)] font-mono">{server.endpoint}</p>
                      <div className="flex items-center gap-6 mt-2 text-xs text-[var(--muted)]">
                        <span className="flex items-center gap-1">
                          <Wrench className="h-3 w-3" />
                          {(server.tools || []).length || server.toolCount || 0} tools
                        </span>
                        <span className="flex items-center gap-1">
                          <Activity className="h-3 w-3" />
                          {(server.requestsToday ?? server.totalRequests ?? 0).toLocaleString()} requests
                        </span>
                        {(server.errorsToday ?? stats.failedRequests ?? 0) > 0 && (
                          <span className="flex items-center gap-1 text-red-400">
                            <XCircle className="h-3 w-3" />
                            {server.errorsToday ?? stats.failedRequests} errors
                          </span>
                        )}
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {server.latencyMs !== undefined ? `${server.latencyMs}ms latency` : `${server.successRate ?? 100}% success`}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Expanded Tools */}
                  {expandedServer === server.id && (
                    <div className="mt-4 ml-9 pl-4 border-l border-[var(--border)]">
                      <h4 className="text-sm font-medium text-[var(--muted)] mb-3">Available Tools</h4>
                      {(server.tools || []).length === 0 ? (
                        <div className="p-4 text-center text-[var(--muted)]">
                          <p className="text-sm">No MCP tools reported by the server</p>
                        </div>
                      ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {(server.tools || []).map((tool) => (
                            <div
                              key={tool.name}
                              className="bg-[var(--surface-raised)]/50 rounded-lg p-3 border border-[var(--border)]"
                            >
                              <div className="flex items-center justify-between mb-1">
                                <div className="flex items-center gap-2">
                                  <Terminal className="h-4 w-4 text-primary-400" />
                                  <span className="font-mono text-sm text-[var(--fg)]">{tool.name}</span>
                                </div>
                                {tool.usageCount !== undefined && <span className="text-xs text-[var(--muted)]">{tool.usageCount} uses</span>}
                              </div>
                              <p className="text-xs text-[var(--muted)]">{tool.description}</p>
                              {tool.lastUsed && (
                                <p className="text-xs text-[var(--muted)] mt-1">
                                  Last used: {new Date(tool.lastUsed).toLocaleString()}
                                </p>
                              )}
                            </div>
                          ))}
                        </div>
                      )}

                      <div className="flex gap-2 mt-4">
                        <button
                          onClick={() => handleTestConnection(server.id)}
                          disabled={loading === `test-${server.id}`}
                          className="flex items-center gap-2 bg-[var(--surface-raised)] hover:bg-[var(--surface-elevated)] rounded-lg px-3 py-2 text-sm text-[var(--muted)] disabled:opacity-50"
                        >
                          {loading === `test-${server.id}` ? <Loader2 className="h-4 w-4 animate-spin" /> : <Terminal className="h-4 w-4" />}
                          Test Connection
                        </button>
                        <button
                          onClick={() => handleViewSchema(server)}
                          className="flex items-center gap-2 bg-[var(--surface-raised)] hover:bg-[var(--surface-elevated)] rounded-lg px-3 py-2 text-sm text-[var(--muted)]"
                        >
                          <FileText className="h-4 w-4" />
                          View Schema
                        </button>
                      </div>
                      {schemaServer?.id === server.id && (
                        <div className="mt-4 bg-[var(--surface-inset)] rounded-lg p-4 border border-[var(--border)]">
                          <h4 className="text-sm font-medium text-[var(--fg)] mb-2">Tool Schemas</h4>
                          <pre className="text-xs text-[var(--muted)] overflow-x-auto max-h-64 overflow-y-auto">
                            {JSON.stringify((server.tools || []).map(t => ({ name: t.name, description: t.description, inputSchema: t.inputSchema, requiredPermissions: t.requiredPermissions })), null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Context Providers */}
        <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)]">
          <div className="p-6 border-b border-[var(--border)] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="h-5 w-5 text-purple-400" />
              <h2 className="text-lg font-semibold text-[var(--fg)]">Context Providers</h2>
            </div>
          </div>
          <div className="divide-y divide-[var(--border)]/50 max-h-[250px] overflow-y-auto">
            {contextProviders.length === 0 ? (
              <div className="p-8 text-center text-[var(--muted)]">
                <Server className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p className="text-sm">No context providers configured</p>
              </div>
            ) : (
              contextProviders.map((provider) => (
                <div key={provider.id || provider.name} className="p-4 hover:bg-[var(--surface-raised)]/30 transition-colors">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium text-[var(--fg)]">{provider.name}</span>
                    {provider.status && (
                      <span className={cn(
                        'text-xs px-2 py-0.5 rounded',
                        provider.status === 'active' ? 'bg-green-500/20 text-green-400' :
                        'bg-[var(--surface-raised)] text-[var(--muted)]'
                      )}>
                        {provider.status}
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-[var(--muted)]">{provider.description || provider.type || 'MCP context provider'}</p>
                  {provider.resourceCount !== undefined && (
                    <p className="text-xs text-[var(--muted)] mt-1">{provider.resourceCount} resources</p>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Connection Logs */}
        <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)]">
          <div
            onClick={() => setShowLogs(!showLogs)}
            className="p-6 border-b border-[var(--border)] flex items-center justify-between cursor-pointer"
          >
            <div className="flex items-center gap-2">
              <FileText className="h-5 w-5 text-primary-400" />
              <h2 className="text-lg font-semibold text-[var(--fg)]">Connection Logs</h2>
            </div>
            {showLogs ? (
              <ChevronDown className="h-5 w-5 text-[var(--muted)]" />
            ) : (
              <ChevronRight className="h-5 w-5 text-[var(--muted)]" />
            )}
          </div>

          {showLogs && (
            <div className="divide-y divide-[var(--border)]/50 max-h-[300px] overflow-y-auto">
              {connectionLogs.length === 0 ? (
                <div className="p-12 text-center text-[var(--muted)]">
                  <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No connection logs available</p>
                </div>
              ) : (
                connectionLogs.map((log) => {
                  const event = log.event || (log.method ? 'tool_call' : 'heartbeat')
                  const message = log.message || log.method || log.status || 'MCP request'
                  return (
                  <div key={log.id} className="p-3 hover:bg-[var(--surface-raised)]/30 transition-colors">
                    <div className="flex items-center gap-4">
                      <span className="text-xs text-[var(--muted)] font-mono w-32">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </span>
                      <span className={cn('text-xs font-medium w-20', getEventColor(event))}>
                        {event.toUpperCase()}
                      </span>
                      <span className="text-sm text-[var(--muted)]">{log.serverName || log.clientId || 'mcp-client'}</span>
                      <span className="text-sm text-[var(--muted)]">{message}</span>
                      {log.durationMs !== undefined && (
                        <span className="text-xs text-[var(--muted)] font-mono">{log.durationMs}ms</span>
                      )}
                      {log.details && (
                        <span className="text-xs text-[var(--muted)] font-mono">
                          {JSON.stringify(log.details)}
                        </span>
                      )}
                    </div>
                  </div>
                )})
              )}
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  )
}
