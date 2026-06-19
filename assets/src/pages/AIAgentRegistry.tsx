import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Bot,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Activity,
  Settings,
  FileText,
  Database,
  Globe,
  ChevronRight,
  Search,
  RefreshCw,
} from 'lucide-react'
import { cn, safeCapitalize } from '@/lib/utils'
import { useState } from 'react'
import { Select, SelectItem } from '@/components/ui/baseui'

// Types
interface AIAgent {
  id: string
  name: string
  description: string
  type: 'llm_chain' | 'rag_agent' | 'autonomous' | 'workflow' | 'assistant'
  status: 'active' | 'inactive' | 'suspended' | 'error'
  riskLevel: 'critical' | 'high' | 'medium' | 'low'
  riskScore?: number
  approved?: boolean
  owner: string
  department: string
  createdAt: string
  lastActive: string
  permissions: Permission[]
  activityCount24h: number
  errorCount24h: number
}

interface Permission {
  id: string
  name: string
  category: 'data' | 'network' | 'system' | 'ai'
  granted: boolean
  lastUsed?: string
}

interface ActivityLog {
  id: string
  agentId: string
  agentName: string
  action: string
  resource: string
  status: 'success' | 'failure' | 'blocked'
  timestamp: string
  details?: string
  riskScore?: number
}

interface AIAgentRegistryProps {
  agents: AIAgent[]
  permissions: Permission[]
  activityLogs: ActivityLog[]
}

export default function AgentRegistry({ agents, permissions: _permissions, activityLogs }: AIAgentRegistryProps) {
  const [selectedAgent, setSelectedAgent] = useState<AIAgent | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const normalizedAgents = agents.map((agent) => normalizeAgent(agent))
  const normalizedActivityLogs = activityLogs.map((log) => normalizeActivityLog(log))

  const stats = {
    totalAgents: normalizedAgents.length,
    activeAgents: normalizedAgents.filter(a => a.status === 'active').length,
    highRiskAgents: normalizedAgents.filter(a => a.riskLevel === 'critical' || a.riskLevel === 'high').length,
    blockedActions24h: normalizedActivityLogs.filter(l => l.status === 'blocked').length,
  }

  const filteredAgents = normalizedAgents.filter(agent => {
    const matchesSearch = agent.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      agent.department.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesStatus = statusFilter === 'all' || agent.status === statusFilter
    return matchesSearch && matchesStatus
  })

  const handleRefresh = () => {
    router.reload()
  }

  return (
    <MainLayout title="AI Agent Registry">
      <Head title="AI Agent Registry - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            title="Total Agents"
            value={stats.totalAgents}
            icon={Bot}
            color="primary"
          />
          <StatCard
            title="Active Agents"
            value={stats.activeAgents}
            icon={Activity}
            color="primary"
          />
          <StatCard
            title="High Risk Agents"
            value={stats.highRiskAgents}
            icon={AlertTriangle}
            color="danger"
          />
          <StatCard
            title="Blocked Actions (24h)"
            value={stats.blockedActions24h}
            icon={Shield}
            color="warning"
          />
        </div>

        {/* Search and Filters */}
        <div className="flex gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" style={{ color: 'var(--muted)' }} />
            <input
              type="text"
              placeholder="Search agents..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full rounded-lg pl-10 pr-4 py-2 placeholder-[var(--subtle)] focus:ring-2 focus:ring-primary-500 focus:border-transparent"
              style={{ background: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--fg)' }}
            />
          </div>
          <Select
            value={statusFilter}
            onValueChange={setStatusFilter}
            placeholder="All Status"
            className="rounded-lg px-4 py-2 focus:ring-2 focus:ring-primary-500"
          >
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="inactive">Inactive</SelectItem>
            <SelectItem value="suspended">Suspended</SelectItem>
            <SelectItem value="error">Error</SelectItem>
          </Select>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Agents Table */}
          <div className="lg:col-span-2 card-sentinel rounded-xl">
            <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Registered Agents</h2>
            </div>
            <div style={{ borderColor: 'var(--border)' }}>
              {filteredAgents.length === 0 ? (
                <div className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                  <Bot className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p className="text-lg font-medium mb-1">No AI agents observed</p>
                  <p className="text-sm">Agent governance data appears after AI agents or data flows are reported.</p>
                </div>
              ) : filteredAgents.map((agent) => (
                <AgentRow
                  key={agent.id}
                  agent={agent}
                  isSelected={selectedAgent?.id === agent.id}
                  onSelect={() => setSelectedAgent(agent)}
                />
              ))}
            </div>
          </div>

          {/* Agent Details / Permissions */}
          <div className="space-y-6">
            {selectedAgent ? (
              <>
                <AgentDetails agent={selectedAgent} />
                <PermissionsMatrix permissions={selectedAgent.permissions} />
              </>
            ) : (
              <div className="card-sentinel rounded-xl p-8 text-center">
                <Bot className="h-12 w-12 mx-auto mb-4" style={{ color: 'var(--subtle)' }} />
                <p style={{ color: 'var(--muted)' }}>Select an agent to view details</p>
              </div>
            )}
          </div>
        </div>

        {/* Activity Logs */}
        <div className="card-sentinel rounded-xl">
          <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
            <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Recent Activity</h2>
            <button
              onClick={handleRefresh}
              className="flex items-center gap-2 text-sm text-primary-400 hover:text-primary-300"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Time</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Agent</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Action</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Resource</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Status</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Risk</th>
                  <th className="text-left p-4 text-sm font-medium" style={{ color: 'var(--muted)' }}>Details</th>
                </tr>
              </thead>
              <tbody>
                {normalizedActivityLogs.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="p-12 text-center" style={{ color: 'var(--subtle)' }}>
                      No AI agent activity recorded
                    </td>
                  </tr>
                ) : normalizedActivityLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--hairline)' }}>
                    <td className="p-4 text-sm" style={{ color: 'var(--muted)' }}>
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="p-4 text-sm" style={{ color: 'var(--fg)' }}>{log.agentName}</td>
                    <td className="p-4">
                      <span className="text-sm font-mono" style={{ color: 'var(--fg-2)' }}>{log.action}</span>
                    </td>
                    <td className="p-4 text-sm" style={{ color: 'var(--fg-2)' }}>{log.resource}</td>
                    <td className="p-4">
                      <StatusBadge status={log.status} />
                    </td>
                    <td className="p-4">
                      {log.riskScore !== undefined && (
                        <RiskBadge score={log.riskScore} />
                      )}
                    </td>
                    <td className="p-4 text-sm max-w-xs truncate" style={{ color: 'var(--muted)' }}>
                      {log.details || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </MainLayout>
  )
}

// Helper Components
function normalizeAgent(agent: AIAgent): AIAgent {
  const rawPermissions = agent.permissions as Permission[] | { dataAccess?: string[]; toolAccess?: string[]; apiScopes?: string[] } | undefined
  const permissions = Array.isArray(rawPermissions)
    ? rawPermissions
    : [
        ...(rawPermissions?.dataAccess || []).map((name) => ({ id: `data-${name}`, name, category: 'data' as const, granted: true })),
        ...(rawPermissions?.toolAccess || []).map((name) => ({ id: `tool-${name}`, name, category: 'system' as const, granted: true })),
        ...(rawPermissions?.apiScopes || []).map((name) => ({ id: `api-${name}`, name, category: 'ai' as const, granted: true })),
      ]
  const riskScore = agent.riskScore ?? 0
  const riskLevel = agent.riskLevel || (riskScore >= 80 ? 'critical' : riskScore >= 60 ? 'high' : riskScore >= 30 ? 'medium' : 'low')

  return {
    ...agent,
    description: agent.description || `${agent.vendor || 'AI'} agent observed by posture telemetry`,
    type: agent.type || 'assistant',
    status: agent.status || 'inactive',
    riskLevel,
    owner: agent.owner || 'Unknown',
    department: agent.department || 'Unassigned',
    createdAt: agent.createdAt || (agent as AIAgent & { registeredAt?: string }).registeredAt || '',
    lastActive: agent.lastActive || (agent as AIAgent & { lastSeenAt?: string }).lastSeenAt || '',
    permissions,
    activityCount24h: agent.activityCount24h || 0,
    errorCount24h: agent.errorCount24h || 0,
  }
}

function normalizeActivityLog(log: ActivityLog): ActivityLog {
  return {
    ...log,
    agentName: log.agentName || (log as ActivityLog & { agentId?: string }).agentId || 'Unknown agent',
    action: log.action || 'data_flow',
    resource: log.resource || 'AI resource',
    status: log.status || 'success',
    timestamp: log.timestamp || new Date().toISOString(),
  }
}

interface StatCardProps {
  title: string
  value: number
  icon: React.ElementType
  color: 'primary' | 'danger' | 'warning'
}

function StatCard({ title, value, icon: Icon, color }: StatCardProps) {
  const colorClasses = {
    primary: 'bg-primary-600/20 text-primary-400',
    danger: 'bg-red-500/20 text-red-400',
    warning: 'bg-yellow-500/20 text-yellow-400',
  }

  return (
    <div className="card-sentinel rounded-xl p-4">
      <div className="flex items-center justify-between">
        <div className={cn('p-2 rounded-lg', colorClasses[color])}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      <div className="mt-4">
        <span className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>{value}</span>
        <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>{title}</p>
      </div>
    </div>
  )
}

function AgentRow({
  agent,
  isSelected,
  onSelect,
}: {
  agent: AIAgent
  isSelected: boolean
  onSelect: () => void
}) {
  const typeIcons = {
    llm_chain: Bot,
    rag_agent: Database,
    autonomous: Activity,
    workflow: Settings,
    assistant: FileText,
  }
  const TypeIcon = typeIcons[agent.type]

  const statusColors = {
    active: 'bg-green-500',
    inactive: 'bg-[var(--subtle)]',
    suspended: 'bg-yellow-500',
    error: 'bg-red-500',
  }

  const riskColors = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-yellow-400',
    low: 'text-green-400',
  }

  return (
    <button
      onClick={onSelect}
      className={cn(
        'w-full p-4 flex items-center gap-4 transition-colors text-left',
        isSelected ? 'bg-primary-500/10' : 'hover:bg-[var(--surface-2)]'
      )}
      style={{ borderBottom: '1px solid var(--hairline)' }}
    >
      <div className="p-2 rounded-lg" style={{ background: 'var(--surface-2)' }}>
        <TypeIcon className="h-5 w-5 text-primary-400" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium truncate" style={{ color: 'var(--fg)' }}>{agent.name}</span>
          <span className={cn('h-2 w-2 rounded-full', statusColors[agent.status])} />
        </div>
        <p className="text-xs truncate" style={{ color: 'var(--muted)' }}>{agent.department} - {agent.owner}</p>
      </div>
      <div className="text-right">
        <span className={cn('text-xs font-medium uppercase', riskColors[agent.riskLevel])}>
          {agent.riskLevel}
        </span>
        <p className="text-xs mt-0.5" style={{ color: 'var(--subtle)' }}>{agent.activityCount24h} actions</p>
      </div>
      <ChevronRight className="h-4 w-4" style={{ color: 'var(--subtle)' }} />
    </button>
  )
}

function AgentDetails({ agent }: { agent: AIAgent }) {
  const statusColors = {
    active: 'bg-green-500/20 text-green-400',
    inactive: 'bg-[var(--surface-2)] text-[var(--muted)]',
    suspended: 'bg-yellow-500/20 text-yellow-400',
    error: 'bg-red-500/20 text-red-400',
  }

  return (
    <div className="card-sentinel rounded-xl">
      <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
        <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{agent.name}</h3>
      </div>
      <div className="p-4 space-y-4">
        <div>
          <span className={cn('inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium', statusColors[agent.status])}>
            {safeCapitalize(agent.status)}
          </span>
        </div>
        <p className="text-sm" style={{ color: 'var(--fg-2)' }}>{agent.description}</p>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span style={{ color: 'var(--muted)' }}>Type:</span>
            <span className="ml-2 capitalize" style={{ color: 'var(--fg)' }}>{agent.type.replace('_', ' ')}</span>
          </div>
          <div>
            <span style={{ color: 'var(--muted)' }}>Owner:</span>
            <span className="ml-2" style={{ color: 'var(--fg)' }}>{agent.owner}</span>
          </div>
          <div>
            <span style={{ color: 'var(--muted)' }}>Department:</span>
            <span className="ml-2" style={{ color: 'var(--fg)' }}>{agent.department}</span>
          </div>
          <div>
            <span style={{ color: 'var(--muted)' }}>Risk Level:</span>
            <span className={cn(
              'ml-2 uppercase font-medium',
              agent.riskLevel === 'critical' ? 'text-red-400' :
              agent.riskLevel === 'high' ? 'text-orange-400' :
              agent.riskLevel === 'medium' ? 'text-yellow-400' : 'text-green-400'
            )}>
              {agent.riskLevel}
            </span>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4 pt-4" style={{ borderTop: '1px solid var(--border)' }}>
          <div className="text-center p-3 rounded-lg" style={{ background: 'var(--surface-2)' }}>
            <div className="text-xl font-bold" style={{ color: 'var(--fg)' }}>{agent.activityCount24h}</div>
            <div className="text-xs" style={{ color: 'var(--muted)' }}>Actions (24h)</div>
          </div>
          <div className="text-center p-3 rounded-lg" style={{ background: 'var(--surface-2)' }}>
            <div className={cn(
              'text-xl font-bold',
              agent.errorCount24h > 10 ? 'text-red-400' :
              agent.errorCount24h > 0 ? 'text-yellow-400' : 'text-green-400'
            )}>
              {agent.errorCount24h}
            </div>
            <div className="text-xs" style={{ color: 'var(--muted)' }}>Errors (24h)</div>
          </div>
        </div>
      </div>
    </div>
  )
}

function PermissionsMatrix({ permissions }: { permissions: Permission[] }) {
  const categoryIcons = {
    data: Database,
    network: Globe,
    system: Settings,
    ai: Bot,
  }

  return (
    <div className="card-sentinel rounded-xl">
      <div className="p-4" style={{ borderBottom: '1px solid var(--border)' }}>
        <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Permissions</h3>
      </div>
      <div className="p-4 space-y-3">
        {permissions.map((permission) => {
          const CategoryIcon = categoryIcons[permission.category]
          return (
            <div
              key={permission.id}
              className={cn(
                'flex items-center justify-between p-3 rounded-lg',
                permission.granted ? 'bg-[var(--surface-2)]' : 'bg-[var(--bg-2)]'
              )}
            >
              <div className="flex items-center gap-3">
                <CategoryIcon className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                <div>
                  <span className="text-sm" style={{ color: 'var(--fg)' }}>{permission.name}</span>
                  {permission.lastUsed && (
                    <p className="text-xs" style={{ color: 'var(--subtle)' }}>
                      Last used: {new Date(permission.lastUsed).toLocaleDateString()}
                    </p>
                  )}
                </div>
              </div>
              {permission.granted ? (
                <CheckCircle className="h-5 w-5 text-green-400" />
              ) : (
                <XCircle className="h-5 w-5 text-red-400" />
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function StatusBadge({ status }: { status: ActivityLog['status'] }) {
  return (
    <span className={cn(
      'inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium',
      status === 'success' && 'bg-green-500/20 text-green-400',
      status === 'failure' && 'bg-red-500/20 text-red-400',
      status === 'blocked' && 'bg-orange-500/20 text-orange-400'
    )}>
      {status === 'success' && <CheckCircle className="h-3 w-3" />}
      {status === 'failure' && <XCircle className="h-3 w-3" />}
      {status === 'blocked' && <Shield className="h-3 w-3" />}
      {safeCapitalize(status)}
    </span>
  )
}

function RiskBadge({ score }: { score: number }) {
  return (
    <div className="flex items-center gap-2">
      <div className="w-12 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--surface-2)' }}>
        <div
          className={cn(
            'h-full rounded-full',
            score > 70 ? 'bg-red-500' : score > 40 ? 'bg-yellow-500' : 'bg-green-500'
          )}
          style={{ width: `${score}%` }}
        />
      </div>
      <span className={cn(
        'text-xs font-medium',
        score > 70 ? 'text-red-400' : score > 40 ? 'text-yellow-400' : 'text-green-400'
      )}>
        {score}
      </span>
    </div>
  )
}
