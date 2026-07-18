import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Terminal,
  Search,
  Play,
  Code,
  Save,
  Clock,
  Bookmark,
  Copy,
  ChevronRight,
  Sparkles,
  FileText,
  Download,
  RefreshCw,
  Trash2,
  Lightbulb,
  Edit3,
  Bot,
  Zap,
  AlertCircle,
  CheckCircle,
  Cpu,
  Globe,
  Server,
} from 'lucide-react'
import { useState, useEffect, useCallback } from 'react'
import { toast } from 'sonner'
import { cn } from '@/lib/utils'
import { logger } from '@/lib/logger'

function getCsrfToken(): string {
  const metaToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
  if (metaToken) return metaToken

  const cookie = document.cookie
    .split('; ')
    .find(row => row.startsWith('XSRF-TOKEN='))
    ?.split('=')[1]

  return cookie ? decodeURIComponent(cookie) : ''
}

async function readJsonResponse(response: Response): Promise<any> {
  const text = await response.text()
  if (!text) return {}

  try {
    return JSON.parse(text)
  } catch {
    return { error: text }
  }
}

function normalizeQueryResults(rawResults: unknown): QueryResult[] {
  if (!Array.isArray(rawResults)) return []

  return rawResults.map((item, index) => {
    const row = (item || {}) as Record<string, any>
    const details = row.details && typeof row.details === 'object' ? row.details : row

    return {
      id: String(row.id || row.event_id || `result-${index}`),
      agent_id: String(row.agent_id || row.agentId || details.agent_id || ''),
      timestamp: String(row.timestamp || row.inserted_at || new Date().toISOString()),
      hostname: String(row.hostname || row.agent_hostname || row.host || 'unknown-host'),
      event_type: String(row.event_type || row.type || row.category || 'event'),
      severity: String(row.severity || row.level || 'medium').toLowerCase(),
      details,
    }
  })
}

interface QueryResult {
  id: string
  agent_id?: string
  timestamp: string
  hostname: string
  event_type: string
  severity: string
  details: Record<string, unknown>
}

interface ProcessContextNode {
  pid: number
  ppid?: number
  name?: string
  path?: string
  cmdline?: string
  user?: string
  sha256?: string
  signer?: string
}

interface ProcessContextResponse {
  process?: ProcessContextNode
  ancestors?: ProcessContextNode[]
  chain?: ProcessContextNode[]
}

interface ResultContext {
  payload: Record<string, unknown>
  pid?: number
  processName?: string
  processPath?: string
  commandLine?: string
  parentPid?: number
  parentName?: string
  user?: string
  sha256?: string
  remoteIp?: string
  remotePort?: number
  localIp?: string
  localPort?: number
  protocol?: string
  direction?: string
  domain?: string
  sni?: string
  resolverLabel?: string
  classification?: string
  confidence?: 'confirmed' | 'candidate'
  evidence: string[]
  gaps: string[]
}

interface SavedQuery {
  id: string
  name: string
  naturalQuery: string
  translatedQuery: string
  queryType: 'kql' | 'sql' | 'sigma'
  createdAt: string
  lastRun?: string
}

interface HuntSession {
  id: string
  name: string
  createdAt: string
  queries: number
  findings: number
}

interface SuggestedHypothesis {
  id: string
  title: string
  description: string
  query: string
  category: string
}

interface NLHuntPageProps {
  sessions?: HuntSession[]
  savedQueries?: SavedQuery[]
  suggestedHypotheses?: SuggestedHypothesis[]
}

export default function NLHunt({
  sessions = [],
  savedQueries = [],
  suggestedHypotheses = [],
}: NLHuntPageProps) {
  const [naturalQuery, setNaturalQuery] = useState('')
  const [translatedQuery, setTranslatedQuery] = useState('')
  const [editableQuery, setEditableQuery] = useState('')
  const [isEditingQuery, setIsEditingQuery] = useState(false)
  const [queryType, setQueryType] = useState<'kql' | 'sql' | 'sigma'>('kql')
  const [isTranslating, setIsTranslating] = useState(false)
  const [isRunning, setIsRunning] = useState(false)
  const [results, setResults] = useState<QueryResult[]>([])
  const [showSavedQueries, setShowSavedQueries] = useState(true)
  const [translationSource, setTranslationSource] = useState<'llm' | 'pattern' | null>(null)
  const [translationError, setTranslationError] = useState<string | null>(null)
  const [processContexts, setProcessContexts] = useState<Record<string, ProcessContextResponse>>({})

  const handleTranslate = useCallback(async () => {
    if (!naturalQuery.trim()) return
    setIsTranslating(true)
    setTranslationSource(null)
    setTranslationError(null)
    setIsEditingQuery(false)

    try {
      const response = await fetch('/api/v1/nl-hunt/query', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
        body: JSON.stringify({
          query: naturalQuery,
          output_format: queryType,
          include_context: false,
        })
      })

      if (!response.ok) {
        const errorData = await readJsonResponse(response)
        logger.error('Translation failed:', errorData)
        const errorMsg = errorData.message || errorData.error || 'Translation failed'
        setTranslationError(errorMsg)
        setTranslatedQuery('')
        setTranslationSource(null)
        toast.error('Translation failed', {
          description: errorMsg,
          icon: <AlertCircle className="h-4 w-4" />,
        })
        return
      }

      const data = await readJsonResponse(response)
      const translated = data.data?.translated_query || ''

      if (!translated) {
        setTranslationError('No translation returned')
        toast.error('Translation returned empty result')
        return
      }

      setTranslatedQuery(translated)
      setEditableQuery(translated)
      setTranslationError(null)

      // Capture translation source from backend response
      const source = data.data?.translation_source
      const isLLM = source === 'llm' || source === 'gpt'
      setTranslationSource(isLLM ? 'llm' : 'pattern')

      toast.success('Query translated', {
        description: isLLM ? 'Translated using GPT-4' : 'Translated using pattern matching',
        icon: isLLM ? <Bot className="h-4 w-4" /> : <Zap className="h-4 w-4" />,
      })
    } catch (error) {
      logger.error('Translation error:', error)
      const errorMsg = error instanceof Error ? error.message : 'Network error'
      setTranslationError(errorMsg)
      setTranslatedQuery('')
      setTranslationSource(null)
      toast.error('Translation failed', {
        description: 'Could not connect to server',
        icon: <AlertCircle className="h-4 w-4" />,
      })
    } finally {
      setIsTranslating(false)
    }
  }, [naturalQuery, queryType])

  const handleStartEditing = () => {
    setEditableQuery(translatedQuery)
    setIsEditingQuery(true)
  }

  const handleSaveEdit = () => {
    setTranslatedQuery(editableQuery)
    setIsEditingQuery(false)
    toast.success('Query updated', {
      icon: <CheckCircle className="h-4 w-4" />,
      duration: 2000,
    })
  }

  const handleCancelEdit = () => {
    setEditableQuery(translatedQuery)
    setIsEditingQuery(false)
  }

  const handleRunQuery = async () => {
    if (!translatedQuery.trim()) return
    setIsRunning(true)
    setTranslationError(null)

    try {
      const response = await fetch('/api/v1/nl-hunt/query', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
        body: JSON.stringify({
          query: naturalQuery,
          translated_query: translatedQuery,
          output_format: queryType,
          execute: true,
        }),
      })

      const data = await readJsonResponse(response)

      if (!response.ok) {
        const errorMsg = data.message || data.error || 'Query execution failed'
        setTranslationError(errorMsg)
        toast.error('Query execution failed', {
          description: errorMsg,
          icon: <AlertCircle className="h-4 w-4" />,
        })
        return
      }

      const backendResults = data.data?.results || data.results || []
      setResults(normalizeQueryResults(backendResults))
      toast.success('Query executed', {
        description: `${Array.isArray(backendResults) ? backendResults.length : 0} result(s) returned`,
        icon: <CheckCircle className="h-4 w-4" />,
      })
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Network error'
      logger.error('Query execution error:', error)
      setTranslationError(errorMsg)
      toast.error('Query execution failed', {
        description: 'Could not connect to server',
        icon: <AlertCircle className="h-4 w-4" />,
      })
    } finally {
      setIsRunning(false)
    }
  }

  const loadSavedQuery = (query: SavedQuery) => {
    setNaturalQuery(query.naturalQuery)
    setTranslatedQuery(query.translatedQuery)
    setQueryType(query.queryType)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/20'
      case 'high': return 'text-orange-400 bg-orange-500/20'
      case 'medium': return 'text-yellow-400 bg-yellow-500/20'
      case 'low': return 'text-blue-400 bg-blue-500/20'
      default: return 'text-[var(--muted)] bg-[var(--surface)]'
    }
  }

  const detailPayload = (details: Record<string, unknown>): Record<string, unknown> => {
    const nested = details.payload
    return nested && typeof nested === 'object' && !Array.isArray(nested)
      ? nested as Record<string, unknown>
      : details
  }

  const valueFrom = (source: Record<string, unknown>, keys: string[]) => {
    for (const key of keys) {
      const value = source[key]
      if (value !== undefined && value !== null && value !== '') return value
    }
    return undefined
  }

  const asText = (value: unknown): string | undefined => {
    if (typeof value === 'string' && value.trim()) return value.trim()
    if (typeof value === 'number' && Number.isFinite(value)) return String(value)
    return undefined
  }

  const asNumber = (value: unknown): number | undefined => {
    if (typeof value === 'number' && Number.isFinite(value)) return value
    if (typeof value === 'string') {
      const parsed = Number(value)
      if (Number.isFinite(parsed)) return parsed
    }
    return undefined
  }

  const isPidOnlyProcess = (value?: string) => !value || /^pid:\d+$/i.test(value)

  const resolverName = (ip?: string) => {
    const resolvers: Record<string, string> = {
      '8.8.8.8': 'Google Public DNS',
      '8.8.4.4': 'Google Public DNS',
      '1.1.1.1': 'Cloudflare DNS',
      '1.0.0.1': 'Cloudflare DNS',
      '9.9.9.9': 'Quad9 DNS',
      '149.112.112.112': 'Quad9 DNS',
      '208.67.222.222': 'OpenDNS',
      '208.67.220.220': 'OpenDNS',
    }
    return ip ? resolvers[ip] : undefined
  }

  const resultContext = (result: QueryResult): ResultContext => {
    const details = result.details || {}
    const payload = detailPayload(details)
    const pid = asNumber(valueFrom(payload, ['pid', 'process_pid', 'process_id']) ?? valueFrom(details, ['pid', 'process_id']))
    const correlated = processContexts[result.id]?.process
    const correlatedParent = processContexts[result.id]?.ancestors?.[0]
    const rawProcessName = asText(valueFrom(payload, ['process_name', 'name', 'image', 'exe_name']) ?? valueFrom(details, ['process_name', 'name']))
    const processName = (isPidOnlyProcess(rawProcessName) ? undefined : rawProcessName) || correlated?.name
    const processPath = asText(valueFrom(payload, ['process_path', 'path', 'image_path', 'exe_path', 'executable_path'])) || correlated?.path
    const commandLine = asText(valueFrom(payload, ['command_line', 'cmdline', 'command'])) || correlated?.cmdline
    const parentPid = asNumber(valueFrom(payload, ['ppid', 'parent_pid', 'parent_process_id'])) || correlatedParent?.pid || correlated?.ppid
    const parentName = asText(valueFrom(payload, ['parent_name', 'parent_process_name', 'parent_image'])) || correlatedParent?.name
    const user = asText(valueFrom(payload, ['user', 'username', 'user_name', 'account_name'])) || correlated?.user
    const sha256 = asText(valueFrom(payload, ['sha256', 'process_sha256', 'file_sha256', 'hash_sha256'])) || correlated?.sha256
    const remoteIp = asText(valueFrom(payload, ['remote_ip', 'dst_ip', 'destination_ip']) ?? valueFrom(details, ['remote_ip']))
    const remotePort = asNumber(valueFrom(payload, ['remote_port', 'dst_port', 'destination_port']) ?? valueFrom(details, ['remote_port']))
    const localIp = asText(valueFrom(payload, ['local_ip', 'src_ip', 'source_ip']))
    const localPort = asNumber(valueFrom(payload, ['local_port', 'src_port', 'source_port']))
    const protocol = asText(valueFrom(payload, ['protocol', 'transport']))
    const direction = asText(valueFrom(payload, ['direction']))
    const domain = asText(valueFrom(payload, ['domain', 'query', 'query_name', 'remote_domain', 'host', 'hostname']))
    const sni = asText(valueFrom(payload, ['sni', 'tls_sni', 'server_name']))
    const resolverLabel = resolverName(remoteIp)
    const isNetwork = result.event_type.includes('network')
    const isEncrypted = valueFrom(payload, ['is_encrypted']) === true || remotePort === 443
    const isDohCandidate = isNetwork && remotePort === 443 && Boolean(resolverLabel || /dns|doh/i.test(domain || sni || ''))

    const evidence: string[] = []
    const gaps: string[] = []
    if (remoteIp) evidence.push(`remote_ip=${remoteIp}`)
    if (remotePort) evidence.push(`remote_port=${remotePort}`)
    if (protocol) evidence.push(`protocol=${protocol}`)
    if (isEncrypted) evidence.push('encrypted transport observed')
    if (resolverLabel) evidence.push(`known resolver: ${resolverLabel}`)
    if (domain) evidence.push(`domain=${domain}`)
    if (sni) evidence.push(`sni=${sni}`)
    if (processName) evidence.push(`process=${processName}`)
    if (processPath) evidence.push(correlated?.path === processPath ? 'binary path correlated from process tree' : 'binary path present')
    if (sha256) evidence.push(correlated?.sha256 === sha256 ? 'hash correlated from process tree' : 'hash present')

    if (isNetwork && !domain && !sni) gaps.push('no domain/SNI captured')
    if (isNetwork && !processName) gaps.push(rawProcessName ? 'process name is PID-only' : 'process name missing')
    if (isNetwork && !processPath) gaps.push('binary path missing')
    if (isNetwork && !sha256) gaps.push('binary hash missing')
    if (isNetwork && !parentPid && !parentName) gaps.push('parent process missing')
    if (isDohCandidate && !domain && !sni) gaps.push('DoH inferred from resolver IP/port')

    return {
      payload,
      pid,
      processName,
      processPath,
      commandLine,
      parentPid,
      parentName,
      user,
      sha256,
      remoteIp,
      remotePort,
      localIp,
      localPort,
      protocol,
      direction,
      domain,
      sni,
      resolverLabel,
      classification: isDohCandidate ? 'DoH candidate' : undefined,
      confidence: isDohCandidate ? (domain || sni ? 'confirmed' : 'candidate') : undefined,
      evidence,
      gaps,
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard', {
      icon: <CheckCircle className="h-4 w-4" />,
      duration: 2000,
    })
  }

  const translationWarnings = () => {
    const warnings: string[] = []
    const natural = naturalQuery.toLowerCase()
    const translated = translatedQuery.toLowerCase()

    if ((natural.includes('doh') || natural.includes('dns over https')) && /xyz|top|tk|ml/.test(translated)) {
      warnings.push('DoH request translated with suspicious-TLD DNS regex; verify this was intended.')
    }

    if (translatedQuery && translationSource === 'pattern') {
      warnings.push('Pattern translation is heuristic; treat returned matches as candidate evidence.')
    }

    return warnings
  }

  useEffect(() => {
    const candidates = results
      .map(result => {
        const details = result.details || {}
        const payload = detailPayload(details)
        const agentId = result.agent_id || asText(details.agent_id) || asText(details.agentId)
        const pid = asNumber(valueFrom(payload, ['pid', 'process_pid', 'process_id']) ?? valueFrom(details, ['pid', 'process_id']))
        return { result, agentId: agentId && agentId !== 'undefined' ? agentId : undefined, pid }
      })
      .filter(item => item.agentId && item.pid && !processContexts[item.result.id])

    if (candidates.length === 0) return

    let cancelled = false

    const loadContexts = async () => {
      const loaded: Record<string, ProcessContextResponse> = {}

      await Promise.all(candidates.slice(0, 20).map(async ({ result, agentId, pid }) => {
        try {
          const response = await fetch(`/api/v1/agents/${encodeURIComponent(agentId!)}/processes/${pid}/context`, {
            credentials: 'same-origin',
          })
          if (!response.ok) return
          const data = await readJsonResponse(response)
          if (data?.data) loaded[result.id] = data.data
        } catch (error) {
          logger.log('Process context unavailable for hunt result:', error)
        }
      }))

      if (!cancelled && Object.keys(loaded).length > 0) {
        setProcessContexts(prev => ({ ...prev, ...loaded }))
      }
    }

    loadContexts()

    return () => {
      cancelled = true
    }
  }, [results, processContexts])

  // Keyboard shortcut: Ctrl+Enter to translate
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && naturalQuery.trim() && !isTranslating) {
        e.preventDefault()
        handleTranslate()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [naturalQuery, isTranslating, handleTranslate])

  // Default suggested queries when none provided from backend
  const defaultSuggestedQueries = [
    'Find all failed login attempts in the last hour',
    'Show processes that spawned cmd.exe from Office applications',
    'Detect network connections to known malicious IPs',
  ]

  const suggestedQueries = suggestedHypotheses.length > 0
    ? suggestedHypotheses.map(h => h.query)
    : defaultSuggestedQueries

  return (
    <MainLayout title="Natural Language Hunt">
      <Head title="NL Hunt - Tamandua EDR" />

      <div className="space-y-6">
        {/* Query Input */}
        <div className="card-sentinel rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-primary-400" />
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>AI-Powered Query Builder</h2>
            </div>
            {/* AI-Powered Badge */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full" style={{ background: 'rgba(217, 70, 239, 0.15)', border: '1px solid var(--sol-magenta)' }}>
              <Bot className="h-4 w-4" style={{ color: 'var(--sol-magenta)' }} />
              <span className="text-xs font-medium" style={{ color: 'var(--sol-magenta)' }}>
                GPT-Powered Translation
              </span>
            </div>
          </div>

          <div className="space-y-4">
            {/* Natural Language Input */}
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Zap className="h-4 w-4" style={{ color: 'var(--sol-magenta)' }} />
                <span className="text-xs font-medium" style={{ color: 'var(--sol-magenta)' }}>
                  AI-Powered Query Translation
                </span>
              </div>
              <label className="block text-sm font-medium mb-2" style={{ color: 'var(--muted)' }}>
                Describe what you want to find
              </label>
              <div className="relative">
                <Terminal className="absolute left-4 top-4 h-5 w-5" style={{ color: 'var(--muted)' }} />
                <textarea
                  value={naturalQuery}
                  onChange={(e) => setNaturalQuery(e.target.value)}
                  placeholder="e.g., Find all PowerShell executions with encoded commands in the last 24 hours"
                  className="w-full h-24 rounded-lg pl-12 pr-4 py-3 focus:outline-none focus:ring-2 focus:ring-primary-500 resize-none"
                  style={{
                    backgroundColor: 'var(--bg)',
                    border: '1px solid var(--border)',
                    color: 'var(--fg)'
                  }}
                />
              </div>

              {/* Suggested Queries */}
              <div className="mt-2 flex flex-wrap items-center gap-2">
                {suggestedQueries.slice(0, 3).map((query, idx) => (
                  <button
                    key={idx}
                    onClick={() => setNaturalQuery(query)}
                    className="text-xs px-2 py-1 rounded transition-colors hover:opacity-80"
                    style={{
                      backgroundColor: 'var(--surface)',
                      color: 'var(--muted)'
                    }}
                  >
                    {query}
                  </button>
                ))}
                <span className="text-xs ml-auto" style={{ color: 'var(--muted)', opacity: 0.6 }}>
                  Press <kbd className="px-1 py-0.5 rounded text-[10px]" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>Ctrl</kbd>+<kbd className="px-1 py-0.5 rounded text-[10px]" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}>Enter</kbd> to translate
                </span>
              </div>
            </div>

            {/* Query Type Selection & Translate Button */}
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <span className="text-sm" style={{ color: 'var(--muted)' }}>Output:</span>
                <div className="flex rounded-lg p-1" style={{ backgroundColor: 'var(--surface)' }}>
                  {(['kql', 'sql', 'sigma'] as const).map((type) => (
                    <button
                      key={type}
                      onClick={() => setQueryType(type)}
                      className={cn(
                        'px-3 py-1 rounded text-sm font-medium transition-colors',
                        queryType === type
                          ? 'bg-primary-600 text-white'
                          : ''
                      )}
                      style={queryType !== type ? { color: 'var(--muted)' } : undefined}
                    >
                      {type.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>

              <button
                onClick={handleTranslate}
                disabled={isTranslating || !naturalQuery.trim()}
                className={cn(
                  'flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors',
                  isTranslating || !naturalQuery.trim()
                    ? 'cursor-not-allowed'
                    : 'bg-primary-600 hover:bg-primary-500 text-white'
                )}
                style={isTranslating || !naturalQuery.trim() ? {
                  backgroundColor: 'var(--surface)',
                  color: 'var(--muted)'
                } : undefined}
              >
                {isTranslating ? (
                  <>
                    <Bot className="h-4 w-4 animate-pulse" />
                    Translating with AI...
                  </>
                ) : (
                  <>
                    <Sparkles className="h-4 w-4" />
                    Translate
                  </>
                )}
              </button>
            </div>

            {/* AI Translation Loading State */}
            {isTranslating && (
              <div className="mt-4 p-6 rounded-lg text-center" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
                <div className="flex flex-col items-center gap-3">
                  <div className="relative">
                    <Bot className="h-8 w-8 animate-pulse" style={{ color: 'var(--sol-magenta)' }} />
                    <div className="absolute -top-1 -right-1 h-3 w-3 rounded-full animate-ping" style={{ backgroundColor: 'var(--sol-magenta)' }} />
                  </div>
                  <div>
                    <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>Translating with AI...</p>
                    <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                      GPT is analyzing your natural language query
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Error State */}
            {translationError && !isTranslating && (
              <div className="mt-4 p-4 rounded-lg" style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
                <div className="flex items-start gap-3">
                  <AlertCircle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-red-400">Translation failed</p>
                    <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{translationError}</p>
                    <button
                      onClick={handleTranslate}
                      className="text-xs mt-2 px-2 py-1 rounded transition-colors hover:opacity-80"
                      style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)' }}
                    >
                      Try again
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Translated Query Display */}
            {translatedQuery && !isTranslating && (
              <div className="mt-4 p-4 rounded-lg" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Code className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                    <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                      Translated Query ({queryType.toUpperCase()})
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    {/* Translation Source Badge */}
                    {translationSource && (
                      <span
                        className="flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium"
                        style={translationSource === 'llm' ? {
                          background: 'rgba(217, 70, 239, 0.15)',
                          color: 'var(--sol-magenta)',
                          border: '1px solid var(--sol-magenta)'
                        } : {
                          background: 'var(--emerald-glow)',
                          color: 'var(--emerald-400)',
                          border: '1px solid var(--emerald-500)'
                        }}
                      >
                        {translationSource === 'llm' ? (
                          <>
                            <Bot className="h-3 w-3" />
                            GPT-4
                          </>
                        ) : (
                          <>
                            <Zap className="h-3 w-3" />
                            Pattern Match
                          </>
                        )}
                      </span>
                    )}
                    <button
                      onClick={() => copyToClipboard(translatedQuery)}
                      className="flex items-center gap-1 text-xs hover:opacity-80"
                      style={{ color: 'var(--muted)' }}
                    >
                      <Copy className="h-3 w-3" />
                      Copy
                    </button>
                    <button
                      className="flex items-center gap-1 text-xs hover:opacity-80"
                      style={{ color: 'var(--muted)' }}
                    >
                      <Save className="h-3 w-3" />
                      Save
                    </button>
                  </div>
                </div>

                {/* Query Display / Edit Mode */}
                {isEditingQuery ? (
                  <div className="space-y-3">
                    <div className="relative">
                      <textarea
                        value={editableQuery}
                        onChange={(e) => setEditableQuery(e.target.value)}
                        className="w-full h-32 rounded-lg p-3 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 resize-none"
                        style={{
                          backgroundColor: 'var(--bg)',
                          border: '1px solid var(--emerald-500)',
                          color: 'var(--emerald-200)'
                        }}
                        autoFocus
                      />
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleSaveEdit}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-primary-600 hover:bg-primary-500 text-white transition-colors"
                      >
                        <Save className="h-3 w-3" />
                        Save Changes
                      </button>
                      <button
                        onClick={handleCancelEdit}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors hover:opacity-80"
                        style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <pre
                      className="p-3 rounded text-sm font-mono overflow-x-auto whitespace-pre-wrap"
                      style={{
                        background: 'var(--bg)',
                        color: 'var(--emerald-200)',
                        border: '1px solid var(--border)'
                      }}
                    >
                      {translatedQuery}
                    </pre>
                    {translationWarnings().length > 0 && (
                      <div className="rounded-lg p-3" style={{ background: 'rgba(245, 158, 11, 0.10)', border: '1px solid rgba(245, 158, 11, 0.35)' }}>
                        <div className="flex items-start gap-2">
                          <AlertCircle className="h-4 w-4 mt-0.5 text-yellow-400" />
                          <div className="space-y-1">
                            {translationWarnings().map(warning => (
                              <p key={warning} className="text-xs text-yellow-300">{warning}</p>
                            ))}
                          </div>
                        </div>
                      </div>
                    )}
                    <button
                      onClick={handleStartEditing}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors hover:opacity-80"
                      style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg)' }}
                    >
                      <Edit3 className="h-3 w-3" />
                      Edit Query
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* Run Query Button */}
            {translatedQuery && (
              <div className="flex justify-end">
                <button
                  onClick={handleRunQuery}
                  disabled={isRunning}
                  className={cn(
                    'flex items-center gap-2 rounded-lg px-6 py-2 text-sm font-medium transition-colors',
                    isRunning
                      ? 'cursor-not-allowed'
                      : 'bg-green-600 hover:bg-green-500 text-white'
                  )}
                  style={isRunning ? {
                    backgroundColor: 'var(--surface)',
                    color: 'var(--muted)'
                  } : undefined}
                >
                  <Play className={cn('h-4 w-4', isRunning && 'animate-spin')} />
                  {isRunning ? 'Running...' : 'Run Query'}
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Main Content */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Results */}
          <div className="lg:col-span-2">
            {results.length > 0 ? (
              <div className="card-sentinel rounded-xl">
                <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
                  <div className="flex items-center gap-2">
                    <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Results</h2>
                    <span className="px-2 py-0.5 bg-primary-500/20 text-primary-400 rounded text-sm">
                      {results.length} matches
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      className="flex items-center gap-1 text-sm hover:opacity-80"
                      style={{ color: 'var(--muted)' }}
                    >
                      <Download className="h-4 w-4" />
                      Export
                    </button>
                    <button
                      className="flex items-center gap-1 text-sm hover:opacity-80"
                      style={{ color: 'var(--muted)' }}
                    >
                      <RefreshCw className="h-4 w-4" />
                      Refresh
                    </button>
                  </div>
                </div>

                <div className="divide-y max-h-[640px] overflow-y-auto" style={{ borderColor: 'var(--border)' }}>
                  {results.map((result) => {
                    const context = resultContext(result)
                    const processContext = processContexts[result.id]
                    const destination = context.remoteIp
                      ? `${context.remoteIp}${context.remotePort ? `:${context.remotePort}` : ''}`
                      : context.domain || context.sni
                    const processLabel = context.processName || (context.pid ? `PID ${context.pid}` : undefined)
                    const chainLabel = processContext?.chain
                      ?.map(node => node.name || `PID ${node.pid}`)
                      .filter(Boolean)
                      .join(' -> ')

                    return (
                      <div key={result.id} className="p-4 hover:opacity-90 transition-colors">
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={cn('px-2 py-0.5 rounded text-xs font-medium', getSeverityColor(result.severity))}>
                              {result.severity}
                            </span>
                            <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{result.event_type}</span>
                            <span className="text-sm" style={{ color: 'var(--muted)' }}>{result.hostname}</span>
                            {context.classification && (
                              <span
                                className="px-2 py-0.5 rounded text-xs font-medium"
                                style={{ background: 'var(--med-bg)', color: 'var(--med)' }}
                              >
                                {context.classification}
                              </span>
                            )}
                            {context.confidence && (
                              <span className="text-xs capitalize" style={{ color: 'var(--muted)' }}>
                                {context.confidence} confidence
                              </span>
                            )}
                          </div>
                          <span className="text-xs" style={{ color: 'var(--muted)' }}>
                            {new Date(result.timestamp).toLocaleString()}
                          </span>
                        </div>

                        <div className="rounded-lg p-3 mb-3" style={{ background: 'var(--bg)', border: '1px solid var(--border)' }}>
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                            <div>
                              <div className="flex items-center gap-1 text-xs uppercase font-semibold mb-1" style={{ color: 'var(--muted)' }}>
                                <Globe className="h-3 w-3" />
                                Flow
                              </div>
                              <div className="text-sm font-medium" style={{ color: 'var(--fg)' }}>
                                {destination || 'No network destination'}
                              </div>
                              <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                                {[context.direction, context.protocol, context.localIp && context.localPort ? `${context.localIp}:${context.localPort}` : context.localIp].filter(Boolean).join(' / ') || 'network metadata unavailable'}
                              </div>
                              {context.resolverLabel && (
                                <div className="text-xs mt-1" style={{ color: 'var(--emerald-400)' }}>
                                  {context.resolverLabel}
                                </div>
                              )}
                            </div>
                            <div>
                              <div className="flex items-center gap-1 text-xs uppercase font-semibold mb-1" style={{ color: 'var(--muted)' }}>
                                <Cpu className="h-3 w-3" />
                                Process / Binary
                              </div>
                              <div className="text-sm font-medium truncate" style={{ color: processLabel ? 'var(--fg)' : 'var(--muted)' }}>
                                {processLabel || 'Process identity missing'}
                              </div>
                              <div className="text-xs mt-1 truncate font-mono" style={{ color: context.processPath ? 'var(--fg-2)' : 'var(--muted)' }} title={context.processPath}>
                                {context.processPath || 'binary path not captured'}
                              </div>
                              {context.commandLine && (
                                <div className="text-xs mt-1 truncate font-mono" style={{ color: 'var(--muted)' }} title={context.commandLine}>
                                  {context.commandLine}
                                </div>
                              )}
                            </div>
                            <div>
                              <div className="flex items-center gap-1 text-xs uppercase font-semibold mb-1" style={{ color: 'var(--muted)' }}>
                                <Server className="h-3 w-3" />
                                Lineage
                              </div>
                              <div className="text-sm" style={{ color: context.parentName || context.parentPid ? 'var(--fg)' : 'var(--muted)' }}>
                                {context.parentName || context.parentPid ? `${context.parentName || 'parent'}${context.parentPid ? ` (${context.parentPid})` : ''}` : 'Parent process missing'}
                              </div>
                              <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                                {context.user ? `user=${context.user}` : 'user context not captured'}
                              </div>
                              {chainLabel && (
                                <div className="text-xs mt-1 truncate" style={{ color: 'var(--fg-2)' }} title={chainLabel}>
                                  {chainLabel}
                                </div>
                              )}
                              {context.sha256 && (
                                <div className="text-xs mt-1 font-mono truncate" style={{ color: 'var(--high)' }} title={context.sha256}>
                                  sha256={context.sha256}
                                </div>
                              )}
                            </div>
                          </div>

                          <div className="mt-3 flex flex-wrap gap-2">
                            {context.evidence.slice(0, 8).map(item => (
                              <span
                                key={item}
                                className="px-2 py-1 rounded text-xs"
                                style={{ background: 'var(--surface)', color: 'var(--fg-2)' }}
                              >
                                {item}
                              </span>
                            ))}
                            {context.gaps.slice(0, 6).map(item => (
                              <span
                                key={item}
                                className="px-2 py-1 rounded text-xs"
                                style={{ background: 'rgba(239, 68, 68, 0.1)', color: 'rgb(248 113 113)' }}
                              >
                                {item}
                              </span>
                            ))}
                          </div>
                        </div>

                        <details>
                          <summary className="text-xs cursor-pointer hover:opacity-80" style={{ color: 'var(--muted)' }}>
                            Show raw event
                          </summary>
                          <pre
                            className="text-xs rounded p-3 overflow-x-auto mt-2"
                            style={{
                              backgroundColor: 'var(--bg)',
                              color: 'var(--muted)'
                            }}
                          >
                            {JSON.stringify(result.details, null, 2)}
                          </pre>
                        </details>
                      </div>
                    )
                  })}
                </div>
              </div>
            ) : (
              <div className="card-sentinel rounded-xl p-12 text-center">
                <Search className="h-16 w-16 mx-auto mb-4 opacity-50" style={{ color: 'var(--muted)' }} />
                <p className="text-lg" style={{ color: 'var(--muted)' }}>No results yet</p>
                <p className="text-sm mt-1" style={{ color: 'var(--muted)', opacity: 0.7 }}>
                  Describe what you want to find in natural language and let AI translate it
                </p>
              </div>
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Suggested Hypotheses */}
            {suggestedHypotheses.length > 0 && (
              <div className="card-sentinel rounded-xl">
                <div className="p-4 flex items-center gap-2" style={{ borderBottom: '1px solid var(--border)' }}>
                  <Lightbulb className="h-5 w-5 text-yellow-400" />
                  <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Suggested Hypotheses</h2>
                </div>
                <div className="divide-y max-h-[300px] overflow-y-auto" style={{ borderColor: 'var(--border)' }}>
                  {suggestedHypotheses.map((hypothesis) => (
                    <div
                      key={hypothesis.id}
                      onClick={() => setNaturalQuery(hypothesis.query)}
                      className="p-4 cursor-pointer transition-colors group hover:opacity-90"
                    >
                      <div className="flex items-start justify-between mb-1">
                        <span className="text-sm font-medium group-hover:text-primary-400" style={{ color: 'var(--fg)' }}>
                          {hypothesis.title}
                        </span>
                        <span
                          className="text-xs px-1.5 py-0.5 rounded"
                          style={{ backgroundColor: 'var(--surface)', color: 'var(--muted)' }}
                        >
                          {hypothesis.category}
                        </span>
                      </div>
                      <p className="text-xs line-clamp-2" style={{ color: 'var(--muted)' }}>{hypothesis.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Saved Queries */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4 flex items-center justify-between" style={{ borderBottom: '1px solid var(--border)' }}>
                <div className="flex items-center gap-2">
                  <Bookmark className="h-5 w-5 text-primary-400" />
                  <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Saved Queries</h2>
                </div>
                <button
                  onClick={() => setShowSavedQueries(!showSavedQueries)}
                  style={{ color: 'var(--muted)' }}
                  className="hover:opacity-80"
                >
                  <ChevronRight className={cn('h-5 w-5 transition-transform', showSavedQueries && 'rotate-90')} />
                </button>
              </div>

              {showSavedQueries && (
                <div className="divide-y max-h-[400px] overflow-y-auto" style={{ borderColor: 'var(--border)' }}>
                  {savedQueries.length === 0 ? (
                    <div className="p-8 text-center" style={{ color: 'var(--muted)' }}>
                      <Bookmark className="h-8 w-8 mx-auto mb-2 opacity-50" />
                      <p className="text-sm">No saved queries</p>
                    </div>
                  ) : (
                    savedQueries.map((query) => (
                      <div
                        key={query.id}
                        onClick={() => loadSavedQuery(query)}
                        className="p-4 cursor-pointer transition-colors group hover:opacity-90"
                      >
                        <div className="flex items-start justify-between mb-1">
                          <span className="text-sm font-medium group-hover:text-primary-400" style={{ color: 'var(--fg)' }}>
                            {query.name}
                          </span>
                          <span
                            className="text-xs px-1.5 py-0.5 rounded"
                            style={{ backgroundColor: 'var(--surface)', color: 'var(--muted)' }}
                          >
                            {query.queryType.toUpperCase()}
                          </span>
                        </div>
                        <p className="text-xs line-clamp-2 mb-2" style={{ color: 'var(--muted)' }}>{query.naturalQuery}</p>
                        <div className="flex items-center justify-between text-xs" style={{ color: 'var(--muted)' }}>
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {query.lastRun ? `Last run: ${new Date(query.lastRun).toLocaleDateString()}` : 'Never run'}
                          </span>
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              // Handle delete
                            }}
                            className="opacity-0 group-hover:opacity-100 text-red-400 hover:text-red-300"
                          >
                            <Trash2 className="h-3 w-3" />
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              <div className="p-4" style={{ borderTop: '1px solid var(--border)' }}>
                <button
                  className="w-full flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm transition-colors hover:opacity-80"
                  style={{ backgroundColor: 'var(--surface)', color: 'var(--muted)' }}
                >
                  <FileText className="h-4 w-4" />
                  View All Queries
                </button>
              </div>
            </div>

            {/* Hunt Sessions */}
            {sessions.length > 0 && (
              <div className="card-sentinel rounded-xl">
                <div className="p-4 flex items-center gap-2" style={{ borderBottom: '1px solid var(--border)' }}>
                  <Search className="h-5 w-5 text-primary-400" />
                  <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Hunt Sessions</h2>
                </div>
                <div className="divide-y max-h-[200px] overflow-y-auto" style={{ borderColor: 'var(--border)' }}>
                  {sessions.map((session) => (
                    <div
                      key={session.id}
                      className="p-4 cursor-pointer transition-colors hover:opacity-90"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{session.name}</span>
                        <span className="text-xs" style={{ color: 'var(--muted)' }}>
                          {new Date(session.createdAt).toLocaleDateString()}
                        </span>
                      </div>
                      <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--muted)' }}>
                        <span>{session.queries} queries</span>
                        <span>{session.findings} findings</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
