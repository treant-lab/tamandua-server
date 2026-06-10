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
  timestamp: string
  hostname: string
  event_type: string
  severity: string
  details: Record<string, unknown>
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

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard', {
      icon: <CheckCircle className="h-4 w-4" />,
      duration: 2000,
    })
  }

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

                <div className="divide-y max-h-[500px] overflow-y-auto" style={{ borderColor: 'var(--border)' }}>
                  {results.map((result) => (
                    <div key={result.id} className="p-4 hover:opacity-90 transition-colors">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className={cn('px-2 py-0.5 rounded text-xs font-medium', getSeverityColor(result.severity))}>
                            {result.severity}
                          </span>
                          <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{result.event_type}</span>
                          <span className="text-sm" style={{ color: 'var(--muted)' }}>{result.hostname}</span>
                        </div>
                        <span className="text-xs" style={{ color: 'var(--muted)' }}>
                          {new Date(result.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <pre
                        className="text-xs rounded p-3 overflow-x-auto"
                        style={{
                          backgroundColor: 'var(--bg)',
                          color: 'var(--muted)'
                        }}
                      >
                        {JSON.stringify(result.details, null, 2)}
                      </pre>
                    </div>
                  ))}
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
