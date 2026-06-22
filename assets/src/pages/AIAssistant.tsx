import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { useState, useRef, useEffect, useCallback } from 'react'
import {
  Sparkles,
  Send,
  User,
  Bot,
  Clock,
  Trash2,
  Copy,
  Check,
  ChevronRight,
  AlertTriangle,
  Shield,
  Search,
  FileSearch,
  Network,
  Server,
  Terminal,
  Lightbulb,
  History,
  Loader2,
  Zap,
  Target,
  Plus,
  MessageSquare,
  RefreshCw,
} from 'lucide-react'
import { Dialog, DialogFooter } from '@/components/ui/baseui'
import { cn } from '@/lib/utils'
import { logger } from '@/lib/logger'

// Types
interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: string
  suggestedActions?: SuggestedAction[]
  isStreaming?: boolean
  error?: boolean
}

interface SuggestedAction {
  id: string
  label: string
  type: 'query' | 'investigation' | 'response' | 'info'
  action: string
  kind?: 'prompt' | 'navigate'
  url?: string
  requiresConfirmation?: boolean
}

interface QueryHistoryItem {
  id: string
  query: string
  timestamp: string
  category: 'threat' | 'hunt' | 'response' | 'analysis' | 'general'
}

interface ContextualRecommendation {
  id: string
  title: string
  description: string
  priority: 'high' | 'medium' | 'low'
  category: 'investigation' | 'response' | 'monitoring' | 'learning'
  relatedAlerts?: number
}

interface Conversation {
  id: string
  title: string
  messages: ChatMessage[]
  createdAt: string
  updatedAt: string
}

interface SuggestedQuery {
  icon: string
  label: string
  query: string
}

interface Capability {
  id: string
  name: string
  description: string
  icon: string
}

interface EnvironmentContext {
  activeAgents: number
  openAlerts: number
  activeInvestigations: number
  eventsToday: number
}

interface AIAssistantPageProps {
  conversations?: Conversation[]
  suggestedQueries?: SuggestedQuery[]
  capabilities?: Capability[]
  queryHistory?: QueryHistoryItem[]
  recommendations?: ContextualRecommendation[]
  environmentContext?: EnvironmentContext
}

// Default environment context
const defaultEnvironmentContext: EnvironmentContext = {
  activeAgents: 0,
  openAlerts: 0,
  activeInvestigations: 0,
  eventsToday: 0,
}

// Icon mapping
const iconMap: Record<string, React.ElementType> = {
  AlertTriangle,
  Search,
  Shield,
  Network,
  Server,
  Terminal,
  FileSearch,
  Zap,
  Target,
  Lightbulb,
}

function getCsrfToken(): string {
  const cookie = document.cookie
    .split('; ')
    .find(row => row.startsWith('XSRF-TOKEN='))
    ?.split('=')[1]

  if (cookie) return decodeURIComponent(cookie)

  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

function csrfHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const token = getCsrfToken()
  return token ? { ...extra, 'X-CSRF-Token': token, 'X-XSRF-TOKEN': token } : extra
}

async function readJsonResponse(response: Response): Promise<any> {
  const text = await response.text()
  if (!text) return {}

  try {
    return JSON.parse(text)
  } catch {
    return { message: text }
  }
}

function normalizeConversation(raw: any): Conversation {
  const updatedAt = raw.updatedAt || raw.updated_at || raw.inserted_at || new Date().toISOString()
  const createdAt = raw.createdAt || raw.created_at || updatedAt

  return {
    id: raw.id,
    title: raw.title || 'Conversation',
    createdAt,
    updatedAt,
    messages: Array.isArray(raw.messages)
      ? raw.messages.map((message: any, index: number) => ({
          id: message.id || `loaded-${raw.id || 'conversation'}-${index}`,
          role: message.role === 'user' ? 'user' : 'assistant',
          content: message.content || '',
          timestamp: message.timestamp || updatedAt,
          suggestedActions: message.suggestedActions || message.suggested_actions,
        }))
      : [],
  }
}

function normalizeSuggestedAction(raw: any, id: string): SuggestedAction {
  return {
    id,
    label: raw.label || raw.action || raw.query || 'Action',
    type: raw.type || 'query',
    action: raw.action || raw.query || raw.url || '',
    kind: raw.kind || (raw.url ? 'navigate' : 'prompt'),
    url: raw.url,
    requiresConfirmation: raw.requires_confirmation || raw.requiresConfirmation || false,
  }
}

export default function AIAssistant({
  conversations: initialConversations = [],
  suggestedQueries: _propSuggestedQueries,
  queryHistory: initialQueryHistory = [],
  recommendations: initialRecommendations = [],
  environmentContext = defaultEnvironmentContext,
}: AIAssistantPageProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [inputValue, setInputValue] = useState('')
  const [isProcessing, setIsProcessing] = useState(false)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const [conversations, setConversations] = useState<Conversation[]>(initialConversations)
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null)
  const [suggestedQueries, setSuggestedQueries] = useState<SuggestedQuery[]>(_propSuggestedQueries || [])
  const [recommendations, setRecommendations] = useState<ContextualRecommendation[]>(initialRecommendations)
  const [queryHistory, setQueryHistory] = useState<QueryHistoryItem[]>(initialQueryHistory)
  const [welcomeLoading, setWelcomeLoading] = useState(true)
  const [conversationsLoading, setConversationsLoading] = useState(true)
  const [suggestionsLoading, setSuggestionsLoading] = useState(true)
  const [pendingAction, setPendingAction] = useState<SuggestedAction | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const abortControllerRef = useRef<AbortController | null>(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  // Load welcome message from backend on mount
  useEffect(() => {
    async function loadWelcome() {
      try {
        const response = await fetch('/api/v1/ai/chat', {
          method: 'POST',
          credentials: 'same-origin',
          headers: csrfHeaders({
            'Content-Type': 'application/json',
          }),
          body: JSON.stringify({
            message: '__welcome__',
            conversation_id: null,
            context: { type: 'welcome', environment: environmentContext },
          }),
        })

        if (response.ok) {
          const result = await response.json()
          if (result.data?.message) {
            const welcomeMsg: ChatMessage = {
              id: 'welcome-1',
              role: 'assistant',
              content: result.data.message,
              timestamp: new Date().toISOString(),
              suggestedActions: result.data.suggested_actions?.map((a: any, i: number) => ({
                ...normalizeSuggestedAction(a, `sa-welcome-${i}`),
              })) || [],
            }
            setMessages([welcomeMsg])
            if (result.data.conversation_id) {
              setActiveConversationId(result.data.conversation_id)
            }
          } else {
            setMessages([buildFallbackWelcome()])
          }
        } else {
          setMessages([buildFallbackWelcome()])
        }
      } catch {
        setMessages([buildFallbackWelcome()])
      } finally {
        setWelcomeLoading(false)
      }
    }

    loadWelcome()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Load conversations list from backend
  useEffect(() => {
    async function loadConversations() {
      try {
        const response = await fetch('/api/v1/ai/conversations', {
          credentials: 'same-origin',
          headers: csrfHeaders(),
        })
        if (response.ok) {
          const result = await response.json()
          if (result.data && Array.isArray(result.data)) {
            setConversations(result.data.map(normalizeConversation))
          }
        }
      } catch (err) {
        logger.error('Failed to load conversations:', err)
      } finally {
        setConversationsLoading(false)
      }
    }

    loadConversations()
  }, [])

  // Load dynamic suggestions based on current context
  const loadSuggestions = useCallback(async () => {
    setSuggestionsLoading(true)
    try {
      const response = await fetch('/api/v1/ai/suggestions', {
        method: 'POST',
        credentials: 'same-origin',
        headers: csrfHeaders({
          'Content-Type': 'application/json',
        }),
        body: JSON.stringify({
          context: {
            environment: environmentContext,
            active_conversation_id: activeConversationId,
            recent_message_count: messages.filter(m => m.role === 'user').length,
          },
        }),
      })

      if (response.ok) {
        const result = await response.json()
        if (result.data?.suggestions && Array.isArray(result.data.suggestions)) {
          setSuggestedQueries(result.data.suggestions.map((s: any) => ({
            icon: s.icon || 'Search',
            label: s.label,
            query: s.query,
          })))
        }
        if (result.data?.recommendations && Array.isArray(result.data.recommendations)) {
          setRecommendations(result.data.recommendations)
        }
        if (result.data?.query_history && Array.isArray(result.data.query_history)) {
          setQueryHistory(result.data.query_history)
        }
      }
    } catch (err) {
      logger.error('Failed to load suggestions:', err)
    } finally {
      setSuggestionsLoading(false)
    }
  }, [environmentContext, activeConversationId, messages])

  useEffect(() => {
    loadSuggestions()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Refresh suggestions when context changes (new messages sent)
  const userMessageCount = messages.filter(m => m.role === 'user').length
  const prevUserMessageCountRef = useRef(0)
  useEffect(() => {
    if (userMessageCount > prevUserMessageCountRef.current && userMessageCount > 0) {
      loadSuggestions()
    }
    prevUserMessageCountRef.current = userMessageCount
  }, [userMessageCount, loadSuggestions])

  function buildFallbackWelcome(): ChatMessage {
    return {
      id: 'welcome-fallback',
      role: 'assistant',
      content: `Hello! I'm your AI Security Assistant. I can help you with:

- **Threat Analysis**: Understand current threats and attack patterns
- **Hunting Queries**: Build and execute threat hunting queries
- **Response Guidance**: Get recommendations for incident response
- **Context & Learning**: Explain detections, MITRE techniques, and security concepts

How can I assist you today?`,
      timestamp: new Date().toISOString(),
      suggestedActions: [
        { id: 'sa1', label: 'Review open alerts', type: 'investigation', action: 'Show me all open high-severity alerts' },
        { id: 'sa2', label: 'Threat summary', type: 'info', action: 'Provide a current threat landscape summary' },
        { id: 'sa3', label: 'Start hunt', type: 'query', action: 'Help me create a threat hunting query' },
      ],
    }
  }

  const handleSendMessage = async (message?: string) => {
    const content = message || inputValue
    if (!content.trim() || isProcessing) return

    const userMessage: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: content.trim(),
      timestamp: new Date().toISOString(),
    }

    setMessages(prev => [...prev, userMessage])
    setQueryHistory(prev => [
      {
        id: `qh-${Date.now()}`,
        query: content.trim(),
        timestamp: new Date().toISOString(),
        category: 'analysis',
      },
      ...prev,
    ].slice(0, 20))
    setInputValue('')
    setIsProcessing(true)

    // Create a placeholder for the streaming response
    const assistantMsgId = `assistant-${Date.now()}`
    const streamingPlaceholder: ChatMessage = {
      id: assistantMsgId,
      role: 'assistant',
      content: '',
      timestamp: new Date().toISOString(),
      isStreaming: true,
    }
    setMessages(prev => [...prev, streamingPlaceholder])

    // Cancel any previous in-flight request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
    }
    const abortController = new AbortController()
    abortControllerRef.current = abortController

    try {
      const response = await fetch('/api/v1/ai/chat', {
        method: 'POST',
        credentials: 'same-origin',
        headers: csrfHeaders({
          'Content-Type': 'application/json',
          'Accept': 'text/event-stream, application/json',
        }),
        body: JSON.stringify({
          message: content.trim(),
          conversation_id: activeConversationId,
          context: {
            previous_messages: messages.slice(-10).map(m => ({
              role: m.role,
              content: m.content,
            })),
            environment: environmentContext,
          },
        }),
        signal: abortController.signal,
      })

      if (!response.ok) {
        const errorBody = await readJsonResponse(response)
        throw new Error(errorBody.message || errorBody.error || `API request failed: ${response.status} ${response.statusText}`)
      }

      const contentType = response.headers.get('Content-Type') || ''

      if (contentType.includes('text/event-stream') && response.body) {
        // Handle streaming SSE response
        const reader = response.body.getReader()
        const decoder = new TextDecoder()
        let accumulatedContent = ''
        let suggestedActions: SuggestedAction[] = []
        let conversationId: string | null = null

        while (true) {
          const { done, value } = await reader.read()
          if (done) break

          const chunk = decoder.decode(value, { stream: true })
          const lines = chunk.split('\n')

          for (const line of lines) {
            if (line.startsWith('data: ')) {
              const data = line.slice(6)
              if (data === '[DONE]') continue

              try {
                const parsed = JSON.parse(data)

                if (parsed.type === 'token' || parsed.type === 'chunk') {
                  accumulatedContent += parsed.content || parsed.token || ''
                  setMessages(prev =>
                    prev.map(m =>
                      m.id === assistantMsgId
                        ? { ...m, content: accumulatedContent }
                        : m
                    )
                  )
                } else if (parsed.type === 'suggested_actions') {
                  suggestedActions = (parsed.actions || []).map((a: any, i: number) => ({
                    ...normalizeSuggestedAction(a, `sa-${Date.now()}-${i}`),
                  }))
                } else if (parsed.type === 'metadata') {
                  conversationId = parsed.conversation_id || conversationId
                } else if (parsed.type === 'error') {
                  throw new Error(parsed.message || 'Stream error')
                }
              } catch (parseErr) {
                // Not valid JSON, accumulate as raw text
                if (data !== '[DONE]') {
                  accumulatedContent += data
                  setMessages(prev =>
                    prev.map(m =>
                      m.id === assistantMsgId
                        ? { ...m, content: accumulatedContent }
                        : m
                    )
                  )
                }
              }
            }
          }
        }

        // Finalize streaming message
        setMessages(prev =>
          prev.map(m =>
            m.id === assistantMsgId
              ? { ...m, isStreaming: false, suggestedActions: suggestedActions.length > 0 ? suggestedActions : generateSuggestedActions(content) }
              : m
          )
        )

        if (conversationId) {
          setActiveConversationId(conversationId)
          await loadConversationsList()
        }
      } else {
        // Handle regular JSON response
        const result = await readJsonResponse(response)

        if (result.data) {
          const responseContent = formatAIResponse(result.data)
          const responseSuggestedActions = result.data.suggested_actions
            ? result.data.suggested_actions.map((a: any, i: number) => ({
                ...normalizeSuggestedAction(a, `sa-${Date.now()}-${i}`),
              }))
            : generateSuggestedActions(content)

          setMessages(prev =>
            prev.map(m =>
              m.id === assistantMsgId
                ? { ...m, content: responseContent, isStreaming: false, suggestedActions: responseSuggestedActions }
                : m
            )
          )

          if (result.data.conversation_id) {
            setActiveConversationId(result.data.conversation_id)
            await loadConversationsList()
          }
        } else {
          throw new Error(result.message || result.error || 'Unknown error from AI service')
        }
      }
    } catch (error) {
      if ((error as Error).name === 'AbortError') return

      logger.error('AI chat error:', error)
      setMessages(prev =>
        prev.map(m =>
          m.id === assistantMsgId
            ? {
                ...m,
                content: `I encountered an error processing your request. Please try again or rephrase your query.\n\nError: ${error instanceof Error ? error.message : 'Unknown error'}`,
                isStreaming: false,
                error: true,
              }
            : m
        )
      )
    } finally {
      setIsProcessing(false)
      abortControllerRef.current = null
    }
  }

  const handleSuggestedAction = (action: SuggestedAction) => {
    if (action.kind === 'navigate' && action.url) {
      window.location.href = action.url
      return
    }

    if (action.requiresConfirmation) {
      setPendingAction(action)
      return
    }

    handleSendMessage(action.action)
  }

  const confirmPendingAction = () => {
    const action = pendingAction
    setPendingAction(null)
    if (!action) return
    handleSendMessage(action.action)
  }

  const formatAIResponse = (data: any): string => {
    if (typeof data === 'string') return data
    if (typeof data.message === 'string') return data.message

    let response = ''

    if (data.summary) {
      response += data.summary + '\n\n'
    }

    if (data.results && Array.isArray(data.results) && data.results.length > 0) {
      response += `**Results (${data.result_count || data.results.length} found):**\n\n`

      const displayResults = data.results.slice(0, 5)
      displayResults.forEach((result: any, index: number) => {
        if (result.hostname) {
          response += `${index + 1}. **${result.hostname}**`
          if (result.event_type) response += ` - ${result.event_type}`
          if (result.timestamp) response += ` (${new Date(result.timestamp).toLocaleString()})`
          response += '\n'
        }
      })

      if (data.results.length > 5) {
        response += `\n*...and ${data.results.length - 5} more results*\n`
      }
    }

    if (data.follow_up_queries && Array.isArray(data.follow_up_queries) && data.follow_up_queries.length > 0) {
      response += '\n**Suggested follow-up queries:**\n'
      data.follow_up_queries.slice(0, 3).forEach((query: string) => {
        response += `- ${query}\n`
      })
    }

    if (data.intent) {
      response += `\n*Query type: ${data.intent.description || data.intent.type}*`
    }

    return response || 'No relevant information found for your query.'
  }

  const generateSuggestedActions = (query: string): SuggestedAction[] => {
    const lowerQuery = query.toLowerCase()
    const actions: SuggestedAction[] = []
    let actionId = 0

    // Threat-related queries
    if (lowerQuery.includes('threat') || lowerQuery.includes('attack') || lowerQuery.includes('malware') || lowerQuery.includes('malicious')) {
      actions.push(
        { id: `sa-${actionId++}`, label: 'View affected hosts', type: 'investigation', action: 'Show me all hosts affected by the current threats' },
        { id: `sa-${actionId++}`, label: 'Start response', type: 'response', action: 'What response actions should I take for this threat?' },
        { id: `sa-${actionId++}`, label: 'Hunt for related activity', type: 'query', action: 'Create a hunt query to find related malicious activity' }
      )
    }

    // Alert-related queries
    if (lowerQuery.includes('alert') || lowerQuery.includes('critical') || lowerQuery.includes('high') || lowerQuery.includes('severity')) {
      actions.push(
        { id: `sa-${actionId++}`, label: 'Show alert details', type: 'investigation', action: 'Show me the details and evidence for these alerts' },
        { id: `sa-${actionId++}`, label: 'Correlate alerts', type: 'query', action: 'Find alerts correlated with this activity' },
        { id: `sa-${actionId++}`, label: 'Triage guidance', type: 'info', action: 'How should I triage and prioritize these alerts?' }
      )
    }

    // Process-related queries
    if (lowerQuery.includes('process') || lowerQuery.includes('execution') || lowerQuery.includes('powershell') || lowerQuery.includes('cmd')) {
      actions.push(
        { id: `sa-${actionId++}`, label: 'View process tree', type: 'investigation', action: 'Show me the full process tree for this activity' },
        { id: `sa-${actionId++}`, label: 'Kill process', type: 'response', action: 'How can I safely terminate this suspicious process?' },
        { id: `sa-${actionId++}`, label: 'Check parent chain', type: 'query', action: 'What is the parent process chain for this execution?' }
      )
    }

    // Network-related queries
    if (lowerQuery.includes('network') || lowerQuery.includes('connection') || lowerQuery.includes('ip') || lowerQuery.includes('dns') || lowerQuery.includes('c2')) {
      actions.push(
        { id: `sa-${actionId++}`, label: 'Block connection', type: 'response', action: 'How can I block this suspicious network connection?' },
        { id: `sa-${actionId++}`, label: 'Check reputation', type: 'query', action: 'What is the threat intelligence on these IPs/domains?' },
        { id: `sa-${actionId++}`, label: 'Network timeline', type: 'investigation', action: 'Show me the network activity timeline for this host' }
      )
    }

    // Credential/authentication queries
    if (lowerQuery.includes('credential') || lowerQuery.includes('password') || lowerQuery.includes('login') || lowerQuery.includes('auth') || lowerQuery.includes('lsass')) {
      actions.push(
        { id: `sa-${actionId++}`, label: 'Check for theft', type: 'investigation', action: 'Are there signs of credential theft or dumping?' },
        { id: `sa-${actionId++}`, label: 'Reset credentials', type: 'response', action: 'What accounts should have their passwords reset?' },
        { id: `sa-${actionId++}`, label: 'Find lateral movement', type: 'query', action: 'Hunt for lateral movement using these credentials' }
      )
    }

    // File-related queries
    if (lowerQuery.includes('file') || lowerQuery.includes('download') || lowerQuery.includes('hash') || lowerQuery.includes('quarantine')) {
      actions.push(
        { id: `sa-${actionId++}`, label: 'Quarantine file', type: 'response', action: 'How can I quarantine this suspicious file?' },
        { id: `sa-${actionId++}`, label: 'Check file hash', type: 'query', action: 'Look up this file hash in threat intelligence' },
        { id: `sa-${actionId++}`, label: 'Find file spread', type: 'investigation', action: 'Has this file been seen on other hosts?' }
      )
    }

    // MITRE ATT&CK queries
    if (lowerQuery.includes('mitre') || lowerQuery.includes('technique') || lowerQuery.includes('tactic') || lowerQuery.match(/t\d{4}/i)) {
      actions.push(
        { id: `sa-${actionId++}`, label: 'Explain technique', type: 'info', action: 'Explain this MITRE ATT&CK technique in detail' },
        { id: `sa-${actionId++}`, label: 'Find detections', type: 'query', action: 'What detections do we have for this technique?' },
        { id: `sa-${actionId++}`, label: 'Defense recommendations', type: 'response', action: 'How can we defend against this technique?' }
      )
    }

    // Investigation queries
    if (lowerQuery.includes('investigate') || lowerQuery.includes('investigation') || lowerQuery.includes('analyze') || lowerQuery.includes('root cause')) {
      actions.push(
        { id: `sa-${actionId++}`, label: 'Build timeline', type: 'investigation', action: 'Create a timeline of events for this investigation' },
        { id: `sa-${actionId++}`, label: 'Collect evidence', type: 'query', action: 'What evidence should I collect for this investigation?' },
        { id: `sa-${actionId++}`, label: 'Related hosts', type: 'investigation', action: 'Are there other hosts involved in this incident?' }
      )
    }

    // Ransomware queries
    if (lowerQuery.includes('ransomware') || lowerQuery.includes('encrypt') || lowerQuery.includes('shadow') || lowerQuery.includes('vssadmin')) {
      actions.push(
        { id: `sa-${actionId++}`, label: 'Isolate immediately', type: 'response', action: 'Isolate this host to prevent ransomware spread' },
        { id: `sa-${actionId++}`, label: 'Check backups', type: 'info', action: 'What backup and recovery options are available?' },
        { id: `sa-${actionId++}`, label: 'Find spread', type: 'investigation', action: 'Has the ransomware spread to other hosts?' }
      )
    }

    // Hunting queries
    if (lowerQuery.includes('hunt') || lowerQuery.includes('search') || lowerQuery.includes('find') || lowerQuery.includes('query')) {
      actions.push(
        { id: `sa-${actionId++}`, label: 'Save hunt query', type: 'query', action: 'Save this as a reusable hunt query' },
        { id: `sa-${actionId++}`, label: 'Expand scope', type: 'query', action: 'Expand this hunt to include more data sources' },
        { id: `sa-${actionId++}`, label: 'Schedule hunt', type: 'query', action: 'How can I schedule this hunt to run periodically?' }
      )
    }

    // Return top 3 most relevant actions, or defaults if none matched
    if (actions.length > 0) {
      return actions.slice(0, 3)
    }

    // Default fallback suggestions based on query content
    if (lowerQuery.includes('how') || lowerQuery.includes('what') || lowerQuery.includes('why')) {
      return [
        { id: 'sa-def-1', label: 'More details', type: 'info', action: 'Can you provide more specific details about this?' },
        { id: 'sa-def-2', label: 'Show examples', type: 'info', action: 'Show me some practical examples' },
        { id: 'sa-def-3', label: 'Related topics', type: 'info', action: 'What related topics should I know about?' }
      ]
    }

    return [
      { id: 'sa-def-1', label: 'Learn more', type: 'info', action: 'Can you explain this in more detail?' },
      { id: 'sa-def-2', label: 'Related alerts', type: 'investigation', action: 'Show me related security alerts' },
      { id: 'sa-def-3', label: 'Hunt queries', type: 'query', action: 'Create a hunt query related to this topic' }
    ]
  }

  const handleCopy = async (content: string, id: string) => {
    await navigator.clipboard.writeText(content)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const clearChat = async () => {
    setMessages([buildFallbackWelcome()])
    setActiveConversationId(null)
  }

  // Manual save fallback. Normal chat requests are persisted by the backend
  // atomically with the assistant response.
  const saveConversation = async () => {
    if (messages.length <= 1) return

    try {
      const payload: any = {
        messages: messages.map(m => ({
          role: m.role,
          content: m.content,
          timestamp: m.timestamp,
        })),
        title: deriveConversationTitle(),
      }

      if (activeConversationId) {
        payload.conversation_id = activeConversationId
      }

      const response = await fetch('/api/v1/ai/conversations', {
        method: 'POST',
        credentials: 'same-origin',
        headers: csrfHeaders({
          'Content-Type': 'application/json',
        }),
        body: JSON.stringify(payload),
      })

      if (response.ok) {
        const result = await response.json()
        if (result.data?.id) {
          setActiveConversationId(result.data.id)
          // Refresh conversations list
          loadConversationsList()
        }
      }
    } catch (err) {
      logger.error('Failed to save conversation:', err)
    }
  }

  const loadConversationsList = async () => {
    try {
      const response = await fetch('/api/v1/ai/conversations', {
        credentials: 'same-origin',
        headers: csrfHeaders(),
      })
      if (response.ok) {
        const result = await response.json()
        if (result.data && Array.isArray(result.data)) {
          setConversations(result.data.map(normalizeConversation))
        }
      }
    } catch (err) {
      logger.error('Failed to refresh conversations:', err)
    }
  }

  // Load a specific conversation from backend
  const loadConversation = async (conversationId: string) => {
    try {
      const response = await fetch(`/api/v1/ai/conversations/${conversationId}`, {
        credentials: 'same-origin',
        headers: csrfHeaders(),
      })

      if (response.ok) {
        const result = await response.json()
        if (result.data) {
          const normalized = normalizeConversation(result.data)
          setActiveConversationId(conversationId)
          setMessages(normalized.messages.length > 0 ? normalized.messages : [buildFallbackWelcome()])
        }
      }
    } catch (err) {
      logger.error('Failed to load conversation:', err)
    }
  }

  const startNewConversation = () => {
    setActiveConversationId(null)
    setMessages([buildFallbackWelcome()])
  }

  const deriveConversationTitle = (): string => {
    const firstUserMessage = messages.find(m => m.role === 'user')
    if (firstUserMessage) {
      return firstUserMessage.content.slice(0, 60) + (firstUserMessage.content.length > 60 ? '...' : '')
    }
    return `Conversation ${new Date().toLocaleDateString()}`
  }

  const categoryColors = {
    threat: 'bg-[var(--crit-bg)] text-[var(--crit)]',
    hunt: 'bg-purple-500/20 text-purple-400',
    response: 'bg-[var(--high-bg)] text-[var(--high)]',
    analysis: 'bg-[var(--med-bg)] text-[var(--med)]',
    general: 'bg-[var(--low-bg)] text-[var(--muted)]',
  }

  const priorityColors = {
    high: 'border-[var(--crit)] bg-[var(--crit-bg)]',
    medium: 'border-[var(--high)] bg-[var(--high-bg)]',
    low: 'border-[var(--border)] bg-[var(--surface)]',
  }

  const categoryIcons = {
    investigation: FileSearch,
    response: Zap,
    monitoring: Target,
    learning: Lightbulb,
  }

  return (
    <MainLayout title="AI Security Assistant">
      <Head title="AI Assistant - Tamandua EDR" />

      <div className="h-[calc(100vh-12rem)] flex gap-6">
        {/* Main Chat Area */}
        <div
          className="card-sentinel flex-1 flex flex-col rounded-xl"
          style={{ padding: 0, overflow: 'hidden' }}
        >
          {/* Chat Header */}
          <div
            className="p-4 flex items-center justify-between"
            style={{ borderBottom: '1px solid var(--border)' }}
          >
            <div className="flex items-center gap-3">
              <div
                className="p-2 rounded-lg"
                style={{ backgroundColor: 'var(--emerald-glow)' }}
              >
                <Sparkles className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
              </div>
              <div>
                <h2 className="font-medium" style={{ color: 'var(--fg)' }}>Security AI Assistant</h2>
                <p className="text-xs" style={{ color: 'var(--muted)' }}>
                  {activeConversationId ? `Conversation active` : 'Powered by advanced threat analysis'}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={startNewConversation}
                className="p-2 rounded-lg transition-colors hover:brightness-110"
                style={{ color: 'var(--muted)', backgroundColor: 'transparent' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                  e.currentTarget.style.color = 'var(--fg)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent'
                  e.currentTarget.style.color = 'var(--muted)'
                }}
                title="New conversation"
              >
                <Plus className="h-4 w-4" />
              </button>
              <button
                onClick={clearChat}
                className="p-2 rounded-lg transition-colors"
                style={{ color: 'var(--muted)', backgroundColor: 'transparent' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                  e.currentTarget.style.color = 'var(--fg)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent'
                  e.currentTarget.style.color = 'var(--muted)'
                }}
                title="Clear chat"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Messages Area */}
          <div
            className="flex-1 overflow-y-auto p-4 space-y-4"
            style={{ backgroundColor: 'var(--bg-2)' }}
          >
            {welcomeLoading && messages.length === 0 ? (
              <div className="flex gap-3">
                <div
                  className="p-2 rounded-lg h-fit"
                  style={{ backgroundColor: 'var(--emerald-glow)' }}
                >
                  <Bot className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                </div>
                <div
                  className="rounded-xl p-4"
                  style={{ backgroundColor: 'var(--surface)' }}
                >
                  <div className="flex items-center gap-2" style={{ color: 'var(--muted)' }}>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span className="text-sm">Initializing assistant...</span>
                  </div>
                </div>
              </div>
            ) : (
              messages.map((message) => (
                <div
                  key={message.id}
                  className={cn(
                    'flex gap-3',
                    message.role === 'user' ? 'justify-end' : 'justify-start'
                  )}
                >
                  {message.role === 'assistant' && (
                    <div
                      className="p-2 rounded-lg h-fit flex-shrink-0"
                      style={{ backgroundColor: 'var(--emerald-glow)' }}
                    >
                      <Bot className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                    </div>
                  )}
                  <div
                    className={cn(
                      'max-w-[80%] rounded-xl',
                      message.role === 'user' ? 'p-4' : ''
                    )}
                    style={{
                      backgroundColor: message.role === 'user'
                        ? 'var(--emerald-600)'
                        : 'var(--surface)',
                      color: message.role === 'user' ? '#fff' : 'var(--fg)',
                      border: message.error ? '1px solid var(--crit)' : 'none',
                    }}
                  >
                    {message.role === 'assistant' ? (
                      <div className="p-4">
                        <div className="prose prose-invert prose-sm max-w-none">
                          {message.content.split('\n').map((line, idx) => {
                            if (line.startsWith('**') && line.endsWith('**')) {
                              return <h4 key={idx} className="font-semibold mt-3 mb-1" style={{ color: 'var(--fg)' }}>{line.replace(/\*\*/g, '')}</h4>
                            }
                            if (line.startsWith('```')) {
                              return null
                            }
                            if (line.startsWith('- ') || line.match(/^\d+\./)) {
                              return <p key={idx} className="text-sm my-1 ml-2" style={{ color: 'var(--fg-2)' }}>{line}</p>
                            }
                            return line ? <p key={idx} className="text-sm my-1" style={{ color: 'var(--fg-2)' }}>{line}</p> : <br key={idx} />
                          })}
                        </div>
                        {message.isStreaming && (
                          <div className="flex items-center gap-2 mt-2" style={{ color: 'var(--emerald-400)' }}>
                            <Loader2 className="h-3 w-3 animate-spin" />
                            <span className="text-xs">Generating response...</span>
                          </div>
                        )}
                        {!message.isStreaming && message.suggestedActions && message.suggestedActions.length > 0 && (
                          <div
                            className="mt-4 pt-4"
                            style={{ borderTop: '1px solid var(--hairline)' }}
                          >
                            <p className="text-xs mb-2" style={{ color: 'var(--subtle)' }}>Suggested actions:</p>
                            <div className="flex flex-wrap gap-2">
                              {message.suggestedActions.map((action) => (
                                <button
                                  key={action.id}
                                  onClick={() => handleSuggestedAction(action)}
                                  className="text-xs px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1"
                                  style={{
                                    backgroundColor: 'var(--surface-2)',
                                    color: 'var(--fg-2)'
                                  }}
                                  onMouseEnter={(e) => {
                                    e.currentTarget.style.backgroundColor = 'var(--surface-3)'
                                  }}
                                  onMouseLeave={(e) => {
                                    e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                                  }}
                                >
                                  {action.label}
                                  <ChevronRight className="h-3 w-3" />
                                </button>
                              ))}
                            </div>
                          </div>
                        )}
                        {!message.isStreaming && (
                          <div
                            className="flex items-center justify-between mt-3 pt-2"
                            style={{ borderTop: '1px solid var(--hairline)' }}
                          >
                            <span className="text-xs" style={{ color: 'var(--subtle)' }}>
                              {new Date(message.timestamp).toLocaleTimeString()}
                            </span>
                            <button
                              onClick={() => handleCopy(message.content, message.id)}
                              className="transition-colors"
                              style={{ color: 'var(--subtle)' }}
                              onMouseEnter={(e) => {
                                e.currentTarget.style.color = 'var(--fg-2)'
                              }}
                              onMouseLeave={(e) => {
                                e.currentTarget.style.color = 'var(--subtle)'
                              }}
                            >
                              {copiedId === message.id ? (
                                <Check className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                              ) : (
                                <Copy className="h-4 w-4" />
                              )}
                            </button>
                          </div>
                        )}
                      </div>
                    ) : (
                      <>
                        <p className="text-sm whitespace-pre-wrap">{message.content}</p>
                        <p className="text-xs mt-2 opacity-60">
                          {new Date(message.timestamp).toLocaleTimeString()}
                        </p>
                      </>
                    )}
                  </div>
                  {message.role === 'user' && (
                    <div
                      className="p-2 rounded-lg h-fit flex-shrink-0"
                      style={{ backgroundColor: 'var(--surface-2)' }}
                    >
                      <User className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                    </div>
                  )}
                </div>
              ))
            )}
            {isProcessing && !messages.some(m => m.isStreaming) && (
              <div className="flex gap-3">
                <div
                  className="p-2 rounded-lg h-fit"
                  style={{ backgroundColor: 'var(--emerald-glow)' }}
                >
                  <Bot className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
                </div>
                <div
                  className="rounded-xl p-4"
                  style={{ backgroundColor: 'var(--surface)' }}
                >
                  <div className="flex items-center gap-2" style={{ color: 'var(--muted)' }}>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span className="text-sm">Analyzing your query...</span>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick Queries */}
          <div
            className="p-4"
            style={{
              borderTop: '1px solid var(--border)',
              backgroundColor: 'var(--surface)'
            }}
          >
            <div className="flex items-center justify-between mb-2">
              <p className="text-xs" style={{ color: 'var(--subtle)' }}>Quick queries:</p>
              <button
                onClick={loadSuggestions}
                disabled={suggestionsLoading}
                className="text-xs transition-colors flex items-center gap-1"
                style={{ color: 'var(--subtle)' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = 'var(--fg-2)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = 'var(--subtle)'
                }}
                title="Refresh suggestions"
              >
                <RefreshCw className={cn('h-3 w-3', suggestionsLoading && 'animate-spin')} />
              </button>
            </div>
            <div className="flex flex-wrap gap-2">
              {suggestionsLoading && suggestedQueries.length === 0 ? (
                <div className="flex items-center gap-2 text-xs py-1" style={{ color: 'var(--subtle)' }}>
                  <Loader2 className="h-3 w-3 animate-spin" />
                  Loading suggestions...
                </div>
              ) : (
                suggestedQueries.slice(0, 4).map((sample, idx) => {
                  const IconComponent = iconMap[sample.icon] || AlertTriangle
                  return (
                    <button
                      key={idx}
                      onClick={() => handleSendMessage(sample.query)}
                      className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg transition-colors"
                      style={{
                        backgroundColor: 'var(--surface-2)',
                        color: 'var(--fg-2)'
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = 'var(--surface-3)'
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                      }}
                    >
                      <IconComponent className="h-3 w-3" />
                      {sample.label}
                    </button>
                  )
                })
              )}
            </div>
          </div>

          {/* Input Area */}
          <div
            className="p-4"
            style={{ borderTop: '1px solid var(--border)' }}
          >
            <div className="flex gap-3">
              <input
                type="text"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
                placeholder="Ask about threats, hunt for IOCs, get response guidance..."
                className="flex-1 rounded-xl px-4 py-3 focus:outline-none focus:ring-2"
                style={{
                  backgroundColor: 'var(--bg)',
                  border: '1px solid var(--border)',
                  color: 'var(--fg)',
                  '--tw-ring-color': 'var(--emerald-500)',
                } as React.CSSProperties}
                disabled={isProcessing}
              />
              <button
                onClick={() => handleSendMessage()}
                disabled={!inputValue.trim() || isProcessing}
                className="px-4 rounded-xl transition-colors flex items-center gap-2"
                style={{
                  backgroundColor: inputValue.trim() && !isProcessing
                    ? 'var(--emerald-500)'
                    : 'var(--surface-2)',
                  color: inputValue.trim() && !isProcessing
                    ? '#fff'
                    : 'var(--subtle)',
                  cursor: inputValue.trim() && !isProcessing ? 'pointer' : 'not-allowed',
                }}
              >
                {isProcessing ? <Loader2 className="h-5 w-5 animate-spin" /> : <Send className="h-5 w-5" />}
              </button>
            </div>
          </div>
        </div>

        {/* Right Sidebar */}
        <div className="w-80 space-y-6 flex-shrink-0 overflow-y-auto">
          {/* Saved Conversations */}
          <div className="card-sentinel rounded-xl" style={{ padding: 0 }}>
            <div
              className="p-4"
              style={{ borderBottom: '1px solid var(--border)' }}
            >
              <h3 className="font-medium flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <MessageSquare className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                Conversations
              </h3>
            </div>
            <div className="max-h-[200px] overflow-y-auto">
              {conversationsLoading ? (
                <div className="p-4 text-center" style={{ color: 'var(--subtle)' }}>
                  <Loader2 className="h-5 w-5 mx-auto mb-1 animate-spin" />
                  <p className="text-xs">Loading...</p>
                </div>
              ) : conversations.length === 0 ? (
                <div className="p-6 text-center" style={{ color: 'var(--subtle)' }}>
                  <MessageSquare className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No saved conversations</p>
                </div>
              ) : (
                conversations.slice(0, 10).map((conv) => (
                  <button
                    key={conv.id}
                    onClick={() => loadConversation(conv.id)}
                    className={cn(
                      'w-full p-3 text-left transition-colors',
                      activeConversationId === conv.id && 'border-l-2'
                    )}
                    style={{
                      borderBottom: '1px solid var(--hairline)',
                      backgroundColor: activeConversationId === conv.id ? 'var(--surface-2)' : 'transparent',
                      borderLeftColor: activeConversationId === conv.id ? 'var(--emerald-400)' : 'transparent',
                    }}
                    onMouseEnter={(e) => {
                      if (activeConversationId !== conv.id) {
                        e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                      }
                    }}
                    onMouseLeave={(e) => {
                      if (activeConversationId !== conv.id) {
                        e.currentTarget.style.backgroundColor = 'transparent'
                      }
                    }}
                  >
                    <p className="text-sm truncate" style={{ color: 'var(--fg)' }}>{conv.title}</p>
                    <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>
                      {new Date(conv.updatedAt).toLocaleDateString()} {new Date(conv.updatedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </p>
                  </button>
                ))
              )}
            </div>
          </div>

          {/* Context-Aware Recommendations */}
          <div className="card-sentinel rounded-xl" style={{ padding: 0 }}>
            <div
              className="p-4"
              style={{ borderBottom: '1px solid var(--border)' }}
            >
              <h3 className="font-medium flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <Lightbulb className="h-4 w-4" style={{ color: 'var(--high)' }} />
                Recommendations
              </h3>
            </div>
            <div className="max-h-[300px] overflow-y-auto">
              {recommendations.length === 0 ? (
                <div className="p-6 text-center" style={{ color: 'var(--subtle)' }}>
                  <Lightbulb className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No recommendations</p>
                </div>
              ) : (
                recommendations.map((rec) => {
                  const IconComponent = categoryIcons[rec.category]
                  return (
                    <button
                      key={rec.id}
                      onClick={() => handleSendMessage(`Tell me more about: ${rec.title}`)}
                      className={cn(
                        'w-full p-3 text-left transition-colors border-l-2',
                        priorityColors[rec.priority]
                      )}
                      style={{ borderBottom: '1px solid var(--hairline)' }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = ''
                      }}
                    >
                      <div className="flex items-start gap-2">
                        <IconComponent className={cn(
                          'h-4 w-4 mt-0.5 flex-shrink-0'
                        )} style={{
                          color: rec.priority === 'high' ? 'var(--crit)' :
                                 rec.priority === 'medium' ? 'var(--high)' : 'var(--muted)'
                        }} />
                        <div>
                          <p className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{rec.title}</p>
                          <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{rec.description}</p>
                          {rec.relatedAlerts && (
                            <p className="text-xs mt-1" style={{ color: 'var(--emerald-400)' }}>{rec.relatedAlerts} related alerts</p>
                          )}
                        </div>
                      </div>
                    </button>
                  )
                })
              )}
            </div>
          </div>

          {/* Query History */}
          <div className="card-sentinel rounded-xl" style={{ padding: 0 }}>
            <div
              className="p-4"
              style={{ borderBottom: '1px solid var(--border)' }}
            >
              <h3 className="font-medium flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                <History className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                Query History
              </h3>
            </div>
            <div className="max-h-[280px] overflow-y-auto">
              {queryHistory.length === 0 ? (
                <div className="p-6 text-center" style={{ color: 'var(--subtle)' }}>
                  <History className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No query history</p>
                </div>
              ) : (
                queryHistory.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => handleSendMessage(item.query)}
                    className="w-full p-3 text-left transition-colors"
                    style={{ borderBottom: '1px solid var(--hairline)' }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.backgroundColor = 'transparent'
                    }}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <span className={cn('text-xs px-1.5 py-0.5 rounded', categoryColors[item.category])}>
                        {item.category}
                      </span>
                      <span className="text-xs flex items-center gap-1" style={{ color: 'var(--subtle)' }}>
                        <Clock className="h-3 w-3" />
                        {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                    <p className="text-sm truncate" style={{ color: 'var(--fg-2)' }}>{item.query}</p>
                  </button>
                ))
              )}
            </div>
          </div>

          {/* Quick Stats */}
          <div className="card-sentinel rounded-xl p-4">
            <h3 className="font-medium mb-3" style={{ color: 'var(--fg)' }}>Environment Context</h3>
            <div className="space-y-2 text-sm">
              <div className="flex items-center justify-between">
                <span style={{ color: 'var(--muted)' }}>Active Agents</span>
                <span className="font-medium" style={{ color: 'var(--fg)' }}>{environmentContext.activeAgents}</span>
              </div>
              <div className="flex items-center justify-between">
                <span style={{ color: 'var(--muted)' }}>Open Alerts</span>
                <span
                  className="font-medium"
                  style={{ color: environmentContext.openAlerts > 0 ? 'var(--crit)' : 'var(--fg)' }}
                >
                  {environmentContext.openAlerts > 0 ? `${environmentContext.openAlerts} high` : '0'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span style={{ color: 'var(--muted)' }}>Active Investigations</span>
                <span
                  className="font-medium"
                  style={{ color: environmentContext.activeInvestigations > 0 ? 'var(--high)' : 'var(--fg)' }}
                >
                  {environmentContext.activeInvestigations}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span style={{ color: 'var(--muted)' }}>Events Today</span>
                <span className="font-medium" style={{ color: 'var(--fg)' }}>{environmentContext.eventsToday.toLocaleString()}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <Dialog
        open={!!pendingAction}
        onOpenChange={(o) => !o && setPendingAction(null)}
        title="Confirm action"
        description={pendingAction ? `Run action: ${pendingAction.label}?` : ''}
      >
        <DialogFooter>
          <button
            type="button"
            className="btn-sentinel btn-sentinel-secondary"
            onClick={() => setPendingAction(null)}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn-sentinel btn-sentinel-primary"
            onClick={confirmPendingAction}
          >
            Run action
          </button>
        </DialogFooter>
      </Dialog>
    </MainLayout>
  )
}
