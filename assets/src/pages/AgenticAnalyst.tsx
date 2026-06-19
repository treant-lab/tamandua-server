import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import { useState, useRef, useEffect, useCallback } from 'react'
import {
  Brain,
  Search,
  Clock,
  AlertTriangle,
  CheckCircle,
  ChevronRight,
  ChevronDown,
  Send,
  User,
  Bot,
  Target,
  Shield,
  Activity,
  FileSearch,
  Loader2,
  Plus,
  X,
  Paperclip,
  Play,
  RefreshCw,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { Select, SelectItem } from '@/components/ui/baseui'

// Types
interface Investigation {
  id: string
  title: string
  status: 'active' | 'completed' | 'pending_review'
  severity: 'critical' | 'high' | 'medium' | 'low'
  startedAt: string
  alertCount: number
  findings: number
  assignedAgent: string
}

interface AIInsight {
  id: string
  type: 'pattern' | 'recommendation' | 'correlation' | 'risk'
  title: string
  description: string
  confidence: number
  timestamp: string
  relatedInvestigations: string[]
}

interface TriageResult {
  id: string
  alertId: string
  alertTitle: string
  verdict: 'malicious' | 'suspicious' | 'benign' | 'needs_review'
  confidence: number
  reasoning: string
  suggestedActions: string[]
  timestamp: string
}

interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: string
  steps?: InvestigationStep[]
  error?: boolean
}

interface InvestigationStep {
  id: string
  label: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  detail?: string
  startedAt?: string
  completedAt?: string
}

interface EvidenceItem {
  id: string
  type: 'alert' | 'event' | 'process' | 'file' | 'network' | 'ioc'
  title: string
  description: string
  sourceId: string
  addedAt: string
  metadata?: Record<string, any>
}

interface AnalystStats {
  activeInvestigations: number
  insightsGenerated: number
  alertsTriagedToday: number
  confirmedThreats: number
}

interface AgenticAnalystProps {
  investigations: Investigation[]
  activeInvestigation: Investigation | null
  triageQueue: TriageResult[]
  stats: AnalystStats
  insights?: AIInsight[]
  chatHistory?: ChatMessage[]
}

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

export default function Analyst({
  investigations: initialInvestigations,
  activeInvestigation,
  triageQueue: initialTriageQueue,
  stats: initialStats,
  insights: initialInsights = [],
  chatHistory = []
}: AgenticAnalystProps) {
  const [investigations, setInvestigations] = useState<Investigation[]>(initialInvestigations)
  const [selectedInvestigation, setSelectedInvestigation] = useState<Investigation | null>(activeInvestigation)
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>(chatHistory)
  const [inputMessage, setInputMessage] = useState('')
  const [isProcessing, setIsProcessing] = useState(false)
  const [insights, setInsights] = useState<AIInsight[]>(initialInsights)
  const [triageQueue, setTriageQueue] = useState<TriageResult[]>(initialTriageQueue)
  const [stats, setStats] = useState<AnalystStats>(initialStats)

  // Evidence collection state
  const [evidence, setEvidence] = useState<EvidenceItem[]>([])
  const [showEvidencePanel, setShowEvidencePanel] = useState(false)
  const [evidenceSearchQuery, setEvidenceSearchQuery] = useState('')
  const [evidenceSearchResults, setEvidenceSearchResults] = useState<EvidenceItem[]>([])
  const [isSearchingEvidence, setIsSearchingEvidence] = useState(false)
  const [evidenceType, setEvidenceType] = useState<EvidenceItem['type']>('alert')

  // Investigation analysis state
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysisSteps, setAnalysisSteps] = useState<InvestigationStep[]>([])
  const [analysisProgress, setAnalysisProgress] = useState(0)

  const chatEndRef = useRef<HTMLDivElement>(null)
  const abortControllerRef = useRef<AbortController | null>(null)

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [chatMessages])

  // Fetch fresh investigation data on mount
  useEffect(() => {
    async function loadInvestigationData() {
      try {
        const response = await fetch('/api/v1/analyst/investigate', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCsrfToken(),
          },
          body: JSON.stringify({ action: 'list_investigations' }),
        })

        if (response.ok) {
          const result = await response.json()
          if (result.data?.investigations) {
            setInvestigations(result.data.investigations)
          }
          if (result.data?.insights) {
            setInsights(result.data.insights)
          }
          if (result.data?.stats) {
            setStats(result.data.stats)
          }
          if (result.data?.triage_queue) {
            setTriageQueue(result.data.triage_queue)
          }
        }
      } catch (err) {
        logger.error('Failed to load investigation data:', err)
      }
    }

    loadInvestigationData()
  }, [])

  // Send message in investigation chat context
  const handleSendMessage = async () => {
    if (!inputMessage.trim() || isProcessing) return

    const userMessage: ChatMessage = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content: inputMessage,
      timestamp: new Date().toISOString(),
    }

    setChatMessages(prev => [...prev, userMessage])
    setInputMessage('')
    setIsProcessing(true)

    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
    }
    const abortController = new AbortController()
    abortControllerRef.current = abortController

    try {
      const response = await fetch('/api/v1/analyst/investigate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
        body: JSON.stringify({
          action: 'chat',
          query: inputMessage.trim(),
          context: {
            investigation_id: selectedInvestigation?.id || null,
            investigation: selectedInvestigation ? {
              title: selectedInvestigation.title,
              severity: selectedInvestigation.severity,
              status: selectedInvestigation.status,
              alertCount: selectedInvestigation.alertCount,
              findings: selectedInvestigation.findings,
            } : null,
            evidence: evidence.map(e => ({
              id: e.id,
              type: e.type,
              title: e.title,
              source_id: e.sourceId,
              metadata: e.metadata,
            })),
            active_investigations_count: investigations.length,
            previous_messages: chatMessages.slice(-5).map(m => ({
              role: m.role,
              content: m.content,
            })),
          },
        }),
        signal: abortController.signal,
      })

      if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`)
      }

      const result = await response.json()

      if (result.data) {
        const aiResponse: ChatMessage = {
          id: `msg-${Date.now() + 1}`,
          role: 'assistant',
          content: formatAnalystResponse(result.data),
          timestamp: new Date().toISOString(),
          steps: result.data.steps?.map((s: any, i: number) => ({
            id: `step-${i}`,
            label: s.label || s.name,
            status: s.status || 'completed',
            detail: s.detail || s.result,
          })),
        }
        setChatMessages(prev => [...prev, aiResponse])

        // If the response includes updated investigation data, refresh
        if (result.data.updated_investigation) {
          setSelectedInvestigation(result.data.updated_investigation)
        }
      } else {
        throw new Error(result.message || 'Unknown error from AI service')
      }
    } catch (error) {
      if ((error as Error).name === 'AbortError') return

      logger.error('AI investigate error:', error)
      const errorResponse: ChatMessage = {
        id: `msg-${Date.now() + 1}`,
        role: 'assistant',
        content: `I encountered an error processing your request. Please try again.\n\nError: ${error instanceof Error ? error.message : 'Unknown error'}`,
        timestamp: new Date().toISOString(),
        error: true,
      }
      setChatMessages(prev => [...prev, errorResponse])
    } finally {
      setIsProcessing(false)
      abortControllerRef.current = null
    }
  }

  // Run full investigation analysis
  const runInvestigationAnalysis = async (investigationId?: string) => {
    const targetId = investigationId || selectedInvestigation?.id
    if (!targetId || isAnalyzing) return

    setIsAnalyzing(true)
    setAnalysisProgress(0)
    setAnalysisSteps([])

    // Define the expected analysis steps
    const steps: InvestigationStep[] = [
      { id: 'collect', label: 'Collecting evidence and context', status: 'pending' },
      { id: 'correlate', label: 'Correlating events and alerts', status: 'pending' },
      { id: 'analyze', label: 'Analyzing attack patterns', status: 'pending' },
      { id: 'assess', label: 'Assessing risk and impact', status: 'pending' },
      { id: 'recommend', label: 'Generating recommendations', status: 'pending' },
    ]
    setAnalysisSteps(steps)

    try {
      const response = await fetch('/api/v1/analyst/investigate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
          'Accept': 'text/event-stream, application/json',
        },
        body: JSON.stringify({
          action: 'analyze',
          investigation_id: targetId,
          evidence: evidence.map(e => ({
            id: e.id,
            type: e.type,
            title: e.title,
            source_id: e.sourceId,
            metadata: e.metadata,
          })),
        }),
      })

      if (!response.ok) {
        throw new Error(`Analysis API failed: ${response.status}`)
      }

      const contentType = response.headers.get('Content-Type') || ''

      if (contentType.includes('text/event-stream') && response.body) {
        // Stream step-by-step progress
        const reader = response.body.getReader()
        const decoder = new TextDecoder()
        let finalResult: any = null

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

                if (parsed.type === 'step_update') {
                  const stepId = parsed.step_id
                  const stepStatus = parsed.status
                  const stepDetail = parsed.detail

                  setAnalysisSteps(prev =>
                    prev.map(s =>
                      s.id === stepId
                        ? { ...s, status: stepStatus, detail: stepDetail, completedAt: stepStatus === 'completed' ? new Date().toISOString() : s.completedAt }
                        : s
                    )
                  )

                  // Calculate progress
                  const completedCount = steps.filter((_, i) => {
                    const idx = steps.findIndex(st => st.id === stepId)
                    return i <= idx && stepStatus === 'completed'
                  }).length
                  setAnalysisProgress(Math.round((completedCount / steps.length) * 100))
                } else if (parsed.type === 'progress') {
                  setAnalysisProgress(parsed.percentage || 0)
                } else if (parsed.type === 'result') {
                  finalResult = parsed
                } else if (parsed.type === 'error') {
                  throw new Error(parsed.message || 'Analysis error')
                }
              } catch (parseErr) {
                if ((parseErr as Error).message?.includes('Analysis error')) {
                  throw parseErr
                }
              }
            }
          }
        }

        // Add analysis result as chat message
        if (finalResult) {
          addAnalysisResultToChat(finalResult)
        }

        // Mark all steps completed
        setAnalysisSteps(prev =>
          prev.map(s => ({ ...s, status: s.status === 'pending' ? 'completed' : s.status }))
        )
        setAnalysisProgress(100)
      } else {
        // Regular JSON response -- simulate step progression
        const result = await response.json()

        for (let i = 0; i < steps.length; i++) {
          setAnalysisSteps(prev =>
            prev.map((s, idx) =>
              idx === i ? { ...s, status: 'running' } : s
            )
          )

          // Brief delay between steps for visual feedback
          await new Promise(resolve => setTimeout(resolve, 400))

          const stepResult = result.data?.steps?.[i]
          setAnalysisSteps(prev =>
            prev.map((s, idx) =>
              idx === i
                ? { ...s, status: 'completed', detail: stepResult?.detail || stepResult?.result || 'Completed', completedAt: new Date().toISOString() }
                : s
            )
          )
          setAnalysisProgress(Math.round(((i + 1) / steps.length) * 100))
        }

        if (result.data) {
          addAnalysisResultToChat(result.data)
        }
      }
    } catch (error) {
      logger.error('Investigation analysis error:', error)

      // Mark remaining steps as failed
      setAnalysisSteps(prev =>
        prev.map(s => s.status === 'pending' || s.status === 'running' ? { ...s, status: 'failed' } : s)
      )

      const errorMsg: ChatMessage = {
        id: `msg-analysis-err-${Date.now()}`,
        role: 'assistant',
        content: `Investigation analysis failed.\n\nError: ${error instanceof Error ? error.message : 'Unknown error'}`,
        timestamp: new Date().toISOString(),
        error: true,
      }
      setChatMessages(prev => [...prev, errorMsg])
    } finally {
      setIsAnalyzing(false)
    }
  }

  const addAnalysisResultToChat = (data: any) => {
    let content = ''

    if (data.summary) content += data.summary + '\n\n'

    if (data.findings && Array.isArray(data.findings)) {
      content += '**Key Findings:**\n'
      data.findings.forEach((f: any, i: number) => {
        const desc = typeof f === 'string' ? f : f.description || f.title
        content += `${i + 1}. ${desc}\n`
      })
      content += '\n'
    }

    if (data.attack_chain || data.attackChain) {
      const chain = data.attack_chain || data.attackChain
      content += '**Attack Chain:**\n'
      if (Array.isArray(chain)) {
        chain.forEach((step: any) => {
          const label = typeof step === 'string' ? step : step.technique || step.label
          content += `- ${label}\n`
        })
      } else if (typeof chain === 'string') {
        content += chain + '\n'
      }
      content += '\n'
    }

    if (data.risk_assessment || data.riskAssessment) {
      const risk = data.risk_assessment || data.riskAssessment
      content += '**Risk Assessment:**\n'
      if (typeof risk === 'string') {
        content += risk + '\n\n'
      } else {
        if (risk.level) content += `- Risk Level: ${risk.level}\n`
        if (risk.score) content += `- Risk Score: ${risk.score}/100\n`
        if (risk.description) content += `- ${risk.description}\n`
        content += '\n'
      }
    }

    if (data.recommendations && Array.isArray(data.recommendations)) {
      content += '**Recommended Actions:**\n'
      data.recommendations.forEach((rec: any) => {
        const action = typeof rec === 'string' ? rec : rec.action || rec.description
        content += `- ${action}\n`
      })
      content += '\n'
    }

    if (data.mitre_techniques || data.mitreTechniques) {
      const techniques = data.mitre_techniques || data.mitreTechniques
      if (Array.isArray(techniques) && techniques.length > 0) {
        content += '**MITRE ATT&CK Techniques:**\n'
        techniques.forEach((t: any) => {
          const label = typeof t === 'string' ? t : `${t.id || ''} - ${t.name || t.technique || ''}`
          content += `- ${label}\n`
        })
        content += '\n'
      }
    }

    if (!content) {
      content = formatAnalystResponse(data)
    }

    const analysisMsg: ChatMessage = {
      id: `msg-analysis-${Date.now()}`,
      role: 'assistant',
      content: content || 'Analysis complete. No specific findings to report.',
      timestamp: new Date().toISOString(),
      steps: data.steps?.map((s: any, i: number) => ({
        id: `step-result-${i}`,
        label: s.label || s.name,
        status: s.status || 'completed',
        detail: s.detail || s.result,
      })),
    }
    setChatMessages(prev => [...prev, analysisMsg])
  }

  const formatAnalystResponse = (data: any): string => {
    if (typeof data === 'string') return data
    if (typeof data.message === 'string') return data.message

    let response = ''

    if (data.summary) {
      response += data.summary + '\n\n'
    }

    if (data.findings && Array.isArray(data.findings)) {
      response += '**Key Findings:**\n'
      data.findings.slice(0, 5).forEach((finding: any, index: number) => {
        response += `${index + 1}. ${finding.description || finding}\n`
      })
      response += '\n'
    }

    if (data.results && Array.isArray(data.results) && data.results.length > 0) {
      response += `**Related Events (${data.result_count || data.results.length}):**\n`
      data.results.slice(0, 3).forEach((result: any) => {
        if (result.hostname) {
          response += `- ${result.hostname}`
          if (result.event_type) response += ` (${result.event_type})`
          response += '\n'
        }
      })
      if (data.results.length > 3) {
        response += `*...and ${data.results.length - 3} more*\n`
      }
      response += '\n'
    }

    if (data.recommendations && Array.isArray(data.recommendations)) {
      response += '**Recommended Actions:**\n'
      data.recommendations.slice(0, 3).forEach((rec: any) => {
        const action = typeof rec === 'string' ? rec : rec.action || rec.description
        response += `- ${action}\n`
      })
      response += '\n'
    }

    if (data.follow_up_queries && Array.isArray(data.follow_up_queries)) {
      response += '**Suggested Queries:**\n'
      data.follow_up_queries.slice(0, 2).forEach((query: string) => {
        response += `- ${query}\n`
      })
    }

    return response || 'Analysis complete. No specific findings to report for this query.'
  }

  // Evidence search
  const searchEvidence = async () => {
    if (!evidenceSearchQuery.trim()) return

    setIsSearchingEvidence(true)
    setEvidenceSearchResults([])

    try {
      const response = await fetch('/api/v1/analyst/investigate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': getCsrfToken(),
        },
        body: JSON.stringify({
          action: 'search_evidence',
          query: evidenceSearchQuery.trim(),
          evidence_type: evidenceType,
          investigation_id: selectedInvestigation?.id || null,
        }),
      })

      if (response.ok) {
        const result = await response.json()
        if (result.data?.results && Array.isArray(result.data.results)) {
          setEvidenceSearchResults(result.data.results.map((r: any) => ({
            id: r.id || `evidence-${Date.now()}-${Math.random()}`,
            type: r.type || evidenceType,
            title: r.title || r.name || r.description?.slice(0, 60) || 'Untitled',
            description: r.description || r.summary || '',
            sourceId: r.source_id || r.id || '',
            addedAt: new Date().toISOString(),
            metadata: r.metadata || {},
          })))
        }
      }
    } catch (err) {
      logger.error('Evidence search failed:', err)
    } finally {
      setIsSearchingEvidence(false)
    }
  }

  const addEvidence = (item: EvidenceItem) => {
    if (evidence.some(e => e.id === item.id)) return
    setEvidence(prev => [...prev, { ...item, addedAt: new Date().toISOString() }])
  }

  const removeEvidence = (itemId: string) => {
    setEvidence(prev => prev.filter(e => e.id !== itemId))
  }

  // Add alert from triage queue as evidence
  const addTriageAlertAsEvidence = (result: TriageResult) => {
    const item: EvidenceItem = {
      id: `evidence-alert-${result.alertId}`,
      type: 'alert',
      title: result.alertTitle,
      description: `Verdict: ${result.verdict} (${result.confidence}% confidence) - ${result.reasoning}`,
      sourceId: result.alertId,
      addedAt: new Date().toISOString(),
      metadata: {
        verdict: result.verdict,
        confidence: result.confidence,
        suggestedActions: result.suggestedActions,
      },
    }
    addEvidence(item)
  }

  // Add investigation as evidence context
  const addInvestigationAsEvidence = (inv: Investigation) => {
    const item: EvidenceItem = {
      id: `evidence-inv-${inv.id}`,
      type: 'alert',
      title: `Investigation: ${inv.title}`,
      description: `${inv.severity} severity, ${inv.alertCount} alerts, ${inv.findings} findings - ${inv.status}`,
      sourceId: inv.id,
      addedAt: new Date().toISOString(),
      metadata: {
        severity: inv.severity,
        status: inv.status,
        alertCount: inv.alertCount,
        findings: inv.findings,
      },
    }
    addEvidence(item)
  }

  const severityColors = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  }

  const statusColors = {
    active: 'bg-green-500/20 text-green-400',
    completed: 'bg-[var(--surface)]/20 text-[var(--muted)]',
    pending_review: 'bg-purple-500/20 text-purple-400',
  }

  const verdictColors = {
    malicious: 'bg-red-500/20 text-red-400',
    suspicious: 'bg-orange-500/20 text-orange-400',
    benign: 'bg-green-500/20 text-green-400',
    needs_review: 'bg-yellow-500/20 text-yellow-400',
  }

  const insightTypeIcons = {
    pattern: Target,
    recommendation: Shield,
    correlation: Activity,
    risk: AlertTriangle,
  }

  const stepStatusColors = {
    pending: 'text-[var(--muted)]',
    running: 'text-blue-400',
    completed: 'text-[var(--emerald-400)]',
    failed: 'text-red-400',
  }

  const evidenceTypeLabels: Record<EvidenceItem['type'], string> = {
    alert: 'Alerts',
    event: 'Events',
    process: 'Processes',
    file: 'Files',
    network: 'Network',
    ioc: 'IOCs',
  }

  return (
    <MainLayout title="Agentic Security Analyst">
      <Head title="Agentic Analyst - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-green-500/20 rounded-lg">
                <Brain className="h-5 w-5 text-[var(--emerald-400)]" />
              </div>
              <div>
                <p className="text-2xl font-bold text-[var(--fg)]">{stats.activeInvestigations}</p>
                <p className="text-sm text-[var(--muted)]">Active Investigations</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-500/20 rounded-lg">
                <FileSearch className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-[var(--fg)]">{stats.insightsGenerated}</p>
                <p className="text-sm text-[var(--muted)]">AI Insights Generated</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-500/20 rounded-lg">
                <CheckCircle className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-[var(--fg)]">{stats.alertsTriagedToday}</p>
                <p className="text-sm text-[var(--muted)]">Alerts Triaged Today</p>
              </div>
            </div>
          </div>
          <div className="card-sentinel rounded-xl p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-500/20 rounded-lg">
                <AlertTriangle className="h-5 w-5 text-red-400" />
              </div>
              <div>
                <p className="text-2xl font-bold text-[var(--fg)]">{stats.confirmedThreats}</p>
                <p className="text-sm text-[var(--muted)]">Confirmed Threats</p>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Active Investigations */}
          <div className="lg:col-span-2 space-y-6">
            <div className="card-sentinel rounded-xl">
              <div className="p-4 border-b border-[var(--surface)] flex items-center justify-between">
                <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
                  <Search className="h-5 w-5 text-primary-400" />
                  Active Investigations
                </h2>
                {selectedInvestigation && (
                  <button
                    onClick={() => runInvestigationAnalysis()}
                    disabled={isAnalyzing}
                    className={cn(
                      'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
                      isAnalyzing
                        ? 'bg-[var(--surface)] text-[var(--muted)] cursor-not-allowed'
                        : 'bg-primary-600 hover:bg-primary-500 text-white'
                    )}
                  >
                    {isAnalyzing ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4" />
                        Run Analysis
                      </>
                    )}
                  </button>
                )}
              </div>
              <div className="divide-y divide-[var(--surface)]">
                {investigations.length === 0 ? (
                  <div className="p-12 text-center text-[var(--muted)]">
                    <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p className="text-lg font-medium mb-1">No active investigations</p>
                    <p className="text-sm">Investigations will appear here when alerts are analyzed</p>
                  </div>
                ) : (
                  investigations.map((investigation) => (
                    <button
                      key={investigation.id}
                      onClick={() => setSelectedInvestigation(investigation)}
                      className={cn(
                        'w-full p-4 text-left hover:bg-[var(--surface)]/50 transition-colors',
                        selectedInvestigation?.id === investigation.id && 'bg-[var(--surface)]/50'
                      )}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <h3 className="text-[var(--fg)] font-medium">{investigation.title}</h3>
                            <span className={cn('text-xs px-2 py-0.5 rounded border', severityColors[investigation.severity])}>
                              {investigation.severity.toUpperCase()}
                            </span>
                            <span className={cn('text-xs px-2 py-0.5 rounded', statusColors[investigation.status])}>
                              {investigation.status.replace('_', ' ')}
                            </span>
                          </div>
                          <div className="flex items-center gap-4 text-sm text-[var(--muted)]">
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              Started {new Date(investigation.startedAt).toLocaleString()}
                            </span>
                            <span>{investigation.alertCount} alerts</span>
                            <span>{investigation.findings} findings</span>
                          </div>
                          <div className="mt-2 flex items-center gap-2">
                            <span className="text-xs text-[var(--muted)]">
                              Assigned to: {investigation.assignedAgent}
                            </span>
                            <button
                              onClick={(e) => {
                                e.stopPropagation()
                                addInvestigationAsEvidence(investigation)
                              }}
                              className="text-xs text-primary-400 hover:text-primary-300 flex items-center gap-1"
                              title="Add to evidence"
                            >
                              <Paperclip className="h-3 w-3" />
                              Attach
                            </button>
                          </div>
                        </div>
                        <ChevronRight className="h-5 w-5 text-[var(--muted)]" />
                      </div>
                    </button>
                  ))
                )}
              </div>
            </div>

            {/* Analysis Progress */}
            {analysisSteps.length > 0 && (
              <div className="card-sentinel rounded-xl">
                <div className="p-4 border-b border-[var(--surface)]">
                  <div className="flex items-center justify-between">
                    <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
                      <Brain className="h-5 w-5 text-primary-400" />
                      Investigation Analysis
                    </h2>
                    <span className="text-sm text-[var(--muted)]">{analysisProgress}%</span>
                  </div>
                  {/* Progress bar */}
                  <div className="mt-3 h-2 bg-[var(--surface)] rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary-500 rounded-full transition-all duration-500 ease-out"
                      style={{ width: `${analysisProgress}%` }}
                    />
                  </div>
                </div>
                <div className="p-4 space-y-3">
                  {analysisSteps.map((step) => (
                    <div key={step.id} className="flex items-start gap-3">
                      <div className="mt-0.5">
                        {step.status === 'running' ? (
                          <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />
                        ) : step.status === 'completed' ? (
                          <CheckCircle className="h-4 w-4 text-[var(--emerald-400)]" />
                        ) : step.status === 'failed' ? (
                          <AlertTriangle className="h-4 w-4 text-red-400" />
                        ) : (
                          <div className="h-4 w-4 rounded-full border border-[var(--surface)]" />
                        )}
                      </div>
                      <div className="flex-1">
                        <p className={cn('text-sm font-medium', stepStatusColors[step.status])}>
                          {step.label}
                        </p>
                        {step.detail && (
                          <p className="text-xs text-[var(--muted)] mt-0.5">{step.detail}</p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Automated Triage Results */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4 border-b border-[var(--surface)]">
                <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
                  <CheckCircle className="h-5 w-5 text-primary-400" />
                  Automated Triage Results
                </h2>
              </div>
              <div className="divide-y divide-[var(--surface)]">
                {triageQueue.length === 0 ? (
                  <div className="p-12 text-center text-[var(--muted)]">
                    <CheckCircle className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p className="text-lg font-medium mb-1">No alerts in triage queue</p>
                    <p className="text-sm">Automated triage results will appear here</p>
                  </div>
                ) : (
                  triageQueue.map((result) => (
                    <div key={result.id} className="p-4">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <h3 className="text-[var(--fg)] font-medium">{result.alertTitle}</h3>
                          <p className="text-xs text-[var(--muted)] mt-1">Alert ID: {result.alertId}</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={cn('text-xs px-2 py-1 rounded font-medium', verdictColors[result.verdict])}>
                            {result.verdict.replace('_', ' ').toUpperCase()}
                          </span>
                          <span className="text-xs text-[var(--muted)]">{result.confidence}% confidence</span>
                        </div>
                      </div>
                      <p className="text-sm text-[var(--muted)] mb-3">{result.reasoning}</p>
                      <div className="flex items-center justify-between">
                        <div className="flex flex-wrap gap-2">
                          {result.suggestedActions.map((action, idx) => (
                            <span
                              key={idx}
                              className="text-xs bg-[var(--surface)] text-[var(--muted)] px-2 py-1 rounded"
                            >
                              {action}
                            </span>
                          ))}
                        </div>
                        <button
                          onClick={() => addTriageAlertAsEvidence(result)}
                          className="text-xs text-primary-400 hover:text-primary-300 flex items-center gap-1 flex-shrink-0 ml-2"
                          title="Add to evidence"
                        >
                          <Paperclip className="h-3 w-3" />
                          Attach
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Right Column - AI Insights, Evidence & Chat */}
          <div className="space-y-6">
            {/* Evidence Collection Panel */}
            <div className="card-sentinel rounded-xl">
              <button
                onClick={() => setShowEvidencePanel(!showEvidencePanel)}
                className="w-full p-4 border-b border-[var(--surface)] flex items-center justify-between"
              >
                <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
                  <Paperclip className="h-5 w-5 text-primary-400" />
                  Evidence ({evidence.length})
                </h2>
                <ChevronDown className={cn(
                  'h-5 w-5 text-[var(--muted)] transition-transform',
                  showEvidencePanel && 'rotate-180'
                )} />
              </button>

              {showEvidencePanel && (
                <div className="p-4 space-y-4">
                  {/* Evidence Search */}
                  <div className="space-y-2">
                    <div className="flex gap-2">
                      <Select
                        value={evidenceType}
                        onValueChange={(value) => setEvidenceType(value as EvidenceItem['type'])}
                        className="bg-[var(--surface)] border border-[var(--surface)] rounded-lg px-2 py-1.5 text-xs text-[var(--fg)] focus:outline-none focus:ring-1 focus:ring-primary-500"
                      >
                        {Object.entries(evidenceTypeLabels).map(([value, label]) => (
                          <SelectItem key={value} value={value}>{label}</SelectItem>
                        ))}
                      </Select>
                      <input
                        type="text"
                        value={evidenceSearchQuery}
                        onChange={(e) => setEvidenceSearchQuery(e.target.value)}
                        onKeyDown={(e) => e.key === 'Enter' && searchEvidence()}
                        placeholder="Search for evidence..."
                        className="flex-1 bg-[var(--surface)] border border-[var(--surface)] rounded-lg px-3 py-1.5 text-xs text-[var(--fg)] placeholder-[var(--muted)] focus:outline-none focus:ring-1 focus:ring-primary-500"
                      />
                      <button
                        onClick={searchEvidence}
                        disabled={isSearchingEvidence || !evidenceSearchQuery.trim()}
                        className="p-1.5 bg-primary-600 hover:bg-primary-500 text-white rounded-lg transition-colors disabled:bg-[var(--surface)] disabled:text-[var(--muted)]"
                      >
                        {isSearchingEvidence ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                      </button>
                    </div>

                    {/* Search Results */}
                    {evidenceSearchResults.length > 0 && (
                      <div className="max-h-[150px] overflow-y-auto space-y-1 border border-[var(--surface)] rounded-lg p-2">
                        {evidenceSearchResults.map((item) => (
                          <div
                            key={item.id}
                            className="flex items-center justify-between p-2 bg-[var(--surface)]/50 rounded-lg"
                          >
                            <div className="flex-1 min-w-0 mr-2">
                              <p className="text-xs text-[var(--fg)] font-medium truncate">{item.title}</p>
                              <p className="text-xs text-[var(--muted)] truncate">{item.description}</p>
                            </div>
                            <button
                              onClick={() => addEvidence(item)}
                              disabled={evidence.some(e => e.id === item.id)}
                              className={cn(
                                'p-1 rounded transition-colors flex-shrink-0',
                                evidence.some(e => e.id === item.id)
                                  ? 'text-[var(--emerald-400)]'
                                  : 'text-primary-400 hover:bg-[var(--surface)]'
                              )}
                            >
                              {evidence.some(e => e.id === item.id) ? (
                                <CheckCircle className="h-4 w-4" />
                              ) : (
                                <Plus className="h-4 w-4" />
                              )}
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Attached Evidence */}
                  {evidence.length > 0 ? (
                    <div className="space-y-1.5 max-h-[200px] overflow-y-auto">
                      {evidence.map((item) => (
                        <div
                          key={item.id}
                          className="flex items-center justify-between p-2 bg-[var(--surface)]/30 rounded-lg border border-[var(--surface)]/50"
                        >
                          <div className="flex-1 min-w-0 mr-2">
                            <div className="flex items-center gap-1.5">
                              <span className="text-xs bg-[var(--surface)] text-[var(--muted)] px-1.5 py-0.5 rounded">
                                {item.type}
                              </span>
                              <p className="text-xs text-[var(--fg)] font-medium truncate">{item.title}</p>
                            </div>
                          </div>
                          <button
                            onClick={() => removeEvidence(item.id)}
                            className="p-1 text-[var(--muted)] hover:text-red-400 transition-colors flex-shrink-0"
                          >
                            <X className="h-3 w-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-3 text-[var(--muted)]">
                      <Paperclip className="h-6 w-6 mx-auto mb-1 opacity-50" />
                      <p className="text-xs">No evidence attached. Search above or use the Attach buttons on investigations and alerts.</p>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* AI Insights Panel */}
            <div className="card-sentinel rounded-xl">
              <div className="p-4 border-b border-[var(--surface)]">
                <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
                  <Brain className="h-5 w-5 text-primary-400" />
                  AI-Generated Insights
                </h2>
              </div>
              <div className="divide-y divide-[var(--surface)] max-h-[400px] overflow-y-auto">
                {insights.length === 0 ? (
                  <div className="p-6 text-center text-[var(--muted)]">
                    <Brain className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">No insights generated yet</p>
                  </div>
                ) : (
                  insights.map((insight) => {
                    const IconComponent = insightTypeIcons[insight.type]
                    return (
                      <div key={insight.id} className="p-4">
                        <div className="flex items-start gap-3">
                          <div className={cn(
                            'p-2 rounded-lg',
                            insight.type === 'risk' ? 'bg-red-500/20' :
                            insight.type === 'pattern' ? 'bg-purple-500/20' :
                            insight.type === 'correlation' ? 'bg-blue-500/20' : 'bg-green-500/20'
                          )}>
                            <IconComponent className={cn(
                              'h-4 w-4',
                              insight.type === 'risk' ? 'text-red-400' :
                              insight.type === 'pattern' ? 'text-purple-400' :
                              insight.type === 'correlation' ? 'text-blue-400' : 'text-[var(--emerald-400)]'
                            )} />
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center justify-between mb-1">
                              <h3 className="text-sm font-medium text-[var(--fg)]">{insight.title}</h3>
                              <span className="text-xs text-[var(--muted)]">{insight.confidence}%</span>
                            </div>
                            <p className="text-xs text-[var(--muted)]">{insight.description}</p>
                            <div className="mt-2 text-xs text-[var(--muted)]">
                              {new Date(insight.timestamp).toLocaleTimeString()}
                            </div>
                          </div>
                        </div>
                      </div>
                    )
                  })
                )}
              </div>
            </div>

            {/* Investigation Chat Interface */}
            <div className="card-sentinel rounded-xl flex flex-col h-[400px]">
              <div className="p-4 border-b border-[var(--surface)] flex items-center justify-between">
                <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
                  <Bot className="h-5 w-5 text-primary-400" />
                  Investigation Chat
                </h2>
                {evidence.length > 0 && (
                  <span className="text-xs text-primary-400 flex items-center gap-1">
                    <Paperclip className="h-3 w-3" />
                    {evidence.length} evidence items
                  </span>
                )}
              </div>
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {chatMessages.length === 0 && (
                  <div className="text-center py-8 text-[var(--muted)]">
                    <Bot className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">Ask about investigations, evidence, or request analysis.</p>
                    {selectedInvestigation && (
                      <p className="text-xs mt-1 text-primary-400">
                        Context: {selectedInvestigation.title}
                      </p>
                    )}
                  </div>
                )}
                {chatMessages.map((message) => (
                  <div
                    key={message.id}
                    className={cn(
                      'flex gap-3',
                      message.role === 'user' ? 'justify-end' : 'justify-start'
                    )}
                  >
                    {message.role === 'assistant' && (
                      <div className="p-2 bg-primary-500/20 rounded-lg h-fit">
                        <Bot className="h-4 w-4 text-primary-400" />
                      </div>
                    )}
                    <div
                      className={cn(
                        'max-w-[80%] rounded-lg p-3',
                        message.role === 'user'
                          ? 'bg-primary-600 text-white'
                          : 'bg-[var(--surface)] text-[var(--fg)]',
                        message.error && 'border border-red-500/30'
                      )}
                    >
                      <p className="text-sm whitespace-pre-wrap">{message.content}</p>
                      {/* Show reasoning steps inline */}
                      {message.steps && message.steps.length > 0 && (
                        <div className="mt-2 pt-2 border-t border-[var(--surface)] space-y-1">
                          <p className="text-xs text-[var(--muted)] font-medium mb-1">Analysis Steps:</p>
                          {message.steps.map((step) => (
                            <div key={step.id} className="flex items-center gap-2">
                              {step.status === 'completed' ? (
                                <CheckCircle className="h-3 w-3 text-[var(--emerald-400)] flex-shrink-0" />
                              ) : step.status === 'failed' ? (
                                <AlertTriangle className="h-3 w-3 text-red-400 flex-shrink-0" />
                              ) : (
                                <div className="h-3 w-3 rounded-full border border-[var(--muted)] flex-shrink-0" />
                              )}
                              <span className="text-xs text-[var(--muted)]">{step.label}</span>
                              {step.detail && <span className="text-xs text-[var(--muted)]">- {step.detail}</span>}
                            </div>
                          ))}
                        </div>
                      )}
                      <p className="text-xs mt-2 opacity-60">
                        {new Date(message.timestamp).toLocaleTimeString()}
                      </p>
                    </div>
                    {message.role === 'user' && (
                      <div className="p-2 bg-[var(--surface)] rounded-lg h-fit">
                        <User className="h-4 w-4 text-[var(--muted)]" />
                      </div>
                    )}
                  </div>
                ))}
                {isProcessing && (
                  <div className="flex gap-3">
                    <div className="p-2 bg-primary-500/20 rounded-lg h-fit">
                      <Bot className="h-4 w-4 text-primary-400" />
                    </div>
                    <div className="bg-[var(--surface)] rounded-lg p-3">
                      <div className="flex items-center gap-2 text-[var(--muted)]">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        <span className="text-xs">Investigating...</span>
                      </div>
                    </div>
                  </div>
                )}
                <div ref={chatEndRef} />
              </div>
              <div className="p-4 border-t border-[var(--surface)]">
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={inputMessage}
                    onChange={(e) => setInputMessage(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
                    placeholder={
                      selectedInvestigation
                        ? `Ask about "${selectedInvestigation.title}"...`
                        : 'Ask about investigations...'
                    }
                    className="flex-1 bg-[var(--surface)] border border-[var(--surface)] rounded-lg px-4 py-2 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:outline-none focus:ring-2 focus:ring-primary-500"
                    disabled={isProcessing}
                  />
                  <button
                    onClick={handleSendMessage}
                    disabled={!inputMessage.trim() || isProcessing}
                    className={cn(
                      'p-2 rounded-lg transition-colors',
                      inputMessage.trim() && !isProcessing
                        ? 'bg-primary-600 hover:bg-primary-500 text-white'
                        : 'bg-[var(--surface)] text-[var(--muted)] cursor-not-allowed'
                    )}
                  >
                    {isProcessing ? <Loader2 className="h-5 w-5 animate-spin" /> : <Send className="h-5 w-5" />}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </MainLayout>
  )
}
