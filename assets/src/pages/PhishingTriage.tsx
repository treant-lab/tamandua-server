import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Fish,
  Mail,
  AlertTriangle,
  CheckCircle,
  Clock,
  User,
  Shield,
  Ban,
  Trash2,
  Search,
  Filter,
  RefreshCw,
  Users,
  Link as LinkIcon,
  Paperclip,
  Brain,
  Eye,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { Select, SelectItem } from '@/components/ui/baseui'
import { useState } from 'react'
import axios from 'axios'
import { toast } from 'sonner'

// Types
interface ReportedEmail {
  id: string
  subject: string
  sender: string
  senderDomain: string
  recipient: string
  reportedBy: string
  reportedAt: string
  receivedAt: string
  hasAttachments: boolean
  hasLinks: boolean
  linkCount: number
  attachmentCount: number
  headers: Record<string, string>
  status: 'pending' | 'analyzing' | 'reviewed' | 'resolved'
}

interface AIClassification {
  emailId: string
  verdict: 'phishing' | 'spam' | 'suspicious' | 'legitimate'
  confidence: number
  reasons: string[]
  indicators: {
    type: string
    value: string
    severity: 'high' | 'medium' | 'low'
  }[]
  analyzedAt: string
  model: string
}

interface VerdictHistory {
  id: string
  emailId: string
  subject: string
  sender: string
  verdict: 'phishing' | 'spam' | 'suspicious' | 'legitimate'
  reviewedBy: string
  reviewedAt: string
  actionsTaken: string[]
  notes: string
}

interface ReporterStats {
  email: string
  name: string
  department: string
  totalReports: number
  accurateReports: number
  falsePositives: number
  lastReport: string
  accuracyRate: number
}

interface PhishingTriagePageProps {
  reportedEmails?: ReportedEmail[]
  classifications?: AIClassification[]
  verdictHistory?: VerdictHistory[]
  reporterStats?: ReporterStats[]
  stats?: {
    totalReportsToday: number
    pendingCount: number
    phishingDetected: number
    avgConfidence: number
  }
}

// Default values
const defaultStats = {
  totalReportsToday: 0,
  pendingCount: 0,
  phishingDetected: 0,
  avgConfidence: 0,
}

export default function PhishingTriage({
  reportedEmails = [],
  classifications = [],
  verdictHistory = [],
  reporterStats = [],
  stats = defaultStats,
}: PhishingTriagePageProps) {
  const [selectedEmail, setSelectedEmail] = useState<ReportedEmail | null>(null)
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [activeTab, setActiveTab] = useState<'queue' | 'history' | 'reporters'>('queue')
  const [loading, setLoading] = useState<string | null>(null)

  const handleRefresh = () => {
    router.reload()
  }

  const handleBlockSender = async () => {
    if (!selectedEmail) return
    setLoading('block-sender')
    try {
      await axios.post(`/api/v1/phishing/${selectedEmail.id}/block-sender`)
      toast.success('Sender blocked successfully')
      router.reload()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'Failed to block sender')
    } finally {
      setLoading(null)
    }
  }

  const handleQuarantine = async () => {
    if (!selectedEmail) return
    setLoading('quarantine')
    try {
      await axios.post(`/api/v1/phishing/${selectedEmail.id}/quarantine`)
      toast.success('Email quarantined')
      router.reload()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'Failed to quarantine email')
    } finally {
      setLoading(null)
    }
  }

  const handleReport = async () => {
    if (!selectedEmail) return
    setLoading('report')
    try {
      await axios.post(`/api/v1/phishing/${selectedEmail.id}/report`)
      toast.success('Reported to vendor')
      router.reload()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'Failed to report')
    } finally {
      setLoading(null)
    }
  }

  const handleMarkSafe = async () => {
    if (!selectedEmail) return
    setLoading('mark-safe')
    try {
      await axios.post(`/api/v1/phishing/${selectedEmail.id}/mark-safe`)
      toast.success('Email marked as safe')
      router.reload()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'Failed to mark as safe')
    } finally {
      setLoading(null)
    }
  }

  const handleViewEmail = () => {
    if (!selectedEmail) return
    window.open(`/api/v1/phishing/${selectedEmail.id}`, '_blank')
  }

  const getClassification = (emailId: string) => {
    return classifications.find((c) => c.emailId === emailId)
  }

  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case 'phishing':
        return 'text-red-400 bg-red-500/20'
      case 'spam':
        return 'text-orange-400 bg-orange-500/20'
      case 'suspicious':
        return 'text-yellow-400 bg-yellow-500/20'
      case 'legitimate':
        return 'text-green-400 bg-green-500/20'
      default:
        return 'text-[var(--muted)] bg-[var(--surface-raised)]'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pending':
        return 'text-yellow-400 bg-yellow-500/20'
      case 'analyzing':
        return 'text-blue-400 bg-blue-500/20'
      case 'reviewed':
        return 'text-purple-400 bg-purple-500/20'
      case 'resolved':
        return 'text-green-400 bg-green-500/20'
      default:
        return 'text-[var(--muted)] bg-[var(--surface-raised)]'
    }
  }

  const filteredEmails = reportedEmails.filter((email) => {
    if (statusFilter !== 'all' && email.status !== statusFilter) return false
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      return (
        email.subject.toLowerCase().includes(query) ||
        email.sender.toLowerCase().includes(query) ||
        email.reportedBy.toLowerCase().includes(query)
      )
    }
    return true
  })

  return (
    <MainLayout title="Phishing Triage">
      <Head title="Phishing Triage - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <StatCard
            icon={Mail}
            label="Reports Today"
            value={stats.totalReportsToday}
            color="primary"
          />
          <StatCard
            icon={Clock}
            label="Pending Review"
            value={stats.pendingCount}
            color="yellow"
            highlight={stats.pendingCount > 5}
          />
          <StatCard
            icon={Fish}
            label="Phishing Detected"
            value={stats.phishingDetected}
            color="red"
          />
          <StatCard
            icon={Brain}
            label="AI Confidence"
            value={`${stats.avgConfidence}%`}
            color="green"
          />
        </div>

        {/* Main Content Area */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Panel - Email Queue / History / Reporters */}
          <div className="lg:col-span-2 space-y-4">
            {/* Tabs */}
            <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setActiveTab('queue')}
                    className={cn(
                      'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                      activeTab === 'queue'
                        ? 'bg-primary-600 text-white'
                        : 'text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface-raised)]'
                    )}
                  >
                    <Mail className="h-4 w-4 inline-block mr-2" />
                    Email Queue ({filteredEmails.length})
                  </button>
                  <button
                    onClick={() => setActiveTab('history')}
                    className={cn(
                      'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                      activeTab === 'history'
                        ? 'bg-primary-600 text-white'
                        : 'text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface-raised)]'
                    )}
                  >
                    <Clock className="h-4 w-4 inline-block mr-2" />
                    Verdict History
                  </button>
                  <button
                    onClick={() => setActiveTab('reporters')}
                    className={cn(
                      'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                      activeTab === 'reporters'
                        ? 'bg-primary-600 text-white'
                        : 'text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface-raised)]'
                    )}
                  >
                    <Users className="h-4 w-4 inline-block mr-2" />
                    Reporter Stats
                  </button>
                </div>
                <button
                  onClick={handleRefresh}
                  className="flex items-center gap-2 bg-[var(--surface-raised)] hover:bg-[var(--surface-elevated)] rounded-lg px-3 py-1.5 text-sm text-[var(--muted)]"
                >
                  <RefreshCw className="h-4 w-4" />
                  Refresh
                </button>
              </div>

              {/* Queue Tab */}
              {activeTab === 'queue' && (
                <>
                  {/* Filters */}
                  <div className="flex items-center gap-4 mb-4">
                    <div className="relative flex-1">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
                      <input
                        type="text"
                        placeholder="Search emails..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full bg-[var(--surface-raised)] border border-[var(--border)] rounded-lg pl-10 pr-4 py-2 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:outline-none focus:ring-2 focus:ring-primary-500"
                      />
                    </div>
                    <div className="flex items-center gap-2">
                      <Filter className="h-4 w-4 text-[var(--muted)]" />
                      <Select
                        value={statusFilter}
                        onValueChange={setStatusFilter}
                        placeholder="All Status"
                        className="bg-[var(--surface-raised)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm text-[var(--muted)] focus:outline-none focus:ring-2 focus:ring-primary-500"
                      >
                        <SelectItem value="all">All Status</SelectItem>
                        <SelectItem value="pending">Pending</SelectItem>
                        <SelectItem value="analyzing">Analyzing</SelectItem>
                        <SelectItem value="reviewed">Reviewed</SelectItem>
                        <SelectItem value="resolved">Resolved</SelectItem>
                      </Select>
                    </div>
                  </div>

                  {/* Email List */}
                  <div className="space-y-2">
                    {filteredEmails.length === 0 ? (
                      <div className="p-12 text-center text-[var(--muted)]">
                        <Mail className="h-12 w-12 mx-auto mb-4 opacity-50" />
                        <p>No reported emails</p>
                      </div>
                    ) : (
                      filteredEmails.map((email) => {
                        const classification = getClassification(email.id)
                        return (
                          <div
                            key={email.id}
                            onClick={() => setSelectedEmail(email)}
                            className={cn(
                              'p-4 rounded-lg border cursor-pointer transition-colors',
                              selectedEmail?.id === email.id
                                ? 'bg-[var(--surface-raised)] border-primary-500'
                                : 'bg-[var(--surface-raised)]/30 border-[var(--border)] hover:bg-[var(--surface-raised)]/50'
                            )}
                          >
                            <div className="flex items-start justify-between">
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 mb-1">
                                  <h4 className="text-[var(--fg)] font-medium truncate">
                                    {email.subject}
                                  </h4>
                                  <span
                                    className={cn(
                                      'px-2 py-0.5 rounded text-xs font-medium shrink-0',
                                      getStatusColor(email.status)
                                    )}
                                  >
                                    {email.status}
                                  </span>
                                  {classification && (
                                    <span
                                      className={cn(
                                        'px-2 py-0.5 rounded text-xs font-medium shrink-0',
                                        getVerdictColor(classification.verdict)
                                      )}
                                    >
                                      {classification.verdict} ({Math.round(classification.confidence * 100)}%)
                                    </span>
                                  )}
                                </div>
                                <p className="text-sm text-[var(--muted)] truncate">
                                  From: {email.sender}
                                </p>
                                <div className="flex items-center gap-4 mt-2 text-xs text-[var(--muted)]">
                                  <span className="flex items-center gap-1">
                                    <User className="h-3 w-3" />
                                    Reported by {email.reportedBy.split('@')[0]}
                                  </span>
                                  <span className="flex items-center gap-1">
                                    <Clock className="h-3 w-3" />
                                    {formatDate(email.reportedAt)}
                                  </span>
                                  {email.hasAttachments && (
                                    <span className="flex items-center gap-1 text-orange-400">
                                      <Paperclip className="h-3 w-3" />
                                      {email.attachmentCount}
                                    </span>
                                  )}
                                  {email.hasLinks && (
                                    <span className="flex items-center gap-1 text-blue-400">
                                      <LinkIcon className="h-3 w-3" />
                                      {email.linkCount}
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>
                          </div>
                        )
                      })
                    )}
                  </div>
                </>
              )}

              {/* History Tab */}
              {activeTab === 'history' && (
                <div className="space-y-3">
                  {verdictHistory.length === 0 ? (
                    <div className="p-12 text-center text-[var(--muted)]">
                      <Clock className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No verdict history</p>
                    </div>
                  ) : (
                    verdictHistory.map((item) => (
                      <div
                        key={item.id}
                        className="bg-[var(--surface-raised)]/30 rounded-lg p-4 border border-[var(--border)]"
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <h4 className="text-[var(--fg)] font-medium">{item.subject}</h4>
                              <span
                                className={cn(
                                  'px-2 py-0.5 rounded text-xs font-medium',
                                  getVerdictColor(item.verdict)
                                )}
                              >
                                {item.verdict.toUpperCase()}
                              </span>
                            </div>
                            <p className="text-sm text-[var(--muted)]">From: {item.sender}</p>
                          </div>
                          <div className="text-right">
                            <p className="text-xs text-[var(--muted)]">Reviewed by</p>
                            <p className="text-sm text-[var(--muted)]">{item.reviewedBy.split('@')[0]}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-wrap mt-3">
                          {item.actionsTaken.map((action, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-1 bg-[var(--surface-elevated)] rounded text-xs text-[var(--muted)]"
                            >
                              {action}
                            </span>
                          ))}
                        </div>
                        {item.notes && (
                          <p className="mt-2 text-sm text-[var(--muted)] italic">
                            "{item.notes}"
                          </p>
                        )}
                        <p className="mt-2 text-xs text-[var(--muted)]">
                          {formatDate(item.reviewedAt)}
                        </p>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Reporters Tab */}
              {activeTab === 'reporters' && (
                <div className="overflow-x-auto">
                  {reporterStats.length === 0 ? (
                    <div className="p-12 text-center text-[var(--muted)]">
                      <Users className="h-12 w-12 mx-auto mb-4 opacity-50" />
                      <p>No reporter statistics</p>
                    </div>
                  ) : (
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-[var(--border)]">
                          <th className="text-left p-3 text-sm font-medium text-[var(--muted)]">Reporter</th>
                          <th className="text-left p-3 text-sm font-medium text-[var(--muted)]">Department</th>
                          <th className="text-left p-3 text-sm font-medium text-[var(--muted)]">Reports</th>
                          <th className="text-left p-3 text-sm font-medium text-[var(--muted)]">Accuracy</th>
                          <th className="text-left p-3 text-sm font-medium text-[var(--muted)]">Last Report</th>
                        </tr>
                      </thead>
                      <tbody>
                        {reporterStats.map((reporter) => (
                          <tr
                            key={reporter.email}
                            className="border-b border-[var(--border)]/50 hover:bg-[var(--surface-raised)]/30"
                          >
                            <td className="p-3">
                              <div>
                                <p className="text-[var(--fg)] font-medium">{reporter.name}</p>
                                <p className="text-xs text-[var(--muted)]">{reporter.email}</p>
                              </div>
                            </td>
                            <td className="p-3">
                              <span className="px-2 py-1 bg-[var(--surface-raised)] rounded text-xs text-[var(--muted)]">
                                {reporter.department}
                              </span>
                            </td>
                            <td className="p-3">
                              <div className="text-[var(--muted)]">
                                <span className="font-medium">{reporter.totalReports}</span>
                                <span className="text-xs text-[var(--muted)] ml-1">
                                  ({reporter.accurateReports} accurate, {reporter.falsePositives} FP)
                                </span>
                              </div>
                            </td>
                            <td className="p-3">
                              <div className="flex items-center gap-2">
                                <div className="w-16 h-2 bg-[var(--surface-elevated)] rounded-full overflow-hidden">
                                  <div
                                    className={cn(
                                      'h-full rounded-full',
                                      reporter.accuracyRate >= 90
                                        ? 'bg-green-500'
                                        : reporter.accuracyRate >= 70
                                        ? 'bg-yellow-500'
                                        : 'bg-red-500'
                                    )}
                                    style={{ width: `${reporter.accuracyRate}%` }}
                                  />
                                </div>
                                <span
                                  className={cn(
                                    'text-sm font-medium',
                                    reporter.accuracyRate >= 90
                                      ? 'text-green-400'
                                      : reporter.accuracyRate >= 70
                                      ? 'text-yellow-400'
                                      : 'text-red-400'
                                  )}
                                >
                                  {reporter.accuracyRate}%
                                </span>
                              </div>
                            </td>
                            <td className="p-3 text-sm text-[var(--muted)]">
                              {formatDate(reporter.lastReport)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Right Panel - Details / Quick Actions */}
          <div className="space-y-4">
            {/* AI Classification Details */}
            {selectedEmail && (
              <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
                <h3 className="text-lg font-semibold text-[var(--fg)] mb-4 flex items-center gap-2">
                  <Brain className="h-5 w-5 text-primary-400" />
                  AI Analysis
                </h3>

                {(() => {
                  const classification = getClassification(selectedEmail.id)
                  if (!classification) {
                    return (
                      <div className="text-center text-[var(--muted)] py-8">
                        <Brain className="h-8 w-8 mx-auto mb-2 opacity-50 animate-pulse" />
                        <p className="text-sm">Analyzing...</p>
                      </div>
                    )
                  }

                  return (
                    <div className="space-y-4">
                      {/* Verdict */}
                      <div className="flex items-center justify-between">
                        <span className="text-[var(--muted)]">Verdict</span>
                        <span
                          className={cn(
                            'px-3 py-1 rounded-lg text-sm font-medium',
                            getVerdictColor(classification.verdict)
                          )}
                        >
                          {classification.verdict.toUpperCase()}
                        </span>
                      </div>

                      {/* Confidence */}
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[var(--muted)] text-sm">Confidence</span>
                          <span className="text-[var(--fg)] font-medium">
                            {Math.round(classification.confidence * 100)}%
                          </span>
                        </div>
                        <div className="h-2 bg-[var(--surface-raised)] rounded-full overflow-hidden">
                          <div
                            className={cn(
                              'h-full rounded-full',
                              classification.confidence >= 0.9
                                ? 'bg-green-500'
                                : classification.confidence >= 0.7
                                ? 'bg-yellow-500'
                                : 'bg-red-500'
                            )}
                            style={{ width: `${classification.confidence * 100}%` }}
                          />
                        </div>
                      </div>

                      {/* Reasons */}
                      <div>
                        <h4 className="text-sm text-[var(--muted)] mb-2">Detection Reasons</h4>
                        <ul className="space-y-1">
                          {classification.reasons.map((reason, idx) => (
                            <li
                              key={idx}
                              className="flex items-start gap-2 text-sm text-[var(--muted)]"
                            >
                              <CheckCircle className="h-4 w-4 text-primary-400 mt-0.5 shrink-0" />
                              {reason}
                            </li>
                          ))}
                        </ul>
                      </div>

                      {/* Indicators */}
                      {classification.indicators.length > 0 && (
                        <div>
                          <h4 className="text-sm text-[var(--muted)] mb-2">Indicators</h4>
                          <div className="space-y-2">
                            {classification.indicators.map((indicator, idx) => (
                              <div
                                key={idx}
                                className={cn(
                                  'p-2 rounded-lg border-l-2',
                                  indicator.severity === 'high'
                                    ? 'bg-red-900/20 border-red-500'
                                    : indicator.severity === 'medium'
                                    ? 'bg-yellow-900/20 border-yellow-500'
                                    : 'bg-blue-900/20 border-blue-500'
                                )}
                              >
                                <p className="text-xs text-[var(--muted)]">{indicator.type}</p>
                                <p className="text-sm text-[var(--fg)] font-mono truncate">
                                  {indicator.value}
                                </p>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      <p className="text-xs text-[var(--muted)]">
                        Analyzed by {classification.model} at {formatDate(classification.analyzedAt)}
                      </p>
                    </div>
                  )
                })()}
              </div>
            )}

            {/* Quick Actions */}
            <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
              <h3 className="text-lg font-semibold text-[var(--fg)] mb-4 flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary-400" />
                Quick Actions
              </h3>

              <div className="space-y-2">
                <button
                  onClick={handleBlockSender}
                  disabled={!selectedEmail || loading === 'block-sender'}
                  className={cn(
                    'w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors',
                    selectedEmail && loading !== 'block-sender'
                      ? 'bg-red-600 hover:bg-red-700 text-white'
                      : 'bg-[var(--surface-raised)] text-[var(--muted)] cursor-not-allowed'
                  )}
                >
                  <Ban className="h-5 w-5" />
                  <div className="text-left">
                    <p className="font-medium">{loading === 'block-sender' ? 'Blocking...' : 'Block Sender'}</p>
                    <p className="text-xs opacity-75">Add sender to blocklist</p>
                  </div>
                </button>

                <button
                  onClick={handleQuarantine}
                  disabled={!selectedEmail || loading === 'quarantine'}
                  className={cn(
                    'w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors',
                    selectedEmail && loading !== 'quarantine'
                      ? 'bg-orange-600 hover:bg-orange-700 text-white'
                      : 'bg-[var(--surface-raised)] text-[var(--muted)] cursor-not-allowed'
                  )}
                >
                  <Trash2 className="h-5 w-5" />
                  <div className="text-left">
                    <p className="font-medium">{loading === 'quarantine' ? 'Quarantining...' : 'Quarantine'}</p>
                    <p className="text-xs opacity-75">Move to quarantine folder</p>
                  </div>
                </button>

                <button
                  onClick={handleReport}
                  disabled={!selectedEmail || loading === 'report'}
                  className={cn(
                    'w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors',
                    selectedEmail && loading !== 'report'
                      ? 'bg-yellow-600 hover:bg-yellow-700 text-white'
                      : 'bg-[var(--surface-raised)] text-[var(--muted)] cursor-not-allowed'
                  )}
                >
                  <AlertTriangle className="h-5 w-5" />
                  <div className="text-left">
                    <p className="font-medium">{loading === 'report' ? 'Reporting...' : 'Report to Vendor'}</p>
                    <p className="text-xs opacity-75">Submit as malicious sample</p>
                  </div>
                </button>

                <button
                  onClick={handleMarkSafe}
                  disabled={!selectedEmail || loading === 'mark-safe'}
                  className={cn(
                    'w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors',
                    selectedEmail && loading !== 'mark-safe'
                      ? 'bg-green-600 hover:bg-green-700 text-white'
                      : 'bg-[var(--surface-raised)] text-[var(--muted)] cursor-not-allowed'
                  )}
                >
                  <CheckCircle className="h-5 w-5" />
                  <div className="text-left">
                    <p className="font-medium">{loading === 'mark-safe' ? 'Marking...' : 'Mark as Safe'}</p>
                    <p className="text-xs opacity-75">Release to inbox</p>
                  </div>
                </button>

                <button
                  onClick={handleViewEmail}
                  disabled={!selectedEmail}
                  className={cn(
                    'w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors',
                    selectedEmail
                      ? 'bg-[var(--surface-elevated)] hover:bg-[var(--surface-raised)] text-[var(--fg)]'
                      : 'bg-[var(--surface-raised)] text-[var(--muted)] cursor-not-allowed'
                  )}
                >
                  <Eye className="h-5 w-5" />
                  <div className="text-left">
                    <p className="font-medium">View Full Email</p>
                    <p className="text-xs opacity-75">Open in sandbox viewer</p>
                  </div>
                </button>
              </div>
            </div>

            {/* Email Details */}
            {selectedEmail && (
              <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--border)] p-4">
                <h3 className="text-lg font-semibold text-[var(--fg)] mb-4 flex items-center gap-2">
                  <Mail className="h-5 w-5 text-primary-400" />
                  Email Details
                </h3>

                <div className="space-y-3 text-sm">
                  <div>
                    <p className="text-[var(--muted)]">Subject</p>
                    <p className="text-[var(--fg)]">{selectedEmail.subject}</p>
                  </div>
                  <div>
                    <p className="text-[var(--muted)]">From</p>
                    <p className="text-[var(--fg)] font-mono">{selectedEmail.sender}</p>
                  </div>
                  <div>
                    <p className="text-[var(--muted)]">To</p>
                    <p className="text-[var(--muted)]">{selectedEmail.recipient}</p>
                  </div>
                  <div>
                    <p className="text-[var(--muted)]">Received</p>
                    <p className="text-[var(--muted)]">{formatDate(selectedEmail.receivedAt)}</p>
                  </div>
                  <div>
                    <p className="text-[var(--muted)]">Reported By</p>
                    <p className="text-[var(--muted)]">{selectedEmail.reportedBy}</p>
                  </div>
                  {selectedEmail.hasAttachments && (
                    <div className="flex items-center gap-2 text-orange-400">
                      <Paperclip className="h-4 w-4" />
                      {selectedEmail.attachmentCount} attachment(s)
                    </div>
                  )}
                  {selectedEmail.hasLinks && (
                    <div className="flex items-center gap-2 text-blue-400">
                      <LinkIcon className="h-4 w-4" />
                      {selectedEmail.linkCount} link(s) detected
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </MainLayout>
  )
}

function StatCard({
  icon: Icon,
  label,
  value,
  color,
  highlight = false,
}: {
  icon: React.ElementType
  label: string
  value: number | string
  color: 'primary' | 'green' | 'red' | 'yellow'
  highlight?: boolean
}) {
  const colors = {
    primary: 'bg-primary-500/20 text-primary-400',
    green: 'bg-green-500/20 text-green-400',
    red: 'bg-red-500/20 text-red-400',
    yellow: 'bg-yellow-500/20 text-yellow-400',
  }

  return (
    <div
      className={cn(
        'card-sentinel bg-[var(--surface)] rounded-xl border p-4',
        highlight ? 'border-yellow-500 animate-pulse' : 'border-[var(--border)]'
      )}
    >
      <div className="flex items-center gap-3">
        <div className={cn('p-2 rounded-lg', colors[color])}>
          <Icon className="h-5 w-5" />
        </div>
        <div>
          <p className="text-2xl font-bold text-[var(--fg)]">{value}</p>
          <p className="text-sm text-[var(--muted)]">{label}</p>
        </div>
      </div>
    </div>
  )
}
