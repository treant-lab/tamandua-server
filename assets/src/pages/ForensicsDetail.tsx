import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  ArrowLeft,
  AlertTriangle,
  Microscope,
  Clock,
  Download,
  FileText,
  HardDrive,
  Hash,
  Server,
  CheckCircle,
  XCircle,
  Loader2,
  User,
  Activity,
  Link2,
} from 'lucide-react'
import { cn } from '@/lib/utils'

interface ForensicCollection {
  id: string
  agentId: string
  hostname: string
  collectionType: string
  status: 'pending' | 'in_progress' | 'completed' | 'failed'
  requestedBy: string
  requestedAt: string
  completedAt: string | null
  artifacts: unknown[]
  evidenceChainEntries: unknown[]
}

interface Artifact {
  id: string
  type: string
  name: string
  path: string
  size: number
  hash: string
  sha256: string
  md5: string
  collectedAt: string
  metadata: Record<string, unknown>
}

interface AnalysisResult {
  id?: string
  type?: string
  title?: string
  description?: string
  findings?: string[]
  severity?: string
  [key: string]: unknown
}

interface EvidenceChainEntry {
  action: string
  timestamp: string
  user: string
  notes: string
}

interface ForensicsDetailPageProps {
  collectionId: string
  collection: ForensicCollection | null
  artifacts: Artifact[]
  analysisResults: AnalysisResult[]
  evidenceChain: EvidenceChainEntry[]
  error?: string
}

const statusConfig: Record<string, { icon: typeof CheckCircle; color: string; label: string }> = {
  pending: { icon: Clock, color: 'text-yellow-400 bg-yellow-400/10 border-yellow-500/30', label: 'Pending' },
  in_progress: { icon: Loader2, color: 'text-blue-400 bg-blue-400/10 border-blue-500/30', label: 'In Progress' },
  completed: { icon: CheckCircle, color: 'text-green-400 bg-green-400/10 border-green-500/30', label: 'Completed' },
  failed: { icon: XCircle, color: 'text-red-400 bg-red-400/10 border-red-500/30', label: 'Failed' },
}

const formatFileSize = (bytes: number) => {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

export default function ForensicsDetail({
  collectionId,
  collection,
  artifacts,
  analysisResults,
  evidenceChain,
  error,
}: ForensicsDetailPageProps) {
  const formatDate = (dateString?: string | null) => {
    if (!dateString) return 'N/A'
    return new Intl.DateTimeFormat('en-US', {
      dateStyle: 'short',
      timeStyle: 'medium',
    }).format(new Date(dateString))
  }

  if (error || !collection) {
    return (
      <MainLayout title="Forensics Detail">
        <Head title="Forensics Detail - Tamandua EDR" />
        <div className="space-y-6">
          <button
            onClick={() => router.visit('/app/forensics')}
            className="flex items-center gap-2 text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Forensics
          </button>
          <div className="card-sentinel rounded-xl p-12 text-center">
            <AlertTriangle className="h-16 w-16 mx-auto mb-4 text-[var(--muted)]" />
            <p className="text-lg text-[var(--muted)]">{error || 'Collection not found'}</p>
            <p className="text-sm text-[var(--muted)] mt-1">
              The requested forensic collection could not be loaded.
            </p>
          </div>
        </div>
      </MainLayout>
    )
  }

  const status = statusConfig[collection.status] || statusConfig.pending
  const StatusIcon = status.icon

  return (
    <MainLayout title="Forensics Detail">
      <Head title={`Collection ${collectionId} - Tamandua EDR`} />

      <div className="space-y-6">
        {/* Back link */}
        <button
          onClick={() => router.visit('/app/forensics')}
          className="flex items-center gap-2 text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Forensics
        </button>

        {/* Collection Header */}
        <div className="card-sentinel rounded-xl p-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-lg bg-primary-500/10">
                <Microscope className="h-6 w-6 text-primary-400" />
              </div>
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="text-xl font-semibold text-[var(--fg)]">
                    Collection {collectionId.substring(0, 8)}...
                  </h1>
                  <span className={cn('flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border', status.color)}>
                    <StatusIcon className={cn('h-3.5 w-3.5', collection.status === 'in_progress' && 'animate-spin')} />
                    {status.label}
                  </span>
                </div>
                <div className="flex items-center gap-4 text-sm text-[var(--muted)] mt-1">
                  <span className="flex items-center gap-1">
                    <Server className="h-3.5 w-3.5" />
                    {collection.hostname}
                  </span>
                  <span>Type: {collection.collectionType}</span>
                  <span className="font-mono text-xs">Agent: {collection.agentId.substring(0, 8)}...</span>
                </div>
                <div className="flex items-center gap-4 text-xs text-[var(--muted)] mt-2">
                  <span className="flex items-center gap-1">
                    <User className="h-3.5 w-3.5" />
                    Requested by: {collection.requestedBy}
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5" />
                    Requested: {formatDate(collection.requestedAt)}
                  </span>
                  {collection.completedAt && (
                    <span>Completed: {formatDate(collection.completedAt)}</span>
                  )}
                </div>
              </div>
            </div>

            <button
              className="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded-lg text-sm font-medium transition-colors"
              onClick={() => {
                // Placeholder download action
                window.open(`/api/v1/forensics/${collectionId}/download`, '_blank')
              }}
            >
              <Download className="h-4 w-4" />
              Download Artifacts
            </button>
          </div>
        </div>

        {/* Artifacts Table */}
        <div className="card-sentinel rounded-xl">
          <div className="p-4 border-b border-[var(--border)]">
            <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
              <HardDrive className="h-5 w-5 text-[var(--muted)]" />
              Artifacts ({artifacts.length})
            </h2>
          </div>
          {artifacts.length === 0 ? (
            <div className="p-8 text-center text-[var(--muted)]">
              <HardDrive className="h-10 w-10 mx-auto mb-3 opacity-50" />
              <p>No artifacts collected</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[var(--border)]">
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Name</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Type</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Path</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Size</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Hash</th>
                    <th className="text-left text-xs font-semibold text-[var(--muted)] uppercase tracking-wide px-4 py-3">Collected At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)]">
                  {artifacts.map((artifact) => (
                    <tr key={artifact.id} className="hover:bg-[var(--surface-alt)] transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <FileText className="h-4 w-4 text-[var(--muted)]" />
                          <span className="text-sm text-[var(--fg)] font-medium">{artifact.name}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-[var(--surface-alt)] text-[var(--fg)]">
                          {artifact.type}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-[var(--muted)] font-mono max-w-[250px] truncate">
                        {artifact.path}
                      </td>
                      <td className="px-4 py-3 text-sm text-[var(--muted)]">{formatFileSize(artifact.size)}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1">
                          <Hash className="h-3.5 w-3.5 text-[var(--muted)]" />
                          <span className="text-xs text-[var(--muted)] font-mono truncate max-w-[120px]">
                            {artifact.sha256 || artifact.hash || artifact.md5 || 'N/A'}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-[var(--muted)]">{formatDate(artifact.collectedAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Evidence Chain */}
        <div className="card-sentinel rounded-xl">
          <div className="p-4 border-b border-[var(--border)]">
            <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
              <Link2 className="h-5 w-5 text-[var(--muted)]" />
              Evidence Chain ({evidenceChain.length})
            </h2>
          </div>
          {evidenceChain.length === 0 ? (
            <div className="p-8 text-center text-[var(--muted)]">
              <Link2 className="h-10 w-10 mx-auto mb-3 opacity-50" />
              <p>No evidence chain entries</p>
            </div>
          ) : (
            <div className="p-4">
              <div className="relative">
                {/* Timeline line */}
                <div className="absolute left-6 top-0 bottom-0 w-px bg-[var(--border)]" />

                <div className="space-y-4">
                  {evidenceChain.map((entry, idx) => (
                    <div key={idx} className="relative flex gap-4 pl-4">
                      {/* Timeline dot */}
                      <div className="absolute left-4 w-5 h-5 rounded-full bg-primary-500 flex items-center justify-center -translate-x-1/2 z-10">
                        <Activity className="h-3 w-3 text-white" />
                      </div>

                      {/* Content */}
                      <div className="flex-1 ml-8 bg-[var(--surface-alt)] rounded-lg p-4">
                        <div className="flex items-start justify-between mb-1">
                          <div>
                            <p className="text-sm font-medium text-[var(--fg)]">{entry.action}</p>
                            <div className="flex items-center gap-3 text-xs text-[var(--muted)] mt-1">
                              <span className="flex items-center gap-1">
                                <User className="h-3 w-3" />
                                {entry.user}
                              </span>
                              <span className="flex items-center gap-1">
                                <Clock className="h-3 w-3" />
                                {formatDate(entry.timestamp)}
                              </span>
                            </div>
                          </div>
                        </div>
                        {entry.notes && (
                          <p className="text-sm text-[var(--muted)] mt-2">{entry.notes}</p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Analysis Results */}
        <div className="card-sentinel rounded-xl">
          <div className="p-4 border-b border-[var(--border)]">
            <h2 className="text-lg font-semibold text-[var(--fg)] flex items-center gap-2">
              <Microscope className="h-5 w-5 text-[var(--muted)]" />
              Analysis Results ({analysisResults.length})
            </h2>
          </div>
          {analysisResults.length === 0 ? (
            <div className="p-8 text-center text-[var(--muted)]">
              <Microscope className="h-10 w-10 mx-auto mb-3 opacity-50" />
              <p>No analysis results available</p>
            </div>
          ) : (
            <div className="divide-y divide-[var(--border)]">
              {analysisResults.map((result, idx) => (
                <div key={result.id || idx} className="p-4 hover:bg-[var(--surface-alt)] transition-colors">
                  <div className="flex items-start gap-3">
                    <div className="p-2 bg-[var(--surface-alt)] rounded">
                      <Activity className="h-4 w-4 text-[var(--muted)]" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-sm font-medium text-[var(--fg)]">
                          {result.title || result.type || `Analysis ${idx + 1}`}
                        </span>
                        {result.severity && (
                          <span className={cn(
                            'px-2 py-0.5 rounded text-xs font-medium border',
                            result.severity === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                            result.severity === 'high' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                            result.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                            'bg-blue-500/20 text-blue-400 border-blue-500/30'
                          )}>
                            {result.severity}
                          </span>
                        )}
                      </div>
                      {result.description && (
                        <p className="text-sm text-[var(--muted)]">{result.description}</p>
                      )}
                      {result.findings && Array.isArray(result.findings) && result.findings.length > 0 && (
                        <div className="mt-2 space-y-1">
                          {result.findings.map((finding, fi) => (
                            <div key={fi} className="text-xs text-[var(--fg)] bg-[var(--surface)] rounded p-2">
                              {finding}
                            </div>
                          ))}
                        </div>
                      )}
                      {!result.title && !result.description && !result.findings && (
                        <details>
                          <summary className="text-xs text-[var(--muted)] cursor-pointer hover:text-[var(--fg)]">
                            View raw data
                          </summary>
                          <pre className="mt-2 text-xs text-[var(--fg)] bg-[var(--surface)] rounded p-2 overflow-x-auto">
                            {JSON.stringify(result, null, 2)}
                          </pre>
                        </details>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </MainLayout>
  )
}
