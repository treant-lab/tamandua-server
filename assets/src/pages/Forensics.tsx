import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Microscope,
  HardDrive,
  Cpu,
  Database,
  Download,
  Upload,
  Clock,
  CheckCircle,
  AlertTriangle,
  Loader2,
  FileText,
  Monitor,
  User,
  Shield,
  Lock,
  ChevronRight,
  Search,
  Package,
  Hash,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { useState } from 'react'
import axios from 'axios'
import { toast } from 'sonner'

// Types
interface MemoryDump {
  id: string
  agentId: string
  hostname: string
  dumpType: 'full' | 'process' | 'kernel'
  processName?: string
  processPid?: number
  size: number
  status: 'collecting' | 'completed' | 'failed' | 'analyzing'
  createdAt: string
  completedAt?: string
  hash?: string
  analysisResults?: {
    malwareDetected: boolean
    injections: number
    suspiciousStrings: number
  }
}

interface DiskImage {
  id: string
  agentId: string
  hostname: string
  imageType: 'full' | 'partition' | 'logical'
  partitionInfo?: string
  size: number
  status: 'imaging' | 'completed' | 'failed' | 'verifying'
  progress?: number
  createdAt: string
  completedAt?: string
  hash?: string
  verified?: boolean
}

interface ChainOfCustodyEntry {
  id: string
  evidenceId: string
  evidenceType: 'memory_dump' | 'disk_image' | 'file' | 'log'
  action: 'collected' | 'transferred' | 'analyzed' | 'exported' | 'archived'
  performedBy: string
  timestamp: string
  notes?: string
  hash?: string
}

interface EvidenceStats {
  totalCollections: number
  activeCollections: number
  memoryDumps: number
  diskImages: number
  files: number
  totalSize: string
}

interface ForensicsPageProps {
  stats?: EvidenceStats
  memoryDumps?: MemoryDump[]
  diskImages?: DiskImage[]
  chainOfCustody?: ChainOfCustodyEntry[]
}

const defaultStats: EvidenceStats = {
  totalCollections: 0,
  activeCollections: 0,
  memoryDumps: 0,
  diskImages: 0,
  files: 0,
  totalSize: '0 B',
}

function formatBytes(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = bytes
  let unitIndex = 0
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024
    unitIndex++
  }
  return `${size.toFixed(1)} ${units[unitIndex]}`
}

const statusConfig: Record<string, { icon: React.ElementType; color: string; bg: string }> = {
  collecting: { icon: Loader2, color: 'text-[var(--info)]', bg: 'bg-[var(--info)]/10' },
  imaging: { icon: Loader2, color: 'text-[var(--info)]', bg: 'bg-[var(--info)]/10' },
  completed: { icon: CheckCircle, color: 'text-[var(--success)]', bg: 'bg-[var(--success)]/10' },
  analyzing: { icon: Microscope, color: 'text-purple-400', bg: 'bg-purple-400/10' },
  verifying: { icon: Shield, color: 'text-[var(--warning)]', bg: 'bg-[var(--warning)]/10' },
  failed: { icon: AlertTriangle, color: 'text-[var(--critical)]', bg: 'bg-[var(--critical)]/10' },
}

const actionConfig: Record<string, { icon: React.ElementType; color: string }> = {
  collected: { icon: Download, color: 'text-[var(--info)]' },
  transferred: { icon: Upload, color: 'text-purple-400' },
  analyzed: { icon: Microscope, color: 'text-[var(--success)]' },
  exported: { icon: Package, color: 'text-[var(--warning)]' },
  archived: { icon: Database, color: 'text-[var(--muted)]' },
}

export default function Forensics({
  stats,
  memoryDumps = [],
  diskImages = [],
  chainOfCustody = [],
}: ForensicsPageProps) {
  const [activeTab, setActiveTab] = useState<'memory' | 'disk' | 'custody'>('memory')
  const [selectedDump, setSelectedDump] = useState<MemoryDump | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [loading, setLoading] = useState<string | null>(null)

  const handleNewCollection = async () => {
    setLoading('new-collection')
    try {
      await axios.post('/api/v1/forensics', { type: 'memory', dump_type: 'full' })
      toast.success('Memory collection started')
      router.reload()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'Failed to start collection')
    } finally {
      setLoading(null)
    }
  }

  const handleNewImage = async () => {
    setLoading('new-image')
    try {
      await axios.post('/api/v1/forensics', { type: 'disk_image', image_type: 'full' })
      toast.success('Disk imaging started')
      router.reload()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'Failed to start imaging')
    } finally {
      setLoading(null)
    }
  }

  const handleAnalyze = async (id: string) => {
    setLoading(`analyze-${id}`)
    try {
      await axios.post(`/api/v1/forensics/${id}/analyze`)
      toast.success('Analysis started')
      router.reload()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } }
      toast.error(err.response?.data?.error || 'Failed to start analysis')
    } finally {
      setLoading(null)
    }
  }

  const handleDownload = (id: string) => {
    window.open(`/api/v1/forensics/${id}/download`, '_blank')
  }

  const evidenceStats = stats || defaultStats
  const memoryList = memoryDumps
  const diskList = diskImages
  const custodyLog = chainOfCustody

  return (
    <MainLayout title="Digital Forensics">
      <Head title="Forensics - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Overview */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <StatCard
            icon={Package}
            label="Total Collections"
            value={evidenceStats.totalCollections}
            color="primary"
          />
          <StatCard
            icon={Loader2}
            label="Active"
            value={evidenceStats.activeCollections}
            color="info"
            animate
          />
          <StatCard
            icon={Cpu}
            label="Memory Dumps"
            value={evidenceStats.memoryDumps}
            color="purple"
          />
          <StatCard
            icon={HardDrive}
            label="Disk Images"
            value={evidenceStats.diskImages}
            color="success"
          />
          <StatCard
            icon={FileText}
            label="Files"
            value={evidenceStats.files}
            color="warning"
          />
          <StatCard
            icon={Database}
            label="Total Size"
            value={evidenceStats.totalSize}
            color="muted"
            isText
          />
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-4 border-b border-[var(--border)]">
          <button
            onClick={() => setActiveTab('memory')}
            className={cn(
              'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'memory'
                ? 'border-[var(--accent)] text-[var(--accent)]'
                : 'border-transparent text-[var(--muted)] hover:text-[var(--fg)]'
            )}
          >
            <Cpu className="h-4 w-4" />
            Memory Dumps
            <span className="bg-[var(--surface)] text-[var(--muted)] text-xs px-2 py-0.5 rounded-full">
              {memoryList.length}
            </span>
          </button>
          <button
            onClick={() => setActiveTab('disk')}
            className={cn(
              'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'disk'
                ? 'border-[var(--accent)] text-[var(--accent)]'
                : 'border-transparent text-[var(--muted)] hover:text-[var(--fg)]'
            )}
          >
            <HardDrive className="h-4 w-4" />
            Disk Images
            <span className="bg-[var(--surface)] text-[var(--muted)] text-xs px-2 py-0.5 rounded-full">
              {diskList.length}
            </span>
          </button>
          <button
            onClick={() => setActiveTab('custody')}
            className={cn(
              'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'custody'
                ? 'border-[var(--accent)] text-[var(--accent)]'
                : 'border-transparent text-[var(--muted)] hover:text-[var(--fg)]'
            )}
          >
            <Lock className="h-4 w-4" />
            Chain of Custody
          </button>
        </div>

        {/* Memory Dumps Tab */}
        {activeTab === 'memory' && (
          <div className="flex gap-6">
            <div className="flex-1 card-sentinel">
              <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
                <h2 className="text-lg font-semibold text-[var(--fg)]">Memory Dumps</h2>
                <div className="flex items-center gap-2">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
                    <input
                      type="text"
                      placeholder="Search..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-48 bg-[var(--surface)] border border-[var(--border)] rounded-lg pl-10 pr-4 py-1.5 text-sm text-[var(--fg)] placeholder-[var(--muted)] focus:ring-2 focus:ring-[var(--accent)]"
                    />
                  </div>
                  <button
                    onClick={handleNewCollection}
                    disabled={loading === 'new-collection'}
                    className="btn-sentinel flex items-center gap-2"
                  >
                    {loading === 'new-collection' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
                    New Collection
                  </button>
                </div>
              </div>

              <div className="divide-y divide-[var(--border)]">
                {memoryList.map((dump) => {
                  const statusInfo = statusConfig[dump.status]
                  const StatusIcon = statusInfo?.icon || AlertTriangle

                  return (
                    <button
                      key={dump.id}
                      onClick={() => setSelectedDump(dump)}
                      className={cn(
                        'w-full flex items-center gap-4 p-4 hover:bg-[var(--surface)] transition-colors text-left',
                        selectedDump?.id === dump.id && 'bg-[var(--surface)]'
                      )}
                    >
                      <div className={cn('p-2 rounded-lg', statusInfo?.bg)}>
                        <StatusIcon
                          className={cn(
                            'h-5 w-5',
                            statusInfo?.color,
                            dump.status === 'collecting' && 'animate-spin'
                          )}
                        />
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-medium text-[var(--fg)]">
                            {dump.dumpType === 'process'
                              ? `${dump.processName} (PID: ${dump.processPid})`
                              : dump.dumpType === 'full'
                              ? 'Full Memory Dump'
                              : 'Kernel Dump'}
                          </span>
                          <span
                            className={cn(
                              'text-xs px-1.5 py-0.5 rounded capitalize',
                              statusInfo?.bg,
                              statusInfo?.color
                            )}
                          >
                            {dump.status}
                          </span>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-[var(--muted)]">
                          <span className="flex items-center gap-1">
                            <Monitor className="h-3 w-3" />
                            {dump.hostname}
                          </span>
                          <span className="flex items-center gap-1">
                            <Database className="h-3 w-3" />
                            {formatBytes(dump.size)}
                          </span>
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {formatDate(dump.createdAt)}
                          </span>
                        </div>
                      </div>

                      {dump.analysisResults?.malwareDetected && (
                        <span className="flex items-center gap-1 text-xs text-[var(--critical)] bg-[var(--critical)]/10 px-2 py-1 rounded">
                          <AlertTriangle className="h-3 w-3" />
                          Malware Detected
                        </span>
                      )}

                      <ChevronRight className="h-5 w-5 text-[var(--muted)]" />
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Memory Dump Details */}
            <div className="w-96 card-sentinel flex flex-col">
              <div className="p-4 border-b border-[var(--border)]">
                <h2 className="text-lg font-semibold text-[var(--fg)]">Dump Details</h2>
              </div>

              {selectedDump ? (
                <div className="flex-1 overflow-y-auto p-4 space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                        Type
                      </label>
                      <p className="text-sm text-[var(--fg)] mt-1 capitalize">{selectedDump.dumpType}</p>
                    </div>
                    <div>
                      <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                        Status
                      </label>
                      <p
                        className={cn(
                          'text-sm mt-1 capitalize',
                          statusConfig[selectedDump.status]?.color
                        )}
                      >
                        {selectedDump.status}
                      </p>
                    </div>
                  </div>

                  {selectedDump.processName && (
                    <div>
                      <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                        Process
                      </label>
                      <p className="text-sm text-[var(--fg)] mt-1">
                        {selectedDump.processName} (PID: {selectedDump.processPid})
                      </p>
                    </div>
                  )}

                  <div>
                    <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                      Host
                    </label>
                    <p className="text-sm text-[var(--fg)] mt-1">{selectedDump.hostname}</p>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                        Size
                      </label>
                      <p className="text-sm text-[var(--fg)] mt-1">{formatBytes(selectedDump.size)}</p>
                    </div>
                    <div>
                      <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                        Created
                      </label>
                      <p className="text-sm text-[var(--fg)] mt-1">{formatDate(selectedDump.createdAt)}</p>
                    </div>
                  </div>

                  {selectedDump.hash && (
                    <div>
                      <label className="text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                        Hash
                      </label>
                      <p className="text-xs text-[var(--muted)] mt-1 font-mono break-all">
                        {selectedDump.hash}
                      </p>
                    </div>
                  )}

                  {selectedDump.analysisResults && (
                    <div className="bg-[var(--bg)] rounded-lg p-4">
                      <h4 className="text-sm font-medium text-[var(--fg)] mb-3">Analysis Results</h4>
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-[var(--muted)]">Malware Detected</span>
                          <span
                            className={
                              selectedDump.analysisResults.malwareDetected
                                ? 'text-[var(--critical)]'
                                : 'text-[var(--success)]'
                            }
                          >
                            {selectedDump.analysisResults.malwareDetected ? 'Yes' : 'No'}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-[var(--muted)]">Code Injections</span>
                          <span className="text-[var(--fg)]">
                            {selectedDump.analysisResults.injections}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-[var(--muted)]">Suspicious Strings</span>
                          <span className="text-[var(--fg)]">
                            {selectedDump.analysisResults.suspiciousStrings}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}

                  <div className="pt-4 space-y-2">
                    <button
                      onClick={() => handleAnalyze(selectedDump.id)}
                      disabled={loading === `analyze-${selectedDump.id}`}
                      className="btn-sentinel w-full flex items-center justify-center gap-2"
                    >
                      {loading === `analyze-${selectedDump.id}` ? <Loader2 className="h-4 w-4 animate-spin" /> : <Microscope className="h-4 w-4" />}
                      Analyze
                    </button>
                    <button
                      onClick={() => handleDownload(selectedDump.id)}
                      className="w-full flex items-center justify-center gap-2 bg-[var(--surface)] hover:bg-[var(--border)] text-[var(--fg)] px-4 py-2 rounded-lg text-sm transition-colors"
                    >
                      <Download className="h-4 w-4" />
                      Download
                    </button>
                  </div>
                </div>
              ) : (
                <div className="flex-1 flex items-center justify-center text-[var(--muted)]">
                  <div className="text-center">
                    <Cpu className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>Select a dump to view details</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Disk Images Tab */}
        {activeTab === 'disk' && (
          <div className="card-sentinel">
            <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
              <h2 className="text-lg font-semibold text-[var(--fg)]">Disk Images</h2>
              <button
                onClick={handleNewImage}
                disabled={loading === 'new-image'}
                className="btn-sentinel flex items-center gap-2"
              >
                {loading === 'new-image' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
                New Image
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-[var(--bg)] text-[var(--muted)] text-xs uppercase tracking-wider">
                  <tr>
                    <th className="text-left px-4 py-3">Host</th>
                    <th className="text-left px-4 py-3">Type</th>
                    <th className="text-left px-4 py-3">Partition</th>
                    <th className="text-left px-4 py-3">Size</th>
                    <th className="text-left px-4 py-3">Status</th>
                    <th className="text-left px-4 py-3">Created</th>
                    <th className="text-left px-4 py-3">Verified</th>
                    <th className="text-left px-4 py-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)]">
                  {diskList.map((image) => {
                    const statusInfo = statusConfig[image.status]
                    const StatusIcon = statusInfo?.icon || AlertTriangle

                    return (
                      <tr key={image.id} className="hover:bg-[var(--surface)]">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <Monitor className="h-4 w-4 text-[var(--muted)]" />
                            <span className="text-sm text-[var(--fg)]">{image.hostname}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-sm text-[var(--muted)] capitalize">{image.imageType}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-sm text-[var(--muted)]">
                            {image.partitionInfo || '-'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-sm text-[var(--muted)]">{formatBytes(image.size)}</span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <StatusIcon
                              className={cn(
                                'h-4 w-4',
                                statusInfo?.color,
                                image.status === 'imaging' && 'animate-spin'
                              )}
                            />
                            <span className={cn('text-sm capitalize', statusInfo?.color)}>
                              {image.status}
                            </span>
                            {image.progress !== undefined && (
                              <span className="text-xs text-[var(--muted)]">({image.progress}%)</span>
                            )}
                          </div>
                          {image.progress !== undefined && (
                            <div className="mt-1 h-1 w-24 bg-[var(--border)] rounded-full overflow-hidden">
                              <div
                                className="h-full bg-[var(--info)] transition-all"
                                style={{ width: `${image.progress}%` }}
                              />
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-sm text-[var(--muted)]">{formatDate(image.createdAt)}</span>
                        </td>
                        <td className="px-4 py-3">
                          {image.verified !== undefined ? (
                            image.verified ? (
                              <span className="flex items-center gap-1 text-[var(--success)]">
                                <CheckCircle className="h-4 w-4" />
                                Yes
                              </span>
                            ) : (
                              <span className="flex items-center gap-1 text-[var(--critical)]">
                                <AlertTriangle className="h-4 w-4" />
                                Failed
                              </span>
                            )
                          ) : (
                            <span className="text-[var(--muted)]">-</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => handleAnalyze(image.id)}
                              disabled={loading === `analyze-${image.id}`}
                              className="p-1.5 text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface)] rounded disabled:opacity-50 transition-colors"
                            >
                              {loading === `analyze-${image.id}` ? <Loader2 className="h-4 w-4 animate-spin" /> : <Microscope className="h-4 w-4" />}
                            </button>
                            <button
                              onClick={() => handleDownload(image.id)}
                              className="p-1.5 text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface)] rounded transition-colors"
                            >
                              <Download className="h-4 w-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Chain of Custody Tab */}
        {activeTab === 'custody' && (
          <div className="card-sentinel">
            <div className="p-4 border-b border-[var(--border)] flex items-center justify-between">
              <h2 className="text-lg font-semibold text-[var(--fg)]">Chain of Custody Log</h2>
              <button className="flex items-center gap-2 bg-[var(--surface)] hover:bg-[var(--border)] text-[var(--fg)] px-3 py-1.5 rounded-lg text-sm transition-colors">
                <Download className="h-4 w-4" />
                Export Log
              </button>
            </div>

            <div className="p-4">
              <div className="relative pl-8">
                {/* Timeline line */}
                <div className="absolute left-3 top-0 bottom-0 w-px bg-[var(--border)]" />

                <div className="space-y-4">
                  {custodyLog.map((entry) => {
                    const actionInfo = actionConfig[entry.action]
                    const ActionIcon = actionInfo?.icon || FileText

                    return (
                      <div key={entry.id} className="relative">
                        {/* Timeline dot */}
                        <div
                          className={cn(
                            'absolute -left-5 top-3 h-3 w-3 rounded-full border-2 border-[var(--surface)]',
                            entry.action === 'collected' && 'bg-[var(--info)]',
                            entry.action === 'transferred' && 'bg-purple-500',
                            entry.action === 'analyzed' && 'bg-[var(--success)]',
                            entry.action === 'exported' && 'bg-[var(--warning)]',
                            entry.action === 'archived' && 'bg-[var(--muted)]'
                          )}
                        />

                        <div className="p-4 bg-[var(--bg)] rounded-lg">
                          <div className="flex items-start gap-3">
                            <div className={cn('p-2 rounded-lg bg-[var(--surface)]', actionInfo?.color)}>
                              <ActionIcon className="h-4 w-4" />
                            </div>

                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="text-sm font-medium text-[var(--fg)] capitalize">
                                  {entry.action}
                                </span>
                                <span className="text-xs px-1.5 py-0.5 rounded bg-[var(--surface)] text-[var(--muted)]">
                                  {entry.evidenceType.replace('_', ' ')}
                                </span>
                              </div>

                              <div className="flex items-center gap-4 text-xs text-[var(--muted)] mb-2">
                                <span className="flex items-center gap-1">
                                  <User className="h-3 w-3" />
                                  {entry.performedBy}
                                </span>
                                <span className="flex items-center gap-1">
                                  <Clock className="h-3 w-3" />
                                  {formatDate(entry.timestamp)}
                                </span>
                              </div>

                              {entry.notes && (
                                <p className="text-sm text-[var(--muted)]">{entry.notes}</p>
                              )}

                              {entry.hash && (
                                <div className="flex items-center gap-2 mt-2 text-xs text-[var(--muted)]">
                                  <Hash className="h-3 w-3" />
                                  <span className="font-mono">{entry.hash}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </MainLayout>
  )
}

interface StatCardProps {
  icon: React.ElementType
  label: string
  value: number | string
  color: 'primary' | 'info' | 'purple' | 'success' | 'warning' | 'muted'
  animate?: boolean
  isText?: boolean
}

function StatCard({ icon: Icon, label, value, color, animate, isText }: StatCardProps) {
  const colorClasses = {
    primary: 'bg-[var(--accent)]/20 text-[var(--accent)]',
    info: 'bg-[var(--info)]/20 text-[var(--info)]',
    purple: 'bg-purple-500/20 text-purple-400',
    success: 'bg-[var(--success)]/20 text-[var(--success)]',
    warning: 'bg-[var(--warning)]/20 text-[var(--warning)]',
    muted: 'bg-[var(--muted)]/20 text-[var(--muted)]',
  }

  return (
    <div className="card-sentinel p-4">
      <div className={cn('p-2 rounded-lg w-fit', colorClasses[color])}>
        <Icon className={cn('h-5 w-5', animate && 'animate-spin')} />
      </div>
      <div className="mt-3">
        <span className={cn('text-2xl font-bold text-[var(--fg)]', isText && 'text-xl')}>
          {value}
        </span>
        <p className="text-sm text-[var(--muted)] mt-1">{label}</p>
      </div>
    </div>
  )
}
