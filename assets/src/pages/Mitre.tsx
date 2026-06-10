import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Shield,
  Download,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  TrendingUp,
  Target,
  Search,
  RefreshCw,
  Loader2,
  ExternalLink,
  BarChart3,
  Grid3X3,
  List,
} from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { useState, useEffect, useCallback } from 'react'
import axios from 'axios'
import { logger } from '@/lib/logger'

interface MitrePageProps {
  coverage: {
    total_techniques: number
    covered_count: number
    coverage_percent: number
    by_tactic: TacticCoverage[]
  }
  techniques: Technique[]
}

interface TacticCoverage {
  tactic: {
    id: string
    name: string
    shortname: string
    description: string
  }
  techniques: Technique[]
  covered_count: number
  total_count: number
  coverage_percent: number
}

interface Technique {
  id: string
  name: string
  tactics: string[]
  platforms: string[]
  description: string
  detected?: boolean
  detection_count?: number
  severity?: string
  subtechniques?: Array<{ id: string; count: number }>
}

interface TechniqueDetail {
  id: string
  name: string
  tactics: string[]
  total_detections: number
  recent_detections: Array<{
    id: string
    title: string
    severity: string
    timestamp: string
    agent_id: string
  }>
  trend: Array<{ date: string; count: number }>
  severity_breakdown: Record<string, number>
}

interface Gap {
  tactic: { id: string; name: string }
  technique_id: string
  technique_name: string
  priority: 'high' | 'medium' | 'low'
}

type ViewMode = 'list' | 'heatmap'

export default function Mitre({ coverage: initialCoverage }: MitrePageProps) {
  const [expandedTactics, setExpandedTactics] = useState<Set<string>>(new Set())
  const [viewMode, setViewMode] = useState<ViewMode>('list')
  const [searchQuery, setSearchQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [coverage, setCoverage] = useState(initialCoverage)
  const [tacticData, setTacticData] = useState<TacticCoverage[]>(initialCoverage?.by_tactic || [])
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null)
  const [techniqueDetail, setTechniqueDetail] = useState<TechniqueDetail | null>(null)
  const [gaps, setGaps] = useState<Gap[]>([])
  const [showGaps, setShowGaps] = useState(false)
  const [heatmapData, setHeatmapData] = useState<any[]>([])

  // Fetch coverage data from API
  const fetchCoverage = useCallback(async () => {
    setLoading(true)
    try {
      const [coverageRes, tacticsRes] = await Promise.all([
        axios.get('/api/v1/mitre/coverage'),
        axios.get('/api/v1/mitre/tactics'),
      ])

      if (coverageRes.data?.data) {
        setCoverage(coverageRes.data.data)
      }
      if (tacticsRes.data?.data) {
        setTacticData(tacticsRes.data.data)
      }
    } catch (error) {
      logger.error('Failed to fetch MITRE coverage:', error)
    } finally {
      setLoading(false)
    }
  }, [])

  // Fetch gaps
  const fetchGaps = useCallback(async () => {
    try {
      const response = await axios.get('/api/v1/mitre/gaps')
      if (response.data?.data) {
        setGaps(response.data.data)
      }
    } catch (error) {
      logger.error('Failed to fetch gaps:', error)
    }
  }, [])

  // Fetch heatmap data
  const fetchHeatmap = useCallback(async () => {
    try {
      const response = await axios.get('/api/v1/mitre/heatmap')
      if (response.data?.data) {
        setHeatmapData(response.data.data)
      }
    } catch (error) {
      logger.error('Failed to fetch heatmap:', error)
    }
  }, [])

  // Fetch technique detail
  const fetchTechniqueDetail = useCallback(async (techniqueId: string) => {
    try {
      const response = await axios.get(`/api/v1/mitre/technique/${techniqueId}`)
      if (response.data?.data) {
        setTechniqueDetail(response.data.data)
      }
    } catch (error) {
      logger.error('Failed to fetch technique detail:', error)
    }
  }, [])

  // Download Navigator layer
  const downloadNavigatorLayer = async () => {
    try {
      const response = await axios.get('/api/v1/mitre/navigator', {
        responseType: 'blob',
      })
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', 'tamandua-mitre-layer.json')
      document.body.appendChild(link)
      link.click()
      link.remove()
    } catch (error) {
      logger.error('Failed to download Navigator layer:', error)
    }
  }

  // Initial fetch
  useEffect(() => {
    fetchCoverage()
    fetchGaps()
  }, [])

  // Fetch heatmap when switching to heatmap view
  useEffect(() => {
    if (viewMode === 'heatmap' && heatmapData.length === 0) {
      fetchHeatmap()
    }
  }, [viewMode])

  // Fetch technique detail when selected
  useEffect(() => {
    if (selectedTechnique) {
      fetchTechniqueDetail(selectedTechnique)
    } else {
      setTechniqueDetail(null)
    }
  }, [selectedTechnique])

  const toggleTactic = (tacticId: string) => {
    const newExpanded = new Set(expandedTactics)
    if (newExpanded.has(tacticId)) {
      newExpanded.delete(tacticId)
    } else {
      newExpanded.add(tacticId)
    }
    setExpandedTactics(newExpanded)
  }

  // Filter tactics by search
  const filteredTactics = tacticData.filter((tc) => {
    if (!searchQuery) return true
    const query = searchQuery.toLowerCase()
    return (
      tc.tactic.name.toLowerCase().includes(query) ||
      tc.tactic.id.toLowerCase().includes(query) ||
      tc.techniques.some(
        (t) =>
          t.name.toLowerCase().includes(query) ||
          t.id.toLowerCase().includes(query)
      )
    )
  })

  return (
    <MainLayout title="MITRE ATT&CK">
      <Head title="MITRE ATT&CK - Tamandua EDR" />

      <div className="space-y-6">
        {/* Coverage Summary */}
        <div
          className="rounded-xl p-6"
          style={{
            backgroundColor: 'var(--surface)',
            border: '1px solid var(--border)',
          }}
        >
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-xl font-semibold" style={{ color: 'var(--fg)' }}>
                Coverage Overview
              </h2>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>
                Based on detection rules and alerts
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={fetchCoverage}
                disabled={loading}
                className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors hover:opacity-80"
                style={{
                  backgroundColor: 'var(--surface-2)',
                  color: 'var(--fg)',
                }}
              >
                <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
              </button>
              <button
                onClick={downloadNavigatorLayer}
                className="flex items-center gap-2 rounded-lg px-4 py-2 text-sm transition-colors hover:opacity-90"
                style={{
                  backgroundColor: 'var(--emerald-600)',
                  color: 'var(--fg)',
                }}
              >
                <Download className="h-4 w-4" />
                Export Navigator Layer
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface-2)' }}>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Total Techniques</p>
              <p className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>
                {coverage?.total_techniques || 0}
              </p>
            </div>
            <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface-2)' }}>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Covered</p>
              <p className="text-3xl font-bold" style={{ color: 'var(--emerald-400)' }}>
                {coverage?.covered_count || 0}
              </p>
            </div>
            <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface-2)' }}>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>Coverage</p>
              <div className="flex items-end gap-2">
                <p className="text-3xl font-bold" style={{ color: 'var(--emerald-400)' }}>
                  {coverage?.coverage_percent || 0}%
                </p>
                <TrendingUp className="h-5 w-5 mb-1" style={{ color: 'var(--emerald-400)' }} />
              </div>
            </div>
            <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface-2)' }}>
              <p className="text-sm" style={{ color: 'var(--muted)' }}>High Priority Gaps</p>
              <p className="text-3xl font-bold" style={{ color: 'var(--crit)' }}>
                {gaps.filter((g) => g.priority === 'high').length}
              </p>
            </div>
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="relative">
              <Search
                className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4"
                style={{ color: 'var(--muted)' }}
              />
              <input
                type="text"
                placeholder="Search techniques..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-64 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:ring-2"
                style={{
                  backgroundColor: 'var(--surface)',
                  border: '1px solid var(--border)',
                  color: 'var(--fg)',
                  '--tw-ring-color': 'var(--emerald-500)',
                } as React.CSSProperties}
              />
            </div>

            <button
              onClick={() => setShowGaps(!showGaps)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
              style={{
                backgroundColor: showGaps ? 'var(--crit)' : 'var(--surface)',
                border: showGaps ? 'none' : '1px solid var(--border)',
                color: showGaps ? 'var(--fg)' : 'var(--fg-2)',
              }}
            >
              <Target className="h-4 w-4" />
              Coverage Gaps ({gaps.length})
            </button>
          </div>

          <div
            className="flex items-center gap-1 rounded-lg p-1"
            style={{
              backgroundColor: 'var(--surface)',
              border: '1px solid var(--border)',
            }}
          >
            <button
              onClick={() => setViewMode('list')}
              className="flex items-center gap-2 px-3 py-1.5 rounded-md text-sm transition-colors"
              style={{
                backgroundColor: viewMode === 'list' ? 'var(--emerald-600)' : 'transparent',
                color: viewMode === 'list' ? 'var(--fg)' : 'var(--muted)',
              }}
            >
              <List className="h-4 w-4" />
              List
            </button>
            <button
              onClick={() => setViewMode('heatmap')}
              className="flex items-center gap-2 px-3 py-1.5 rounded-md text-sm transition-colors"
              style={{
                backgroundColor: viewMode === 'heatmap' ? 'var(--emerald-600)' : 'transparent',
                color: viewMode === 'heatmap' ? 'var(--fg)' : 'var(--muted)',
              }}
            >
              <Grid3X3 className="h-4 w-4" />
              Heatmap
            </button>
          </div>
        </div>

        {/* Coverage Gaps Panel */}
        {showGaps && gaps.length > 0 && (
          <div
            className="rounded-xl p-4"
            style={{
              backgroundColor: 'var(--crit-bg)',
              border: '1px solid var(--crit)',
            }}
          >
            <div className="flex items-center gap-2 mb-4">
              <Target className="h-5 w-5" style={{ color: 'var(--crit)' }} />
              <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
                Priority Coverage Gaps
              </h3>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
              {gaps.slice(0, 12).map((gap) => (
                <button
                  key={gap.technique_id}
                  onClick={() => setSelectedTechnique(gap.technique_id)}
                  className="flex items-center justify-between p-3 rounded-lg transition-colors text-left hover:opacity-90"
                  style={{
                    backgroundColor: gap.priority === 'high' ? 'var(--crit-bg)' : 'var(--surface)',
                    border: `1px solid ${gap.priority === 'high' ? 'var(--crit)' : 'var(--border)'}`,
                  }}
                >
                  <div>
                    <span className="text-xs font-mono" style={{ color: 'var(--subtle)' }}>
                      {gap.technique_id}
                    </span>
                    <p className="text-sm" style={{ color: 'var(--fg)' }}>
                      {gap.technique_name}
                    </p>
                    <span className="text-xs" style={{ color: 'var(--muted)' }}>
                      {gap.tactic.name}
                    </span>
                  </div>
                  {gap.priority === 'high' && (
                    <AlertTriangle className="h-4 w-4" style={{ color: 'var(--crit)' }} />
                  )}
                </button>
              ))}
            </div>
            {gaps.length > 12 && (
              <p className="text-sm mt-3" style={{ color: 'var(--muted)' }}>
                +{gaps.length - 12} more uncovered techniques
              </p>
            )}
          </div>
        )}

        {/* Main Content */}
        <div className="flex gap-6">
          {/* Tactics/Techniques Panel */}
          <div className="flex-1">
            {viewMode === 'list' ? (
              <div className="space-y-4">
                {filteredTactics.map((tacticCoverage) => (
                  <div
                    key={tacticCoverage.tactic.id}
                    className="rounded-xl"
                    style={{
                      backgroundColor: 'var(--surface)',
                      border: '1px solid var(--border)',
                    }}
                  >
                    <button
                      onClick={() => toggleTactic(tacticCoverage.tactic.id)}
                      className="w-full flex items-center justify-between p-4 transition-colors hover:opacity-90"
                    >
                      <div className="flex items-center gap-4">
                        {expandedTactics.has(tacticCoverage.tactic.id) ? (
                          <ChevronDown className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                        ) : (
                          <ChevronRight className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                        )}
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono" style={{ color: 'var(--subtle)' }}>
                              {tacticCoverage.tactic.id}
                            </span>
                            <h3 className="text-lg font-medium" style={{ color: 'var(--fg)' }}>
                              {tacticCoverage.tactic.name}
                            </h3>
                          </div>
                          <p className="text-sm text-left" style={{ color: 'var(--muted)' }}>
                            {tacticCoverage.tactic.description}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right">
                          <p className="text-sm" style={{ color: 'var(--muted)' }}>
                            {tacticCoverage.covered_count} / {tacticCoverage.total_count}
                          </p>
                          <p
                            className="text-lg font-bold"
                            style={{
                              color:
                                tacticCoverage.coverage_percent >= 50
                                  ? 'var(--emerald-400)'
                                  : tacticCoverage.coverage_percent >= 25
                                  ? 'var(--high)'
                                  : 'var(--crit)',
                            }}
                          >
                            {tacticCoverage.coverage_percent}%
                          </p>
                        </div>
                        <div
                          className="w-24 h-2 rounded-full overflow-hidden"
                          style={{ backgroundColor: 'var(--surface-3)' }}
                        >
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${tacticCoverage.coverage_percent}%`,
                              backgroundColor:
                                tacticCoverage.coverage_percent >= 50
                                  ? 'var(--emerald-500)'
                                  : tacticCoverage.coverage_percent >= 25
                                  ? 'var(--high)'
                                  : 'var(--crit)',
                            }}
                          />
                        </div>
                      </div>
                    </button>

                    {expandedTactics.has(tacticCoverage.tactic.id) && (
                      <div
                        className="p-4"
                        style={{ borderTop: '1px solid var(--border)' }}
                      >
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                          {tacticCoverage.techniques?.map((technique) => (
                            <button
                              key={technique.id}
                              onClick={() => setSelectedTechnique(technique.id)}
                              className="p-3 rounded-lg text-left transition-colors hover:opacity-90"
                              style={{
                                backgroundColor: technique.detected
                                  ? 'var(--emerald-glow)'
                                  : 'var(--surface-2)',
                                border: `1px solid ${
                                  technique.detected ? 'var(--emerald-700)' : 'var(--border)'
                                }`,
                                outline:
                                  selectedTechnique === technique.id
                                    ? '2px solid var(--emerald-400)'
                                    : 'none',
                              }}
                            >
                              <div className="flex items-center justify-between mb-1">
                                <span
                                  className="text-xs font-mono"
                                  style={{ color: 'var(--subtle)' }}
                                >
                                  {technique.id}
                                </span>
                                {technique.detected && (
                                  <span
                                    className="text-xs px-1.5 py-0.5 rounded"
                                    style={{
                                      backgroundColor: 'var(--emerald-glow)',
                                      color: 'var(--emerald-400)',
                                    }}
                                  >
                                    {technique.detection_count} hits
                                  </span>
                                )}
                              </div>
                              <p className="text-sm" style={{ color: 'var(--fg)' }}>
                                {technique.name}
                              </p>
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              // Heatmap View
              <div
                className="rounded-xl p-4"
                style={{
                  backgroundColor: 'var(--surface)',
                  border: '1px solid var(--border)',
                }}
              >
                <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>
                  Detection Heatmap
                </h3>
                <div className="overflow-x-auto">
                  <div className="inline-flex flex-col gap-1">
                    {filteredTactics.map((tc) => (
                      <div key={tc.tactic.id} className="flex items-center gap-1">
                        <div
                          className="w-32 text-xs truncate"
                          style={{ color: 'var(--muted)' }}
                        >
                          {tc.tactic.name}
                        </div>
                        <div className="flex gap-1">
                          {tc.techniques.map((tech) => {
                            const count = tech.detection_count || 0
                            // Use severity-based gradient for heatmap
                            const getHeatmapColor = () => {
                              if (count === 0) return 'var(--surface-3)'
                              if (count < 5) return 'var(--low)'
                              if (count < 20) return 'var(--high)'
                              if (count < 50) return 'var(--emerald-600)'
                              return 'var(--emerald-400)'
                            }
                            return (
                              <button
                                key={tech.id}
                                onClick={() => setSelectedTechnique(tech.id)}
                                title={`${tech.id}: ${tech.name} (${count} detections)`}
                                className="w-8 h-8 rounded transition-all hover:scale-110"
                                style={{
                                  backgroundColor: getHeatmapColor(),
                                  outline:
                                    selectedTechnique === tech.id
                                      ? '2px solid var(--fg)'
                                      : 'none',
                                }}
                              />
                            )
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
                <div
                  className="flex items-center gap-4 mt-4 text-xs"
                  style={{ color: 'var(--muted)' }}
                >
                  <span>Detection intensity:</span>
                  <div className="flex items-center gap-1">
                    <div
                      className="w-4 h-4 rounded"
                      style={{ backgroundColor: 'var(--surface-3)' }}
                    />
                    <span>0</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <div
                      className="w-4 h-4 rounded"
                      style={{ backgroundColor: 'var(--low)' }}
                    />
                    <span>1-5</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <div
                      className="w-4 h-4 rounded"
                      style={{ backgroundColor: 'var(--high)' }}
                    />
                    <span>5-20</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <div
                      className="w-4 h-4 rounded"
                      style={{ backgroundColor: 'var(--emerald-600)' }}
                    />
                    <span>20-50</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <div
                      className="w-4 h-4 rounded"
                      style={{ backgroundColor: 'var(--emerald-400)' }}
                    />
                    <span>50+</span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Technique Detail Panel */}
          {selectedTechnique && (
            <div
              className="w-96 rounded-xl flex flex-col"
              style={{
                backgroundColor: 'var(--surface)',
                border: '1px solid var(--border)',
              }}
            >
              <div
                className="p-4 flex items-center justify-between"
                style={{ borderBottom: '1px solid var(--border)' }}
              >
                <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>
                  Technique Details
                </h2>
                <button
                  onClick={() => setSelectedTechnique(null)}
                  className="hover:opacity-70"
                  style={{ color: 'var(--muted)' }}
                >
                  x
                </button>
              </div>

              {techniqueDetail ? (
                <div className="flex-1 overflow-y-auto p-4 space-y-4">
                  <div>
                    <span
                      className="text-xs font-mono"
                      style={{ color: 'var(--subtle)' }}
                    >
                      {techniqueDetail.id}
                    </span>
                    <h3 className="font-medium" style={{ color: 'var(--fg)' }}>
                      {techniqueDetail.name}
                    </h3>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div
                      className="rounded-lg p-3"
                      style={{ backgroundColor: 'var(--surface-2)' }}
                    >
                      <p className="text-xs" style={{ color: 'var(--muted)' }}>
                        Total Detections
                      </p>
                      <p className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                        {techniqueDetail.total_detections}
                      </p>
                    </div>
                    <div
                      className="rounded-lg p-3"
                      style={{ backgroundColor: 'var(--surface-2)' }}
                    >
                      <p className="text-xs" style={{ color: 'var(--muted)' }}>
                        Tactics
                      </p>
                      <p className="text-sm" style={{ color: 'var(--emerald-400)' }}>
                        {techniqueDetail.tactics.join(', ') || 'N/A'}
                      </p>
                    </div>
                  </div>

                  {/* Severity Breakdown */}
                  <div>
                    <label
                      className="text-xs font-medium uppercase tracking-wider"
                      style={{ color: 'var(--muted)' }}
                    >
                      Severity Breakdown
                    </label>
                    <div className="flex gap-2 mt-2">
                      <div
                        className="flex-1 rounded p-2 text-center"
                        style={{ backgroundColor: 'var(--crit-bg)' }}
                      >
                        <p className="text-lg font-bold" style={{ color: 'var(--crit)' }}>
                          {techniqueDetail.severity_breakdown.critical || 0}
                        </p>
                        <p className="text-xs" style={{ color: 'var(--muted)' }}>
                          Critical
                        </p>
                      </div>
                      <div
                        className="flex-1 rounded p-2 text-center"
                        style={{ backgroundColor: 'var(--high-bg)' }}
                      >
                        <p className="text-lg font-bold" style={{ color: 'var(--high)' }}>
                          {techniqueDetail.severity_breakdown.high || 0}
                        </p>
                        <p className="text-xs" style={{ color: 'var(--muted)' }}>
                          High
                        </p>
                      </div>
                      <div
                        className="flex-1 rounded p-2 text-center"
                        style={{ backgroundColor: 'var(--med-bg)' }}
                      >
                        <p className="text-lg font-bold" style={{ color: 'var(--med)' }}>
                          {techniqueDetail.severity_breakdown.medium || 0}
                        </p>
                        <p className="text-xs" style={{ color: 'var(--muted)' }}>
                          Medium
                        </p>
                      </div>
                      <div
                        className="flex-1 rounded p-2 text-center"
                        style={{ backgroundColor: 'var(--low-bg)' }}
                      >
                        <p className="text-lg font-bold" style={{ color: 'var(--low)' }}>
                          {techniqueDetail.severity_breakdown.low || 0}
                        </p>
                        <p className="text-xs" style={{ color: 'var(--muted)' }}>
                          Low
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* 30-Day Trend Mini Chart */}
                  <div>
                    <label
                      className="text-xs font-medium uppercase tracking-wider"
                      style={{ color: 'var(--muted)' }}
                    >
                      30-Day Trend
                    </label>
                    <div className="mt-2 h-16 flex items-end gap-0.5">
                      {techniqueDetail.trend.slice(-30).map((day, idx) => {
                        const maxCount = Math.max(
                          ...techniqueDetail.trend.map((d) => d.count),
                          1
                        )
                        const height = (day.count / maxCount) * 100
                        return (
                          <div
                            key={idx}
                            className="flex-1 rounded-t"
                            style={{
                              height: `${Math.max(height, 2)}%`,
                              backgroundColor: 'var(--emerald-500)',
                            }}
                            title={`${day.date}: ${day.count}`}
                          />
                        )
                      })}
                    </div>
                  </div>

                  {/* Recent Detections */}
                  {techniqueDetail.recent_detections.length > 0 && (
                    <div>
                      <label
                        className="text-xs font-medium uppercase tracking-wider"
                        style={{ color: 'var(--muted)' }}
                      >
                        Recent Detections
                      </label>
                      <div className="mt-2 space-y-2">
                        {techniqueDetail.recent_detections.slice(0, 5).map((detection) => {
                          const getSeverityStyles = (severity: string) => {
                            switch (severity) {
                              case 'critical':
                                return { bg: 'var(--crit-bg)', color: 'var(--crit)' }
                              case 'high':
                                return { bg: 'var(--high-bg)', color: 'var(--high)' }
                              case 'medium':
                                return { bg: 'var(--med-bg)', color: 'var(--med)' }
                              default:
                                return { bg: 'var(--low-bg)', color: 'var(--low)' }
                            }
                          }
                          const severityStyles = getSeverityStyles(detection.severity)
                          return (
                            <a
                              key={detection.id}
                              href={`/app/alerts/${detection.id}`}
                              className="block p-2 rounded transition-colors hover:opacity-90"
                              style={{ backgroundColor: 'var(--surface-2)' }}
                            >
                              <div className="flex items-center gap-2">
                                <span
                                  className="text-xs px-1.5 py-0.5 rounded"
                                  style={{
                                    backgroundColor: severityStyles.bg,
                                    color: severityStyles.color,
                                  }}
                                >
                                  {detection.severity}
                                </span>
                                <span className="text-xs" style={{ color: 'var(--muted)' }}>
                                  {formatDate(detection.timestamp)}
                                </span>
                              </div>
                              <p
                                className="text-sm truncate mt-1"
                                style={{ color: 'var(--fg)' }}
                              >
                                {detection.title}
                              </p>
                            </a>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  <div className="pt-4">
                    <a
                      href={`https://attack.mitre.org/techniques/${techniqueDetail.id.replace('.', '/')}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center justify-center gap-2 px-4 py-2 rounded-lg text-sm w-full transition-colors hover:opacity-90"
                      style={{
                        backgroundColor: 'var(--surface-2)',
                        color: 'var(--fg)',
                      }}
                    >
                      <ExternalLink className="h-4 w-4" />
                      View on MITRE ATT&CK
                    </a>
                  </div>
                </div>
              ) : (
                <div className="flex-1 flex items-center justify-center">
                  <Loader2
                    className="h-8 w-8 animate-spin"
                    style={{ color: 'var(--emerald-400)' }}
                  />
                </div>
              )}
            </div>
          )}
        </div>

        {/* Empty State */}
        {(!tacticData || tacticData.length === 0) && !loading && (
          <div
            className="rounded-xl p-12 text-center"
            style={{
              backgroundColor: 'var(--surface)',
              border: '1px solid var(--border)',
            }}
          >
            <Shield
              className="h-16 w-16 mx-auto mb-4 opacity-50"
              style={{ color: 'var(--subtle)' }}
            />
            <p className="text-lg" style={{ color: 'var(--muted)' }}>
              No MITRE ATT&CK data available
            </p>
            <p className="text-sm" style={{ color: 'var(--subtle)' }}>
              Detection coverage will appear here as alerts are generated
            </p>
          </div>
        )}
      </div>
    </MainLayout>
  )
}
