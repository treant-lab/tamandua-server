import { useState, useEffect } from 'react';
import { Head, router } from '@inertiajs/react';
import {
  ArrowLeft, Clock, AlertTriangle, Activity, Cpu,
  Globe, File, Server, Settings, RefreshCw,
  ChevronRight, X, Play, List
} from 'lucide-react';
import InvestigationGraph from '@/components/InvestigationGraph';
import EntityPivot from '@/components/EntityPivot';
import { Select, SelectItem } from '@/components/ui/baseui';
import { logger } from '@/lib/logger';
import {
  InvestigationGraphPageProps,
  InvestigationGraphData,
  GraphNode,
  TimelineEntry,
  GraphNodeType,
} from '@/types';

const NODE_ICONS: Record<GraphNodeType, typeof Cpu> = {
  process: Cpu,
  network: Globe,
  file: File,
  dns: Server,
  registry: Settings,
};

export default function InvestigationGraphPage({
  investigationType,
  investigationId,
  alert,
  agent,
  processId,
  agentId,
  eventId,
  timeWindow,
  apiEndpoint,
  error: initialError,
}: InvestigationGraphPageProps) {
  const [graphData, setGraphData] = useState<InvestigationGraphData | null>(null);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(initialError || null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [showTimeline, setShowTimeline] = useState(true);
  const [timeRange, setTimeRange] = useState(String(timeWindow || 60));

  useEffect(() => {
    if (initialError) {
      setLoading(false);
      return;
    }
    fetchGraphData();
  }, [investigationType, investigationId, timeRange]);

  const fetchGraphData = async () => {
    setLoading(true);
    setError(null);

    try {
      let url: string;
      let options: RequestInit = {
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      };

      if (investigationType === 'alert') {
        url = `/api/v1/investigation/${investigationId}?time_window_minutes=${timeRange}`;
      } else if (investigationType === 'process') {
        url = `/api/v1/investigation/process`;
        options.method = 'POST';
        options.body = JSON.stringify({
          agent_id: agentId,
          pid: processId,
          time_window_minutes: parseInt(timeRange),
        });
      } else if (investigationType === 'event') {
        url = `/api/v1/investigation/event`;
        options.method = 'POST';
        options.body = JSON.stringify({
          event_id: eventId,
          time_window_minutes: parseInt(timeRange),
        });
      } else {
        throw new Error('Invalid investigation type');
      }

      const response = await fetch(url, options);
      const result = await response.json();

      if (result.data) {
        setGraphData(result.data);

        // Also fetch timeline
        const timelineUrl = `/api/v1/investigation/${result.data.agent_id}/timeline?time_window_minutes=${timeRange}`;
        const timelineResponse = await fetch(timelineUrl, { credentials: 'include' });
        const timelineResult = await timelineResponse.json();

        if (timelineResult.data?.events) {
          setTimeline(timelineResult.data.events);
        }
      } else {
        setError(result.error || 'Failed to load investigation data');
      }
    } catch (err) {
      logger.error('Failed to fetch graph data:', err);
      setError('Failed to load investigation data');
    } finally {
      setLoading(false);
    }
  };

  const handleNodeClick = (node: GraphNode) => {
    setSelectedNode(node);
  };

  const handleNodeDoubleClick = (node: GraphNode) => {
    // Navigate to related view based on node type
    if (node.type === 'process' && node.pid && graphData?.agent_id) {
      router.visit(`/app/investigation/${node.pid}?type=process&agent_id=${graphData.agent_id}`);
    }
  };

  const handlePivot = (pivotType: string, entityData: Record<string, unknown>) => {
    switch (pivotType) {
      case 'process-tree':
        router.visit(`/app/process-tree?agent_id=${graphData?.agent_id}&pid=${entityData.pid}`);
        break;
      case 'network':
        router.visit(`/app/network?agent_id=${graphData?.agent_id}&pid=${entityData.pid}`);
        break;
      case 'hunt-hash':
        router.visit(`/app/hunt?q=sha256:${entityData.sha256}`);
        break;
      case 'hunt-ip':
        router.visit(`/app/hunt?q=remote_ip:${entityData.remote_ip}`);
        break;
      case 'hunt-domain':
        router.visit(`/app/hunt?q=domain:${entityData.domain}`);
        break;
      case 'graph':
        if (entityData.pid && graphData?.agent_id) {
          router.visit(`/app/investigation/${entityData.pid}?type=process&agent_id=${graphData.agent_id}`);
        }
        break;
      default:
        break;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-green-500';
      default: return 'bg-[var(--muted)]';
    }
  };

  const getEventIcon = (eventType: string) => {
    if (eventType.includes('process')) return Cpu;
    if (eventType.includes('network')) return Globe;
    if (eventType.includes('file')) return File;
    if (eventType.includes('dns')) return Server;
    if (eventType.includes('registry')) return Settings;
    return Activity;
  };

  if (error) {
    return (
      <>
        <Head title="Investigation Error" />
        <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)' }}>
          <div className="card-sentinel rounded-lg p-8 max-w-md text-center border" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
            <AlertTriangle size={48} className="text-red-400 mx-auto mb-4" />
            <h2 className="text-xl font-semibold mb-2" style={{ color: 'var(--fg)' }}>Investigation Failed</h2>
            <p className="mb-4" style={{ color: 'var(--muted)' }}>{error}</p>
            <button
              onClick={() => router.visit('/app/investigation')}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded font-medium transition-colors text-white"
            >
              Back to Investigation Hub
            </button>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <Head title={`Investigation: ${investigationId}`} />

      <div className="min-h-screen" style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)' }}>
        {/* Header */}
        <div className="border-b" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--muted)' }}>
          <div className="max-w-full mx-auto px-4 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <button
                  onClick={() => router.visit('/app/investigation')}
                  className="p-2 rounded transition-colors hover:opacity-80"
                  style={{ backgroundColor: 'var(--surface)' }}
                >
                  <ArrowLeft size={20} style={{ color: 'var(--muted)' }} />
                </button>

                <div>
                  <h1 className="text-xl font-semibold" style={{ color: 'var(--fg)' }}>
                    {alert ? alert.title : `Investigation: ${investigationType}`}
                  </h1>
                  <div className="flex items-center gap-3 text-sm" style={{ color: 'var(--muted)' }}>
                    {alert && (
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        alert.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                        alert.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        alert.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-blue-500/20 text-blue-400'
                      }`}>
                        {alert.severity.toUpperCase()}
                      </span>
                    )}
                    {agent && <span>{agent.hostname}</span>}
                    {processId && <span>PID: {processId}</span>}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <Clock size={16} style={{ color: 'var(--muted)' }} />
                  <Select
                    value={timeRange}
                    onValueChange={setTimeRange}
                    className="rounded px-3 py-1.5 text-sm"
                  >
                    <SelectItem value="60">1 hour</SelectItem>
                    <SelectItem value="360">6 hours</SelectItem>
                    <SelectItem value="1440">24 hours</SelectItem>
                    <SelectItem value="10080">7 days</SelectItem>
                  </Select>
                </div>

                <button
                  onClick={() => setShowTimeline(!showTimeline)}
                  className={`p-2 rounded transition-colors ${
                    showTimeline ? 'bg-blue-600 text-white' : 'hover:opacity-80'
                  }`}
                  style={!showTimeline ? { backgroundColor: 'var(--surface)', color: 'var(--muted)', border: '1px solid var(--muted)' } : undefined}
                  title="Toggle Timeline"
                >
                  <List size={18} />
                </button>

                <button
                  onClick={fetchGraphData}
                  className="p-2 rounded transition-colors hover:opacity-80"
                  style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}
                  disabled={loading}
                >
                  <RefreshCw size={18} className={loading ? 'animate-spin' : ''} style={{ color: 'var(--muted)' }} />
                </button>
              </div>
            </div>
          </div>
        </div>

        <div className="flex h-[calc(100vh-73px)]">
          {/* Main Graph Area */}
          <div className="flex-1 relative">
            {loading ? (
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center">
                  <RefreshCw size={32} className="text-blue-400 animate-spin mx-auto mb-4" />
                  <p style={{ color: 'var(--muted)' }}>Loading investigation data...</p>
                </div>
              </div>
            ) : graphData ? (
              <InvestigationGraph
                nodes={graphData.nodes}
                edges={graphData.edges}
                selectedNodeId={selectedNode?.id}
                onNodeClick={handleNodeClick}
                onNodeDoubleClick={handleNodeDoubleClick}
                className="w-full h-full"
              />
            ) : (
              <div className="absolute inset-0 flex items-center justify-center">
                <p style={{ color: 'var(--muted)' }}>No data to display</p>
              </div>
            )}

            {/* Stats Overlay - Bottom Right (does not overlap with component controls) */}
            {graphData && (
              <div className="absolute bottom-4 right-4 card-sentinel rounded-lg p-3 text-xs z-10 border" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--muted)' }}>
                <div className="text-[10px] uppercase tracking-wider mb-1.5 font-semibold" style={{ color: 'var(--muted)' }}>Investigation Stats</div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                  <span style={{ color: 'var(--muted)' }}>Processes:</span>
                  <span className="text-blue-400 font-medium">{graphData.stats.process_count}</span>
                  <span style={{ color: 'var(--muted)' }}>Network:</span>
                  <span className="text-green-400 font-medium">{graphData.stats.network_count}</span>
                  <span style={{ color: 'var(--muted)' }}>Files:</span>
                  <span className="text-amber-400 font-medium">{graphData.stats.file_count}</span>
                  <span style={{ color: 'var(--muted)' }}>DNS:</span>
                  <span className="text-violet-400 font-medium">{graphData.stats.dns_count}</span>
                  {graphData.stats.registry_count > 0 && (
                    <>
                      <span style={{ color: 'var(--muted)' }}>Registry:</span>
                      <span className="text-red-400 font-medium">{graphData.stats.registry_count}</span>
                    </>
                  )}
                  <span className="border-t pt-1 mt-1" style={{ color: 'var(--muted)', borderColor: 'var(--muted)' }}>Total:</span>
                  <span className="font-medium border-t pt-1 mt-1" style={{ color: 'var(--fg)', borderColor: 'var(--muted)' }}>{graphData.stats.total_nodes} nodes</span>
                </div>
              </div>
            )}
          </div>

          {/* Timeline Sidebar */}
          {showTimeline && (
            <div className="w-96 border-l flex flex-col" style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--muted)' }}>
              {/* Selected Node Details */}
              {selectedNode && (
                <div className="p-4 border-b" style={{ borderColor: 'var(--muted)' }}>
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="font-medium" style={{ color: 'var(--fg)' }}>Selected Entity</h3>
                    <button
                      onClick={() => setSelectedNode(null)}
                      className="p-1 rounded hover:opacity-80"
                      style={{ backgroundColor: 'var(--surface)' }}
                    >
                      <X size={16} style={{ color: 'var(--muted)' }} />
                    </button>
                  </div>

                  <EntityPivot
                    entityType={selectedNode.type}
                    entityId={selectedNode.id}
                    entityLabel={selectedNode.label}
                    entityData={selectedNode.data}
                    onPivot={handlePivot}
                    position="bottom-left"
                  />

                  <div className="mt-3 space-y-2">
                    {Object.entries(selectedNode.data).slice(0, 6).map(([key, value]) => (
                      <div key={key} className="flex justify-between text-sm">
                        <span style={{ color: 'var(--muted)' }}>{key}:</span>
                        <span className="truncate max-w-[200px] font-mono text-xs" style={{ color: 'var(--fg)' }}>
                          {String(value)}
                        </span>
                      </div>
                    ))}
                  </div>

                  {selectedNode.detections && selectedNode.detections.length > 0 && (
                    <div className="mt-3 pt-3 border-t" style={{ borderColor: 'var(--muted)' }}>
                      <div className="text-sm text-red-400 font-medium mb-2">
                        {selectedNode.detections.length} Detection(s)
                      </div>
                      {selectedNode.detections.map((det, i) => (
                        <div key={i} className="text-xs bg-red-500/10 rounded p-2 mb-1" style={{ color: 'var(--muted)' }}>
                          {det.ruleName}: {det.description}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Timeline */}
              <div className="flex-1 overflow-hidden flex flex-col">
                <div className="px-4 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--muted)' }}>
                  <h3 className="font-medium" style={{ color: 'var(--fg)' }}>Event Timeline</h3>
                  <span className="text-xs" style={{ color: 'var(--muted)' }}>{timeline.length} events</span>
                </div>

                <div className="flex-1 overflow-y-auto">
                  {timeline.length === 0 ? (
                    <div className="p-4 text-center text-sm" style={{ color: 'var(--muted)' }}>
                      No events in timeline
                    </div>
                  ) : (
                    <div className="divide-y" style={{ borderColor: 'var(--muted)' }}>
                      {timeline.map((entry, idx) => {
                        const Icon = getEventIcon(entry.event_type);
                        return (
                          <div
                            key={entry.id || idx}
                            className="px-4 py-3 cursor-pointer transition-colors hover:opacity-80"
                            onClick={() => {
                              const node = graphData?.nodes.find(n =>
                                n.pid === entry.pid || n.id.includes(entry.id)
                              );
                              if (node) setSelectedNode(node);
                            }}
                          >
                            <div className="flex items-start gap-3">
                              <div className={`p-1.5 rounded ${getSeverityColor(entry.severity)}/20`}>
                                <Icon size={14} className={getSeverityColor(entry.severity).replace('bg-', 'text-')} />
                              </div>
                              <div className="flex-1 min-w-0">
                                <div className="text-sm truncate" style={{ color: 'var(--fg)' }}>
                                  {entry.summary}
                                </div>
                                <div className="flex items-center gap-2 mt-1 text-xs" style={{ color: 'var(--muted)' }}>
                                  <span>{entry.event_type}</span>
                                  {entry.pid && <span>PID: {entry.pid}</span>}
                                </div>
                                <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                                  {entry.timestamp}
                                </div>
                              </div>
                              {entry.detections && entry.detections.length > 0 && (
                                <AlertTriangle size={14} className="text-red-400" />
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
