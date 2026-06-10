import { useState, useEffect, useCallback } from 'react';
import { Link } from '@inertiajs/react';
import {
  Monitor,
  Activity,
  Bell,
  Shield,
  Crosshair,
  FileText,
  Link2,
  ExternalLink,
  CheckCircle2,
  XCircle,
  Clock,
  AlertCircle,
  Loader2,
  RefreshCw,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { logger } from '@/lib/logger';

// Flow step status
type StepStatus = 'pending' | 'success' | 'error' | 'no-data';

interface FlowStep {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  status: StepStatus;
  timestamp?: string;
  link?: string;
  linkLabel?: string;
  detail?: string;
}

interface DemoFlowData {
  agentEnrolled: {
    status: StepStatus;
    timestamp?: string;
    agentId?: string;
  };
  telemetryCollected: {
    status: StepStatus;
    timestamp?: string;
    eventCount?: number;
  };
  detectionFired: {
    status: StepStatus;
    timestamp?: string;
    ruleId?: string;
    ruleName?: string;
  };
  alertCreated: {
    status: StepStatus;
    timestamp?: string;
    alertId?: string;
    title?: string;
    severity?: string;
  };
  responseAction: {
    status: StepStatus;
    timestamp?: string;
    action?: string;
  };
  iocManifest: {
    status: StepStatus;
    timestamp?: string;
    iocCount?: number;
    manifestHash?: string;
  };
  solanaProof: {
    status: StepStatus;
    timestamp?: string;
    txId?: string;
    solscanUrl?: string;
  };
  publicAudit: {
    status: StepStatus;
    available: boolean;
  };
}

interface DemoFlowProps {
  className?: string;
  onRefresh?: () => void;
}

export function DemoFlow({ className, onRefresh }: DemoFlowProps) {
  const [flowData, setFlowData] = useState<DemoFlowData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchFlowData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      // Fetch agents status
      const agentsRes = await fetch('/api/v1/agents', { credentials: 'include' });
      let agentData: DemoFlowData['agentEnrolled'] = { status: 'no-data' };

      if (agentsRes.ok) {
        const agents = await agentsRes.json();
        const agentList = agents.data || agents.agents || agents || [];
        if (Array.isArray(agentList) && agentList.length > 0) {
          const onlineAgent = agentList.find((a: any) => a.status === 'online');
          agentData = {
            status: onlineAgent ? 'success' : 'pending',
            timestamp: onlineAgent?.last_seen || onlineAgent?.lastSeen,
            agentId: onlineAgent?.id,
          };
        }
      }

      // Fetch latest alerts with attestation
      const alertsRes = await fetch('/api/v1/alerts?limit=1&sort=inserted_at:desc', { credentials: 'include' });
      let alertData: DemoFlowData['alertCreated'] = { status: 'no-data' };
      let detectionData: DemoFlowData['detectionFired'] = { status: 'no-data' };
      let responseData: DemoFlowData['responseAction'] = { status: 'no-data' };
      let iocData: DemoFlowData['iocManifest'] = { status: 'no-data' };
      let solanaData: DemoFlowData['solanaProof'] = { status: 'no-data' };
      let publicAuditData: DemoFlowData['publicAudit'] = { status: 'no-data', available: false };

      if (alertsRes.ok) {
        const alertsResponse = await alertsRes.json();
        const alerts = alertsResponse.data || alertsResponse.alerts || alertsResponse || [];

        if (Array.isArray(alerts) && alerts.length > 0) {
          const latestAlert = alerts[0];

          // Alert created
          alertData = {
            status: 'success',
            timestamp: latestAlert.inserted_at || latestAlert.created_at || latestAlert.insertedAt,
            alertId: latestAlert.id,
            title: latestAlert.title,
            severity: latestAlert.severity,
          };

          // Detection fired (extract from alert)
          const metadata = latestAlert.detection_metadata || latestAlert.detectionMetadata || {};
          detectionData = {
            status: 'success',
            timestamp: alertData.timestamp,
            ruleId: metadata.rule_id || metadata.ruleId,
            ruleName: metadata.rule_name || metadata.ruleName || latestAlert.title,
          };

          // Response action (check if any response was taken)
          if (latestAlert.status === 'resolved' || latestAlert.workflow_state) {
            responseData = {
              status: 'success',
              timestamp: latestAlert.resolved_at || latestAlert.state_changed_at,
              action: latestAlert.workflow_state || 'resolved',
            };
          } else {
            responseData = { status: 'pending' };
          }

          // IOC Manifest (check evidence/enrichment for indicators)
          const evidence = latestAlert.evidence || {};
          const enrichment = latestAlert.enrichment || {};
          const indicators = evidence.indicators || enrichment.indicators || [];
          const indicatorCount = Array.isArray(indicators) ? indicators.length : 0;

          if (indicatorCount > 0 || latestAlert.blockchain_tx_id) {
            iocData = {
              status: 'success',
              timestamp: alertData.timestamp,
              iocCount: indicatorCount,
              manifestHash: latestAlert.manifest_hash,
            };
          }

          // Solana attestation
          if (latestAlert.blockchain_tx_id) {
            solanaData = {
              status: 'success',
              timestamp: latestAlert.blockchain_attested_at || alertData.timestamp,
              txId: latestAlert.blockchain_tx_id,
              solscanUrl: `https://solscan.io/tx/${latestAlert.blockchain_tx_id}?cluster=devnet`,
            };
            publicAuditData = { status: 'success', available: true };
          }
        }
      }

      // Telemetry (we infer from having agents and alerts)
      let telemetryData: DemoFlowData['telemetryCollected'] = { status: 'no-data' };
      if (agentData.status === 'success') {
        telemetryData = {
          status: alertData.status === 'success' ? 'success' : 'pending',
          timestamp: alertData.timestamp,
        };
      }

      setFlowData({
        agentEnrolled: agentData,
        telemetryCollected: telemetryData,
        detectionFired: detectionData,
        alertCreated: alertData,
        responseAction: responseData,
        iocManifest: iocData,
        solanaProof: solanaData,
        publicAudit: publicAuditData,
      });
    } catch (err) {
      logger.error('Failed to fetch validation flow data:', err);
      setError('Failed to load validation flow data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchFlowData();
  }, [fetchFlowData]);

  const handleRefresh = () => {
    fetchFlowData();
    onRefresh?.();
  };

  const getStatusIcon = (status: StepStatus) => {
    switch (status) {
      case 'success':
        return <CheckCircle2 className="h-5 w-5 text-green-400" />;
      case 'error':
        return <XCircle className="h-5 w-5 text-red-400" />;
      case 'pending':
        return <Clock className="h-5 w-5 text-yellow-400" />;
      case 'no-data':
      default:
        return <AlertCircle className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusText = (status: StepStatus): string => {
    switch (status) {
      case 'success':
        return 'Complete';
      case 'error':
        return 'Error';
      case 'pending':
        return 'Waiting...';
      case 'no-data':
      default:
        return 'No data yet';
    }
  };

  const getStatusBg = (status: StepStatus): string => {
    switch (status) {
      case 'success':
        return 'bg-green-500/10 border-green-500/30';
      case 'error':
        return 'bg-red-500/10 border-red-500/30';
      case 'pending':
        return 'bg-yellow-500/10 border-yellow-500/30';
      case 'no-data':
      default:
        return 'bg-gray-700/50 border-gray-600';
    }
  };

  const steps: FlowStep[] = flowData ? [
    {
      id: 'agent',
      label: 'Agent Enrolled',
      icon: Monitor,
      status: flowData.agentEnrolled.status,
      timestamp: flowData.agentEnrolled.timestamp,
      link: '/app/agents',
      linkLabel: 'View Agents',
      detail: flowData.agentEnrolled.agentId ? `ID: ${flowData.agentEnrolled.agentId.slice(0, 8)}...` : undefined,
    },
    {
      id: 'telemetry',
      label: 'Telemetry Collected',
      icon: Activity,
      status: flowData.telemetryCollected.status,
      timestamp: flowData.telemetryCollected.timestamp,
      link: '/app/events',
      linkLabel: 'View Events',
      detail: flowData.telemetryCollected.eventCount ? `${flowData.telemetryCollected.eventCount} events` : undefined,
    },
    {
      id: 'detection',
      label: 'Detection Fired',
      icon: Shield,
      status: flowData.detectionFired.status,
      timestamp: flowData.detectionFired.timestamp,
      link: '/app/detection-rules',
      linkLabel: 'View Rules',
      detail: flowData.detectionFired.ruleName,
    },
    {
      id: 'alert',
      label: 'Alert Created',
      icon: Bell,
      status: flowData.alertCreated.status,
      timestamp: flowData.alertCreated.timestamp,
      link: flowData.alertCreated.alertId ? `/app/alerts/${flowData.alertCreated.alertId}` : '/app/alerts',
      linkLabel: 'View Alert',
      detail: flowData.alertCreated.title,
    },
    {
      id: 'response',
      label: 'Response Action',
      icon: Crosshair,
      status: flowData.responseAction.status,
      timestamp: flowData.responseAction.timestamp,
      link: '/app/response',
      linkLabel: 'View Response',
      detail: flowData.responseAction.action,
    },
    {
      id: 'ioc',
      label: 'IOC Manifest',
      icon: FileText,
      status: flowData.iocManifest.status,
      timestamp: flowData.iocManifest.timestamp,
      detail: flowData.iocManifest.iocCount !== undefined ? `${flowData.iocManifest.iocCount} IOCs` : undefined,
    },
    {
      id: 'solana',
      label: 'Solana Proof',
      icon: Link2,
      status: flowData.solanaProof.status,
      timestamp: flowData.solanaProof.timestamp,
      link: flowData.solanaProof.solscanUrl,
      linkLabel: 'View on Solscan',
      detail: flowData.solanaProof.txId ? `tx: ${flowData.solanaProof.txId.slice(0, 8)}...` : undefined,
    },
    {
      id: 'audit',
      label: 'Public Audit',
      icon: ExternalLink,
      status: flowData.publicAudit.status,
      link: '/public/attestations',
      linkLabel: 'View Public Attestations',
      detail: flowData.publicAudit.available ? 'Available' : 'Waiting for attestation',
    },
  ] : [];

  if (loading) {
    return (
      <div className={cn('bg-gray-800 rounded-lg p-6', className)}>
        <div className="flex items-center justify-center gap-3 text-gray-400">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span>Loading validation flow...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={cn('bg-gray-800 rounded-lg p-6', className)}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3 text-red-400">
            <XCircle className="h-5 w-5" />
            <span>{error}</span>
          </div>
          <button
            onClick={handleRefresh}
            className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-sm transition-colors flex items-center gap-2"
          >
            <RefreshCw className="h-4 w-4" />
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={cn('bg-gray-800 rounded-lg p-6', className)}>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-lg font-semibold text-white">Validation Flow</h2>
          <p className="text-sm text-gray-400">End-to-end security proof pipeline visualization</p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={loading}
          className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 rounded text-sm transition-colors flex items-center gap-2"
        >
          <RefreshCw className={cn('h-4 w-4', loading && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {/* Flow visualization */}
      <div className="relative">
        {/* Connecting line */}
        <div className="absolute top-6 left-6 right-6 h-0.5 bg-gray-700" style={{ zIndex: 0 }} />

        {/* Steps */}
        <div className="relative grid grid-cols-8 gap-2">
          {steps.map((step, index) => {
            const Icon = step.icon;
            const isExternal = step.link?.startsWith('http');

            return (
              <div key={step.id} className="flex flex-col items-center">
                {/* Step icon */}
                <div
                  className={cn(
                    'relative z-10 w-12 h-12 rounded-full border-2 flex items-center justify-center',
                    getStatusBg(step.status)
                  )}
                >
                  <Icon className="h-5 w-5 text-gray-300" />
                </div>

                {/* Step label */}
                <div className="mt-3 text-center">
                  <div className="text-xs font-medium text-gray-300 whitespace-nowrap">
                    {step.label}
                  </div>

                  {/* Status indicator */}
                  <div className="flex items-center justify-center gap-1 mt-1">
                    {getStatusIcon(step.status)}
                    <span className="text-xs text-gray-500">{getStatusText(step.status)}</span>
                  </div>

                  {/* Detail */}
                  {step.detail && (
                    <div className="text-xs text-gray-500 mt-1 truncate max-w-[100px]" title={step.detail}>
                      {step.detail}
                    </div>
                  )}

                  {/* Timestamp */}
                  {step.timestamp && (
                    <div className="text-xs text-gray-600 mt-1">
                      {new Date(step.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </div>
                  )}

                  {/* Link */}
                  {step.link && step.status !== 'no-data' && (
                    <div className="mt-2">
                      {isExternal ? (
                        <a
                          href={step.link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-blue-400 hover:text-blue-300 flex items-center justify-center gap-1"
                        >
                          {step.linkLabel}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      ) : (
                        <Link
                          href={step.link}
                          className="text-xs text-blue-400 hover:text-blue-300"
                        >
                          {step.linkLabel}
                        </Link>
                      )}
                    </div>
                  )}
                </div>

                {/* Arrow between steps (except last) */}
                {index < steps.length - 1 && (
                  <div className="absolute top-6 h-0.5 bg-gray-600"
                    style={{
                      left: `calc(${(index + 1) * 12.5}% - 0.5rem)`,
                      width: 'calc(12.5% - 1rem)',
                      zIndex: 1
                    }}
                  />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Empty state guidance */}
      {flowData && flowData.agentEnrolled.status === 'no-data' && (
        <div className="mt-6 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
          <h3 className="text-sm font-medium text-blue-400 mb-2">Getting Started</h3>
          <ol className="text-sm text-gray-300 space-y-1 list-decimal list-inside">
            <li>Deploy an agent to start collecting telemetry</li>
            <li>Trigger a real detection and wait for the alert pipeline</li>
            <li>View the alert and take response actions</li>
            <li>Observe Solana blockchain attestation</li>
          </ol>
          <div className="mt-3">
            <Link
              href="/app/deploy-agent"
              className="text-sm text-blue-400 hover:text-blue-300"
            >
              Deploy Agent
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}

export default DemoFlow;
