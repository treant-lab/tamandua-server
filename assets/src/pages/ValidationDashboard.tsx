import { useState, useEffect, useCallback } from 'react';
import { PageProps } from '@/types';
import { Head, Link, router } from '@inertiajs/react';
import { logger } from '@/lib/logger';
import { cn, formatDate, safeCapitalize } from '@/lib/utils';
import { DemoFlow } from '@/components/hackathon/DemoFlow';
import {
  Monitor,
  Shield,
  AlertTriangle,
  Activity,
  ExternalLink,
  Database,
  Lock,
  RefreshCw,
  Search,
  Crosshair,
  FileSearch,
  BarChart3,
  ChevronRight,
  Loader2,
  CheckCircle2,
  WifiOff,
  Terminal,
  ShieldCheck,
} from 'lucide-react';

interface Test {
  technique_id: string;
  name: string;
  category: string;
  priority: string;
  test_count: number;
}

interface TestCategory {
  category: string;
  categoryName: string;
  tests: Test[];
  count: number;
}

interface Agent {
  id: string;
  hostname: string;
  status: string;
  os: string;
  lastSeen: string | null;
}

interface Stats {
  totalTestsRun: number;
  totalDetections: number;
  agentsTested: number;
  detectionRate: number;
  techniquesAvailable: number;
  lastTestRun: string | null;
}

interface PriorityLevel {
  id: string;
  name: string;
  color: string;
}

interface TestResult {
  technique_id: string;
  test_name: string;
  category: string;
  priority: string;
  command: string;
  executed: boolean;
  simulated: boolean;
  detected: boolean;
  detection_time_ms: number | null;
  alert_id: string | null;
  timestamp: string;
}

interface SuiteResult {
  technique_id: string;
  test_number: number;
  name: string;
  result: TestResult;
}

interface SuiteSummary {
  total_tests: number;
  detected: number;
  missed: number;
  detection_rate: number;
  by_category: Record<string, { total: number; detected: number; rate: number }>;
}

// Latest alert with attestation
interface LatestAlert {
  id: string;
  title: string;
  severity: string;
  mitreTechniques: string[];
  insertedAt: string;
  blockchainTxId: string | null;
  blockchainAttestedAt: string | null;
  manifestHash: string | null;
  iocCount: number;
}

// Solana attestation status
interface SolanaStatus {
  latestTxId: string | null;
  latestAlertId: string | null;
  manifestHash: string | null;
  iocCount: number;
  attestedAt: string | null;
  solscanUrl: string | null;
}

// MITRE coverage summary
interface MitreCoverage {
  totalTechniques: number;
  coveredCount: number;
  coveragePercent: number;
  byTactic: Array<{
    tacticId: string;
    tacticName: string;
    covered: number;
    total: number;
  }>;
}

interface Props extends PageProps {
  tests: Test[];
  testsByCategory: TestCategory[];
  agents: Agent[];
  stats: Stats;
  priorityLevels: PriorityLevel[];
}

export default function ValidationDashboard({ tests: _tests, testsByCategory: initialCategories, agents: initialAgents, stats: initialStats, priorityLevels }: Props) {
  const [selectedAgent, setSelectedAgent] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [runningTests, setRunningTests] = useState<Set<string>>(new Set());
  const [testResults, setTestResults] = useState<Record<string, TestResult>>({});
  const [stats, setStats] = useState<Stats>(initialStats);
  const [agents, setAgents] = useState<Agent[]>(initialAgents);
  const [testsByCategory, setTestsByCategory] = useState<TestCategory[]>(initialCategories);
  const [isLoading, setIsLoading] = useState(false);
  const [isRunningFullSuite, setIsRunningFullSuite] = useState(false);
  const [suiteProgress, setSuiteProgress] = useState<{ completed: number; total: number } | null>(null);
  const [suiteResults, setSuiteResults] = useState<SuiteSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  // New state for Hackathon Lab Center features
  const [latestAlerts, setLatestAlerts] = useState<LatestAlert[]>([]);
  const [solanaStatus, setSolanaStatus] = useState<SolanaStatus | null>(null);
  const [mitreCoverage, setMitreCoverage] = useState<MitreCoverage | null>(null);
  const [labLoading, setLabLoading] = useState(true);

  const getPriorityColor = (priority: string) => {
    const level = priorityLevels.find(p => p.id === priority);
    return level?.color || '#6b7280';
  };

  // Fetch agents data
  const refreshAgents = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/agents', { credentials: 'include' });
      const data = await response.json();
      const agentList = data.data || data.agents || data || [];

      if (Array.isArray(agentList)) {
        setAgents(agentList.map((a: any) => ({
          id: a.id,
          hostname: a.hostname,
          status: a.status,
          os: a.os_type || a.os || 'unknown',
          lastSeen: a.last_seen || a.lastSeen,
        })));
      }
    } catch (err) {
      logger.error('Failed to refresh agents:', err);
    }
  }, []);

  // Refresh stats from API
  const refreshStats = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/validation/stats');
      const data = await response.json();
      if (data.success && data.stats) {
        setStats({
          totalTestsRun: data.stats.total_tests_run || 0,
          totalDetections: data.stats.total_detections || 0,
          agentsTested: data.stats.agents_tested_count || 0,
          detectionRate: data.stats.detection_rate || 0,
          techniquesAvailable: data.stats.techniques_available || 0,
          lastTestRun: data.stats.last_test_run || null
        });
      }
    } catch (err) {
      logger.error('Failed to refresh stats:', err);
    }
  }, []);

  // Refresh tests list from API
  const refreshTests = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/validation/tests');
      const data = await response.json();
      if (data.success && data.tests) {
        // Group tests by category
        const grouped = data.tests.reduce((acc: Record<string, Test[]>, test: Test) => {
          if (!acc[test.category]) {
            acc[test.category] = [];
          }
          acc[test.category].push(test);
          return acc;
        }, {});

        const categories = Object.entries(grouped).map(([category, tests]) => ({
          category,
          categoryName: formatCategoryName(category),
          tests: tests as Test[],
          count: (tests as Test[]).length
        }));

        setTestsByCategory(categories);
      }
    } catch (err) {
      logger.error('Failed to refresh tests:', err);
    }
  }, []);

  // Format category name for display
  const formatCategoryName = (category: string): string => {
    return category.split('_').map((word) => safeCapitalize(word)).join(' ');
  };

  // Fetch latest alerts with attestation data
  const fetchLatestAlerts = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/alerts?limit=5&sort=inserted_at:desc', { credentials: 'include' });
      if (!response.ok) return;

      const data = await response.json();
      const alerts = data.data || data.alerts || data || [];

      if (Array.isArray(alerts)) {
        const mapped = alerts.map((a: any) => ({
          id: a.id,
          title: a.title,
          severity: a.severity,
          mitreTechniques: a.mitre_techniques || a.mitreTechniques || [],
          insertedAt: a.inserted_at || a.insertedAt || a.created_at,
          blockchainTxId: a.blockchain_tx_id || a.blockchainTxId,
          blockchainAttestedAt: a.blockchain_attested_at || a.blockchainAttestedAt,
          manifestHash: a.manifest_hash || a.manifestHash,
          iocCount: a.ioc_count || 0,
        }));
        setLatestAlerts(mapped);

        // Extract Solana status from latest attested alert
        const attestedAlert = mapped.find((a: LatestAlert) => a.blockchainTxId);
        if (attestedAlert) {
          setSolanaStatus({
            latestTxId: attestedAlert.blockchainTxId,
            latestAlertId: attestedAlert.id,
            manifestHash: attestedAlert.manifestHash,
            iocCount: attestedAlert.iocCount,
            attestedAt: attestedAlert.blockchainAttestedAt,
            solscanUrl: attestedAlert.blockchainTxId
              ? `https://solscan.io/tx/${attestedAlert.blockchainTxId}?cluster=devnet`
              : null,
          });
        }
      }
    } catch (err) {
      logger.error('Failed to fetch latest alerts:', err);
    }
  }, []);

  // Fetch MITRE coverage
  const fetchMitreCoverage = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/mitre/coverage', { credentials: 'include' });
      if (!response.ok) return;

      const data = await response.json();
      const coverage = data.data || data;

      if (coverage) {
        setMitreCoverage({
          totalTechniques: coverage.total_techniques || 0,
          coveredCount: coverage.covered_count || 0,
          coveragePercent: coverage.coverage_percent || 0,
          byTactic: (coverage.by_tactic || []).map((t: any) => ({
            tacticId: t.tactic?.id || t.id,
            tacticName: t.tactic?.name || t.name,
            covered: t.covered_count || 0,
            total: t.total_count || t.techniques?.length || 0,
          })),
        });
      }
    } catch (err) {
      logger.error('Failed to fetch MITRE coverage:', err);
    }
  }, []);

  // Refresh all lab data
  const refreshLabData = useCallback(async () => {
    setLabLoading(true);
    try {
      await Promise.all([
        refreshAgents(),
        fetchLatestAlerts(),
        fetchMitreCoverage(),
      ]);
    } catch (err) {
      logger.error('Failed to refresh lab data:', err);
    } finally {
      setLabLoading(false);
    }
  }, [refreshAgents, fetchLatestAlerts, fetchMitreCoverage]);

  // Refresh all data
  const refreshData = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      await Promise.all([refreshStats(), refreshTests(), refreshLabData()]);
      setLastRefresh(new Date());
    } catch (err) {
      setError('Failed to refresh data');
    } finally {
      setIsLoading(false);
    }
  }, [refreshStats, refreshTests, refreshLabData]);

  // Initial load of lab data
  useEffect(() => {
    refreshLabData();
  }, [refreshLabData]);

  // Get results for selected agent
  const loadAgentResults = useCallback(async (agentId: string) => {
    if (!agentId) return;
    try {
      const response = await fetch(`/api/v1/validation/results/${agentId}`);
      const data = await response.json();
      if (data.success && data.results) {
        // Convert results map to our format
        const results: Record<string, TestResult> = {};
        Object.entries(data.results).forEach(([key, value]) => {
          const result = value as TestResult;
          if (result.technique_id) {
            results[result.technique_id] = result;
          }
        });
        setTestResults(results);
      }
    } catch (err) {
      logger.error('Failed to load agent results:', err);
    }
  }, []);

  // Load agent results when agent changes
  useEffect(() => {
    if (selectedAgent) {
      loadAgentResults(selectedAgent);
    } else {
      setTestResults({});
    }
  }, [selectedAgent, loadAgentResults]);

  const handleRunTest = async (techniqueId: string) => {
    if (!selectedAgent) {
      setError('Please select an agent first');
      return;
    }

    setError(null);
    setRunningTests(prev => new Set(prev).add(techniqueId));

    try {
      const response = await fetch(`/api/v1/validation/tests/${techniqueId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent_id: selectedAgent, simulate: false })
      });

      if (!response.ok) {
        throw new Error(`HTTP error ${response.status}`);
      }

      const data = await response.json();

      if (data.success) {
        setTestResults(prev => ({ ...prev, [techniqueId]: data.result }));
        // Refresh stats after test
        await refreshStats();
      } else {
        setError(data.error || 'Test failed');
      }
    } catch (err) {
      logger.error('Test failed:', err);
      setError(err instanceof Error ? err.message : 'Test failed');
    } finally {
      setRunningTests(prev => {
        const next = new Set(prev);
        next.delete(techniqueId);
        return next;
      });
    }
  };

  const handleRunSuite = async () => {
    if (!selectedAgent) {
      setError('Please select an agent first');
      return;
    }

    setError(null);
    setIsRunningFullSuite(true);
    setSuiteResults(null);

    const categories = selectedCategory === 'all' ? undefined : selectedCategory;

    // Calculate total tests for progress
    const totalTests = filteredCategories.reduce((sum, cat) =>
      sum + cat.tests.reduce((s, t) => s + t.test_count, 0), 0
    );
    setSuiteProgress({ completed: 0, total: totalTests });

    try {
      const response = await fetch('/api/v1/validation/suite', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent_id: selectedAgent, dry_run: false, categories })
      });

      if (!response.ok) {
        throw new Error(`HTTP error ${response.status}`);
      }

      const data = await response.json();

      if (data.success) {
        setSuiteResults(data.summary);

        // Update test results from suite
        if (data.results) {
          const newResults: Record<string, TestResult> = { ...testResults };
          data.results.forEach((r: SuiteResult) => {
            if (r.result) {
              newResults[r.technique_id] = r.result;
            }
          });
          setTestResults(newResults);
        }

        // Refresh stats
        await refreshStats();
      } else {
        setError(data.error || 'Suite run failed');
      }
    } catch (err) {
      logger.error('Suite failed:', err);
      setError(err instanceof Error ? err.message : 'Suite run failed');
    } finally {
      setIsRunningFullSuite(false);
      setSuiteProgress(null);
    }
  };

  const handleRefresh = () => {
    router.reload({ only: ['tests', 'testsByCategory', 'agents', 'stats'] });
    refreshLabData();
  };

  const filteredCategories = selectedCategory === 'all'
    ? testsByCategory
    : testsByCategory.filter(c => c.category === selectedCategory);

  const onlineAgents = agents.filter(a => a.status === 'online');
  const offlineAgents = agents.filter(a => a.status === 'offline' || a.status !== 'online');

  return (
    <>
      <Head title="Hackathon Lab Center" />

      <div className="min-h-screen" style={{ background: 'var(--bg)', color: 'var(--fg)' }}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Header */}
          <div className="mb-8 flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold" style={{ color: 'var(--fg)' }}>Hackathon Lab Center</h1>
              <p className="mt-2" style={{ color: 'var(--muted)' }}>
                End-to-end EDR validation with MITRE ATT&CK coverage and Solana attestation
              </p>
            </div>
            <div className="flex items-center gap-4">
              <span className="text-sm" style={{ color: 'var(--subtle)' }}>
                Last updated: {lastRefresh.toLocaleTimeString()}
              </span>
              <button
                onClick={handleRefresh}
                disabled={isLoading}
                className="px-3 py-1.5 rounded text-sm transition-colors flex items-center gap-2"
                style={{ background: 'var(--surface-2)', color: 'var(--fg)' }}
              >
                <RefreshCw className={cn('h-4 w-4', isLoading && 'animate-spin')} />
                {isLoading ? 'Refreshing...' : 'Refresh'}
              </button>
            </div>
          </div>

          {/* Validation Flow Section */}
          <DemoFlow className="mb-8" onRefresh={refreshLabData} />

          {/* Error Banner */}
          {error && (
            <div className="mb-6 bg-red-500/10 border border-red-500/30 rounded-lg p-4 flex items-center justify-between">
              <span className="text-red-400">{error}</span>
              <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300">
                Dismiss
              </button>
            </div>
          )}

          {/* Lab Status Grid */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            {/* Agent Status */}
            <div className="card-sentinel rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3">
                <Monitor className="h-5 w-5 text-blue-400" />
                <div className="text-sm" style={{ color: 'var(--muted)' }}>Agents</div>
              </div>
              <div className="flex items-baseline gap-4">
                <div>
                  <div className="text-2xl font-bold text-green-400">{onlineAgents.length}</div>
                  <div className="text-xs" style={{ color: 'var(--subtle)' }}>online</div>
                </div>
                <div>
                  <div className="text-2xl font-bold" style={{ color: 'var(--subtle)' }}>{offlineAgents.length}</div>
                  <div className="text-xs" style={{ color: 'var(--subtle)' }}>offline</div>
                </div>
              </div>
              {onlineAgents.length === 0 && (
                <div className="mt-2 text-xs text-yellow-400 flex items-center gap-1">
                  <WifiOff className="h-3 w-3" />
                  No agents connected
                </div>
              )}
            </div>

            {/* Validation Stats */}
            <div className="card-sentinel rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3">
                <ShieldCheck className="h-5 w-5 text-green-400" />
                <div className="text-sm" style={{ color: 'var(--muted)' }}>Detection Rate</div>
              </div>
              <div className="text-2xl font-bold text-blue-400">{stats.detectionRate}%</div>
              <div className="text-xs" style={{ color: 'var(--subtle)' }}>
                {stats.totalDetections}/{stats.totalTestsRun} tests detected
              </div>
            </div>

            {/* MITRE Coverage */}
            <div className="card-sentinel rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="h-5 w-5 text-purple-400" />
                <div className="text-sm" style={{ color: 'var(--muted)' }}>MITRE Coverage</div>
              </div>
              {mitreCoverage ? (
                <>
                  <div className="text-2xl font-bold text-purple-400">
                    {mitreCoverage.coveragePercent.toFixed(1)}%
                  </div>
                  <div className="text-xs" style={{ color: 'var(--subtle)' }}>
                    {mitreCoverage.coveredCount}/{mitreCoverage.totalTechniques} techniques
                  </div>
                </>
              ) : (
                <div className="text-sm" style={{ color: 'var(--subtle)' }}>No data</div>
              )}
            </div>

            {/* Solana Status */}
            <div className="card-sentinel rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3">
                <Database className="h-5 w-5 text-orange-400" />
                <div className="text-sm" style={{ color: 'var(--muted)' }}>Solana Attestation</div>
              </div>
              {solanaStatus?.latestTxId ? (
                <>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-green-400" />
                    <span className="text-sm text-green-400">Active</span>
                  </div>
                  <div className="text-xs mt-1 truncate" style={{ color: 'var(--subtle)' }} title={solanaStatus.latestTxId}>
                    tx: {solanaStatus.latestTxId.slice(0, 12)}...
                  </div>
                </>
              ) : (
                <div className="text-sm" style={{ color: 'var(--subtle)' }}>No attestations yet</div>
              )}
            </div>
          </div>

          {/* Solana Attestation Details */}
          {solanaStatus?.latestTxId && (
            <div className="card-sentinel rounded-lg p-4 mb-8">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <Database className="h-5 w-5 text-orange-400" />
                  Latest Blockchain Attestation
                </h3>
                <a
                  href={solanaStatus.solscanUrl || '#'}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1"
                >
                  View on Solscan
                  <ExternalLink className="h-4 w-4" />
                </a>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div>
                  <div className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>Transaction ID</div>
                  <div className="text-sm font-mono break-all" style={{ color: 'var(--fg-2)' }}>{solanaStatus.latestTxId}</div>
                </div>
                <div>
                  <div className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>Manifest Hash</div>
                  <div className="text-sm font-mono break-all" style={{ color: 'var(--fg-2)' }}>
                    {solanaStatus.manifestHash || 'N/A'}
                  </div>
                </div>
                <div>
                  <div className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>IOC Count</div>
                  <div className="text-sm" style={{ color: 'var(--fg-2)' }}>{solanaStatus.iocCount}</div>
                </div>
                <div>
                  <div className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--subtle)' }}>Attested At</div>
                  <div className="text-sm" style={{ color: 'var(--fg-2)' }}>
                    {solanaStatus.attestedAt ? formatDate(solanaStatus.attestedAt) : 'N/A'}
                  </div>
                </div>
              </div>

              {/* Privacy Badge */}
              <div className="mt-4 p-3 bg-green-500/10 border border-green-500/30 rounded-lg flex items-center gap-3">
                <Lock className="h-5 w-5 text-green-400 flex-shrink-0" />
                <div className="text-sm text-green-400">
                  <strong>Privacy Guaranteed:</strong> No hostname, username, local IP, path, or customer data on-chain.
                  Only public IOCs (hashes, public domains/IPs) and pseudonymized identifiers.
                </div>
              </div>
            </div>
          )}

          {/* Latest Alerts from Validation */}
          {latestAlerts.length > 0 && (
            <div className="card-sentinel rounded-lg p-4 mb-8">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                  <AlertTriangle className="h-5 w-5 text-yellow-400" />
                  Latest Alerts
                </h3>
                <Link
                  href="/app/alerts"
                  className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1"
                >
                  View All
                  <ChevronRight className="h-4 w-4" />
                </Link>
              </div>

              <div className="space-y-2">
                {latestAlerts.slice(0, 5).map(alert => (
                  <Link
                    key={alert.id}
                    href={`/app/alerts/${alert.id}`}
                    className="block p-3 rounded-lg transition-colors hover:bg-[var(--surface-2)]"
                    style={{ background: 'var(--surface-2)' }}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className={cn(
                          'px-2 py-0.5 rounded text-xs font-medium uppercase',
                          alert.severity === 'critical' && 'bg-red-500/20 text-red-400',
                          alert.severity === 'high' && 'bg-orange-500/20 text-orange-400',
                          alert.severity === 'medium' && 'bg-yellow-500/20 text-yellow-400',
                          alert.severity === 'low' && 'bg-blue-500/20 text-blue-400'
                        )}>
                          {alert.severity}
                        </span>
                        <span className="text-sm" style={{ color: 'var(--fg-2)' }}>{alert.title}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {alert.mitreTechniques.length > 0 && (
                          <span className="text-xs text-purple-400">
                            {alert.mitreTechniques[0]}
                          </span>
                        )}
                        {alert.blockchainTxId && (
                          <CheckCircle2 className="h-4 w-4 text-green-400" title="Attested on Solana" />
                        )}
                        <span className="text-xs" style={{ color: 'var(--subtle)' }}>
                          {new Date(alert.insertedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Quick Links */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
            <Link
              href="/app/alerts"
              className="card-sentinel card-sentinel-interactive rounded-lg p-4 flex flex-col items-center gap-2"
            >
              <AlertTriangle className="h-6 w-6 text-yellow-400" />
              <span className="text-sm" style={{ color: 'var(--fg-2)' }}>Alert Detail</span>
            </Link>
            <Link
              href="/app/live-response"
              className="card-sentinel card-sentinel-interactive rounded-lg p-4 flex flex-col items-center gap-2"
            >
              <Terminal className="h-6 w-6 text-green-400" />
              <span className="text-sm" style={{ color: 'var(--fg-2)' }}>Live Response</span>
            </Link>
            <Link
              href="/app/investigation"
              className="card-sentinel card-sentinel-interactive rounded-lg p-4 flex flex-col items-center gap-2"
            >
              <FileSearch className="h-6 w-6 text-blue-400" />
              <span className="text-sm" style={{ color: 'var(--fg-2)' }}>Investigation</span>
            </Link>
            <Link
              href="/app/validation/benchmark"
              className="card-sentinel card-sentinel-interactive rounded-lg p-4 flex flex-col items-center gap-2"
            >
              <BarChart3 className="h-6 w-6 text-purple-400" />
              <span className="text-sm" style={{ color: 'var(--fg-2)' }}>Benchmark</span>
            </Link>
            <a
              href="/public/attestations"
              className="card-sentinel card-sentinel-interactive rounded-lg p-4 flex flex-col items-center gap-2"
            >
              <Database className="h-6 w-6 text-orange-400" />
              <span className="text-sm" style={{ color: 'var(--fg-2)' }}>Public Audit</span>
            </a>
          </div>

          {/* Suite Results Banner */}
          {suiteResults && (
            <div className="mb-6 bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <h3 className="font-semibold text-blue-400">Test Suite Completed</h3>
                <button onClick={() => setSuiteResults(null)} className="text-blue-400 hover:text-blue-300">
                  Dismiss
                </button>
              </div>
              <div className="grid grid-cols-4 gap-4 text-sm">
                <div>
                  <span style={{ color: 'var(--muted)' }}>Total Tests:</span>
                  <span className="ml-2" style={{ color: 'var(--fg)' }}>{suiteResults.total_tests}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--muted)' }}>Detected:</span>
                  <span className="ml-2 text-green-400">{suiteResults.detected}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--muted)' }}>Missed:</span>
                  <span className="ml-2 text-red-400">{suiteResults.missed}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--muted)' }}>Detection Rate:</span>
                  <span className="ml-2 text-blue-400">{suiteResults.detection_rate}%</span>
                </div>
              </div>
            </div>
          )}

          {/* Agent & Category Controls */}
          <div className="card-sentinel rounded-lg p-4 mb-8">
            <div className="flex flex-wrap gap-4 items-center">
              <div className="flex-1 min-w-[200px]">
                <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Target Agent</label>
                <select
                  value={selectedAgent}
                  onChange={(e) => setSelectedAgent(e.target.value)}
                  className="input-sentinel w-full rounded px-3 py-2"
                >
                  <option value="">Select an agent...</option>
                  {onlineAgents.length > 0 ? (
                    <optgroup label="Online">
                      {onlineAgents.map(agent => (
                        <option key={agent.id} value={agent.id}>
                          {agent.hostname} ({agent.os})
                        </option>
                      ))}
                    </optgroup>
                  ) : null}
                  {offlineAgents.length > 0 ? (
                    <optgroup label="Offline">
                      {offlineAgents.map(agent => (
                        <option key={agent.id} value={agent.id} disabled>
                          {agent.hostname} ({agent.os}) - {agent.status}
                        </option>
                      ))}
                    </optgroup>
                  ) : null}
                </select>
                {agents.length === 0 && (
                  <p className="text-xs text-yellow-400 mt-1">No agents connected</p>
                )}
              </div>

              <div className="flex-1 min-w-[200px]">
                <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Category Filter</label>
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="input-sentinel w-full rounded px-3 py-2"
                >
                  <option value="all">All Categories</option>
                  {testsByCategory.map(cat => (
                    <option key={cat.category} value={cat.category}>
                      {cat.categoryName} ({cat.count})
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex gap-2 items-end">
                <button
                  onClick={handleRunSuite}
                  disabled={!selectedAgent || isRunningFullSuite}
                  className="btn-sentinel-primary rounded px-4 py-2 font-medium flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isRunningFullSuite ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Running Suite...
                    </>
                  ) : (
                    'Run Test Suite'
                  )}
                </button>
                <Link
                  href="/app/validation/benchmark"
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded font-medium transition-colors"
                  style={{ color: 'white' }}
                >
                  View Benchmark
                </Link>
              </div>
            </div>

            {/* Progress bar for suite run */}
            {suiteProgress && (
              <div className="mt-4">
                <div className="flex justify-between text-sm mb-1" style={{ color: 'var(--muted)' }}>
                  <span>Running test suite...</span>
                  <span>{suiteProgress.completed}/{suiteProgress.total} tests</span>
                </div>
                <div className="h-2 rounded-full overflow-hidden" style={{ background: 'var(--surface-2)' }}>
                  <div
                    className="h-full bg-green-500 transition-all duration-300"
                    style={{ width: `${(suiteProgress.completed / suiteProgress.total) * 100}%` }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Test Categories */}
          <div className="space-y-6">
            {filteredCategories.length === 0 ? (
              <div className="card-sentinel rounded-lg p-8 text-center">
                <p style={{ color: 'var(--muted)' }}>No tests available</p>
              </div>
            ) : (
              filteredCategories.map(category => (
                <div key={category.category} className="card-sentinel rounded-lg overflow-hidden">
                  <div className="px-4 py-3 flex items-center justify-between" style={{ background: 'var(--surface-2)' }}>
                    <div>
                      <h3 className="font-semibold" style={{ color: 'var(--fg)' }}>{category.categoryName}</h3>
                      <span className="text-sm" style={{ color: 'var(--muted)' }}>{category.count} techniques</span>
                    </div>
                    <div className="text-sm" style={{ color: 'var(--muted)' }}>
                      {Object.values(testResults).filter(r => r.category === category.category && r.detected).length}/
                      {category.tests.length} detected
                    </div>
                  </div>

                  <div style={{ borderColor: 'var(--border)' }}>
                    {category.tests.map(test => {
                      const result = testResults[test.technique_id];
                      return (
                        <div key={test.technique_id} className="px-4 py-3 flex items-center justify-between hover:bg-[var(--surface-2)]" style={{ borderBottom: '1px solid var(--border)' }}>
                          <div className="flex items-center gap-4">
                            <span
                              className="px-2 py-1 rounded text-xs font-medium"
                              style={{ backgroundColor: getPriorityColor(test.priority) + '20', color: getPriorityColor(test.priority) }}
                            >
                              {test.technique_id}
                            </span>
                            <div>
                              <div className="font-medium" style={{ color: 'var(--fg)' }}>{test.name}</div>
                              <div className="text-sm" style={{ color: 'var(--muted)' }}>
                                {test.test_count} test{test.test_count > 1 ? 's' : ''} available
                                {result?.timestamp && (
                                  <span className="ml-2" style={{ color: 'var(--subtle)' }}>
                                    Last run: {new Date(result.timestamp).toLocaleString()}
                                  </span>
                                )}
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center gap-4">
                            {result && (
                              <div className="flex items-center gap-2">
                                <span className={cn(
                                  'px-2 py-1 rounded text-xs font-medium',
                                  result.detected
                                    ? 'bg-green-500/20 text-green-400'
                                    : 'bg-red-500/20 text-red-400'
                                )}>
                                  {result.detected ? 'DETECTED' : 'MISSED'}
                                </span>
                                {result.detection_time_ms && (
                                  <span className="text-xs" style={{ color: 'var(--subtle)' }}>
                                    {result.detection_time_ms}ms
                                  </span>
                                )}
                              </div>
                            )}
                            <button
                              onClick={() => handleRunTest(test.technique_id)}
                              disabled={!selectedAgent || runningTests.has(test.technique_id)}
                              className="btn-sentinel-secondary rounded px-3 py-1.5 text-sm font-medium flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                              {runningTests.has(test.technique_id) ? (
                                <>
                                  <Loader2 className="h-3 w-3 animate-spin" />
                                  Running...
                                </>
                              ) : (
                                'Run Test'
                              )}
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Priority Legend */}
          <div className="mt-8 card-sentinel rounded-lg p-4">
            <h4 className="text-sm font-medium mb-3" style={{ color: 'var(--muted)' }}>Priority Levels</h4>
            <div className="flex flex-wrap gap-4">
              {priorityLevels.map(level => (
                <div key={level.id} className="flex items-center gap-2">
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: level.color }}
                  />
                  <span className="text-sm" style={{ color: 'var(--fg-2)' }}>{level.name}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Last Test Run */}
          {stats.lastTestRun && (
            <div className="mt-4 text-sm text-right" style={{ color: 'var(--subtle)' }}>
              Last test run: {new Date(stats.lastTestRun).toLocaleString()}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
