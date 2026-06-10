import React, { useState, useEffect, useMemo } from 'react';
import {
  Building2,
  Shield,
  AlertTriangle,
  Users,
  Server,
  Activity,
  Search,
  Filter,
  RefreshCw,
  MoreVertical,
  ExternalLink,
  Settings,
  Download,
  ChevronDown,
  ChevronRight,
  Globe,
  CheckCircle,
  XCircle,
  Clock,
  TrendingUp,
  TrendingDown,
  Zap,
  Bell,
  FileText,
  Play,
  Pause,
  Trash2,
  Edit,
  Eye,
  BarChart3,
  PieChart,
  LineChart,
  ArrowUpRight,
  ArrowDownRight,
  Minus,
  AlertCircle,
  ShieldAlert,
  ShieldCheck,
  Layers,
  Database,
  CreditCard
} from 'lucide-react';
import { safeCapitalize } from '@/lib/utils';

// Types
interface Tenant {
  id: string;
  name: string;
  slug: string;
  status: 'active' | 'suspended' | 'trial' | 'expired';
  licenseTier: 'trial' | 'pro' | 'enterprise';
  agentCount: number;
  maxAgents: number;
  userCount: number;
  alertsToday: number;
  criticalAlerts: number;
  healthScore: number;
  lastActivity: string;
  subscriptionExpires: string | null;
  features: {
    detection: boolean;
    hunting: boolean;
    playbooks: boolean;
    api_access: boolean;
    mssp_features: boolean;
  };
  metrics: {
    eventsPerDay: number;
    responseTime: number;
    detectionRate: number;
    mttr: number;
  };
}

interface TenantGroup {
  id: string;
  name: string;
  tenantIds: string[];
  color: string;
}

interface CrossTenantSearchResult {
  tenantId: string;
  tenantName: string;
  type: 'alert' | 'event' | 'agent' | 'user';
  id: string;
  title: string;
  severity?: string;
  timestamp: string;
}

interface BulkOperation {
  id: string;
  type: 'policy_update' | 'rule_deploy' | 'config_push' | 'license_update';
  status: 'pending' | 'running' | 'completed' | 'failed';
  targetTenants: string[];
  completedTenants: string[];
  failedTenants: string[];
  startedAt: string;
  completedAt?: string;
}

const MSSPPortal: React.FC = () => {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [selectedTenants, setSelectedTenants] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState('');
  const [crossTenantSearch, setCrossTenantSearch] = useState('');
  const [searchResults, setSearchResults] = useState<CrossTenantSearchResult[]>([]);
  const [showBulkActions, setShowBulkActions] = useState(false);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [tierFilter, setTierFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<string>('name');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  const [view, setView] = useState<'grid' | 'list'>('grid');
  const [expandedTenant, setExpandedTenant] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'health' | 'alerts' | 'licenses'>('overview');

  // Calculate summary metrics
  const summaryMetrics = useMemo(() => {
    const active = tenants.filter(t => t.status === 'active');
    return {
      totalTenants: tenants.length,
      activeTenants: active.length,
      totalAgents: tenants.reduce((sum, t) => sum + t.agentCount, 0),
      totalAlerts: tenants.reduce((sum, t) => sum + t.alertsToday, 0),
      criticalAlerts: tenants.reduce((sum, t) => sum + t.criticalAlerts, 0),
      averageHealth: Math.round(active.reduce((sum, t) => sum + t.healthScore, 0) / (active.length || 1)),
      needsAttention: tenants.filter(t => t.healthScore < 80 || t.criticalAlerts > 0 || t.status !== 'active').length,
      expiringLicenses: tenants.filter(t => {
        if (!t.subscriptionExpires) return false;
        const expires = new Date(t.subscriptionExpires);
        const thirtyDays = new Date();
        thirtyDays.setDate(thirtyDays.getDate() + 30);
        return expires <= thirtyDays;
      }).length
    };
  }, [tenants]);

  // Filter and sort tenants
  const filteredTenants = useMemo(() => {
    let result = [...tenants];

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(t =>
        t.name.toLowerCase().includes(query) ||
        t.slug.toLowerCase().includes(query)
      );
    }

    // Apply status filter
    if (statusFilter !== 'all') {
      result = result.filter(t => t.status === statusFilter);
    }

    // Apply tier filter
    if (tierFilter !== 'all') {
      result = result.filter(t => t.licenseTier === tierFilter);
    }

    // Sort
    result.sort((a, b) => {
      let comparison = 0;
      switch (sortBy) {
        case 'name':
          comparison = a.name.localeCompare(b.name);
          break;
        case 'agents':
          comparison = a.agentCount - b.agentCount;
          break;
        case 'health':
          comparison = a.healthScore - b.healthScore;
          break;
        case 'alerts':
          comparison = a.alertsToday - b.alertsToday;
          break;
        case 'critical':
          comparison = a.criticalAlerts - b.criticalAlerts;
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return result;
  }, [tenants, searchQuery, statusFilter, tierFilter, sortBy, sortOrder]);

  // Fetch tenants from API on mount
  useEffect(() => {
    const fetchTenants = async () => {
      setIsLoading(true);
      setLoadError(null);
      try {
        const response = await fetch('/api/v1/mssp/tenants');
        if (!response.ok) throw new Error('Failed to fetch tenants');
        const result = await response.json();
        setTenants(result.data || []);
      } catch (err) {
        setLoadError(err instanceof Error ? err.message : 'Failed to load tenants');
      } finally {
        setIsLoading(false);
      }
    };
    fetchTenants();
  }, []);

  // Cross-tenant search handler
  const handleCrossTenantSearch = async () => {
    if (crossTenantSearch.length < 3) return;
    try {
      const response = await fetch(`/api/v1/mssp/search?q=${encodeURIComponent(crossTenantSearch)}`);
      if (!response.ok) throw new Error('Search failed');
      const result = await response.json();
      setSearchResults(result.data || []);
    } catch {
      setSearchResults([]);
    }
  };

  // Bulk action handlers
  const handleSelectAll = () => {
    if (selectedTenants.size === filteredTenants.length) {
      setSelectedTenants(new Set());
    } else {
      setSelectedTenants(new Set(filteredTenants.map(t => t.id)));
    }
  };

  const handleSelectTenant = (id: string) => {
    const newSelected = new Set(selectedTenants);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedTenants(newSelected);
  };

  const getStatusBadge = (status: Tenant['status']) => {
    const styles = {
      active: 'bg-green-500/20 text-green-400 border-green-500/30',
      suspended: 'bg-red-500/20 text-red-400 border-red-500/30',
      trial: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      expired: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    };
    return (
      <span className={`px-2 py-0.5 text-xs font-medium rounded border ${styles[status]}`}>
        {safeCapitalize(status)}
      </span>
    );
  };

  const getTierBadge = (tier: Tenant['licenseTier']) => {
    const styles = {
      trial: 'bg-[var(--muted)]/20 text-[var(--muted)]',
      pro: 'bg-purple-500/20 text-purple-400',
      enterprise: 'bg-amber-500/20 text-amber-400'
    };
    return (
      <span className={`px-2 py-0.5 text-xs font-medium rounded ${styles[tier]}`}>
        {safeCapitalize(tier)}
      </span>
    );
  };

  const getHealthColor = (score: number) => {
    if (score >= 90) return 'text-green-400';
    if (score >= 70) return 'text-yellow-400';
    return 'text-red-400';
  };

  const getHealthBg = (score: number) => {
    if (score >= 90) return 'bg-green-500';
    if (score >= 70) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[var(--bg)] text-[var(--fg)] flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500 mx-auto mb-4" />
          <p className="text-[var(--muted)]">Loading tenants...</p>
        </div>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="min-h-screen bg-[var(--bg)] text-[var(--fg)] flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="h-12 w-12 text-red-400 mx-auto mb-4" />
          <p className="text-red-400 text-lg font-medium mb-2">Failed to load tenants</p>
          <p className="text-[var(--muted)] text-sm mb-4">{loadError}</p>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 bg-[var(--surface)] border border-[var(--surface-border)] rounded-lg text-sm text-[var(--fg-secondary)] hover:bg-[var(--surface-hover)]"
          >
            <RefreshCw className="w-4 h-4 inline mr-2" />
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[var(--bg)] text-[var(--fg)]">
      {/* Header */}
      <div className="border-b border-[var(--surface-border)] bg-[var(--bg)]/95 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-lg">
                <Building2 className="w-6 h-6" />
              </div>
              <div>
                <h1 className="text-xl font-bold">MSSP Portal</h1>
                <p className="text-sm text-[var(--muted)]">Multi-Tenant Management Dashboard</p>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              {/* Cross-tenant search */}
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-[var(--muted)]" />
                <input
                  type="text"
                  placeholder="Search across all tenants..."
                  value={crossTenantSearch}
                  onChange={(e) => setCrossTenantSearch(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleCrossTenantSearch()}
                  className="pl-10 pr-4 py-2 w-80 bg-[var(--surface)] border border-[var(--surface-border)] rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <button className="p-2 hover:bg-[var(--surface)] rounded-lg" title="Refresh">
                <RefreshCw className="w-5 h-5" />
              </button>

              <button className="p-2 hover:bg-[var(--surface)] rounded-lg relative" title="Notifications">
                <Bell className="w-5 h-5" />
                {summaryMetrics.criticalAlerts > 0 && (
                  <span className="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full" />
                )}
              </button>

              <button className="p-2 hover:bg-[var(--surface)] rounded-lg" title="Settings">
                <Settings className="w-5 h-5" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="max-w-7xl mx-auto px-4 py-6">
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4 mb-6">
          <div className="card-sentinel bg-[var(--surface)] rounded-lg p-4 border border-[var(--surface-border)]">
            <div className="flex items-center justify-between mb-2">
              <Building2 className="w-5 h-5 text-indigo-400" />
              <span className="text-xs text-[var(--muted)]">Tenants</span>
            </div>
            <p className="text-2xl font-bold">{summaryMetrics.totalTenants}</p>
            <p className="text-xs text-green-400">{summaryMetrics.activeTenants} active</p>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-lg p-4 border border-[var(--surface-border)]">
            <div className="flex items-center justify-between mb-2">
              <Server className="w-5 h-5 text-cyan-400" />
              <span className="text-xs text-[var(--muted)]">Agents</span>
            </div>
            <p className="text-2xl font-bold">{summaryMetrics.totalAgents.toLocaleString()}</p>
            <p className="text-xs text-[var(--muted)]">deployed</p>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-lg p-4 border border-[var(--surface-border)]">
            <div className="flex items-center justify-between mb-2">
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
              <span className="text-xs text-[var(--muted)]">Alerts</span>
            </div>
            <p className="text-2xl font-bold">{summaryMetrics.totalAlerts}</p>
            <p className="text-xs text-[var(--muted)]">today</p>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-lg p-4 border border-[var(--surface-border)]">
            <div className="flex items-center justify-between mb-2">
              <ShieldAlert className="w-5 h-5 text-red-400" />
              <span className="text-xs text-[var(--muted)]">Critical</span>
            </div>
            <p className="text-2xl font-bold text-red-400">{summaryMetrics.criticalAlerts}</p>
            <p className="text-xs text-[var(--muted)]">need action</p>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-lg p-4 border border-[var(--surface-border)]">
            <div className="flex items-center justify-between mb-2">
              <Activity className="w-5 h-5 text-green-400" />
              <span className="text-xs text-[var(--muted)]">Health</span>
            </div>
            <p className={`text-2xl font-bold ${getHealthColor(summaryMetrics.averageHealth)}`}>
              {summaryMetrics.averageHealth}%
            </p>
            <p className="text-xs text-[var(--muted)]">average</p>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-lg p-4 border border-[var(--surface-border)]">
            <div className="flex items-center justify-between mb-2">
              <AlertCircle className="w-5 h-5 text-orange-400" />
              <span className="text-xs text-[var(--muted)]">Attention</span>
            </div>
            <p className="text-2xl font-bold text-orange-400">{summaryMetrics.needsAttention}</p>
            <p className="text-xs text-[var(--muted)]">tenants</p>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-lg p-4 border border-[var(--surface-border)]">
            <div className="flex items-center justify-between mb-2">
              <CreditCard className="w-5 h-5 text-purple-400" />
              <span className="text-xs text-[var(--muted)]">Expiring</span>
            </div>
            <p className="text-2xl font-bold text-purple-400">{summaryMetrics.expiringLicenses}</p>
            <p className="text-xs text-[var(--muted)]">in 30 days</p>
          </div>

          <div className="card-sentinel bg-[var(--surface)] rounded-lg p-4 border border-[var(--surface-border)]">
            <div className="flex items-center justify-between mb-2">
              <Users className="w-5 h-5 text-teal-400" />
              <span className="text-xs text-[var(--muted)]">Users</span>
            </div>
            <p className="text-2xl font-bold">{tenants.reduce((s, t) => s + t.userCount, 0)}</p>
            <p className="text-xs text-[var(--muted)]">total</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex items-center space-x-1 mb-6 bg-[var(--surface)]/50 p-1 rounded-lg w-fit">
          {([
            { id: 'overview', label: 'Overview', icon: Layers },
            { id: 'health', label: 'Health', icon: Activity },
            { id: 'alerts', label: 'Alerts', icon: AlertTriangle },
            { id: 'licenses', label: 'Licenses', icon: CreditCard }
          ] as const).map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm transition-colors ${
                activeTab === tab.id
                  ? 'bg-indigo-600 text-white'
                  : 'text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--surface-hover)]'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </div>

        {/* Cross-tenant search results */}
        {searchResults.length > 0 && (
          <div className="mb-6 card-sentinel bg-[var(--surface)] rounded-lg border border-[var(--surface-border)] p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-medium">Cross-Tenant Search Results</h3>
              <button
                onClick={() => setSearchResults([])}
                className="text-[var(--muted)] hover:text-[var(--fg)] text-sm"
              >
                Clear
              </button>
            </div>
            <div className="space-y-2">
              {searchResults.map((result, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-3 bg-[var(--surface-hover)]/50 rounded-lg hover:bg-[var(--surface-hover)] cursor-pointer"
                >
                  <div className="flex items-center space-x-3">
                    {result.type === 'alert' && <AlertTriangle className={`w-4 h-4 ${result.severity === 'critical' ? 'text-red-400' : 'text-yellow-400'}`} />}
                    {result.type === 'event' && <Activity className="w-4 h-4 text-blue-400" />}
                    {result.type === 'agent' && <Server className="w-4 h-4 text-cyan-400" />}
                    {result.type === 'user' && <Users className="w-4 h-4 text-purple-400" />}
                    <div>
                      <p className="text-sm font-medium">{result.title}</p>
                      <p className="text-xs text-[var(--muted)]">{result.tenantName} - {result.timestamp}</p>
                    </div>
                  </div>
                  <ExternalLink className="w-4 h-4 text-[var(--muted)]" />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Filters and Actions */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-[var(--muted)]" />
              <input
                type="text"
                placeholder="Filter tenants..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 pr-4 py-2 w-64 bg-[var(--surface)] border border-[var(--surface-border)] rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 bg-[var(--surface)] border border-[var(--surface-border)] rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="trial">Trial</option>
              <option value="suspended">Suspended</option>
              <option value="expired">Expired</option>
            </select>

            <select
              value={tierFilter}
              onChange={(e) => setTierFilter(e.target.value)}
              className="px-3 py-2 bg-[var(--surface)] border border-[var(--surface-border)] rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="all">All Tiers</option>
              <option value="trial">Trial</option>
              <option value="pro">Pro</option>
              <option value="enterprise">Enterprise</option>
            </select>

            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="px-3 py-2 bg-[var(--surface)] border border-[var(--surface-border)] rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="name">Sort by Name</option>
              <option value="agents">Sort by Agents</option>
              <option value="health">Sort by Health</option>
              <option value="alerts">Sort by Alerts</option>
              <option value="critical">Sort by Critical</option>
            </select>
          </div>

          <div className="flex items-center space-x-2">
            {selectedTenants.size > 0 && (
              <div className="flex items-center space-x-2 mr-4">
                <span className="text-sm text-[var(--muted)]">{selectedTenants.size} selected</span>
                <button
                  onClick={() => setShowBulkActions(true)}
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 rounded-lg text-sm font-medium"
                >
                  Bulk Actions
                </button>
              </div>
            )}

            <button
              onClick={() => setView('grid')}
              className={`p-2 rounded-lg ${view === 'grid' ? 'bg-[var(--surface-hover)] text-[var(--fg)]' : 'text-[var(--muted)] hover:text-[var(--fg)]'}`}
            >
              <Layers className="w-4 h-4" />
            </button>
            <button
              onClick={() => setView('list')}
              className={`p-2 rounded-lg ${view === 'list' ? 'bg-[var(--surface-hover)] text-[var(--fg)]' : 'text-[var(--muted)] hover:text-[var(--fg)]'}`}
            >
              <BarChart3 className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tenant Grid/List */}
        {view === 'grid' ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredTenants.map(tenant => (
              <div
                key={tenant.id}
                className={`card-sentinel bg-[var(--surface)] rounded-lg border ${
                  selectedTenants.has(tenant.id) ? 'border-indigo-500' : 'border-[var(--surface-border)]'
                } hover:border-[var(--muted)] transition-colors`}
              >
                <div className="p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={selectedTenants.has(tenant.id)}
                        onChange={() => handleSelectTenant(tenant.id)}
                        className="w-4 h-4 rounded border-[var(--surface-border)] bg-[var(--surface-hover)] text-indigo-600 focus:ring-indigo-500"
                      />
                      <div>
                        <h3 className="font-medium">{tenant.name}</h3>
                        <p className="text-sm text-[var(--muted)]">{tenant.slug}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      {getStatusBadge(tenant.status)}
                      <button className="p-1 hover:bg-[var(--surface-hover)] rounded">
                        <MoreVertical className="w-4 h-4 text-[var(--muted)]" />
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3 mb-3">
                    <div className="bg-[var(--surface-hover)]/50 rounded-lg p-2">
                      <div className="flex items-center justify-between text-xs text-[var(--muted)] mb-1">
                        <span>Agents</span>
                        <Server className="w-3 h-3" />
                      </div>
                      <p className="font-medium">{tenant.agentCount} / {tenant.maxAgents}</p>
                      <div className="w-full bg-[var(--surface-active)] rounded-full h-1 mt-1">
                        <div
                          className="bg-cyan-500 h-1 rounded-full"
                          style={{ width: `${(tenant.agentCount / tenant.maxAgents) * 100}%` }}
                        />
                      </div>
                    </div>
                    <div className="bg-[var(--surface-hover)]/50 rounded-lg p-2">
                      <div className="flex items-center justify-between text-xs text-[var(--muted)] mb-1">
                        <span>Health</span>
                        <Activity className="w-3 h-3" />
                      </div>
                      <p className={`font-medium ${getHealthColor(tenant.healthScore)}`}>{tenant.healthScore}%</p>
                      <div className="w-full bg-[var(--surface-active)] rounded-full h-1 mt-1">
                        <div
                          className={`${getHealthBg(tenant.healthScore)} h-1 rounded-full`}
                          style={{ width: `${tenant.healthScore}%` }}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center space-x-4">
                      <div className="flex items-center space-x-1">
                        <AlertTriangle className="w-3.5 h-3.5 text-yellow-400" />
                        <span>{tenant.alertsToday}</span>
                      </div>
                      {tenant.criticalAlerts > 0 && (
                        <div className="flex items-center space-x-1 text-red-400">
                          <ShieldAlert className="w-3.5 h-3.5" />
                          <span>{tenant.criticalAlerts}</span>
                        </div>
                      )}
                      <div className="flex items-center space-x-1 text-[var(--muted)]">
                        <Users className="w-3.5 h-3.5" />
                        <span>{tenant.userCount}</span>
                      </div>
                    </div>
                    {getTierBadge(tenant.licenseTier)}
                  </div>
                </div>

                <div className="border-t border-[var(--surface-border)] px-4 py-2 flex items-center justify-between text-xs text-[var(--muted)]">
                  <span>Last activity: {tenant.lastActivity}</span>
                  <button className="text-indigo-400 hover:text-indigo-300 flex items-center space-x-1">
                    <span>Open</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="card-sentinel bg-[var(--surface)] rounded-lg border border-[var(--surface-border)] overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[var(--surface-border)]">
                  <th className="px-4 py-3 text-left">
                    <input
                      type="checkbox"
                      checked={selectedTenants.size === filteredTenants.length && filteredTenants.length > 0}
                      onChange={handleSelectAll}
                      className="w-4 h-4 rounded border-[var(--surface-border)] bg-[var(--surface-hover)] text-indigo-600 focus:ring-indigo-500"
                    />
                  </th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-[var(--muted)]">Tenant</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-[var(--muted)]">Status</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-[var(--muted)]">License</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-[var(--muted)]">Agents</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-[var(--muted)]">Health</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-[var(--muted)]">Alerts</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-[var(--muted)]">Critical</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-[var(--muted)]">Users</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-[var(--muted)]">Last Activity</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-[var(--muted)]">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredTenants.map(tenant => (
                  <tr key={tenant.id} className="border-b border-[var(--surface-border)]/50 hover:bg-[var(--surface-hover)]/30">
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedTenants.has(tenant.id)}
                        onChange={() => handleSelectTenant(tenant.id)}
                        className="w-4 h-4 rounded border-[var(--surface-border)] bg-[var(--surface-hover)] text-indigo-600 focus:ring-indigo-500"
                      />
                    </td>
                    <td className="px-4 py-3">
                      <div>
                        <p className="font-medium">{tenant.name}</p>
                        <p className="text-sm text-[var(--muted)]">{tenant.slug}</p>
                      </div>
                    </td>
                    <td className="px-4 py-3">{getStatusBadge(tenant.status)}</td>
                    <td className="px-4 py-3">{getTierBadge(tenant.licenseTier)}</td>
                    <td className="px-4 py-3">
                      <span className="text-sm">{tenant.agentCount} / {tenant.maxAgents}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`font-medium ${getHealthColor(tenant.healthScore)}`}>
                        {tenant.healthScore}%
                      </span>
                    </td>
                    <td className="px-4 py-3">{tenant.alertsToday}</td>
                    <td className="px-4 py-3">
                      {tenant.criticalAlerts > 0 ? (
                        <span className="text-red-400 font-medium">{tenant.criticalAlerts}</span>
                      ) : (
                        <span className="text-[var(--muted)]">0</span>
                      )}
                    </td>
                    <td className="px-4 py-3">{tenant.userCount}</td>
                    <td className="px-4 py-3 text-sm text-[var(--muted)]">{tenant.lastActivity}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center space-x-1">
                        <button className="p-1.5 hover:bg-[var(--surface-active)] rounded" title="View">
                          <Eye className="w-4 h-4" />
                        </button>
                        <button className="p-1.5 hover:bg-[var(--surface-active)] rounded" title="Edit">
                          <Edit className="w-4 h-4" />
                        </button>
                        <button className="p-1.5 hover:bg-[var(--surface-active)] rounded" title="Settings">
                          <Settings className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Bulk Actions Modal */}
        {showBulkActions && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-[var(--surface)] rounded-lg border border-[var(--surface-border)] w-full max-w-lg p-6">
              <h3 className="text-lg font-semibold mb-4">Bulk Operations</h3>
              <p className="text-sm text-[var(--muted)] mb-4">
                Apply actions to {selectedTenants.size} selected tenant(s)
              </p>

              <div className="space-y-3 mb-6">
                <button className="w-full flex items-center space-x-3 p-3 bg-[var(--surface-hover)]/50 hover:bg-[var(--surface-hover)] rounded-lg text-left">
                  <Shield className="w-5 h-5 text-indigo-400" />
                  <div>
                    <p className="font-medium">Deploy Detection Rules</p>
                    <p className="text-sm text-[var(--muted)]">Push YARA/Sigma rules to selected tenants</p>
                  </div>
                </button>

                <button className="w-full flex items-center space-x-3 p-3 bg-[var(--surface-hover)]/50 hover:bg-[var(--surface-hover)] rounded-lg text-left">
                  <Settings className="w-5 h-5 text-cyan-400" />
                  <div>
                    <p className="font-medium">Update Agent Policy</p>
                    <p className="text-sm text-[var(--muted)]">Configure collection and response settings</p>
                  </div>
                </button>

                <button className="w-full flex items-center space-x-3 p-3 bg-[var(--surface-hover)]/50 hover:bg-[var(--surface-hover)] rounded-lg text-left">
                  <FileText className="w-5 h-5 text-purple-400" />
                  <div>
                    <p className="font-medium">Deploy Playbook</p>
                    <p className="text-sm text-[var(--muted)]">Push automated response playbooks</p>
                  </div>
                </button>

                <button className="w-full flex items-center space-x-3 p-3 bg-[var(--surface-hover)]/50 hover:bg-[var(--surface-hover)] rounded-lg text-left">
                  <CreditCard className="w-5 h-5 text-amber-400" />
                  <div>
                    <p className="font-medium">Update License</p>
                    <p className="text-sm text-[var(--muted)]">Modify license tier or agent limits</p>
                  </div>
                </button>

                <button className="w-full flex items-center space-x-3 p-3 bg-[var(--surface-hover)]/50 hover:bg-[var(--surface-hover)] rounded-lg text-left">
                  <Download className="w-5 h-5 text-green-400" />
                  <div>
                    <p className="font-medium">Export Reports</p>
                    <p className="text-sm text-[var(--muted)]">Generate compliance or executive reports</p>
                  </div>
                </button>
              </div>

              <div className="flex items-center justify-end space-x-3">
                <button
                  onClick={() => setShowBulkActions(false)}
                  className="px-4 py-2 text-[var(--muted)] hover:text-[var(--fg)]"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default MSSPPortal;
