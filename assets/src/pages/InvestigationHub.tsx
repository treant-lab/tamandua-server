import { useState, useMemo, useCallback } from 'react';
import { Head, router } from '@inertiajs/react';
import { MainLayout } from '@/layouts/MainLayout';
import {
  Search, Plus, RefreshCw, FileSearch, Clock, AlertTriangle, User, Tag,
  ChevronRight, X, Loader2, Filter, Download,
  Shield, Link2, Archive,
  PlayCircle, CheckCircle, FileJson, FileText,
  Timer, AlertCircle,
  ChevronDown, Zap, Activity
} from 'lucide-react';
import { cn, formatDate, safeCapitalize, severityColor } from '@/lib/utils';
import type { InvestigationHubProps, CaseInvestigation } from '@/types';
import { logger } from '@/lib/logger';
import { Select, SelectItem, Dialog, DialogFooter, Checkbox } from '@/components/ui/baseui';

// ============================================================================
// Constants & Types
// ============================================================================

const STATUS_WORKFLOW = [
  { value: 'open', label: 'Open', color: 'blue', icon: PlayCircle, description: 'New case awaiting investigation' },
  { value: 'in_progress', label: 'Investigating', color: 'yellow', icon: Loader2, description: 'Active investigation in progress' },
  { value: 'closed', label: 'Resolved', color: 'green', icon: CheckCircle, description: 'Investigation completed' },
  { value: 'archived', label: 'Archived', color: 'slate', icon: Archive, description: 'Case archived for records' },
];

const SEVERITY_LEVELS = [
  { value: 'critical', label: 'Critical', color: 'red', slaHours: 1 },
  { value: 'high', label: 'High', color: 'orange', slaHours: 4 },
  { value: 'medium', label: 'Medium', color: 'yellow', slaHours: 24 },
  { value: 'low', label: 'Low', color: 'blue', slaHours: 72 },
  { value: 'info', label: 'Info', color: 'slate', slaHours: 168 },
];

const MITRE_TACTICS = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact'
];

interface CreateCaseForm {
  title: string;
  description: string;
  severity: string;
  assignedTo: string;
  tags: string;
  alertIds: string[];
  mitreTactics: string[];
  mitreTechniques: string;
}

// ============================================================================
// CSRF & API Helpers
// ============================================================================

function getCsrfToken(): string {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta?.getAttribute('content') || '';
}

async function apiRequest(url: string, options: RequestInit = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': getCsrfToken(),
      ...options.headers,
    },
    credentials: 'same-origin',
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Request failed' }));
    throw new Error(error.error || error.errors?.title?.[0] || 'Request failed');
  }

  if (response.status === 204) return null;
  return response.json();
}

// ============================================================================
// Utility Functions
// ============================================================================

function formatRelativeTime(date: string | Date): string {
  const now = new Date();
  const then = new Date(date);
  const diffMs = now.getTime() - then.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return formatDate(date);
}

function calculateSLAStatus(investigation: CaseInvestigation): { status: 'ok' | 'warning' | 'breach'; timeLeft: string; percentage: number } {
  if (investigation.status === 'closed' || investigation.status === 'archived') {
    return { status: 'ok', timeLeft: 'Resolved', percentage: 100 };
  }

  const severityConfig = SEVERITY_LEVELS.find(s => s.value === investigation.severity);
  const slaHours = severityConfig?.slaHours || 24;
  const createdAt = new Date(investigation.insertedAt);
  const deadline = new Date(createdAt.getTime() + slaHours * 3600000);
  const now = new Date();
  const remaining = deadline.getTime() - now.getTime();
  const total = slaHours * 3600000;
  const percentage = Math.max(0, Math.min(100, ((total - remaining) / total) * 100));

  if (remaining < 0) {
    const overdueMins = Math.abs(Math.floor(remaining / 60000));
    const overdueHours = Math.floor(overdueMins / 60);
    return {
      status: 'breach',
      timeLeft: overdueHours > 0 ? `${overdueHours}h overdue` : `${overdueMins}m overdue`,
      percentage: 100
    };
  }

  const minsLeft = Math.floor(remaining / 60000);
  const hoursLeft = Math.floor(minsLeft / 60);
  const daysLeft = Math.floor(hoursLeft / 24);

  let timeLeft = '';
  if (daysLeft > 0) timeLeft = `${daysLeft}d ${hoursLeft % 24}h left`;
  else if (hoursLeft > 0) timeLeft = `${hoursLeft}h ${minsLeft % 60}m left`;
  else timeLeft = `${minsLeft}m left`;

  const status = percentage > 75 ? 'warning' : 'ok';
  return { status, timeLeft, percentage };
}

// ============================================================================
// Sub-Components
// ============================================================================

function StatusBadge({ status, size = 'sm' }: { status: string; size?: 'sm' | 'md' | 'lg' }) {
  const config = STATUS_WORKFLOW.find(s => s.value === status) || STATUS_WORKFLOW[0];
  const sizes = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-sm',
    lg: 'px-3 py-1.5 text-sm',
  };

  const colorClasses: Record<string, string> = {
    blue: 'bg-[var(--med-bg)] text-[var(--med)] border-[var(--med)]/30',
    yellow: 'bg-[var(--high-bg)] text-[var(--high)] border-[var(--high)]/30',
    green: 'bg-[var(--emerald-glow)] text-[var(--emerald-400)] border-[var(--emerald-400)]/30',
    slate: 'bg-[var(--surface-2)] text-[var(--muted)] border-[var(--border)]',
  };

  return (
    <span className={cn('font-medium rounded border inline-flex items-center gap-1', sizes[size], colorClasses[config.color])}>
      {status.replace('_', ' ').toUpperCase()}
    </span>
  );
}

function SeverityBadge({ severity, size = 'sm' }: { severity: string; size?: 'sm' | 'md' }) {
  const sizes = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-sm',
  };

  const getSeverityClass = (sev: string) => {
    switch (sev) {
      case 'critical': return 'badge-sentinel badge-sentinel-critical';
      case 'high': return 'badge-sentinel badge-sentinel-high';
      case 'medium': return 'badge-sentinel badge-sentinel-medium';
      case 'low': return 'badge-sentinel badge-sentinel-low';
      case 'info': return 'badge-sentinel badge-sentinel-info';
      default: return 'badge-sentinel badge-sentinel-default';
    }
  };

  return (
    <span className={cn(getSeverityClass(severity), sizes[size])}>
      {severity.toUpperCase()}
    </span>
  );
}

function SLAIndicator({ investigation }: { investigation: CaseInvestigation }) {
  const sla = calculateSLAStatus(investigation);

  const colorClasses = {
    ok: 'bg-[var(--emerald-400)]',
    warning: 'bg-[var(--high)]',
    breach: 'bg-[var(--crit)]',
  };

  const bgClasses = {
    ok: 'bg-[var(--emerald-glow)]',
    warning: 'bg-[var(--high-bg)]',
    breach: 'bg-[var(--crit-bg)]',
  };

  const textClasses = {
    ok: 'text-[var(--emerald-400)]',
    warning: 'text-[var(--high)]',
    breach: 'text-[var(--crit)]',
  };

  return (
    <div className="flex items-center gap-2">
      <div className={cn('w-20 h-1.5 rounded-full', bgClasses[sla.status])}>
        <div
          className={cn('h-full rounded-full transition-all', colorClasses[sla.status])}
          style={{ width: `${sla.percentage}%` }}
        />
      </div>
      <span className={cn('text-xs font-medium', textClasses[sla.status])}>
        {sla.timeLeft}
      </span>
    </div>
  );
}

function MitreTag({ technique }: { technique: string }) {
  return (
    <a
      href={`https://attack.mitre.org/techniques/${technique.replace('.', '/')}`}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-[var(--sol-magenta)]/20 text-[var(--sol-magenta)] hover:bg-[var(--sol-magenta)]/30 rounded text-xs transition-colors"
      onClick={(e) => e.stopPropagation()}
    >
      <Shield className="h-3 w-3" />
      {technique}
    </a>
  );
}

// ============================================================================
// Stats Cards Component
// ============================================================================

function StatsCards({ stats }: { stats: InvestigationHubProps['stats'] }) {
  const cards = [
    {
      label: 'Total Cases',
      value: stats.total,
      icon: FileSearch,
      color: 'slate',
      trend: null,
    },
    {
      label: 'Open',
      value: stats.open,
      icon: PlayCircle,
      color: 'blue',
      trend: null,
    },
    {
      label: 'In Progress',
      value: stats.in_progress,
      icon: Activity,
      color: 'yellow',
      trend: null,
    },
    {
      label: 'Resolved',
      value: stats.closed,
      icon: CheckCircle,
      color: 'green',
      trend: null,
    },
  ];

  const colorClasses: Record<string, { icon: string; bg: string; text: string }> = {
    slate: { icon: 'text-[var(--muted)]', bg: 'bg-[var(--surface-2)]', text: 'text-[var(--fg)]' },
    blue: { icon: 'text-[var(--med)]', bg: 'bg-[var(--med-bg)]', text: 'text-[var(--med)]' },
    yellow: { icon: 'text-[var(--high)]', bg: 'bg-[var(--high-bg)]', text: 'text-[var(--high)]' },
    green: { icon: 'text-[var(--emerald-400)]', bg: 'bg-[var(--emerald-glow)]', text: 'text-[var(--emerald-400)]' },
  };

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card) => {
        const colors = colorClasses[card.color];
        return (
          <div key={card.label} className="card-sentinel card-sentinel-interactive">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-[var(--muted)]">{card.label}</p>
                <p className={cn('text-2xl font-bold', colors.text)}>{card.value}</p>
              </div>
              <div className={cn('p-3 rounded-lg', colors.bg)}>
                <card.icon className={cn('h-6 w-6', colors.icon)} />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ============================================================================
// SLA Metrics Panel
// ============================================================================

function SLAMetricsPanel({ investigations }: { investigations: CaseInvestigation[] }) {
  const activeInvestigations = investigations.filter(i => i.status !== 'closed' && i.status !== 'archived');

  const metrics = useMemo(() => {
    const slaStatuses = activeInvestigations.map(i => calculateSLAStatus(i));
    const breached = slaStatuses.filter(s => s.status === 'breach').length;
    const atRisk = slaStatuses.filter(s => s.status === 'warning').length;
    const onTrack = slaStatuses.filter(s => s.status === 'ok').length;

    // Calculate average time to resolution for closed cases
    const closedCases = investigations.filter(i => i.status === 'closed');
    let avgResolutionTime = 0;
    if (closedCases.length > 0) {
      const totalTime = closedCases.reduce((sum, c) => {
        const created = new Date(c.insertedAt).getTime();
        const updated = new Date(c.updatedAt).getTime();
        return sum + (updated - created);
      }, 0);
      avgResolutionTime = Math.round(totalTime / closedCases.length / 3600000); // hours
    }

    return { breached, atRisk, onTrack, avgResolutionTime, total: activeInvestigations.length };
  }, [activeInvestigations, investigations]);

  if (metrics.total === 0) return null;

  return (
    <div className="card-sentinel">
      <div className="flex items-center gap-2 mb-4">
        <Timer className="h-5 w-5 text-[var(--muted)]" />
        <h3 className="text-sm font-semibold text-[var(--fg)]">SLA Metrics</h3>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <div className="text-center">
          <div className="text-2xl font-bold text-[var(--emerald-400)]">{metrics.onTrack}</div>
          <div className="text-xs text-[var(--muted)]">On Track</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-[var(--high)]">{metrics.atRisk}</div>
          <div className="text-xs text-[var(--muted)]">At Risk</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-[var(--crit)]">{metrics.breached}</div>
          <div className="text-xs text-[var(--muted)]">Breached</div>
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold text-[var(--fg-2)]">{metrics.avgResolutionTime}h</div>
          <div className="text-xs text-[var(--muted)]">Avg Resolution</div>
        </div>
      </div>

      {(metrics.breached > 0 || metrics.atRisk > 0) && (
        <div className="mt-3 pt-3 border-t border-[var(--hairline)]">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-[var(--high)]" />
            <span className="text-xs text-[var(--muted)]">
              {metrics.breached > 0 && <span className="text-[var(--crit)]">{metrics.breached} SLA breached</span>}
              {metrics.breached > 0 && metrics.atRisk > 0 && ' | '}
              {metrics.atRisk > 0 && <span className="text-[var(--high)]">{metrics.atRisk} at risk</span>}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Advanced Filters Panel
// ============================================================================

interface FiltersState {
  status: string;
  severity: string;
  assignee: string;
  dateRange: string;
  hasMitre: boolean;
  hasAlerts: boolean;
  slaStatus: string;
}

function AdvancedFiltersPanel({
  filters,
  onChange,
  isOpen,
  onClose,
}: {
  filters: FiltersState;
  onChange: (filters: FiltersState) => void;
  isOpen: boolean;
  onClose: () => void;
}) {
  if (!isOpen) return null;

  const dateRanges = [
    { value: 'all', label: 'All Time' },
    { value: 'today', label: 'Today' },
    { value: 'week', label: 'This Week' },
    { value: 'month', label: 'This Month' },
    { value: 'quarter', label: 'This Quarter' },
  ];

  const slaOptions = [
    { value: 'all', label: 'All' },
    { value: 'ok', label: 'On Track' },
    { value: 'warning', label: 'At Risk' },
    { value: 'breach', label: 'Breached' },
  ];

  return (
    <div className="card-sentinel mb-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-[var(--fg)] flex items-center gap-2">
          <Filter className="h-4 w-4" />
          Advanced Filters
        </h3>
        <button onClick={onClose} className="p-1 hover:bg-[var(--surface-2)] rounded">
          <X className="h-4 w-4 text-[var(--muted)]" />
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div>
          <label className="block text-xs font-medium text-[var(--muted)] mb-1">Date Range</label>
          <Select value={filters.dateRange} onValueChange={(v) => onChange({ ...filters, dateRange: v })} placeholder="Date range" fullWidth>
            {dateRanges.map((r) => (
              <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>
            ))}
          </Select>
        </div>

        <div>
          <label className="block text-xs font-medium text-[var(--muted)] mb-1">SLA Status</label>
          <Select value={filters.slaStatus} onValueChange={(v) => onChange({ ...filters, slaStatus: v })} placeholder="SLA status" fullWidth>
            {slaOptions.map((o) => (
              <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
            ))}
          </Select>
        </div>

        <div className="flex items-end gap-4">
          <Checkbox
            checked={filters.hasMitre}
            onCheckedChange={(checked) => onChange({ ...filters, hasMitre: checked })}
            label="Has MITRE Tags"
          />
        </div>

        <div className="flex items-end gap-4">
          <Checkbox
            checked={filters.hasAlerts}
            onCheckedChange={(checked) => onChange({ ...filters, hasAlerts: checked })}
            label="Has Linked Alerts"
          />
        </div>
      </div>

      <div className="flex justify-end mt-4 pt-4 border-t border-[var(--hairline)]">
        <button
          onClick={() => onChange({
            status: 'all',
            severity: 'all',
            assignee: 'all',
            dateRange: 'all',
            hasMitre: false,
            hasAlerts: false,
            slaStatus: 'all',
          })}
          className="px-3 py-1.5 text-sm text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
        >
          Clear Filters
        </button>
      </div>
    </div>
  );
}

// ============================================================================
// Create Investigation Modal
// ============================================================================

function CreateInvestigationModal({
  isOpen,
  onClose,
  users,
  severities,
}: {
  isOpen: boolean;
  onClose: () => void;
  users: InvestigationHubProps['users'];
  severities: string[];
}) {
  const [form, setForm] = useState<CreateCaseForm>({
    title: '',
    description: '',
    severity: 'medium',
    assignedTo: '',
    tags: '',
    alertIds: [],
    mitreTactics: [],
    mitreTechniques: '',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState<'basic' | 'mitre' | 'links'>('basic');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsSubmitting(true);

    try {
      await apiRequest('/api/v1/case-investigations', {
        method: 'POST',
        body: JSON.stringify({
          title: form.title,
          description: form.description || null,
          severity: form.severity,
          assigned_to: form.assignedTo || null,
          tags: form.tags ? form.tags.split(',').map(t => t.trim()).filter(Boolean) : [],
          alert_ids: form.alertIds,
          mitre_tactics: form.mitreTactics,
          mitre_techniques: form.mitreTechniques ? form.mitreTechniques.split(',').map(t => t.trim()).filter(Boolean) : [],
        }),
      });

      setForm({
        title: '',
        description: '',
        severity: 'medium',
        assignedTo: '',
        tags: '',
        alertIds: [],
        mitreTactics: [],
        mitreTechniques: '',
      });
      onClose();
      router.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create investigation');
    } finally {
      setIsSubmitting(false);
    }
  };

  const toggleTactic = (tactic: string) => {
    setForm(prev => ({
      ...prev,
      mitreTactics: prev.mitreTactics.includes(tactic)
        ? prev.mitreTactics.filter(t => t !== tactic)
        : [...prev.mitreTactics, tactic]
    }));
  };

  return (
    <Dialog
      open={isOpen}
      onOpenChange={(open) => { if (!open) onClose(); }}
      title="Create Investigation Case"
      maxWidth="42rem"
    >
      <div>
        {/* Tabs */}
        <div className="flex border-b border-[var(--border)] -mx-6 -mt-5 mb-4 px-6">
          {[
            { id: 'basic', label: 'Basic Info', icon: FileSearch },
            { id: 'mitre', label: 'MITRE ATT&CK', icon: Shield },
            { id: 'links', label: 'Link Alerts', icon: Link2 },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as 'basic' | 'mitre' | 'links')}
              className={cn(
                'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
                activeTab === tab.id
                  ? 'border-[var(--emerald-500)] text-[var(--emerald-400)]'
                  : 'border-transparent text-[var(--muted)] hover:text-[var(--fg)]'
              )}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        <form onSubmit={handleSubmit} className="p-4 space-y-4 max-h-[60vh] overflow-y-auto">
          {error && (
            <div className="p-3 bg-[var(--crit-bg)] border border-[var(--crit)]/30 rounded-lg text-[var(--crit)] text-sm">
              {error}
            </div>
          )}

          {activeTab === 'basic' && (
            <>
              <div>
                <label className="block text-sm font-medium text-[var(--fg-2)] mb-1">
                  Title <span className="text-[var(--crit)]">*</span>
                </label>
                <input
                  type="text"
                  value={form.title}
                  onChange={(e) => setForm({ ...form, title: e.target.value })}
                  placeholder="e.g., Suspicious PowerShell Activity on WORKSTATION-01"
                  required
                  minLength={3}
                  className="input-sentinel w-full"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-[var(--fg-2)] mb-1">Description</label>
                <textarea
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder="Describe the incident, initial observations, and scope..."
                  rows={4}
                  className="input-sentinel w-full min-h-[100px]"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-[var(--fg-2)] mb-1">Severity</label>
                  <Select value={form.severity} onValueChange={(v) => setForm({ ...form, severity: v })} placeholder="Severity" fullWidth>
                    {severities.map((s) => {
                      const config = SEVERITY_LEVELS.find(sl => sl.value === s);
                      return (
                        <SelectItem key={s} value={s}>
                          {safeCapitalize(s)} {config ? `(SLA: ${config.slaHours}h)` : ''}
                        </SelectItem>
                      );
                    })}
                  </Select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-[var(--fg-2)] mb-1">Assign To</label>
                  <Select value={form.assignedTo} onValueChange={(v) => setForm({ ...form, assignedTo: v })} placeholder="Unassigned" fullWidth>
                    <SelectItem value="">Unassigned</SelectItem>
                    {users.map((user) => (
                      <SelectItem key={user.id} value={user.id}>{user.name}</SelectItem>
                    ))}
                  </Select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-[var(--fg-2)] mb-1">Tags (comma-separated)</label>
                <input
                  type="text"
                  value={form.tags}
                  onChange={(e) => setForm({ ...form, tags: e.target.value })}
                  placeholder="malware, phishing, ransomware, insider-threat..."
                  className="input-sentinel w-full"
                />
              </div>
            </>
          )}

          {activeTab === 'mitre' && (
            <>
              <div>
                <label className="block text-sm font-medium text-[var(--fg-2)] mb-2">
                  <Shield className="h-4 w-4 inline mr-1" />
                  MITRE ATT&CK Tactics
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {MITRE_TACTICS.map((tactic) => (
                    <button
                      key={tactic}
                      type="button"
                      onClick={() => toggleTactic(tactic)}
                      className={cn(
                        'px-3 py-2 text-sm rounded-lg border text-left transition-colors',
                        form.mitreTactics.includes(tactic)
                          ? 'bg-[var(--sol-magenta)]/20 border-[var(--sol-magenta)]/50 text-[var(--sol-magenta)]'
                          : 'bg-[var(--surface-2)] border-[var(--border)] text-[var(--muted)] hover:border-[var(--border-strong)]'
                      )}
                    >
                      {tactic.split('-').map((word) => safeCapitalize(word)).join(' ')}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-[var(--fg-2)] mb-1">
                  Techniques (comma-separated, e.g., T1059.001, T1055)
                </label>
                <input
                  type="text"
                  value={form.mitreTechniques}
                  onChange={(e) => setForm({ ...form, mitreTechniques: e.target.value })}
                  placeholder="T1059.001, T1055, T1003..."
                  className="input-sentinel w-full"
                />
                <p className="mt-1 text-xs text-[var(--subtle)]">
                  <a
                    href="https://attack.mitre.org/techniques/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[var(--emerald-400)] hover:underline"
                  >
                    View MITRE ATT&CK Matrix
                  </a>
                </p>
              </div>
            </>
          )}

          {activeTab === 'links' && (
            <div className="text-center py-8 text-[var(--muted)]">
              <Link2 className="h-12 w-12 mx-auto mb-3 opacity-50" />
              <p className="text-sm">Link alerts after creating the case.</p>
              <p className="text-xs text-[var(--subtle)] mt-1">
                You can link alerts from the case detail page or the alerts page.
              </p>
            </div>
          )}
        </form>
      </div>
      <DialogFooter className="-mx-6 -mb-5">
        <button
          type="button"
          onClick={onClose}
          className="btn-sentinel btn-sentinel-secondary"
        >
          Cancel
        </button>
        <button
          onClick={handleSubmit}
          disabled={isSubmitting || !form.title.trim()}
          className="btn-sentinel btn-sentinel-primary"
        >
          {isSubmitting ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Creating...
            </>
          ) : (
            <>
              <Plus className="h-4 w-4" />
              Create Case
            </>
          )}
        </button>
      </DialogFooter>
    </Dialog>
  );
}

// ============================================================================
// Export Modal
// ============================================================================

function ExportModal({
  isOpen,
  onClose,
  investigations,
}: {
  isOpen: boolean;
  onClose: () => void;
  investigations: CaseInvestigation[];
}) {
  const [format, setFormat] = useState<'json' | 'csv'>('json');
  const [includeNotes, setIncludeNotes] = useState(true);
  const [includeClosed, setIncludeClosed] = useState(true);

  const handleExport = () => {
    let dataToExport = investigations;

    if (!includeClosed) {
      dataToExport = dataToExport.filter(i => i.status !== 'closed' && i.status !== 'archived');
    }

    const exportData = dataToExport.map(inv => ({
      id: inv.id,
      title: inv.title,
      description: inv.description,
      status: inv.status,
      severity: inv.severity,
      assignee: inv.assignedUser?.name || 'Unassigned',
      createdAt: inv.insertedAt,
      updatedAt: inv.updatedAt,
      alertCount: inv.alertIds.length,
      tags: inv.tags.join(', '),
      mitreTactics: inv.mitreTactics.join(', '),
      mitreTechniques: inv.mitreTechniques.join(', '),
      ...(includeNotes ? { notes: inv.notes, findings: inv.findings } : {}),
    }));

    let content: string;
    let filename: string;
    let mimeType: string;

    if (format === 'json') {
      content = JSON.stringify(exportData, null, 2);
      filename = `investigations_export_${new Date().toISOString().split('T')[0]}.json`;
      mimeType = 'application/json';
    } else {
      const headers = Object.keys(exportData[0] || {});
      const csvRows = [
        headers.join(','),
        ...exportData.map(row =>
          headers.map(h => {
            const val = (row as Record<string, unknown>)[h];
            const str = String(val ?? '').replace(/"/g, '""');
            return `"${str}"`;
          }).join(',')
        )
      ];
      content = csvRows.join('\n');
      filename = `investigations_export_${new Date().toISOString().split('T')[0]}.csv`;
      mimeType = 'text/csv';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    onClose();
  };

  return (
    <Dialog
      open={isOpen}
      onOpenChange={(open) => { if (!open) onClose(); }}
      title={
        <span className="flex items-center gap-2">
          <Download className="h-5 w-5" />
          Export Cases
        </span>
      }
      maxWidth="28rem"
    >
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-[var(--fg-2)] mb-2">Format</label>
          <div className="flex gap-3">
            <button
              onClick={() => setFormat('json')}
              className={cn(
                'flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg border transition-colors',
                format === 'json'
                  ? 'bg-[var(--emerald-glow)] border-[var(--emerald-500)]/50 text-[var(--emerald-400)]'
                  : 'bg-[var(--surface-2)] border-[var(--border)] text-[var(--muted)] hover:border-[var(--border-strong)]'
              )}
            >
              <FileJson className="h-5 w-5" />
              JSON
            </button>
            <button
              onClick={() => setFormat('csv')}
              className={cn(
                'flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg border transition-colors',
                format === 'csv'
                  ? 'bg-[var(--emerald-glow)] border-[var(--emerald-500)]/50 text-[var(--emerald-400)]'
                  : 'bg-[var(--surface-2)] border-[var(--border)] text-[var(--muted)] hover:border-[var(--border-strong)]'
              )}
            >
              <FileText className="h-5 w-5" />
              CSV
            </button>
          </div>
        </div>

        <div className="space-y-2">
          <Checkbox
            checked={includeNotes}
            onCheckedChange={setIncludeNotes}
            label="Include notes & findings"
          />
          <Checkbox
            checked={includeClosed}
            onCheckedChange={setIncludeClosed}
            label="Include closed/archived cases"
          />
        </div>

        <div className="pt-4 border-t border-[var(--hairline)]">
          <p className="text-xs text-[var(--muted)]">
            Exporting {includeClosed ? investigations.length : investigations.filter(i => i.status !== 'closed' && i.status !== 'archived').length} cases
          </p>
        </div>
      </div>
      <DialogFooter className="-mx-6 -mb-5 mt-4">
        <button
          onClick={onClose}
          className="btn-sentinel btn-sentinel-secondary"
        >
          Cancel
        </button>
        <button
          onClick={handleExport}
          className="btn-sentinel btn-sentinel-primary"
        >
          <Download className="h-4 w-4" />
          Export
        </button>
      </DialogFooter>
    </Dialog>
  );
}

// ============================================================================
// Investigation Card Component
// ============================================================================

function InvestigationCard({
  investigation,
  isSelected,
  onSelect,
}: {
  investigation: CaseInvestigation;
  isSelected: boolean;
  onSelect: (id: string) => void;
}) {
  const sla = calculateSLAStatus(investigation);

  return (
    <div
      className={cn(
        'card-sentinel card-sentinel-interactive group',
        isSelected && 'border-[var(--emerald-500)] bg-[var(--surface-2)]'
      )}
    >
      <div className="flex items-start gap-3">
        {/* Selection checkbox */}
        <div
          className="pt-1"
          onClick={(e) => e.stopPropagation()}
        >
          <Checkbox
            checked={isSelected}
            onCheckedChange={() => onSelect(investigation.id)}
            aria-label="Select investigation"
          />
        </div>

        {/* Severity icon */}
        <div className={cn(
          'p-2 rounded-lg shrink-0',
          investigation.severity === 'critical' ? 'bg-[var(--crit-bg)]' :
          investigation.severity === 'high' ? 'bg-[var(--high-bg)]' :
          investigation.severity === 'medium' ? 'bg-[var(--med-bg)]' : 'bg-[var(--low-bg)]'
        )}>
          <FileSearch className={cn(
            'h-5 w-5',
            investigation.severity === 'critical' ? 'text-[var(--crit)]' :
            investigation.severity === 'high' ? 'text-[var(--high)]' :
            investigation.severity === 'medium' ? 'text-[var(--med)]' : 'text-[var(--low)]'
          )} />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <a
            href={`/app/investigations/${investigation.id}`}
            className="block"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <h3 className="text-[var(--fg)] font-medium truncate hover:text-[var(--emerald-400)] transition-colors">
                {investigation.title}
              </h3>
            </div>
          </a>

          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <SeverityBadge severity={investigation.severity} />
            <StatusBadge status={investigation.status} />
            {sla.status !== 'ok' && investigation.status !== 'closed' && investigation.status !== 'archived' && (
              <span className={cn(
                'px-2 py-0.5 text-xs font-medium rounded',
                sla.status === 'breach' ? 'bg-[var(--crit-bg)] text-[var(--crit)]' : 'bg-[var(--high-bg)] text-[var(--high)]'
              )}>
                {sla.status === 'breach' ? 'SLA BREACH' : 'AT RISK'}
              </span>
            )}
          </div>

          {investigation.description && (
            <p className="text-sm text-[var(--muted)] mb-3 line-clamp-2">{investigation.description}</p>
          )}

          {/* MITRE Techniques */}
          {investigation.mitreTechniques.length > 0 && (
            <div className="flex flex-wrap gap-1 mb-3">
              {investigation.mitreTechniques.slice(0, 4).map((t) => (
                <MitreTag key={t} technique={t} />
              ))}
              {investigation.mitreTechniques.length > 4 && (
                <span className="text-xs text-[var(--subtle)]">+{investigation.mitreTechniques.length - 4} more</span>
              )}
            </div>
          )}

          {/* Meta info */}
          <div className="flex items-center gap-4 text-xs text-[var(--subtle)] flex-wrap">
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {formatRelativeTime(investigation.insertedAt)}
            </span>
            {investigation.assignedUser && (
              <span className="flex items-center gap-1">
                <User className="h-3 w-3" />
                {investigation.assignedUser.name}
              </span>
            )}
            {investigation.alertIds.length > 0 && (
              <span className="flex items-center gap-1">
                <AlertTriangle className="h-3 w-3" />
                {investigation.alertIds.length} alert{investigation.alertIds.length !== 1 ? 's' : ''}
              </span>
            )}
            {investigation.tags.length > 0 && (
              <span className="flex items-center gap-1">
                <Tag className="h-3 w-3" />
                {investigation.tags.slice(0, 2).join(', ')}
                {investigation.tags.length > 2 && ` +${investigation.tags.length - 2}`}
              </span>
            )}
          </div>

          {/* SLA Bar */}
          {investigation.status !== 'closed' && investigation.status !== 'archived' && (
            <div className="mt-3 pt-3 border-t border-[var(--hairline)]">
              <SLAIndicator investigation={investigation} />
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-start gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <a
            href={`/app/investigations/${investigation.id}`}
            className="p-2 hover:bg-[var(--surface-2)] rounded-lg transition-colors"
            title="View Details"
            onClick={(e) => e.stopPropagation()}
          >
            <ChevronRight className="h-4 w-4 text-[var(--muted)]" />
          </a>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Investigation Table Row (List View)
// ============================================================================

function InvestigationTableRow({
  investigation,
  isSelected,
  onSelect,
}: {
  investigation: CaseInvestigation;
  isSelected: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <tr className={cn(
      'hover:bg-[var(--surface-2)]/50 transition-colors',
      isSelected && 'bg-[var(--surface-2)]/30'
    )}>
      <td className="px-4 py-3">
        <Checkbox
          checked={isSelected}
          onCheckedChange={() => onSelect(investigation.id)}
          aria-label="Select investigation"
        />
      </td>
      <td className="px-4 py-3">
        <a
          href={`/app/investigations/${investigation.id}`}
          className="text-[var(--fg)] hover:text-[var(--emerald-400)] font-medium transition-colors"
        >
          {investigation.title}
        </a>
        {investigation.tags.length > 0 && (
          <div className="flex gap-1 mt-1">
            {investigation.tags.slice(0, 2).map((tag, i) => (
              <span key={i} className="px-1.5 py-0.5 bg-[var(--surface-2)] text-[var(--muted)] rounded text-xs">
                {tag}
              </span>
            ))}
          </div>
        )}
      </td>
      <td className="px-4 py-3">
        <SeverityBadge severity={investigation.severity} />
      </td>
      <td className="px-4 py-3">
        <StatusBadge status={investigation.status} />
      </td>
      <td className="px-4 py-3">
        {investigation.assignedUser ? (
          <span className="flex items-center gap-1 text-sm text-[var(--fg-2)]">
            <User className="h-3.5 w-3.5" />
            {investigation.assignedUser.name}
          </span>
        ) : (
          <span className="text-sm text-[var(--subtle)]">Unassigned</span>
        )}
      </td>
      <td className="px-4 py-3">
        <span className="text-sm text-[var(--muted)]">{investigation.alertIds.length}</span>
      </td>
      <td className="px-4 py-3">
        {investigation.mitreTechniques.length > 0 ? (
          <div className="flex gap-1">
            <MitreTag technique={investigation.mitreTechniques[0]} />
            {investigation.mitreTechniques.length > 1 && (
              <span className="text-xs text-[var(--subtle)]">+{investigation.mitreTechniques.length - 1}</span>
            )}
          </div>
        ) : (
          <span className="text-[var(--subtle)]">-</span>
        )}
      </td>
      <td className="px-4 py-3">
        {investigation.status !== 'closed' && investigation.status !== 'archived' ? (
          <div className="w-24">
            <SLAIndicator investigation={investigation} />
          </div>
        ) : (
          <span className="text-xs text-[var(--emerald-400)]">Resolved</span>
        )}
      </td>
      <td className="px-4 py-3">
        <span className="text-sm text-[var(--muted)]">{formatRelativeTime(investigation.insertedAt)}</span>
      </td>
      <td className="px-4 py-3">
        <a
          href={`/app/investigations/${investigation.id}`}
          className="p-1.5 hover:bg-[var(--surface-2)] rounded transition-colors inline-block"
        >
          <ChevronRight className="h-4 w-4 text-[var(--muted)]" />
        </a>
      </td>
    </tr>
  );
}

// ============================================================================
// Bulk Actions Bar
// ============================================================================

function BulkActionsBar({
  selectedCount,
  onClearSelection,
  onBulkStatusChange,
  onBulkAssign,
  users,
}: {
  selectedCount: number;
  onClearSelection: () => void;
  onBulkStatusChange: (status: string) => void;
  onBulkAssign: (userId: string | null) => void;
  users: InvestigationHubProps['users'];
}) {
  const [showStatusMenu, setShowStatusMenu] = useState(false);
  const [showAssignMenu, setShowAssignMenu] = useState(false);

  if (selectedCount === 0) return null;

  return (
    <div className="card-sentinel p-3 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <span className="text-sm text-[var(--fg)] font-medium">
          {selectedCount} case{selectedCount !== 1 ? 's' : ''} selected
        </span>
        <button
          onClick={onClearSelection}
          className="text-xs text-[var(--muted)] hover:text-[var(--fg)] transition-colors"
        >
          Clear selection
        </button>
      </div>

      <div className="flex items-center gap-2">
        {/* Status dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowStatusMenu(!showStatusMenu)}
            className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
          >
            <Activity className="h-4 w-4" />
            Change Status
            <ChevronDown className="h-3 w-3" />
          </button>
          {showStatusMenu && (
            <div className="absolute right-0 mt-1 w-48 bg-[var(--surface)] border border-[var(--border)] rounded-lg shadow-xl z-10">
              {STATUS_WORKFLOW.map((status) => (
                <button
                  key={status.value}
                  onClick={() => {
                    onBulkStatusChange(status.value);
                    setShowStatusMenu(false);
                  }}
                  className="w-full px-3 py-2 text-left text-sm text-[var(--fg-2)] hover:bg-[var(--surface-2)] first:rounded-t-lg last:rounded-b-lg flex items-center gap-2"
                >
                  <status.icon className="h-4 w-4" />
                  {status.label}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Assign dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowAssignMenu(!showAssignMenu)}
            className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
          >
            <User className="h-4 w-4" />
            Assign
            <ChevronDown className="h-3 w-3" />
          </button>
          {showAssignMenu && (
            <div className="absolute right-0 mt-1 w-48 bg-[var(--surface)] border border-[var(--border)] rounded-lg shadow-xl z-10 max-h-64 overflow-y-auto">
              <button
                onClick={() => {
                  onBulkAssign(null);
                  setShowAssignMenu(false);
                }}
                className="w-full px-3 py-2 text-left text-sm text-[var(--muted)] hover:bg-[var(--surface-2)] rounded-t-lg"
              >
                Unassign
              </button>
              {users.map((user) => (
                <button
                  key={user.id}
                  onClick={() => {
                    onBulkAssign(user.id);
                    setShowAssignMenu(false);
                  }}
                  className="w-full px-3 py-2 text-left text-sm text-[var(--fg-2)] hover:bg-[var(--surface-2)] last:rounded-b-lg"
                >
                  {user.name}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Quick Links Panel
// ============================================================================

function QuickLinksPanel() {
  const links = [
    {
      href: '/app/investigation',
      icon: FileSearch,
      title: 'Investigation Graph',
      description: 'Visual D3.js attack graph',
      color: 'purple',
    },
    {
      href: '/app/analyst',
      icon: Zap,
      title: 'AI Analyst',
      description: 'Automated investigations',
      color: 'blue',
    },
    {
      href: '/app/alerts',
      icon: AlertTriangle,
      title: 'Alert Queue',
      description: 'Triage pending alerts',
      color: 'orange',
    },
    {
      href: '/app/timeline',
      icon: Activity,
      title: 'Attack Timeline',
      description: 'Temporal event analysis',
      color: 'green',
    },
  ];

  const colorClasses: Record<string, { bg: string; text: string; hover: string }> = {
    purple: { bg: 'bg-[var(--sol-magenta)]/20', text: 'text-[var(--sol-magenta)]', hover: 'group-hover:text-[var(--sol-magenta)]' },
    blue: { bg: 'bg-[var(--med-bg)]', text: 'text-[var(--med)]', hover: 'group-hover:text-[var(--med)]' },
    orange: { bg: 'bg-[var(--high-bg)]', text: 'text-[var(--high)]', hover: 'group-hover:text-[var(--high)]' },
    green: { bg: 'bg-[var(--emerald-glow)]', text: 'text-[var(--emerald-400)]', hover: 'group-hover:text-[var(--emerald-400)]' },
  };

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {links.map((link) => {
        const colors = colorClasses[link.color];
        return (
          <a
            key={link.href}
            href={link.href}
            className="card-sentinel card-sentinel-interactive group"
          >
            <div className="flex items-center gap-3">
              <div className={cn('p-2 rounded-lg', colors.bg)}>
                <link.icon className={cn('h-5 w-5', colors.text)} />
              </div>
              <div>
                <div className={cn('font-medium text-[var(--fg)] transition-colors', colors.hover)}>
                  {link.title}
                </div>
                <div className="text-sm text-[var(--subtle)]">{link.description}</div>
              </div>
            </div>
          </a>
        );
      })}
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export default function InvestigationHub({
  investigations,
  stats,
  users,
  filters: initialFilters,
  statuses,
  severities,
}: InvestigationHubProps) {
  // View state
  const [viewMode, setViewMode] = useState<'cards' | 'table'>('cards');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);

  // Selection state
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Filter state
  const [searchQuery, setSearchQuery] = useState(initialFilters.search || '');
  const [filters, setFilters] = useState<FiltersState>({
    status: initialFilters.status || 'all',
    severity: initialFilters.severity || 'all',
    assignee: initialFilters.assigned_to || 'all',
    dateRange: 'all',
    hasMitre: false,
    hasAlerts: false,
    slaStatus: 'all',
  });

  // Apply filters
  const filteredInvestigations = useMemo(() => {
    return investigations.filter((inv) => {
      // Status filter
      if (filters.status !== 'all' && inv.status !== filters.status) return false;

      // Severity filter
      if (filters.severity !== 'all' && inv.severity !== filters.severity) return false;

      // Assignee filter
      if (filters.assignee !== 'all') {
        if (filters.assignee === 'unassigned' && inv.assignedTo) return false;
        if (filters.assignee !== 'unassigned' && inv.assignedTo !== filters.assignee) return false;
      }

      // Date range filter
      if (filters.dateRange !== 'all') {
        const createdAt = new Date(inv.insertedAt);
        const now = new Date();
        switch (filters.dateRange) {
          case 'today':
            if (createdAt.toDateString() !== now.toDateString()) return false;
            break;
          case 'week':
            const weekAgo = new Date(now.getTime() - 7 * 24 * 3600000);
            if (createdAt < weekAgo) return false;
            break;
          case 'month':
            const monthAgo = new Date(now.getTime() - 30 * 24 * 3600000);
            if (createdAt < monthAgo) return false;
            break;
          case 'quarter':
            const quarterAgo = new Date(now.getTime() - 90 * 24 * 3600000);
            if (createdAt < quarterAgo) return false;
            break;
        }
      }

      // MITRE filter
      if (filters.hasMitre && inv.mitreTechniques.length === 0 && inv.mitreTactics.length === 0) {
        return false;
      }

      // Alerts filter
      if (filters.hasAlerts && inv.alertIds.length === 0) return false;

      // SLA filter
      if (filters.slaStatus !== 'all' && inv.status !== 'closed' && inv.status !== 'archived') {
        const sla = calculateSLAStatus(inv);
        if (sla.status !== filters.slaStatus) return false;
      }

      // Search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          inv.title.toLowerCase().includes(query) ||
          (inv.description?.toLowerCase().includes(query) ?? false) ||
          inv.tags.some((t) => t.toLowerCase().includes(query)) ||
          inv.mitreTechniques.some((t) => t.toLowerCase().includes(query))
        );
      }

      return true;
    });
  }, [investigations, filters, searchQuery]);

  // Selection handlers
  const handleSelect = useCallback((id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  const handleSelectAll = useCallback(() => {
    if (selectedIds.size === filteredInvestigations.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filteredInvestigations.map(i => i.id)));
    }
  }, [filteredInvestigations, selectedIds.size]);

  const handleClearSelection = useCallback(() => {
    setSelectedIds(new Set());
  }, []);

  // Bulk actions
  const handleBulkStatusChange = async (status: string) => {
    for (const id of selectedIds) {
      try {
        await apiRequest(`/api/v1/case-investigations/${id}/status`, {
          method: 'PATCH',
          body: JSON.stringify({ status }),
        });
      } catch (err) {
        logger.error(`Failed to update status for ${id}:`, err);
      }
    }
    setSelectedIds(new Set());
    router.reload();
  };

  const handleBulkAssign = async (userId: string | null) => {
    for (const id of selectedIds) {
      try {
        await apiRequest(`/api/v1/case-investigations/${id}/assign`, {
          method: 'POST',
          body: JSON.stringify({ user_id: userId }),
        });
      } catch (err) {
        logger.error(`Failed to assign ${id}:`, err);
      }
    }
    setSelectedIds(new Set());
    router.reload();
  };

  // Filter change handler
  const handleFilterChange = (key: string, value: string) => {
    const params = new URLSearchParams(window.location.search);
    if (value === 'all' || value === '') {
      params.delete(key);
    } else {
      params.set(key, value);
    }
    const newUrl = `${window.location.pathname}${params.toString() ? '?' + params.toString() : ''}`;
    router.visit(newUrl, { preserveState: true });
  };

  return (
    <MainLayout title="Investigation Hub">
      <Head title="Investigations - Tamandua EDR" />

      <div className="space-y-6">
        {/* Stats Cards */}
        <StatsCards stats={stats} />

        {/* SLA Metrics */}
        <SLAMetricsPanel investigations={investigations} />

        {/* Toolbar */}
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3 flex-wrap">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--muted)]" />
              <input
                type="text"
                placeholder="Search cases..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    handleFilterChange('search', searchQuery);
                  }
                }}
                className="input-sentinel pl-10 pr-4 w-64"
              />
            </div>

            {/* Quick filters */}
            <Select
              value={filters.status}
              onValueChange={(v) => {
                setFilters({ ...filters, status: v });
                handleFilterChange('status', v);
              }}
              placeholder="All Status"
            >
              <SelectItem value="all">All Status</SelectItem>
              {statuses.map((s) => (
                <SelectItem key={s} value={s}>
                  {safeCapitalize(s?.replace('_', ' '))}
                </SelectItem>
              ))}
            </Select>

            <Select
              value={filters.severity}
              onValueChange={(v) => {
                setFilters({ ...filters, severity: v });
                handleFilterChange('severity', v);
              }}
              placeholder="All Severity"
            >
              <SelectItem value="all">All Severity</SelectItem>
              {severities.map((s) => (
                <SelectItem key={s} value={s}>
                  {safeCapitalize(s)}
                </SelectItem>
              ))}
            </Select>

            <Select
              value={filters.assignee}
              onValueChange={(v) => {
                setFilters({ ...filters, assignee: v });
                handleFilterChange('assigned_to', v);
              }}
              placeholder="All Assignees"
            >
              <SelectItem value="all">All Assignees</SelectItem>
              <SelectItem value="unassigned">Unassigned</SelectItem>
              {users.map((user) => (
                <SelectItem key={user.id} value={user.id}>{user.name}</SelectItem>
              ))}
            </Select>

            {/* Advanced filters toggle */}
            <button
              onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
              className={cn(
                'btn-sentinel',
                showAdvancedFilters
                  ? 'btn-sentinel-outline'
                  : 'btn-sentinel-secondary'
              )}
            >
              <Filter className="h-4 w-4" />
              Filters
            </button>
          </div>

          <div className="flex items-center gap-2">
            {/* View toggle */}
            <div className="flex bg-[var(--surface)] border border-[var(--border)] rounded-lg p-1">
              <button
                onClick={() => setViewMode('cards')}
                className={cn(
                  'px-3 py-1.5 text-sm rounded transition-colors',
                  viewMode === 'cards' ? 'bg-[var(--surface-2)] text-[var(--fg)]' : 'text-[var(--muted)] hover:text-[var(--fg)]'
                )}
              >
                Cards
              </button>
              <button
                onClick={() => setViewMode('table')}
                className={cn(
                  'px-3 py-1.5 text-sm rounded transition-colors',
                  viewMode === 'table' ? 'bg-[var(--surface-2)] text-[var(--fg)]' : 'text-[var(--muted)] hover:text-[var(--fg)]'
                )}
              >
                Table
              </button>
            </div>

            <button
              onClick={() => router.reload()}
              className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
              title="Refresh"
            >
              <RefreshCw className="h-4 w-4" />
            </button>

            <button
              onClick={() => setShowExportModal(true)}
              className="btn-sentinel btn-sentinel-secondary"
            >
              <Download className="h-4 w-4" />
              Export
            </button>

            <button
              onClick={() => setShowCreateModal(true)}
              className="btn-sentinel btn-sentinel-primary"
            >
              <Plus className="h-4 w-4" />
              Create Case
            </button>
          </div>
        </div>

        {/* Advanced Filters Panel */}
        <AdvancedFiltersPanel
          filters={filters}
          onChange={setFilters}
          isOpen={showAdvancedFilters}
          onClose={() => setShowAdvancedFilters(false)}
        />

        {/* Bulk Actions Bar */}
        <BulkActionsBar
          selectedCount={selectedIds.size}
          onClearSelection={handleClearSelection}
          onBulkStatusChange={handleBulkStatusChange}
          onBulkAssign={handleBulkAssign}
          users={users}
        />

        {/* Investigations List */}
        <div className="card-sentinel p-0 overflow-hidden">
          {filteredInvestigations.length === 0 ? (
            <div className="p-12 text-center text-[var(--subtle)]">
              <FileSearch className="h-16 w-16 mx-auto mb-4 opacity-50" />
              <p className="text-lg">No investigations found</p>
              <p className="text-sm mt-1">
                {investigations.length === 0
                  ? 'Create your first investigation case to get started'
                  : 'Try adjusting your filters'}
              </p>
              {investigations.length === 0 && (
                <button
                  onClick={() => setShowCreateModal(true)}
                  className="mt-4 btn-sentinel btn-sentinel-primary"
                >
                  <Plus className="h-4 w-4" />
                  Create Case
                </button>
              )}
            </div>
          ) : viewMode === 'cards' ? (
            <div className="p-4 grid gap-4 md:grid-cols-2">
              {filteredInvestigations.map((investigation) => (
                <InvestigationCard
                  key={investigation.id}
                  investigation={investigation}
                  isSelected={selectedIds.has(investigation.id)}
                  onSelect={handleSelect}
                />
              ))}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-[var(--bg-2)]">
                  <tr className="text-left text-xs font-medium text-[var(--muted)] uppercase tracking-wider">
                    <th className="px-4 py-3 w-10">
                      <Checkbox
                        checked={selectedIds.size === filteredInvestigations.length && filteredInvestigations.length > 0}
                        onCheckedChange={() => handleSelectAll()}
                        aria-label="Select all investigations"
                      />
                    </th>
                    <th className="px-4 py-3">Title</th>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Assignee</th>
                    <th className="px-4 py-3">Alerts</th>
                    <th className="px-4 py-3">MITRE</th>
                    <th className="px-4 py-3">SLA</th>
                    <th className="px-4 py-3">Created</th>
                    <th className="px-4 py-3 w-10"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--hairline)]">
                  {filteredInvestigations.map((investigation) => (
                    <InvestigationTableRow
                      key={investigation.id}
                      investigation={investigation}
                      isSelected={selectedIds.has(investigation.id)}
                      onSelect={handleSelect}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Results count */}
        {filteredInvestigations.length > 0 && (
          <div className="text-sm text-[var(--muted)] text-center">
            Showing {filteredInvestigations.length} of {investigations.length} cases
          </div>
        )}

        {/* Quick Links */}
        <QuickLinksPanel />
      </div>

      {/* Modals */}
      <CreateInvestigationModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        users={users}
        severities={severities}
      />

      <ExportModal
        isOpen={showExportModal}
        onClose={() => setShowExportModal(false)}
        investigations={filteredInvestigations}
      />
    </MainLayout>
  );
}
