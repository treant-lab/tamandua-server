import { useState, useMemo } from 'react';
import { Head, router } from '@inertiajs/react';
import { MainLayout } from '@/layouts/MainLayout';
import {
  ArrowLeft, FileSearch, Clock, User, Tag, AlertTriangle, Edit2, Save, X,
  Trash2, RefreshCw, ChevronRight, Shield, Loader2, MessageSquare,
  Download, FileJson, FileText, Link2, ExternalLink,
  CheckCircle, PlayCircle, Archive, History, Copy, Check,
  Send, Paperclip, BarChart3, Calendar, Activity
} from 'lucide-react';
import { cn, formatDate, safeCapitalize, severityColor } from '@/lib/utils';
import type { InvestigationCaseDetailProps, Alert, CaseInvestigation } from '@/types';
import { Checkbox, Dialog, DialogFooter } from '@/components/ui/baseui';

// ============================================================================
// Constants
// ============================================================================

const STATUS_WORKFLOW = [
  { value: 'open', label: 'Open', color: 'blue', icon: PlayCircle },
  { value: 'in_progress', label: 'Investigating', color: 'yellow', icon: Loader2 },
  { value: 'closed', label: 'Resolved', color: 'green', icon: CheckCircle },
  { value: 'archived', label: 'Archived', color: 'slate', icon: Archive },
];

const SEVERITY_LEVELS = [
  { value: 'critical', label: 'Critical', color: 'red', slaHours: 1 },
  { value: 'high', label: 'High', color: 'orange', slaHours: 4 },
  { value: 'medium', label: 'Medium', color: 'yellow', slaHours: 24 },
  { value: 'low', label: 'Low', color: 'blue', slaHours: 72 },
  { value: 'info', label: 'Info', color: 'slate', slaHours: 168 },
];

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

function copyToClipboard(text: string): Promise<void> {
  return navigator.clipboard.writeText(text);
}

// ============================================================================
// Sub-Components
// ============================================================================

function StatusBadge({ status }: { status: string }) {
  const config = STATUS_WORKFLOW.find(s => s.value === status) || STATUS_WORKFLOW[0];
  const colorClasses: Record<string, string> = {
    blue: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    yellow: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    green: 'bg-green-500/20 text-green-400 border-green-500/30',
    slate: 'bg-[var(--muted)]/20 text-[var(--muted)] border-[var(--muted)]/30',
  };

  return (
    <span className={cn('px-2 py-0.5 text-xs font-medium rounded border', colorClasses[config.color])}>
      {status.replace('_', ' ').toUpperCase()}
    </span>
  );
}

function SLAIndicator({ investigation }: { investigation: CaseInvestigation }) {
  const sla = calculateSLAStatus(investigation);

  const colorClasses = {
    ok: 'bg-green-500',
    warning: 'bg-yellow-500',
    breach: 'bg-red-500',
  };

  const bgClasses = {
    ok: 'bg-green-500/20',
    warning: 'bg-yellow-500/20',
    breach: 'bg-red-500/20',
  };

  const textClasses = {
    ok: 'text-green-400',
    warning: 'text-yellow-400',
    breach: 'text-red-400',
  };

  return (
    <div className="flex items-center gap-2">
      <div className={cn('flex-1 h-2 rounded-full', bgClasses[sla.status])}>
        <div
          className={cn('h-full rounded-full transition-all', colorClasses[sla.status])}
          style={{ width: `${sla.percentage}%` }}
        />
      </div>
      <span className={cn('text-sm font-medium', textClasses[sla.status])}>
        {sla.timeLeft}
      </span>
    </div>
  );
}

function AlertRow({ alert, onRemove }: { alert: Alert; onRemove?: () => void }) {
  return (
    <div className="flex items-center gap-4 p-3 rounded-lg transition-colors group hover:opacity-90" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}>
      <div className={cn(
        'p-2 rounded-lg',
        alert.severity === 'critical' ? 'bg-red-500/20' :
        alert.severity === 'high' ? 'bg-orange-500/20' :
        alert.severity === 'medium' ? 'bg-yellow-500/20' : 'bg-blue-500/20'
      )}>
        <AlertTriangle className={cn(
          'h-4 w-4',
          alert.severity === 'critical' ? 'text-red-400' :
          alert.severity === 'high' ? 'text-orange-400' :
          alert.severity === 'medium' ? 'text-yellow-400' : 'text-blue-400'
        )} />
      </div>
      <div className="flex-1 min-w-0">
        <a
          href={`/app/alerts/${alert.id}`}
          className="text-sm font-medium truncate hover:text-primary-400 transition-colors"
          style={{ color: 'var(--fg)' }}
        >
          {alert.title}
        </a>
        <div className="text-xs" style={{ color: 'var(--muted)' }}>{formatDate(alert.createdAt)}</div>
      </div>
      <span className={cn('px-2 py-0.5 text-xs font-medium rounded', severityColor(alert.severity))}>
        {alert.severity.toUpperCase()}
      </span>
      {onRemove && (
        <button
          onClick={onRemove}
          className="p-1.5 hover:bg-red-500/20 rounded opacity-0 group-hover:opacity-100 transition-opacity"
          title="Remove from investigation"
        >
          <X className="h-4 w-4 text-red-400" />
        </button>
      )}
      <a
        href={`/app/alerts/${alert.id}`}
        className="p-1.5 rounded opacity-0 group-hover:opacity-100 transition-opacity hover:opacity-80"
        style={{ backgroundColor: 'var(--surface)' }}
        title="View Alert"
      >
        <ChevronRight className="h-4 w-4" style={{ color: 'var(--muted)' }} />
      </a>
    </div>
  );
}

function MitreTag({ technique }: { technique: string }) {
  return (
    <a
      href={`https://attack.mitre.org/techniques/${technique.replace('.', '/')}`}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 px-2 py-1 bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 rounded text-sm transition-colors"
    >
      <Shield className="h-3.5 w-3.5" />
      {technique}
      <ExternalLink className="h-3 w-3" />
    </a>
  );
}

// Timeline entry type based on notes format
interface ParsedNote {
  timestamp: string;
  author: string | null;
  content: string;
}

function parseNotes(notes: string | null): ParsedNote[] {
  if (!notes) return [];

  const entries: ParsedNote[] = [];
  const notePattern = /\[([^\]]+)\](?:\s*\(([^)]+)\))?:\s*(.+)/g;
  let match;

  while ((match = notePattern.exec(notes)) !== null) {
    entries.push({
      timestamp: match[1],
      author: match[2] || null,
      content: match[3].trim(),
    });
  }

  // If no structured notes found, treat the whole thing as a single note
  if (entries.length === 0 && notes.trim()) {
    entries.push({
      timestamp: new Date().toISOString(),
      author: null,
      content: notes,
    });
  }

  return entries.reverse(); // Most recent first
}

function TimelineEntry({ entry }: { entry: ParsedNote }) {
  return (
    <div className="flex gap-3">
      <div className="flex flex-col items-center">
        <div className="w-2 h-2 rounded-full bg-blue-500 mt-2" />
        <div className="flex-1 w-px mt-1" style={{ backgroundColor: 'var(--muted)' }} />
      </div>
      <div className="flex-1 pb-4">
        <div className="rounded-lg p-3" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--muted)' }}>
              {entry.author && (
                <>
                  <User className="h-3 w-3" />
                  <span className="font-medium" style={{ color: 'var(--fg)' }}>{entry.author}</span>
                  <span>-</span>
                </>
              )}
              <Clock className="h-3 w-3" />
              <span>{formatRelativeTime(entry.timestamp)}</span>
            </div>
          </div>
          <p className="text-sm whitespace-pre-wrap" style={{ color: 'var(--fg)' }}>{entry.content}</p>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Export Modal
// ============================================================================

function ExportModal({
  isOpen,
  onClose,
  investigation,
  linkedAlerts,
}: {
  isOpen: boolean;
  onClose: () => void;
  investigation: CaseInvestigation;
  linkedAlerts: Alert[];
}) {
  const [format, setFormat] = useState<'json' | 'markdown'>('json');
  const [includeAlerts, setIncludeAlerts] = useState(true);

  const handleExport = () => {
    let content: string;
    let filename: string;
    let mimeType: string;

    if (format === 'json') {
      const exportData = {
        investigation: {
          ...investigation,
          exportedAt: new Date().toISOString(),
        },
        ...(includeAlerts ? { linkedAlerts } : {}),
      };
      content = JSON.stringify(exportData, null, 2);
      filename = `investigation_${investigation.id}_${new Date().toISOString().split('T')[0]}.json`;
      mimeType = 'application/json';
    } else {
      const lines = [
        `# Investigation: ${investigation.title}`,
        '',
        `**ID:** ${investigation.id}`,
        `**Status:** ${investigation.status}`,
        `**Severity:** ${investigation.severity}`,
        `**Assigned To:** ${investigation.assignedUser?.name || 'Unassigned'}`,
        `**Created:** ${formatDate(investigation.insertedAt)}`,
        `**Updated:** ${formatDate(investigation.updatedAt)}`,
        '',
        '## Description',
        investigation.description || '_No description_',
        '',
        '## Findings',
        investigation.findings || '_No findings documented_',
        '',
        '## MITRE ATT&CK',
        investigation.mitreTechniques.length > 0
          ? investigation.mitreTechniques.map(t => `- ${t}`).join('\n')
          : '_No techniques tagged_',
        '',
        '## Tags',
        investigation.tags.length > 0
          ? investigation.tags.map(t => `- ${t}`).join('\n')
          : '_No tags_',
        '',
        '## Notes',
        investigation.notes || '_No notes_',
      ];

      if (includeAlerts && linkedAlerts.length > 0) {
        lines.push('', '## Linked Alerts');
        linkedAlerts.forEach(alert => {
          lines.push(`- **${alert.title}** (${alert.severity}) - ${formatDate(alert.createdAt)}`);
        });
      }

      lines.push('', `---`, `Exported: ${new Date().toISOString()}`);

      content = lines.join('\n');
      filename = `investigation_${investigation.id}_${new Date().toISOString().split('T')[0]}.md`;
      mimeType = 'text/markdown';
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
          Export Case
        </span>
      }
      maxWidth="28rem"
    >
      <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg)' }}>Format</label>
            <div className="flex gap-3">
              <button
                onClick={() => setFormat('json')}
                className={cn(
                  'flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg border transition-colors',
                  format === 'json'
                    ? 'bg-primary-600/20 border-primary-500/50 text-primary-400'
                    : 'hover:opacity-80'
                )}
                style={format !== 'json' ? { backgroundColor: 'var(--surface)', borderColor: 'var(--muted)', color: 'var(--muted)' } : undefined}
              >
                <FileJson className="h-5 w-5" />
                JSON
              </button>
              <button
                onClick={() => setFormat('markdown')}
                className={cn(
                  'flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg border transition-colors',
                  format === 'markdown'
                    ? 'bg-primary-600/20 border-primary-500/50 text-primary-400'
                    : 'hover:opacity-80'
                )}
                style={format !== 'markdown' ? { backgroundColor: 'var(--surface)', borderColor: 'var(--muted)', color: 'var(--muted)' } : undefined}
              >
                <FileText className="h-5 w-5" />
                Markdown
              </button>
            </div>
          </div>

          <Checkbox
            checked={includeAlerts}
            onCheckedChange={setIncludeAlerts}
            label="Include linked alerts"
          />
      </div>

      <DialogFooter>
        <button
          onClick={onClose}
          className="px-4 py-2 rounded-lg transition-colors hover:opacity-80"
          style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
        >
          Cancel
        </button>
        <button
          onClick={handleExport}
          className="px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-white transition-colors flex items-center gap-2"
        >
          <Download className="h-4 w-4" />
          Export
        </button>
      </DialogFooter>
    </Dialog>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export default function InvestigationCaseDetail({
  investigation,
  linkedAlerts,
  users,
  statuses,
  severities,
}: InvestigationCaseDetailProps) {
  // Edit mode state
  const [isEditing, setIsEditing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isAddingNote, setIsAddingNote] = useState(false);
  const [noteContent, setNoteContent] = useState('');
  const [activeTab, setActiveTab] = useState<'overview' | 'timeline' | 'alerts' | 'evidence'>('overview');
  const [showExportModal, setShowExportModal] = useState(false);
  const [copiedId, setCopiedId] = useState(false);

  // Edit form state
  const [editTitle, setEditTitle] = useState(investigation.title);
  const [editDescription, setEditDescription] = useState(investigation.description || '');
  const [editStatus, setEditStatus] = useState(investigation.status);
  const [editSeverity, setEditSeverity] = useState(investigation.severity);
  const [editAssignedTo, setEditAssignedTo] = useState(investigation.assignedTo || '');
  const [editFindings, setEditFindings] = useState(investigation.findings || '');
  const [editTags, setEditTags] = useState(investigation.tags.join(', '));
  const [editMitreTechniques, setEditMitreTechniques] = useState(investigation.mitreTechniques.join(', '));

  const [error, setError] = useState('');

  // Parse notes into timeline entries
  const timelineEntries = useMemo(() => parseNotes(investigation.notes), [investigation.notes]);

  // SLA status
  const sla = calculateSLAStatus(investigation);

  const handleCopyId = async () => {
    await copyToClipboard(investigation.id);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  const handleSave = async () => {
    setError('');
    setIsSaving(true);

    try {
      await apiRequest(`/api/v1/case-investigations/${investigation.id}`, {
        method: 'PUT',
        body: JSON.stringify({
          title: editTitle,
          description: editDescription || null,
          status: editStatus,
          severity: editSeverity,
          assigned_to: editAssignedTo || null,
          findings: editFindings || null,
          tags: editTags ? editTags.split(',').map(t => t.trim()).filter(Boolean) : [],
          mitre_techniques: editMitreTechniques ? editMitreTechniques.split(',').map(t => t.trim()).filter(Boolean) : [],
        }),
      });

      setIsEditing(false);
      router.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save changes');
    } finally {
      setIsSaving(false);
    }
  };

  const handleAddNote = async () => {
    if (!noteContent.trim()) return;

    setIsAddingNote(true);
    setError('');

    try {
      await apiRequest(`/api/v1/case-investigations/${investigation.id}/notes`, {
        method: 'POST',
        body: JSON.stringify({ content: noteContent }),
      });

      setNoteContent('');
      router.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add note');
    } finally {
      setIsAddingNote(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm('Are you sure you want to delete this investigation? This action cannot be undone.')) {
      return;
    }

    try {
      await apiRequest(`/api/v1/case-investigations/${investigation.id}`, {
        method: 'DELETE',
      });

      router.visit('/app/investigations');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete investigation');
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    try {
      await apiRequest(`/api/v1/case-investigations/${investigation.id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status: newStatus }),
      });

      router.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update status');
    }
  };

  const handleRemoveAlert = async (alertId: string) => {
    try {
      await apiRequest(`/api/v1/case-investigations/${investigation.id}/alerts/${alertId}`, {
        method: 'DELETE',
      });
      router.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove alert');
    }
  };

  return (
    <MainLayout title={investigation.title}>
      <Head title={`${investigation.title} - Tamandua EDR`} />

      <div className="space-y-6">
        {/* Header */}
        <div className="card-sentinel rounded-xl border p-6" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-4">
              <button
                onClick={() => router.visit('/app/investigations')}
                className="p-2 rounded-lg transition-colors hover:opacity-80"
                style={{ backgroundColor: 'var(--surface)' }}
              >
                <ArrowLeft className="h-5 w-5" style={{ color: 'var(--muted)' }} />
              </button>
              <div className={cn(
                'p-3 rounded-xl',
                investigation.severity === 'critical' ? 'bg-red-500/20' :
                investigation.severity === 'high' ? 'bg-orange-500/20' :
                investigation.severity === 'medium' ? 'bg-yellow-500/20' : 'bg-blue-500/20'
              )}>
                <FileSearch className={cn(
                  'h-8 w-8',
                  investigation.severity === 'critical' ? 'text-red-400' :
                  investigation.severity === 'high' ? 'text-orange-400' :
                  investigation.severity === 'medium' ? 'text-yellow-400' : 'text-blue-400'
                )} />
              </div>
              <div>
                {isEditing ? (
                  <input
                    type="text"
                    value={editTitle}
                    onChange={(e) => setEditTitle(e.target.value)}
                    className="text-xl font-bold rounded px-2 py-1 w-full"
                    style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                  />
                ) : (
                  <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{investigation.title}</h1>
                )}
                <div className="flex items-center gap-4 mt-2 text-sm flex-wrap" style={{ color: 'var(--muted)' }}>
                  <StatusBadge status={investigation.status} />
                  <span className={cn('px-2 py-0.5 text-xs font-medium rounded', severityColor(investigation.severity))}>
                    {investigation.severity.toUpperCase()}
                  </span>
                  <button
                    onClick={handleCopyId}
                    className="flex items-center gap-1 transition-colors hover:opacity-80"
                    title="Copy ID"
                  >
                    {copiedId ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                    <span className="font-mono text-xs">{investigation.id.slice(0, 8)}...</span>
                  </button>
                  <span className="flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5" />
                    {formatRelativeTime(investigation.insertedAt)}
                  </span>
                  {investigation.assignedUser && (
                    <span className="flex items-center gap-1">
                      <User className="h-3.5 w-3.5" />
                      {investigation.assignedUser.name}
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {isEditing ? (
                <>
                  <button
                    onClick={() => {
                      setIsEditing(false);
                      setEditTitle(investigation.title);
                      setEditDescription(investigation.description || '');
                      setEditStatus(investigation.status);
                      setEditSeverity(investigation.severity);
                      setEditAssignedTo(investigation.assignedTo || '');
                      setEditFindings(investigation.findings || '');
                      setEditTags(investigation.tags.join(', '));
                      setEditMitreTechniques(investigation.mitreTechniques.join(', '));
                    }}
                    className="px-3 py-2 rounded-lg text-sm transition-colors hover:opacity-80"
                    style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSave}
                    disabled={isSaving}
                    className="px-3 py-2 bg-primary-600 hover:bg-primary-700 disabled:opacity-50 rounded-lg text-white text-sm transition-colors flex items-center gap-2"
                  >
                    {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                    Save
                  </button>
                </>
              ) : (
                <>
                  <button
                    onClick={() => setShowExportModal(true)}
                    className="p-2 rounded-lg transition-colors hover:opacity-80"
                    style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}
                    title="Export"
                  >
                    <Download className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                  </button>
                  <button
                    onClick={() => router.reload()}
                    className="p-2 rounded-lg transition-colors hover:opacity-80"
                    style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}
                    title="Refresh"
                  >
                    <RefreshCw className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                  </button>
                  <button
                    onClick={() => setIsEditing(true)}
                    className="px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-2 hover:opacity-80"
                    style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                  >
                    <Edit2 className="h-4 w-4" />
                    Edit
                  </button>
                  <button
                    onClick={handleDelete}
                    className="px-3 py-2 bg-red-600/20 hover:bg-red-600/30 border border-red-500/30 rounded-lg text-red-400 text-sm transition-colors flex items-center gap-2"
                  >
                    <Trash2 className="h-4 w-4" />
                    Delete
                  </button>
                </>
              )}
            </div>
          </div>

          {/* SLA Indicator */}
          {investigation.status !== 'closed' && investigation.status !== 'archived' && (
            <div className="mt-4 pt-4 border-t" style={{ borderColor: 'var(--muted)' }}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm" style={{ color: 'var(--muted)' }}>SLA Status</span>
                {sla.status !== 'ok' && (
                  <span className={cn(
                    'px-2 py-0.5 text-xs font-medium rounded',
                    sla.status === 'breach' ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400'
                  )}>
                    {sla.status === 'breach' ? 'SLA BREACH' : 'AT RISK'}
                  </span>
                )}
              </div>
              <SLAIndicator investigation={investigation} />
            </div>
          )}

          {error && (
            <div className="mt-4 p-3 bg-red-500/20 border border-red-500/30 rounded-lg text-red-400 text-sm">
              {error}
            </div>
          )}
        </div>

        {/* Tab Navigation */}
        <div className="card-sentinel rounded-xl border" style={{ borderColor: 'var(--muted)', backgroundColor: 'var(--surface)' }}>
          <div className="border-b px-4" style={{ borderColor: 'var(--muted)' }}>
            <div className="flex gap-1">
              {([
                { id: 'overview', label: 'Overview', icon: FileSearch },
                { id: 'timeline', label: 'Timeline', icon: History, count: timelineEntries.length },
                { id: 'alerts', label: 'Linked Alerts', icon: AlertTriangle, count: linkedAlerts.length },
                { id: 'evidence', label: 'Evidence', icon: Paperclip },
              ] as const).map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors',
                    activeTab === tab.id
                      ? 'border-primary-500 text-primary-400'
                      : 'border-transparent hover:opacity-80'
                  )}
                  style={activeTab !== tab.id ? { color: 'var(--muted)' } : undefined}
                >
                  <tab.icon className="h-4 w-4" />
                  {tab.label}
                  {'count' in tab && tab.count !== undefined && tab.count > 0 && (
                    <span className="px-1.5 py-0.5 rounded text-xs" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}>{tab.count}</span>
                  )}
                </button>
              ))}
            </div>
          </div>

          <div className="p-6">
            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 space-y-6">
                  {/* Description */}
                  <div>
                    <h2 className="text-lg font-semibold mb-3" style={{ color: 'var(--fg)' }}>Description</h2>
                    {isEditing ? (
                      <textarea
                        value={editDescription}
                        onChange={(e) => setEditDescription(e.target.value)}
                        rows={4}
                        placeholder="Add a description..."
                        className="w-full px-3 py-2 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
                        style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                      />
                    ) : (
                      <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}>
                        <p style={{ color: 'var(--fg)' }} className="whitespace-pre-wrap">
                          {investigation.description || <span style={{ color: 'var(--muted)' }} className="italic">No description</span>}
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Findings */}
                  <div>
                    <h2 className="text-lg font-semibold mb-3" style={{ color: 'var(--fg)' }}>Findings</h2>
                    {isEditing ? (
                      <textarea
                        value={editFindings}
                        onChange={(e) => setEditFindings(e.target.value)}
                        rows={6}
                        placeholder="Document your findings..."
                        className="w-full px-3 py-2 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
                        style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                      />
                    ) : (
                      <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}>
                        <p style={{ color: 'var(--fg)' }} className="whitespace-pre-wrap">
                          {investigation.findings || <span style={{ color: 'var(--muted)' }} className="italic">No findings documented</span>}
                        </p>
                      </div>
                    )}
                  </div>

                  {/* MITRE ATT&CK */}
                  <div>
                    <h2 className="text-lg font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--fg)' }}>
                      <Shield className="h-5 w-5 text-purple-400" />
                      MITRE ATT&CK
                    </h2>
                    {isEditing ? (
                      <div>
                        <input
                          type="text"
                          value={editMitreTechniques}
                          onChange={(e) => setEditMitreTechniques(e.target.value)}
                          placeholder="T1059.001, T1055, T1003..."
                          className="w-full px-3 py-2 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
                          style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                        />
                        <p className="mt-1 text-xs" style={{ color: 'var(--muted)' }}>Comma-separated technique IDs</p>
                      </div>
                    ) : investigation.mitreTechniques.length > 0 ? (
                      <div className="flex flex-wrap gap-2">
                        {investigation.mitreTechniques.map((t) => (
                          <MitreTag key={t} technique={t} />
                        ))}
                      </div>
                    ) : (
                      <p className="italic" style={{ color: 'var(--muted)' }}>No techniques tagged</p>
                    )}
                  </div>
                </div>

                {/* Sidebar */}
                <div className="space-y-6">
                  {/* Status & Assignment */}
                  <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}>
                    <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--fg)' }}>Details</h3>

                    <div className="space-y-4">
                      {/* Status */}
                      <div>
                        <label className="block text-xs font-medium mb-2" style={{ color: 'var(--muted)' }}>Status</label>
                        {isEditing ? (
                          <select
                            value={editStatus}
                            onChange={(e) => setEditStatus(e.target.value as 'open' | 'in_progress' | 'closed' | 'archived')}
                            className="w-full px-3 py-2 rounded-lg text-sm"
                            style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                          >
                            {statuses.map((s) => (
                              <option key={s} value={s}>
                                {safeCapitalize(s?.replace('_', ' '))}
                              </option>
                            ))}
                          </select>
                        ) : (
                          <div className="flex flex-wrap gap-2">
                            {STATUS_WORKFLOW.map((s) => (
                              <button
                                key={s.value}
                                onClick={() => handleStatusChange(s.value)}
                                className={cn(
                                  'px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors',
                                  s.value === investigation.status
                                    ? 'bg-primary-600/20 border-primary-500/30 text-primary-400'
                                    : 'hover:opacity-80'
                                )}
                                style={s.value !== investigation.status ? { backgroundColor: 'var(--surface)', borderColor: 'var(--muted)', color: 'var(--fg)' } : undefined}
                              >
                                {s.label}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Severity */}
                      <div>
                        <label className="block text-xs font-medium mb-2" style={{ color: 'var(--muted)' }}>Severity</label>
                        {isEditing ? (
                          <select
                            value={editSeverity}
                            onChange={(e) => setEditSeverity(e.target.value as 'critical' | 'high' | 'medium' | 'low' | 'info')}
                            className="w-full px-3 py-2 rounded-lg text-sm"
                            style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                          >
                            {severities.map((s) => (
                              <option key={s} value={s}>
                                {safeCapitalize(s)}
                              </option>
                            ))}
                          </select>
                        ) : (
                          <span className={cn('px-3 py-1.5 text-sm font-medium rounded-lg inline-block', severityColor(investigation.severity))}>
                            {investigation.severity.toUpperCase()}
                          </span>
                        )}
                      </div>

                      {/* Assignee */}
                      <div>
                        <label className="block text-xs font-medium mb-2" style={{ color: 'var(--muted)' }}>Assigned To</label>
                        {isEditing ? (
                          <select
                            value={editAssignedTo}
                            onChange={(e) => setEditAssignedTo(e.target.value)}
                            className="w-full px-3 py-2 rounded-lg text-sm"
                            style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                          >
                            <option value="">Unassigned</option>
                            {users.map((user) => (
                              <option key={user.id} value={user.id}>{user.name}</option>
                            ))}
                          </select>
                        ) : investigation.assignedUser ? (
                          <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--fg)' }}>
                            <User className="h-4 w-4" />
                            {investigation.assignedUser.name}
                          </div>
                        ) : (
                          <span className="italic" style={{ color: 'var(--muted)' }}>Unassigned</span>
                        )}
                      </div>

                      {/* Tags */}
                      <div>
                        <label className="block text-xs font-medium mb-2" style={{ color: 'var(--muted)' }}>Tags</label>
                        {isEditing ? (
                          <input
                            type="text"
                            value={editTags}
                            onChange={(e) => setEditTags(e.target.value)}
                            placeholder="tag1, tag2, tag3..."
                            className="w-full px-3 py-2 rounded-lg text-sm"
                            style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                          />
                        ) : investigation.tags.length > 0 ? (
                          <div className="flex flex-wrap gap-2">
                            {investigation.tags.map((tag, i) => (
                              <span key={i} className="px-2 py-1 rounded text-sm flex items-center gap-1" style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}>
                                <Tag className="h-3 w-3" />
                                {tag}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <p className="italic" style={{ color: 'var(--muted)' }}>No tags</p>
                        )}
                      </div>

                      {/* Dates */}
                      <div>
                        <label className="block text-xs font-medium mb-2" style={{ color: 'var(--muted)' }}>Created</label>
                        <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--fg)' }}>
                          <Calendar className="h-4 w-4" />
                          {formatDate(investigation.insertedAt)}
                        </div>
                      </div>

                      <div>
                        <label className="block text-xs font-medium mb-2" style={{ color: 'var(--muted)' }}>Last Updated</label>
                        <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--fg)' }}>
                          <Clock className="h-4 w-4" />
                          {formatDate(investigation.updatedAt)}
                        </div>
                      </div>

                      {investigation.creator && (
                        <div>
                          <label className="block text-xs font-medium mb-2" style={{ color: 'var(--muted)' }}>Created By</label>
                          <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--fg)' }}>
                            <User className="h-4 w-4" />
                            {investigation.creator.name}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Quick Actions */}
                  <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}>
                    <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--fg)' }}>Quick Actions</h3>
                    <div className="space-y-2">
                      <a
                        href={`/app/investigation/${investigation.alertIds[0] || investigation.id}?type=alert`}
                        className="w-full px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-2 hover:opacity-80"
                        style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                      >
                        <Activity className="h-4 w-4" />
                        View Investigation Graph
                      </a>
                      <a
                        href="/app/alerts"
                        className="w-full px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-2 hover:opacity-80"
                        style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                      >
                        <Link2 className="h-4 w-4" />
                        Link More Alerts
                      </a>
                      <a
                        href="/app/ai-assistant"
                        className="w-full px-3 py-2 rounded-lg text-sm transition-colors flex items-center gap-2 hover:opacity-80"
                        style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                      >
                        <BarChart3 className="h-4 w-4" />
                        AI Analyst
                      </a>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Timeline Tab */}
            {activeTab === 'timeline' && (
              <div className="space-y-6">
                {/* Add note form */}
                <div className="rounded-lg p-4" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}>
                  <div className="flex items-start gap-3">
                    <div className="p-2 rounded-lg" style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--muted)' }}>
                      <MessageSquare className="h-5 w-5" style={{ color: 'var(--muted)' }} />
                    </div>
                    <div className="flex-1">
                      <textarea
                        value={noteContent}
                        onChange={(e) => setNoteContent(e.target.value)}
                        rows={3}
                        placeholder="Add a note or update..."
                        className="w-full px-3 py-2 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
                        style={{ backgroundColor: 'var(--surface)', color: 'var(--fg)', border: '1px solid var(--muted)' }}
                      />
                      <div className="flex justify-end mt-2">
                        <button
                          onClick={handleAddNote}
                          disabled={isAddingNote || !noteContent.trim()}
                          className="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-white text-sm transition-colors flex items-center gap-2"
                        >
                          {isAddingNote ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                          Add Note
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Timeline entries */}
                {timelineEntries.length > 0 ? (
                  <div>
                    {timelineEntries.map((entry, idx) => (
                      <TimelineEntry key={idx} entry={entry} />
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-12">
                    <History className="h-12 w-12 mx-auto mb-3" style={{ color: 'var(--muted)' }} />
                    <p style={{ color: 'var(--muted)' }}>No notes yet</p>
                    <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>Add notes to track investigation progress</p>
                  </div>
                )}
              </div>
            )}

            {/* Linked Alerts Tab */}
            {activeTab === 'alerts' && (
              <div className="space-y-4">
                {linkedAlerts.length === 0 ? (
                  <div className="text-center py-12">
                    <AlertTriangle className="h-12 w-12 mx-auto mb-3" style={{ color: 'var(--muted)' }} />
                    <p style={{ color: 'var(--muted)' }}>No alerts linked</p>
                    <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>Link alerts from the alerts page</p>
                    <a
                      href="/app/alerts"
                      className="mt-4 inline-flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-white text-sm transition-colors"
                    >
                      <Link2 className="h-4 w-4" />
                      Browse Alerts
                    </a>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {linkedAlerts.map((alert) => (
                      <AlertRow
                        key={alert.id}
                        alert={alert}
                        onRemove={() => handleRemoveAlert(alert.id)}
                      />
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Evidence Tab */}
            {activeTab === 'evidence' && (
              <div className="text-center py-12">
                <Paperclip className="h-12 w-12 mx-auto mb-3" style={{ color: 'var(--muted)' }} />
                <p style={{ color: 'var(--muted)' }}>No evidence attachments are stored for this case.</p>
                <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
                  Attachment upload is disabled until case evidence storage and audit trails are wired.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Export Modal */}
      <ExportModal
        isOpen={showExportModal}
        onClose={() => setShowExportModal(false)}
        investigation={investigation}
        linkedAlerts={linkedAlerts}
      />
    </MainLayout>
  );
}
