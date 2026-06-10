import { Head } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  Settings,
  Trash2,
  Plus,
  Edit,
  Users,
  Brain,
  Activity,
  Bug,
  Lock,
  Terminal,
  Key,
  ArrowRightLeft,
  Cpu,
  Save,
  X,
  Loader2,
  CheckCircle,
  XCircle,
  Copy,
  ChevronDown,
  ChevronUp,
  Star,
  AlertTriangle,
  Globe,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useState, useEffect, useCallback, useRef } from 'react'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type AggressivenessLevel = 'disabled' | 'cautious' | 'moderate' | 'aggressive' | 'extra_aggressive'
type ResponseMode = 'detect_only' | 'detect_and_prevent'

interface CategorySetting {
  category: string
  aggressiveness: AggressivenessLevel
  mode: ResponseMode
}

interface Exclusions {
  paths: string[]
  processes: string[]
  hashes: string[]
  users: string[]
}

interface AssignedAgent {
  id: string
  hostname: string
  os: string
}

interface NetworkContainment {
  allow_dns: boolean
  allowed_ips: string[]
}

interface PreventionPolicy {
  id: string
  name: string
  description: string
  is_default: boolean
  mode: ResponseMode
  aggressiveness: AggressivenessLevel
  category_settings: CategorySetting[]
  exclusions: Exclusions
  network_containment: NetworkContainment
  assigned_agents: AssignedAgent[]
  created_at: string
  updated_at: string
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AGGRESSIVENESS_LEVELS: { value: AggressivenessLevel; label: string }[] = [
  { value: 'disabled', label: 'Disabled' },
  { value: 'cautious', label: 'Cautious' },
  { value: 'moderate', label: 'Moderate' },
  { value: 'aggressive', label: 'Aggressive' },
  { value: 'extra_aggressive', label: 'Extra Aggressive' },
]

const AGGRESSIVENESS_INDEX: Record<AggressivenessLevel, number> = {
  disabled: 0,
  cautious: 1,
  moderate: 2,
  aggressive: 3,
  extra_aggressive: 4,
}

const AGGRESSIVENESS_THRESHOLDS: Record<AggressivenessLevel, { alert: number; block: number } | null> = {
  disabled: null,
  cautious: { alert: 0.85, block: 0.95 },
  moderate: { alert: 0.75, block: 0.90 },
  aggressive: { alert: 0.60, block: 0.80 },
  extra_aggressive: { alert: 0.40, block: 0.60 },
}

const AGGRESSIVENESS_STYLES: Record<AggressivenessLevel, { text: string; bg: string; border: string; dot: string }> = {
  disabled: { text: 'var(--subtle)', bg: 'var(--surface-2)', border: 'var(--border)', dot: 'var(--subtle)' },
  cautious: { text: 'var(--med)', bg: 'var(--med-bg)', border: 'var(--med)', dot: 'var(--med)' },
  moderate: { text: 'var(--emerald-400)', bg: 'var(--emerald-glow)', border: 'var(--emerald-500)', dot: 'var(--emerald-400)' },
  aggressive: { text: 'var(--high)', bg: 'var(--high-bg)', border: 'var(--high)', dot: 'var(--high)' },
  extra_aggressive: { text: 'var(--crit)', bg: 'var(--crit-bg)', border: 'var(--crit)', dot: 'var(--crit)' },
}

const THREAT_CATEGORIES: { id: string; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'malware_ml', label: 'Machine Learning', icon: Brain },
  { id: 'behavioral_ioa', label: 'Behavioral IOA', icon: Activity },
  { id: 'exploit_prevention', label: 'Exploit Prevention', icon: Bug },
  { id: 'ransomware', label: 'Ransomware', icon: Lock },
  { id: 'script_execution', label: 'Script Execution', icon: Terminal },
  { id: 'credential_theft', label: 'Credential Theft', icon: Key },
  { id: 'lateral_movement', label: 'Lateral Movement', icon: ArrowRightLeft },
  { id: 'fileless_attack', label: 'Fileless Attack', icon: Cpu },
]

const MODE_LABELS: Record<ResponseMode, string> = {
  detect_only: 'Detect Only',
  detect_and_prevent: 'Detect & Prevent',
}

const API_BASE = '/api/v1/prevention-policies'

function getCsrfToken(): string {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
}

// ---------------------------------------------------------------------------
// Toast system (matches Settings.tsx pattern)
// ---------------------------------------------------------------------------

interface Toast {
  id: number
  type: 'success' | 'error'
  message: string
}

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  return (
    <div className="fixed top-4 right-4 z-50 space-y-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className="flex items-center gap-3 px-4 py-3 rounded-lg shadow-lg min-w-[320px] animate-in slide-in-from-right"
          style={{
            backgroundColor: toast.type === 'success' ? 'var(--emerald-glow)' : 'var(--crit-bg)',
            border: `1px solid ${toast.type === 'success' ? 'var(--emerald-500)' : 'var(--crit)'}`,
            color: toast.type === 'success' ? 'var(--emerald-200)' : 'var(--crit)',
          }}
        >
          {toast.type === 'success' ? (
            <CheckCircle className="h-5 w-5 flex-shrink-0" style={{ color: 'var(--emerald-400)' }} />
          ) : (
            <XCircle className="h-5 w-5 flex-shrink-0" style={{ color: 'var(--crit)' }} />
          )}
          <span className="text-sm flex-1">{toast.message}</span>
          <button
            onClick={() => onDismiss(toast.id)}
            className="ml-2 flex-shrink-0 transition-colors"
            style={{ color: 'var(--muted)' }}
            onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--fg)' }}
            onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--muted)' }}
          >
            <XCircle className="h-4 w-4" />
          </button>
        </div>
      ))}
    </div>
  )
}

function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([])

  const addToast = useCallback((type: 'success' | 'error', message: string) => {
    const id = Date.now() + Math.random()
    setToasts((prev) => [...prev, { id, type, message }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, 5000)
  }, [])

  const dismissToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  return { toasts, addToast, dismissToast }
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async function apiFetch<T>(url: string, options?: RequestInit): Promise<T | undefined> {
  const csrfToken = getCsrfToken()
  const response = await fetch(url, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
      ...(options?.headers || {}),
    },
  })
  if (!response.ok) {
    let errorMessage = `Request failed (status ${response.status})`
    try {
      const data = await response.json()
      if (data.error) errorMessage = data.error
      else if (data.message) errorMessage = data.message
    } catch {
      // use default
    }
    throw new Error(errorMessage)
  }
  if (response.status === 204) return undefined
  return response.json()
}

// ---------------------------------------------------------------------------
// Small shared components
// ---------------------------------------------------------------------------

function AggressivenessDots({ level }: { level: AggressivenessLevel }) {
  const idx = AGGRESSIVENESS_INDEX[level]
  const styles = AGGRESSIVENESS_STYLES[level]
  const total = 5

  return (
    <div className="flex items-center gap-1">
      {Array.from({ length: total }).map((_, i) => (
        <span
          key={i}
          className="h-2.5 w-2.5 rounded-full transition-colors"
          style={{
            backgroundColor: i <= idx - (level === 'disabled' ? 1 : 0) && level !== 'disabled'
              ? styles.dot
              : 'var(--surface-3)'
          }}
        />
      ))}
    </div>
  )
}

function AggressivenessBadge({ level }: { level: AggressivenessLevel }) {
  const label = AGGRESSIVENESS_LEVELS.find((l) => l.value === level)?.label ?? level
  const styles = AGGRESSIVENESS_STYLES[level]
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium"
      style={{
        color: styles.text,
        backgroundColor: styles.bg,
        border: `1px solid ${styles.border}`,
      }}
    >
      {label}
    </span>
  )
}

function ModeBadge({ mode }: { mode: ResponseMode }) {
  const isPrevent = mode === 'detect_and_prevent'
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium"
      style={{
        color: isPrevent ? 'var(--emerald-400)' : 'var(--high)',
        backgroundColor: isPrevent ? 'var(--emerald-glow)' : 'var(--high-bg)',
        border: `1px solid ${isPrevent ? 'var(--emerald-500)' : 'var(--high)'}`,
      }}
    >
      {isPrevent ? <ShieldCheck className="h-3 w-3" /> : <Shield className="h-3 w-3" />}
      {MODE_LABELS[mode]}
    </span>
  )
}

function ThresholdIndicator({ level }: { level: AggressivenessLevel }) {
  const thresholds = AGGRESSIVENESS_THRESHOLDS[level]
  if (!thresholds) return <span className="text-xs" style={{ color: 'var(--subtle)' }}>No detection</span>
  return (
    <span className="text-xs" style={{ color: 'var(--muted)' }}>
      Alert: {thresholds.alert.toFixed(2)} | Block: {thresholds.block.toFixed(2)}
    </span>
  )
}

// Tag input component for exclusions
function TagInput({
  tags,
  onChange,
  placeholder,
  disabled,
}: {
  tags: string[]
  onChange: (tags: string[]) => void
  placeholder: string
  disabled?: boolean
}) {
  const [input, setInput] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  const addTag = () => {
    const trimmed = input.trim()
    if (trimmed && !tags.includes(trimmed)) {
      onChange([...tags, trimmed])
    }
    setInput('')
  }

  const removeTag = (tag: string) => {
    onChange(tags.filter((t) => t !== tag))
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      addTag()
    } else if (e.key === 'Backspace' && input === '' && tags.length > 0) {
      removeTag(tags[tags.length - 1])
    }
  }

  return (
    <div
      className={cn(
        'flex flex-wrap items-center gap-1.5 min-h-[42px] rounded-lg px-3 py-2 cursor-text',
        disabled && 'opacity-50'
      )}
      style={{
        backgroundColor: 'var(--surface-2)',
        border: '1px solid var(--border)',
      }}
      onClick={() => inputRef.current?.focus()}
    >
      {tags.map((tag) => (
        <span
          key={tag}
          className="inline-flex items-center gap-1 text-xs px-2 py-1 rounded"
          style={{
            backgroundColor: 'var(--surface-3)',
            color: 'var(--fg-2)',
          }}
        >
          <span className="max-w-[200px] truncate">{tag}</span>
          {!disabled && (
            <button
              type="button"
              onClick={() => removeTag(tag)}
              className="transition-colors"
              style={{ color: 'var(--muted)' }}
              onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--fg)' }}
              onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--muted)' }}
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </span>
      ))}
      <input
        ref={inputRef}
        type="text"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={handleKeyDown}
        onBlur={addTag}
        placeholder={tags.length === 0 ? placeholder : ''}
        disabled={disabled}
        className="flex-1 min-w-[120px] bg-transparent text-sm outline-none disabled:cursor-not-allowed"
        style={{ color: 'var(--fg)' }}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Aggressiveness selector (5-level button group)
// ---------------------------------------------------------------------------

function AggressivenessSelector({
  value,
  onChange,
  disabled,
  compact,
}: {
  value: AggressivenessLevel
  onChange: (v: AggressivenessLevel) => void
  disabled?: boolean
  compact?: boolean
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className={cn('flex', compact ? 'gap-0.5' : 'gap-1')}>
        {AGGRESSIVENESS_LEVELS.map((level) => {
          const isActive = value === level.value
          const styles = AGGRESSIVENESS_STYLES[level.value]

          return (
            <button
              key={level.value}
              type="button"
              onClick={() => onChange(level.value)}
              disabled={disabled}
              title={level.label}
              className={cn(
                'font-medium transition-all disabled:opacity-50',
                compact
                  ? 'px-2 py-1 text-[10px] rounded'
                  : 'px-3 py-1.5 text-xs rounded-lg'
              )}
              style={{
                backgroundColor: isActive ? styles.bg : 'var(--surface-2)',
                color: isActive ? styles.text : 'var(--muted)',
                border: `1px solid ${isActive ? styles.border : 'var(--border)'}`,
              }}
              onMouseEnter={(e) => {
                if (!isActive && !disabled) {
                  e.currentTarget.style.backgroundColor = 'var(--surface-3)'
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive && !disabled) {
                  e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                }
              }}
            >
              {compact ? level.label.slice(0, 3).toUpperCase() : level.label}
            </button>
          )
        })}
      </div>
      <ThresholdIndicator level={value} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Mode toggle
// ---------------------------------------------------------------------------

function ModeToggle({
  value,
  onChange,
  disabled,
  compact,
}: {
  value: ResponseMode
  onChange: (v: ResponseMode) => void
  disabled?: boolean
  compact?: boolean
}) {
  const options: { value: ResponseMode; label: string; compactLabel: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { value: 'detect_only', label: 'Detect Only', compactLabel: 'Detect', icon: Shield },
    { value: 'detect_and_prevent', label: 'Detect & Prevent', compactLabel: 'Prevent', icon: ShieldCheck },
  ]

  return (
    <div className="flex gap-1">
      {options.map((opt) => {
        const isActive = value === opt.value
        const isPrevent = opt.value === 'detect_and_prevent'
        return (
          <button
            key={opt.value}
            type="button"
            onClick={() => onChange(opt.value)}
            disabled={disabled}
            className={cn(
              'flex items-center gap-1.5 font-medium transition-all disabled:opacity-50',
              compact
                ? 'px-2 py-1 text-[10px] rounded'
                : 'px-3 py-1.5 text-xs rounded-lg'
            )}
            style={{
              backgroundColor: isActive
                ? (isPrevent ? 'var(--emerald-glow)' : 'var(--high-bg)')
                : 'var(--surface-2)',
              color: isActive
                ? (isPrevent ? 'var(--emerald-400)' : 'var(--high)')
                : 'var(--muted)',
              border: `1px solid ${isActive
                ? (isPrevent ? 'var(--emerald-500)' : 'var(--high)')
                : 'var(--border)'}`,
            }}
            onMouseEnter={(e) => {
              if (!isActive && !disabled) {
                e.currentTarget.style.backgroundColor = 'var(--surface-3)'
              }
            }}
            onMouseLeave={(e) => {
              if (!isActive && !disabled) {
                e.currentTarget.style.backgroundColor = 'var(--surface-2)'
              }
            }}
          >
            <opt.icon className={compact ? 'h-3 w-3' : 'h-3.5 w-3.5'} />
            {compact ? opt.compactLabel : opt.label}
          </button>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Confirmation dialog
// ---------------------------------------------------------------------------

function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel,
  onConfirm,
  onCancel,
  destructive,
}: {
  open: boolean
  title: string
  message: string
  confirmLabel: string
  onConfirm: () => void
  onCancel: () => void
  destructive?: boolean
}) {
  if (!open) return null

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center backdrop-blur-sm" style={{ backgroundColor: 'rgba(0, 0, 0, 0.6)' }}>
      <div
        className="card-sentinel rounded-xl shadow-2xl w-full max-w-md p-6"
        style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        <div className="flex items-center gap-3 mb-4">
          <div
            className="h-10 w-10 rounded-full flex items-center justify-center"
            style={{ backgroundColor: destructive ? 'var(--crit-bg)' : 'var(--high-bg)' }}
          >
            <AlertTriangle className="h-5 w-5" style={{ color: destructive ? 'var(--crit)' : 'var(--high)' }} />
          </div>
          <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>{title}</h3>
        </div>
        <p className="text-sm mb-6" style={{ color: 'var(--fg-2)' }}>{message}</p>
        <div className="flex justify-end gap-3">
          <button
            type="button"
            onClick={onCancel}
            className="btn-sentinel btn-sentinel-secondary"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className={cn('btn-sentinel', destructive ? 'btn-sentinel-danger' : 'btn-sentinel-primary')}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Policy Editor Modal
// ---------------------------------------------------------------------------

function defaultCategorySettings(): CategorySetting[] {
  return THREAT_CATEGORIES.map((cat) => ({
    category: cat.id,
    aggressiveness: 'moderate' as AggressivenessLevel,
    mode: 'detect_and_prevent' as ResponseMode,
  }))
}

function emptyPolicy(): Omit<PreventionPolicy, 'id' | 'created_at' | 'updated_at'> {
  return {
    name: '',
    description: '',
    is_default: false,
    mode: 'detect_and_prevent',
    aggressiveness: 'moderate',
    category_settings: defaultCategorySettings(),
    exclusions: { paths: [], processes: [], hashes: [], users: [] },
    network_containment: { allow_dns: true, allowed_ips: [] },
    assigned_agents: [],
  }
}

function PolicyEditor({
  policy,
  onSave,
  onClose,
  saving,
}: {
  policy: PreventionPolicy | null // null = create mode
  onSave: (data: Omit<PreventionPolicy, 'id' | 'created_at' | 'updated_at'>) => void
  onClose: () => void
  saving: boolean
}) {
  const isCreate = policy === null
  const [data, setData] = useState(() => {
    if (policy) {
      return {
        name: policy.name,
        description: policy.description,
        is_default: policy.is_default,
        mode: policy.mode,
        aggressiveness: policy.aggressiveness,
        category_settings: policy.category_settings.length > 0 ? policy.category_settings : defaultCategorySettings(),
        exclusions: policy.exclusions ?? { paths: [], processes: [], hashes: [], users: [] },
        network_containment: policy.network_containment ?? { allow_dns: true, allowed_ips: [] },
        assigned_agents: policy.assigned_agents ?? [],
      }
    }
    return emptyPolicy()
  })

  const [activeSection, setActiveSection] = useState<'basic' | 'categories' | 'exclusions' | 'network' | 'agents'>('basic')

  const updateCategorySetting = (categoryId: string, field: 'aggressiveness' | 'mode', value: AggressivenessLevel | ResponseMode) => {
    setData((prev) => ({
      ...prev,
      category_settings: prev.category_settings.map((cs) =>
        cs.category === categoryId ? { ...cs, [field]: value } : cs
      ),
    }))
  }

  const applyGlobalToAll = () => {
    setData((prev) => ({
      ...prev,
      category_settings: prev.category_settings.map((cs) => ({
        ...cs,
        aggressiveness: prev.aggressiveness,
        mode: prev.mode,
      })),
    }))
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSave(data)
  }

  const sections = [
    { id: 'basic' as const, label: 'Basic Info', icon: Settings },
    { id: 'categories' as const, label: 'Category Settings', icon: Shield },
    { id: 'exclusions' as const, label: 'Exclusions', icon: ShieldOff },
    { id: 'network' as const, label: 'Network', icon: Globe },
    { id: 'agents' as const, label: 'Agents', icon: Users },
  ]

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto py-8 backdrop-blur-sm" style={{ backgroundColor: 'rgba(0, 0, 0, 0.6)' }}>
      <div
        className="card-sentinel rounded-xl shadow-2xl w-full max-w-5xl my-auto"
        style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6" style={{ borderBottom: '1px solid var(--hairline)' }}>
          <div>
            <h2 className="text-xl font-semibold" style={{ color: 'var(--fg)' }}>
              {isCreate ? 'Create Prevention Policy' : 'Edit Prevention Policy'}
            </h2>
            <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
              Configure detection sensitivity and response behavior
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={saving}
            className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Section tabs */}
        <div className="flex px-6" style={{ borderBottom: '1px solid var(--hairline)' }}>
          {sections.map((section) => (
            <button
              key={section.id}
              type="button"
              onClick={() => setActiveSection(section.id)}
              className="flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors -mb-px"
              style={{
                color: activeSection === section.id ? 'var(--emerald-400)' : 'var(--muted)',
                borderBottom: activeSection === section.id ? '2px solid var(--emerald-400)' : '2px solid transparent',
              }}
              onMouseEnter={(e) => {
                if (activeSection !== section.id) {
                  e.currentTarget.style.color = 'var(--fg-2)'
                }
              }}
              onMouseLeave={(e) => {
                if (activeSection !== section.id) {
                  e.currentTarget.style.color = 'var(--muted)'
                }
              }}
            >
              <section.icon className="h-4 w-4" />
              {section.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <form onSubmit={handleSubmit}>
          <div className="p-6 min-h-[400px]">
            {/* Basic Info */}
            {activeSection === 'basic' && (
              <div className="space-y-6 max-w-2xl">
                <div>
                  <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg-2)' }}>
                    Policy Name
                  </label>
                  <input
                    type="text"
                    value={data.name}
                    onChange={(e) => setData((prev) => ({ ...prev, name: e.target.value }))}
                    placeholder="e.g., Standard Workstation Policy"
                    disabled={saving}
                    required
                    className="input-sentinel"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg-2)' }}>
                    Description
                  </label>
                  <textarea
                    value={data.description}
                    onChange={(e) => setData((prev) => ({ ...prev, description: e.target.value }))}
                    placeholder="Describe the purpose and scope of this policy..."
                    disabled={saving}
                    rows={3}
                    className="input-sentinel resize-none"
                    style={{ height: 'auto' }}
                  />
                </div>

                <div className="pt-6" style={{ borderTop: '1px solid var(--hairline)' }}>
                  <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--fg)' }}>Global Response Mode</h3>
                  <ModeToggle
                    value={data.mode}
                    onChange={(v) => setData((prev) => ({ ...prev, mode: v }))}
                    disabled={saving}
                  />
                </div>

                <div className="pt-6" style={{ borderTop: '1px solid var(--hairline)' }}>
                  <h3 className="text-sm font-semibold mb-1" style={{ color: 'var(--fg)' }}>Global Aggressiveness</h3>
                  <p className="text-xs mb-4" style={{ color: 'var(--muted)' }}>
                    Sets the default detection sensitivity. Individual categories can override this.
                  </p>
                  <AggressivenessSelector
                    value={data.aggressiveness}
                    onChange={(v) => setData((prev) => ({ ...prev, aggressiveness: v }))}
                    disabled={saving}
                  />
                  <div className="mt-4">
                    <AggressivenessDots level={data.aggressiveness} />
                  </div>
                </div>
              </div>
            )}

            {/* Per-category settings */}
            {activeSection === 'categories' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold" style={{ color: 'var(--fg)' }}>Per-Category Configuration</h3>
                    <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                      Override global settings for individual threat categories
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={applyGlobalToAll}
                    disabled={saving}
                    className="btn-sentinel btn-sentinel-secondary btn-sentinel-sm"
                  >
                    <Copy className="h-3 w-3" />
                    Apply Global to All
                  </button>
                </div>

                <div
                  className="card-sentinel-inset rounded-xl overflow-hidden"
                  style={{ backgroundColor: 'var(--bg-2)', border: '1px solid var(--hairline)' }}
                >
                  {/* Table header */}
                  <div
                    className="grid grid-cols-[minmax(200px,1fr)_auto_auto_auto] gap-4 px-5 py-3"
                    style={{ backgroundColor: 'var(--bg)', borderBottom: '1px solid var(--hairline)' }}
                  >
                    <div className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Category</div>
                    <div className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Aggressiveness</div>
                    <div className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Mode</div>
                    <div className="text-xs font-semibold uppercase tracking-wider w-[120px]" style={{ color: 'var(--subtle)' }}>Thresholds</div>
                  </div>

                  {/* Rows */}
                  {data.category_settings.map((cs) => {
                    const catDef = THREAT_CATEGORIES.find((c) => c.id === cs.category)
                    if (!catDef) return null
                    const CatIcon = catDef.icon
                    const styles = AGGRESSIVENESS_STYLES[cs.aggressiveness]
                    return (
                      <div
                        key={cs.category}
                        className="grid grid-cols-[minmax(200px,1fr)_auto_auto_auto] gap-4 items-center px-5 py-3 transition-colors"
                        style={{ borderBottom: '1px solid var(--hairline)' }}
                        onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = 'var(--surface)' }}
                        onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = 'transparent' }}
                      >
                        <div className="flex items-center gap-3">
                          <div
                            className="h-8 w-8 rounded-lg flex items-center justify-center"
                            style={{ backgroundColor: styles.bg }}
                          >
                            <CatIcon className="h-4 w-4" style={{ color: styles.text }} />
                          </div>
                          <div>
                            <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{catDef.label}</span>
                            <div className="mt-0.5">
                              <AggressivenessDots level={cs.aggressiveness} />
                            </div>
                          </div>
                        </div>
                        <AggressivenessSelector
                          value={cs.aggressiveness}
                          onChange={(v) => updateCategorySetting(cs.category, 'aggressiveness', v)}
                          disabled={saving}
                          compact
                        />
                        <ModeToggle
                          value={cs.mode}
                          onChange={(v) => updateCategorySetting(cs.category, 'mode', v)}
                          disabled={saving}
                          compact
                        />
                        <div className="w-[120px]">
                          <ThresholdIndicator level={cs.aggressiveness} />
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {/* Exclusions */}
            {activeSection === 'exclusions' && (
              <div className="space-y-6 max-w-3xl">
                <div>
                  <h3 className="text-sm font-semibold mb-1" style={{ color: 'var(--fg)' }}>Detection Exclusions</h3>
                  <p className="text-xs mb-6" style={{ color: 'var(--muted)' }}>
                    Items matching these exclusions will bypass detection. Use with caution.
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg-2)' }}>
                    Excluded Paths
                  </label>
                  <TagInput
                    tags={data.exclusions.paths}
                    onChange={(tags) => setData((prev) => ({ ...prev, exclusions: { ...prev.exclusions, paths: tags } }))}
                    placeholder="Type a path and press Enter (e.g., C:\Program Files\...)"
                    disabled={saving}
                  />
                  <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>File or directory paths to exclude from scanning</p>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg-2)' }}>
                    Excluded Processes
                  </label>
                  <TagInput
                    tags={data.exclusions.processes}
                    onChange={(tags) => setData((prev) => ({ ...prev, exclusions: { ...prev.exclusions, processes: tags } }))}
                    placeholder="Type a process name and press Enter (e.g., svchost.exe)"
                    disabled={saving}
                  />
                  <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>Process names to exclude from behavioral analysis</p>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg-2)' }}>
                    Excluded Hashes
                  </label>
                  <TagInput
                    tags={data.exclusions.hashes}
                    onChange={(tags) => setData((prev) => ({ ...prev, exclusions: { ...prev.exclusions, hashes: tags } }))}
                    placeholder="Type a SHA-256 hash and press Enter"
                    disabled={saving}
                  />
                  <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>SHA-256 file hashes to whitelist</p>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg-2)' }}>
                    Excluded Users
                  </label>
                  <TagInput
                    tags={data.exclusions.users}
                    onChange={(tags) => setData((prev) => ({ ...prev, exclusions: { ...prev.exclusions, users: tags } }))}
                    placeholder="Type a username and press Enter (e.g., DOMAIN\admin)"
                    disabled={saving}
                  />
                  <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>User accounts to exclude from detection</p>
                </div>

                {(data.exclusions.paths.length > 0 || data.exclusions.processes.length > 0 || data.exclusions.hashes.length > 0 || data.exclusions.users.length > 0) && (
                  <div
                    className="p-4 rounded-lg"
                    style={{
                      backgroundColor: 'var(--high-bg)',
                      border: '1px solid var(--high)',
                    }}
                  >
                    <div className="flex items-start gap-3">
                      <AlertTriangle className="h-5 w-5 flex-shrink-0 mt-0.5" style={{ color: 'var(--high)' }} />
                      <div>
                        <p className="text-sm font-medium" style={{ color: 'var(--high)' }}>Exclusions reduce protection</p>
                        <p className="text-xs mt-1" style={{ color: 'var(--muted)' }}>
                          Excluded items will not be analyzed by the detection engine. Attackers may exploit exclusions to evade detection. Review exclusions regularly.
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Network Containment */}
            {activeSection === 'network' && (
              <div className="space-y-6 max-w-3xl">
                <div>
                  <h3 className="text-sm font-semibold mb-1" style={{ color: 'var(--fg)' }}>Network Containment Policy</h3>
                  <p className="text-xs mb-6" style={{ color: 'var(--muted)' }}>
                    Configure rules for host isolation. When a host is isolated, all traffic is blocked except for these allowances.
                  </p>
                </div>

                <div
                  className="flex items-center gap-3 p-4 rounded-lg"
                  style={{ backgroundColor: 'var(--surface-2)', border: '1px solid var(--border)' }}
                >
                  <div className="flex-1">
                    <label className="text-sm font-medium" style={{ color: 'var(--fg-2)' }}>Allow DNS Traffic (UDP 53)</label>
                    <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>
                      Always allow DNS resolution even when isolated. Required for agent communication.
                    </p>
                  </div>
                  <div className="flex items-center">
                    <button
                      type="button"
                      role="switch"
                      aria-checked={data.network_containment.allow_dns}
                      onClick={() => setData(prev => ({
                        ...prev,
                        network_containment: {
                          ...prev.network_containment,
                          allow_dns: !prev.network_containment.allow_dns
                        }
                      }))}
                      disabled={saving}
                      className="relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full transition-colors duration-200 ease-in-out focus:outline-none focus-visible:ring-2 disabled:opacity-50"
                      style={{
                        backgroundColor: data.network_containment.allow_dns ? 'var(--emerald-500)' : 'var(--surface-3)',
                        border: `2px solid ${data.network_containment.allow_dns ? 'var(--emerald-500)' : 'var(--border)'}`,
                      }}
                    >
                      <span
                        aria-hidden="true"
                        className="pointer-events-none inline-block h-5 w-5 transform rounded-full shadow ring-0 transition duration-200 ease-in-out"
                        style={{
                          backgroundColor: 'white',
                          transform: data.network_containment.allow_dns ? 'translateX(20px)' : 'translateX(0)',
                        }}
                      />
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2" style={{ color: 'var(--fg-2)' }}>
                    Allowed IP Addresses
                  </label>
                  <TagInput
                    tags={data.network_containment.allowed_ips}
                    onChange={(tags) => setData((prev) => ({
                      ...prev,
                      network_containment: {
                        ...prev.network_containment,
                        allowed_ips: tags
                      }
                    }))}
                    placeholder="Type an IP address (e.g., 10.0.0.5) and press Enter"
                    disabled={saving}
                  />
                  <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>
                    IP addresses that can communicate with the host even during isolation (e.g., Management Server, Domain Controllers)
                  </p>
                </div>
              </div>
            )}

            {/* Agent assignment */}
            {activeSection === 'agents' && (
              <div className="space-y-4 max-w-2xl">
                <div>
                  <h3 className="text-sm font-semibold mb-1" style={{ color: 'var(--fg)' }}>Assigned Agents</h3>
                  <p className="text-xs mb-4" style={{ color: 'var(--muted)' }}>
                    Agents using this prevention policy. Agents can only be assigned to one policy at a time.
                  </p>
                </div>

                {data.assigned_agents.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <div
                      className="h-12 w-12 rounded-full flex items-center justify-center mb-4"
                      style={{ backgroundColor: 'var(--surface-2)' }}
                    >
                      <Users className="h-6 w-6" style={{ color: 'var(--muted)' }} />
                    </div>
                    <p className="text-sm" style={{ color: 'var(--muted)' }}>No agents assigned to this policy</p>
                    <p className="text-xs mt-1" style={{ color: 'var(--subtle)' }}>
                      Agents can be assigned from the Agents page or via the API
                    </p>
                  </div>
                ) : (
                  <div
                    className="card-sentinel-inset rounded-xl divide-y"
                    style={{ backgroundColor: 'var(--bg-2)', border: '1px solid var(--hairline)', borderColor: 'var(--hairline)' }}
                  >
                    {data.assigned_agents.map((agent) => (
                      <div key={agent.id} className="flex items-center justify-between px-4 py-3" style={{ borderColor: 'var(--hairline)' }}>
                        <div className="flex items-center gap-3">
                          <div
                            className="h-8 w-8 rounded-lg flex items-center justify-center"
                            style={{ backgroundColor: 'var(--surface-2)' }}
                          >
                            <Users className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                          </div>
                          <div>
                            <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{agent.hostname}</span>
                            <span className="text-xs ml-2" style={{ color: 'var(--muted)' }}>{agent.os}</span>
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() =>
                            setData((prev) => ({
                              ...prev,
                              assigned_agents: prev.assigned_agents.filter((a) => a.id !== agent.id),
                            }))
                          }
                          disabled={saving}
                          className="transition-colors disabled:opacity-50"
                          style={{ color: 'var(--muted)' }}
                          onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--crit)' }}
                          onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--muted)' }}
                          title="Remove agent"
                        >
                          <X className="h-4 w-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end gap-3 px-6 py-4" style={{ borderTop: '1px solid var(--hairline)' }}>
            <button
              type="button"
              onClick={onClose}
              disabled={saving}
              className="btn-sentinel btn-sentinel-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !data.name.trim()}
              className="btn-sentinel btn-sentinel-primary"
            >
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              {saving ? 'Saving...' : isCreate ? 'Create Policy' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Policy Card
// ---------------------------------------------------------------------------

function PolicyCard({
  policy,
  onEdit,
  onDelete,
  onDuplicate,
}: {
  policy: PreventionPolicy
  onEdit: () => void
  onDelete: () => void
  onDuplicate: () => void
}) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div
      className="card-sentinel card-sentinel-interactive rounded-xl transition-colors"
      style={{
        backgroundColor: 'var(--surface)',
        border: '1px solid var(--border)',
      }}
    >
      {/* Card header */}
      <div className="p-5">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3 min-w-0">
            <div
              className="h-10 w-10 rounded-lg flex items-center justify-center flex-shrink-0"
              style={{
                backgroundColor: policy.mode === 'detect_and_prevent' ? 'var(--emerald-glow)' : 'var(--high-bg)',
              }}
            >
              {policy.mode === 'detect_and_prevent' ? (
                <ShieldCheck className="h-5 w-5" style={{ color: 'var(--emerald-400)' }} />
              ) : (
                <ShieldAlert className="h-5 w-5" style={{ color: 'var(--high)' }} />
              )}
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <h3 className="text-base font-semibold truncate" style={{ color: 'var(--fg)' }}>{policy.name}</h3>
                {policy.is_default && (
                  <span
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider"
                    style={{
                      backgroundColor: 'var(--emerald-glow)',
                      color: 'var(--emerald-400)',
                      border: '1px solid var(--emerald-500)',
                    }}
                  >
                    <Star className="h-3 w-3" />
                    Default
                  </span>
                )}
              </div>
              {policy.description && (
                <p className="text-sm mt-0.5 line-clamp-2" style={{ color: 'var(--muted)' }}>{policy.description}</p>
              )}
            </div>
          </div>

          {/* Actions dropdown */}
          <div className="flex items-center gap-1 flex-shrink-0 ml-3">
            <button
              type="button"
              onClick={onEdit}
              className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon btn-sentinel-sm"
              title="Edit policy"
            >
              <Edit className="h-4 w-4" />
            </button>
            <button
              type="button"
              onClick={onDuplicate}
              className="btn-sentinel btn-sentinel-ghost btn-sentinel-icon btn-sentinel-sm"
              title="Duplicate policy"
            >
              <Copy className="h-4 w-4" />
            </button>
            {!policy.is_default && (
              <button
                type="button"
                onClick={onDelete}
                className="p-2 rounded-lg transition-colors"
                style={{ color: 'var(--muted)' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = 'var(--crit)'
                  e.currentTarget.style.backgroundColor = 'var(--crit-bg)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = 'var(--muted)'
                  e.currentTarget.style.backgroundColor = 'transparent'
                }}
                title="Delete policy"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>

        {/* Badges row */}
        <div className="flex flex-wrap items-center gap-2 mb-4">
          <ModeBadge mode={policy.mode} />
          <AggressivenessBadge level={policy.aggressiveness} />
          <span
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium"
            style={{
              color: 'var(--fg-2)',
              backgroundColor: 'var(--surface-2)',
              border: '1px solid var(--border)',
            }}
          >
            <Users className="h-3 w-3" />
            {policy.assigned_agents?.length ?? 0} agent{(policy.assigned_agents?.length ?? 0) !== 1 ? 's' : ''}
          </span>
        </div>

        {/* Aggressiveness dots */}
        <div className="flex items-center gap-3">
          <AggressivenessDots level={policy.aggressiveness} />
          <ThresholdIndicator level={policy.aggressiveness} />
        </div>
      </div>

      {/* Expandable category detail */}
      <div style={{ borderTop: '1px solid var(--hairline)' }}>
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="flex items-center justify-between w-full px-5 py-2.5 text-xs font-medium transition-colors"
          style={{ color: 'var(--muted)' }}
          onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--fg-2)' }}
          onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--muted)' }}
        >
          <span>Category settings ({policy.category_settings?.length ?? 0})</span>
          {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
        </button>

        {expanded && policy.category_settings && (
          <div className="px-5 pb-4 space-y-2">
            {policy.category_settings.map((cs) => {
              const catDef = THREAT_CATEGORIES.find((c) => c.id === cs.category)
              if (!catDef) return null
              const CatIcon = catDef.icon
              const styles = AGGRESSIVENESS_STYLES[cs.aggressiveness]
              return (
                <div key={cs.category} className="flex items-center justify-between py-1.5">
                  <div className="flex items-center gap-2.5">
                    <CatIcon className="h-3.5 w-3.5" style={{ color: styles.text }} />
                    <span className="text-xs" style={{ color: 'var(--fg-2)' }}>{catDef.label}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <AggressivenessDots level={cs.aggressiveness} />
                    <span
                      className="text-[10px] font-medium px-1.5 py-0.5 rounded"
                      style={{
                        color: cs.mode === 'detect_and_prevent' ? 'var(--emerald-400)' : 'var(--high)',
                        backgroundColor: cs.mode === 'detect_and_prevent' ? 'var(--emerald-glow)' : 'var(--high-bg)',
                      }}
                    >
                      {cs.mode === 'detect_and_prevent' ? 'PREVENT' : 'DETECT'}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Page Component
// ---------------------------------------------------------------------------

export default function PreventionPolicies() {
  const [policies, setPolicies] = useState<PreventionPolicy[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [editorOpen, setEditorOpen] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<PreventionPolicy | null>(null)
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<PreventionPolicy | null>(null)
  const { toasts, addToast, dismissToast } = useToast()

  const fetchPolicies = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await apiFetch<{ data: PreventionPolicy[] }>(API_BASE)
      setPolicies(data?.data ?? [])
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load prevention policies'
      setError(message)
      addToast('error', message)
    } finally {
      setLoading(false)
    }
  }, [addToast])

  useEffect(() => {
    fetchPolicies()
  }, [fetchPolicies])

  const handleCreate = () => {
    setEditingPolicy(null)
    setEditorOpen(true)
  }

  const handleEdit = (policy: PreventionPolicy) => {
    setEditingPolicy(policy)
    setEditorOpen(true)
  }

  const handleDuplicate = (policy: PreventionPolicy) => {
    setEditingPolicy({
      ...policy,
      id: '',
      name: `${policy.name} (Copy)`,
      is_default: false,
      assigned_agents: [],
    })
    setEditorOpen(true)
  }

  const handleSave = async (data: Omit<PreventionPolicy, 'id' | 'created_at' | 'updated_at'>) => {
    setSaving(true)
    try {
      if (editingPolicy && editingPolicy.id) {
        await apiFetch(`${API_BASE}/${editingPolicy.id}`, {
          method: 'PUT',
          body: JSON.stringify({ policy: data }),
        })
        addToast('success', `Policy "${data.name}" updated successfully.`)
      } else {
        await apiFetch(API_BASE, {
          method: 'POST',
          body: JSON.stringify({ policy: data }),
        })
        addToast('success', `Policy "${data.name}" created successfully.`)
      }
      setEditorOpen(false)
      setEditingPolicy(null)
      fetchPolicies()
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to save policy.')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await apiFetch(`${API_BASE}/${deleteTarget.id}`, { method: 'DELETE' })
      addToast('success', `Policy "${deleteTarget.name}" deleted.`)
      setDeleteTarget(null)
      fetchPolicies()
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to delete policy.')
      setDeleteTarget(null)
    }
  }

  return (
    <MainLayout title="Prevention Policies">
      <Head title="Prevention Policies - Tamandua EDR" />
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Page header */}
      <div className="flex items-start justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>Prevention Policies</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--muted)' }}>
            Configure detection sensitivity and automated response for each threat category
          </p>
        </div>
        <button
          type="button"
          onClick={handleCreate}
          className="btn-sentinel btn-sentinel-primary"
        >
          <Plus className="h-4 w-4" />
          Create Policy
        </button>
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex flex-col items-center justify-center py-24">
          <Loader2 className="h-8 w-8 animate-spin mb-4" style={{ color: 'var(--emerald-400)' }} />
          <p className="text-sm" style={{ color: 'var(--muted)' }}>Loading prevention policies...</p>
        </div>
      ) : error ? (
        <div className="flex flex-col items-center justify-center py-24">
          <div
            className="h-12 w-12 rounded-full flex items-center justify-center mb-4"
            style={{ backgroundColor: 'var(--crit-bg)' }}
          >
            <XCircle className="h-6 w-6" style={{ color: 'var(--crit)' }} />
          </div>
          <p className="text-sm mb-4" style={{ color: 'var(--crit)' }}>{error}</p>
          <button
            type="button"
            onClick={fetchPolicies}
            className="flex items-center gap-2 text-sm transition-colors"
            style={{ color: 'var(--emerald-400)' }}
            onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--emerald-200)' }}
            onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--emerald-400)' }}
          >
            Retry
          </button>
        </div>
      ) : policies.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-24">
          <div
            className="h-16 w-16 rounded-full flex items-center justify-center mb-6"
            style={{ backgroundColor: 'var(--surface-2)' }}
          >
            <Shield className="h-8 w-8" style={{ color: 'var(--muted)' }} />
          </div>
          <h3 className="text-lg font-semibold mb-2" style={{ color: 'var(--fg)' }}>No prevention policies</h3>
          <p className="text-sm mb-6 text-center max-w-md" style={{ color: 'var(--muted)' }}>
            Create your first prevention policy to configure detection sensitivity and automated response actions for your agents.
          </p>
          <button
            type="button"
            onClick={handleCreate}
            className="btn-sentinel btn-sentinel-primary"
          >
            <Plus className="h-4 w-4" />
            Create Your First Policy
          </button>
        </div>
      ) : (
        <>
          {/* Summary bar */}
          <div className="grid grid-cols-4 gap-4 mb-6">
            <div
              className="card-sentinel rounded-xl p-4"
              style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
            >
              <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>{policies.length}</div>
              <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Total Policies</div>
            </div>
            <div
              className="card-sentinel rounded-xl p-4"
              style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
            >
              <div className="text-2xl font-bold" style={{ color: 'var(--emerald-400)' }}>
                {policies.filter((p) => p.mode === 'detect_and_prevent').length}
              </div>
              <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Detect & Prevent</div>
            </div>
            <div
              className="card-sentinel rounded-xl p-4"
              style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
            >
              <div className="text-2xl font-bold" style={{ color: 'var(--high)' }}>
                {policies.filter((p) => p.mode === 'detect_only').length}
              </div>
              <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Detect Only</div>
            </div>
            <div
              className="card-sentinel rounded-xl p-4"
              style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border)' }}
            >
              <div className="text-2xl font-bold" style={{ color: 'var(--fg)' }}>
                {policies.reduce((sum, p) => sum + (p.assigned_agents?.length ?? 0), 0)}
              </div>
              <div className="text-xs mt-1" style={{ color: 'var(--muted)' }}>Assigned Agents</div>
            </div>
          </div>

          {/* Policy grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
            {policies.map((policy) => (
              <PolicyCard
                key={policy.id}
                policy={policy}
                onEdit={() => handleEdit(policy)}
                onDelete={() => setDeleteTarget(policy)}
                onDuplicate={() => handleDuplicate(policy)}
              />
            ))}
          </div>
        </>
      )}

      {/* Editor modal */}
      {editorOpen && (
        <PolicyEditor
          policy={editingPolicy}
          onSave={handleSave}
          onClose={() => {
            setEditorOpen(false)
            setEditingPolicy(null)
          }}
          saving={saving}
        />
      )}

      {/* Delete confirmation */}
      <ConfirmDialog
        open={deleteTarget !== null}
        title="Delete Policy"
        message={`Are you sure you want to delete "${deleteTarget?.name}"? This action cannot be undone. Any agents assigned to this policy will be unassigned.`}
        confirmLabel="Delete Policy"
        onConfirm={handleDelete}
        onCancel={() => setDeleteTarget(null)}
        destructive
      />
    </MainLayout>
  )
}
