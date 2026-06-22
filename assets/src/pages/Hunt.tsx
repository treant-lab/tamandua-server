import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Search, Play, Clock, FileSearch, Code, Save, AlertCircle,
  Plus, X, ChevronDown, Filter, Cpu, Globe, File,
  Server, Settings, Share2, Eye, Trash2, BookOpen, Zap,
  FolderOpen, ChevronRight, Copy, CornerDownRight, AlertTriangle,
  CheckCircle2, Layers, Terminal, HelpCircle, BarChart3
} from 'lucide-react'
import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { cn, safeRandomUUID } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { ExportDropdown } from '@/components/ExportDropdown'
import { Checkbox, Select, SelectItem } from '@/components/ui/baseui'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface HuntResult {
  id: string
  agent_id: string
  agent_hostname: string
  event_type: string
  timestamp: string
  payload: Record<string, any>
  pid?: number
  process_name?: string
  sha256?: string
  remote_ip?: string
  domain?: string
  path?: string
}

interface QueryCondition {
  id: string
  field: string
  operator: string
  value: string
}

/** A group is either a single condition or a set of children joined by a connector. */
interface ConditionGroup {
  id: string
  connector: 'AND' | 'OR'
  children: (QueryCondition | ConditionGroup)[]
}

function isGroup(node: QueryCondition | ConditionGroup): node is ConditionGroup {
  return 'children' in node
}

interface SavedQuery {
  id?: string
  name: string
  query: string
  description?: string
  category?: string
  type?: string
  tags?: string[]
  is_template?: boolean
  is_public?: boolean
  use_count?: number
  created_at?: string
}

interface QueryHistoryEntry {
  id: string
  query: string
  type: string
  result_count?: number
  execution_time_ms?: number
  executed_at: string
}

// TQL Schema types
interface TQLSchema {
  version: string
  name: string
  description: string
  table_sources: string[]
  operators: Record<string, string>
  aggregation_functions: string[]
  scalar_functions: string[]
  keywords: string[]
  field_mappings: Record<string, string[]>
  syntax: {
    basic_structure: string
    operators: { name: string; syntax: string; description: string }[]
    comparison_operators: { op: string; description: string }[]
    logical_operators: string[]
  }
  examples: { name: string; query: string }[]
}

interface TQLValidationResult {
  valid: boolean
  ast?: any
  errors?: { message: string; line?: number; column?: number }[]
  message: string
}

interface HuntPageProps {
  savedQueries?: SavedQuery[]
  initialQuery?: string
}

// ---------------------------------------------------------------------------
// Validation types
// ---------------------------------------------------------------------------

interface ValidationError {
  message: string
  position?: number
  length?: number
}

// ---------------------------------------------------------------------------
// Field & operator definitions (defaults, will be overridden by API)
// ---------------------------------------------------------------------------

interface FieldDefinition {
  field: string
  label: string
  type: string
  description?: string
}

interface Operator {
  value: string
  label: string
  symbol: string
  types: string[]
}

interface QueryTemplate {
  id?: string
  name: string
  query: string
  description: string
  category?: string
  use_count?: number
}

// Default field definitions (fallback if API fails)
const DEFAULT_FIELD_DEFINITIONS: Record<string, FieldDefinition[]> = {
  process: [
    { field: 'process.name', label: 'Process Name', type: 'string' },
    { field: 'process.path', label: 'Process Path', type: 'string' },
    { field: 'process.cmdline', label: 'Command Line', type: 'string' },
    { field: 'process.pid', label: 'Process ID', type: 'number' },
    { field: 'process.ppid', label: 'Parent PID', type: 'number' },
    { field: 'process.user', label: 'User', type: 'string' },
    { field: 'process.sha256', label: 'SHA256 Hash', type: 'string' },
    { field: 'process.is_elevated', label: 'Is Elevated', type: 'boolean' },
    { field: 'process.parent', label: 'Parent Process', type: 'string' },
  ],
  network: [
    { field: 'network.remote_ip', label: 'Remote IP', type: 'string' },
    { field: 'network.remote_port', label: 'Remote Port', type: 'number' },
    { field: 'network.local_port', label: 'Local Port', type: 'number' },
    { field: 'network.protocol', label: 'Protocol', type: 'string' },
    { field: 'network.direction', label: 'Direction', type: 'string' },
    { field: 'network.bytes_sent', label: 'Bytes Sent', type: 'number' },
    { field: 'network.bytes_recv', label: 'Bytes Received', type: 'number' },
  ],
  file: [
    { field: 'file.path', label: 'File Path', type: 'string' },
    { field: 'file.name', label: 'File Name', type: 'string' },
    { field: 'file.sha256', label: 'SHA256 Hash', type: 'string' },
    { field: 'file.operation', label: 'Operation', type: 'string' },
    { field: 'file.size', label: 'File Size', type: 'number' },
  ],
  dns: [
    { field: 'dns.query', label: 'DNS Query', type: 'string' },
    { field: 'dns.query_type', label: 'Query Type', type: 'string' },
    { field: 'dns.response', label: 'Response', type: 'string' },
  ],
  registry: [
    { field: 'registry.path', label: 'Registry Path', type: 'string' },
    { field: 'registry.key', label: 'Key Name', type: 'string' },
    { field: 'registry.value', label: 'Value', type: 'string' },
    { field: 'registry.operation', label: 'Operation', type: 'string' },
  ],
  general: [
    { field: 'event.type', label: 'Event Type', type: 'string' },
    { field: 'agent.id', label: 'Agent ID', type: 'string' },
    { field: 'agent.hostname', label: 'Hostname', type: 'string' },
  ],
}

// Default operators (fallback if API fails)
const DEFAULT_OPERATORS: Operator[] = [
  { value: ':', label: 'equals', symbol: '=', types: ['string', 'number', 'boolean'] },
  { value: ':*', label: 'contains', symbol: 'contains', types: ['string'] },
  { value: ':~', label: 'regex', symbol: 'regex', types: ['string'] },
  { value: ':^', label: 'starts with', symbol: 'startsWith', types: ['string'] },
  { value: ':$', label: 'ends with', symbol: 'endsWith', types: ['string'] },
  { value: ':>', label: 'greater than', symbol: '>', types: ['number'] },
  { value: ':<', label: 'less than', symbol: '<', types: ['number'] },
  { value: ':>=', label: 'greater or equal', symbol: '>=', types: ['number'] },
  { value: ':<=', label: 'less or equal', symbol: '<=', types: ['number'] },
  { value: ':!', label: 'not equals', symbol: '!=', types: ['string', 'number', 'boolean'] },
  { value: ':in', label: 'in list', symbol: 'in', types: ['string', 'number'] },
  { value: ':!in', label: 'not in list', symbol: 'not_in', types: ['string', 'number'] },
]

// Default MITRE categories
const DEFAULT_MITRE_CATEGORIES = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact'
]

// ---------------------------------------------------------------------------
// Query validation
// ---------------------------------------------------------------------------

const KNOWN_OPERATORS_REGEX = /:(>=|<=|!\s*in|in|\*|~|\^|\$|>|<|!)?/

// Common natural language words that indicate user wants NL search
const NL_INDICATOR_WORDS = [
  'find', 'show', 'search', 'get', 'list', 'display', 'hunt', 'look',
  'where', 'when', 'what', 'which', 'how', 'why',
  'last', 'past', 'recent', 'today', 'yesterday', 'week', 'month', 'hours', 'minutes', 'days',
  'all', 'any', 'the', 'with', 'from', 'to', 'in', 'on', 'by', 'for', 'of', 'that', 'this',
  'suspicious', 'malicious', 'encoded', 'obfuscated', 'encrypted',
  'powershell', 'cmd', 'wmic', 'psexec', 'mimikatz', 'cobalt', 'beacon',
  'lateral', 'movement', 'persistence', 'execution', 'exfiltration', 'discovery',
  'credential', 'access', 'privilege', 'escalation', 'injection', 'evasion',
]

function isNaturalLanguageQuery(queryText: string): boolean {
  const trimmed = queryText.trim().toLowerCase()
  if (!trimmed) return false

  const words = trimmed.split(/\s+/)

  // If no colons at all and multiple words, likely NL
  if (!trimmed.includes(':') && words.length > 2) return true

  // Count NL indicator words
  const nlWordCount = words.filter(w => NL_INDICATOR_WORDS.includes(w)).length

  // If more than half the words are NL indicators, it's NL
  if (nlWordCount >= words.length * 0.4) return true

  // If starts with common NL phrases
  if (/^(find|show|search|get|list|hunt|look for|display)/i.test(trimmed)) return true

  return false
}

interface ValidationResult {
  errors: ValidationError[]
  isNaturalLanguage: boolean
}

function validateQuery(queryText: string): ValidationResult {
  const errors: ValidationError[] = []
  const trimmed = queryText.trim()
  if (!trimmed) return { errors, isNaturalLanguage: false }

  // Check if this looks like natural language
  const isNL = isNaturalLanguageQuery(trimmed)
  if (isNL) {
    return {
      errors: [{
        message: 'This looks like a natural language query. Use the NL Hunt feature for AI-powered search, or use field:value syntax here (e.g., process.name:powershell.exe)'
      }],
      isNaturalLanguage: true
    }
  }

  // Check balanced parentheses
  let depth = 0
  for (let i = 0; i < trimmed.length; i++) {
    if (trimmed[i] === '(') depth++
    if (trimmed[i] === ')') depth--
    if (depth < 0) {
      errors.push({ message: 'Unmatched closing parenthesis', position: i, length: 1 })
      break
    }
  }
  if (depth > 0) {
    errors.push({ message: `${depth} unclosed parenthesis(es)` })
  }

  // Tokenise: split on whitespace but respect parentheses
  // We validate individual "field:value" tokens
  const stripped = trimmed.replace(/\(|\)/g, ' ')
  const tokens = stripped.split(/\s+/).filter(Boolean)

  let expectConnector = false
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]
    const upper = token.toUpperCase()

    if (upper === 'AND' || upper === 'OR' || upper === 'NOT') {
      if (!expectConnector && upper !== 'NOT') {
        errors.push({ message: `Unexpected connector "${token}" without preceding condition` })
      }
      expectConnector = false
      continue
    }

    // Should be a field:operator:value expression
    const colonIndex = token.indexOf(':')
    if (colonIndex === -1) {
      errors.push({ message: `"${token}" is not a valid condition. Expected format: field:value` })
      expectConnector = true
      continue
    }

    const fieldPart = token.substring(0, colonIndex)
    if (!fieldPart) {
      errors.push({ message: `Missing field name before ":" in "${token}"` })
    }

    const valuePart = token.substring(colonIndex + 1)
    // Strip operator prefix from value to check emptiness
    const valueAfterOp = valuePart.replace(/^(>=|<=|!\s*in|in|\*|~|\^|\$|>|<|!)/, '')
    // For some operators the value may be part of them, check the raw value
    if (!valuePart) {
      errors.push({ message: `Missing value after ":" in "${token}"` })
    }

    expectConnector = true
  }

  // Check for trailing connector
  if (!expectConnector && tokens.length > 0) {
    const last = tokens[tokens.length - 1].toUpperCase()
    if (last === 'AND' || last === 'OR') {
      errors.push({ message: `Query ends with a trailing "${last}" connector` })
    }
  }

  return { errors, isNaturalLanguage: false }
}

// ---------------------------------------------------------------------------
// Visual builder: serialisation helpers
// ---------------------------------------------------------------------------

function newCondition(): QueryCondition {
  return {
    id: safeRandomUUID(),
    field: '',
    operator: ':',
    value: '',
  }
}

function newGroup(connector: 'AND' | 'OR' = 'AND'): ConditionGroup {
  return {
    id: safeRandomUUID(),
    connector,
    children: [newCondition()],
  }
}

/** Serialise a group tree into a query string. */
function groupToQuery(group: ConditionGroup): string {
  const parts: string[] = []
  for (const child of group.children) {
    if (isGroup(child)) {
      const inner = groupToQuery(child)
      if (inner) parts.push(`(${inner})`)
    } else {
      if (child.field && child.value) {
        parts.push(`${child.field}${child.operator}${child.value}`)
      }
    }
  }
  return parts.join(` ${group.connector} `)
}

/** Parse a flat query string into a top-level ConditionGroup.
 *  This handles simple "a:b AND c:d OR e:f" patterns and parenthesised groups
 *  with one level of nesting.
 */
function parseQueryToGroup(queryText: string): ConditionGroup {
  const root: ConditionGroup = newGroup('AND')
  const trimmed = queryText.trim()
  if (!trimmed) return root

  // Tokenise respecting parentheses
  const tokens: string[] = []
  let current = ''
  let depth = 0
  for (let i = 0; i < trimmed.length; i++) {
    const ch = trimmed[i]
    if (ch === '(') {
      if (depth === 0 && current.trim()) {
        tokens.push(current.trim())
        current = ''
      }
      depth++
      if (depth === 1) {
        current = ''
        continue
      }
    }
    if (ch === ')') {
      depth--
      if (depth === 0) {
        tokens.push('(' + current.trim() + ')')
        current = ''
        continue
      }
    }
    current += ch
  }
  if (current.trim()) tokens.push(current.trim())

  // Now parse tokens into conditions
  // We split each token by spaces to find AND/OR connectors and field:value pairs
  let lastConnector: 'AND' | 'OR' = 'AND'
  const allParts: string[] = []
  for (const t of tokens) {
    if (t.startsWith('(') && t.endsWith(')')) {
      allParts.push(t)
    } else {
      const words = t.split(/\s+/)
      allParts.push(...words)
    }
  }

  const parsedChildren: (QueryCondition | ConditionGroup)[] = []
  let detectedConnector: 'AND' | 'OR' | null = null

  for (let i = 0; i < allParts.length; i++) {
    const part = allParts[i]
    const upper = part.toUpperCase()

    if (upper === 'AND' || upper === 'OR') {
      detectedConnector = upper as 'AND' | 'OR'
      continue
    }

    if (upper === 'NOT') {
      continue // skip NOT for visual builder simplicity
    }

    if (part.startsWith('(') && part.endsWith(')')) {
      // Nested group
      const inner = part.slice(1, -1)
      const subGroup = parseQueryToGroup(inner)
      parsedChildren.push(subGroup)
      continue
    }

    // Parse field:value
    const colonIdx = part.indexOf(':')
    if (colonIdx === -1) continue

    const field = part.substring(0, colonIdx)
    const rest = part.substring(colonIdx)

    // Determine operator
    let matchedOp = ':'
    let value = rest.substring(1)
    // Try matching longest operators first (use default operators for parsing)
    const sortedOps = [...DEFAULT_OPERATORS].sort((a, b) => b.value.length - a.value.length)
    for (const op of sortedOps) {
      if (rest.startsWith(op.value)) {
        matchedOp = op.value
        value = rest.substring(op.value.length)
        break
      }
    }

    parsedChildren.push({
      id: safeRandomUUID(),
      field,
      operator: matchedOp,
      value,
    })
  }

  // Determine root connector from first found connector
  if (detectedConnector) {
    root.connector = detectedConnector
  }

  root.children = parsedChildren.length > 0 ? parsedChildren : [newCondition()]
  return root
}

// ---------------------------------------------------------------------------
// Autocomplete helpers
// ---------------------------------------------------------------------------

/** Given the cursor position in a query string, find the current word being typed. */
function getCurrentWord(text: string, cursorPos: number): { word: string; start: number; end: number } {
  // Walk backwards from cursor to find word start
  let start = cursorPos
  while (start > 0 && !/\s/.test(text[start - 1]) && text[start - 1] !== '(' && text[start - 1] !== ')') {
    start--
  }
  let end = cursorPos
  while (end < text.length && !/\s/.test(text[end]) && text[end] !== '(' && text[end] !== ')') {
    end++
  }
  return { word: text.substring(start, end), start, end }
}

// Flatten default fields for static contexts (unused - see getAutocompleteSuggestionsFromFields in component)
const DEFAULT_ALL_FIELDS = Object.values(DEFAULT_FIELD_DEFINITIONS).flat()

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** A single condition row inside the visual builder. */
function ConditionRow({
  condition,
  onUpdate,
  onRemove,
  canRemove,
  fieldDefinitions,
  allFields,
  operators,
}: {
  condition: QueryCondition
  onUpdate: (updates: Partial<QueryCondition>) => void
  onRemove: () => void
  canRemove: boolean
  fieldDefinitions: Record<string, FieldDefinition[]>
  allFields: FieldDefinition[]
  operators: Operator[]
}) {
  const [showFieldDropdown, setShowFieldDropdown] = useState(false)
  const [fieldSearch, setFieldSearch] = useState('')
  const dropdownRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowFieldDropdown(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const filteredFields = useMemo(() => {
    if (!fieldSearch) return allFields
    const s = fieldSearch.toLowerCase()
    return allFields.filter(f => f.field.toLowerCase().includes(s) || f.label.toLowerCase().includes(s))
  }, [fieldSearch, allFields])

  const selectedFieldDef = allFields.find(f => f.field === condition.field)
  const applicableOps = selectedFieldDef
    ? operators.filter(op => op.types.includes(selectedFieldDef.type))
    : operators

  return (
    <div className="flex items-center gap-2">
      {/* Field selector */}
      <div className="relative flex-1 min-w-0" ref={dropdownRef}>
        <button
          type="button"
          onClick={() => setShowFieldDropdown(!showFieldDropdown)}
          className="w-full flex items-center justify-between rounded px-3 py-1.5 text-sm text-left transition-colors"
          style={{
            background: 'var(--surface-2)',
            border: '1px solid var(--border)',
            color: condition.field ? 'var(--fg)' : 'var(--muted)',
          }}
        >
          <span>
            {condition.field || 'Select field...'}
          </span>
          <ChevronDown className="h-3.5 w-3.5 flex-shrink-0" style={{ color: 'var(--muted)' }} />
        </button>

        {showFieldDropdown && (
          <div
            className="absolute z-50 top-full left-0 mt-1 w-72 rounded-lg shadow-xl max-h-64 overflow-hidden"
            style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
          >
            <div className="p-2" style={{ borderBottom: '1px solid var(--border)' }}>
              <input
                type="text"
                value={fieldSearch}
                onChange={e => setFieldSearch(e.target.value)}
                placeholder="Search fields..."
                className="w-full rounded px-2 py-1 text-sm"
                style={{
                  background: 'var(--bg)',
                  border: '1px solid var(--border)',
                  color: 'var(--fg)',
                }}
                autoFocus
              />
            </div>
            <div className="max-h-48 overflow-y-auto">
              {Object.entries(fieldDefinitions).map(([category, fields]) => {
                const matching = (fields as FieldDefinition[]).filter(f => {
                  if (!fieldSearch) return true
                  const s = fieldSearch.toLowerCase()
                  return f.field.toLowerCase().includes(s) || f.label.toLowerCase().includes(s)
                })
                if (matching.length === 0) return null
                return (
                  <div key={category}>
                    <div
                      className="px-3 py-1 text-xs uppercase font-semibold sticky top-0"
                      style={{ background: 'var(--surface-3)', color: 'var(--muted)' }}
                    >
                      {category}
                    </div>
                    {matching.map(field => (
                      <button
                        key={field.field}
                        type="button"
                        onClick={() => {
                          onUpdate({ field: field.field })
                          setShowFieldDropdown(false)
                          setFieldSearch('')
                        }}
                        className={cn(
                          'w-full flex items-center justify-between px-3 py-1.5 text-sm text-left transition-colors',
                          condition.field === field.field && 'bg-[var(--surface-3)]'
                        )}
                        style={{ color: 'var(--fg)' }}
                        onMouseEnter={(e) => e.currentTarget.style.background = 'var(--surface-3)'}
                        onMouseLeave={(e) => e.currentTarget.style.background = condition.field === field.field ? 'var(--surface-3)' : 'transparent'}
                      >
                        <span>{field.label}</span>
                        <span className="text-xs font-mono" style={{ color: 'var(--muted)' }}>{field.field}</span>
                      </button>
                    ))}
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Operator */}
      <div className="w-36 flex-shrink-0">
        <Select
          value={condition.operator}
          onValueChange={(v) => onUpdate({ operator: v })}
          placeholder="Operator"
          fullWidth
        >
          {applicableOps.map(op => (
            <SelectItem key={op.value} value={op.value}>{op.label}</SelectItem>
          ))}
        </Select>
      </div>

      {/* Value */}
      <input
        type="text"
        value={condition.value}
        onChange={e => onUpdate({ value: e.target.value })}
        placeholder={condition.operator === ':in' || condition.operator === ':!in' ? 'val1,val2,val3' : 'Value...'}
        className="flex-1 min-w-0 rounded px-3 py-1.5 text-sm"
        style={{
          background: 'var(--surface-2)',
          border: '1px solid var(--border)',
          color: 'var(--fg)',
        }}
      />

      {/* Remove */}
      <button
        type="button"
        onClick={onRemove}
        disabled={!canRemove}
        className={cn(
          'p-1.5 transition-colors flex-shrink-0',
          canRemove ? 'hover:text-[var(--crit)]' : 'cursor-not-allowed'
        )}
        style={{ color: canRemove ? 'var(--muted)' : 'var(--dim)' }}
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  )
}

/** A recursive group component for the visual builder. */
function GroupBuilder({
  group,
  onUpdate,
  onRemove,
  depth,
  canRemove,
  fieldDefinitions,
  allFields,
  operators,
}: {
  group: ConditionGroup
  onUpdate: (updated: ConditionGroup) => void
  onRemove: () => void
  depth: number
  canRemove: boolean
  fieldDefinitions: Record<string, FieldDefinition[]>
  allFields: FieldDefinition[]
  operators: Operator[]
}) {
  const updateChild = (index: number, updated: QueryCondition | ConditionGroup) => {
    const newChildren = [...group.children]
    newChildren[index] = updated
    onUpdate({ ...group, children: newChildren })
  }

  const removeChild = (index: number) => {
    if (group.children.length <= 1) return
    const newChildren = group.children.filter((_, i) => i !== index)
    onUpdate({ ...group, children: newChildren })
  }

  const addCondition = () => {
    onUpdate({ ...group, children: [...group.children, newCondition()] })
  }

  const addNestedGroup = () => {
    const sub = newGroup(group.connector === 'AND' ? 'OR' : 'AND')
    onUpdate({ ...group, children: [...group.children, sub] })
  }

  const borderColors = ['border-[var(--emerald-400)]/40', 'border-[var(--high)]/40', 'border-[var(--emerald-500)]/40', 'border-[var(--sol-magenta)]/40']
  const bgColors = ['bg-[var(--emerald-400)]/5', 'bg-[var(--high)]/5', 'bg-[var(--emerald-500)]/5', 'bg-[var(--sol-magenta)]/5']

  return (
    <div
      className={cn(
        'rounded-lg p-3',
        depth > 0 ? borderColors[depth % borderColors.length] : '',
        depth > 0 ? bgColors[depth % bgColors.length] : ''
      )}
      style={{
        background: depth === 0 ? 'var(--bg)' : undefined,
        border: depth === 0 ? '1px solid var(--border)' : '1px solid var(--border)',
      }}
    >
      {/* Group header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          {depth > 0 && <CornerDownRight className="h-4 w-4" style={{ color: 'var(--muted)' }} />}
          <Layers className="h-4 w-4" style={{ color: 'var(--muted)' }} />
          <span className="text-xs font-medium uppercase" style={{ color: 'var(--muted)' }}>Match</span>
          <div className="flex items-center rounded-lg overflow-hidden" style={{ background: 'var(--bg)', border: '1px solid var(--border)' }}>
            <button
              type="button"
              onClick={() => onUpdate({ ...group, connector: 'AND' })}
              className={cn(
                'px-3 py-1 text-xs font-semibold transition-colors'
              )}
              style={{
                background: group.connector === 'AND' ? 'var(--emerald-600)' : 'transparent',
                color: group.connector === 'AND' ? 'white' : 'var(--muted)',
              }}
            >
              ALL (AND)
            </button>
            <button
              type="button"
              onClick={() => onUpdate({ ...group, connector: 'OR' })}
              className={cn(
                'px-3 py-1 text-xs font-semibold transition-colors'
              )}
              style={{
                background: group.connector === 'OR' ? 'var(--high)' : 'transparent',
                color: group.connector === 'OR' ? 'white' : 'var(--muted)',
              }}
            >
              ANY (OR)
            </button>
          </div>
          <span className="text-xs" style={{ color: 'var(--muted)' }}>of the following conditions</span>
        </div>
        <div className="flex items-center gap-1">
          {canRemove && (
            <button
              type="button"
              onClick={onRemove}
              className="p-1 transition-colors hover:text-[var(--crit)]"
              style={{ color: 'var(--muted)' }}
              title="Remove group"
            >
              <Trash2 className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>

      {/* Children */}
      <div className="space-y-2">
        {group.children.map((child, idx) => (
          <div key={isGroup(child) ? child.id : child.id}>
            {idx > 0 && (
              <div className="flex items-center gap-2 py-1 px-2">
                <div className="flex-1 h-px" style={{ background: 'var(--border)' }} />
                <span className={cn(
                  'text-xs font-bold px-2'
                )} style={{ color: group.connector === 'AND' ? 'var(--emerald-400)' : 'var(--high)' }}>
                  {group.connector}
                </span>
                <div className="flex-1 h-px" style={{ background: 'var(--border)' }} />
              </div>
            )}
            {isGroup(child) ? (
              <GroupBuilder
                group={child}
                onUpdate={updated => updateChild(idx, updated)}
                onRemove={() => removeChild(idx)}
                depth={depth + 1}
                canRemove={group.children.length > 1}
                fieldDefinitions={fieldDefinitions}
                allFields={allFields}
                operators={operators}
              />
            ) : (
              <ConditionRow
                condition={child}
                onUpdate={updates => updateChild(idx, { ...child, ...updates })}
                onRemove={() => removeChild(idx)}
                canRemove={group.children.length > 1}
                fieldDefinitions={fieldDefinitions}
                allFields={allFields}
                operators={operators}
              />
            )}
          </div>
        ))}
      </div>

      {/* Add buttons */}
      <div className="flex items-center gap-2 mt-3 pt-3" style={{ borderTop: '1px solid var(--hairline)' }}>
        <button
          type="button"
          onClick={addCondition}
          className="flex items-center gap-1 text-xs transition-colors hover:opacity-80"
          style={{ color: 'var(--emerald-400)' }}
        >
          <Plus className="h-3.5 w-3.5" />
          Add Condition
        </button>
        {depth < 2 && (
          <button
            type="button"
            onClick={addNestedGroup}
            className="flex items-center gap-1 text-xs transition-colors hover:opacity-80"
            style={{ color: 'var(--high)' }}
          >
            <Layers className="h-3.5 w-3.5" />
            Add Nested Group
          </button>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function Hunt({ savedQueries: initialSavedQueries, initialQuery }: HuntPageProps) {
  const [query, setQuery] = useState(initialQuery || '')
  const [isRunning, setIsRunning] = useState(false)
  const [results, setResults] = useState<HuntResult[]>([])
  const [error, setError] = useState<string | null>(null)
  const [timeRange, setTimeRange] = useState('24h')
  const [meta, setMeta] = useState<{ query: string; time_range: string; total: number; execution_time_ms?: number; query_type?: string; page?: number; page_size?: number; has_more?: boolean } | null>(null)

  // Query mode: 'simple' or 'tql'
  const [queryMode, setQueryMode] = useState<'simple' | 'tql'>('simple')
  const [tqlQuery, setTqlQuery] = useState('')
  const [tqlSchema, setTqlSchema] = useState<TQLSchema | null>(null)
  const [tqlValidation, setTqlValidation] = useState<TQLValidationResult | null>(null)
  const [showTqlHelp, setShowTqlHelp] = useState(false)
  const [tqlPage, setTqlPage] = useState(1)
  const [tqlPageSize, setTqlPageSize] = useState(100)

  // Schema and templates from API
  const [fieldDefinitions, setFieldDefinitions] = useState<Record<string, FieldDefinition[]>>(DEFAULT_FIELD_DEFINITIONS)
  const [operators, setOperators] = useState<Operator[]>(DEFAULT_OPERATORS)
  const [queryTemplates, setQueryTemplates] = useState<Record<string, QueryTemplate[]>>({})
  const [mitreCategories, setMitreCategories] = useState<string[]>(DEFAULT_MITRE_CATEGORIES)
  const [schemaLoaded, setSchemaLoaded] = useState(false)
  const [templatesLoaded, setTemplatesLoaded] = useState(false)

  // Computed from schema
  const allFields = useMemo(() => {
    return Object.values(fieldDefinitions).flat()
  }, [fieldDefinitions])

  // Visual query builder
  const [showVisualBuilder, setShowVisualBuilder] = useState(false)
  const [rootGroup, setRootGroup] = useState<ConditionGroup>(newGroup('AND'))

  // Templates
  const [showTemplates, setShowTemplates] = useState(false)
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)

  // Result selection
  const [selectedResults, setSelectedResults] = useState<Set<string>>(new Set())

  // Saved queries
  const [showSaveModal, setShowSaveModal] = useState(false)
  const [showSavedQueriesPanel, setShowSavedQueriesPanel] = useState(false)
  const [loadedQueries, setLoadedQueries] = useState<SavedQuery[]>(initialSavedQueries || [])
  const [saveForm, setSaveForm] = useState({ name: '', description: '', category: '', isPublic: false })
  const [isSaving, setIsSaving] = useState(false)

  // History
  const [showHistoryPanel, setShowHistoryPanel] = useState(false)
  const [queryHistory, setQueryHistory] = useState<QueryHistoryEntry[]>([])

  // Autocomplete
  const [showAutocomplete, setShowAutocomplete] = useState(false)
  const [autocompleteSuggestions, setAutocompleteSuggestions] = useState<{ field: string; label: string }[]>([])
  const [autocompleteIndex, setAutocompleteIndex] = useState(0)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const tqlTextareaRef = useRef<HTMLTextAreaElement>(null)
  const autocompleteRef = useRef<HTMLDivElement>(null)

  // Validation
  const [validationErrors, setValidationErrors] = useState<ValidationError[]>([])
  const [showValidation, setShowValidation] = useState(false)

  // Parse URL query on mount
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const q = urlParams.get('q')
    if (q) {
      setQuery(q)
      handleRunQueryWithValue(q)
    }
  }, [])

  // Load schema, templates, saved queries, and history on mount
  useEffect(() => {
    loadHuntSchema()
    loadHuntTemplates()
    loadSavedQueries()
    loadQueryHistory()
    loadTqlSchema()
  }, [])

  // Validate TQL query on change (debounced)
  useEffect(() => {
    if (queryMode === 'tql' && tqlQuery.trim()) {
      const timer = setTimeout(() => {
        validateTqlQuery(tqlQuery)
      }, 500)
      return () => clearTimeout(timer)
    }
  }, [tqlQuery, queryMode])

  // Validate query on change (debounced)
  useEffect(() => {
    const timer = setTimeout(() => {
      if (query.trim()) {
        const result = validateQuery(query)
        setValidationErrors(result.errors)
      } else {
        setValidationErrors([])
      }
    }, 300)
    return () => clearTimeout(timer)
  }, [query])

  // Close autocomplete on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (autocompleteRef.current && !autocompleteRef.current.contains(e.target as Node)) {
        setShowAutocomplete(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  // -----------------------------------------------------------------------
  // API calls
  // -----------------------------------------------------------------------

  const loadHuntSchema = async () => {
    try {
      const response = await fetch('/api/v1/hunting/schema', { credentials: 'include' })
      if (response.ok) {
        const data = await response.json()
        if (data.data) {
          if (data.data.fields) {
            setFieldDefinitions(data.data.fields)
          }
          if (data.data.operators) {
            setOperators(data.data.operators)
          }
          if (data.data.categories) {
            setMitreCategories(data.data.categories)
          }
          setSchemaLoaded(true)
        }
      }
    } catch (err) {
      logger.error('Failed to load hunt schema:', err)
      // Keep using defaults
    }
  }

  const loadHuntTemplates = async () => {
    try {
      const response = await fetch('/api/v1/hunting/templates', { credentials: 'include' })
      if (response.ok) {
        const data = await response.json()
        if (data.data?.templates) {
          setQueryTemplates(data.data.templates)
          if (data.data.categories) {
            setMitreCategories(data.data.categories)
          }
          setTemplatesLoaded(true)
        }
      }
    } catch (err) {
      logger.error('Failed to load hunt templates:', err)
      // Keep using empty templates - users can still use saved queries
    }
  }

  const loadSavedQueries = async () => {
    try {
      const response = await fetch('/api/v1/queries?limit=50', { credentials: 'include' })
      if (response.ok) {
        const data = await response.json()
        setLoadedQueries(data.data || [])
      }
    } catch (err) {
      logger.error('Failed to load saved queries:', err)
    }
  }

  const loadQueryHistory = async () => {
    try {
      const response = await fetch('/api/v1/queries/history?unique=true&limit=20', { credentials: 'include' })
      if (response.ok) {
        const data = await response.json()
        const history = Array.isArray(data?.data) ? data.data : Array.isArray(data) ? data : []
        setQueryHistory(history)
      }
    } catch (err) {
      // API may not be implemented yet -- log for debugging only
      console.debug('Query history not available:', err)
    }
  }

  // TQL (Tamandua Query Language) API calls
  const loadTqlSchema = async () => {
    try {
      const response = await fetch('/api/v1/hunting/tql-schema', { credentials: 'include' })
      if (response.ok) {
        const data = await response.json()
        if (data.data) {
          setTqlSchema(data.data)
        }
      }
    } catch (err) {
      logger.error('Failed to load TQL schema:', err)
    }
  }

  const validateTqlQuery = async (queryValue: string) => {
    try {
      const response = await fetch('/api/v1/hunting/tql/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ query: queryValue }),
      })
      if (response.ok) {
        const data = await response.json()
        setTqlValidation(data)
      }
    } catch (err) {
      logger.error('Failed to validate TQL query:', err)
    }
  }

  const executeTqlQuery = async (queryValue: string, page: number = 1) => {
    if (!queryValue.trim()) return

    setIsRunning(true)
    setError(null)
    setResults([])
    setSelectedResults(new Set())

    try {
      const response = await fetch('/api/v1/hunting/tql', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          query: queryValue,
          page,
          page_size: tqlPageSize,
          timeout: 60000,
        }),
      })

      if (!response.ok) {
        const contentType = response.headers.get('content-type') || ''
        if (contentType.includes('application/json')) {
          const errorData = await response.json()
          throw new Error(errorData.error || 'TQL query failed')
        } else {
          throw new Error(`TQL query failed with status ${response.status}`)
        }
      }

      const data = await response.json()
      const resultData = data.data || []

      setResults(resultData)
      setMeta(data.meta)
      setTqlPage(page)

      // Record in history
      if (data.meta?.execution_time_ms) {
        recordQueryHistory(queryValue, resultData.length, data.meta.execution_time_ms)
      }
    } catch (err: any) {
      setError(err.message || 'Failed to execute TQL query')
    } finally {
      setIsRunning(false)
    }
  }

  const handleRunTqlQuery = () => executeTqlQuery(tqlQuery, 1)

  const handleTqlNextPage = () => {
    if (meta?.has_more) {
      executeTqlQuery(tqlQuery, tqlPage + 1)
    }
  }

  const handleTqlPrevPage = () => {
    if (tqlPage > 1) {
      executeTqlQuery(tqlQuery, tqlPage - 1)
    }
  }

  const saveQuery = async () => {
    const currentQuery = queryMode === 'tql' ? tqlQuery : query
    if (!currentQuery.trim() || !saveForm.name.trim()) return
    setIsSaving(true)

    try {
      const response = await fetch('/api/v1/queries', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          name: saveForm.name,
          description: saveForm.description,
          query: currentQuery,
          category: saveForm.category || null,
          is_public: saveForm.isPublic,
          type: queryMode === 'tql' ? 'tql' : 'hunt',
        }),
      })

      if (response.ok) {
        const contentType = response.headers.get('content-type') || ''
        if (contentType.includes('application/json')) {
          const data = await response.json()
          setLoadedQueries(prev => [data.data, ...prev])
        } else {
          await loadSavedQueries()
        }
        setShowSaveModal(false)
        setSaveForm({ name: '', description: '', category: '', isPublic: false })
        setError(null)
      } else {
        const contentType = response.headers.get('content-type') || ''
        if (contentType.includes('application/json')) {
          const errorData = await response.json()
          setError(errorData.error || 'Failed to save query')
        } else {
          setError(`Failed to save query (status ${response.status})`)
        }
      }
    } catch (err) {
      setError('Failed to save query')
    } finally {
      setIsSaving(false)
    }
  }

  const deleteQuery = async (queryId: string) => {
    try {
      const response = await fetch(`/api/v1/queries/${queryId}`, {
        method: 'DELETE',
        credentials: 'include',
      })
      if (response.ok) {
        setLoadedQueries(prev => prev.filter(q => q.id !== queryId))
      }
    } catch (err) {
      logger.error('Failed to delete query:', err)
    }
  }

  const recordQueryHistory = async (queryValue: string, resultCount: number, executionTimeMs: number) => {
    try {
      await fetch('/api/v1/queries/history', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          query: queryValue,
          type: 'hunt',
          result_count: resultCount,
          execution_time_ms: executionTimeMs,
        }),
      })
      loadQueryHistory()
    } catch (err) {
      logger.error('Failed to record history:', err)
    }
  }

  // -----------------------------------------------------------------------
  // Query execution
  // -----------------------------------------------------------------------

  const handleRunQueryWithValue = async (queryValue: string) => {
    if (!queryValue.trim()) return

    // Validate first
    const result = validateQuery(queryValue)
    setValidationErrors(result.errors)
    if (result.errors.length > 0) {
      setShowValidation(true)
      // If it's a natural language query, suggest NL Hunt
      if (result.isNaturalLanguage) {
        setError('Try NL Hunt for natural language queries, or use field:value syntax here.')
      } else {
        setError('Query has validation errors. Review them before running.')
      }
      return
    }

    setIsRunning(true)
    setError(null)
    setResults([])
    setSelectedResults(new Set())
    setShowValidation(false)

    const startTime = Date.now()

    try {
      const response = await fetch('/api/v1/hunting/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          query: queryValue,
          time_range: timeRange,
          limit: 100,
        }),
      })

      if (!response.ok) {
        const contentType = response.headers.get('content-type') || ''
        if (contentType.includes('application/json')) {
          const errorData = await response.json()
          throw new Error(errorData.error || 'Search failed')
        } else {
          throw new Error(`Search failed with status ${response.status}`)
        }
      }

      const data = await response.json()
      const resultData = data.data || []
      const executionTime = Date.now() - startTime

      setResults(resultData)
      setMeta(data.meta)

      recordQueryHistory(queryValue, resultData.length, executionTime)
    } catch (err: any) {
      setError(err.message || 'Failed to execute query')
    } finally {
      setIsRunning(false)
    }
  }

  const handleRunQuery = () => handleRunQueryWithValue(query)

  // -----------------------------------------------------------------------
  // Autocomplete handlers
  // -----------------------------------------------------------------------

  const handleQueryChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const value = e.target.value
    setQuery(value)

    const cursorPos = e.target.selectionStart || 0
    const { word } = getCurrentWord(value, cursorPos)

    // Compute autocomplete suggestions using current schema
    const suggestions = getAutocompleteSuggestionsFromFields(word, allFields)
    setAutocompleteSuggestions(suggestions)
    setAutocompleteIndex(0)
    setShowAutocomplete(suggestions.length > 0)
  }

  // Helper to get autocomplete suggestions from the current field definitions
  const getAutocompleteSuggestionsFromFields = (word: string, fields: FieldDefinition[]): { field: string; label: string }[] => {
    if (!word) return []
    // Only suggest if the word looks like a field (no colon yet)
    if (word.includes(':')) return []
    const lower = word.toLowerCase()
    return fields.filter(
      f => f.field.toLowerCase().startsWith(lower) || f.label.toLowerCase().includes(lower)
    ).slice(0, 8)
  }

  const applyAutocompleteSuggestion = (field: string) => {
    if (!textareaRef.current) return
    const cursorPos = textareaRef.current.selectionStart || 0
    const { start, end } = getCurrentWord(query, cursorPos)

    const before = query.substring(0, start)
    const after = query.substring(end)
    const newQuery = before + field + ':' + after
    setQuery(newQuery)
    setShowAutocomplete(false)

    // Set cursor after the colon
    setTimeout(() => {
      if (textareaRef.current) {
        const newPos = start + field.length + 1
        textareaRef.current.selectionStart = newPos
        textareaRef.current.selectionEnd = newPos
        textareaRef.current.focus()
      }
    }, 0)
  }

  const handleQueryKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (showAutocomplete && autocompleteSuggestions.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setAutocompleteIndex(prev => Math.min(prev + 1, autocompleteSuggestions.length - 1))
        return
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        setAutocompleteIndex(prev => Math.max(prev - 1, 0))
        return
      }
      if (e.key === 'Tab' || e.key === 'Enter') {
        if (autocompleteSuggestions[autocompleteIndex]) {
          e.preventDefault()
          applyAutocompleteSuggestion(autocompleteSuggestions[autocompleteIndex].field)
          return
        }
      }
      if (e.key === 'Escape') {
        e.preventDefault()
        setShowAutocomplete(false)
        return
      }
    }

    // Ctrl/Cmd+Enter to run query
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault()
      handleRunQuery()
    }
  }

  // -----------------------------------------------------------------------
  // Visual builder <-> text query
  // -----------------------------------------------------------------------

  const syncVisualToText = () => {
    const built = groupToQuery(rootGroup)
    if (built) {
      setQuery(built)
    }
  }

  const syncTextToVisual = () => {
    const parsed = parseQueryToGroup(query)
    setRootGroup(parsed)
  }

  const handleToggleVisualBuilder = () => {
    if (!showVisualBuilder && query.trim()) {
      // Opening: parse text query into visual builder
      syncTextToVisual()
    }
    setShowVisualBuilder(!showVisualBuilder)
  }

  const applyVisualQuery = () => {
    const built = groupToQuery(rootGroup)
    if (built) {
      setQuery(built)
      setShowVisualBuilder(false)
    }
  }

  // -----------------------------------------------------------------------
  // Template handling
  // -----------------------------------------------------------------------

  const applyTemplate = (template: { name: string; query: string }) => {
    setQuery(template.query)
    setShowTemplates(false)
    setSelectedCategory(null)
  }

  // -----------------------------------------------------------------------
  // Result handling
  // -----------------------------------------------------------------------

  const toggleResultSelection = (id: string) => {
    const next = new Set(selectedResults)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSelectedResults(next)
  }

  const selectAllResults = () => {
    if (selectedResults.size === results.length) {
      setSelectedResults(new Set())
    } else {
      setSelectedResults(new Set(results.map(r => r.id)))
    }
  }


  const getEventIcon = (eventType: string) => {
    if (eventType.includes('process')) return Cpu
    if (eventType.includes('network')) return Globe
    if (eventType.includes('file')) return File
    if (eventType.includes('dns')) return Server
    if (eventType.includes('registry')) return Settings
    return Search
  }

  const navigateToGraph = (result: HuntResult) => {
    if (result.pid && result.agent_id) {
      router.visit(`/app/investigation/${result.pid}?type=process&agent_id=${result.agent_id}`)
    }
  }

  const navigateToProcessTree = (result: HuntResult) => {
    if (result.agent_id) {
      const pid = result.pid || result.payload?.pid
      router.visit(`/app/process-tree?agent_id=${result.agent_id}${pid ? `&pid=${pid}` : ''}`)
    }
  }

  const huntForValue = (field: string, value: string) => {
    setQuery(`${field}:${value}`)
    handleRunQueryWithValue(`${field}:${value}`)
  }

  const formatTimeAgo = (dateStr: string) => {
    const diff = Date.now() - new Date(dateStr).getTime()
    if (diff < 60000) return 'just now'
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
    return `${Math.floor(diff / 86400000)}d ago`
  }

  // -----------------------------------------------------------------------
  // Render
  // -----------------------------------------------------------------------

  return (
    <MainLayout title="Threat Hunt">
      <Head title="Threat Hunt - Tamandua EDR" />

      <div className="space-y-6">
        {/* ================================================================ */}
        {/* Query Builder Card                                               */}
        {/* ================================================================ */}
        <div className="rounded-xl p-6" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
          {/* Mode Selector */}
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <div className="flex items-center rounded-lg p-1" style={{ background: 'var(--bg)', border: '1px solid var(--border)' }}>
                <button
                  type="button"
                  onClick={() => setQueryMode('simple')}
                  className={cn(
                    'px-4 py-2 rounded-md text-sm font-medium transition-all'
                  )}
                  style={{
                    background: queryMode === 'simple' ? 'var(--emerald-600)' : 'transparent',
                    color: queryMode === 'simple' ? 'white' : 'var(--muted)',
                  }}
                >
                  <Search className="h-4 w-4 inline mr-2" />
                  Simple Search
                </button>
                <button
                  type="button"
                  onClick={() => setQueryMode('tql')}
                  className={cn(
                    'px-4 py-2 rounded-md text-sm font-medium transition-all'
                  )}
                  style={{
                    background: queryMode === 'tql' ? 'var(--sol-magenta)' : 'transparent',
                    color: queryMode === 'tql' ? 'white' : 'var(--muted)',
                  }}
                >
                  <Terminal className="h-4 w-4 inline mr-2" />
                  TQL Editor
                </button>
              </div>
              {queryMode === 'tql' && (
                <button
                  type="button"
                  onClick={() => setShowTqlHelp(!showTqlHelp)}
                  className="p-2 rounded-lg transition-colors"
                  style={{
                    background: showTqlHelp ? 'var(--sol-magenta)' : 'var(--surface-2)',
                    color: showTqlHelp ? 'white' : 'var(--muted)',
                  }}
                  title="TQL Syntax Help"
                >
                  <HelpCircle className="h-5 w-5" />
                </button>
              )}
            </div>
            {queryMode === 'simple' && (
              <div className="text-xs" style={{ color: 'var(--muted)' }}>
                Use field:value syntax (e.g., process.name:cmd.exe)
              </div>
            )}
            {queryMode === 'tql' && tqlSchema && (
              <div className="text-xs" style={{ color: 'var(--muted)' }}>
                TQL v{tqlSchema.version} - Pipe-based query language
              </div>
            )}
          </div>

          {/* TQL Help Panel */}
          {queryMode === 'tql' && showTqlHelp && tqlSchema && (
            <div className="mb-4 p-4 rounded-lg" style={{ background: 'var(--bg)', border: '1px solid rgba(217, 70, 239, 0.3)' }}>
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold" style={{ color: 'var(--sol-magenta)' }}>TQL Syntax Reference</h3>
                <button
                  type="button"
                  onClick={() => setShowTqlHelp(false)}
                  style={{ color: 'var(--muted)' }}
                  className="hover:opacity-80"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div>
                  <h4 className="font-medium mb-2" style={{ color: 'var(--muted)' }}>Basic Structure</h4>
                  <code className="block p-2 rounded font-mono" style={{ background: 'var(--surface)', color: 'var(--sol-magenta)' }}>
                    {tqlSchema.syntax.basic_structure}
                  </code>
                  <h4 className="font-medium mt-3 mb-2" style={{ color: 'var(--muted)' }}>Operators</h4>
                  <div className="space-y-1">
                    {tqlSchema.syntax.operators.slice(0, 6).map((op, i) => (
                      <div key={i} className="flex gap-2">
                        <code className="font-mono whitespace-nowrap" style={{ color: 'var(--sol-magenta)' }}>{op.syntax}</code>
                        <span style={{ color: 'var(--muted)' }}>{op.description}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <h4 className="font-medium mb-2" style={{ color: 'var(--muted)' }}>Examples</h4>
                  <div className="space-y-2">
                    {tqlSchema.examples.slice(0, 3).map((ex, i) => (
                      <button
                        key={i}
                        type="button"
                        onClick={() => {
                          setTqlQuery(ex.query)
                          setShowTqlHelp(false)
                        }}
                        className="block w-full text-left p-2 rounded transition-colors hover:opacity-80"
                        style={{ background: 'var(--surface)' }}
                      >
                        <div className="font-medium" style={{ color: 'var(--fg-2)' }}>{ex.name}</div>
                        <code className="font-mono text-xs truncate block" style={{ color: 'var(--sol-magenta)' }}>{ex.query}</code>
                      </button>
                    ))}
                  </div>
                  <h4 className="font-medium mt-3 mb-2" style={{ color: 'var(--muted)' }}>Available Tables</h4>
                  <div className="flex flex-wrap gap-2">
                    {tqlSchema.table_sources.map(src => (
                      <span key={src} className="px-2 py-1 rounded font-mono" style={{ background: 'var(--surface)', color: 'var(--sol-magenta)' }}>{src}</span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TQL Editor */}
          {queryMode === 'tql' && (
            <div className="space-y-3 mb-4">
              <div className="relative">
                <Terminal className="absolute left-4 top-4 h-5 w-5 z-10" style={{ color: 'var(--sol-magenta)' }} />
                <textarea
                  ref={tqlTextareaRef}
                  value={tqlQuery}
                  onChange={e => setTqlQuery(e.target.value)}
                  onKeyDown={e => {
                    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                      e.preventDefault()
                      handleRunTqlQuery()
                    }
                  }}
                  placeholder={`events | where event_type == "process" | where command_line contains "-enc" | limit 100`}
                  className="w-full h-32 rounded-lg pl-12 pr-4 py-3 font-mono text-sm focus:outline-none focus:ring-2 resize-none"
                  style={{
                    background: 'var(--bg)',
                    border: tqlValidation && !tqlValidation.valid ? '1px solid var(--crit)' : '1px solid rgba(217, 70, 239, 0.3)',
                    color: 'var(--fg)',
                  }}
                  spellCheck={false}
                />
              </div>

              {/* TQL Validation Feedback */}
              {tqlQuery.trim() && tqlValidation && (
                <div className={cn(
                  'flex items-center gap-2 px-3 py-2 rounded-lg text-sm'
                )} style={{
                  background: tqlValidation.valid ? 'var(--emerald-glow)' : 'var(--crit-bg)',
                  border: tqlValidation.valid ? '1px solid rgba(47, 196, 113, 0.3)' : '1px solid rgba(240, 80, 110, 0.3)',
                }}>
                  {tqlValidation.valid ? (
                    <>
                      <CheckCircle2 className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                      <span style={{ color: 'var(--emerald-400)' }}>Query syntax is valid</span>
                    </>
                  ) : (
                    <>
                      <AlertTriangle className="h-4 w-4" style={{ color: 'var(--crit)' }} />
                      <div style={{ color: 'var(--crit)' }}>
                        {tqlValidation.errors?.map((err, i) => (
                          <div key={i}>
                            {err.message}
                            {err.line && ` (line ${err.line}, col ${err.column})`}
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* TQL Controls */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4 text-sm" style={{ color: 'var(--muted)' }}>
                  <span>Page Size:</span>
                  <Select
                    value={String(tqlPageSize)}
                    onValueChange={(v) => setTqlPageSize(Number(v))}
                    placeholder="Page size"
                  >
                    <SelectItem value="50">50</SelectItem>
                    <SelectItem value="100">100</SelectItem>
                    <SelectItem value="500">500</SelectItem>
                    <SelectItem value="1000">1000</SelectItem>
                  </Select>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      const currentQuery = queryMode === 'tql' ? tqlQuery : query
                      if (currentQuery.trim()) {
                        setShowSaveModal(true)
                      }
                    }}
                    disabled={!tqlQuery.trim()}
                    className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors"
                    style={{
                      background: tqlQuery.trim() ? 'var(--surface-2)' : 'var(--surface)',
                      color: tqlQuery.trim() ? 'var(--fg-2)' : 'var(--dim)',
                      cursor: tqlQuery.trim() ? 'pointer' : 'not-allowed',
                    }}
                  >
                    <Save className="h-4 w-4" />
                    Save
                  </button>
                  <button
                    type="button"
                    onClick={handleRunTqlQuery}
                    disabled={isRunning || !tqlQuery.trim() || (tqlValidation && !tqlValidation.valid)}
                    className="flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors"
                    style={{
                      background: (isRunning || !tqlQuery.trim() || (tqlValidation && !tqlValidation.valid)) ? 'var(--surface-2)' : 'var(--sol-magenta)',
                      color: (isRunning || !tqlQuery.trim() || (tqlValidation && !tqlValidation.valid)) ? 'var(--dim)' : 'white',
                      cursor: (isRunning || !tqlQuery.trim() || (tqlValidation && !tqlValidation.valid)) ? 'not-allowed' : 'pointer',
                    }}
                  >
                    <Play className={cn('h-4 w-4', isRunning && 'animate-spin')} />
                    {isRunning ? 'Running...' : 'Run TQL Query'}
                  </button>
                </div>
              </div>

              {/* TQL Example Queries */}
              {tqlSchema && !tqlQuery.trim() && (
                <div className="pt-3" style={{ borderTop: '1px solid var(--border)' }}>
                  <p className="text-xs mb-2" style={{ color: 'var(--muted)' }}>Quick Examples:</p>
                  <div className="flex flex-wrap gap-2">
                    {tqlSchema.examples.map((ex, i) => (
                      <button
                        key={i}
                        type="button"
                        onClick={() => setTqlQuery(ex.query)}
                        className="px-3 py-1.5 rounded text-xs font-mono transition-colors hover:opacity-80"
                        style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}
                      >
                        {ex.name}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Simple Mode Header row */}
          {queryMode === 'simple' && (
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Query Builder</h2>
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={handleToggleVisualBuilder}
                  className="px-3 py-1 rounded-lg text-sm transition-colors"
                  style={{
                    background: showVisualBuilder ? 'var(--emerald-600)' : 'var(--surface-2)',
                    color: showVisualBuilder ? 'white' : 'var(--fg-2)',
                  }}
                >
                  <Filter className="h-4 w-4 inline mr-1" />
                  Visual
                </button>
                <button
                  type="button"
                  onClick={() => setShowTemplates(!showTemplates)}
                  className="px-3 py-1 rounded-lg text-sm transition-colors"
                  style={{
                    background: showTemplates ? 'var(--emerald-600)' : 'var(--surface-2)',
                    color: showTemplates ? 'white' : 'var(--fg-2)',
                  }}
                >
                  <BookOpen className="h-4 w-4 inline mr-1" />
                  Templates
                </button>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setShowSavedQueriesPanel(!showSavedQueriesPanel)}
                className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors"
                style={{
                  background: showSavedQueriesPanel ? 'var(--emerald-600)' : 'var(--surface-2)',
                  color: showSavedQueriesPanel ? 'white' : 'var(--fg-2)',
                }}
              >
                <FolderOpen className="h-4 w-4" />
                Saved
                {loadedQueries.length > 0 && (
                  <span className="px-1.5 py-0.5 rounded text-xs" style={{ background: 'var(--surface-3)' }}>{loadedQueries.length}</span>
                )}
              </button>
              <button
                type="button"
                onClick={() => query.trim() && setShowSaveModal(true)}
                disabled={!query.trim()}
                className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors"
                style={{
                  background: query.trim() ? 'var(--surface-2)' : 'var(--surface)',
                  color: query.trim() ? 'var(--fg-2)' : 'var(--dim)',
                  cursor: query.trim() ? 'pointer' : 'not-allowed',
                }}
              >
                <Save className="h-4 w-4" />
                Save
              </button>
              <button
                type="button"
                onClick={() => setShowHistoryPanel(!showHistoryPanel)}
                className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-colors"
                style={{
                  background: showHistoryPanel ? 'var(--emerald-600)' : 'var(--surface-2)',
                  color: showHistoryPanel ? 'white' : 'var(--fg-2)',
                }}
              >
                <Clock className="h-4 w-4" />
                History
                {queryHistory.length > 0 && (
                  <span className="px-1.5 py-0.5 rounded text-xs" style={{ background: 'var(--surface-3)' }}>{queryHistory.length}</span>
                )}
              </button>
            </div>
          </div>
          )}

          {/* ============================================================== */}
          {/* Visual Query Builder                                           */}
          {/* ============================================================== */}
          {showVisualBuilder && (
            <div className="mb-4">
              <GroupBuilder
                group={rootGroup}
                onUpdate={setRootGroup}
                onRemove={() => setRootGroup(newGroup('AND'))}
                depth={0}
                canRemove={false}
                fieldDefinitions={fieldDefinitions}
                allFields={allFields}
                operators={operators}
              />
              <div className="mt-3 flex items-center justify-between">
                <div className="flex-1 min-w-0 mr-4">
                  <div className="text-xs mb-1" style={{ color: 'var(--muted)' }}>Preview:</div>
                  <div
                    className="text-sm font-mono rounded px-3 py-2 truncate"
                    style={{ background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--fg-2)' }}
                  >
                    {groupToQuery(rootGroup) || '(empty - add conditions above)'}
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <button
                    type="button"
                    onClick={syncTextToVisual}
                    className="flex items-center gap-1 px-3 py-1.5 rounded text-xs transition-colors hover:opacity-80"
                    style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}
                    title="Import current text query into visual builder"
                  >
                    <Copy className="h-3.5 w-3.5" />
                    Import Text
                  </button>
                  <button
                    type="button"
                    onClick={applyVisualQuery}
                    disabled={!groupToQuery(rootGroup)}
                    className="flex items-center gap-2 px-3 py-1.5 rounded text-sm transition-colors"
                    style={{
                      background: groupToQuery(rootGroup) ? 'var(--emerald-600)' : 'var(--surface-2)',
                      color: groupToQuery(rootGroup) ? 'white' : 'var(--dim)',
                    }}
                  >
                    <Zap className="h-4 w-4" />
                    Apply to Query
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ============================================================== */}
          {/* MITRE Templates                                                */}
          {/* ============================================================== */}
          {showTemplates && (
            <div className="mb-4 p-4 rounded-lg" style={{ background: 'var(--bg)', border: '1px solid var(--border)' }}>
              <div className="flex items-center gap-2 mb-3">
                <span className="text-sm" style={{ color: 'var(--muted)' }}>MITRE ATT&CK Templates</span>
                {!templatesLoaded && <span className="text-xs" style={{ color: 'var(--dim)' }}>(loading...)</span>}
              </div>
              <div className="flex flex-wrap gap-2 mb-3">
                {mitreCategories.map(category => (
                  <button
                    key={category}
                    type="button"
                    onClick={() => setSelectedCategory(selectedCategory === category ? null : category)}
                    className={cn(
                      'px-3 py-1 rounded-full text-xs font-medium transition-colors',
                      !queryTemplates[category]?.length && 'opacity-50'
                    )}
                    style={{
                      background: selectedCategory === category ? 'var(--emerald-600)' : 'var(--surface-2)',
                      color: selectedCategory === category ? 'white' : 'var(--fg-2)',
                    }}
                  >
                    {category}
                    {queryTemplates[category]?.length ? (
                      <span className="ml-1" style={{ color: selectedCategory === category ? 'rgba(255,255,255,0.7)' : 'var(--muted)' }}>({queryTemplates[category].length})</span>
                    ) : null}
                  </button>
                ))}
              </div>
              {selectedCategory && queryTemplates[selectedCategory]?.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {queryTemplates[selectedCategory].map((template, idx) => (
                    <button
                      key={template.id || idx}
                      type="button"
                      onClick={() => applyTemplate(template)}
                      className="flex flex-col items-start p-3 rounded-lg text-left transition-colors hover:opacity-80"
                      style={{ background: 'var(--surface)' }}
                    >
                      <span className="text-sm font-medium" style={{ color: 'var(--fg)' }}>{template.name}</span>
                      <span className="text-xs mt-1" style={{ color: 'var(--muted)' }}>{template.description}</span>
                      <span className="text-xs font-mono mt-2 truncate w-full" style={{ color: 'var(--dim)' }}>{template.query}</span>
                    </button>
                  ))}
                </div>
              )}
              {selectedCategory && !queryTemplates[selectedCategory]?.length && (
                <div className="text-center py-4 text-sm" style={{ color: 'var(--muted)' }}>
                  No templates available for this category
                </div>
              )}
            </div>
          )}

          {/* ============================================================== */}
          {/* Saved Queries Panel                                            */}
          {/* ============================================================== */}
          {showSavedQueriesPanel && (
            <div className="mb-4 p-4 rounded-lg" style={{ background: 'var(--bg)', border: '1px solid var(--border)' }}>
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm font-medium" style={{ color: 'var(--fg-2)' }}>Saved Queries</span>
                <button
                  type="button"
                  onClick={() => setShowSavedQueriesPanel(false)}
                  style={{ color: 'var(--muted)' }}
                  className="hover:opacity-80"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              {loadedQueries.length === 0 ? (
                <p className="text-sm text-center py-4" style={{ color: 'var(--muted)' }}>
                  No saved queries yet. Save a query to see it here.
                </p>
              ) : (
                <div className="space-y-2 max-h-72 overflow-y-auto">
                  {loadedQueries.map((sq, idx) => (
                    <div
                      key={sq.id || idx}
                      className="flex items-center gap-3 p-3 rounded-lg group transition-colors"
                      style={{ background: 'var(--surface)' }}
                    >
                      <button
                        type="button"
                        onClick={() => {
                          setQuery(sq.query)
                          setShowSavedQueriesPanel(false)
                        }}
                        className="flex-1 min-w-0 text-left"
                      >
                        <div className="flex items-center gap-2">
                          <p className="text-sm font-medium truncate" style={{ color: 'var(--fg)' }}>{sq.name}</p>
                          {sq.category && (
                            <span className="px-1.5 py-0.5 rounded text-xs flex-shrink-0" style={{ background: 'var(--surface-2)', color: 'var(--muted)' }}>
                              {sq.category}
                            </span>
                          )}
                          {sq.is_public && (
                            <Share2 className="h-3 w-3 flex-shrink-0" style={{ color: 'var(--muted)' }} />
                          )}
                        </div>
                        {sq.description && (
                          <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--muted)' }}>{sq.description}</p>
                        )}
                        <p className="text-xs font-mono mt-1 truncate" style={{ color: 'var(--dim)' }}>{sq.query}</p>
                      </button>
                      <div className="flex items-center gap-1 flex-shrink-0">
                        <button
                          type="button"
                          onClick={() => {
                            setQuery(sq.query)
                            setShowSavedQueriesPanel(false)
                            handleRunQueryWithValue(sq.query)
                          }}
                          className="p-1.5 transition-colors opacity-0 group-hover:opacity-100 hover:text-[var(--emerald-400)]"
                          style={{ color: 'var(--muted)' }}
                          title="Load and run"
                        >
                          <Play className="h-4 w-4" />
                        </button>
                        {sq.id && (
                          <button
                            type="button"
                            onClick={() => {
                              if (confirm(`Delete saved query "${sq.name}"?`)) {
                                deleteQuery(sq.id!)
                              }
                            }}
                            className="p-1.5 transition-colors opacity-0 group-hover:opacity-100 hover:text-[var(--crit)]"
                            style={{ color: 'var(--muted)' }}
                            title="Delete query"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ============================================================== */}
          {/* History Panel                                                   */}
          {/* ============================================================== */}
          {showHistoryPanel && (
            <div className="mb-4 p-4 rounded-lg" style={{ background: 'var(--bg)', border: '1px solid var(--border)' }}>
              <div className="flex items-center justify-between mb-3">
                <span className="text-sm font-medium" style={{ color: 'var(--fg-2)' }}>Query History</span>
                <button
                  type="button"
                  onClick={() => setShowHistoryPanel(false)}
                  style={{ color: 'var(--muted)' }}
                  className="hover:opacity-80"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              {queryHistory.length === 0 ? (
                <p className="text-sm text-center py-4" style={{ color: 'var(--muted)' }}>
                  No query history yet. Run some queries to see them here.
                </p>
              ) : (
                <div className="space-y-1 max-h-72 overflow-y-auto">
                  {queryHistory.map((entry, idx) => (
                    <button
                      key={entry.id || idx}
                      type="button"
                      onClick={() => {
                        setQuery(entry.query)
                        setShowHistoryPanel(false)
                      }}
                      className="w-full flex items-center gap-3 p-2.5 rounded-lg text-left transition-colors group hover:opacity-80"
                      style={{ background: 'var(--surface)' }}
                    >
                      <Clock className="h-4 w-4 flex-shrink-0" style={{ color: 'var(--dim)' }} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-mono truncate" style={{ color: 'var(--fg)' }}>{entry.query}</p>
                        <div className="flex items-center gap-3 mt-1">
                          {entry.result_count !== undefined && (
                            <span className="text-xs" style={{ color: 'var(--muted)' }}>
                              {entry.result_count} result{entry.result_count !== 1 ? 's' : ''}
                            </span>
                          )}
                          {entry.execution_time_ms !== undefined && (
                            <span className="text-xs" style={{ color: 'var(--dim)' }}>{entry.execution_time_ms}ms</span>
                          )}
                          {entry.executed_at && (
                            <span className="text-xs" style={{ color: 'var(--dim)' }}>{formatTimeAgo(entry.executed_at)}</span>
                          )}
                        </div>
                      </div>
                      <Play className="h-4 w-4 flex-shrink-0 transition-colors group-hover:text-[var(--emerald-400)]" style={{ color: 'var(--dim)' }} />
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ============================================================== */}
          {/* Text Query Input with Autocomplete                             */}
          {/* ============================================================== */}
          <div className="space-y-3">
            <div className="relative">
              <Code className="absolute left-4 top-4 h-5 w-5 z-10" style={{ color: 'var(--muted)' }} />
              <textarea
                ref={textareaRef}
                value={query}
                onChange={handleQueryChange}
                onKeyDown={handleQueryKeyDown}
                onBlur={() => {
                  // Delay so click on autocomplete item works
                  setTimeout(() => setShowAutocomplete(false), 200)
                }}
                placeholder='Enter query... (e.g., process.name:cmd.exe AND process.user:SYSTEM)  [Ctrl+Enter to run]'
                className="w-full h-28 rounded-lg pl-12 pr-4 py-3 font-mono text-sm focus:outline-none focus:ring-2 resize-none"
                style={{
                  background: 'var(--bg)',
                  border: validationErrors.length > 0 && query.trim() ? '1px solid var(--crit)' : '1px solid var(--border)',
                  color: 'var(--fg)',
                }}
              />

              {/* Autocomplete dropdown */}
              {showAutocomplete && autocompleteSuggestions.length > 0 && (
                <div
                  ref={autocompleteRef}
                  className="absolute z-50 left-12 top-28 w-80 rounded-lg shadow-xl overflow-hidden"
                  style={{ background: 'var(--surface-2)', border: '1px solid var(--border)' }}
                >
                  <div className="px-3 py-1.5" style={{ borderBottom: '1px solid var(--border)' }}>
                    <span className="text-xs" style={{ color: 'var(--muted)' }}>Field suggestions (Tab to accept)</span>
                  </div>
                  {autocompleteSuggestions.map((suggestion, idx) => (
                    <button
                      key={suggestion.field}
                      type="button"
                      onMouseDown={(e) => {
                        e.preventDefault()
                        applyAutocompleteSuggestion(suggestion.field)
                      }}
                      className="w-full flex items-center justify-between px-3 py-2 text-sm text-left transition-colors"
                      style={{
                        background: idx === autocompleteIndex ? 'var(--emerald-glow)' : 'transparent',
                        color: idx === autocompleteIndex ? 'var(--fg)' : 'var(--fg-2)',
                      }}
                    >
                      <span>{suggestion.label}</span>
                      <span className="text-xs font-mono" style={{ color: 'var(--muted)' }}>{suggestion.field}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Validation errors */}
            {validationErrors.length > 0 && query.trim() && (
              <div
                className="rounded-lg p-3 transition-all"
                style={{
                  background: showValidation ? 'var(--crit-bg)' : 'var(--high-bg)',
                  border: showValidation ? '1px solid rgba(240, 80, 110, 0.3)' : '1px solid rgba(245, 165, 36, 0.3)',
                }}
              >
                <button
                  type="button"
                  onClick={() => setShowValidation(!showValidation)}
                  className="flex items-center gap-2 w-full text-left"
                >
                  <AlertTriangle className="h-4 w-4 flex-shrink-0" style={{ color: showValidation ? 'var(--crit)' : 'var(--high)' }} />
                  <span className="text-sm font-medium" style={{ color: showValidation ? 'var(--crit)' : 'var(--high)' }}>
                    {validationErrors.length} validation issue{validationErrors.length !== 1 ? 's' : ''}
                  </span>
                  <ChevronDown
                    className={cn('h-4 w-4 ml-auto transition-transform', showValidation && 'rotate-180')}
                    style={{ color: showValidation ? 'var(--crit)' : 'var(--high)' }}
                  />
                </button>
                {showValidation && (
                  <ul className="mt-2 space-y-1 pl-6">
                    {validationErrors.map((err, idx) => (
                      <li key={idx} className="text-xs list-disc" style={{ color: 'var(--crit)' }}>
                        {err.message}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            {/* Valid query indicator */}
            {query.trim() && validationErrors.length === 0 && (
              <div className="flex items-center gap-2 px-3">
                <CheckCircle2 className="h-4 w-4" style={{ color: 'var(--emerald-400)' }} />
                <span className="text-xs" style={{ color: 'var(--emerald-400)' }}>Query syntax is valid</span>
              </div>
            )}

            {/* Controls row */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4 text-sm" style={{ color: 'var(--muted)' }}>
                <span>Time Range:</span>
                <Select value={timeRange} onValueChange={setTimeRange} placeholder="Time range">
                  <SelectItem value="1h">Last 1 hour</SelectItem>
                  <SelectItem value="6h">Last 6 hours</SelectItem>
                  <SelectItem value="24h">Last 24 hours</SelectItem>
                  <SelectItem value="7d">Last 7 days</SelectItem>
                  <SelectItem value="30d">Last 30 days</SelectItem>
                </Select>
              </div>
              <button
                type="button"
                onClick={handleRunQuery}
                disabled={isRunning || !query.trim()}
                className="flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors"
                style={{
                  background: (isRunning || !query.trim()) ? 'var(--surface-2)' : 'var(--emerald-600)',
                  color: (isRunning || !query.trim()) ? 'var(--dim)' : 'white',
                  cursor: (isRunning || !query.trim()) ? 'not-allowed' : 'pointer',
                }}
              >
                <Play className={cn('h-4 w-4', isRunning && 'animate-spin')} />
                {isRunning ? 'Running...' : 'Run Query'}
              </button>
            </div>
          </div>
        </div>

        {/* ================================================================ */}
        {/* Quick Queries / Saved Queries Card                               */}
        {/* ================================================================ */}
        <div className="rounded-xl p-6" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--fg)' }}>
            {loadedQueries.length > 0 ? 'Saved Queries' : 'Quick Queries'}
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {(loadedQueries.length > 0 ? loadedQueries : [
              { name: 'PowerShell', query: 'process.name:powershell.exe' },
              { name: 'Port 4444', query: 'network.remote_port:4444' },
              { name: 'Run Keys', query: 'registry.path:*\\Run\\*' },
              { name: 'LSASS', query: 'process.name:lsass.exe OR file.path:*\\lsass*' },
            ] as SavedQuery[]).slice(0, 8).map((sample, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setQuery(sample.query)
                  handleRunQueryWithValue(sample.query)
                }}
                className="flex items-start gap-3 p-3 rounded-lg text-left transition-colors group hover:opacity-80"
                style={{ background: 'var(--surface-2)' }}
              >
                <FileSearch className="h-5 w-5 mt-0.5 flex-shrink-0" style={{ color: 'var(--emerald-400)' }} />
                <div className="min-w-0 flex-1">
                  <p className="font-medium text-sm" style={{ color: 'var(--fg)' }}>{sample.name}</p>
                  {sample.description && (
                    <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--muted)' }}>{sample.description}</p>
                  )}
                  <p className="text-xs font-mono mt-1 truncate" style={{ color: 'var(--muted)' }}>{sample.query}</p>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* ================================================================ */}
        {/* Error Message                                                    */}
        {/* ================================================================ */}
        {error && (
          <div className="rounded-xl p-4" style={{ background: 'var(--crit-bg)', border: '1px solid var(--crit)' }}>
            <div className="flex items-center gap-3">
              <AlertCircle className="h-5 w-5 flex-shrink-0" style={{ color: 'var(--crit)' }} />
              <p style={{ color: 'var(--crit)' }}>{error}</p>
              <button
                type="button"
                onClick={() => setError(null)}
                className="ml-auto hover:opacity-80"
                style={{ color: 'var(--crit)' }}
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}

        {/* ================================================================ */}
        {/* Results                                                          */}
        {/* ================================================================ */}
        {results.length > 0 ? (
          <div className="rounded-xl" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
            <div className="p-4 flex justify-between items-center" style={{ borderBottom: '1px solid var(--border)' }}>
              <div className="flex items-center gap-4">
                <h2 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Results</h2>
                {meta && (
                  <div className="flex items-center gap-3">
                    <span className="text-sm" style={{ color: 'var(--muted)' }}>
                      {meta.total} result{meta.total !== 1 ? 's' : ''}
                      {meta.time_range && ` in ${meta.time_range}`}
                    </span>
                    {meta.query_type === 'tql' && meta.execution_time_ms && (
                      <span className="text-xs flex items-center gap-1" style={{ color: 'var(--dim)' }}>
                        <BarChart3 className="h-3 w-3" />
                        {meta.execution_time_ms}ms
                      </span>
                    )}
                    {meta.query_type === 'tql' && meta.page && (
                      <span className="text-xs" style={{ color: 'var(--dim)' }}>
                        Page {meta.page}
                      </span>
                    )}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={selectAllResults}
                  className="px-3 py-1.5 rounded text-sm transition-colors hover:opacity-80"
                  style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}
                >
                  {selectedResults.size === results.length ? 'Deselect All' : 'Select All'}
                </button>
                <ExportDropdown
                  getData={() => {
                    const dataToExport = selectedResults.size > 0
                      ? results.filter(r => selectedResults.has(r.id))
                      : results
                    return dataToExport.map(r => ({
                      id: r.id,
                      agent_id: r.agent_id,
                      agent_hostname: r.agent_hostname,
                      event_type: r.event_type,
                      timestamp: r.timestamp,
                      pid: r.pid,
                      process_name: r.process_name,
                      sha256: r.sha256,
                      remote_ip: r.remote_ip,
                      domain: r.domain,
                      path: r.path,
                      ...r.payload,
                    }))
                  }}
                  filenameBase="tamandua-hunt-results"
                  label={selectedResults.size > 0 ? `Export (${selectedResults.size})` : 'Export All'}
                  disabled={results.length === 0}
                />
              </div>
            </div>
            <div className="max-h-[600px] overflow-y-auto">
              {results.map(result => {
                const Icon = getEventIcon(result.event_type)
                const isSelected = selectedResults.has(result.id)
                const pid = result.pid || result.payload?.pid
                const processName = result.process_name || result.payload?.process_name || result.payload?.name
                const sha256 = result.sha256 || result.payload?.sha256
                const remoteIp = result.remote_ip || result.payload?.remote_ip
                const domain = result.domain || result.payload?.domain || result.payload?.query

                return (
                  <div
                    key={result.id}
                    className="p-4 transition-colors hover:opacity-90"
                    style={{
                      background: isSelected ? 'var(--emerald-glow)' : 'transparent',
                      borderBottom: '1px solid var(--hairline)',
                    }}
                  >
                    <div className="flex items-start gap-3">
                      <div className="mt-1">
                        <Checkbox
                          checked={isSelected}
                          onCheckedChange={() => toggleResultSelection(result.id)}
                          aria-label="Select hunt result"
                        />
                      </div>
                      <div className="p-2 rounded" style={{ background: 'var(--surface-2)' }}>
                        <Icon className="h-4 w-4" style={{ color: 'var(--muted)' }} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 mb-2">
                          <span
                            className="px-2 py-1 rounded text-xs font-medium"
                            style={{ background: 'var(--emerald-glow)', color: 'var(--emerald-400)' }}
                          >
                            {result.event_type}
                          </span>
                          <span className="text-sm" style={{ color: 'var(--muted)' }}>{result.agent_hostname}</span>
                          {pid && <span className="text-xs" style={{ color: 'var(--dim)' }}>PID: {pid}</span>}
                          <span className="text-sm ml-auto" style={{ color: 'var(--dim)' }}>
                            {new Date(result.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <div className="flex flex-wrap gap-2 mb-2">
                          {processName && (
                            <button
                              type="button"
                              onClick={() => huntForValue('process.name', processName)}
                              className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors hover:opacity-80"
                              style={{ background: 'var(--med-bg)', color: 'var(--med)' }}
                            >
                              <Cpu className="h-3 w-3" />
                              {processName}
                            </button>
                          )}
                          {remoteIp && (
                            <button
                              type="button"
                              onClick={() => huntForValue('network.remote_ip', remoteIp)}
                              className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors hover:opacity-80"
                              style={{ background: 'var(--emerald-glow)', color: 'var(--emerald-400)' }}
                            >
                              <Globe className="h-3 w-3" />
                              {remoteIp}
                            </button>
                          )}
                          {domain && (
                            <button
                              type="button"
                              onClick={() => huntForValue('dns.query', domain)}
                              className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors hover:opacity-80"
                              style={{ background: 'rgba(217, 70, 239, 0.12)', color: 'var(--sol-magenta)' }}
                            >
                              <Server className="h-3 w-3" />
                              {domain}
                            </button>
                          )}
                          {sha256 && (
                            <button
                              type="button"
                              onClick={() => huntForValue('file.sha256', sha256)}
                              className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-mono transition-colors hover:opacity-80"
                              style={{ background: 'var(--high-bg)', color: 'var(--high)' }}
                              title={sha256}
                            >
                              <File className="h-3 w-3" />
                              {sha256.substring(0, 12)}...
                            </button>
                          )}
                        </div>
                        <details className="group">
                          <summary className="text-xs cursor-pointer hover:opacity-80" style={{ color: 'var(--muted)' }}>
                            Show raw payload
                          </summary>
                          <pre
                            className="text-xs rounded p-3 overflow-x-auto mt-2 font-mono"
                            style={{ background: 'var(--bg)', color: 'var(--fg-2)' }}
                          >
                            {JSON.stringify(result.payload, null, 2)}
                          </pre>
                        </details>
                      </div>
                      <div className="flex items-center gap-1">
                        {pid && result.agent_id && (
                          <>
                            <button
                              type="button"
                              onClick={() => navigateToProcessTree(result)}
                              className="p-2 rounded transition-colors hover:opacity-80"
                              style={{ color: 'var(--muted)' }}
                              title="View in Process Tree"
                            >
                              <Cpu className="h-4 w-4" />
                            </button>
                            <button
                              type="button"
                              onClick={() => navigateToGraph(result)}
                              className="p-2 rounded transition-colors hover:opacity-80"
                              style={{ color: 'var(--muted)' }}
                              title="View Investigation Graph"
                            >
                              <Share2 className="h-4 w-4" />
                            </button>
                          </>
                        )}
                        <button
                          type="button"
                          onClick={() => router.visit(`/app/network?agent_id=${result.agent_id}`)}
                          className="p-2 rounded transition-colors hover:opacity-80"
                          style={{ color: 'var(--muted)' }}
                          title="View Network Activity"
                        >
                          <Globe className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>

            {/* TQL Pagination */}
            {queryMode === 'tql' && meta && (meta.has_more || tqlPage > 1) && (
              <div className="p-4 flex items-center justify-between" style={{ borderTop: '1px solid var(--border)' }}>
                <div className="text-sm" style={{ color: 'var(--muted)' }}>
                  Showing page {tqlPage} ({results.length} of {meta.total} total)
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleTqlPrevPage}
                    disabled={tqlPage <= 1 || isRunning}
                    className="px-3 py-1.5 rounded text-sm transition-colors"
                    style={{
                      background: 'var(--surface-2)',
                      color: (tqlPage <= 1 || isRunning) ? 'var(--dim)' : 'var(--fg-2)',
                      cursor: (tqlPage <= 1 || isRunning) ? 'not-allowed' : 'pointer',
                    }}
                  >
                    Previous
                  </button>
                  <button
                    type="button"
                    onClick={handleTqlNextPage}
                    disabled={!meta.has_more || isRunning}
                    className="px-3 py-1.5 rounded text-sm transition-colors"
                    style={{
                      background: (!meta.has_more || isRunning) ? 'var(--surface-2)' : 'var(--sol-magenta)',
                      color: (!meta.has_more || isRunning) ? 'var(--dim)' : 'white',
                      cursor: (!meta.has_more || isRunning) ? 'not-allowed' : 'pointer',
                    }}
                  >
                    Next Page
                  </button>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="rounded-xl p-12 text-center" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
            <Search className="h-16 w-16 mx-auto mb-4 opacity-50" style={{ color: 'var(--muted)' }} />
            <p className="text-lg" style={{ color: 'var(--muted)' }}>
              {isRunning ? 'Searching...' : 'No results yet'}
            </p>
            <p className="text-sm" style={{ color: 'var(--dim)' }}>
              {isRunning
                ? 'Please wait while we search through telemetry data'
                : 'Run a query to search through telemetry data'}
            </p>
          </div>
        )}
      </div>

      {/* ================================================================ */}
      {/* Save Query Modal                                                 */}
      {/* ================================================================ */}
      {showSaveModal && (
        <div className="fixed inset-0 flex items-center justify-center z-50" style={{ background: 'rgba(0,0,0,0.5)' }}>
          <div className="rounded-xl p-6 w-full max-w-md mx-4" style={{ background: 'var(--surface)', border: '1px solid var(--border)' }}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold" style={{ color: 'var(--fg)' }}>Save Query</h3>
              <button
                type="button"
                onClick={() => setShowSaveModal(false)}
                className="hover:opacity-80"
                style={{ color: 'var(--muted)' }}
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Query Name *</label>
                <input
                  type="text"
                  value={saveForm.name}
                  onChange={e => setSaveForm({ ...saveForm, name: e.target.value })}
                  placeholder="e.g., Suspicious PowerShell Activity"
                  className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2"
                  style={{
                    background: 'var(--surface-2)',
                    border: '1px solid var(--border)',
                    color: 'var(--fg)',
                  }}
                  autoFocus
                />
              </div>
              <div>
                <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Description</label>
                <textarea
                  value={saveForm.description}
                  onChange={e => setSaveForm({ ...saveForm, description: e.target.value })}
                  placeholder="What does this query detect?"
                  rows={2}
                  className="w-full rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 resize-none"
                  style={{
                    background: 'var(--surface-2)',
                    border: '1px solid var(--border)',
                    color: 'var(--fg)',
                  }}
                />
              </div>
              <div>
                <label className="block text-sm mb-1" style={{ color: 'var(--muted)' }}>Category (MITRE Tactic)</label>
                <Select
                  value={saveForm.category}
                  onValueChange={(v) => setSaveForm({ ...saveForm, category: v })}
                  placeholder="Select category..."
                  fullWidth
                >
                  {mitreCategories.map(cat => (
                    <SelectItem key={cat} value={cat}>{cat}</SelectItem>
                  ))}
                </Select>
              </div>
              <div>
                <label className="block text-sm mb-2" style={{ color: 'var(--muted)' }}>Query</label>
                <div className="flex items-center gap-2 mb-2">
                  <span
                    className="px-2 py-0.5 rounded text-xs font-medium"
                    style={{
                      background: queryMode === 'tql' ? 'rgba(217, 70, 239, 0.2)' : 'var(--emerald-glow)',
                      color: queryMode === 'tql' ? 'var(--sol-magenta)' : 'var(--emerald-400)',
                    }}
                  >
                    {queryMode === 'tql' ? 'TQL' : 'Simple'}
                  </span>
                </div>
                <pre
                  className="rounded-lg p-3 text-xs font-mono overflow-x-auto"
                  style={{ background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--fg-2)' }}
                >
                  {queryMode === 'tql' ? tqlQuery : query}
                </pre>
              </div>
              <Checkbox
                checked={saveForm.isPublic}
                onCheckedChange={(checked) => setSaveForm({ ...saveForm, isPublic: checked })}
                label="Share with team"
              />
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button
                type="button"
                onClick={() => setShowSaveModal(false)}
                className="px-4 py-2 rounded-lg text-sm transition-colors hover:opacity-80"
                style={{ background: 'var(--surface-2)', color: 'var(--fg-2)' }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={saveQuery}
                disabled={!saveForm.name.trim() || isSaving}
                className="px-4 py-2 rounded-lg text-sm font-medium transition-colors"
                style={{
                  background: (saveForm.name.trim() && !isSaving) ? 'var(--emerald-600)' : 'var(--surface-2)',
                  color: (saveForm.name.trim() && !isSaving) ? 'white' : 'var(--dim)',
                  cursor: (saveForm.name.trim() && !isSaving) ? 'pointer' : 'not-allowed',
                }}
              >
                {isSaving ? 'Saving...' : 'Save Query'}
              </button>
            </div>
          </div>
        </div>
      )}
    </MainLayout>
  )
}
