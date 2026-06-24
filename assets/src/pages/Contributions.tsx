import { Head } from '@inertiajs/react'
import { useEffect, useState } from 'react'
import {
  Award,
  CheckCircle2,
  Clock,
  Crown,
  Eye,
  ExternalLink,
  FileCode,
  Gift,
  Loader2,
  Plus,
  Shield,
  ShieldCheck,
  Star,
  Trophy,
  Users,
  XCircle,
  Zap,
} from 'lucide-react'
import { MainLayout } from '@/layouts/MainLayout'
import { cn } from '@/lib/utils'

// Types
interface Submission {
  id: string
  type: 'sigma' | 'yara' | 'config'
  ruleName: string
  status: 'accepted' | 'in_review' | 'rejected'
  solReward: number
  rank: number | null
  submittedAt: number
}

interface Bounty {
  id: string
  category: 'sigma' | 'yara' | 'config'
  tier: 'free' | 'paid'
  solAmount: number | null
  title: string
  description: string
  author: string
  coverageTags: string[]
  fpRisk: number
  validationScore: number
}

interface LeaderboardEntry {
  rank: number
  wallet: string
  submissions: number
  accepted: number
  totalEarned: number
}

interface ContributionsProps {
  submissions?: Submission[]
  bounties?: Bounty[]
  leaderboard?: LeaderboardEntry[]
  stats?: {
    your_submissions: number
    accepted: number
    total_earned: number
  }
}

// Helper components
function TypeBadge({ type }: { type: 'sigma' | 'yara' | 'config' }) {
  const config = {
    sigma: { label: 'Sigma', color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
    yara: { label: 'YARA', color: 'bg-amber-500/20 text-amber-400 border-amber-500/30' },
    config: { label: 'Config', color: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30' },
  }
  const { label, color } = config[type]
  return (
    <span className={cn('rounded-full border px-2 py-0.5 text-xs font-medium', color)}>
      {label}
    </span>
  )
}

function StatusBadge({ status }: { status: 'accepted' | 'in_review' | 'rejected' }) {
  const config = {
    accepted: {
      label: 'Accepted',
      icon: CheckCircle2,
      color: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    },
    in_review: {
      label: 'In Review',
      icon: Clock,
      color: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    },
    rejected: {
      label: 'Rejected',
      icon: XCircle,
      color: 'bg-red-500/20 text-red-400 border-red-500/30',
    },
  }
  const { label, icon: Icon, color } = config[status]
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium', color)}>
      <Icon className="h-3 w-3" />
      {label}
    </span>
  )
}

function SolAmount({ amount }: { amount: number }) {
  return (
    <span className="inline-flex items-center gap-1 font-medium" style={{ color: 'var(--emerald-400)' }}>
      <span className="text-sm">{amount.toFixed(2)}</span>
      <span className="text-xs opacity-75">SOL</span>
    </span>
  )
}

function formatRelativeTime(timestamp?: number | null): string {
  if (!timestamp) return '-'
  const now = Date.now()
  const diff = now - timestamp
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return `${Math.floor(diff / 86400000)}d ago`
}

function FPRiskBar({ value }: { value: number }) {
  const percentage = Math.min(value * 100, 100)
  const color = value <= 0.03 ? 'var(--emerald-400)' : value <= 0.06 ? 'var(--high)' : 'var(--crit)'
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 rounded-full" style={{ backgroundColor: 'var(--surface-3)' }}>
        <div
          className="h-full rounded-full"
          style={{ width: `${percentage * 10}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-xs font-mono" style={{ color }}>{value.toFixed(2)}</span>
    </div>
  )
}

// Tab components
function YourSubmissionsTab({ submissions }: { submissions: Submission[] }) {
  return (
    <div className="card-sentinel overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--hairline)' }}>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Type</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Rule Name</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Status</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>SOL Reward</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Rank</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Submitted</th>
            </tr>
          </thead>
          <tbody>
            {submissions.map((submission) => (
              <tr
                key={submission.id}
                className="transition-colors"
                style={{ borderBottom: '1px solid var(--hairline)' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent'
                }}
              >
                <td className="px-4 py-3">
                  <TypeBadge type={submission.type} />
                </td>
                <td className="px-4 py-3">
                  <span className="font-medium" style={{ color: 'var(--fg)' }}>{submission.ruleName}</span>
                </td>
                <td className="px-4 py-3">
                  <StatusBadge status={submission.status} />
                </td>
                <td className="px-4 py-3">
                  {submission.solReward > 0 ? (
                    <SolAmount amount={submission.solReward} />
                  ) : (
                    <span style={{ color: 'var(--muted)' }}>-</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  {submission.rank ? (
                    <span className="font-medium" style={{ color: 'var(--fg)' }}>#{submission.rank}</span>
                  ) : (
                    <span style={{ color: 'var(--muted)' }}>-</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className="text-sm" style={{ color: 'var(--muted)' }}>
                    {formatRelativeTime(submission.submittedAt)}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {submissions.length === 0 && (
        <div className="py-12 text-center" style={{ color: 'var(--muted)' }}>
          <FileCode className="mx-auto h-12 w-12 opacity-50" />
          <p className="mt-3">No submissions yet</p>
          <p className="mt-1 text-sm">Submit your first detection rule to start earning</p>
        </div>
      )}
    </div>
  )
}

function BountyCard({ bounty }: { bounty: Bounty }) {
  return (
    <div
      className="card-sentinel rounded-lg border p-4 transition-all"
      style={{ borderColor: 'var(--hairline)', backgroundColor: 'var(--surface)' }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = 'var(--emerald-500)'
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = 'var(--hairline)'
      }}
    >
      {/* Header with badges */}
      <div className="flex items-start justify-between">
        <TypeBadge type={bounty.category} />
        {bounty.tier === 'paid' && bounty.solAmount ? (
          <div className="flex items-center gap-1 rounded-full px-2 py-0.5" style={{ backgroundColor: 'var(--emerald-glow)' }}>
            <Gift className="h-3 w-3" style={{ color: 'var(--emerald-400)' }} />
            <SolAmount amount={bounty.solAmount} />
          </div>
        ) : (
          <span className="rounded-full px-2 py-0.5 text-xs font-medium" style={{ backgroundColor: 'var(--surface-2)', color: 'var(--muted)' }}>
            Free
          </span>
        )}
      </div>

      {/* Title and description */}
      <h3 className="mt-3 font-semibold" style={{ color: 'var(--fg)' }}>{bounty.title}</h3>
      <p className="mt-1 line-clamp-2 text-sm" style={{ color: 'var(--muted)' }}>{bounty.description}</p>

      {/* Author */}
      <div className="mt-3 flex items-center gap-2">
        <div className="h-5 w-5 rounded-full" style={{ backgroundColor: 'var(--surface-3)' }} />
        <span className="font-mono text-xs" style={{ color: 'var(--subtle)' }}>{bounty.author}</span>
      </div>

      {/* Coverage tags */}
      <div className="mt-3 flex flex-wrap gap-1">
        {bounty.coverageTags.map((tag) => (
          <span
            key={tag}
            className="rounded px-2 py-0.5 text-xs font-medium uppercase"
            style={{ backgroundColor: 'var(--surface-2)', color: 'var(--subtle)' }}
          >
            {tag}
          </span>
        ))}
      </div>

      {/* Metrics */}
      <div className="mt-4 flex items-center justify-between border-t pt-4" style={{ borderColor: 'var(--hairline)' }}>
        <div className="flex items-center gap-4">
          <div>
            <p className="text-xs uppercase" style={{ color: 'var(--subtle)' }}>FP Risk</p>
            <FPRiskBar value={bounty.fpRisk} />
          </div>
          <div>
            <p className="text-xs uppercase" style={{ color: 'var(--subtle)' }}>Validation</p>
            <span className="font-medium text-indigo-400">{bounty.validationScore}</span>
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="mt-4 flex gap-2">
        <button
          className="flex flex-1 items-center justify-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-colors"
          style={{ backgroundColor: 'var(--surface-2)', color: 'var(--fg-2)' }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = 'var(--surface-3)'
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'var(--surface-2)'
          }}
        >
          <Eye className="h-4 w-4" />
          Preview
        </button>
        <button
          className="flex flex-1 items-center justify-center gap-2 rounded-lg px-3 py-2 text-sm font-medium text-white transition-colors"
          style={{ backgroundColor: 'var(--emerald-500)' }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = 'var(--emerald-600)'
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'var(--emerald-500)'
          }}
        >
          <Zap className="h-4 w-4" />
          Install
        </button>
      </div>
    </div>
  )
}

function AvailableBountiesTab({ bounties }: { bounties: Bounty[] }) {
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
      {bounties.map((bounty) => (
        <BountyCard key={bounty.id} bounty={bounty} />
      ))}
      {bounties.length === 0 && (
        <div className="card-sentinel p-8 text-center md:col-span-2 lg:col-span-3" style={{ color: 'var(--muted)' }}>
          <Gift className="mx-auto h-10 w-10 opacity-50" />
          <p className="mt-3">No bounty-eligible submissions yet</p>
        </div>
      )}
    </div>
  )
}

function LeaderboardTab({ leaderboard }: { leaderboard: LeaderboardEntry[] }) {
  return (
    <div className="card-sentinel overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--hairline)' }}>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Rank</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Contributor</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Submissions</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Accepted</th>
              <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>Total Earned</th>
            </tr>
          </thead>
          <tbody>
            {leaderboard.map((entry) => (
              <tr
                key={entry.rank}
                className="transition-colors"
                style={{ borderBottom: '1px solid var(--hairline)' }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = 'var(--surface-2)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent'
                }}
              >
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    {entry.rank <= 3 ? (
                      <Crown
                        className="h-5 w-5"
                        style={{
                          color: entry.rank === 1 ? '#FFD700' : entry.rank === 2 ? '#C0C0C0' : '#CD7F32',
                        }}
                      />
                    ) : (
                      <span className="w-5 text-center font-medium" style={{ color: 'var(--muted)' }}>{entry.rank}</span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className="font-mono text-sm" style={{ color: 'var(--fg)' }}>{entry.wallet}</span>
                </td>
                <td className="px-4 py-3">
                  <span style={{ color: 'var(--fg-2)' }}>{entry.submissions}</span>
                </td>
                <td className="px-4 py-3">
                  <span style={{ color: 'var(--emerald-400)' }}>{entry.accepted}</span>
                </td>
                <td className="px-4 py-3">
                  <SolAmount amount={entry.totalEarned} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {leaderboard.length === 0 && (
        <div className="py-12 text-center" style={{ color: 'var(--muted)' }}>
          <Trophy className="mx-auto h-12 w-12 opacity-50" />
          <p className="mt-3">No paid bounty claims yet</p>
        </div>
      )}
    </div>
  )
}

// Sidebar component
function Sidebar({ stats }: { stats: ContributionsProps['stats'] }) {
  const userStats = stats ?? { your_submissions: 0, accepted: 0, total_earned: 0 }
  return (
    <div className="space-y-4">
      {/* Submit CTA */}
      <div className="card-sentinel p-4">
        <button
          className="flex w-full items-center justify-center gap-2 rounded-lg px-4 py-3 text-sm font-semibold text-white transition-colors"
          style={{ backgroundColor: 'var(--emerald-500)' }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = 'var(--emerald-600)'
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'var(--emerald-500)'
          }}
        >
          <Plus className="h-5 w-5" />
          Submit a detection
        </button>
      </div>

      {/* User Stats */}
      <div className="card-sentinel p-4">
        <h3 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--subtle)' }}>
          Your Stats
        </h3>
        <div className="mt-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm" style={{ color: 'var(--muted)' }}>Submissions</span>
            <span className="font-semibold" style={{ color: 'var(--fg)' }}>{userStats.your_submissions}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm" style={{ color: 'var(--muted)' }}>Accepted</span>
            <span className="font-semibold" style={{ color: 'var(--emerald-400)' }}>{userStats.accepted}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm" style={{ color: 'var(--muted)' }}>Total Earned</span>
            <SolAmount amount={userStats.total_earned} />
          </div>
        </div>
      </div>

      {/* Guidelines Link */}
      <div className="card-sentinel p-4">
        <a
          href="#"
          className="flex items-center gap-2 text-sm font-medium transition-colors"
          style={{ color: 'var(--emerald-400)' }}
          onMouseEnter={(e) => {
            e.currentTarget.style.color = 'var(--emerald-300)'
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.color = 'var(--emerald-400)'
          }}
        >
          <ExternalLink className="h-4 w-4" />
          Contribution Guidelines
        </a>
        <p className="mt-2 text-xs" style={{ color: 'var(--muted)' }}>
          Learn about submission requirements, reward tiers, and best practices.
        </p>
      </div>
    </div>
  )
}

// Main component
export default function Contributions({
  submissions = [],
  bounties = [],
  leaderboard = [],
  stats,
}: ContributionsProps) {
  const [activeTab, setActiveTab] = useState<'submissions' | 'bounties' | 'leaderboard'>('submissions')

  useEffect(() => {
    if (window.location.hash === '#leaderboard') {
      setActiveTab('leaderboard')
    }
  }, [])

  const tabs = [
    { id: 'submissions' as const, label: 'Your Submissions', icon: FileCode },
    { id: 'bounties' as const, label: 'Available Bounties', icon: Gift },
    { id: 'leaderboard' as const, label: 'Leaderboard', icon: Trophy },
  ]

  return (
    <MainLayout title="Contributions & Bounties">
      <Head title="Contributions & Bounties" />

      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg" style={{ background: 'var(--emerald-glow)' }}>
                <Award className="h-8 w-8" style={{ color: 'var(--emerald-400)' }} />
              </div>
              <div>
                <h1 className="text-2xl font-semibold" style={{ color: 'var(--fg)' }}>Contributions & Bounties</h1>
                <p className="text-sm" style={{ color: 'var(--muted)' }}>
                  Submit detection rules and earn SOL rewards
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Main content with sidebar */}
        <div className="grid gap-6 lg:grid-cols-[1fr_280px]">
          {/* Main area */}
          <div className="space-y-6">
            {/* Tabs */}
            <div className="flex gap-2 border-b" style={{ borderColor: 'var(--hairline)' }}>
              {tabs.map((tab) => {
                const Icon = tab.icon
                const isActive = activeTab === tab.id
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={cn(
                      'flex items-center gap-2 px-4 py-3 text-sm font-medium transition-colors -mb-px',
                      isActive
                        ? 'border-b-2'
                        : 'opacity-60 hover:opacity-100'
                    )}
                    style={{
                      color: isActive ? 'var(--emerald-400)' : 'var(--fg-2)',
                      borderColor: isActive ? 'var(--emerald-400)' : 'transparent',
                    }}
                  >
                    <Icon className="h-4 w-4" />
                    {tab.label}
                  </button>
                )
              })}
            </div>

            {/* Tab content */}
            {activeTab === 'submissions' && <YourSubmissionsTab submissions={submissions} />}
            {activeTab === 'bounties' && <AvailableBountiesTab bounties={bounties} />}
            {activeTab === 'leaderboard' && <LeaderboardTab leaderboard={leaderboard} />}
          </div>

          {/* Right sidebar */}
          <Sidebar stats={stats} />
        </div>
      </div>
    </MainLayout>
  )
}
