import { Head, Link, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  ArrowLeft,
  Building2,
  Crown,
  Briefcase,
  Rocket,
  Sparkles,
  Check,
  Loader2,
  Info,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useState } from 'react'
import type { PageProps, TenantPlan } from '@/types'

const plans: Array<{
  id: TenantPlan
  name: string
  description: string
  icon: React.ComponentType<{ className?: string }>
  color: string
  limits: {
    agents: number
    users: number
    eventsPerDay: number
    retentionDays: number
  }
  features: string[]
}> = [
  {
    id: 'trial',
    name: 'Trial',
    description: '14-day free trial with limited features',
    icon: Sparkles,
    color: 'purple',
    limits: { agents: 5, users: 3, eventsPerDay: 10000, retentionDays: 7 },
    features: ['Basic detection', 'Email alerts', 'Community support'],
  },
  {
    id: 'starter',
    name: 'Starter',
    description: 'For small teams getting started',
    icon: Rocket,
    color: 'blue',
    limits: { agents: 25, users: 10, eventsPerDay: 100000, retentionDays: 30 },
    features: ['ML detection', 'Response actions', 'Email support', 'API access'],
  },
  {
    id: 'professional',
    name: 'Professional',
    description: 'For growing organizations',
    icon: Briefcase,
    color: 'emerald',
    limits: { agents: 100, users: 50, eventsPerDay: 1000000, retentionDays: 90 },
    features: ['Advanced ML', 'Custom playbooks', 'SSO', 'Priority support', 'Threat intelligence'],
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    description: 'For large-scale deployments',
    icon: Crown,
    color: 'amber',
    limits: { agents: -1, users: -1, eventsPerDay: -1, retentionDays: 365 },
    features: ['Unlimited agents', 'Unlimited users', 'Custom retention', 'Dedicated support', 'On-premise option', 'Custom integrations'],
  },
]

interface TenantCreateProps extends PageProps {
  // Any props passed from backend
}

export default function TenantCreate({}: TenantCreateProps) {
  const [step, setStep] = useState(1)
  const [selectedPlan, setSelectedPlan] = useState<TenantPlan>('professional')
  const [formData, setFormData] = useState({
    name: '',
    slug: '',
    domain: '',
    admin_email: '',
    admin_name: '',
  })
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [submitting, setSubmitting] = useState(false)

  const handleInputChange = (field: keyof typeof formData, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }))

    // Auto-generate slug from name
    if (field === 'name') {
      const slug = value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '')
      setFormData(prev => ({ ...prev, slug }))
    }

    // Clear error when user types
    if (errors[field]) {
      setErrors(prev => {
        const next = { ...prev }
        delete next[field]
        return next
      })
    }
  }

  const validateStep1 = () => {
    const newErrors: Record<string, string> = {}

    if (!formData.name.trim()) {
      newErrors.name = 'Tenant name is required'
    } else if (formData.name.length < 2) {
      newErrors.name = 'Tenant name must be at least 2 characters'
    }

    if (!formData.slug.trim()) {
      newErrors.slug = 'Slug is required'
    } else if (!/^[a-z0-9-]+$/.test(formData.slug)) {
      newErrors.slug = 'Slug can only contain lowercase letters, numbers, and hyphens'
    }

    if (formData.domain && !/^[a-z0-9][a-z0-9.-]*[a-z0-9]\.[a-z]{2,}$/i.test(formData.domain)) {
      newErrors.domain = 'Invalid domain format'
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const validateStep2 = () => {
    const newErrors: Record<string, string> = {}

    if (!formData.admin_email.trim()) {
      newErrors.admin_email = 'Admin email is required'
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.admin_email)) {
      newErrors.admin_email = 'Invalid email format'
    }

    if (!formData.admin_name.trim()) {
      newErrors.admin_name = 'Admin name is required'
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleNext = () => {
    if (step === 1 && validateStep1()) {
      setStep(2)
    } else if (step === 2 && validateStep2()) {
      setStep(3)
    }
  }

  const handleBack = () => {
    setStep(prev => Math.max(1, prev - 1))
  }

  const handleSubmit = async () => {
    setSubmitting(true)

    try {
      const response = await fetch('/api/v1/admin/tenants', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          name: formData.name,
          slug: formData.slug,
          domain: formData.domain || null,
          plan: selectedPlan,
          admin_email: formData.admin_email,
          admin_name: formData.admin_name,
        }),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || 'Failed to create tenant')
      }

      const data = await response.json()
      router.visit(`/app/admin/tenants/${data.tenant.id}`)
    } catch (err) {
      setErrors({
        submit: err instanceof Error ? err.message : 'Failed to create tenant',
      })
    } finally {
      setSubmitting(false)
    }
  }

  const selectedPlanDetails = plans.find(p => p.id === selectedPlan)!

  return (
    <MainLayout title="Create Tenant">
      <Head title="Create Tenant - Admin - Tamandua EDR" />

      <div className="max-w-3xl mx-auto">
        <Link
          href="/app/admin/tenants"
          className="flex items-center gap-2 text-sm text-slate-400 hover:text-white mb-6"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Tenants
        </Link>

        {/* Progress Steps */}
        <div className="flex items-center justify-center mb-8">
          {[1, 2, 3].map((s) => (
            <div key={s} className="flex items-center">
              <div
                className={cn(
                  'h-10 w-10 rounded-full flex items-center justify-center font-semibold text-sm transition-colors',
                  step >= s
                    ? 'bg-primary-600 text-white'
                    : 'bg-slate-700 text-slate-400'
                )}
              >
                {step > s ? <Check className="h-5 w-5" /> : s}
              </div>
              {s < 3 && (
                <div
                  className={cn(
                    'w-24 h-1 mx-2',
                    step > s ? 'bg-primary-600' : 'bg-slate-700'
                  )}
                />
              )}
            </div>
          ))}
        </div>

        {/* Step 1: Basic Info */}
        {step === 1 && (
          <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
            <h2 className="text-xl font-semibold text-white mb-1">Tenant Information</h2>
            <p className="text-sm text-slate-400 mb-6">Basic details about the new tenant organization</p>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">
                  Tenant Name *
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => handleInputChange('name', e.target.value)}
                  className={cn(
                    'w-full bg-slate-700 border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent',
                    errors.name ? 'border-red-500' : 'border-slate-600'
                  )}
                  placeholder="Acme Corporation"
                />
                {errors.name && <p className="text-sm text-red-400 mt-1">{errors.name}</p>}
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">
                  Slug *
                </label>
                <div className="flex items-center gap-2">
                  <span className="text-slate-500 text-sm">treantlab.org/</span>
                  <input
                    type="text"
                    value={formData.slug}
                    onChange={(e) => handleInputChange('slug', e.target.value.toLowerCase())}
                    className={cn(
                      'flex-1 bg-slate-700 border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent',
                      errors.slug ? 'border-red-500' : 'border-slate-600'
                    )}
                    placeholder="acme-corp"
                  />
                </div>
                {errors.slug && <p className="text-sm text-red-400 mt-1">{errors.slug}</p>}
                <p className="text-xs text-slate-500 mt-1">
                  Used in URLs and as a unique identifier
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">
                  Custom Domain (optional)
                </label>
                <input
                  type="text"
                  value={formData.domain}
                  onChange={(e) => handleInputChange('domain', e.target.value)}
                  className={cn(
                    'w-full bg-slate-700 border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent',
                    errors.domain ? 'border-red-500' : 'border-slate-600'
                  )}
                  placeholder="edr.acme.com"
                />
                {errors.domain && <p className="text-sm text-red-400 mt-1">{errors.domain}</p>}
                <p className="text-xs text-slate-500 mt-1">
                  Configure custom domain for white-label access
                </p>
              </div>
            </div>

            <div className="flex justify-end mt-6">
              <button
                onClick={handleNext}
                className="bg-primary-600 hover:bg-primary-700 text-white px-6 py-2 rounded-lg font-medium"
              >
                Continue
              </button>
            </div>
          </div>
        )}

        {/* Step 2: Admin User */}
        {step === 2 && (
          <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
            <h2 className="text-xl font-semibold text-white mb-1">Primary Administrator</h2>
            <p className="text-sm text-slate-400 mb-6">
              This user will be the tenant admin and primary contact
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">
                  Admin Name *
                </label>
                <input
                  type="text"
                  value={formData.admin_name}
                  onChange={(e) => handleInputChange('admin_name', e.target.value)}
                  className={cn(
                    'w-full bg-slate-700 border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent',
                    errors.admin_name ? 'border-red-500' : 'border-slate-600'
                  )}
                  placeholder="John Smith"
                />
                {errors.admin_name && <p className="text-sm text-red-400 mt-1">{errors.admin_name}</p>}
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1">
                  Admin Email *
                </label>
                <input
                  type="email"
                  value={formData.admin_email}
                  onChange={(e) => handleInputChange('admin_email', e.target.value)}
                  className={cn(
                    'w-full bg-slate-700 border rounded-lg px-4 py-2 text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent',
                    errors.admin_email ? 'border-red-500' : 'border-slate-600'
                  )}
                  placeholder="admin@acme.com"
                />
                {errors.admin_email && <p className="text-sm text-red-400 mt-1">{errors.admin_email}</p>}
                <p className="text-xs text-slate-500 mt-1">
                  An invitation will be sent to this email address
                </p>
              </div>
            </div>

            <div className="flex justify-between mt-6">
              <button
                onClick={handleBack}
                className="text-slate-400 hover:text-white px-4 py-2"
              >
                Back
              </button>
              <button
                onClick={handleNext}
                className="bg-primary-600 hover:bg-primary-700 text-white px-6 py-2 rounded-lg font-medium"
              >
                Continue
              </button>
            </div>
          </div>
        )}

        {/* Step 3: Select Plan */}
        {step === 3 && (
          <div className="space-y-6">
            <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
              <h2 className="text-xl font-semibold text-white mb-1">Select Plan</h2>
              <p className="text-sm text-slate-400 mb-6">Choose the subscription plan for this tenant</p>

              <div className="grid grid-cols-2 gap-4">
                {plans.map((plan) => {
                  const Icon = plan.icon
                  const isSelected = selectedPlan === plan.id

                  return (
                    <button
                      key={plan.id}
                      onClick={() => setSelectedPlan(plan.id)}
                      className={cn(
                        'p-4 rounded-xl border-2 text-left transition-colors',
                        isSelected
                          ? `border-${plan.color}-500 bg-${plan.color}-500/10`
                          : 'border-slate-600 hover:border-slate-500'
                      )}
                    >
                      <div className="flex items-center gap-3 mb-2">
                        <Icon className={cn(
                          'h-6 w-6',
                          `text-${plan.color}-400`
                        )} />
                        <span className="text-lg font-semibold text-white">{plan.name}</span>
                        {isSelected && (
                          <Check className={cn('h-5 w-5 ml-auto', `text-${plan.color}-400`)} />
                        )}
                      </div>
                      <p className="text-sm text-slate-400">{plan.description}</p>
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Plan Details */}
            <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
              <h3 className="text-lg font-semibold text-white mb-4">
                {selectedPlanDetails.name} Plan Details
              </h3>

              <div className="grid grid-cols-2 gap-6">
                <div>
                  <h4 className="text-sm font-medium text-slate-400 mb-3">Limits</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-300">Agents</span>
                      <span className="text-white font-medium">
                        {selectedPlanDetails.limits.agents === -1 ? 'Unlimited' : selectedPlanDetails.limits.agents}
                      </span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-300">Users</span>
                      <span className="text-white font-medium">
                        {selectedPlanDetails.limits.users === -1 ? 'Unlimited' : selectedPlanDetails.limits.users}
                      </span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-300">Events/Day</span>
                      <span className="text-white font-medium">
                        {selectedPlanDetails.limits.eventsPerDay === -1 ? 'Unlimited' : selectedPlanDetails.limits.eventsPerDay.toLocaleString()}
                      </span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-300">Retention</span>
                      <span className="text-white font-medium">
                        {selectedPlanDetails.limits.retentionDays} days
                      </span>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="text-sm font-medium text-slate-400 mb-3">Features</h4>
                  <ul className="space-y-2">
                    {selectedPlanDetails.features.map((feature, i) => (
                      <li key={i} className="flex items-center gap-2 text-sm text-slate-300">
                        <Check className="h-4 w-4 text-green-400" />
                        {feature}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>

            {/* Summary */}
            <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
              <h3 className="text-lg font-semibold text-white mb-4">Review</h3>

              <div className="space-y-3 mb-6">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400">Tenant Name</span>
                  <span className="text-white">{formData.name}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400">Slug</span>
                  <span className="text-white">{formData.slug}</span>
                </div>
                {formData.domain && (
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Domain</span>
                    <span className="text-white">{formData.domain}</span>
                  </div>
                )}
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400">Plan</span>
                  <span className="text-white capitalize">{selectedPlan}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400">Admin</span>
                  <span className="text-white">{formData.admin_name} ({formData.admin_email})</span>
                </div>
              </div>

              {errors.submit && (
                <div className="p-4 bg-red-900/30 border border-red-700 rounded-lg mb-4">
                  <p className="text-sm text-red-300">{errors.submit}</p>
                </div>
              )}

              <div className="flex items-center gap-3 p-3 bg-blue-900/30 border border-blue-700 rounded-lg mb-6">
                <Info className="h-5 w-5 text-blue-400 flex-shrink-0" />
                <p className="text-sm text-blue-300">
                  The admin will receive an email invitation to set up their account and access the tenant.
                </p>
              </div>

              <div className="flex justify-between">
                <button
                  onClick={handleBack}
                  disabled={submitting}
                  className="text-slate-400 hover:text-white px-4 py-2 disabled:opacity-50"
                >
                  Back
                </button>
                <button
                  onClick={handleSubmit}
                  disabled={submitting}
                  className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white px-6 py-2 rounded-lg font-medium disabled:opacity-50"
                >
                  {submitting ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Creating...
                    </>
                  ) : (
                    <>
                      <Building2 className="h-4 w-4" />
                      Create Tenant
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </MainLayout>
  )
}
