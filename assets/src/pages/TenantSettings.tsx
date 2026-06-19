import { Head, router } from '@inertiajs/react'
import { MainLayout } from '@/layouts/MainLayout'
import {
  Building2,
  Palette,
  Shield,
  Key,
  CreditCard,
  Save,
  Loader2,
  Upload,
  Copy,
  Plus,
  Trash2,
  Eye,
  EyeOff,
  CheckCircle,
  XCircle,
  AlertCircle,
  ExternalLink,
  RefreshCw,
  Info,
} from 'lucide-react'
import { cn, safeInitial } from '@/lib/utils'
import { logger } from '@/lib/logger'
import { useState, useRef } from 'react'
import { Select, SelectItem } from '@/components/ui/baseui'
import type { TenantSettingsPageProps, APIKey, TenantSettings as TenantSettingsType } from '@/types'

const tabs = [
  { id: 'branding', label: 'Branding', icon: Palette },
  { id: 'security', label: 'Security & SSO', icon: Shield },
  { id: 'api', label: 'API Keys', icon: Key },
  { id: 'license', label: 'License & Billing', icon: CreditCard },
]

function BrandingTab({ tenant, settings, onSave }: {
  tenant: TenantSettingsPageProps['tenant']
  settings: TenantSettingsType
  onSave: (data: Partial<TenantSettingsType>) => Promise<void>
}) {
  const [logoUrl, setLogoUrl] = useState(settings.logo_url || '')
  const [primaryColor, setPrimaryColor] = useState(settings.primary_color || '#6366f1')
  const [secondaryColor, setSecondaryColor] = useState(settings.secondary_color || '#10b981')
  const [faviconUrl, setFaviconUrl] = useState(settings.favicon_url || '')
  const [customCss, setCustomCss] = useState(settings.custom_css || '')
  const [saving, setSaving] = useState(false)

  const handleSave = async () => {
    setSaving(true)
    try {
      await onSave({
        logo_url: logoUrl || undefined,
        primary_color: primaryColor,
        secondary_color: secondaryColor,
        favicon_url: faviconUrl || undefined,
        custom_css: customCss || undefined,
      })
    } finally {
      setSaving(false)
    }
  }

  // Preview initials for tenant logo
  const initials = tenant.name
    .split(' ')
    .map(word => word[0])
    .slice(0, 2)
    .join('')
    .toUpperCase()

  return (
    <div className="space-y-6">
      {/* Logo & Colors */}
      <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] p-6">
        <h3 className="text-lg font-semibold text-[var(--fg)] mb-4">Logo & Colors</h3>

        <div className="grid grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-2">Logo</label>
            <div className="flex items-start gap-4">
              <div
                className="h-20 w-20 rounded-xl flex items-center justify-center text-white text-2xl font-bold bg-cover bg-center"
                style={{
                  backgroundColor: logoUrl ? 'transparent' : primaryColor,
                  backgroundImage: logoUrl ? `url(${logoUrl})` : undefined,
                }}
              >
                {!logoUrl && initials}
              </div>
              <div className="flex-1">
                <input
                  type="url"
                  value={logoUrl}
                  onChange={(e) => setLogoUrl(e.target.value)}
                  className="w-full bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] text-sm focus:ring-2 focus:ring-primary-500"
                  placeholder="https://example.com/logo.png"
                />
                <p className="text-xs text-[var(--muted)] mt-1">Recommended: 200x200px, PNG or SVG</p>
              </div>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-2">Favicon</label>
            <input
              type="url"
              value={faviconUrl}
              onChange={(e) => setFaviconUrl(e.target.value)}
              className="w-full bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] text-sm focus:ring-2 focus:ring-primary-500"
              placeholder="https://example.com/favicon.ico"
            />
            <p className="text-xs text-[var(--muted)] mt-1">Browser tab icon (16x16 or 32x32)</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-2">Primary Color</label>
            <div className="flex items-center gap-3">
              <input
                type="color"
                value={primaryColor}
                onChange={(e) => setPrimaryColor(e.target.value)}
                className="h-10 w-14 rounded cursor-pointer bg-[var(--surface-hover)] border border-[var(--surface-border)]"
              />
              <input
                type="text"
                value={primaryColor}
                onChange={(e) => setPrimaryColor(e.target.value)}
                className="flex-1 bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] text-sm focus:ring-2 focus:ring-primary-500 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-2">Secondary Color</label>
            <div className="flex items-center gap-3">
              <input
                type="color"
                value={secondaryColor}
                onChange={(e) => setSecondaryColor(e.target.value)}
                className="h-10 w-14 rounded cursor-pointer bg-[var(--surface-hover)] border border-[var(--surface-border)]"
              />
              <input
                type="text"
                value={secondaryColor}
                onChange={(e) => setSecondaryColor(e.target.value)}
                className="flex-1 bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] text-sm focus:ring-2 focus:ring-primary-500 font-mono"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Custom CSS */}
      <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] p-6">
        <h3 className="text-lg font-semibold text-[var(--fg)] mb-2">Custom CSS</h3>
        <p className="text-sm text-[var(--muted)] mb-4">Add custom styles for advanced branding (enterprise feature)</p>

        <textarea
          value={customCss}
          onChange={(e) => setCustomCss(e.target.value)}
          rows={6}
          className="w-full bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-3 text-[var(--fg)] text-sm font-mono focus:ring-2 focus:ring-primary-500"
          placeholder="/* Custom CSS styles */"
        />
      </div>

      {/* Preview */}
      <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] p-6">
        <h3 className="text-lg font-semibold text-[var(--fg)] mb-4">Preview</h3>

        <div className="bg-[var(--surface-inset)] rounded-lg p-4">
          <div className="flex items-center gap-3 mb-4">
            <div
              className="h-10 w-10 rounded-lg flex items-center justify-center text-white font-bold bg-cover bg-center"
              style={{
                backgroundColor: logoUrl ? 'transparent' : primaryColor,
                backgroundImage: logoUrl ? `url(${logoUrl})` : undefined,
              }}
            >
              {!logoUrl && initials[0]}
            </div>
            <span className="text-lg font-semibold text-[var(--fg)]">{tenant.name}</span>
          </div>

          <div className="flex items-center gap-3">
            <button
              className="px-4 py-2 rounded-lg text-white text-sm font-medium"
              style={{ backgroundColor: primaryColor }}
            >
              Primary Button
            </button>
            <button
              className="px-4 py-2 rounded-lg text-white text-sm font-medium"
              style={{ backgroundColor: secondaryColor }}
            >
              Secondary Button
            </button>
          </div>
        </div>
      </div>

      <div className="flex justify-end">
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg font-medium disabled:opacity-50"
        >
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </div>
  )
}

function SecurityTab({ settings, availableProviders, onSave }: {
  settings: TenantSettingsType
  availableProviders: string[]
  onSave: (data: Partial<TenantSettingsType>) => Promise<void>
}) {
  const [ssoEnabled, setSsoEnabled] = useState(settings.sso_enabled)
  const [ssoProvider, setSsoProvider] = useState(settings.sso_provider || '')
  const [mfaRequired, setMfaRequired] = useState(settings.mfa_required)
  const [saving, setSaving] = useState(false)

  // SSO Config fields
  const [samlEntityId, setSamlEntityId] = useState(settings.sso_config?.saml_entity_id || '')
  const [samlSsoUrl, setSamlSsoUrl] = useState(settings.sso_config?.saml_sso_url || '')
  const [samlCertificate, setSamlCertificate] = useState(settings.sso_config?.saml_certificate || '')
  const [oidcIssuer, setOidcIssuer] = useState(settings.sso_config?.oidc_issuer || '')
  const [oidcClientId, setOidcClientId] = useState(settings.sso_config?.oidc_client_id || '')
  const [oidcClientSecret, setOidcClientSecret] = useState(settings.sso_config?.oidc_client_secret || '')
  const [azureTenantId, setAzureTenantId] = useState(settings.sso_config?.azure_tenant_id || '')
  const [oktaDomain, setOktaDomain] = useState(settings.sso_config?.okta_domain || '')

  const handleSave = async () => {
    setSaving(true)
    try {
      await onSave({
        sso_enabled: ssoEnabled,
        sso_provider: ssoEnabled ? (ssoProvider as TenantSettingsType['sso_provider']) : undefined,
        mfa_required: mfaRequired,
        sso_config: ssoEnabled ? {
          saml_entity_id: samlEntityId || undefined,
          saml_sso_url: samlSsoUrl || undefined,
          saml_certificate: samlCertificate || undefined,
          oidc_issuer: oidcIssuer || undefined,
          oidc_client_id: oidcClientId || undefined,
          oidc_client_secret: oidcClientSecret || undefined,
          azure_tenant_id: azureTenantId || undefined,
          okta_domain: oktaDomain || undefined,
        } : undefined,
      })
    } finally {
      setSaving(false)
    }
  }

  const providerLabels: Record<string, string> = {
    saml: 'SAML 2.0',
    oidc: 'OpenID Connect',
    azure_ad: 'Azure Active Directory',
    okta: 'Okta',
    google: 'Google Workspace',
  }

  return (
    <div className="space-y-6">
      {/* MFA */}
      <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] p-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-[var(--fg)]">Multi-Factor Authentication</h3>
            <p className="text-sm text-[var(--muted)] mt-1">Require MFA for all users in this tenant</p>
          </div>
          <button
            onClick={() => setMfaRequired(!mfaRequired)}
            className={cn(
              'relative inline-flex h-6 w-11 items-center rounded-full transition-colors',
              mfaRequired ? 'bg-primary-600' : 'bg-[var(--surface-active)]'
            )}
          >
            <span
              className={cn(
                'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                mfaRequired ? 'translate-x-6' : 'translate-x-1'
              )}
            />
          </button>
        </div>
      </div>

      {/* SSO */}
      <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-lg font-semibold text-[var(--fg)]">Single Sign-On (SSO)</h3>
            <p className="text-sm text-[var(--muted)] mt-1">Enable enterprise SSO for your organization</p>
          </div>
          <button
            onClick={() => setSsoEnabled(!ssoEnabled)}
            className={cn(
              'relative inline-flex h-6 w-11 items-center rounded-full transition-colors',
              ssoEnabled ? 'bg-primary-600' : 'bg-[var(--surface-active)]'
            )}
          >
            <span
              className={cn(
                'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                ssoEnabled ? 'translate-x-6' : 'translate-x-1'
              )}
            />
          </button>
        </div>

        {ssoEnabled && (
          <div className="space-y-4 pt-4 border-t border-[var(--surface-border)]">
            <div>
              <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-2">Identity Provider</label>
              <Select
                value={ssoProvider}
                onValueChange={setSsoProvider}
                className="w-full bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] focus:ring-2 focus:ring-primary-500"
                fullWidth
                placeholder="Select provider..."
              >
                <SelectItem value="">Select provider...</SelectItem>
                {availableProviders.map(provider => (
                  <SelectItem key={provider} value={provider}>
                    {providerLabels[provider] || provider}
                  </SelectItem>
                ))}
              </Select>
            </div>

            {/* SAML Config */}
            {ssoProvider === 'saml' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-1">Entity ID</label>
                  <input
                    type="text"
                    value={samlEntityId}
                    onChange={(e) => setSamlEntityId(e.target.value)}
                    className="w-full bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] text-sm"
                    placeholder="https://your-idp.com/entity"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-1">SSO URL</label>
                  <input
                    type="url"
                    value={samlSsoUrl}
                    onChange={(e) => setSamlSsoUrl(e.target.value)}
                    className="w-full bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] text-sm"
                    placeholder="https://your-idp.com/sso"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-1">X.509 Certificate</label>
                  <textarea
                    value={samlCertificate}
                    onChange={(e) => setSamlCertificate(e.target.value)}
                    rows={4}
                    className="w-full bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] text-sm font-mono"
                    placeholder="-----BEGIN CERTIFICATE-----"
                  />
                </div>
              </div>
            )}

            {/* OIDC Config */}
            {ssoProvider === 'oidc' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-1">Issuer URL</label>
                  <input
                    type="url"
                    value={oidcIssuer}
                    onChange={(e) => setOidcIssuer(e.target.value)}
                    className="w-full bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] text-sm"
                    placeholder="https://your-idp.com"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-1">Client ID</label>
                  <input
                    type="text"
                    value={oidcClientId}
                    onChange={(e) => setOidcClientId(e.target.value)}
                    className="w-full bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-1">Client Secret</label>
                  <input
                    type="password"
                    value={oidcClientSecret}
                    onChange={(e) => setOidcClientSecret(e.target.value)}
                    className="w-full bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] text-sm"
                  />
                </div>
              </div>
            )}

            {/* Azure AD Config */}
            {ssoProvider === 'azure_ad' && (
              <div>
                <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-1">Azure Tenant ID</label>
                <input
                  type="text"
                  value={azureTenantId}
                  onChange={(e) => setAzureTenantId(e.target.value)}
                  className="w-full bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] text-sm"
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                />
              </div>
            )}

            {/* Okta Config */}
            {ssoProvider === 'okta' && (
              <div>
                <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-1">Okta Domain</label>
                <input
                  type="text"
                  value={oktaDomain}
                  onChange={(e) => setOktaDomain(e.target.value)}
                  className="w-full bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] text-sm"
                  placeholder="your-company.okta.com"
                />
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex justify-end">
        <button
          onClick={handleSave}
          disabled={saving}
          className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg font-medium disabled:opacity-50"
        >
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </div>
  )
}

function APIKeysTab({ apiKeys, tenantId }: { apiKeys: APIKey[]; tenantId: string }) {
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyScopes, setNewKeyScopes] = useState<string[]>(['read:events', 'read:alerts'])
  const [creating, setCreating] = useState(false)
  const [createdKey, setCreatedKey] = useState<string | null>(null)

  const availableScopes = [
    'read:events',
    'read:alerts',
    'write:alerts',
    'read:agents',
    'write:agents',
    'execute:response',
  ]

  const handleCreateKey = async (e: React.FormEvent) => {
    e.preventDefault()
    setCreating(true)
    try {
      const response = await fetch(`/api/v1/tenant/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newKeyName, scopes: newKeyScopes }),
      })
      const data = await response.json()
      setCreatedKey(data.key)
    } catch (err) {
      logger.error('Failed to create API key:', err)
    } finally {
      setCreating(false)
    }
  }

  const handleRevokeKey = async (keyId: string) => {
    if (!confirm('Are you sure you want to revoke this API key?')) return
    try {
      await fetch(`/api/v1/tenant/api-keys/${keyId}`, {
        method: 'DELETE',
      })
      router.reload()
    } catch (err) {
      logger.error('Failed to revoke API key:', err)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="space-y-6">
      <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)]">
        <div className="p-4 border-b border-[var(--surface-border)] flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-[var(--fg)]">API Keys</h3>
            <p className="text-sm text-[var(--muted)]">Manage API access for integrations</p>
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white px-3 py-1.5 rounded-lg text-sm font-medium"
          >
            <Plus className="h-4 w-4" />
            Create API Key
          </button>
        </div>

        <div className="divide-y divide-[var(--surface-border)]">
          {apiKeys.length > 0 ? apiKeys.map((key) => (
            <div key={key.id} className="p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <Key className={cn('h-5 w-5', key.is_active ? 'text-green-400' : 'text-[var(--muted)]')} />
                  <span className="text-sm font-medium text-[var(--fg)]">{key.name}</span>
                  {!key.is_active && (
                    <span className="text-xs bg-red-400/10 text-red-400 px-2 py-0.5 rounded">Revoked</span>
                  )}
                </div>
                {key.is_active && (
                  <button
                    onClick={() => handleRevokeKey(key.id)}
                    className="text-xs text-red-400 hover:text-red-300"
                  >
                    Revoke
                  </button>
                )}
              </div>

              <div className="flex items-center gap-2 mb-2">
                <code className="text-sm bg-[var(--surface-hover)] px-2 py-1 rounded text-[var(--fg-secondary)] font-mono">
                  {key.key_prefix}...
                </code>
              </div>

              <div className="flex flex-wrap gap-1 mb-2">
                {key.scopes.map(scope => (
                  <span key={scope} className="text-xs bg-[var(--surface-hover)] text-[var(--fg-secondary)] px-2 py-0.5 rounded">
                    {scope}
                  </span>
                ))}
              </div>

              <div className="text-xs text-[var(--muted)]">
                Created {new Date(key.created_at).toLocaleDateString()}
                {key.last_used_at && ` | Last used ${new Date(key.last_used_at).toLocaleDateString()}`}
              </div>
            </div>
          )) : (
            <div className="p-8 text-center text-[var(--muted)]">
              No API keys created yet
            </div>
          )}
        </div>
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] w-full max-w-md p-6">
            {createdKey ? (
              <>
                <h3 className="text-lg font-semibold text-[var(--fg)] mb-4">API Key Created</h3>
                <div className="bg-green-900/30 border border-green-700 rounded-lg p-4 mb-4">
                  <p className="text-sm text-green-300 mb-2">
                    Copy this key now. You won't be able to see it again.
                  </p>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 text-sm bg-[var(--surface-inset)] px-3 py-2 rounded text-[var(--fg)] font-mono break-all">
                      {createdKey}
                    </code>
                    <button
                      onClick={() => copyToClipboard(createdKey)}
                      className="p-2 bg-[var(--surface-hover)] hover:bg-[var(--surface-active)] rounded"
                    >
                      <Copy className="h-4 w-4 text-[var(--fg)]" />
                    </button>
                  </div>
                </div>
                <button
                  onClick={() => {
                    setShowCreateModal(false)
                    setCreatedKey(null)
                    setNewKeyName('')
                    router.reload()
                  }}
                  className="w-full bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg font-medium"
                >
                  Done
                </button>
              </>
            ) : (
              <>
                <h3 className="text-lg font-semibold text-[var(--fg)] mb-4">Create API Key</h3>
                <form onSubmit={handleCreateKey} className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-1">Name</label>
                    <input
                      type="text"
                      value={newKeyName}
                      onChange={(e) => setNewKeyName(e.target.value)}
                      required
                      className="w-full bg-[var(--surface-hover)] border border-[var(--surface-border)] rounded-lg px-4 py-2 text-[var(--fg)] focus:ring-2 focus:ring-primary-500"
                      placeholder="Integration API Key"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-[var(--fg-secondary)] mb-2">Scopes</label>
                    <div className="space-y-2">
                      {availableScopes.map(scope => (
                        <label key={scope} className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={newKeyScopes.includes(scope)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setNewKeyScopes([...newKeyScopes, scope])
                              } else {
                                setNewKeyScopes(newKeyScopes.filter(s => s !== scope))
                              }
                            }}
                            className="h-4 w-4 rounded border-[var(--surface-border)] bg-[var(--surface-hover)] text-primary-600"
                          />
                          <span className="text-sm text-[var(--fg-secondary)] font-mono">{scope}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                  <div className="flex justify-end gap-3 pt-2">
                    <button
                      type="button"
                      onClick={() => setShowCreateModal(false)}
                      className="px-4 py-2 text-[var(--fg-secondary)] hover:text-[var(--fg)]"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={creating || !newKeyName}
                      className="bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg font-medium disabled:opacity-50"
                    >
                      {creating ? 'Creating...' : 'Create Key'}
                    </button>
                  </div>
                </form>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function LicenseTab({ license }: { license: TenantSettingsPageProps['license'] }) {
  const daysUntilExpiry = Math.ceil(
    (new Date(license.expires_at).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
  )

  const isExpiringSoon = daysUntilExpiry <= 30 && daysUntilExpiry > 0
  const isExpired = daysUntilExpiry <= 0

  return (
    <div className="space-y-6">
      {/* License Info */}
      <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] p-6">
        <div className="flex items-start justify-between mb-6">
          <div>
            <h3 className="text-lg font-semibold text-[var(--fg)] mb-1">Current Plan</h3>
            <p className="text-3xl font-bold text-[var(--fg)] capitalize">{license.plan}</p>
          </div>
          <div className={cn(
            'px-3 py-1.5 rounded-lg text-sm font-medium',
            license.status === 'active' ? 'bg-green-500/20 text-green-400' :
            license.status === 'grace_period' ? 'bg-yellow-500/20 text-yellow-400' :
            'bg-red-500/20 text-red-400'
          )}>
            {license.status === 'active' ? 'Active' :
             license.status === 'grace_period' ? 'Grace Period' : 'Expired'}
          </div>
        </div>

        {/* Expiry Warning */}
        {(isExpiringSoon || isExpired) && (
          <div className={cn(
            'p-4 rounded-lg mb-6 flex items-center gap-3',
            isExpired ? 'bg-red-900/30 border border-red-700' : 'bg-yellow-900/30 border border-yellow-700'
          )}>
            <AlertCircle className={cn('h-5 w-5', isExpired ? 'text-red-400' : 'text-yellow-400')} />
            <div>
              <p className={cn('text-sm', isExpired ? 'text-red-300' : 'text-yellow-300')}>
                {isExpired
                  ? 'Your license has expired. Please renew to continue using all features.'
                  : `Your license expires in ${daysUntilExpiry} days. Renew now to avoid service interruption.`}
              </p>
            </div>
          </div>
        )}

        <div className="grid grid-cols-2 gap-6">
          <div>
            <div className="text-sm text-[var(--muted)] mb-1">Started</div>
            <div className="text-[var(--fg)]">{new Date(license.started_at).toLocaleDateString()}</div>
          </div>
          <div>
            <div className="text-sm text-[var(--muted)] mb-1">Expires</div>
            <div className="text-[var(--fg)]">{new Date(license.expires_at).toLocaleDateString()}</div>
          </div>
          <div>
            <div className="text-sm text-[var(--muted)] mb-1">Auto-Renew</div>
            <div className={cn('font-medium', license.auto_renew ? 'text-green-400' : 'text-[var(--muted)]')}>
              {license.auto_renew ? 'Enabled' : 'Disabled'}
            </div>
          </div>
        </div>
      </div>

      {/* Usage */}
      <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] p-6">
        <h3 className="text-lg font-semibold text-[var(--fg)] mb-4">Current Usage</h3>

        <div className="space-y-4">
          <div>
            <div className="flex justify-between text-sm mb-1">
              <span className="text-[var(--muted)]">Agents</span>
              <span className="text-[var(--fg)]">
                {license.usage.agents} / {license.limits.max_agents === -1 ? 'Unlimited' : license.limits.max_agents}
              </span>
            </div>
            {license.limits.max_agents !== -1 && (
              <div className="h-2 bg-[var(--surface-hover)] rounded-full overflow-hidden">
                <div
                  className={cn(
                    'h-full rounded-full',
                    (license.usage.agents / license.limits.max_agents) > 0.9 ? 'bg-red-500' :
                    (license.usage.agents / license.limits.max_agents) > 0.7 ? 'bg-yellow-500' : 'bg-primary-500'
                  )}
                  style={{ width: `${Math.min(100, (license.usage.agents / license.limits.max_agents) * 100)}%` }}
                />
              </div>
            )}
          </div>

          <div>
            <div className="flex justify-between text-sm mb-1">
              <span className="text-[var(--muted)]">Users</span>
              <span className="text-[var(--fg)]">
                {license.usage.users} / {license.limits.max_users === -1 ? 'Unlimited' : license.limits.max_users}
              </span>
            </div>
            {license.limits.max_users !== -1 && (
              <div className="h-2 bg-[var(--surface-hover)] rounded-full overflow-hidden">
                <div
                  className={cn(
                    'h-full rounded-full',
                    (license.usage.users / license.limits.max_users) > 0.9 ? 'bg-red-500' :
                    (license.usage.users / license.limits.max_users) > 0.7 ? 'bg-yellow-500' : 'bg-primary-500'
                  )}
                  style={{ width: `${Math.min(100, (license.usage.users / license.limits.max_users) * 100)}%` }}
                />
              </div>
            )}
          </div>

          <div>
            <div className="flex justify-between text-sm mb-1">
              <span className="text-[var(--muted)]">Events Today</span>
              <span className="text-[var(--fg)]">
                {license.usage.events_today.toLocaleString()} / {license.limits.max_events_per_day === -1 ? 'Unlimited' : license.limits.max_events_per_day.toLocaleString()}
              </span>
            </div>
            {license.limits.max_events_per_day !== -1 && (
              <div className="h-2 bg-[var(--surface-hover)] rounded-full overflow-hidden">
                <div
                  className={cn(
                    'h-full rounded-full',
                    (license.usage.events_today / license.limits.max_events_per_day) > 0.9 ? 'bg-red-500' :
                    (license.usage.events_today / license.limits.max_events_per_day) > 0.7 ? 'bg-yellow-500' : 'bg-primary-500'
                  )}
                  style={{ width: `${Math.min(100, (license.usage.events_today / license.limits.max_events_per_day) * 100)}%` }}
                />
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Features */}
      <div className="card-sentinel bg-[var(--surface)] rounded-xl border border-[var(--surface-border)] p-6">
        <h3 className="text-lg font-semibold text-[var(--fg)] mb-4">Included Features</h3>

        <div className="grid grid-cols-2 gap-2">
          {license.limits.features.map((feature, i) => (
            <div key={i} className="flex items-center gap-2 text-sm text-[var(--fg-secondary)]">
              <CheckCircle className="h-4 w-4 text-green-400" />
              {feature}
            </div>
          ))}
        </div>
      </div>

      {/* Actions */}
      <div className="flex justify-end gap-3">
        <a
          href="mailto:contato@treantlab.org?subject=License%20Upgrade"
          className="flex items-center gap-2 bg-[var(--surface-hover)] hover:bg-[var(--surface-active)] text-[var(--fg)] px-4 py-2 rounded-lg font-medium"
        >
          <ExternalLink className="h-4 w-4" />
          Contact Sales
        </a>
        <button
          className="flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white px-4 py-2 rounded-lg font-medium"
        >
          <RefreshCw className="h-4 w-4" />
          Upgrade Plan
        </button>
      </div>
    </div>
  )
}

export default function TenantSettings({ tenant, settings, api_keys, license, available_sso_providers }: TenantSettingsPageProps) {
  const [activeTab, setActiveTab] = useState('branding')

  const handleSaveSettings = async (data: Partial<TenantSettingsType>) => {
    try {
      const response = await fetch(`/api/v1/tenant/settings`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })

      if (!response.ok) {
        throw new Error('Failed to save settings')
      }

      router.reload()
    } catch (err) {
      logger.error('Failed to save settings:', err)
      throw err
    }
  }

  return (
    <MainLayout title="Tenant Settings">
      <Head title="Tenant Settings - Tamandua EDR" />

      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-4">
          <div
            className="h-12 w-12 rounded-xl flex items-center justify-center text-white font-bold bg-cover bg-center"
            style={{
              backgroundColor: settings.logo_url ? 'transparent' : (settings.primary_color || '#6366f1'),
              backgroundImage: settings.logo_url ? `url(${settings.logo_url})` : undefined,
            }}
          >
            {!settings.logo_url && safeInitial(tenant.name)}
          </div>
          <div>
            <h1 className="text-2xl font-bold text-[var(--fg)]">{tenant.name}</h1>
            <p className="text-[var(--muted)]">Manage tenant settings and configuration</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-[var(--surface-border)] mb-6">
        <nav className="flex gap-6">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                'flex items-center gap-2 px-1 py-3 text-sm font-medium border-b-2 -mb-px transition-colors',
                activeTab === tab.id
                  ? 'border-primary-500 text-primary-400'
                  : 'border-transparent text-[var(--muted)] hover:text-[var(--fg)]'
              )}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'branding' && (
        <BrandingTab tenant={tenant} settings={settings} onSave={handleSaveSettings} />
      )}
      {activeTab === 'security' && (
        <SecurityTab settings={settings} availableProviders={available_sso_providers} onSave={handleSaveSettings} />
      )}
      {activeTab === 'api' && (
        <APIKeysTab apiKeys={api_keys} tenantId={tenant.id} />
      )}
      {activeTab === 'license' && (
        <LicenseTab license={license} />
      )}
    </MainLayout>
  )
}
