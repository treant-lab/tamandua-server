# SSO Authentication Module

This module provides comprehensive Single Sign-On (SSO) support for Tamandua EDR.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      SSO Module                              │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐  ┌──────────────────┐                │
│  │  SAML 2.0       │  │  OAuth/OIDC      │                │
│  │  Provider       │  │  Provider        │                │
│  └────────┬─────────┘  └────────┬─────────┘                │
│           │                     │                           │
│           └──────────┬──────────┘                           │
│                      │                                       │
│           ┌──────────▼──────────┐                           │
│           │   Provisioner       │                           │
│           │  (JIT Provisioning) │                           │
│           └──────────┬──────────┘                           │
│                      │                                       │
│           ┌──────────▼──────────┐                           │
│           │   Session Manager   │                           │
│           │  (SSO Sessions)     │                           │
│           └─────────────────────┘                           │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. SSO (Main Module)
**File**: `sso.ex`

The main GenServer that coordinates SSO authentication flows.

**Responsibilities:**
- SAML AuthnRequest generation and response processing
- OAuth/OIDC authorization code flow with PKCE
- Provider endpoint resolution (built-in and discovery)
- State/nonce management for CSRF protection
- ETS-based caching for config and pending auth states
- Single Logout (SLO) handling

**Key Functions:**
- `initiate_saml_login/3` - Start SAML login flow
- `handle_saml_response/3` - Process SAML assertion
- `initiate_oauth_login/2` - Start OAuth flow
- `handle_oauth_callback/3` - Process OAuth callback
- `generate_sp_metadata/2` - Generate SAML SP metadata XML

### 2. SSOConfig (Schema)
**File**: `sso_config.ex`

Ecto schema for SSO provider configuration.

**Fields:**
- `provider` - Provider type (`:saml`, `:oidc`, `:azure_ad`, `:okta`, etc.)
- `enabled` - SSO enabled flag
- `settings` - Provider-specific configuration (map)
- `jit_provisioning` - Enable automatic user creation
- `default_role` - Default role for new users
- `group_role_mappings` - Map IdP groups to Tamandua roles
- `allowed_domains` - Domain restrictions
- `session_duration_hours` - Session timeout

### 3. SSOSession (Schema)
**File**: `sso_session.ex`

Ecto schema for tracking active SSO sessions.

**Fields:**
- `user_id` - Associated user
- `provider` - SSO provider used
- `provider_user_id` - IdP user identifier
- `session_index` - SAML session index (for SLO)
- `expires_at` - Session expiration time
- `is_active` - Session active flag
- `terminated_at` / `termination_reason` - Logout tracking

### 4. Provisioner
**File**: `provisioner.ex`

Handles Just-In-Time user provisioning and attribute synchronization.

**Responsibilities:**
- Create users on first SSO login
- Sync user attributes (name, email)
- Map IdP groups to Tamandua RBAC roles
- Enforce domain restrictions
- Handle user deprovisioning

**Key Functions:**
- `provision_user/2` - Create or update user from SSO attributes
- `map_groups_to_role/2` - Map SSO groups to Tamandua role
- `deprovision_user/2` - Disable user account
- `sync_roles_from_groups/3` - Sync RBAC role assignments

## Supported Providers

### SAML 2.0
- Azure AD / Microsoft Entra ID
- Okta
- OneLogin
- Google Workspace
- PingFederate
- Any SAML 2.0 compliant IdP

### OAuth 2.0 / OIDC
- Microsoft Entra ID (Azure AD)
- Google / Google Workspace
- Okta
- GitHub
- GitLab
- Any OIDC-compliant provider

## Security Features

### SAML
- XML signature verification using IdP certificate
- Audience restriction validation
- Time-based assertion validation (NotBefore/NotOnOrAfter)
- Clock skew tolerance (2 minutes)
- Replay attack prevention (state tracking)
- Support for signed requests
- Support for encrypted assertions

### OAuth/OIDC
- PKCE (Proof Key for Code Exchange) - RFC 7636
- State parameter for CSRF protection
- Nonce validation in ID tokens
- ID token signature verification (planned)
- Token refresh support
- Secure token storage

### General
- Session fixation protection
- Domain-based access control
- Audit logging for all SSO events
- Rate limiting (inherited from application)
- HTTPS enforcement (production)

## ETS Tables

The module uses three ETS tables for caching and state management:

1. **`:sso_config_cache`** - Configuration cache (5 min TTL)
2. **`:sso_pending_auth`** - Pending authentication requests (5 min TTL)
3. **`:sso_provider_cache`** - Resolved provider endpoints (5 min TTL)

All tables are cleaned up periodically by a background task.

## Error Handling

Common error codes returned by SSO functions:

- `:not_configured` - SSO provider not found
- `:sso_disabled` - SSO is disabled for this provider
- `:not_saml_provider` / `:not_oauth_provider` - Wrong protocol
- `:missing_email_attribute` - IdP didn't return email
- `:domain_not_allowed` - User's domain not in allowed list
- `:user_not_found_jit_disabled` - User doesn't exist and JIT is off
- `:user_belongs_to_different_org` - User in different organization
- `:signature_verification_failed` - SAML signature invalid
- `:audience_mismatch` - SAML audience doesn't match
- `:saml_assertion_expired` - SAML time conditions failed
- `:invalid_state` / `:state_expired` - OAuth state invalid
- `:jit_provisioning_disabled` - Cannot create user (JIT off)

## Usage Examples

### Configure SAML Provider

```elixir
alias TamanduaServer.Auth.SSO

SSO.configure(organization_id, :saml, %{
  "idp_entity_id" => "https://idp.example.com",
  "idp_sso_url" => "https://idp.example.com/sso",
  "idp_certificate" => "-----BEGIN CERTIFICATE-----\n...",
  "sp_entity_id" => "https://edr.example.com/saml/metadata",
  "email_attribute" => "email",
  "name_attribute" => "displayName",
  "group_attribute" => "groups"
})
```

### Configure OAuth Provider

```elixir
SSO.configure(organization_id, :azure_ad, %{
  "tenant_id" => "your-tenant-id",
  "client_id" => "your-client-id",
  "client_secret" => "your-client-secret"
})
```

### Get SP Metadata (SAML)

```elixir
{:ok, metadata_xml} = SSO.generate_sp_metadata(provider_id, "https://edr.example.com")
```

### Initiate Login

```elixir
# SAML
{:ok, redirect_url, request_id} = SSO.initiate_saml_login(provider_id, base_url)

# OAuth
{:ok, redirect_url, state} = SSO.initiate_oauth_login(provider_id, base_url)
```

### Handle Callback

```elixir
# SAML
{:ok, user, sso_session} = SSO.handle_saml_response(provider_id, saml_response, base_url)

# OAuth
{:ok, user, sso_session} = SSO.handle_oauth_callback(provider_id, params, base_url)
```

## Testing

Run tests with:

```bash
mix test test/tamandua_server/auth/sso/
```

Test coverage includes:
- Provider configuration validation
- SAML AuthnRequest generation
- OAuth PKCE flow
- User provisioning and deprovisioning
- Group-to-role mapping
- Domain restrictions
- Error handling

## Configuration

### Environment Variables

None required - all configuration is stored in the database.

### Runtime Configuration

Configure via Admin UI or programmatically:

```elixir
# Get config
{:ok, config} = SSO.get_config(organization_id)

# List providers
providers = SSO.list_providers(organization_id)

# Test config
{:ok, :valid} = SSO.test_config(provider_id)
```

## Monitoring

The module logs key events:

- SSO service startup
- Authentication attempts (success/failure)
- User provisioning events
- Session creation/termination
- Configuration changes
- Single logout requests

All logs are prefixed with `[SSO]` for easy filtering.

## Limitations

Current limitations (planned for future releases):

1. **SAML:**
   - Request signing not implemented (SP side)
   - Assertion encryption not implemented
   - Artifact binding not supported
   - Only HTTP-POST binding for ACS

2. **OAuth/OIDC:**
   - ID token signature verification uses simple decode (not full JWT verify)
   - No support for implicit flow or hybrid flow
   - JWKS refresh not implemented

3. **General:**
   - No automatic deprovisioning (requires manual API call)
   - Group sync is one-way (IdP → Tamandua)
   - No SCIM support for provisioning

## References

- [SAML 2.0 Core](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
