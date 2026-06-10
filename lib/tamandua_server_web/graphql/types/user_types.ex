defmodule TamanduaServerWeb.GraphQL.Types.UserTypes do
  @moduledoc """
  GraphQL types for Users and Organizations.
  """
  use Absinthe.Schema.Notation

  @desc "User role"
  enum :user_role do
    value :admin, description: "Full administrative access"
    value :analyst, description: "Security analyst"
    value :viewer, description: "Read-only access"
    value :responder, description: "Can perform response actions"
  end

  @desc "A user account"
  object :user do
    field :id, non_null(:id), description: "Unique user identifier"
    field :email, non_null(:string), description: "User email address"
    field :name, :string, description: "Display name"
    field :role, :string, description: "User role"
    field :mfa_enabled, :boolean, description: "MFA enabled"
    field :last_login_at, :datetime, description: "Last login timestamp"
    field :organization_id, :id, description: "Organization ID"
    field :inserted_at, :datetime, description: "Account creation timestamp"

    field :organization, :organization do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.UserResolver.organization/3
    end

    field :roles, list_of(:role) do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.UserResolver.roles/3
    end

    field :permissions, list_of(:string) do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.UserResolver.permissions/3
    end

    field :assigned_alerts, list_of(:alert) do
      arg :status, :string
      arg :limit, :integer, default_value: 20
      resolve &TamanduaServerWeb.GraphQL.Resolvers.UserResolver.assigned_alerts/3
    end
  end

  @desc "The currently authenticated user"
  object :current_user do
    field :id, non_null(:id)
    field :email, non_null(:string)
    field :name, :string
    field :role, :string
    field :mfa_enabled, :boolean
    field :organization, :organization
    field :permissions, list_of(:string)
  end

  @desc "An organization (tenant)"
  object :organization do
    field :id, non_null(:id), description: "Unique organization identifier"
    field :name, non_null(:string), description: "Organization name"
    field :slug, :string, description: "URL-friendly identifier"
    field :license_tier, :string, description: "License tier"
    field :max_agents, :integer, description: "Maximum allowed agents"
    field :is_active, :boolean, description: "Organization is active"
    field :inserted_at, :datetime, description: "Creation timestamp"

    field :agent_count, :integer do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.UserResolver.agent_count/3
    end

    field :users, list_of(:user) do
      resolve &TamanduaServerWeb.GraphQL.Resolvers.UserResolver.organization_users/3
    end
  end

  @desc "A role for RBAC"
  object :role do
    field :id, non_null(:id)
    field :name, non_null(:string)
    field :description, :string
    field :priority, :integer
    field :is_system, :boolean
    field :permissions, list_of(:string)
  end

  @desc "Authentication result"
  object :auth_result do
    field :token, :string, description: "JWT token"
    field :user, :user, description: "Authenticated user"
    field :expires_at, :datetime, description: "Token expiration"
    field :requires_mfa, :boolean, description: "MFA required"
  end

  @desc "API Key"
  object :api_key do
    field :id, non_null(:id)
    field :name, :string
    field :key_prefix, :string, description: "First 8 characters of key"
    field :scopes, list_of(:string), description: "Allowed scopes"
    field :expires_at, :datetime
    field :last_used_at, :datetime
    field :is_active, :boolean
    field :inserted_at, :datetime
  end

  @desc "Input for creating a user"
  input_object :create_user_input do
    field :email, non_null(:string)
    field :name, :string
    field :password, non_null(:string)
    field :role, :string
    field :organization_id, :id
  end

  @desc "Input for updating a user"
  input_object :update_user_input do
    field :name, :string
    field :role, :string
    field :mfa_enabled, :boolean
  end

  @desc "Input for authentication"
  input_object :login_input do
    field :email, non_null(:string)
    field :password, non_null(:string)
    field :totp_code, :string, description: "MFA TOTP code if required"
  end

  @desc "Input for creating an API key"
  input_object :create_api_key_input do
    field :name, non_null(:string)
    field :scopes, list_of(:string)
    field :expires_at, :datetime
  end
end
