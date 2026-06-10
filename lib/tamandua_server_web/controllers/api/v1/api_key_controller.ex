defmodule TamanduaServerWeb.API.V1.APIKeyController do
  @moduledoc """
  API controller for managing API keys.

  API keys provide programmatic access to the Tamandua API. Each key is
  scoped to an organization and can have custom permissions and rate limits.

  ## Security Notes

  - The raw API key is only returned at creation time
  - Keys are stored as bcrypt hashes
  - Keys can be restricted by IP address
  - Keys can have expiration dates
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Tenants
  alias TamanduaServer.Accounts.APIKey

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Lists all API keys for the current organization.
  """
  def index(conn, _params) do
    org_id = conn.assigns.current_organization_id

    api_keys = Tenants.list_api_keys(org_id)

    # Redact key_hash for security
    api_keys = Enum.map(api_keys, &redact_sensitive_fields/1)

    json(conn, %{data: api_keys})
  end

  @doc """
  Shows a single API key.
  """
  def show(conn, %{"id" => id}) do
    org_id = conn.assigns.current_organization_id

    with {:ok, api_key} <- Tenants.get_api_key(org_id, id) do
      json(conn, %{data: redact_sensitive_fields(api_key)})
    end
  end

  @doc """
  Creates a new API key.

  The raw key is only returned in this response and cannot be retrieved later.
  """
  def create(conn, %{"api_key" => params}) do
    org_id = conn.assigns.current_organization_id
    user_id = conn.assigns.current_user && conn.assigns.current_user.id

    params = Map.put(params, "created_by_id", user_id)

    # Determine environment
    env = Application.get_env(:tamandua_server, :environment, :prod)
    env_str = case env do
      :prod -> "live"
      :dev -> "dev"
      :test -> "test"
      _ -> "live"
    end

    with {:ok, api_key} <- Tenants.create_api_key(org_id, params, env: env_str) do
      conn
      |> put_status(:created)
      |> json(%{
        data: redact_sensitive_fields(api_key),
        # IMPORTANT: This is the only time the raw key is available
        raw_key: api_key.raw_key,
        message: "API key created. Save this key securely - it cannot be retrieved later."
      })
    end
  end

  def create(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing api_key parameter"})
  end

  @doc """
  Updates an API key.
  """
  def update(conn, %{"id" => id, "api_key" => params}) do
    org_id = conn.assigns.current_organization_id

    with {:ok, api_key} <- Tenants.get_api_key(org_id, id),
         {:ok, updated} <- Tenants.update_api_key(api_key, params) do
      json(conn, %{data: redact_sensitive_fields(updated)})
    end
  end

  @doc """
  Deletes an API key.
  """
  def delete(conn, %{"id" => id}) do
    org_id = conn.assigns.current_organization_id

    with {:ok, api_key} <- Tenants.get_api_key(org_id, id),
         {:ok, _} <- Tenants.delete_api_key(api_key) do
      send_resp(conn, :no_content, "")
    end
  end

  @doc """
  Deactivates an API key without deleting it.
  """
  def deactivate(conn, %{"id" => id}) do
    org_id = conn.assigns.current_organization_id

    with {:ok, api_key} <- Tenants.get_api_key(org_id, id),
         {:ok, updated} <- Tenants.deactivate_api_key(api_key) do
      json(conn, %{
        data: redact_sensitive_fields(updated),
        message: "API key deactivated"
      })
    end
  end

  @doc """
  Rotates an API key - deactivates the old one and creates a new one with same settings.
  """
  def rotate(conn, %{"id" => id}) do
    org_id = conn.assigns.current_organization_id
    user_id = conn.assigns.current_user && conn.assigns.current_user.id

    with {:ok, old_key} <- Tenants.get_api_key(org_id, id) do
      # Create new key with same settings
      new_params = %{
        "name" => old_key.name <> " (rotated)",
        "description" => old_key.description,
        "permissions" => old_key.permissions,
        "scope" => old_key.scope,
        "rate_limit_per_minute" => old_key.rate_limit_per_minute,
        "rate_limit_per_hour" => old_key.rate_limit_per_hour,
        "expires_at" => old_key.expires_at,
        "allowed_ips" => old_key.allowed_ips,
        "created_by_id" => user_id
      }

      # Determine environment from old key
      env = case old_key.key_prefix do
        "tam_dev_" -> "dev"
        "tam_test_" -> "test"
        _ -> "live"
      end

      with {:ok, new_key} <- Tenants.create_api_key(org_id, new_params, env: env),
           {:ok, _} <- Tenants.deactivate_api_key(old_key) do
        conn
        |> put_status(:created)
        |> json(%{
          data: redact_sensitive_fields(new_key),
          raw_key: new_key.raw_key,
          old_key_id: old_key.id,
          message: "API key rotated. Save the new key securely - it cannot be retrieved later."
        })
      end
    end
  end

  # Remove sensitive fields from API key for responses
  defp redact_sensitive_fields(key) when is_map(key) do
    %{
      id: key.id,
      name: key.name,
      description: key.description,
      key_prefix: key.key_prefix,
      permissions: key.permissions,
      scope: key.scope,
      rate_limit_per_minute: key.rate_limit_per_minute,
      rate_limit_per_hour: key.rate_limit_per_hour,
      expires_at: key.expires_at,
      last_used_at: key.last_used_at,
      is_active: key.is_active,
      allowed_ips: key.allowed_ips,
      organization_id: key.organization_id,
      created_by_id: key.created_by_id,
      inserted_at: key.inserted_at,
      updated_at: key.updated_at
    }
  end
end
