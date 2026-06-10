defmodule TamanduaServerWeb.Plugs.RBAC do
  @moduledoc """
  RBAC Authorization Plug for enforcing permission-based access control.

  This plug checks if the current user has the required permission(s) to
  access a controller action. It supports:

  - Single permission checks
  - Multiple permissions with "any" logic (user needs at least one)
  - Multiple permissions with "all" logic (user needs all)
  - Resource-scoped permissions

  ## Usage

  Single permission:
      plug TamanduaServerWeb.Plugs.RBAC, permission: :manage_alerts

  Any of multiple permissions:
      plug TamanduaServerWeb.Plugs.RBAC, any: [:manage_alerts, :execute_response]

  All of multiple permissions:
      plug TamanduaServerWeb.Plugs.RBAC, all: [:manage_alerts, :view_agents]

  Conditional based on action:
      plug TamanduaServerWeb.Plugs.RBAC, permission: :alerts_read when action in [:index, :show]
      plug TamanduaServerWeb.Plugs.RBAC, permission: :alerts_update when action in [:update]

  With resource scope:
      plug TamanduaServerWeb.Plugs.RBAC, permission: :agents_command, resource: :agent

  ## Configuration

  The plug expects `current_user` to be set in `conn.assigns` before it runs.
  If no user is present, the request is rejected with 401 Unauthorized.

  ## Options

  - `:permission` - Single permission atom to check
  - `:any` - List of permissions, user must have at least one
  - `:all` - List of permissions, user must have all
  - `:resource` - Key in conn.assigns for resource-scoped authorization
  - `:on_failure` - Custom failure handler function `(conn, opts) -> conn`
  """

  import Plug.Conn
  import Phoenix.Controller

  alias TamanduaServer.Authorization.RBAC

  @behaviour Plug

  @impl Plug
  def init(opts) when is_list(opts), do: opts
  def init(permission) when is_atom(permission), do: [permission: permission]

  @impl Plug
  def call(conn, opts) do
    user = conn.assigns[:current_user]

    cond do
      is_nil(user) ->
        unauthorized(conn, "Authentication required")

      opts[:permission] ->
        check_permission(conn, user, opts[:permission], opts[:resource])

      opts[:any] ->
        check_any_permission(conn, user, opts[:any])

      opts[:all] ->
        check_all_permissions(conn, user, opts[:all])

      true ->
        # No permissions specified, allow through
        conn
    end
  end

  defp check_permission(conn, user, permission, resource_key) do
    resource =
      if resource_key do
        conn.assigns[resource_key]
      else
        nil
      end

    if RBAC.can?(user, permission, resource) do
      # Log successful authorization for audit
      log_authorization(conn, user, permission, :allowed)
      conn
    else
      log_authorization(conn, user, permission, :denied)
      forbidden(conn, permission)
    end
  end

  defp check_any_permission(conn, user, permissions) when is_list(permissions) do
    if RBAC.can_any?(user, permissions) do
      log_authorization(conn, user, permissions, :allowed)
      conn
    else
      log_authorization(conn, user, permissions, :denied)
      forbidden(conn, hd(permissions))
    end
  end

  defp check_all_permissions(conn, user, permissions) when is_list(permissions) do
    if RBAC.can_all?(user, permissions) do
      log_authorization(conn, user, permissions, :allowed)
      conn
    else
      missing = Enum.reject(permissions, &RBAC.can?(user, &1))
      log_authorization(conn, user, permissions, :denied, missing: missing)
      forbidden(conn, hd(missing))
    end
  end

  defp unauthorized(conn, message) do
    conn
    |> put_status(:unauthorized)
    |> put_view(json: TamanduaServerWeb.ErrorJSON)
    |> render(:error, %{
      error: "unauthorized",
      message: message
    })
    |> halt()
  end

  defp forbidden(conn, permission) do
    conn
    |> put_status(:forbidden)
    |> put_view(json: TamanduaServerWeb.ErrorJSON)
    |> render(:error, %{
      error: "forbidden",
      message: "You don't have permission to perform this action",
      required_permission: permission,
      hint: "Contact your administrator to request the '#{permission}' permission"
    })
    |> halt()
  end

  defp log_authorization(conn, user, permission, result, opts \\ []) do
    # Log for debugging/audit purposes
    metadata = %{
      user_id: user.id,
      permission: permission,
      result: result,
      path: conn.request_path,
      method: conn.method,
      missing: opts[:missing]
    }

    case result do
      :allowed ->
        :ok  # Don't log successful authorizations by default to reduce noise

      :denied ->
        require Logger
        Logger.warning("Authorization denied", metadata)
    end
  end
end

defmodule TamanduaServerWeb.Plugs.RequireFeature do
  @moduledoc """
  Plug to ensure organization has a required feature enabled.

  ## Usage

      plug TamanduaServerWeb.Plugs.RequireFeature, :hunting
      plug TamanduaServerWeb.Plugs.RequireFeature, [:hunting, :behavioral_analytics]
  """

  import Plug.Conn
  import Phoenix.Controller

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Repo

  @behaviour Plug

  @impl Plug
  def init(feature) when is_atom(feature), do: [feature]
  def init(features) when is_list(features), do: features

  @impl Plug
  def call(conn, required_features) do
    user = conn.assigns[:current_user]

    cond do
      is_nil(user) ->
        unauthorized(conn)

      is_nil(user.organization_id) ->
        forbidden(conn, "No organization associated with user")

      true ->
        org = Repo.get(Organization, user.organization_id)
        check_features(conn, org, required_features)
    end
  end

  defp check_features(conn, org, required_features) do
    missing =
      required_features
      |> Enum.reject(&Organization.has_feature?(org, &1))

    if Enum.empty?(missing) do
      conn
    else
      forbidden(conn, "Feature(s) not available: #{Enum.join(missing, ", ")}. Upgrade your plan to access this functionality.")
    end
  end

  defp unauthorized(conn) do
    conn
    |> put_status(:unauthorized)
    |> put_view(json: TamanduaServerWeb.ErrorJSON)
    |> render(:error, %{error: "unauthorized", message: "Authentication required"})
    |> halt()
  end

  defp forbidden(conn, message) do
    conn
    |> put_status(:forbidden)
    |> put_view(json: TamanduaServerWeb.ErrorJSON)
    |> render(:error, %{
      error: "feature_not_available",
      message: message
    })
    |> halt()
  end
end

defmodule TamanduaServerWeb.Plugs.RequireActiveTenant do
  @moduledoc """
  Plug to ensure the user's organization has an active subscription.

  This should be used for endpoints that require a valid subscription.
  """

  import Plug.Conn
  import Phoenix.Controller

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Repo

  @behaviour Plug

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    user = conn.assigns[:current_user]

    cond do
      is_nil(user) ->
        unauthorized(conn)

      is_nil(user.organization_id) ->
        forbidden(conn, "No organization associated with user")

      true ->
        org = Repo.get(Organization, user.organization_id)
        check_subscription(conn, org)
    end
  end

  defp check_subscription(conn, org) do
    cond do
      is_nil(org) ->
        forbidden(conn, "Organization not found")

      not Organization.subscription_active?(org) ->
        subscription_expired(conn, org)

      true ->
        conn
        |> assign(:current_organization, org)
    end
  end

  defp unauthorized(conn) do
    conn
    |> put_status(:unauthorized)
    |> put_view(json: TamanduaServerWeb.ErrorJSON)
    |> render(:error, %{error: "unauthorized", message: "Authentication required"})
    |> halt()
  end

  defp forbidden(conn, message) do
    conn
    |> put_status(:forbidden)
    |> put_view(json: TamanduaServerWeb.ErrorJSON)
    |> render(:error, %{error: "forbidden", message: message})
    |> halt()
  end

  defp subscription_expired(conn, org) do
    conn
    |> put_status(:payment_required)
    |> put_view(json: TamanduaServerWeb.ErrorJSON)
    |> render(:error, %{
      error: "subscription_expired",
      message: "Your organization's subscription has expired",
      organization: org.name,
      expires_at: org.subscription_expires_at
    })
    |> halt()
  end
end
