defmodule TamanduaServerWeb.API.V1.IdentityController do
  @moduledoc """
  API controller for Identity Protection endpoints.

  Provides REST API for:
  - User risk scores and management
  - Azure AD integration data
  - Identity event queries
  - Risk factor analysis
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Identity.{RiskScoring, AzureAD}

  def action(conn, _opts) do
    apply(__MODULE__, action_name(conn), [conn, conn.params])
  rescue
    exception ->
      Logger.warning("Identity action #{action_name(conn)} failed: #{Exception.message(exception)}")

      conn
      |> put_status(:service_unavailable)
      |> json(%{
        status: "error",
        message: "Identity service is unavailable",
        detail: Exception.message(exception)
      })
  catch
    :exit, {:noproc, _} ->
      conn
      |> put_status(:service_unavailable)
      |> json(%{
        status: "error",
        message: "Identity service is not running in this boot profile"
      })

    :exit, {:timeout, _} ->
      conn
      |> put_status(:gateway_timeout)
      |> json(%{
        status: "error",
        message: "Identity service timed out"
      })

    kind, reason ->
      Logger.warning("Identity action #{action_name(conn)} failed: #{inspect(kind)} #{inspect(reason)}")

      conn
      |> put_status(:service_unavailable)
      |> json(%{
        status: "error",
        message: "Identity service is unavailable"
      })
  end

  # ============================================================================
  # Risk Scores
  # ============================================================================

  @doc """
  Get risk score for a specific user.
  """
  def get_user_risk(conn, %{"user_id" => user_id}) do
    case RiskScoring.get_risk_score(user_id) do
      {:ok, risk_data} ->
        json(conn, %{
          status: "success",
          data: serialize_risk_score(risk_data, user_id)
        })

      {:error, reason} ->
        conn
        |> put_status(:not_found)
        |> json(%{status: "error", message: inspect(reason)})
    end
  end

  @doc """
  List all high risk users.
  """
  def list_high_risk_users(conn, params) do
    opts = [
      min_score: params["min_score"] |> parse_int(60) |> max(0) |> min(100),
      limit: params["limit"] |> parse_int(100) |> max(1) |> min(500),
      sort: parse_risk_sort(Map.get(params, "sort"))
    ]

    case RiskScoring.get_high_risk_users(opts) do
      {:ok, users} ->
        json(conn, %{
          status: "success",
          data: Enum.map(users, &serialize_risk_score(&1, &1.user_id))
        })

      {:error, reason} ->
        identity_dependency_error(conn, "risk_scoring_unavailable", reason)
    end
  end

  @doc """
  Get risky sign-ins.
  """
  def list_risky_sign_ins(conn, params) do
    opts = [
      limit: params["limit"] |> parse_int(50) |> max(1) |> min(500),
      min_risk: parse_risk_level(Map.get(params, "min_risk"))
    ]

    opts = if params["since"] do
      case DateTime.from_iso8601(params["since"]) do
        {:ok, dt, _} -> Keyword.put(opts, :since, dt)
        _ -> opts
      end
    else
      opts
    end

    case RiskScoring.get_risky_sign_ins(opts) do
      {:ok, sign_ins} ->
        json(conn, %{
          status: "success",
          data: sign_ins
        })

      {:error, reason} ->
        identity_dependency_error(conn, "risk_scoring_unavailable", reason)
    end
  end

  @doc """
  Get statistics.
  """
  def statistics(conn, _params) do
    case RiskScoring.get_statistics() do
      {:ok, stats} ->
        json(conn, %{
          status: "success",
          data: stats
        })

      {:error, reason} ->
        identity_dependency_error(conn, "risk_scoring_unavailable", reason)
    end
  end

  @doc """
  Recalculate risk score for a user.
  """
  def recalculate_risk(conn, %{"user_id" => user_id}) do
    case RiskScoring.recalculate_risk(user_id) do
      {:ok, risk_data} ->
        json(conn, %{
          status: "success",
          data: serialize_risk_score(risk_data, user_id)
        })

      {:error, reason} ->
        identity_dependency_error(conn, "risk_scoring_unavailable", reason)
    end
  end

  @doc """
  Reset risk data for a user after remediation.
  """
  def reset_user_risk(conn, %{"user_id" => user_id}) do
    RiskScoring.reset_user_risk(user_id)
    json(conn, %{status: "success", message: "Risk data reset for user"})
  end

  @doc """
  Get user baseline profile.
  """
  def get_baseline(conn, %{"user_id" => user_id}) do
    case RiskScoring.get_baseline(user_id) do
      {:ok, baseline} ->
        json(conn, %{
          status: "success",
          data: baseline
        })

      {:error, reason} ->
        conn
        |> put_status(:not_found)
        |> json(%{status: "error", message: inspect(reason)})
    end
  end

  # ============================================================================
  # Azure AD Integration
  # ============================================================================

  @doc """
  Get Azure AD integration status.
  """
  def azure_ad_status(conn, _params) do
    status = AzureAD.status()
    json(conn, %{status: "success", data: status})
  end

  @doc """
  Trigger Azure AD sync.
  """
  def azure_ad_sync(conn, _params) do
    AzureAD.sync_now()
    json(conn, %{status: "success", message: "Sync initiated"})
  end

  @doc """
  Get sign-ins from Azure AD.
  """
  def azure_ad_sign_ins(conn, params) do
    opts = []
    |> maybe_add_opt(:user_id, params["user_id"])
    |> maybe_add_opt(:status, params["status"])
    |> maybe_add_opt(:risk_level, params["risk_level"])
    |> maybe_add_opt(:limit, bounded_limit(params["limit"], 100))
    |> maybe_add_since(params["since"])

    case AzureAD.get_sign_ins(opts) do
      {:ok, sign_ins} ->
        json(conn, %{
          status: "success",
          data: sign_ins
        })

      {:error, :not_configured} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{status: "error", message: "Azure AD integration not configured"})

      {:error, reason} ->
        identity_dependency_error(conn, "azure_ad_unavailable", reason)
    end
  end

  @doc """
  Get risky users from Azure AD Identity Protection.
  """
  def azure_ad_risky_users(conn, params) do
    opts = []
    |> maybe_add_opt(:risk_level, params["risk_level"])
    |> maybe_add_opt(:risk_state, params["risk_state"])
    |> maybe_add_opt(:limit, bounded_limit(params["limit"], 100))

    case AzureAD.get_risky_users(opts) do
      {:ok, users} ->
        json(conn, %{
          status: "success",
          data: users
        })

      {:error, :not_configured} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{status: "error", message: "Azure AD integration not configured"})

      {:error, reason} ->
        identity_dependency_error(conn, "azure_ad_unavailable", reason)
    end
  end

  @doc """
  Get conditional access policies.
  """
  def azure_ad_policies(conn, _params) do
    case AzureAD.get_conditional_access_policies() do
      {:ok, policies} ->
        json(conn, %{
          status: "success",
          data: policies
        })

      {:error, :not_configured} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{status: "error", message: "Azure AD integration not configured"})

      {:error, reason} ->
        identity_dependency_error(conn, "azure_ad_unavailable", reason)
    end
  end

  @doc """
  Get service principals.
  """
  def azure_ad_service_principals(conn, params) do
    opts = []
    |> maybe_add_opt(:app_id, params["app_id"])
    |> maybe_add_opt(:display_name, params["display_name"])
    |> maybe_add_opt(:limit, bounded_limit(params["limit"], 100))

    case AzureAD.get_service_principals(opts) do
      {:ok, principals} ->
        json(conn, %{
          status: "success",
          data: principals
        })

      {:error, :not_configured} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{status: "error", message: "Azure AD integration not configured"})

      {:error, reason} ->
        identity_dependency_error(conn, "azure_ad_unavailable", reason)
    end
  end

  @doc """
  Get directory audit logs.
  """
  def azure_ad_audits(conn, params) do
    opts = []
    |> maybe_add_opt(:activity_display_name, params["activity"])
    |> maybe_add_opt(:category, params["category"])
    |> maybe_add_opt(:limit, bounded_limit(params["limit"], 100))
    |> maybe_add_since(params["since"])

    case AzureAD.get_directory_audits(opts) do
      {:ok, audits} ->
        json(conn, %{
          status: "success",
          data: audits
        })

      {:error, :not_configured} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{status: "error", message: "Azure AD integration not configured"})

      {:error, reason} ->
        identity_dependency_error(conn, "azure_ad_unavailable", reason)
    end
  end

  @doc """
  Get user details from Azure AD.
  """
  def azure_ad_user(conn, %{"user_id" => user_id}) do
    case AzureAD.get_user(user_id) do
      {:ok, user} ->
        json(conn, %{
          status: "success",
          data: user
        })

      {:error, :not_configured} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{status: "error", message: "Azure AD integration not configured"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{status: "error", message: "User not found"})

      {:error, reason} ->
        identity_dependency_error(conn, "azure_ad_unavailable", reason)
    end
  end

  # ============================================================================
  # Response Actions
  # ============================================================================

  @doc """
  Confirm user as compromised in Azure AD.
  """
  def confirm_compromised(conn, %{"user_id" => user_id}) do
    case AzureAD.confirm_user_compromised(user_id) do
      {:ok, _} ->
        Logger.info("User #{user_id} marked as compromised by #{conn.assigns[:current_user]}")
        json(conn, %{status: "success", message: "User marked as compromised"})

      {:error, :not_configured} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{status: "error", message: "Azure AD integration not configured"})

      {:error, reason} ->
        identity_dependency_error(conn, "azure_ad_unavailable", reason)
    end
  end

  @doc """
  Dismiss risky user in Azure AD.
  """
  def dismiss_risk(conn, %{"user_id" => user_id}) do
    case AzureAD.dismiss_risky_user(user_id) do
      {:ok, _} ->
        Logger.info("User #{user_id} risk dismissed by #{conn.assigns[:current_user]}")
        json(conn, %{status: "success", message: "User risk dismissed"})

      {:error, :not_configured} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{status: "error", message: "Azure AD integration not configured"})

      {:error, reason} ->
        identity_dependency_error(conn, "azure_ad_unavailable", reason)
    end
  end

  @doc """
  Force password reset for user.
  """
  def force_password_reset(conn, %{"user_id" => user_id}) do
    case AzureAD.force_password_reset(user_id) do
      {:ok, _} ->
        Logger.info("Password reset forced for user #{user_id} by #{conn.assigns[:current_user]}")
        json(conn, %{status: "success", message: "Password reset required on next sign-in"})

      {:error, :not_configured} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{status: "error", message: "Azure AD integration not configured"})

      {:error, reason} ->
        identity_dependency_error(conn, "azure_ad_unavailable", reason)
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp identity_dependency_error(conn, code, reason) do
    conn
    |> put_status(:service_unavailable)
    |> json(%{
      status: "error",
      code: code,
      message: "Identity dependency is unavailable",
      detail: inspect(reason)
    })
  end

  defp serialize_risk_score(risk_data, user_id) do
    %{
      userId: user_id,
      score: risk_data.score,
      level: to_string(risk_data.level),
      factors: Enum.map(risk_data.factors || [], fn f ->
        %{
          name: f.name,
          contribution: f.contribution,
          details: f.details
        }
      end),
      trend: to_string(risk_data.trend),
      lastUpdated: format_datetime(risk_data.last_updated),
      externalSignals: risk_data[:external_signals] || %{}
    }
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp maybe_add_opt(opts, _key, nil), do: opts
  defp maybe_add_opt(opts, key, value), do: Keyword.put(opts, key, value)

  defp maybe_add_since(opts, nil), do: opts
  defp maybe_add_since(opts, since) when is_binary(since) do
    case DateTime.from_iso8601(since) do
      {:ok, dt, _} -> Keyword.put(opts, :since, dt)
      _ -> opts
    end
  end
  defp maybe_add_since(opts, _), do: opts

  defp bounded_limit(value, default) do
    value
    |> parse_int(default)
    |> max(1)
    |> min(500)
  end

  defp parse_int(nil, default), do: default
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(_, default), do: default

  defp parse_risk_sort("score_asc"), do: :score_asc
  defp parse_risk_sort("name_asc"), do: :name_asc
  defp parse_risk_sort("name_desc"), do: :name_desc
  defp parse_risk_sort("recent"), do: :recent
  defp parse_risk_sort(_), do: :score_desc

  defp parse_risk_level("low"), do: :low
  defp parse_risk_level("high"), do: :high
  defp parse_risk_level("critical"), do: :critical
  defp parse_risk_level(_), do: :medium

end
