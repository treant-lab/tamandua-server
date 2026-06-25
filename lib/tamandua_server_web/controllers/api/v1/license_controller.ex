defmodule TamanduaServerWeb.API.V1.LicenseController do
  @moduledoc """
  REST API controller for license management.

  Provides endpoints for:
  - Viewing license status and usage
  - Activating/deactivating licenses
  - Managing feature licenses
  - Viewing usage metrics
  - MSSP sub-licensing operations
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Licensing.{License, Enforcement}
  alias TamanduaServer.AuditLog

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Get current license status and usage for an organization.
  """
  def show(conn, _params) do
    organization_id = conn.assigns.current_organization_id

    usage = License.get_usage(organization_id)
    enforcement = Enforcement.get_status(organization_id)

    json(conn, %{
      license: %{
        tier: usage.license_tier,
        status: usage.license_status,
        expires_at: usage.expires_at,
        days_remaining: usage.days_remaining,
        in_grace_period: usage.in_grace_period
      },
      usage: %{
        agents: %{
          current: usage.agent_count,
          limit: usage.agent_limit,
          percent: usage.agent_usage_percent
        },
        users: %{
          current: usage.user_count
        }
      },
      features: usage.features,
      enforcement: %{
        enforced: enforcement.enforced,
        warnings: enforcement.warnings,
        blocked_actions: enforcement.blocked_actions
      }
    })
  end

  @doc """
  Activate a license key for an organization.
  """
  def activate(conn, %{"license_key" => license_key}) do
    organization_id = conn.assigns.current_organization_id
    user_id = conn.assigns.current_user.id

    case License.activate_license(organization_id, license_key) do
      {:ok, license} ->
        AuditLog.log(%{
          action: "license_activated",
          action_type: "update",
          resource_type: "license",
          resource_id: license.id,
          organization_id: organization_id,
          user_id: user_id,
          details: %{
            tier: license.tier,
            agent_limit: license.agent_limit,
            expires_at: license.expires_at
          }
        })

        conn
        |> put_status(:ok)
        |> json(%{
          message: "License activated successfully",
          license: %{
            id: license.id,
            tier: license.tier,
            agent_limit: license.agent_limit,
            features: license.features,
            expires_at: license.expires_at
          }
        })

      {:error, :invalid_signature} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Invalid license key signature"})

      {:error, :invalid_format} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Invalid license key format"})

      {:error, :license_expired} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "License key has expired"})

      {:error, :organization_mismatch} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "License key is not valid for this organization"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to activate license: #{inspect(reason)}"})
    end
  end

  @doc """
  Deactivate current license (for transfer).
  """
  def deactivate(conn, _params) do
    organization_id = conn.assigns.current_organization_id
    user_id = conn.assigns.current_user.id

    case License.deactivate_license(organization_id) do
      {:ok, _} ->
        AuditLog.log(%{
          action: "license_deactivated",
          action_type: "update",
          resource_type: "license",
          organization_id: organization_id,
          user_id: user_id
        })

        json(conn, %{message: "License deactivated successfully"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to deactivate license: #{inspect(reason)}"})
    end
  end

  @doc """
  Get licensed features for an organization.
  """
  def features(conn, _params) do
    organization_id = conn.assigns.current_organization_id

    {:ok, features} = License.get_features(organization_id)

    json(conn, %{
      features: features,
      feature_details: Enum.map(features, fn f ->
        %{
          name: f,
          description: TamanduaServer.Licensing.FeatureLicense.feature_description(to_string(f))
        }
      end)
    })
  end

  @doc """
  Get usage metrics for billing period.
  """
  def usage_metrics(conn, params) do
    organization_id = conn.assigns.current_organization_id

    opts = []

    opts = if params["date_from"] do
      case DateTime.from_iso8601(params["date_from"]) do
        {:ok, dt, _} -> Keyword.put(opts, :date_from, dt)
        _ -> opts
      end
    else
      opts
    end

    opts = if params["date_to"] do
      case DateTime.from_iso8601(params["date_to"]) do
        {:ok, dt, _} -> Keyword.put(opts, :date_to, dt)
        _ -> opts
      end
    else
      opts
    end

    metrics = License.get_usage_metrics(organization_id, opts)

    json(conn, %{
      metrics: metrics,
      period: %{
        from: Keyword.get(opts, :date_from),
        to: Keyword.get(opts, :date_to)
      }
    })
  end

  @doc """
  Check if a specific action would be allowed by the license.
  """
  def check_action(conn, %{"action" => action}) do
    organization_id = conn.assigns.current_organization_id

    case license_action(action) do
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid action: #{action}"})

      action_atom ->
        allowed = Enforcement.would_allow?(organization_id, action_atom)

        json(conn, %{
          action: action,
          allowed: allowed
        })
    end
  end

  @doc """
  Get available license tiers and their features.
  """
  def tiers(conn, _params) do
    tiers = [:trial, :pro, :enterprise, :mssp]
    |> Enum.map(fn tier ->
      limits = License.tier_limits(tier)
      %{
        tier: tier,
        agent_limit: limits.agent_limit,
        user_limit: limits.user_limit,
        retention_days: limits.retention_days,
        features: limits.features
      }
    end)

    json(conn, %{tiers: tiers})
  end

  @doc """
  Verify a license key without activating it.
  """
  def verify(conn, %{"license_key" => license_key}) do
    case License.verify_license_key(license_key) do
      {:ok, claims} ->
        json(conn, %{
          valid: true,
          claims: %{
            tier: claims["tier"],
            agent_limit: claims["agent_limit"],
            features: claims["features"],
            expires_at: DateTime.from_unix!(claims["exp"]) |> DateTime.to_iso8601()
          }
        })

      {:error, reason} ->
        json(conn, %{
          valid: false,
          error: inspect(reason)
        })
    end
  end

  # MSSP Sub-licensing endpoints

  @doc """
  List sub-licenses for MSSP tenants.
  """
  def list_sub_licenses(conn, _params) do
    organization_id = conn.assigns.current_organization_id

    # Verify MSSP tier
    case License.get_license(organization_id) do
      {:ok, license} when license.tier == :mssp ->
        sub_licenses = get_sub_licenses(organization_id)
        json(conn, %{sub_licenses: sub_licenses})

      _ ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Sub-licensing requires MSSP tier"})
    end
  end

  @doc """
  Create a sub-license for a managed tenant.
  """
  def create_sub_license(conn, %{"child_organization_id" => child_org_id} = params) do
    organization_id = conn.assigns.current_organization_id
    user_id = conn.assigns.current_user.id

    # Verify MSSP tier and available capacity
    with {:ok, license} <- License.get_license(organization_id),
         true <- license.tier == :mssp,
         :ok <- check_sub_license_capacity(organization_id, params) do

      attrs = %{
        parent_organization_id: organization_id,
        child_organization_id: child_org_id,
        parent_license_id: license.id,
        allocated_agents: params["allocated_agents"] || 10,
        allocated_features: params["allocated_features"] || license.features,
        expires_at: license.expires_at,
        is_active: true
      }

      case create_sub_license_record(attrs) do
        {:ok, sub_license} ->
          AuditLog.log(%{
            action: "sub_license_created",
            action_type: "create",
            resource_type: "sub_license",
            resource_id: sub_license.id,
            organization_id: organization_id,
            user_id: user_id,
            details: %{
              child_organization_id: child_org_id,
              allocated_agents: attrs.allocated_agents
            }
          })

          conn
          |> put_status(:created)
          |> json(%{
            message: "Sub-license created successfully",
            sub_license: sub_license
          })

        {:error, changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: "Failed to create sub-license", details: format_errors(changeset)})
      end
    else
      false ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Sub-licensing requires MSSP tier"})

      {:error, :capacity_exceeded} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Insufficient agent capacity for sub-license"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to create sub-license: #{inspect(reason)}"})
    end
  end

  @doc """
  Revoke a sub-license.
  """
  def revoke_sub_license(conn, %{"id" => sub_license_id}) do
    organization_id = conn.assigns.current_organization_id
    user_id = conn.assigns.current_user.id

    case revoke_sub_license_record(organization_id, sub_license_id) do
      {:ok, _} ->
        AuditLog.log(%{
          action: "sub_license_revoked",
          action_type: "delete",
          resource_type: "sub_license",
          resource_id: sub_license_id,
          organization_id: organization_id,
          user_id: user_id
        })

        json(conn, %{message: "Sub-license revoked successfully"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Sub-license not found"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to revoke sub-license: #{inspect(reason)}"})
    end
  end

  # Private helper functions

  defp get_sub_licenses(organization_id) do
    import Ecto.Query

    from(sl in "mssp_sub_licenses",
      where: sl.parent_organization_id == ^organization_id and sl.is_active == true,
      join: o in "organizations", on: o.id == sl.child_organization_id,
      select: %{
        id: sl.id,
        child_organization_id: sl.child_organization_id,
        child_organization_name: o.name,
        allocated_agents: sl.allocated_agents,
        allocated_features: sl.allocated_features,
        expires_at: sl.expires_at,
        inserted_at: sl.inserted_at
      }
    )
    |> TamanduaServer.Repo.all()
  end

  defp check_sub_license_capacity(organization_id, params) do
    import Ecto.Query

    # Get total allocated to sub-licenses
    total_allocated = from(sl in "mssp_sub_licenses",
      where: sl.parent_organization_id == ^organization_id and sl.is_active == true,
      select: sum(sl.allocated_agents)
    )
    |> TamanduaServer.Repo.one() || 0

    # Get parent license limit
    {:ok, license} = License.get_license(organization_id)

    requested = params["allocated_agents"] || 10

    if total_allocated + requested <= license.agent_limit do
      :ok
    else
      {:error, :capacity_exceeded}
    end
  end

  defp create_sub_license_record(attrs) do
    import Ecto.Query

    id = Ecto.UUID.generate()
    now = DateTime.utc_now()

    result = TamanduaServer.Repo.insert_all("mssp_sub_licenses", [
      %{
        id: id,
        parent_organization_id: attrs.parent_organization_id,
        child_organization_id: attrs.child_organization_id,
        parent_license_id: attrs.parent_license_id,
        allocated_agents: attrs.allocated_agents,
        allocated_features: attrs.allocated_features,
        expires_at: attrs.expires_at,
        is_active: true,
        metadata: %{},
        inserted_at: now,
        updated_at: now
      }
    ])

    case result do
      {1, _} -> {:ok, Map.put(attrs, :id, id)}
      _ -> {:error, :insert_failed}
    end
  end

  defp revoke_sub_license_record(organization_id, sub_license_id) do
    import Ecto.Query

    result = from(sl in "mssp_sub_licenses",
      where: sl.id == ^sub_license_id and sl.parent_organization_id == ^organization_id
    )
    |> TamanduaServer.Repo.update_all(set: [is_active: false, updated_at: DateTime.utc_now()])

    case result do
      {1, _} -> {:ok, :revoked}
      {0, _} -> {:error, :not_found}
    end
  end

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  @license_actions ~w(
    view_dashboard view_alerts manage_alerts create_rule update_rule delete_rule
    kill_process quarantine_file isolate_endpoint execute_hunt create_playbook
    execute_playbook view_behavioral live_response_session collect_forensics
    api_request configure_sso generate_compliance_report view_mssp_portal
    manage_tenants configure_branding ai_query threat_intel_lookup add_agent
    add_user view_events execute_query
  )

  defp license_action(action) when action in @license_actions, do: String.to_existing_atom(action)
  defp license_action(_), do: nil
end
