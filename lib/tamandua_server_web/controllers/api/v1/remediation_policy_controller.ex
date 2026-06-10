defmodule TamanduaServerWeb.API.V1.RemediationPolicyController do
  @moduledoc """
  REST API for managing remediation policies.

  ## Endpoints

  - GET /api/v1/remediation/policies - List all policies
  - GET /api/v1/remediation/policies/:id - Get a specific policy
  - POST /api/v1/remediation/policies - Create a new policy
  - PUT /api/v1/remediation/policies/:id - Update a policy
  - DELETE /api/v1/remediation/policies/:id - Delete a policy
  - POST /api/v1/remediation/policies/evaluate - Manually evaluate an alert
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Remediation.Policy
  alias TamanduaServer.Remediation.PolicyEngine

  action_fallback TamanduaServerWeb.FallbackController

  @doc "List all remediation policies"
  def index(conn, params) do
    organization_id = params["organization_id"]
    policies = Policy.list_policies(organization_id: organization_id)

    json(conn, %{
      data: Enum.map(policies, &serialize/1),
      action_types: Policy.action_types(),
      count: length(policies)
    })
  end

  @doc "Get a specific policy by ID"
  def show(conn, %{"id" => id}) do
    policy = Policy.get_policy!(id)
    json(conn, %{data: serialize(policy)})
  end

  @doc "Create a new remediation policy"
  def create(conn, %{"policy" => policy_params}) do
    # Add organization_id from current user if not provided
    policy_params = maybe_add_organization_id(conn, policy_params)

    case Policy.create_policy(policy_params) do
      {:ok, policy} ->
        # Notify engine to reload policies
        PolicyEngine.reload_policies()

        conn
        |> put_status(:created)
        |> json(%{data: serialize(policy)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  @doc "Update an existing policy"
  def update(conn, %{"id" => id, "policy" => policy_params}) do
    policy = Policy.get_policy!(id)

    case Policy.update_policy(policy, policy_params) do
      {:ok, updated} ->
        # Notify engine to reload policies
        PolicyEngine.reload_policies()

        json(conn, %{data: serialize(updated)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  @doc "Delete a policy"
  def delete(conn, %{"id" => id}) do
    policy = Policy.get_policy!(id)

    case Policy.delete_policy(policy) do
      {:ok, _} ->
        PolicyEngine.reload_policies()
        json(conn, %{deleted: true})

      {:error, :cannot_delete_default} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Cannot delete default policy"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc "Manually trigger policy evaluation for an alert"
  def evaluate(conn, %{"alert_id" => alert_id}) do
    organization_id = conn.assigns[:current_user].organization_id

    case TamanduaServer.Alerts.get_alert_for_org(organization_id, alert_id) do
      {:ok, alert} ->
        result = PolicyEngine.evaluate(alert)
        json(conn, %{data: result})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Alert not found"})
    end
  end

  # === Private Helpers ===

  defp serialize(policy) do
    %{
      id: policy.id,
      name: policy.name,
      description: policy.description,
      is_enabled: policy.is_enabled,
      is_default: policy.is_default,
      priority: policy.priority,
      auto_threshold: policy.auto_threshold,
      manual_threshold: policy.manual_threshold,
      action_type: policy.action_type,
      action_config: policy.action_config,
      conditions: policy.conditions,
      agent_group_ids: policy.agent_group_ids,
      organization_id: policy.organization_id,
      inserted_at: policy.inserted_at,
      updated_at: policy.updated_at
    }
  end

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp maybe_add_organization_id(conn, params) do
    if Map.has_key?(params, "organization_id") do
      params
    else
      case conn.assigns[:current_user] do
        %{organization_id: org_id} when not is_nil(org_id) ->
          Map.put(params, "organization_id", org_id)
        _ ->
          params
      end
    end
  end
end
