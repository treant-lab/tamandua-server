defmodule TamanduaServerWeb.API.V1.PreventionPolicyController do
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Detection.PreventionPolicy

  action_fallback TamanduaServerWeb.FallbackController

  def index(conn, _params) do
    policies = PreventionPolicy.list_policies(organization_id: current_org_id(conn))
    json(conn, %{
      data: Enum.map(policies, &serialize/1),
      aggressiveness_levels: PreventionPolicy.aggressiveness_summary(),
      threat_categories: PreventionPolicy.threat_categories()
    })
  end

  def show(conn, %{"id" => id}) do
    policy = authorize_policy!(conn, id)
    json(conn, %{data: serialize(policy)})
  end

  def create(conn, %{"policy" => policy_params}) do
    policy_params = maybe_put_org_id(conn, policy_params)

    case PreventionPolicy.create_policy(policy_params) do
      {:ok, policy} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize(policy)})
      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  def update(conn, %{"id" => id, "policy" => policy_params}) do
    policy = authorize_policy!(conn, id)
    policy_params = maybe_put_org_id(conn, policy_params)

    case PreventionPolicy.update_policy(policy, policy_params) do
      {:ok, updated} ->
        json(conn, %{data: serialize(updated)})
      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  def delete(conn, %{"id" => id}) do
    policy = authorize_policy!(conn, id)

    case PreventionPolicy.delete_policy(policy) do
      {:ok, _} -> json(conn, %{deleted: true})
      {:error, reason} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: reason})
    end
  end

  def assign_agents(conn, %{"id" => id, "agent_ids" => agent_ids}) do
    policy = authorize_policy!(conn, id)

    case PreventionPolicy.assign_to_agents(policy, agent_ids) do
      {:ok, updated} -> json(conn, %{data: serialize(updated)})
      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  def unassign_agents(conn, %{"id" => id, "agent_ids" => agent_ids}) do
    policy = authorize_policy!(conn, id)

    case PreventionPolicy.unassign_agents(policy, agent_ids) do
      {:ok, updated} -> json(conn, %{data: serialize(updated)})
      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  def agent_policy(conn, %{"agent_id" => agent_id}) do
    policy = PreventionPolicy.get_policy_for_agent(agent_id, organization_id: current_org_id(conn))
    json(conn, %{data: serialize(policy)})
  end

  @doc """
  Get ML response settings for an agent.
  Returns just the ML-specific settings for quick access.
  """
  def ml_settings(conn, %{"agent_id" => agent_id}) do
    settings = PreventionPolicy.get_ml_response_settings(agent_id)
    json(conn, %{data: settings})
  end

  defp serialize(policy) do
    category_settings = serialize_category_settings(policy.category_settings)
    exclusions = %{
      paths: policy.excluded_paths || [],
      processes: policy.excluded_processes || [],
      hashes: policy.excluded_hashes || [],
      users: policy.excluded_users || []
    }
    assigned_agents = Enum.map(policy.assigned_agents || [], &serialize_assigned_agent/1)
    network_containment = serialize_network_containment(policy.network_containment)

    %{
      id: policy.id,
      name: policy.name,
      description: policy.description,
      is_default: policy.is_default,
      is_enabled: policy.is_enabled,
      mode: policy.global_mode,
      aggressiveness: policy.global_aggressiveness,
      category_settings: category_settings,
      assigned_groups: policy.assigned_groups || [],
      assigned_agents: assigned_agents,
      exclusions: exclusions,
      network_containment: network_containment,
      auto_quarantine_threshold: policy.auto_quarantine_threshold,
      auto_kill_process: policy.auto_kill_process,
      ml_response_enabled: policy.ml_response_enabled,
      alert_threshold: policy.alert_threshold,
      created_at: policy.inserted_at,
      updated_at: policy.updated_at,
      # Legacy camelCase aliases for older React consumers.
      isDefault: policy.is_default,
      isEnabled: policy.is_enabled,
      globalMode: policy.global_mode,
      globalAggressiveness: policy.global_aggressiveness,
      categorySettings: category_settings,
      assignedGroups: policy.assigned_groups || [],
      assignedAgents: assigned_agents,
      excludedPaths: policy.excluded_paths || [],
      excludedProcesses: policy.excluded_processes || [],
      excludedHashes: policy.excluded_hashes || [],
      excludedUsers: policy.excluded_users || [],
      # ML Response settings
      autoQuarantineThreshold: policy.auto_quarantine_threshold,
      autoKillProcess: policy.auto_kill_process,
      mlResponseEnabled: policy.ml_response_enabled,
      alertThreshold: policy.alert_threshold,
      networkContainment: network_containment,
      insertedAt: policy.inserted_at,
      updatedAt: policy.updated_at
    }
  end

  defp serialize_category_settings(settings) when is_map(settings) do
    Enum.map(settings, fn {category, value} ->
      %{
        category: category,
        aggressiveness: Map.get(value, "aggressiveness") || Map.get(value, :aggressiveness) || "moderate",
        mode: Map.get(value, "mode") || Map.get(value, :mode) || "detect_and_prevent"
      }
    end)
  end
  defp serialize_category_settings(settings) when is_list(settings), do: settings
  defp serialize_category_settings(_), do: []

  defp serialize_network_containment(settings) when is_map(settings) do
    %{
      allow_dns: map_get(settings, "allow_dns", :allow_dns, true),
      allowed_ips: Map.get(settings, "allowed_ips") || Map.get(settings, :allowed_ips) || []
    }
  end
  defp serialize_network_containment(_), do: %{allow_dns: true, allowed_ips: []}

  defp map_get(map, string_key, atom_key, default) do
    cond do
      Map.has_key?(map, string_key) -> Map.get(map, string_key)
      Map.has_key?(map, atom_key) -> Map.get(map, atom_key)
      true -> default
    end
  end

  defp serialize_assigned_agent(%{id: id, hostname: hostname, os: os}) do
    %{id: id, hostname: hostname, os: os}
  end
  defp serialize_assigned_agent(%{"id" => id, "hostname" => hostname, "os" => os}) do
    %{id: id, hostname: hostname, os: os}
  end
  defp serialize_assigned_agent(id) do
    %{id: id, hostname: to_string(id), os: "unknown"}
  end

  defp maybe_put_org_id(conn, params) do
    case current_org_id(conn) do
      nil -> params
      org_id -> Map.put_new(params, "organization_id", org_id)
    end
  end

  defp current_org_id(conn) do
    conn.assigns[:current_organization_id] || conn.assigns[:organization_id]
  end

  defp authorize_policy!(conn, id) do
    policy = PreventionPolicy.get_policy!(id)
    org_id = current_org_id(conn)

    if is_nil(org_id) or is_nil(policy.organization_id) or policy.organization_id == org_id do
      policy
    else
      raise Ecto.NoResultsError, queryable: PreventionPolicy
    end
  end

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
