defmodule TamanduaServer.Agents.BaselineManager do
  @moduledoc """
  Manages configuration baselines for agents.

  Provides helper functions for creating, updating, and managing
  configuration baselines.
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.{Agent, ConfigurationBaseline, Policy}

  @doc """
  Creates a baseline from an agent's current configuration.
  """
  def create_from_agent(agent_id, opts \\ []) do
    with {:ok, agent} <- get_agent(agent_id) do
      baseline_opts = [
        version: get_next_version(agent_id),
        is_active: Keyword.get(opts, :is_active, false),
        notes: Keyword.get(opts, :notes),
        created_by_id: Keyword.get(opts, :created_by_id)
      ]

      ConfigurationBaseline.from_agent_config(agent, agent.config, baseline_opts)
      |> Repo.insert()
    end
  end

  @doc """
  Creates a baseline from a policy.
  """
  def create_from_policy(agent_id, policy_id, opts \\ []) do
    with {:ok, agent} <- get_agent(agent_id),
         {:ok, policy} <- get_policy(policy_id) do

      attrs = %{
        agent_id: agent_id,
        organization_id: agent.organization_id,
        collector_settings: policy.policy_data["collectors"] || %{},
        response_permissions: policy.policy_data["response"] || %{},
        network_settings: policy.policy_data["network"] || %{},
        file_paths: policy.policy_data["paths"] || %{},
        resource_limits: policy.policy_data["resource_limits"] || %{},
        enabled_features: extract_features(policy.policy_data),
        rule_versions: policy.policy_data["rules"] || %{},
        baseline_version: get_next_version(agent_id),
        is_active: Keyword.get(opts, :is_active, false),
        notes: Keyword.get(opts, :notes, "Created from policy: #{policy.name}"),
        created_by_id: Keyword.get(opts, :created_by_id)
      }

      %ConfigurationBaseline{}
      |> ConfigurationBaseline.changeset(attrs)
      |> Repo.insert()
    end
  end

  @doc """
  Activates a baseline and deactivates all others for the agent.
  """
  def activate_baseline(baseline_id) do
    baseline = Repo.get!(ConfigurationBaseline, baseline_id)

    Repo.transaction(fn ->
      # Deactivate all other baselines for this agent
      from(b in ConfigurationBaseline,
        where: b.agent_id == ^baseline.agent_id and b.id != ^baseline_id,
        update: [set: [is_active: false]]
      )
      |> Repo.update_all([])

      # Activate this baseline
      baseline
      |> ConfigurationBaseline.changeset(%{is_active: true})
      |> Repo.update!()
    end)
  end

  @doc """
  Gets the active baseline for an agent.
  """
  def get_active_baseline(agent_id) do
    case Repo.one(
      from b in ConfigurationBaseline,
        where: b.agent_id == ^agent_id and b.is_active == true,
        order_by: [desc: b.baseline_version],
        limit: 1
    ) do
      nil -> {:error, :no_active_baseline}
      baseline -> {:ok, baseline}
    end
  end

  @doc """
  Lists all baselines for an agent.
  """
  def list_baselines(agent_id) do
    Repo.all(
      from b in ConfigurationBaseline,
        where: b.agent_id == ^agent_id,
        order_by: [desc: b.baseline_version]
    )
  end

  @doc """
  Compares two baselines and returns differences.
  """
  def compare_baselines(baseline_id_1, baseline_id_2) do
    baseline1 = Repo.get!(ConfigurationBaseline, baseline_id_1)
    baseline2 = Repo.get!(ConfigurationBaseline, baseline_id_2)

    %{
      collectors: compare_maps(baseline1.collector_settings, baseline2.collector_settings),
      response: compare_maps(baseline1.response_permissions, baseline2.response_permissions),
      network: compare_maps(baseline1.network_settings, baseline2.network_settings),
      paths: compare_maps(baseline1.file_paths, baseline2.file_paths),
      resources: compare_maps(baseline1.resource_limits, baseline2.resource_limits),
      features: compare_maps(baseline1.enabled_features, baseline2.enabled_features),
      rules: compare_maps(baseline1.rule_versions, baseline2.rule_versions)
    }
  end

  @doc """
  Updates a baseline with new configuration.
  """
  def update_baseline(baseline_id, updates, opts \\ []) do
    baseline = Repo.get!(ConfigurationBaseline, baseline_id)

    # If updating active baseline, create new version instead
    if baseline.is_active and Keyword.get(opts, :create_new_version, true) do
      create_new_version(baseline, updates, opts)
    else
      baseline
      |> ConfigurationBaseline.changeset(updates)
      |> Repo.update()
    end
  end

  @doc """
  Archives old baselines, keeping only the last N versions.
  """
  def archive_old_baselines(agent_id, keep_versions \\ 10) do
    baselines = list_baselines(agent_id)

    baselines
    |> Enum.drop(keep_versions)
    |> Enum.each(fn baseline ->
      unless baseline.is_active do
        Repo.delete(baseline)
      end
    end)

    :ok
  end

  @doc """
  Exports a baseline to a JSON file.
  """
  def export_baseline(baseline_id) do
    baseline = Repo.get!(ConfigurationBaseline, baseline_id)
    |> Repo.preload([:agent, :organization])

    export_data = %{
      version: 1,
      exported_at: DateTime.utc_now(),
      agent: %{
        hostname: baseline.agent.hostname,
        os_type: baseline.agent.os_type
      },
      baseline: %{
        version: baseline.baseline_version,
        hash: baseline.baseline_hash,
        collectors: baseline.collector_settings,
        response: baseline.response_permissions,
        network: baseline.network_settings,
        paths: baseline.file_paths,
        resources: baseline.resource_limits,
        features: baseline.enabled_features,
        rules: baseline.rule_versions
      }
    }

    Jason.encode!(export_data, pretty: true)
  end

  @doc """
  Imports a baseline from JSON.
  """
  def import_baseline(agent_id, json_data, opts \\ []) do
    with {:ok, data} <- Jason.decode(json_data),
         {:ok, agent} <- get_agent(agent_id) do

      attrs = %{
        agent_id: agent_id,
        organization_id: agent.organization_id,
        collector_settings: data["baseline"]["collectors"],
        response_permissions: data["baseline"]["response"],
        network_settings: data["baseline"]["network"],
        file_paths: data["baseline"]["paths"],
        resource_limits: data["baseline"]["resources"],
        enabled_features: data["baseline"]["features"],
        rule_versions: data["baseline"]["rules"],
        baseline_version: get_next_version(agent_id),
        is_active: Keyword.get(opts, :is_active, false),
        notes: Keyword.get(opts, :notes, "Imported from JSON"),
        created_by_id: Keyword.get(opts, :created_by_id)
      }

      %ConfigurationBaseline{}
      |> ConfigurationBaseline.changeset(attrs)
      |> Repo.insert()
    end
  end

  @doc """
  Validates a baseline configuration.
  """
  def validate_baseline(baseline) do
    errors = []

    # Validate collectors
    errors =
      if is_map(baseline.collector_settings) and map_size(baseline.collector_settings) > 0 do
        errors
      else
        ["Collector settings must be a non-empty map" | errors]
      end

    # Validate response permissions
    errors =
      if is_map(baseline.response_permissions) and
         is_list(baseline.response_permissions["allowed_actions"]) do
        errors
      else
        ["Response permissions must include allowed_actions list" | errors]
      end

    # Validate resource limits
    errors =
      if is_map(baseline.resource_limits) and
         is_integer(baseline.resource_limits["max_cpu_percent"]) and
         baseline.resource_limits["max_cpu_percent"] > 0 do
        errors
      else
        ["Resource limits must include valid max_cpu_percent" | errors]
      end

    if Enum.empty?(errors) do
      :ok
    else
      {:error, errors}
    end
  end

  @doc """
  Bulk creates baselines for multiple agents from a policy.
  """
  def bulk_create_from_policy(agent_ids, policy_id, opts \\ []) when is_list(agent_ids) do
    results = Enum.map(agent_ids, fn agent_id ->
      case create_from_policy(agent_id, policy_id, opts) do
        {:ok, baseline} -> {:ok, agent_id, baseline}
        {:error, reason} -> {:error, agent_id, reason}
      end
    end)

    successes = Enum.count(results, fn {status, _, _} -> status == :ok end)
    failures = Enum.count(results, fn {status, _, _} -> status == :error end)

    {:ok, %{
      total: length(agent_ids),
      successes: successes,
      failures: failures,
      results: results
    }}
  end

  # Private functions

  defp get_agent(agent_id) do
    case Repo.get(Agent, agent_id) do
      nil -> {:error, :agent_not_found}
      agent -> {:ok, agent}
    end
  end

  defp get_policy(policy_id) do
    case Repo.get(Policy, policy_id) do
      nil -> {:error, :policy_not_found}
      policy -> {:ok, policy}
    end
  end

  defp get_next_version(agent_id) do
    case Repo.one(
      from b in ConfigurationBaseline,
        where: b.agent_id == ^agent_id,
        select: max(b.baseline_version)
    ) do
      nil -> 1
      version -> version + 1
    end
  end

  defp extract_features(policy_data) do
    detection = policy_data["detection"] || %{}
    features = policy_data["features"] || %{}

    %{
      "yara_enabled" => detection["yara_enabled"] || false,
      "sigma_enabled" => detection["sigma_enabled"] || false,
      "ml_enabled" => detection["ml_enabled"] || false,
      "ioc_scanning" => detection["ioc_scanning"] || false,
      "honeyfiles" => detection["honeyfiles"] || false,
      "self_defense" => features["self_defense"] || false,
      "telemetry_streaming" => features["telemetry_streaming"] || true
    }
  end

  defp create_new_version(baseline, updates, opts) do
    new_version_attrs = Map.merge(
      Map.take(baseline, [
        :agent_id,
        :organization_id,
        :collector_settings,
        :response_permissions,
        :network_settings,
        :file_paths,
        :resource_limits,
        :enabled_features,
        :rule_versions
      ]),
      updates
    )
    |> Map.put(:baseline_version, get_next_version(baseline.agent_id))
    |> Map.put(:is_active, false)
    |> Map.put(:notes, Keyword.get(opts, :notes, "Updated version"))
    |> Map.put(:created_by_id, Keyword.get(opts, :created_by_id))

    %ConfigurationBaseline{}
    |> ConfigurationBaseline.changeset(new_version_attrs)
    |> Repo.insert()
  end

  defp compare_maps(map1, map2) when is_map(map1) and is_map(map2) do
    all_keys = MapSet.union(MapSet.new(Map.keys(map1)), MapSet.new(Map.keys(map2)))

    Enum.reduce(all_keys, %{}, fn key, acc ->
      val1 = Map.get(map1, key)
      val2 = Map.get(map2, key)

      if val1 != val2 do
        Map.put(acc, key, %{before: val1, after: val2})
      else
        acc
      end
    end)
  end

  defp compare_maps(_map1, _map2), do: %{}
end
