defmodule TamanduaServer.Agents.VersionManager do
  @moduledoc """
  Manages agent versions across the fleet.

  Provides:
  - Version tracking and inventory
  - Compatibility checking
  - End-of-life (EOL) detection
  - Outdated agent alerts
  - Version statistics and insights
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.Agent

  @doc """
  Get version inventory - count of agents by version.
  """
  @spec get_version_inventory(binary()) :: map()
  def get_version_inventory(organization_id) do
    Agent
    |> where([a], a.organization_id == ^organization_id)
    |> group_by([a], a.agent_version)
    |> select([a], {a.agent_version, count(a.id)})
    |> Repo.all()
    |> Enum.into(%{})
  end

  @doc """
  Get version breakdown by OS type.
  """
  @spec get_version_by_os(binary()) :: list(map())
  def get_version_by_os(organization_id) do
    Agent
    |> where([a], a.organization_id == ^organization_id)
    |> group_by([a], [a.agent_version, a.os_type])
    |> select([a], %{
      version: a.agent_version,
      os_type: a.os_type,
      count: count(a.id)
    })
    |> Repo.all()
  end

  @doc """
  Get outdated agents (versions older than the target version).
  """
  @spec get_outdated_agents(binary(), String.t()) :: list(Agent.t())
  def get_outdated_agents(organization_id, target_version) do
    Agent
    |> where([a], a.organization_id == ^organization_id)
    |> where([a], not is_nil(a.agent_version))
    |> Repo.all()
    |> Enum.filter(fn agent ->
      compare_versions(agent.agent_version, target_version) == :lt
    end)
    |> Repo.preload([:organization])
  end

  @doc """
  Get agents eligible for upgrade to a specific version.

  Considers:
  - Current version (must be older)
  - OS compatibility
  - Minimum version requirement
  """
  @spec get_eligible_agents(binary(), map()) :: list(Agent.t())
  def get_eligible_agents(organization_id, update_package) do
    Agent
    |> where([a], a.organization_id == ^organization_id)
    |> where([a], a.os_type == ^update_package.platform)
    |> where([a], not is_nil(a.agent_version))
    |> Repo.all()
    |> Enum.filter(fn agent ->
      # Agent version must be older than the update package version
      older_than_target = compare_versions(agent.agent_version, update_package.version) == :lt

      # If min_agent_version is set, agent must meet it
      meets_minimum =
        if update_package.min_agent_version do
          compare_versions(agent.agent_version, update_package.min_agent_version) in [:eq, :gt]
        else
          true
        end

      older_than_target and meets_minimum
    end)
  end

  @doc """
  Check version compatibility matrix.

  Returns compatibility status for a given version with various components.
  """
  @spec check_compatibility(String.t()) :: map()
  def check_compatibility(version) do
    %{
      backend: check_backend_compatibility(version),
      ml_service: check_ml_compatibility(version),
      schema: check_schema_compatibility(version),
      features: get_version_features(version)
    }
  end

  @doc """
  Get end-of-life status for a version.
  """
  @spec check_eol_status(String.t()) :: map()
  def check_eol_status(version) do
    # EOL policy: versions older than 6 months are EOL
    # In production, this would come from a configuration or database
    eol_versions = get_eol_versions()

    status =
      cond do
        version in eol_versions ->
          :eol

        is_approaching_eol?(version) ->
          :approaching_eol

        true ->
          :supported
      end

    %{
      status: status,
      version: version,
      eol_date: get_eol_date(version),
      support_ends: calculate_support_end_date(version),
      recommended_action:
        case status do
          :eol -> "Upgrade immediately - this version is no longer supported"
          :approaching_eol -> "Plan upgrade within 30 days"
          :supported -> "No action needed"
        end
    }
  end

  @doc """
  Get version statistics for the fleet.
  """
  @spec get_version_stats(binary()) :: map()
  def get_version_stats(organization_id) do
    agents = Repo.all(from a in Agent, where: a.organization_id == ^organization_id)

    versions =
      agents
      |> Enum.map(& &1.agent_version)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    latest_version = get_latest_version(versions)

    outdated_count =
      agents
      |> Enum.count(fn a ->
        a.agent_version && compare_versions(a.agent_version, latest_version) == :lt
      end)

    eol_count =
      agents
      |> Enum.count(fn a ->
        a.agent_version && check_eol_status(a.agent_version).status == :eol
      end)

    %{
      total_agents: length(agents),
      unique_versions: length(versions),
      latest_version: latest_version,
      up_to_date_count: length(agents) - outdated_count,
      outdated_count: outdated_count,
      eol_count: eol_count,
      outdated_percentage: calculate_percentage(outdated_count, length(agents)),
      version_diversity_score: calculate_diversity_score(versions)
    }
  end

  @doc """
  Compare two semantic versions.

  Returns:
  - `:gt` if v1 > v2
  - `:eq` if v1 == v2
  - `:lt` if v1 < v2
  - `:error` if comparison fails
  """
  @spec compare_versions(String.t(), String.t()) :: :gt | :eq | :lt | :error
  def compare_versions(v1, v2) when is_binary(v1) and is_binary(v2) do
    with {:ok, ver1} <- parse_version(v1),
         {:ok, ver2} <- parse_version(v2) do
      compare_parsed_versions(ver1, ver2)
    else
      _ -> :error
    end
  end

  def compare_versions(_, _), do: :error

  @doc """
  Parse semantic version string into components.
  """
  @spec parse_version(String.t()) :: {:ok, map()} | {:error, :invalid_version}
  def parse_version(version) when is_binary(version) do
    # Support versions like "1.2.3", "1.2.3-beta", "1.2.3-beta.1", "v1.2.3"
    version = String.trim_leading(version, "v")

    case Regex.run(~r/^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$/, version) do
      [_, major, minor, patch | prerelease] ->
        {:ok,
         %{
           major: String.to_integer(major),
           minor: String.to_integer(minor),
           patch: String.to_integer(patch),
           prerelease: List.first(prerelease)
         }}

      _ ->
        {:error, :invalid_version}
    end
  end

  def parse_version(_), do: {:error, :invalid_version}

  # Private Functions

  defp compare_parsed_versions(v1, v2) do
    cond do
      v1.major != v2.major -> if v1.major > v2.major, do: :gt, else: :lt
      v1.minor != v2.minor -> if v1.minor > v2.minor, do: :gt, else: :lt
      v1.patch != v2.patch -> if v1.patch > v2.patch, do: :gt, else: :lt
      v1.prerelease == v2.prerelease -> :eq
      is_nil(v1.prerelease) -> :gt
      is_nil(v2.prerelease) -> :lt
      true -> if v1.prerelease > v2.prerelease, do: :gt, else: :lt
    end
  end

  defp get_latest_version([]), do: "0.0.0"

  defp get_latest_version(versions) do
    versions
    |> Enum.filter(&valid_version?/1)
    |> Enum.max_by(
      fn v ->
        case parse_version(v) do
          {:ok, parsed} -> {parsed.major, parsed.minor, parsed.patch}
          _ -> {0, 0, 0}
        end
      end,
      fn -> "0.0.0" end
    )
  end

  defp valid_version?(version) do
    case parse_version(version) do
      {:ok, _} -> true
      _ -> false
    end
  end

  defp check_backend_compatibility(version) do
    # In production, this would query actual compatibility data
    case parse_version(version) do
      {:ok, %{major: major}} when major >= 1 -> :compatible
      _ -> :incompatible
    end
  end

  defp check_ml_compatibility(version) do
    case parse_version(version) do
      {:ok, %{major: major, minor: minor}} when major >= 1 and minor >= 2 -> :compatible
      {:ok, %{major: major}} when major >= 1 -> :partial
      _ -> :incompatible
    end
  end

  defp check_schema_compatibility(version) do
    case parse_version(version) do
      {:ok, %{major: major}} when major >= 1 -> :compatible
      _ -> :incompatible
    end
  end

  defp get_version_features(version) do
    # Return features available in this version
    # In production, this would come from a database or config
    case parse_version(version) do
      {:ok, %{major: major, minor: minor}} ->
        base_features = ["telemetry", "yara", "sigma"]

        additional_features =
          cond do
            major >= 2 -> ["ml_detection", "deception", "network_isolation"]
            major >= 1 and minor >= 5 -> ["ml_detection", "deception"]
            major >= 1 and minor >= 3 -> ["ml_detection"]
            true -> []
          end

        base_features ++ additional_features

      _ ->
        []
    end
  end

  defp get_eol_versions do
    # Versions marked as EOL
    # In production, this would come from database or external API
    ["0.1.0", "0.2.0", "0.3.0"]
  end

  defp is_approaching_eol?(version) do
    # Check if version is within 30 days of EOL
    # For this implementation, versions 0.4.x are approaching EOL
    case parse_version(version) do
      {:ok, %{major: 0, minor: 4}} -> true
      _ -> false
    end
  end

  defp get_eol_date(version) do
    # In production, fetch from database or API
    case parse_version(version) do
      {:ok, %{major: 0}} -> ~U[2025-12-31 23:59:59Z]
      _ -> nil
    end
  end

  defp calculate_support_end_date(version) do
    # Calculate when support ends (e.g., 12 months from release)
    # In production, this would use actual release dates
    case parse_version(version) do
      {:ok, %{major: major, minor: minor}} ->
        # Estimate: version 1.0 released 2024-01-01, each minor adds 2 months
        base_date = ~U[2024-01-01 00:00:00Z]
        months_offset = major * 12 + minor * 2
        DateTime.add(base_date, months_offset * 30 * 24 * 60 * 60, :second)

      _ ->
        nil
    end
  end

  defp calculate_percentage(_, 0), do: 0.0

  defp calculate_percentage(count, total) do
    Float.round(count / total * 100, 1)
  end

  defp calculate_diversity_score(versions) do
    # Lower score = better (less fragmentation)
    # Score is number of versions divided by 10 (arbitrary scale)
    length(versions) / 10.0
  end
end
