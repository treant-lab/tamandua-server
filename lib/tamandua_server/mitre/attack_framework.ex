defmodule TamanduaServer.Mitre.AttackFramework do
  @moduledoc """
  MITRE ATT&CK Framework data loader and manager.

  Handles importing and managing MITRE ATT&CK STIX data, including:
  - Techniques and sub-techniques
  - Tactics
  - Threat actors/groups
  - Software/malware
  - Mitigations

  Data can be loaded from:
  1. Official MITRE STIX bundles (enterprise-attack.json)
  2. Curated JSON files in priv/mitre/
  3. Hardcoded fallback data
  """

  require Logger
  alias TamanduaServer.Repo
  alias TamanduaServer.Mitre.{Technique, ThreatActor}
  import Ecto.Query

  @enterprise_attack_url "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
  @stix_cache_path "priv/mitre/enterprise-attack.json"

  @doc """
  Import MITRE ATT&CK data from STIX bundle.

  Options:
  - `:force` - Force re-import even if data already exists
  - `:source` - Path to STIX JSON file or URL
  """
  def import_attack_data(opts \\ []) do
    force = Keyword.get(opts, :force, false)
    source = Keyword.get(opts, :source, @stix_cache_path)

    if not force and technique_count() > 0 do
      Logger.info("[AttackFramework] Data already imported, use force: true to re-import")
      {:ok, :already_imported}
    else
      do_import_attack_data(source, force)
    end
  end

  defp do_import_attack_data(source, force) do
    Logger.info("[AttackFramework] Starting MITRE ATT&CK data import from #{source}")

    with {:ok, stix_data} <- load_stix_data(source),
         {:ok, techniques} <- parse_techniques(stix_data),
         {:ok, actors} <- parse_threat_actors(stix_data) do

      Logger.info("[AttackFramework] Importing #{length(techniques)} techniques and #{length(actors)} threat actors")

      # Import in transaction
      Repo.transaction(fn ->
        if force, do: clear_existing_data()

        Enum.each(techniques, &insert_technique/1)
        Enum.each(actors, &insert_threat_actor/1)
      end)

      Logger.info("[AttackFramework] Import completed successfully")
      {:ok, %{techniques: length(techniques), actors: length(actors)}}
    else
      {:error, reason} = error ->
        Logger.error("[AttackFramework] Import failed: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Download latest MITRE ATT&CK STIX data from GitHub.
  """
  def download_latest_stix do
    Logger.info("[AttackFramework] Downloading latest STIX data from #{@enterprise_attack_url}")

    case HTTPoison.get(@enterprise_attack_url, [], recv_timeout: 60_000) do
      {:ok, %{status_code: 200, body: body}} ->
        cache_dir = Path.dirname(@stix_cache_path)
        File.mkdir_p!(cache_dir)
        File.write!(@stix_cache_path, body)
        Logger.info("[AttackFramework] Downloaded and cached STIX data")
        {:ok, @stix_cache_path}

      {:ok, %{status_code: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Get technique by technique ID (e.g., "T1059.001").
  """
  def get_technique(technique_id) do
    Repo.get_by(Technique, technique_id: technique_id)
  end

  @doc """
  Get all techniques.
  """
  def list_techniques do
    Repo.all(from t in Technique, order_by: [asc: t.technique_id])
  end

  @doc """
  Get techniques for a specific tactic.
  """
  def get_techniques_for_tactic(tactic_id) do
    Repo.all(
      from t in Technique,
      where: ^tactic_id in t.tactics,
      order_by: [asc: t.technique_id]
    )
  end

  @doc """
  Get sub-techniques for a parent technique.
  """
  def get_subtechniques(parent_id) do
    Repo.all(
      from t in Technique,
      where: t.parent_technique_id == ^parent_id,
      order_by: [asc: t.technique_id]
    )
  end

  @doc """
  Search techniques by name or description.
  """
  def search_techniques(query) do
    search_pattern = "%#{query}%"

    Repo.all(
      from t in Technique,
      where: ilike(t.name, ^search_pattern) or ilike(t.description, ^search_pattern),
      order_by: [asc: t.technique_id],
      limit: 50
    )
  end

  @doc """
  Get threat actor by actor ID.
  """
  def get_threat_actor(actor_id) do
    Repo.get_by(ThreatActor, actor_id: actor_id)
  end

  @doc """
  Get all threat actors.
  """
  def list_threat_actors do
    Repo.all(from a in ThreatActor, order_by: [asc: a.name])
  end

  @doc """
  Get threat actors that use a specific technique.
  """
  def get_actors_for_technique(technique_id) do
    Repo.all(
      from a in ThreatActor,
      where: ^technique_id in a.techniques,
      order_by: [asc: a.name]
    )
  end

  @doc """
  Get count of techniques in database.
  """
  def technique_count do
    Repo.aggregate(Technique, :count)
  end

  # Private functions

  defp load_stix_data(source) do
    cond do
      String.starts_with?(source, "http") ->
        case HTTPoison.get(source, [], recv_timeout: 60_000) do
          {:ok, %{status_code: 200, body: body}} -> Jason.decode(body)
          {:ok, %{status_code: status}} -> {:error, "HTTP #{status}"}
          {:error, reason} -> {:error, reason}
        end

      File.exists?(source) ->
        source
        |> File.read!()
        |> Jason.decode()

      true ->
        {:error, :file_not_found}
    end
  end

  defp parse_techniques(%{"objects" => objects}) do
    techniques =
      objects
      |> Enum.filter(&(&1["type"] == "attack-pattern"))
      |> Enum.map(&transform_technique/1)
      |> Enum.reject(&is_nil/1)

    {:ok, techniques}
  end
  defp parse_techniques(_), do: {:error, :invalid_stix_format}

  defp transform_technique(stix_object) do
    # Extract technique ID from external references
    technique_id = extract_technique_id(stix_object)

    if is_nil(technique_id) do
      nil
    else
      do_transform_technique(stix_object, technique_id)
    end
  end

  defp do_transform_technique(stix_object, technique_id) do
    # Extract tactics from kill chain phases
    tactics = extract_tactics(stix_object)

    # Check if this is a sub-technique
    is_subtechnique = String.contains?(technique_id, ".")
    parent_id = if is_subtechnique do
      technique_id |> String.split(".") |> List.first()
    else
      nil
    end

    %{
      technique_id: technique_id,
      name: stix_object["name"],
      description: stix_object["description"],
      platforms: get_in(stix_object, ["x_mitre_platforms"]) || [],
      data_sources: get_in(stix_object, ["x_mitre_data_sources"]) || [],
      tactics: tactics,
      is_subtechnique: is_subtechnique,
      parent_technique_id: parent_id,
      detection_guidance: get_in(stix_object, ["x_mitre_detection"]),
      external_references: stix_object["external_references"] || [],
      metadata: %{
        created: stix_object["created"],
        modified: stix_object["modified"],
        version: get_in(stix_object, ["x_mitre_version"])
      }
    }
  end

  defp extract_technique_id(stix_object) do
    stix_object["external_references"]
    |> Enum.find(& &1["source_name"] == "mitre-attack")
    |> case do
      %{"external_id" => id} -> id
      _ -> nil
    end
  end

  defp extract_tactics(stix_object) do
    stix_object["kill_chain_phases"]
    |> Enum.filter(& &1["kill_chain_name"] == "mitre-attack")
    |> Enum.map(& &1["phase_name"])
    |> Enum.map(&tactic_phase_to_id/1)
    |> Enum.reject(&is_nil/1)
  end

  # Map tactic phase names to tactic IDs
  @tactic_mapping %{
    "reconnaissance" => "TA0043",
    "resource-development" => "TA0042",
    "initial-access" => "TA0001",
    "execution" => "TA0002",
    "persistence" => "TA0003",
    "privilege-escalation" => "TA0004",
    "defense-evasion" => "TA0005",
    "credential-access" => "TA0006",
    "discovery" => "TA0007",
    "lateral-movement" => "TA0008",
    "collection" => "TA0009",
    "command-and-control" => "TA0011",
    "exfiltration" => "TA0010",
    "impact" => "TA0040"
  }

  defp tactic_phase_to_id(phase_name) do
    @tactic_mapping[phase_name]
  end

  defp parse_threat_actors(%{"objects" => objects}) do
    actors =
      objects
      |> Enum.filter(&(&1["type"] == "intrusion-set"))
      |> Enum.map(&transform_threat_actor/1)
      |> Enum.reject(&is_nil/1)

    {:ok, actors}
  end
  defp parse_threat_actors(_), do: {:ok, []}

  defp transform_threat_actor(stix_object) do
    actor_id = extract_actor_id(stix_object)

    if is_nil(actor_id) do
      nil
    else
      do_transform_threat_actor(stix_object, actor_id)
    end
  end

  defp do_transform_threat_actor(stix_object, actor_id) do
    %{
      actor_id: actor_id,
      name: stix_object["name"],
      aliases: stix_object["aliases"] || [],
      description: stix_object["description"],
      techniques: [],  # Will be populated via relationship analysis
      country: get_in(stix_object, ["x_mitre_country"]),
      sophistication: normalize_sophistication(get_in(stix_object, ["x_mitre_sophistication"])),
      objectives: get_in(stix_object, ["goals"]) || [],
      external_references: stix_object["external_references"] || [],
      metadata: %{
        created: stix_object["created"],
        modified: stix_object["modified"]
      }
    }
  end

  defp extract_actor_id(stix_object) do
    stix_object["external_references"]
    |> Enum.find(& &1["source_name"] == "mitre-attack")
    |> case do
      %{"external_id" => id} -> id
      _ -> nil
    end
  end

  defp normalize_sophistication(nil), do: "medium"
  defp normalize_sophistication(level) when level in ["low", "medium", "high", "expert"], do: level
  defp normalize_sophistication(_), do: "medium"

  defp insert_technique(attrs) do
    %Technique{}
    |> Technique.changeset(attrs)
    |> Repo.insert!(on_conflict: :replace_all, conflict_target: :technique_id)
  end

  defp insert_threat_actor(attrs) do
    %ThreatActor{}
    |> ThreatActor.changeset(attrs)
    |> Repo.insert!(on_conflict: :replace_all, conflict_target: :actor_id)
  end

  defp clear_existing_data do
    Repo.delete_all(Technique)
    Repo.delete_all(ThreatActor)
  end
end
