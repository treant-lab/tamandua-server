defmodule TamanduaServer.Mitre.TechniqueMapper do
  @moduledoc """
  Maps detection rules and alerts to MITRE ATT&CK techniques.

  Provides automatic technique extraction from:
  - Sigma rule tags
  - YARA rule metadata
  - Alert enrichment data
  - Behavioral detection patterns

  Also maintains the technique_mappings table for coverage tracking.
  """

  require Logger
  alias TamanduaServer.Repo
  alias TamanduaServer.Mitre.TechniqueMapping
  alias TamanduaServer.Detection.{SigmaRule, YaraRule}
  alias TamanduaServer.Alerts.Alert
  import Ecto.Query

  @doc """
  Extract MITRE techniques from a Sigma rule.

  Looks for techniques in:
  - tags (e.g., "attack.t1059.001")
  - mitre_techniques field
  """
  def extract_from_sigma_rule(%SigmaRule{} = rule) do
    techniques = []

    # Extract from tags
    tag_techniques =
      (rule.tags || [])
      |> Enum.filter(&is_attack_tag?/1)
      |> Enum.map(&normalize_technique_id/1)

    # Extract from explicit mitre_techniques field
    field_techniques = rule.mitre_techniques || []

    (techniques ++ tag_techniques ++ field_techniques)
    |> Enum.uniq()
    |> Enum.map(&String.upcase/1)
  end

  @doc """
  Extract MITRE techniques from a YARA rule.

  Looks in:
  - explicit mitre_techniques field
  - attack-style tags
  - metadata embedded in the YARA source's `meta:` section
  """
  def extract_from_yara_rule(%YaraRule{} = rule) do
    explicit_techniques = rule.mitre_techniques || []

    tag_techniques =
      (rule.tags || [])
      |> Enum.filter(&is_attack_tag?/1)
      |> Enum.map(&normalize_technique_id/1)

    source_metadata_techniques =
      rule.source
      |> extract_yara_source_metadata()
      |> Map.take(["mitre_technique", "mitre_attack", "attack_technique"])
      |> Map.values()
      |> Enum.reject(&is_nil/1)
      |> Enum.flat_map(&split_technique_list/1)

    (explicit_techniques ++ tag_techniques ++ source_metadata_techniques)
    |> Enum.map(&normalize_technique_id/1)
    |> Enum.uniq()
  end

  @doc """
  Map alert metadata to MITRE techniques.

  Extracts techniques from alert enrichment data and detection metadata.
  """
  def enrich_alert(%Alert{} = alert) do
    techniques = alert.mitre_techniques || []

    # Also extract from detection metadata if present
    metadata_techniques =
      alert.detection_metadata
      |> Map.get("mitre_techniques", [])
      |> List.wrap()

    all_techniques = (techniques ++ metadata_techniques) |> Enum.uniq()

    # Resolve tactics from techniques
    tactics = get_tactics_for_techniques(all_techniques)

    %{alert | mitre_techniques: all_techniques, mitre_tactics: tactics}
  end

  @doc """
  Create or update technique mapping for a detection rule.

  Options:
  - `:confidence` - Confidence score (0.0-1.0), default: 1.0
  - `:auto_mapped` - Whether this was auto-discovered, default: true
  - `:notes` - Additional notes
  """
  def map_rule_to_technique(technique_id, rule_type, rule_id, rule_name, opts \\ []) do
    attrs = %{
      technique_id: String.upcase(technique_id),
      rule_type: rule_type,
      rule_id: rule_id,
      rule_name: rule_name,
      confidence: Keyword.get(opts, :confidence, 1.0),
      auto_mapped: Keyword.get(opts, :auto_mapped, true),
      notes: Keyword.get(opts, :notes),
      organization_id: Keyword.get(opts, :organization_id)
    }

    %TechniqueMapping{}
    |> TechniqueMapping.changeset(attrs)
    |> Repo.insert(
      on_conflict: {:replace_all_except, [:inserted_at]},
      conflict_target: [:technique_id, :rule_type, :rule_id]
    )
  end

  @doc """
  Scan all Sigma rules and create technique mappings.
  """
  def sync_sigma_mappings(organization_id \\ nil) do
    query = if organization_id do
      from r in SigmaRule, where: r.organization_id == ^organization_id and r.enabled == true
    else
      from r in SigmaRule, where: r.enabled == true
    end

    rules = Repo.all(query)

    Enum.each(rules, fn rule ->
      techniques = extract_from_sigma_rule(rule)

      Enum.each(techniques, fn tech_id ->
        map_rule_to_technique(
          tech_id,
          "sigma",
          rule.id,
          rule.name || rule.title,
          organization_id: rule.organization_id,
          auto_mapped: true
        )
      end)
    end)

    {:ok, length(rules)}
  end

  @doc """
  Scan all YARA rules and create technique mappings.
  """
  def sync_yara_mappings(organization_id \\ nil) do
    query = if organization_id do
      from r in YaraRule, where: r.organization_id == ^organization_id and r.enabled == true
    else
      from r in YaraRule, where: r.enabled == true
    end

    rules = Repo.all(query)

    Enum.each(rules, fn rule ->
      techniques = extract_from_yara_rule(rule)

      Enum.each(techniques, fn tech_id ->
        map_rule_to_technique(
          tech_id,
          "yara",
          rule.id,
          rule.name,
          organization_id: rule.organization_id,
          auto_mapped: true
        )
      end)
    end)

    {:ok, length(rules)}
  end

  @doc """
  Sync all rule mappings (Sigma + YARA).
  """
  def sync_all_mappings(organization_id \\ nil) do
    Logger.info("[TechniqueMapper] Syncing technique mappings for org: #{inspect(organization_id)}")

    with {:ok, sigma_count} <- sync_sigma_mappings(organization_id),
         {:ok, yara_count} <- sync_yara_mappings(organization_id) do
      Logger.info("[TechniqueMapper] Synced #{sigma_count} Sigma and #{yara_count} YARA rules")
      {:ok, %{sigma: sigma_count, yara: yara_count}}
    end
  end

  @doc """
  Get all mappings for a technique.
  """
  def get_mappings_for_technique(technique_id) do
    Repo.all(
      from m in TechniqueMapping,
      where: m.technique_id == ^String.upcase(technique_id),
      order_by: [desc: m.confidence, asc: m.rule_name]
    )
  end

  @doc """
  Get coverage statistics for a technique.
  """
  def get_technique_coverage(technique_id) do
    mappings = get_mappings_for_technique(technique_id)

    %{
      technique_id: technique_id,
      total_rules: length(mappings),
      by_type: Enum.frequencies_by(mappings, & &1.rule_type),
      avg_confidence: calculate_avg_confidence(mappings),
      rules: mappings
    }
  end

  # Private functions

  defp is_attack_tag?(tag) do
    tag = to_string(tag)
    String.starts_with?(tag, "attack.t") or String.match?(tag, ~r/^t\d{4}/i)
  end

  defp normalize_technique_id(id) do
    id
    |> to_string()
    |> String.replace_prefix("attack.", "")
    |> String.upcase()
    |> String.trim()
  end

  defp split_technique_list(value) do
    value
    |> to_string()
    |> String.split([",", ";", " "], trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.filter(&String.match?(&1, ~r/^t?\d{4}/i))
  end

  defp extract_yara_source_metadata(nil), do: %{}
  defp extract_yara_source_metadata(source) do
    case Regex.named_captures(~r/meta:\s*(?<meta>.*?)(?:strings:|condition:)/ms, source) do
      %{"meta" => meta_block} ->
        meta_block
        |> String.split("\n", trim: true)
        |> Enum.reduce(%{}, fn line, acc ->
          case Regex.run(~r/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]+)"/, line) do
            [_, key, value] -> Map.put(acc, String.downcase(key), value)
            _ -> acc
          end
        end)

      _ ->
        %{}
    end
  end

  defp get_tactics_for_techniques(technique_ids) do
    # Use the existing Mitre module to look up tactics
    technique_ids
    |> Enum.flat_map(fn tech_id ->
      case TamanduaServer.Detection.Mitre.get_technique(tech_id) do
        nil -> []
        tech -> tech.tactics
      end
    end)
    |> Enum.uniq()
  end

  defp calculate_avg_confidence([]), do: 0.0
  defp calculate_avg_confidence(mappings) do
    sum = Enum.reduce(mappings, 0.0, fn m, acc -> acc + (m.confidence || 0.0) end)
    Float.round(sum / length(mappings), 2)
  end
end
