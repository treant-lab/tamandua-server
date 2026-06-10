defmodule TamanduaServer.Detection.RuleExporter do
  @moduledoc """
  Exports detection rules in various formats.
  Supports exporting individual rules, rule sets, and with metadata.
  """

  alias TamanduaServer.Detection
  alias TamanduaServer.Detection.{YaraRule, SigmaRule, IOC}
  alias TamanduaServer.Repo

  import Ecto.Query

  @doc """
  Export YARA rules to native YARA format.
  Returns {:ok, content} or {:error, reason}.
  """
  def export_yara_rules(rule_ids, opts \\ []) do
    include_metadata = Keyword.get(opts, :include_metadata, false)
    include_stats = Keyword.get(opts, :include_stats, false)

    rules =
      from(r in YaraRule, where: r.id in ^rule_ids)
      |> Repo.all()

    if Enum.empty?(rules) do
      {:error, "No rules found"}
    else
      content = Enum.map_join(rules, "\n\n", fn rule ->
        export_single_yara(rule, include_metadata, include_stats)
      end)

      {:ok, content}
    end
  end

  @doc """
  Export Sigma rules to YAML format.
  Returns {:ok, content} or {:error, reason}.
  """
  def export_sigma_rules(rule_ids, opts \\ []) do
    include_metadata = Keyword.get(opts, :include_metadata, false)
    format = Keyword.get(opts, :format, :yaml)

    rules =
      from(r in SigmaRule, where: r.id in ^rule_ids)
      |> Repo.all()

    if Enum.empty?(rules) do
      {:error, "No rules found"}
    else
      case format do
        :yaml ->
          content = Enum.map_join(rules, "\n---\n\n", fn rule ->
            export_single_sigma(rule, include_metadata)
          end)

          {:ok, content}

        :json ->
          data = Enum.map(rules, &sigma_to_json/1)
          {:ok, Jason.encode!(data, pretty: true)}

        _ ->
          {:error, "Unsupported format: #{format}"}
      end
    end
  end

  @doc """
  Export IOCs to JSON or CSV format.
  Returns {:ok, content} or {:error, reason}.
  """
  def export_iocs(ioc_ids, opts \\ []) do
    format = Keyword.get(opts, :format, :json)
    include_metadata = Keyword.get(opts, :include_metadata, false)

    iocs =
      from(i in IOC, where: i.id in ^ioc_ids)
      |> Repo.all()

    if Enum.empty?(iocs) do
      {:error, "No IOCs found"}
    else
      case format do
        :json ->
          data = Enum.map(iocs, &ioc_to_json(&1, include_metadata))
          {:ok, Jason.encode!(data, pretty: true)}

        :csv ->
          {:ok, iocs_to_csv(iocs, include_metadata)}

        :stix ->
          {:ok, iocs_to_stix(iocs)}

        _ ->
          {:error, "Unsupported format: #{format}"}
      end
    end
  end

  @doc """
  Export all rules of a specific type.
  """
  def export_all_by_type(rule_type, organization_id, opts \\ []) do
    case rule_type do
      :yara ->
        rule_ids =
          from(r in YaraRule, where: r.organization_id == ^organization_id, select: r.id)
          |> Repo.all()

        export_yara_rules(rule_ids, opts)

      :sigma ->
        rule_ids =
          from(r in SigmaRule, where: r.organization_id == ^organization_id, select: r.id)
          |> Repo.all()

        export_sigma_rules(rule_ids, opts)

      :ioc ->
        ioc_ids =
          from(i in IOC, where: i.organization_id == ^organization_id, select: i.id)
          |> Repo.all()

        export_iocs(ioc_ids, opts)

      _ ->
        {:error, "Unknown rule type: #{rule_type}"}
    end
  end

  @doc """
  Export a rule bundle (combined package).
  Returns a JSON bundle with all rule types.
  """
  def export_bundle(organization_id, opts \\ []) do
    yara_rules = from(r in YaraRule, where: r.organization_id == ^organization_id) |> Repo.all()
    sigma_rules = from(r in SigmaRule, where: r.organization_id == ^organization_id) |> Repo.all()
    iocs = from(i in IOC, where: i.organization_id == ^organization_id) |> Repo.all()

    bundle = %{
      version: "1.0",
      exported_at: DateTime.utc_now(),
      organization_id: organization_id,
      rules: %{
        yara: Enum.map(yara_rules, &yara_to_json/1),
        sigma: Enum.map(sigma_rules, &sigma_to_json/1),
        iocs: Enum.map(iocs, &ioc_to_json(&1, true))
      },
      metadata: %{
        total_yara_rules: length(yara_rules),
        total_sigma_rules: length(sigma_rules),
        total_iocs: length(iocs)
      }
    }

    {:ok, Jason.encode!(bundle, pretty: true)}
  end

  @doc """
  Export predefined template rule sets.
  """
  def export_template(template_name, organization_id) do
    case template_name do
      "ransomware_detection" ->
        export_ransomware_template(organization_id)

      "apt_detection" ->
        export_apt_template(organization_id)

      "malware_analysis" ->
        export_malware_template(organization_id)

      "lateral_movement" ->
        export_lateral_movement_template(organization_id)

      _ ->
        {:error, "Unknown template: #{template_name}"}
    end
  end

  # --- Private Functions ---

  defp export_single_yara(rule, include_metadata, include_stats) do
    metadata_comment = if include_metadata do
      """
      /*
       * Exported from Tamandua EDR
       * Rule ID: #{rule.id}
       * Created: #{rule.inserted_at}
       * Last Updated: #{rule.updated_at}
       * Organization: #{rule.organization_id}
      #{if include_stats, do: format_rule_stats(:yara, rule.id), else: ""}
       */
      """
    else
      ""
    end

    "#{metadata_comment}#{rule.source}"
  end

  defp export_single_sigma(rule, include_metadata) do
    # Use the original source if available, otherwise reconstruct from parsed data
    if rule.source do
      if include_metadata do
        "# Exported from Tamandua EDR - #{DateTime.utc_now()}\n#{rule.source}"
      else
        rule.source
      end
    else
      # Reconstruct Sigma rule from parsed data
      sigma_map = %{
        "title" => rule.title,
        "id" => rule.id,
        "description" => rule.description,
        "author" => rule.author,
        "date" => Date.to_iso8601(DateTime.to_date(rule.inserted_at)),
        "level" => rule.level,
        "status" => rule.status,
        "logsource" => %{
          "category" => rule.logsource_category,
          "product" => rule.logsource_product,
          "service" => rule.logsource_service
        }
        |> Enum.reject(fn {_, v} -> is_nil(v) end)
        |> Map.new(),
        "detection" => rule.detection,
        "tags" => build_sigma_tags(rule),
        "references" => rule.references
      }
      |> Enum.reject(fn {_, v} -> is_nil(v) or v == [] or v == %{} end)
      |> Map.new()

      YamlElixir.write_to_string!(sigma_map)
    end
  end

  defp yara_to_json(rule) do
    %{
      id: rule.id,
      name: rule.name,
      description: rule.description,
      author: rule.author,
      source: rule.source,
      category: rule.category,
      severity: rule.severity,
      tags: rule.tags,
      mitre_tactics: rule.mitre_tactics,
      mitre_techniques: rule.mitre_techniques,
      malware_family: rule.malware_family,
      threat_actor: rule.threat_actor,
      references: rule.references,
      enabled: rule.enabled,
      created_at: rule.inserted_at,
      updated_at: rule.updated_at
    }
  end

  defp sigma_to_json(rule) do
    %{
      id: rule.id,
      name: rule.name,
      title: rule.title,
      description: rule.description,
      author: rule.author,
      level: rule.level,
      status: rule.status,
      detection: rule.detection,
      logsource: %{
        category: rule.logsource_category,
        product: rule.logsource_product,
        service: rule.logsource_service
      },
      tags: rule.tags,
      mitre_tactics: rule.mitre_tactics,
      mitre_techniques: rule.mitre_techniques,
      references: rule.references,
      enabled: rule.enabled,
      created_at: rule.inserted_at,
      updated_at: rule.updated_at
    }
  end

  defp ioc_to_json(ioc, include_metadata) do
    base = %{
      type: ioc.type,
      value: ioc.value,
      description: ioc.description,
      source: ioc.source,
      severity: ioc.severity,
      confidence: ioc.confidence,
      tags: ioc.tags
    }

    if include_metadata do
      Map.merge(base, %{
        id: ioc.id,
        source_ref: ioc.source_ref,
        metadata: ioc.metadata,
        malware_family: ioc.malware_family,
        threat_actor: ioc.threat_actor,
        campaign: ioc.campaign,
        mitre_tactics: ioc.mitre_tactics,
        mitre_techniques: ioc.mitre_techniques,
        first_seen: ioc.first_seen,
        last_seen: ioc.last_seen,
        expires_at: ioc.expires_at,
        enabled: ioc.enabled,
        created_at: ioc.inserted_at,
        updated_at: ioc.updated_at
      })
    else
      base
    end
  end

  defp iocs_to_csv(iocs, include_metadata) do
    headers = if include_metadata do
      ["type", "value", "description", "source", "severity", "confidence", "tags", "malware_family", "threat_actor", "campaign"]
    else
      ["type", "value", "description", "source", "severity"]
    end

    rows = Enum.map(iocs, fn ioc ->
      if include_metadata do
        [
          ioc.type,
          ioc.value,
          ioc.description || "",
          ioc.source || "",
          ioc.severity,
          to_string(ioc.confidence || ""),
          Enum.join(ioc.tags || [], ";"),
          ioc.malware_family || "",
          ioc.threat_actor || "",
          ioc.campaign || ""
        ]
      else
        [
          ioc.type,
          ioc.value,
          ioc.description || "",
          ioc.source || "",
          ioc.severity
        ]
      end
    end)

    [headers | rows]
    |> Enum.map(&Enum.join(&1, ","))
    |> Enum.join("\n")
  end

  defp iocs_to_stix(iocs) do
    # STIX 2.1 format
    stix_bundle = %{
      type: "bundle",
      id: "bundle--#{UUID.uuid4()}",
      spec_version: "2.1",
      objects: Enum.map(iocs, &ioc_to_stix_object/1)
    }

    Jason.encode!(stix_bundle, pretty: true)
  end

  defp ioc_to_stix_object(ioc) do
    stix_type = case ioc.type do
      "ip" -> "ipv4-addr"
      "domain" -> "domain-name"
      "url" -> "url"
      "email" -> "email-addr"
      "hash_md5" -> "file"
      "hash_sha1" -> "file"
      "hash_sha256" -> "file"
      _ -> "indicator"
    end

    pattern = build_stix_pattern(ioc)

    %{
      type: "indicator",
      spec_version: "2.1",
      id: "indicator--#{UUID.uuid4()}",
      created: ioc.inserted_at,
      modified: ioc.updated_at,
      name: ioc.description || "IOC: #{ioc.value}",
      description: ioc.description,
      indicator_types: ["malicious-activity"],
      pattern: pattern,
      pattern_type: "stix",
      valid_from: ioc.first_seen || ioc.inserted_at,
      labels: ioc.tags || []
    }
  end

  defp build_stix_pattern(ioc) do
    case ioc.type do
      "ip" -> "[ipv4-addr:value = '#{ioc.value}']"
      "domain" -> "[domain-name:value = '#{ioc.value}']"
      "url" -> "[url:value = '#{ioc.value}']"
      "email" -> "[email-addr:value = '#{ioc.value}']"
      "hash_md5" -> "[file:hashes.MD5 = '#{ioc.value}']"
      "hash_sha1" -> "[file:hashes.SHA1 = '#{ioc.value}']"
      "hash_sha256" -> "[file:hashes.'SHA-256' = '#{ioc.value}']"
      _ -> "[artifact:payload_bin = '#{ioc.value}']"
    end
  end

  defp build_sigma_tags(rule) do
    mitre_tags = Enum.map(rule.mitre_tactics || [], &"attack.#{&1}")
    technique_tags = Enum.map(rule.mitre_techniques || [], &"attack.#{String.downcase(&1)}")
    custom_tags = rule.tags || []

    mitre_tags ++ technique_tags ++ custom_tags
  end

  defp format_rule_stats(rule_type, rule_id) do
    # Query performance metrics if available
    case get_performance_stats(rule_type, rule_id) do
      nil ->
        ""

      stats ->
        """
         * Performance Stats:
         *   - Executions: #{stats.execution_count}
         *   - Matches: #{stats.match_count}
         *   - Avg Time: #{Float.round(stats.avg_execution_time_ms, 2)}ms
         *   - Match Rate: #{Float.round(stats.match_count / max(stats.execution_count, 1) * 100, 1)}%
        """
    end
  end

  defp get_performance_stats(rule_type, rule_id) do
    # This would query the rule_performance_metrics table
    # For now, return nil (not implemented in this phase)
    nil
  end

  defp export_ransomware_template(organization_id) do
    # Export rules tagged with ransomware detection
    yara_ids =
      from(r in YaraRule,
        where: r.organization_id == ^organization_id and "ransomware" in r.tags,
        select: r.id
      )
      |> Repo.all()

    sigma_ids =
      from(r in SigmaRule,
        where: r.organization_id == ^organization_id and "ransomware" in r.tags,
        select: r.id
      )
      |> Repo.all()

    bundle = %{
      template: "ransomware_detection",
      yara_rules: if(Enum.empty?(yara_ids), do: [], else: elem(export_yara_rules(yara_ids), 1)),
      sigma_rules: if(Enum.empty?(sigma_ids), do: [], else: elem(export_sigma_rules(sigma_ids, format: :json), 1))
    }

    {:ok, Jason.encode!(bundle, pretty: true)}
  end

  defp export_apt_template(organization_id) do
    # Export rules tagged with APT detection
    yara_ids =
      from(r in YaraRule,
        where: r.organization_id == ^organization_id and ("apt" in r.tags or not is_nil(r.threat_actor)),
        select: r.id
      )
      |> Repo.all()

    sigma_ids =
      from(r in SigmaRule,
        where: r.organization_id == ^organization_id and "apt" in r.tags,
        select: r.id
      )
      |> Repo.all()

    bundle = %{
      template: "apt_detection",
      yara_rules: if(Enum.empty?(yara_ids), do: [], else: elem(export_yara_rules(yara_ids), 1)),
      sigma_rules: if(Enum.empty?(sigma_ids), do: [], else: elem(export_sigma_rules(sigma_ids, format: :json), 1))
    }

    {:ok, Jason.encode!(bundle, pretty: true)}
  end

  defp export_malware_template(organization_id) do
    # Export rules for malware analysis
    yara_ids =
      from(r in YaraRule,
        where: r.organization_id == ^organization_id and not is_nil(r.malware_family),
        select: r.id
      )
      |> Repo.all()

    bundle = %{
      template: "malware_analysis",
      yara_rules: if(Enum.empty?(yara_ids), do: [], else: elem(export_yara_rules(yara_ids), 1))
    }

    {:ok, Jason.encode!(bundle, pretty: true)}
  end

  defp export_lateral_movement_template(organization_id) do
    # Export rules for lateral movement detection
    sigma_ids =
      from(r in SigmaRule,
        where: r.organization_id == ^organization_id and "lateral-movement" in r.mitre_tactics,
        select: r.id
      )
      |> Repo.all()

    bundle = %{
      template: "lateral_movement",
      sigma_rules: if(Enum.empty?(sigma_ids), do: [], else: elem(export_sigma_rules(sigma_ids, format: :json), 1))
    }

    {:ok, Jason.encode!(bundle, pretty: true)}
  end
end
