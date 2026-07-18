defmodule TamanduaServer.ThreatIntel.EmergingActions do
  @moduledoc """
  Maps normalized Emerging Threats intelligence into hunt, response, and
  detection-pack recommendations.

  This module is intentionally pure. It returns intent and prerequisites for
  Hunting, Response, and Detection consumers, but never executes hunts, blocks
  IOCs, creates cases, or installs detection content.
  """

  @type normalized_threat :: map()
  @type recommendation :: map()

  @default_window "7d"
  @supported_ioc_types ~w(ip domain url hash hash_md5 hash_sha1 hash_sha256 package_name)
  @blockable_types ~w(ip domain url)
  @high_severities ~w(critical high)

  @doc """
  Build recommended hunts, actions, safety checks, and coverage prerequisites
  for a normalized threat map.

  Accepts atom or string keys. Expected input fields are `type`, `value`,
  `source`, `severity`, `confidence`, `tags`, and `metadata`.
  """
  @spec recommend(normalized_threat(), keyword()) :: recommendation()
  def recommend(threat, opts \\ []) when is_map(threat) do
    normalized = normalize_threat(threat)
    window = opts |> Keyword.get(:window, @default_window) |> to_string()

    %{
      threat: normalized,
      recommended_hunts: recommended_hunts(normalized, window),
      recommended_actions: recommended_actions(normalized),
      prerequisites: prerequisites(normalized),
      safety: safety_prerequisites(normalized),
      coverage: coverage_prerequisites(normalized),
      integration_refs: %{
        hunting: "TamanduaServer.Hunting.QueryLanguage",
        response: "TamanduaServer.Response.Playbook",
        detection: "TamanduaServer.Detection.Packs"
      },
      execution: %{
        status: "not_executed",
        reason: "recommendations_only"
      }
    }
  end

  @doc """
  Compatibility alias for callers that read better as `for_threat/2`.
  """
  @spec for_threat(normalized_threat(), keyword()) :: recommendation()
  def for_threat(threat, opts \\ []), do: recommend(threat, opts)

  defp normalize_threat(threat) do
    type = fetch_any(threat, [:type, "type"]) |> normalize_type()
    value = fetch_any(threat, [:value, "value"]) |> normalize_value(type)
    source = fetch_any(threat, [:source, "source"]) || "unknown"
    source_string = to_string(source)
    severity = fetch_any(threat, [:severity, "severity"]) |> normalize_severity()
    confidence = fetch_any(threat, [:confidence, "confidence"]) |> normalize_confidence()
    tags = fetch_any(threat, [:tags, "tags"]) |> normalize_tags()
    metadata = fetch_any(threat, [:metadata, "metadata"]) |> normalize_metadata()

    %{
      type: type,
      value: value,
      source: source_string,
      severity: severity,
      confidence: confidence,
      tags: tags,
      metadata: metadata,
      feed: metadata["feed"] || source_feed(source_string),
      provider: metadata["provider"] || source_provider(source_string)
    }
  end

  defp recommended_hunts(%{type: type, value: value, tags: tags} = threat, window) do
    base =
      case type do
        "ip" ->
          [
            hunt("tql", "Network connections to IOC", network_tql("network.dst_ip", value, window), ["ioc", "ip", "network"]),
            hunt("kql", "Defender network connections to IOC", network_kql("RemoteIP", value, window), ["ioc", "ip", "kql"]),
            sigma_label("network_connection_destination_ip", "DestinationIp", value)
          ]

        "domain" ->
          [
            hunt("tql", "DNS queries for IOC domain", network_tql("dns.query", value, window), ["ioc", "domain", "dns"]),
            hunt("kql", "Defender DNS queries for IOC domain", network_kql("RemoteUrl", value, window), ["ioc", "domain", "kql"]),
            sigma_label("dns_query_domain", "query", value)
          ]

        "url" ->
          [
            hunt("tql", "Network or DNS activity for IOC URL", url_tql(value, window), ["ioc", "url", "network"]),
            hunt("kql", "Defender URL activity for IOC", network_kql("RemoteUrl", value, window), ["ioc", "url", "kql"]),
            sigma_label("proxy_url", "url", value)
          ]

        "hash_sha256" ->
          file_hash_hunts("sha256", value, window)

        "hash_sha1" ->
          file_hash_hunts("sha1", value, window)

        "hash_md5" ->
          file_hash_hunts("md5", value, window)

        "hash" ->
          file_hash_hunts("hash", value, window)

        "package_name" ->
          [
            hunt("tql", "Package artifact activity", package_tql(value, window), ["ioc", "package", "supply_chain"]),
            sigma_label("package_artifact_name", "package.name", value)
          ]

        _ ->
          [
            hunt("tql", "Generic IOC search", generic_tql(value, window), ["ioc", "generic"])
          ]
      end

    related_hunts(threat, window) ++ tag_enriched(base, tags)
  end

  defp recommended_actions(threat) do
    [
      collect_evidence_action(threat),
      block_ioc_action(threat),
      create_case_action(threat),
      create_detection_pack_action(threat)
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp collect_evidence_action(threat) do
    action("collect_evidence", "response.collect_evidence", "recommended", %{
      scope: evidence_scope(threat.type),
      reason: "Validate Emerging Threats IOC exposure before response execution",
      inputs: %{ioc_type: threat.type, ioc_value: threat.value}
    })
  end

  defp block_ioc_action(%{type: type, severity: severity, confidence: confidence} = threat)
       when type in @blockable_types and severity in @high_severities and confidence >= 0.7 do
    action("block_ioc", block_ioc_ref(type), "requires_approval", %{
      ioc_type: type,
      ioc_value: threat.value,
      reason: "High-confidence Emerging Threats IOC",
      guardrails: ["tenant_scope_required", "allowlist_check_required", "rollback_path_required"]
    })
  end

  defp block_ioc_action(_threat), do: nil

  defp create_case_action(%{severity: severity} = threat) when severity in @high_severities do
    action("create_case", "cases.create_case", "recommended", %{
      title: "Emerging Threats #{String.upcase(threat.type)} IOC: #{threat.value}",
      severity: threat.severity,
      confidence: threat.confidence,
      source: threat.source
    })
  end

  defp create_case_action(%{confidence: confidence} = threat) when confidence >= 0.85 do
    action("create_case", "cases.create_case", "recommended", %{
      title: "High-confidence Emerging Threats IOC: #{threat.value}",
      severity: threat.severity,
      confidence: confidence,
      source: threat.source
    })
  end

  defp create_case_action(_threat), do: nil

  defp create_detection_pack_action(threat) do
    action("create_detection_pack", "detection.packs.candidate", "recommended", %{
      pack_slug: detection_pack_slug(threat),
      pack_name: detection_pack_name(threat),
      rule_labels: sigma_labels_for(threat),
      tags: Enum.uniq(["emerging_threats", "ioc", threat.type] ++ threat.tags),
      note: "Candidate content only; validate and publish through Detection.Packs workflow"
    })
  end

  defp prerequisites(threat) do
    %{
      normalized_threat_required: required_fields_present?(threat),
      supported_ioc_type: threat.type in @supported_ioc_types,
      non_empty_value: threat.value != "",
      minimum_confidence_for_blocking: threat.confidence >= 0.7,
      manual_approval_for_enforcement: threat.type in @blockable_types
    }
  end

  defp safety_prerequisites(threat) do
    [
      %{id: "tenant_scope", status: "required", reason: "Prevent cross-tenant enforcement"},
      %{id: "allowlist_check", status: "required", reason: "Avoid blocking business-critical infrastructure"},
      %{id: "evidence_first", status: "required", reason: "Collect telemetry before irreversible containment"},
      %{id: "rollback_plan", status: "required", reason: "Blocking actions must be reversible"},
      %{
        id: "confidence_gate",
        status: if(threat.confidence >= 0.7, do: "met", else: "not_met"),
        reason: "Low-confidence IOCs should stay hunt-only until validated"
      }
    ]
  end

  defp coverage_prerequisites(threat) do
    base = [
      %{surface: "hunting", capability: "TQL query validation", status: "required"},
      %{surface: "response", capability: "case creation and evidence collection", status: "required"},
      %{surface: "detection", capability: "Sigma label review before pack publication", status: "required"}
    ]

    type_specific =
      case threat.type do
        "ip" -> [%{surface: "telemetry", capability: "network flow destination IP visibility", status: "required"}]
        "domain" -> [%{surface: "telemetry", capability: "DNS query visibility", status: "required"}]
        "url" -> [%{surface: "telemetry", capability: "proxy or network URL visibility", status: "required"}]
        "hash_sha256" -> [%{surface: "telemetry", capability: "file SHA256 visibility", status: "required"}]
        "hash_sha1" -> [%{surface: "telemetry", capability: "file SHA1 visibility", status: "required"}]
        "hash_md5" -> [%{surface: "telemetry", capability: "file MD5 visibility", status: "required"}]
        "package_name" -> [%{surface: "telemetry", capability: "package manager artifact visibility", status: "required"}]
        _ -> [%{surface: "telemetry", capability: "generic IOC search coverage", status: "unknown"}]
      end

    base ++ type_specific
  end

  defp related_hunts(%{tags: tags, type: type, value: value}, window) do
    field = hunt_field(type)

    cond do
      any_tag?(tags, ["botnet", "c2"]) ->
        [
          hunt(
            "tql",
            "Beaconing around IOC contact",
            "#{field} = #{quote_tql(value)} | count by #{field}, agent_id | where count > 3 | sort count desc",
            ["ioc", "c2", "beaconing"]
          )
        ]

      any_tag?(tags, ["tor", "anonymizer"]) ->
        [
          hunt(
            "tql",
            "Repeated anonymizer egress",
            "#{field} = #{quote_tql(value)} AND timestamp > ago(#{window}) | count by agent_id | where count > 1",
            ["ioc", "tor", "egress"]
          )
        ]

      true ->
        []
    end
  end

  defp hunt_field("domain"), do: "dns.query"
  defp hunt_field("url"), do: "network.url"
  defp hunt_field(_type), do: "network.dst_ip"

  defp file_hash_hunts(hash_kind, value, window) do
    field =
      case hash_kind do
        "sha256" -> "file.hash_sha256"
        "sha1" -> "file.hash_sha1"
        "md5" -> "file.hash_md5"
        _ -> "file.hash"
      end

    kql_field =
      case hash_kind do
        "sha256" -> "SHA256"
        "sha1" -> "SHA1"
        "md5" -> "MD5"
        _ -> "SHA256"
      end

    [
      hunt("tql", "File hash IOC activity", "#{field} = #{quote_tql(value)} AND timestamp > ago(#{window})", ["ioc", "hash", hash_kind]),
      hunt("kql", "Defender file hash IOC activity", "DeviceFileEvents | where #{kql_field} == #{quote_kql(value)}", ["ioc", "hash", "kql"]),
      sigma_label("file_hash_#{hash_kind}", kql_field, value)
    ]
  end

  defp network_tql(field, value, window), do: "#{field} = #{quote_tql(value)} AND timestamp > ago(#{window})"

  defp network_kql(field, value, window) do
    "DeviceNetworkEvents | where Timestamp > ago(#{window}) | where #{field} == #{quote_kql(value)}"
  end

  defp url_tql(value, window) do
    "(network.url = #{quote_tql(value)} OR dns.query CONTAINS #{quote_tql(host_from_url(value))}) AND timestamp > ago(#{window})"
  end

  defp package_tql(value, window) do
    "process.command_line CONTAINS #{quote_tql(value)} AND timestamp > ago(#{window})"
  end

  defp generic_tql(value, window), do: "alert.message CONTAINS #{quote_tql(value)} AND timestamp > ago(#{window})"

  defp hunt(language, name, query, labels) do
    %{
      type: "query",
      language: language,
      name: name,
      query: query,
      labels: labels,
      execution: "not_executed"
    }
  end

  defp sigma_label(label, field, value) do
    %{
      type: "sigma_label",
      language: "sigma",
      name: label,
      labels: ["sigma", label],
      match: %{field: field, value: value},
      execution: "not_executed"
    }
  end

  defp action(name, integration_ref, state, payload) do
    %{
      action: name,
      integration_ref: integration_ref,
      state: state,
      payload: payload,
      execution: "not_executed"
    }
  end

  defp evidence_scope("ip"), do: "network"
  defp evidence_scope("domain"), do: "dns"
  defp evidence_scope("url"), do: "proxy_or_network"
  defp evidence_scope("package_name"), do: "supply_chain"
  defp evidence_scope(type) when type in ["hash", "hash_md5", "hash_sha1", "hash_sha256"], do: "file"
  defp evidence_scope(_type), do: "generic"

  defp block_ioc_ref("domain"), do: "response.playbook.update_blocklist.domain"
  defp block_ioc_ref("url"), do: "response.playbook.update_blocklist.url"
  defp block_ioc_ref("ip"), do: "response.playbook.update_blocklist.ip"

  defp detection_pack_slug(%{feed: feed, type: type}) do
    [feed || "emerging_threats", type, "ioc"]
    |> Enum.map(&slug_part/1)
    |> Enum.join("_")
  end

  defp detection_pack_name(%{feed: feed, type: type}) do
    feed_name = feed || "emerging_threats"
    "#{String.replace(feed_name, "_", " ")} #{String.upcase(type)} IOC Pack"
  end

  defp sigma_labels_for(threat) do
    threat
    |> recommended_hunts(@default_window)
    |> Enum.filter(&(&1.type == "sigma_label"))
    |> Enum.map(& &1.name)
  end

  defp tag_enriched(hunts, tags) do
    tag_labels = Enum.map(tags, &"tag:#{&1}")

    Enum.map(hunts, fn hunt ->
      Map.update!(hunt, :labels, &Enum.uniq(&1 ++ tag_labels))
    end)
  end

  defp required_fields_present?(threat), do: threat.type != "unknown" and threat.value != ""

  defp fetch_any(map, keys) do
    Enum.find_value(keys, &Map.get(map, &1))
  end

  defp normalize_type(nil), do: "unknown"
  defp normalize_type(type) do
    type
    |> to_string()
    |> String.trim()
    |> String.downcase()
    |> case do
      "sha256" -> "hash_sha256"
      "sha1" -> "hash_sha1"
      "md5" -> "hash_md5"
      "hash" -> "hash"
      other -> other
    end
  end

  defp normalize_value(nil, _type), do: ""
  defp normalize_value(value, type) when type in ["domain", "url", "hash", "hash_md5", "hash_sha1", "hash_sha256"] do
    value |> to_string() |> String.trim() |> String.downcase()
  end
  defp normalize_value(value, _type), do: value |> to_string() |> String.trim()

  defp normalize_severity(nil), do: "medium"
  defp normalize_severity(severity) do
    severity = severity |> to_string() |> String.downcase()
    if severity in ~w(critical high medium low informational), do: severity, else: "medium"
  end

  defp normalize_confidence(nil), do: 0.7
  defp normalize_confidence(confidence) when is_integer(confidence), do: confidence / 1.0 |> clamp()
  defp normalize_confidence(confidence) when is_float(confidence), do: clamp(confidence)
  defp normalize_confidence(confidence) when is_binary(confidence) do
    case Float.parse(confidence) do
      {value, _} -> clamp(value)
      :error -> 0.7
    end
  end
  defp normalize_confidence(_confidence), do: 0.7

  defp normalize_tags(nil), do: []
  defp normalize_tags(tags) when is_list(tags) do
    tags
    |> Enum.map(&(to_string(&1) |> String.downcase() |> String.trim()))
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end
  defp normalize_tags(tag), do: normalize_tags([tag])

  defp normalize_metadata(metadata) when is_map(metadata) do
    Map.new(metadata, fn {key, value} -> {to_string(key), value} end)
  end
  defp normalize_metadata(_metadata), do: %{}

  defp clamp(value) when value < 0.0, do: 0.0
  defp clamp(value) when value > 1.0, do: 1.0
  defp clamp(value), do: value

  defp source_feed("emerging_threats_" <> feed), do: feed
  defp source_feed(_source), do: nil

  defp source_provider(source) do
    if String.starts_with?(source, "emerging_threats"), do: "emerging_threats", else: nil
  end

  defp any_tag?(tags, candidates), do: Enum.any?(candidates, &(&1 in tags))

  defp quote_tql(value), do: ~s("#{escape_double_quoted(value)}")
  defp quote_kql(value), do: ~s("#{escape_double_quoted(value)}")

  defp escape_double_quoted(value) do
    value
    |> to_string()
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
  end

  defp host_from_url(value) do
    value
    |> URI.parse()
    |> Map.get(:host)
    |> case do
      nil -> value
      host -> host
    end
  end

  defp slug_part(value) do
    value
    |> to_string()
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9]+/, "_")
    |> String.trim("_")
  end
end
