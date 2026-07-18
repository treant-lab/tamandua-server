defmodule TamanduaServer.ThreatIntel.EmergingSources.Aggregator do
  @moduledoc """
  Initial Emerging Threats source aggregation.

  This module converts locally available/static threat signals into normalized
  emerging-threat candidates. It is intentionally read-only: it does not trigger
  feed syncs, network calls, or IOC ingestion. Missing sources are reported as
  health gaps instead of being silently ignored.
  """

  import Ecto.Query

  alias TamanduaServer.AISecurity.AttackSurface
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Repo
  alias TamanduaServer.ThreatIntel.Feeds.EmergingThreats
  alias TamanduaServer.ThreatIntel.SigmaSync
  alias TamanduaServer.ThreatIntel.ThreatActor
  alias TamanduaServer.Vulnerability.CVE

  @default_limit 100
  @default_source_limit 25
  @default_recent_days 14
  @default_epss_threshold 0.7

  @abuse_ch_tables [
    {:urlhaus, :abuse_ch_urlhaus},
    {:threatfox, :abuse_ch_threatfox},
    {:feodo, :abuse_ch_feodo},
    {:malwarebazaar, :abuse_ch_malwarebazaar},
    {:domains, :abuse_ch_domains},
    {:ips, :abuse_ch_ips},
    {:hashes, :abuse_ch_hashes}
  ]

  @doc """
  Aggregate locally available signals into normalized emerging-threat candidates.

  Options:

    * `:limit` - final candidate limit, defaults to #{@default_limit}
    * `:source_limit` - per-source read limit, defaults to #{@default_source_limit}
    * `:recent_days` - recent CVE/alert window, defaults to #{@default_recent_days}
    * `:epss_threshold` - minimum EPSS score for vulnerability candidates,
      defaults to #{@default_epss_threshold}

  Returns a map with `:candidates`, `:source_health`, and `:generated_at`.
  """
  @spec aggregate(keyword()) :: %{
          candidates: [map()],
          source_health: map(),
          generated_at: DateTime.t()
        }
  def aggregate(opts \\ []) do
    limit = Keyword.get(opts, :limit, @default_limit)

    sources = [
      vulnerability_candidates(opts),
      malware_feed_candidates(opts),
      actor_campaign_candidates(opts),
      sigma_rule_candidates(opts),
      ai_model_threat_candidates(opts),
      emerging_threats_feed_health()
    ]

    candidates =
      sources
      |> Enum.flat_map(& &1.candidates)
      |> normalize_candidates()
      |> Enum.take(limit)

    %{
      candidates: candidates,
      source_health: Map.new(sources, &{&1.source, &1.health}),
      generated_at: DateTime.utc_now()
    }
  end

  @doc """
  Return only source health/gap information for the aggregation inputs.
  """
  @spec source_health(keyword()) :: map()
  def source_health(opts \\ []) do
    aggregate(opts).source_health
  end

  defp vulnerability_candidates(opts) do
    limit = Keyword.get(opts, :source_limit, @default_source_limit)
    recent_days = Keyword.get(opts, :recent_days, @default_recent_days)
    epss_threshold = Keyword.get(opts, :epss_threshold, @default_epss_threshold)
    recent_cutoff = DateTime.add(DateTime.utc_now(), -recent_days, :day)

    rows =
      from(c in CVE,
        where:
          c.in_kev == true or c.epss_score >= ^epss_threshold or
            c.published_at >= ^recent_cutoff,
        order_by: [
          desc: c.in_kev,
          desc_nulls_last: c.epss_score,
          desc_nulls_last: c.cvss_v4_score,
          desc_nulls_last: c.cvss_v3_score,
          desc_nulls_last: c.published_at
        ],
        limit: ^limit
      )
      |> Repo.all()

    candidates = Enum.map(rows, &vulnerability_to_candidate/1)

    source_result(:vulnerability_cve_kev_epss, candidates, %{
      status: source_status(candidates),
      records: length(candidates),
      epss_threshold: epss_threshold,
      recent_days: recent_days
    })
  rescue
    error ->
      source_gap(:vulnerability_cve_kev_epss, :unavailable, Exception.message(error))
  end

  defp vulnerability_to_candidate(%CVE{} = cve) do
    cvss_score = cve.cvss_v4_score || cve.cvss_v3_score || cve.cvss_v2_score

    %{
      id: "cve:#{cve.cve_id}",
      kind: "vulnerability",
      name: cve.cve_id,
      summary: cve.description,
      severity: normalize_severity(cve.calculated_severity || cvss_severity(cvss_score)),
      confidence: vulnerability_confidence(cve),
      sources: vulnerability_sources(cve),
      indicators: [%{type: "cve", value: cve.cve_id}],
      first_seen: cve.published_at,
      last_seen: cve.last_modified_at || cve.updated_at,
      tags: vulnerability_tags(cve),
      metadata: prune_nil(%{
        cvss_score: cvss_score,
        epss_score: cve.epss_score,
        epss_percentile: cve.epss_percentile,
        in_kev: cve.in_kev,
        kev_date_added: cve.kev_date_added,
        kev_due_date: cve.kev_due_date,
        kev_ransomware_use: cve.kev_ransomware_use,
        status: cve.status,
        weaknesses: cve.weaknesses
      })
    }
  end

  defp malware_feed_candidates(opts) do
    limit = Keyword.get(opts, :source_limit, @default_source_limit)

    table_status =
      Map.new(@abuse_ch_tables, fn {name, table} ->
        {name, table_size(table)}
      end)

    candidates =
      @abuse_ch_tables
      |> Enum.flat_map(fn {feed, table} -> table_candidates(feed, table, limit) end)
      |> Enum.uniq_by(& &1.id)
      |> Enum.take(limit)

    total_records = table_status |> Map.values() |> Enum.sum()

    source_result(:malware_feeds, candidates, %{
      status: source_status(candidates, total_records),
      records: length(candidates),
      available_records: total_records,
      tables: table_status,
      gap: if(total_records == 0, do: "abuse_ch_ets_tables_empty_or_not_started")
    })
  end

  defp table_candidates(feed, table, limit) do
    case :ets.whereis(table) do
      :undefined ->
        []

      _tid ->
        table
        |> :ets.tab2list()
        |> Enum.take(limit)
        |> Enum.flat_map(fn {_key, data} -> malware_ioc_to_candidate(feed, data) end)
    end
  rescue
    _ -> []
  end

  defp malware_ioc_to_candidate(feed, data) when is_map(data) do
    with {indicator_type, value} <- malware_indicator(data),
         true <- present?(value) do
      family = data[:malware] || data["malware"] || data[:signature] || data["signature"]
      label = family || data[:threat] || data["threat"] || "#{feed} indicator"

      [
        %{
          id: "malware:#{indicator_type}:#{value}",
          kind: "malware_feed",
          name: to_string(label),
          summary: data[:threat] || data["threat"] || data[:file_name] || data["file_name"],
          severity: normalize_severity(data[:severity] || data["severity"]),
          confidence: normalize_confidence(data[:confidence] || data["confidence"]),
          sources: [to_string(data[:source] || data["source"] || feed)],
          indicators: [%{type: indicator_type, value: value}],
          first_seen: data[:first_seen] || data["first_seen"] || data[:date_added] || data["date_added"],
          last_seen: data[:last_seen] || data["last_seen"] || data[:fetched_at] || data["fetched_at"],
          tags: normalize_tags(data[:tags] || data["tags"] || [feed]),
          metadata: prune_nil(Map.take(data, [:port, :country, :as_number, :as_name, :status, :file_type]))
        }
      ]
    else
      _ -> []
    end
  end

  defp malware_ioc_to_candidate(_feed, _data), do: []

  defp malware_indicator(data) do
    cond do
      present?(data[:sha256] || data["sha256"]) -> {"hash_sha256", data[:sha256] || data["sha256"]}
      present?(data[:hash] || data["hash"]) -> {"hash", data[:hash] || data["hash"]}
      present?(data[:ip] || data["ip"]) -> {"ip", data[:ip] || data["ip"]}
      present?(data[:domain] || data["domain"]) -> {"domain", data[:domain] || data["domain"]}
      present?(data[:url] || data["url"]) -> {"url", data[:url] || data["url"]}
      present?(data[:ioc] || data["ioc"]) -> {ioc_type(data[:ioc_type] || data["ioc_type"]), data[:ioc] || data["ioc"]}
      true -> nil
    end
  end

  defp actor_campaign_candidates(opts) do
    limit = Keyword.get(opts, :source_limit, @default_source_limit)

    actor_result = safe_repo_source(fn ->
      ThreatActor.list(limit: limit, active: true, order_by: :last_seen)
    end)

    # This global aggregator has no authenticated tenant principal. Campaigns
    # are therefore intentionally unavailable here instead of accepting an org
    # from caller-controlled options.
    campaign_result = %{items: [], gap: "authoritative_organization_context_required"}

    candidates =
      actor_candidates(actor_result.items) ++ campaign_candidates(campaign_result.items)

    gaps =
      [actor_result.gap, campaign_result.gap]
      |> Enum.reject(&is_nil/1)

    source_result(:actor_campaign, candidates, %{
      status: source_status(candidates, length(actor_result.items) + length(campaign_result.items)),
      records: length(candidates),
      gaps: gaps
    })
  end

  defp actor_candidates(actors) do
    Enum.map(actors, fn actor ->
      %{
        id: "actor:#{actor.id}",
        kind: "threat_actor",
        name: actor.name,
        summary: actor.description,
        severity: actor_severity(actor),
        confidence: normalize_confidence(actor.confidence),
        sources: [actor.source || "threat_actor"],
        indicators: [],
        first_seen: actor.first_seen,
        last_seen: actor.last_seen || actor.updated_at,
        tags: normalize_tags(actor.ttps ++ actor.primary_tactics ++ actor.known_malware),
        metadata: prune_nil(%{
          aliases: actor.aliases,
          motivation: actor.motivation,
          sophistication: actor.sophistication,
          origin_country: actor.origin_country,
          ioc_count: actor.ioc_count,
          active: actor.active
        })
      }
    end)
  end

  defp campaign_candidates(campaigns) do
    Enum.map(campaigns, fn campaign ->
      id = map_get(campaign, :id) || map_get(campaign, "id")
      actor = map_get(campaign, :actor) || map_get(campaign, "actor")

      %{
        id: "campaign:#{id}",
        kind: "campaign",
        name: map_get(campaign, :name) || "Campaign #{id}",
        summary: if(actor, do: "Active campaign attributed to #{actor}"),
        severity: normalize_severity(map_get(campaign, :severity)),
        confidence: normalize_confidence(map_get(campaign, :confidence)),
        sources: ["campaign_tracker"],
        indicators:
          (map_get(campaign, :ioc_values) || [])
          |> Enum.map(&%{type: "ioc", value: &1}),
        first_seen: map_get(campaign, :start_time),
        last_seen: map_get(campaign, :end_time) || map_get(campaign, :updated_at),
        tags: normalize_tags(map_get(campaign, :mitre_techniques) || []),
        metadata: prune_nil(%{
          actor: actor,
          alert_count: length(map_get(campaign, :alert_ids) || []),
          affected_agents: map_get(campaign, :affected_agents),
          ioc_count: map_get(campaign, :ioc_count),
          status: map_get(campaign, :status)
        })
      }
    end)
  end

  defp sigma_rule_candidates(opts) do
    limit = Keyword.get(opts, :source_limit, @default_source_limit)

    result =
      safe_process_call(SigmaSync, fn ->
        SigmaSync.list_rules()
      end)

    candidates =
      result.items
      |> Enum.take(limit)
      |> Enum.map(&sigma_rule_to_candidate/1)

    source_result(:sigma_rule_mappings, candidates, %{
      status: source_status(candidates, length(result.items)),
      records: length(candidates),
      gap: result.gap
    })
  end

  defp sigma_rule_to_candidate(rule) do
    techniques = rule["_mitre_techniques"] || []

    %{
      id: "sigma:#{rule["id"] || rule["title"]}",
      kind: "detection_rule_mapping",
      name: rule["title"] || rule["id"],
      summary: rule["description"],
      severity: normalize_severity(rule["level"]),
      confidence: sigma_confidence(rule),
      sources: ["sigmahq"],
      indicators: Enum.map(techniques, &%{type: "mitre_technique", value: &1}),
      first_seen: rule["date"],
      last_seen: rule["modified"],
      tags: normalize_tags((rule["tags"] || []) ++ techniques),
      metadata: prune_nil(%{
        status: rule["status"],
        category: rule["_category"],
        logsource_category: rule["_logsource_category"],
        logsource_product: rule["_logsource_product"]
      })
    }
  end

  defp ai_model_threat_candidates(opts) do
    limit = Keyword.get(opts, :source_limit, @default_source_limit)

    runtime_result =
      safe_process_call(AttackSurface, fn ->
        events = AttackSurface.get_recent_events(limit: limit)
        shadow = AttackSurface.get_shadow_ai_detections(limit: limit)
        events ++ shadow
      end)

    alert_result = safe_repo_source(fn -> ai_security_alerts(limit) end)

    candidates =
      runtime_ai_candidates(runtime_result.items) ++ alert_ai_candidates(alert_result.items)

    gaps =
      [runtime_result.gap, alert_result.gap]
      |> Enum.reject(&is_nil/1)

    source_result(:ai_model_threats, candidates, %{
      status: source_status(candidates, length(runtime_result.items) + length(alert_result.items)),
      records: length(candidates),
      gaps: gaps
    })
  end

  defp ai_security_alerts(limit) do
    pattern = "%ai_security%"
    llm_pattern = "%llm%"
    prompt_pattern = "%prompt%"
    rag_pattern = "%rag%"

    from(a in Alert,
      where:
        fragment("?::text ILIKE ?", a.evidence, ^pattern) or
          fragment("?::text ILIKE ?", a.detection_metadata, ^pattern) or
          fragment("?::text ILIKE ?", a.enrichment, ^pattern) or
          fragment("? ILIKE ?", a.title, ^llm_pattern) or
          fragment("? ILIKE ?", a.title, ^prompt_pattern) or
          fragment("? ILIKE ?", a.title, ^rag_pattern),
      order_by: [desc: a.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  defp runtime_ai_candidates(events) do
    events
    |> Enum.filter(&is_map/1)
    |> Enum.map(fn event ->
      domain = map_get(event, :domain) || map_get(event, :remote_domain)
      provider = map_get(event, :ai_provider) || map_get(event, :ai_service)
      name = domain || provider || map_get(event, :action_type) || "AI security event"

      %{
        id: "ai_runtime:#{:erlang.phash2(event)}",
        kind: "ai_model_threat",
        name: to_string(name),
        summary: map_get(event, :reason),
        severity: ai_runtime_severity(event),
        confidence: normalize_confidence(map_get(event, :risk_score) || 0.6),
        sources: ["ai_attack_surface"],
        indicators: ai_event_indicators(event),
        first_seen: map_get(event, :detected_at),
        last_seen: map_get(event, :detected_at),
        tags: ["ai_security", "runtime"],
        metadata: prune_nil(%{
          agent_id: map_get(event, :agent_id),
          provider: provider,
          domain: domain,
          is_shadow_ai: map_get(event, :is_shadow_ai),
          process_info: map_get(event, :process_info)
        })
      }
    end)
  end

  defp alert_ai_candidates(alerts) do
    Enum.map(alerts, fn alert ->
      %{
        id: "ai_alert:#{alert.id}",
        kind: "ai_model_threat",
        name: alert.title,
        summary: alert.description,
        severity: normalize_severity(alert.severity),
        confidence: normalize_confidence(alert.threat_score),
        sources: ["alerts"],
        indicators: [],
        first_seen: alert.inserted_at,
        last_seen: alert.last_seen_at || alert.updated_at,
        tags: normalize_tags(["ai_security" | alert.mitre_techniques]),
        metadata: prune_nil(%{
          alert_id: alert.id,
          status: alert.status,
          agent_id: alert.agent_id,
          mitre_tactics: alert.mitre_tactics,
          mitre_techniques: alert.mitre_techniques
        })
      }
    end)
  end

  defp emerging_threats_feed_health do
    health =
      safe_process_call(EmergingThreats, fn ->
        [EmergingThreats.get_status()]
      end)

    status = List.first(health.items)

    source_result(:emerging_threats_feed, [], %{
      status:
        cond do
          health.gap -> :gap
          is_map(status) && status[:enabled] == false -> :disabled
          is_map(status) -> :available
          true -> :gap
        end,
      records: 0,
      available_feeds: if(is_map(status), do: status[:available_feeds] || [], else: []),
      feed_status: if(is_map(status), do: status[:feed_status] || %{}, else: %{}),
      gap: health.gap
    })
  end

  defp normalize_candidates(candidates) do
    candidates
    |> Enum.reject(&(is_nil(&1[:id]) or is_nil(&1[:name])))
    |> Enum.map(&finalize_candidate/1)
    |> Enum.uniq_by(& &1.id)
    |> Enum.sort_by(&candidate_rank/1, :desc)
  end

  defp finalize_candidate(candidate) do
    candidate
    |> Map.update(:severity, "medium", &normalize_severity/1)
    |> Map.update(:confidence, 0.5, &normalize_confidence/1)
    |> Map.update(:sources, [], &normalize_tags/1)
    |> Map.update(:tags, [], &normalize_tags/1)
    |> Map.update(:indicators, [], &List.wrap/1)
    |> Map.put_new(:metadata, %{})
  end

  defp candidate_rank(candidate) do
    severity_weight =
      %{"critical" => 4, "high" => 3, "medium" => 2, "low" => 1, "info" => 0}
      |> Map.get(candidate.severity, 1)

    severity_weight + candidate.confidence
  end

  defp safe_process_call(module, fun) do
    if Process.whereis(module) do
      %{items: List.wrap(fun.()), gap: nil}
    else
      %{items: [], gap: "#{inspect(module)}_not_started"}
    end
  rescue
    error -> %{items: [], gap: Exception.message(error)}
  catch
    :exit, reason -> %{items: [], gap: inspect(reason)}
  end

  defp safe_repo_source(fun) do
    %{items: List.wrap(fun.()), gap: nil}
  rescue
    error -> %{items: [], gap: Exception.message(error)}
  catch
    :exit, reason -> %{items: [], gap: inspect(reason)}
  end

  defp source_result(source, candidates, health) do
    %{
      source: source,
      candidates: candidates,
      health: health |> prune_nil() |> Map.put_new(:status, source_status(candidates))
    }
  end

  defp source_gap(source, status, reason) do
    source_result(source, [], %{status: status, gap: reason, records: 0})
  end

  defp source_status(candidates, available_records \\ nil)
  defp source_status(candidates, nil), do: source_status(candidates, length(candidates))
  defp source_status(_candidates, available_records) when available_records > 0, do: :available
  defp source_status(_candidates, _available_records), do: :gap

  defp table_size(table) do
    case :ets.whereis(table) do
      :undefined -> 0
      _tid -> :ets.info(table, :size) || 0
    end
  rescue
    _ -> 0
  end

  defp vulnerability_confidence(%CVE{} = cve) do
    cond do
      cve.in_kev && is_number(cve.epss_score) -> max(0.9, cve.epss_score)
      cve.in_kev -> 0.9
      is_number(cve.epss_score) -> cve.epss_score
      true -> 0.5
    end
    |> normalize_confidence()
  end

  defp vulnerability_sources(%CVE{} = cve) do
    []
    |> maybe_cons(cve.in_kev, "cisa_kev")
    |> maybe_cons(not is_nil(cve.epss_score), "first_epss")
    |> maybe_cons(not is_nil(cve.source_identifier), "nvd")
    |> case do
      [] -> ["cve"]
      sources -> Enum.reverse(sources)
    end
  end

  defp vulnerability_tags(%CVE{} = cve) do
    tags =
      []
      |> maybe_cons(cve.in_kev, "kev")
      |> maybe_cons(cve.kev_ransomware_use == "Known", "ransomware")
      |> maybe_cons(is_number(cve.epss_score) && cve.epss_score >= @default_epss_threshold, "high_epss")

    normalize_tags(tags ++ (cve.weaknesses || []))
  end

  defp maybe_cons(list, true, value), do: [value | list]
  defp maybe_cons(list, _condition, _value), do: list

  defp cvss_severity(nil), do: "medium"
  defp cvss_severity(score) when score >= 9.0, do: "critical"
  defp cvss_severity(score) when score >= 7.0, do: "high"
  defp cvss_severity(score) when score >= 4.0, do: "medium"
  defp cvss_severity(_score), do: "low"

  defp actor_severity(actor) do
    cond do
      actor.sophistication == "expert" or actor.resource_level == "government" -> "critical"
      actor.sophistication == "advanced" -> "high"
      actor.active -> "medium"
      true -> "low"
    end
  end

  defp sigma_confidence(rule) do
    case rule["status"] do
      "stable" -> 0.85
      "test" -> 0.7
      _ -> 0.5
    end
  end

  defp ai_runtime_severity(event) do
    cond do
      map_get(event, :is_shadow_ai) == true -> "medium"
      normalize_confidence(map_get(event, :risk_score)) >= 0.8 -> "high"
      true -> "medium"
    end
  end

  defp ai_event_indicators(event) do
    []
    |> maybe_indicator("domain", map_get(event, :domain) || map_get(event, :remote_domain))
    |> maybe_indicator("ai_provider", map_get(event, :ai_provider) || map_get(event, :ai_service))
  end

  defp maybe_indicator(indicators, _type, nil), do: indicators
  defp maybe_indicator(indicators, _type, ""), do: indicators
  defp maybe_indicator(indicators, type, value), do: [%{type: type, value: value} | indicators]

  defp ioc_type("ip:port"), do: "ip"
  defp ioc_type("md5_hash"), do: "hash_md5"
  defp ioc_type("sha256_hash"), do: "hash_sha256"
  defp ioc_type(type) when is_binary(type), do: type
  defp ioc_type(_), do: "ioc"

  defp normalize_severity(severity) when is_atom(severity), do: severity |> Atom.to_string() |> normalize_severity()

  defp normalize_severity(severity) when is_binary(severity) do
    case String.downcase(severity) do
      value when value in ["critical", "high", "medium", "low", "info"] -> value
      "informational" -> "info"
      "none" -> "info"
      "unknown" -> "medium"
      _ -> "medium"
    end
  end

  defp normalize_severity(_severity), do: "medium"

  defp normalize_confidence(confidence) when is_integer(confidence), do: normalize_confidence(confidence / 1.0)

  defp normalize_confidence(confidence) when is_float(confidence) do
    cond do
      confidence > 1.0 -> min(confidence / 100.0, 1.0)
      confidence < 0.0 -> 0.0
      true -> Float.round(confidence, 3)
    end
  end

  defp normalize_confidence(_confidence), do: 0.5

  defp normalize_tags(tags) do
    tags
    |> List.wrap()
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&to_string/1)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp prune_nil(map) do
    map
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

  defp present?(value), do: is_binary(value) && String.trim(value) != ""

  defp map_get(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, to_string(key))
  defp map_get(_map, _key), do: nil
end
