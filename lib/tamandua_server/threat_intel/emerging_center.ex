defmodule TamanduaServer.ThreatIntel.EmergingCenter do
  @moduledoc """
  Read model and action layer for Emerging Threats.

  The center keeps source aggregation, local exposure context, and analyst
  actions behind one contract so the Inertia page and JSON API do not drift.
  """

  import Ecto.Query, warn: false

  require Logger

  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.CommandManager
  alias TamanduaServer.Investigations
  alias TamanduaServer.Investigations.CaseInvestigation
  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.ThreatIntel.{EmergingActions, EmergingExposure, EmergingSources, EmergingThreat}

  @default_limit 100
  @default_context_limit 500

  @spec summary(String.t() | nil, keyword()) :: map()
  def summary(organization_id, opts \\ []) do
    aggregate = aggregate(opts)
    context = local_context(organization_id, opts)

    threats =
      aggregate
      |> Map.get(:candidates, [])
      |> Enum.map(&serialize_candidate(&1, context))
      |> Enum.reject(&is_nil/1)

    source_health =
      aggregate
      |> Map.get(:source_health, %{})
      |> Enum.map(fn {source, health} -> serialize_source_health(source, health) end)
      |> Enum.sort_by(& &1.name)

    %{
      threats: threats,
      sourceHealth: source_health,
      generatedAt: format_datetime(Map.get(aggregate, :generated_at)),
      contextHealth: context.health
    }
  end

  @spec get_threat(String.t() | nil, String.t(), keyword()) :: {:ok, map()} | {:error, :not_found}
  def get_threat(organization_id, threat_id, opts \\ []) when is_binary(threat_id) do
    summary(organization_id, opts)
    |> Map.get(:threats, [])
    |> Enum.find(&(&1.id == threat_id))
    |> case do
      nil -> {:error, :not_found}
      threat -> {:ok, threat}
    end
  end

  @spec create_case(String.t(), String.t() | nil, String.t(), map(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def create_case(organization_id, user_id, threat_id, attrs \\ %{}, opts \\ [])
      when is_binary(organization_id) and is_binary(user_id) and is_binary(threat_id) do
    with {:ok, threat} <- get_threat(organization_id, threat_id, opts) do
      case existing_case_for_threat(organization_id, threat.id) do
        nil ->
          with {:ok, investigation} <- Investigations.create_investigation(case_attrs(organization_id, user_id, threat, attrs)) do
            {:ok, case_response(investigation, threat, "created")}
          end

        investigation ->
          {:ok, case_response(investigation, threat, "already_exists")}
      end
    end
  end

  def create_case(_organization_id, _user_id, _threat_id, _attrs, _opts), do: {:error, :tenant_or_user_required}

  @spec collect_evidence(String.t(), String.t(), [String.t()], map(), keyword()) :: map()
  def collect_evidence(organization_id, threat_id, agent_ids, attrs \\ %{}, opts \\ [])
      when is_binary(organization_id) and is_binary(threat_id) and is_list(agent_ids) do
    with {:ok, threat} <- get_threat(organization_id, threat_id, opts) do
      scoped_agents = scoped_agent_ids(organization_id, agent_ids)

      results =
        scoped_agents
        |> Enum.map(&queue_evidence_command(&1, threat, attrs))

      skipped =
        agent_ids
        |> Enum.map(&to_string/1)
        |> Kernel.--(scoped_agents)
        |> Enum.map(&%{agent_id: &1, status: "skipped", reason: "agent_not_in_tenant_or_not_found"})

      %{
        threat_id: threat.id,
        queued: Enum.filter(results, &(&1.status == "queued")),
        failed: Enum.reject(results, &(&1.status == "queued")),
        skipped: skipped,
        execution: if(results == [] and skipped == [], do: "not_executed", else: "queued_or_skipped")
      }
    else
      {:error, :not_found} ->
        %{threat_id: threat_id, queued: [], failed: [], skipped: [], execution: "not_found"}
    end
  end

  def collect_evidence(_organization_id, _threat_id, _agent_ids, _attrs, _opts) do
    %{queued: [], failed: [], skipped: [], execution: "invalid_request"}
  end

  @spec detection_pack_candidate(String.t() | nil, String.t(), keyword()) :: {:ok, map()} | {:error, :not_found}
  def detection_pack_candidate(organization_id, threat_id, opts \\ []) do
    with {:ok, threat} <- get_threat(organization_id, threat_id, opts) do
      actions = threat.recommendedActions || []
      hunts = threat.recommendedHunts || []

      pack =
        actions
        |> Enum.find(&(Map.get(&1, :action) == "create_detection_pack" or Map.get(&1, "action") == "create_detection_pack"))
        |> case do
          nil -> %{}
          action -> Map.get(action, :payload) || Map.get(action, "payload") || %{}
        end

      {:ok,
       %{
         threat_id: threat.id,
         state: "candidate",
         publishable: false,
         reason: "requires_rule_review_and_validation",
         pack:
           Map.merge(pack, %{
             id: Map.get(pack, :pack_slug) || Map.get(pack, "pack_slug") || slugify(threat.title),
             name: Map.get(pack, :pack_name) || Map.get(pack, "pack_name") || "Emerging Threat: #{threat.title}",
             source: "emerging_threats",
             severity: threat.severity,
             confidence: threat.confidence,
             tags: Enum.uniq(["emerging_threats", "review_required"] ++ List.wrap(threat.tags)),
             iocs: threat.iocs || [],
             rules: detection_rules_from_hunts(threat, hunts),
             validation: %{
               required: true,
               gates: [
                 "tenant_scope_review",
                 "false_positive_review",
                 "benchmark_fixture_required",
                 "rollback_or_disable_path_required"
               ]
             }
           }),
         recommended_hunts: hunts
       }}
    end
  end

  defp aggregate(opts) do
    EmergingSources.aggregate(limit: Keyword.get(opts, :limit, @default_limit))
  rescue
    e ->
      Logger.warning("Failed to aggregate emerging threats: #{Exception.message(e)}")

      %{
        candidates: [],
        source_health: %{emerging_threats: %{status: :gap, gap: Exception.message(e)}},
        generated_at: DateTime.utc_now()
      }
  end

  defp local_context(nil, _opts), do: empty_context("tenant_context_missing")

  defp local_context(organization_id, opts) when is_binary(organization_id) do
    agent_rows = agents_for_org(organization_id)
    agent_ids = Enum.map(agent_rows, & &1.agent_id)
    limit = Keyword.get(opts, :context_limit, @default_context_limit)
    software = software_inventory(organization_id, limit)
    vulnerabilities = asset_vulnerabilities(organization_id, limit)
    events = telemetry(organization_id, agent_ids, limit)

    %{
      assets: agent_rows,
      agents: agent_rows,
      software_inventory: software,
      asset_vulnerabilities: vulnerabilities,
      vulnerabilities: vulnerabilities,
      telemetry: events,
      health: context_health(%{
        assets: agent_rows,
        software_inventory: software,
        vulnerabilities: vulnerabilities,
        telemetry: events
      })
    }
  rescue
    e ->
      Logger.warning("Failed to load Emerging Threats local context: #{Exception.message(e)}")
      empty_context(Exception.message(e))
  end

  defp empty_context(reason) do
    %{
      assets: [],
      agents: [],
      software_inventory: [],
      asset_vulnerabilities: [],
      vulnerabilities: [],
      telemetry: [],
      health: %{
        state: "degraded",
        reason: reason,
        sources: [],
        gaps: ["tenant_context_or_local_context_unavailable"],
        counts: %{assets: 0, software_inventory: 0, vulnerabilities: 0, telemetry: 0}
      }
    }
  end

  defp agents_for_org(organization_id) do
    organization_id
    |> Agents.list_all_for_org()
    |> Enum.map(fn agent ->
      %{
        id: map_get(agent, :agent_id) || map_get(agent, :id),
        agent_id: map_get(agent, :agent_id) || map_get(agent, :id),
        hostname: map_get(agent, :hostname),
        platform: map_get(agent, :os_type),
        os_version: map_get(agent, :os_version),
        status: map_get(agent, :status),
        last_seen: map_get(agent, :last_seen_at) || map_get(agent, :last_seen),
        source: "agents"
      }
    end)
  rescue
    _ -> []
  end

  defp software_inventory(organization_id, limit) do
    from(s in "software_inventory",
      where: s.organization_id == ^organization_id,
      order_by: [desc: s.updated_at],
      limit: ^limit,
      select: %{
        id: s.id,
        agent_id: s.agent_id,
        asset_id: s.agent_id,
        name: s.name,
        version: s.version,
        vendor: s.vendor,
        cpe: s.cpe,
        source: s.source,
        package_manager: s.package_manager,
        platform: nil,
        updated_at: s.updated_at
      }
    )
    |> Repo.all()
  rescue
    _ -> []
  end

  defp asset_vulnerabilities(organization_id, limit) do
    from(v in "asset_vulnerabilities",
      left_join: c in "cves",
      on: c.id == v.cve_id,
      where: v.organization_id == ^organization_id,
      order_by: [desc: v.last_seen_at, desc: v.inserted_at],
      limit: ^limit,
      select: %{
        id: v.id,
        agent_id: v.agent_id,
        asset_id: v.agent_id,
        software_id: v.software_id,
        cve_id: c.cve_id,
        severity: c.calculated_severity,
        status: v.status,
        source: "asset_vulnerabilities",
        product: v.affected_software_name,
        software_name: v.affected_software_name,
        version: v.affected_software_version,
        confidence: v.confidence,
        last_seen_at: v.last_seen_at
      }
    )
    |> Repo.all()
  rescue
    _ -> []
  end

  defp telemetry(organization_id, agent_ids, limit) do
    from(e in Event,
      where: e.organization_id == ^organization_id,
      where: is_nil(e.agent_id) or e.agent_id in ^agent_ids,
      order_by: [desc: e.timestamp],
      limit: ^limit,
      select: %{
        id: e.id,
        agent_id: e.agent_id,
        asset_id: e.agent_id,
        event_type: e.event_type,
        timestamp: e.timestamp,
        source: "telemetry_events",
        payload: e.payload
      }
    )
    |> Repo.all()
  rescue
    _ -> []
  end

  defp context_health(context) do
    assets = Map.get(context, :assets, [])
    software = Map.get(context, :software_inventory, [])
    vulnerabilities = Map.get(context, :vulnerabilities, [])
    telemetry = Map.get(context, :telemetry, [])
    gaps = context_gaps(assets, software, vulnerabilities, telemetry)

    %{
      state: if(gaps == [], do: "available", else: "degraded"),
      reason: if(gaps == [], do: nil, else: "local_context_incomplete"),
      gaps: gaps,
      counts: %{
        assets: length(assets),
        software_inventory: length(software),
        vulnerabilities: length(vulnerabilities),
        telemetry: length(telemetry)
      },
      sources: [
        context_source("assets", assets, "agent_inventory"),
        context_source("software_inventory", software, "software_inventory_collector"),
        context_source("vulnerabilities", vulnerabilities, "asset_vulnerability_matcher"),
        context_source("telemetry", telemetry, "telemetry_events")
      ]
    }
  end

  defp context_gaps(assets, software, vulnerabilities, telemetry) do
    []
    |> maybe_gap(assets == [], "asset_inventory_missing")
    |> maybe_gap(software == [], "software_inventory_missing")
    |> maybe_gap(vulnerabilities == [], "asset_vulnerability_inventory_missing")
    |> maybe_gap(telemetry == [], "telemetry_context_missing")
    |> Enum.reverse()
  end

  defp context_source(name, rows, capability) do
    %{
      name: name,
      capability: capability,
      state: if(rows == [], do: "degraded", else: "available"),
      records: length(rows)
    }
  end

  defp maybe_gap(gaps, true, gap), do: [gap | gaps]
  defp maybe_gap(gaps, _condition, _gap), do: gaps

  defp serialize_candidate(candidate, context) when is_map(candidate) do
    threat = threat_contract(candidate, context)
    scored = EmergingThreat.score(threat)
    exposure = EmergingExposure.assess(EmergingThreat.to_map(threat), context)
    action_plan = action_plan(threat)
    score = scored.score

    %{
      id: threat.id,
      title: threat.title,
      summary: threat.summary,
      status: ui_status(threat.status, score),
      severity: EmergingThreat.severity_for_score(score),
      score: score,
      confidence: round(threat.confidence * 100),
      source: threat.sources |> List.wrap() |> Enum.map(&source_name/1) |> Enum.join(", "),
      firstSeen: format_datetime(threat.first_seen),
      lastUpdated: format_datetime(threat.last_seen),
      iocs: Enum.map(threat.iocs, &serialize_ioc(&1, threat.confidence)),
      ttps: Enum.map(threat.ttps, &serialize_ttp/1),
      affectedProducts: Enum.map(threat.affected_products, &serialize_product/1),
      localExposure: serialize_exposure(exposure),
      tags: Map.get(candidate, :tags, []) |> List.wrap() |> Enum.map(&to_string/1),
      scoreBreakdown: scored.score_breakdown,
      recommendedHunts: Map.get(action_plan, :recommended_hunts, []),
      recommendedActions: Map.get(action_plan, :recommended_actions, []),
      coverage: Map.get(action_plan, :coverage, []),
      execution: Map.get(action_plan, :execution, %{status: "not_executed"})
    }
  rescue
    e ->
      Logger.warning("Failed to serialize emerging threat candidate: #{Exception.message(e)}")
      nil
  end

  defp threat_contract(candidate, context) do
    indicators = Map.get(candidate, :indicators, [])
    tags = Map.get(candidate, :tags, [])
    metadata = Map.get(candidate, :metadata, %{})
    local_score = local_relevance_score(candidate, context)

    attrs = %{
      id: to_string(Map.get(candidate, :id)),
      title: to_string(Map.get(candidate, :name) || Map.get(candidate, :id)),
      summary: to_string(Map.get(candidate, :summary) || "Emerging threat candidate from local intelligence sources."),
      category: to_string(Map.get(candidate, :kind) || "emerging_threat"),
      status: "monitoring",
      severity: Map.get(candidate, :severity, "medium"),
      confidence: Map.get(candidate, :confidence, 0.5),
      sources: candidate |> Map.get(:sources, []) |> List.wrap() |> Enum.map(&%{name: to_string(&1)}),
      iocs: indicators,
      ttps: ttps(indicators, tags),
      affected_products: affected_products(candidate, metadata),
      first_seen: Map.get(candidate, :first_seen),
      last_seen: Map.get(candidate, :last_seen),
      exploit_maturity: exploit_maturity(candidate),
      local_relevance_score: local_score,
      recommended_hunts: [],
      recommended_actions: [],
      coverage_gaps: []
    }

    EmergingThreat.new!(attrs)
  end

  defp local_relevance_score(candidate, context) do
    exposure =
      candidate
      |> Map.take([:indicators, :affected_products, :name, :kind])
      |> Map.put(:iocs, Map.get(candidate, :indicators, []))
      |> EmergingExposure.assess(context)

    cond do
      exposure.exposure_status == :exposed -> 100
      exposure.coverage_gaps == [] -> 35
      true -> 10
    end
  rescue
    _ -> 0
  end

  defp action_plan(threat) do
    primary_ioc = threat.iocs |> List.wrap() |> Enum.find(&is_map/1)

    if primary_ioc do
      EmergingActions.recommend(%{
        type: Map.get(primary_ioc, :type) || Map.get(primary_ioc, "type"),
        value: Map.get(primary_ioc, :value) || Map.get(primary_ioc, "value"),
        source: threat.sources |> List.wrap() |> Enum.map(&source_name/1) |> Enum.join(", "),
        severity: threat.severity,
        confidence: threat.confidence,
        tags: threat.ttps,
        metadata: %{threat_id: threat.id, category: threat.category}
      })
    else
      %{
        recommended_hunts: [],
        recommended_actions: [],
        coverage: [%{surface: "telemetry", capability: "IOC or TTP context", status: "missing"}],
        execution: %{status: "not_executed", reason: "no_primary_ioc"}
      }
    end
  rescue
    _ -> %{recommended_hunts: [], recommended_actions: [], coverage: [], execution: %{status: "not_executed", reason: "recommendation_failed"}}
  end

  defp scoped_agent_ids(organization_id, agent_ids) do
    allowed =
      organization_id
      |> Agents.list_all_for_org()
      |> Enum.map(&(map_get(&1, :agent_id) || map_get(&1, :id)))
      |> MapSet.new()

    agent_ids
    |> Enum.map(&to_string/1)
    |> Enum.filter(&MapSet.member?(allowed, &1))
  rescue
    _ -> []
  end

  defp queue_evidence_command(agent_id, threat, attrs) do
    payload = %{
      reason: "emerging_threat_validation",
      threat_id: threat.id,
      threat_title: threat.title,
      iocs: threat.iocs,
      requested_scope: Map.get(attrs, "scope") || Map.get(attrs, :scope) || "ioc_context",
      collect: ["process_tree", "network_connections", "dns_cache", "file_hash_context", "software_inventory"],
      max_age_seconds: 86_400
    }

    case CommandManager.queue_command(agent_id, :collect_forensics, payload,
           priority: 5,
           timeout: 900,
           idempotency_key: "emerging-threat:#{threat.id}:collect-evidence:#{agent_id}"
         ) do
      {:ok, command} -> %{agent_id: agent_id, status: "queued", command_id: command.id, command_type: command.command_type}
      {:error, reason} -> %{agent_id: agent_id, status: "failed", reason: inspect(reason)}
    end
  end

  defp case_attrs(organization_id, user_id, threat, attrs) do
    %{
      organization_id: organization_id,
      created_by: user_id,
      title: Map.get(attrs, "title") || Map.get(attrs, :title) || "Emerging Threat: #{threat.title}",
      description: threat.summary,
      severity: normalize_case_severity(threat.severity),
      tags: Enum.uniq(["emerging_threats", threat.id] ++ List.wrap(threat.tags)),
      notes: "Created from Emerging Threats. Source=#{threat.source}; score=#{threat.score}; exposure=#{threat.localExposure.state}",
      timeline: %{
        "events" => [
          %{
            "type" => "emerging_threat_case_created",
            "entity_id" => threat.id,
            "occurred_at" => DateTime.utc_now() |> DateTime.to_iso8601(),
            "summary" => threat.title
          }
        ]
      }
    }
  end

  defp existing_case_for_threat(organization_id, threat_id) do
    tag = to_string(threat_id)

    CaseInvestigation
    |> where([case_record], case_record.organization_id == ^organization_id)
    |> where([case_record], case_record.status in ["open", "in_progress"])
    |> where([case_record], ^tag in case_record.tags)
    |> order_by([case_record], desc: case_record.inserted_at)
    |> limit(1)
    |> Repo.one()
  rescue
    _ -> nil
  end

  defp case_response(investigation, threat, action) do
    %{
      id: investigation.id,
      title: investigation.title,
      status: investigation.status,
      severity: investigation.severity,
      source: "emerging_threats",
      threat_id: threat.id,
      action: action
    }
  end

  defp normalize_case_severity("critical"), do: "critical"
  defp normalize_case_severity("high"), do: "high"
  defp normalize_case_severity("medium"), do: "medium"
  defp normalize_case_severity("low"), do: "low"
  defp normalize_case_severity(_), do: "info"

  defp detection_rules_from_hunts(threat, hunts) do
    hunts
    |> Enum.with_index(1)
    |> Enum.map(fn {hunt, index} ->
      language = map_get(hunt, :language) || "tql"
      query = map_get(hunt, :query) || map_get(hunt, :match) || ""
      name = map_get(hunt, :name) || "Emerging Threat #{index}"

      %{
        id: "#{slugify(threat.title)}-#{index}",
        name: name,
        language: language,
        query: query,
        severity: threat.severity,
        enabled: false,
        status: "candidate",
        reason: "Generated from Emerging Threats recommendation; validate before enabling.",
        labels: map_get(hunt, :labels) || []
      }
    end)
  end

  defp source_name(%{name: name}) when is_binary(name), do: name
  defp source_name(%{"name" => name}) when is_binary(name), do: name
  defp source_name(source), do: to_string(source)

  defp ttps(indicators, tags) do
    (indicators ++ List.wrap(tags))
    |> Enum.flat_map(fn
      %{type: "mitre_technique", value: value} -> [value]
      %{"type" => "mitre_technique", "value" => value} -> [value]
      value when is_binary(value) -> Regex.scan(~r/T\d{4}(?:\.\d{3})?/, value) |> List.flatten()
      _ -> []
    end)
    |> Enum.uniq()
  end

  defp affected_products(%{kind: "vulnerability", name: cve_id}, metadata) do
    [%{name: to_string(cve_id), cves: [to_string(cve_id)], versions: [], vendor: Map.get(metadata, :vendor)}]
  end

  defp affected_products(candidate, metadata) do
    products =
      Map.get(metadata, :affected_products) ||
        Map.get(metadata, "affected_products") ||
        Map.get(candidate, :affected_products) ||
        []

    products
    |> List.wrap()
    |> Enum.map(&serialize_product/1)
  end

  defp exploit_maturity(candidate) do
    tags = candidate |> Map.get(:tags, []) |> List.wrap() |> Enum.map(&String.downcase(to_string(&1)))

    cond do
      "kev" in tags or "ransomware" in tags -> "exploited"
      "high_epss" in tags -> "weaponized"
      Map.get(candidate, :kind) in ["malware_feed", "campaign"] -> "exploited"
      Map.get(candidate, :kind) == "detection_rule_mapping" -> "poc"
      true -> "unknown"
    end
  end

  defp ui_status("monitoring", score) when score >= 70, do: "active"
  defp ui_status("monitoring", _score), do: "watching"
  defp ui_status("validated", _score), do: "active"
  defp ui_status("archived", _score), do: "stale"
  defp ui_status(_, _score), do: "watching"

  defp serialize_ioc(%{} = ioc, confidence) do
    %{
      type: to_string(Map.get(ioc, :type) || Map.get(ioc, "type") || "indicator"),
      value: to_string(Map.get(ioc, :value) || Map.get(ioc, "value") || ""),
      confidence: round(confidence * 100),
      source: Map.get(ioc, :source) || Map.get(ioc, "source")
    }
  end

  defp serialize_ioc(value, confidence), do: %{type: "indicator", value: to_string(value), confidence: round(confidence * 100)}

  defp serialize_ttp(%{} = ttp) do
    %{id: to_string(Map.get(ttp, :id) || Map.get(ttp, "id") || Map.get(ttp, :value) || Map.get(ttp, "value") || "unknown")}
  end

  defp serialize_ttp(value), do: %{id: to_string(value)}

  defp serialize_product(%{} = product) do
    %{
      vendor: Map.get(product, :vendor) || Map.get(product, "vendor"),
      name: to_string(Map.get(product, :name) || Map.get(product, "name") || Map.get(product, :product) || Map.get(product, "product") || "unknown"),
      versions: Map.get(product, :versions) || Map.get(product, "versions") || [],
      cves: Map.get(product, :cves) || Map.get(product, "cves") || []
    }
  end

  defp serialize_product(value), do: %{name: to_string(value), versions: [], cves: []}

  defp serialize_exposure(exposure) do
    status = Map.get(exposure, :exposure_status, :unknown)
    assets = Map.get(exposure, :matched_assets, [])
    gaps = Map.get(exposure, :coverage_gaps, [])
    collection = Map.get(exposure, :recommended_collection, [])

    %{
      state:
        case status do
          :exposed -> "exposed"
          :not_detected -> "covered"
          _ -> "unknown"
        end,
      exposedAssets: length(assets),
      matchingAgents: length(assets),
      agentIds:
        assets
        |> Enum.map(&(map_get(&1, :asset_id) || map_get(&1, :agent_id) || map_get(&1, :id)))
        |> Enum.reject(&blank?/1)
        |> Enum.uniq(),
      matchedProducts: Map.get(exposure, :matched_products, []),
      matchedCves: Map.get(exposure, :matched_cves, []),
      telemetryMatches: Map.get(exposure, :telemetry_matches, []),
      notes: ["Exposure assessment uses explicit local matches only."],
      gaps: Enum.map(gaps ++ collection, &to_string/1)
    }
  end

  defp serialize_source_health(source, health) do
    status = Map.get(health, :status) || Map.get(health, "status")

    %{
      id: to_string(source),
      name: source |> to_string() |> String.replace("_", " ") |> String.capitalize(),
      status: source_ui_status(status),
      itemsIngested: Map.get(health, :records) || Map.get(health, "records") || Map.get(health, :available_records) || 0,
      detail: Map.get(health, :gap) || Map.get(health, "gap") || Map.get(health, :reason) || "source operational",
      lastSync: format_datetime(Map.get(health, :last_sync) || Map.get(health, "last_sync")),
      freshnessMinutes: Map.get(health, :freshness_minutes) || Map.get(health, "freshness_minutes")
    }
  end

  defp source_ui_status(status) when status in [:available, "available", :ok, "ok"], do: "healthy"
  defp source_ui_status(status) when status in [:disabled, "disabled"], do: "stale"
  defp source_ui_status(_), do: "degraded"

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(%NaiveDateTime{} = dt), do: dt |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_iso8601()
  defp format_datetime(%Date{} = dt), do: Date.to_iso8601(dt)
  defp format_datetime(value) when is_binary(value), do: value
  defp format_datetime(value), do: to_string(value)

  defp slugify(value) do
    value
    |> to_string()
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9]+/, "_")
    |> String.trim("_")
    |> case do
      "" -> "emerging_threat"
      slug -> slug
    end
  end

  defp map_get(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, to_string(key))
  defp map_get(_map, _key), do: nil

  defp blank?(nil), do: true
  defp blank?(""), do: true
  defp blank?([]), do: true
  defp blank?(_), do: false
end
