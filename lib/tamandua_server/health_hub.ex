defmodule TamanduaServer.HealthHub do
  @moduledoc """
  Unified operational health/SLO view for Tamandua control surfaces.

  The hub only reports signals that can be read from existing runtime state or
  persisted tenant telemetry. Missing integrations stay explicit as degraded or
  not configured rather than being filled with sample data.
  """

  import Ecto.Query

  require Logger

  alias TamanduaServer.Agents
  alias TamanduaServer.Agents.{PlatformCapabilities, PlatformVisibility, Registry}
  alias TamanduaServer.Repo
  alias TamanduaServer.LiveResponse.EvidenceSession
  alias TamanduaServer.Telemetry.Event

  @window_hours 24
  @max_future_skew_seconds 300

  @type status :: :healthy | :degraded | :down | :not_configured

  @spec summary(Ecto.UUID.t() | nil, keyword()) :: map()
  def summary(organization_id, opts \\ []) do
    window_hours = Keyword.get(opts, :window_hours, @window_hours)

    agents =
      safe_call([], fn ->
        if organization_id, do: Agents.list_all_for_org(organization_id), else: []
      end)

    now = DateTime.utc_now()
    telemetry = telemetry_summary(organization_id, window_hours, now)

    items = [
      endpoint_agents_item(agents, now),
      collector_item("dns_collector", "DNS collector", "collectors", "DNS", telemetry, ["dns"]),
      collector_item("ndr_collector", "NDR collector", "collectors", "Network", telemetry, [
        "ndr",
        "network"
      ]),
      collector_item(
        "software_inventory",
        "Software inventory",
        "collectors",
        "Endpoint inventory",
        telemetry,
        ["software", "inventory", "package"]
      ),
      mobile_command_link_item(organization_id),
      evidence_sessions_item(organization_id, window_hours, now),
      browser_native_bridge_item(telemetry),
      ai_gateway_item(),
      integrations_soar_item(),
      threat_intel_feeds_item(),
      parser_ingest_item(telemetry)
    ]

    platform_visibility = platform_visibility_summary(agents, now)

    %{
      generated_at: format_datetime(now),
      window_hours: window_hours,
      overall_status: aggregate_status(items),
      status_counts: status_counts(items),
      platform_visibility: platform_visibility,
      platformVisibility: platform_visibility,
      items: items
    }
  end

  defp evidence_sessions_item(nil, _window_hours, _now) do
    unavailable_item(
      "evidence_sessions",
      "Evidence sessions",
      "live_response",
      "Screen evidence",
      "Tenant context is unavailable.",
      "Open a tenant-scoped workspace before assessing evidence-session health."
    )
  end

  defp evidence_sessions_item(organization_id, window_hours, now) do
    cutoff = DateTime.add(now, -window_hours * 3600, :second)
    latest_allowed = DateTime.add(now, @max_future_skew_seconds, :second)

    case safe_call({:error, :unavailable}, fn ->
           {:ok, evidence_session_rows(organization_id, cutoff, latest_allowed)}
         end) do
      {:ok, []} ->
        item(%{
          id: "evidence_sessions",
          name: "Evidence sessions",
          category: "live_response",
          owner: "Endpoint Response",
          surface: "Screen evidence",
          status: :not_configured,
          coverage: coverage(0, 0, "No sessions requested in window"),
          gaps: [],
          recommended_action:
            "Run a policy-authorized evidence session when screen evidence is required.",
          reason:
            "No evidence sessions were requested in this tenant/window; platform capture health is unknown.",
          metrics: evidence_session_empty_metrics()
        })

      {:ok, rows} ->
        metrics = summarize_evidence_session_rows(rows)
        status = evidence_session_status(metrics)

        item(%{
          id: "evidence_sessions",
          name: "Evidence sessions",
          category: "live_response",
          owner: "Endpoint Response",
          surface: "Screen evidence",
          status: status,
          last_seen: format_datetime(metrics.last_seen),
          coverage:
            coverage(
              metrics.successful_terminal,
              metrics.terminal_attempts,
              evidence_session_coverage_label(metrics)
            ),
          gaps: evidence_session_gaps(metrics),
          recommended_action: evidence_session_action(status),
          reason:
            "Derived from persisted tenant evidence-session outcomes; in-flight and operator-cancelled sessions are not counted as platform failures.",
          metrics: Map.delete(metrics, :last_seen)
        })

      {:error, reason} ->
        unavailable_item(
          "evidence_sessions",
          "Evidence sessions",
          "live_response",
          "Screen evidence",
          "Evidence-session metrics unavailable: #{inspect(reason)}.",
          "Apply the evidence-session schema and verify tenant-scoped database access."
        )
    end
  end

  defp evidence_session_rows(organization_id, cutoff, latest_allowed) do
    from(s in EvidenceSession,
      where:
        s.organization_id == ^organization_id and s.inserted_at >= ^cutoff and
          s.inserted_at <= ^latest_allowed,
      group_by: [
        fragment("COALESCE(NULLIF(?->>'platform', ''), 'unknown')", s.capture_request),
        s.status
      ],
      select: %{
        platform: fragment("COALESCE(NULLIF(?->>'platform', ''), 'unknown')", s.capture_request),
        status: s.status,
        count: count(s.id),
        latency_samples: count(s.completed_at),
        average_latency_ms:
          fragment(
            "AVG(CASE WHEN ? IS NOT NULL THEN EXTRACT(EPOCH FROM (? - COALESCE(?, ?))) * 1000 END)",
            s.completed_at,
            s.completed_at,
            s.started_at,
            s.inserted_at
          ),
        last_seen: fragment("MAX(COALESCE(?, ?))", s.completed_at, s.inserted_at)
      }
    )
    |> Repo.all()
  end

  defp summarize_evidence_session_rows(rows) do
    by_platform =
      rows
      |> Enum.group_by(&normalize_platform(&1.platform))
      |> Map.new(fn {platform, platform_rows} ->
        {platform, evidence_platform_metrics(platform_rows)}
      end)

    totals = evidence_platform_metrics(rows)

    totals
    |> Map.put(:by_platform, by_platform)
    |> Map.put(:platforms_observed, map_size(by_platform))
  end

  defp evidence_platform_metrics(rows) do
    status_counts =
      Enum.reduce(rows, evidence_session_status_counts(), fn row, counts ->
        Map.update(
          counts,
          to_string(row.status || "unknown"),
          row.count || 0,
          &(&1 + (row.count || 0))
        )
      end)

    completed = Map.get(status_counts, "completed", 0)
    partial = Map.get(status_counts, "partial", 0)
    failed = Map.get(status_counts, "failed", 0)
    expired = Map.get(status_counts, "expired", 0)
    cancelled = Map.get(status_counts, "cancelled", 0)
    total = Enum.sum(Map.values(status_counts))
    terminal_attempts = completed + partial + failed + expired
    successful_terminal = completed + partial
    in_flight = max(total - terminal_attempts - cancelled, 0)

    latency_samples = Enum.reduce(rows, 0, &(&1.latency_samples + &2))

    average_latency_ms =
      if latency_samples > 0 do
        rows
        |> Enum.reduce(0.0, fn row, sum ->
          sum + numeric(row.average_latency_ms) * row.latency_samples
        end)
        |> Kernel./(latency_samples)
        |> Float.round(1)
      end

    %{
      requested: total,
      completed: completed,
      partial: partial,
      failed: failed,
      expired: expired,
      cancelled: cancelled,
      in_flight: in_flight,
      terminal_attempts: terminal_attempts,
      successful_terminal: successful_terminal,
      completion_percent:
        if(terminal_attempts > 0,
          do: Float.round(successful_terminal / terminal_attempts * 100, 1),
          else: nil
        ),
      failure_percent:
        if(terminal_attempts > 0,
          do: Float.round((failed + expired) / terminal_attempts * 100, 1),
          else: nil
        ),
      average_latency_ms: average_latency_ms,
      latency_samples: latency_samples,
      last_seen: rows |> Enum.map(& &1.last_seen) |> Enum.reject(&is_nil/1) |> max_datetime()
    }
  end

  defp evidence_session_empty_metrics do
    evidence_platform_metrics([])
    |> Map.put(:by_platform, %{})
    |> Map.put(:platforms_observed, 0)
    |> Map.delete(:last_seen)
  end

  defp evidence_session_status_counts do
    Map.new(
      ~w(pending_approval scheduled running completed partial cancelled failed expired),
      &{&1, 0}
    )
  end

  defp evidence_session_status(metrics) do
    cond do
      metrics.terminal_attempts == 0 ->
        :degraded

      metrics.terminal_attempts > 0 and metrics.successful_terminal == 0 and
          metrics.failed + metrics.expired == metrics.terminal_attempts ->
        :down

      metrics.failed > 0 or metrics.expired > 0 or metrics.partial > 0 ->
        :degraded

      true ->
        :healthy
    end
  end

  defp evidence_session_coverage_label(%{terminal_attempts: 0, in_flight: in_flight})
       when in_flight > 0,
       do: "#{in_flight} in flight; no terminal outcomes yet"

  defp evidence_session_coverage_label(metrics),
    do: "#{metrics.successful_terminal}/#{metrics.terminal_attempts} terminal outcomes completed"

  defp evidence_session_gaps(metrics) do
    []
    |> maybe_gap(metrics.failed > 0, "#{metrics.failed} session(s) failed.")
    |> maybe_gap(metrics.expired > 0, "#{metrics.expired} session(s) expired.")
    |> maybe_gap(
      metrics.partial > 0,
      "#{metrics.partial} session(s) completed with partial evidence."
    )
  end

  defp evidence_session_action(:healthy),
    do: "Continue monitoring completion latency and per-platform outcomes."

  defp evidence_session_action(:down),
    do:
      "Inspect broker capability, policy authorization, permissions, and artifact upload failures."

  defp evidence_session_action(_),
    do:
      "Review failed, expired, or partial sessions by platform before relying on screen evidence."

  defp normalize_platform(value) do
    value
    |> to_string()
    |> String.trim()
    |> String.downcase()
    |> case do
      "" -> "unknown"
      platform -> platform
    end
  end

  defp numeric(%Decimal{} = value), do: Decimal.to_float(value)
  defp numeric(value) when is_integer(value), do: value * 1.0
  defp numeric(value) when is_float(value), do: value
  defp numeric(_), do: 0.0

  defp endpoint_agents_item([], _now) do
    item(%{
      id: "endpoint_agents",
      name: "Endpoint agents",
      category: "endpoint",
      owner: "Endpoint",
      surface: "Agents",
      status: :not_configured,
      coverage: %{covered: 0, total: 0, percent: nil, label: "No enrolled agents"},
      gaps: ["No endpoint agents are enrolled for this tenant."],
      recommended_action: "Enroll at least one endpoint agent from Deploy Agent.",
      reason: "No tenant-scoped agent records were found."
    })
  end

  defp endpoint_agents_item(agents, now) do
    total = length(agents)
    online = Enum.count(agents, &(agent_status(&1) in ["online", "isolated"]))
    down = Enum.count(agents, &(agent_status(&1) == "offline"))
    last_seen = agents |> Enum.map(&agent_last_seen/1) |> Enum.reject(&is_nil/1) |> max_datetime()
    stale = Enum.count(agents, &stale_agent?(&1, now))

    status =
      cond do
        total == 0 -> :not_configured
        online == 0 -> :down
        down > 0 or stale > 0 -> :degraded
        true -> :healthy
      end

    gaps =
      []
      |> maybe_gap(down > 0, "#{down} agent(s) are offline.")
      |> maybe_gap(stale > 0, "#{stale} agent(s) have stale heartbeat data.")

    item(%{
      id: "endpoint_agents",
      name: "Endpoint agents",
      category: "endpoint",
      owner: "Endpoint",
      surface: "Agents",
      status: status,
      last_seen: format_datetime(last_seen),
      coverage: coverage(online, total, "#{online}/#{total} active"),
      gaps: gaps,
      recommended_action: endpoint_agents_action(status),
      reason: endpoint_agents_reason(status, online, total, down, stale),
      metrics: %{total: total, active: online, offline: down, stale: stale}
    })
  end

  defp collector_item(id, name, category, surface, telemetry, source_keys) do
    events = count_matching_events(telemetry, source_keys)
    last_seen = latest_matching_event(telemetry, source_keys)
    configured? = telemetry.total_events > 0

    status =
      cond do
        events > 0 -> :healthy
        configured? -> :degraded
        true -> :not_configured
      end

    item(%{
      id: id,
      name: name,
      category: category,
      owner: "Detection Engineering",
      surface: surface,
      status: status,
      last_seen: format_datetime(last_seen),
      coverage: coverage(if(events > 0, do: 1, else: 0), 1, "#{events} events in window"),
      gaps: collector_gaps(status, name),
      recommended_action: collector_action(status, name),
      reason: collector_reason(status, events, telemetry.total_events),
      metrics: %{events_in_window: events}
    })
  end

  defp mobile_command_link_item(nil) do
    unavailable_item(
      "mobile_command_link",
      "Mobile command link",
      "mobile",
      "Mobile",
      "Tenant context is unavailable.",
      "Open a tenant-scoped workspace before assessing mobile command health."
    )
  end

  defp mobile_command_link_item(organization_id) do
    case safe_call({:error, :unavailable}, fn ->
           if module_exports?(TamanduaServer.Mobile, :get_device_stats, 1) do
             {:ok, TamanduaServer.Mobile.get_device_stats(organization_id)}
           else
             {:error, :missing_api}
           end
         end) do
      {:ok, %{total: 0}} ->
        item(%{
          id: "mobile_command_link",
          name: "Mobile command link",
          category: "mobile",
          owner: "Mobile",
          surface: "Mobile",
          status: :not_configured,
          coverage: coverage(0, 0, "No enrolled mobile devices"),
          gaps: ["No mobile devices are enrolled."],
          recommended_action: "Enroll mobile devices or keep this surface disabled.",
          reason: "Mobile API is present, but no tenant devices were found."
        })

      {:ok, stats} when is_map(stats) ->
        total = stats[:total] || 0
        active = stats[:active] || 0
        stale = stats[:stale_24h] || 0
        compromised = stats[:compromised] || 0

        status =
          cond do
            total == 0 -> :not_configured
            active == 0 -> :down
            stale > 0 or compromised > 0 -> :degraded
            true -> :healthy
          end

        gaps =
          []
          |> maybe_gap(stale > 0, "#{stale} mobile device(s) are stale for 24h.")
          |> maybe_gap(compromised > 0, "#{compromised} mobile device(s) are compromised.")

        item(%{
          id: "mobile_command_link",
          name: "Mobile command link",
          category: "mobile",
          owner: "Mobile",
          surface: "Mobile",
          status: status,
          coverage: coverage(active, total, "#{active}/#{total} active"),
          gaps: gaps,
          recommended_action: mobile_action(status),
          reason: "Derived from tenant mobile device registry.",
          metrics: stats
        })

      {:error, reason} ->
        unavailable_item(
          "mobile_command_link",
          "Mobile command link",
          "mobile",
          "Mobile",
          "Mobile health API unavailable: #{inspect(reason)}.",
          "Wire a tenant-scoped mobile device stats API before treating this surface as healthy."
        )
    end
  end

  defp browser_native_bridge_item(telemetry) do
    events = count_matching_events(telemetry, ["browser", "extension", "native_bridge"])
    last_seen = latest_matching_event(telemetry, ["browser", "extension", "native_bridge"])

    status = if events > 0, do: :healthy, else: :degraded

    item(%{
      id: "browser_native_bridge",
      name: "Browser native bridge",
      category: "browser",
      owner: "Endpoint",
      surface: "Browser Guard",
      status: status,
      last_seen: format_datetime(last_seen),
      coverage: coverage(if(events > 0, do: 1, else: 0), 1, "#{events} events in window"),
      gaps: if(events > 0, do: [], else: ["No browser/native bridge telemetry in the window."]),
      recommended_action:
        if(events > 0,
          do: "Continue monitoring browser bridge telemetry freshness.",
          else: "Confirm extension deployment and native bridge heartbeat ingestion."
        ),
      reason: "Derived from tenant telemetry event types.",
      metrics: %{events_in_window: events}
    })
  end

  defp ai_gateway_item do
    case safe_call({:error, :unavailable}, fn ->
           if module_exports?(TamanduaServer.AISecurity.AIGateway, :health, 0) do
             {:ok, TamanduaServer.AISecurity.AIGateway.health()}
           else
             {:error, :missing_api}
           end
         end) do
      {:ok, health} when is_map(health) ->
        persistence = health[:persistence] || health["persistence"] || %{}

        last_seen =
          health[:last_seen] || health["last_seen"] ||
            map_get_any(persistence, [:last_seen, "last_seen"])

        last_error = map_get_any(persistence, [:last_error, "last_error"])
        status = if last_error, do: :degraded, else: :healthy

        item(%{
          id: "ai_gateway_enforcement",
          name: "AI gateway / enforcement",
          category: "ai",
          owner: "AI Security",
          surface: "Shadow AI",
          status: status,
          last_seen: format_datetime(last_seen),
          coverage: %{
            covered: nil,
            total: nil,
            percent: nil,
            label: "Gateway health API available"
          },
          gaps: if(last_error, do: ["AI gateway persistence reports: #{last_error}"], else: []),
          recommended_action:
            if(last_error,
              do: "Investigate AI gateway persistence/enforcement errors.",
              else: "Continue monitoring AI gateway counters."
            ),
          reason: "Derived from AISecurity.AIGateway.health/0.",
          metrics: health
        })

      {:error, reason} ->
        unavailable_item(
          "ai_gateway_enforcement",
          "AI gateway / enforcement",
          "ai",
          "Shadow AI",
          "AI gateway health API unavailable: #{inspect(reason)}.",
          "Expose gateway/enforcement health before this surface can be certified healthy."
        )
    end
  end

  defp integrations_soar_item do
    case safe_call({:error, :unavailable}, fn ->
           if module_exports?(TamanduaServer.Integrations.HealthMonitor, :get_summary, 0) do
             {:ok, TamanduaServer.Integrations.HealthMonitor.get_summary()}
           else
             {:error, :missing_api}
           end
         end) do
      {:ok, summary} when is_map(summary) ->
        total =
          map_get_any(summary, [:total, "total", :total_integrations, "total_integrations"]) || 0

        healthy = map_get_any(summary, [:healthy, "healthy"]) || 0
        degraded = map_get_any(summary, [:degraded, "degraded"]) || 0
        unhealthy = map_get_any(summary, [:unhealthy, "unhealthy", :down, "down"]) || 0

        status =
          cond do
            total == 0 -> :not_configured
            unhealthy > 0 -> :down
            degraded > 0 or healthy < total -> :degraded
            true -> :healthy
          end

        item(%{
          id: "integrations_soar",
          name: "Integrations / SOAR",
          category: "integrations",
          owner: "SecOps",
          surface: "Integrations",
          status: status,
          coverage: coverage(healthy, total, "#{healthy}/#{total} healthy"),
          gaps: integrations_gaps(status, degraded, unhealthy),
          recommended_action: integrations_action(status),
          reason: "Derived from Integrations.HealthMonitor.get_summary/0.",
          metrics: summary
        })

      {:error, reason} ->
        unavailable_item(
          "integrations_soar",
          "Integrations / SOAR",
          "integrations",
          "Integrations",
          "Integration health monitor unavailable: #{inspect(reason)}.",
          "Start or wire integration health monitoring before certifying integrations/SOAR."
        )
    end
  end

  defp threat_intel_feeds_item do
    case safe_call({:error, :unavailable}, fn ->
           if module_exports?(
                TamanduaServer.ThreatIntel.FeedHealthMonitor,
                :get_overall_health,
                0
              ) do
             {:ok, TamanduaServer.ThreatIntel.FeedHealthMonitor.get_overall_health()}
           else
             {:error, :missing_api}
           end
         end) do
      {:ok, summary} when is_map(summary) ->
        total = map_get_any(summary, [:total_feeds, "total_feeds", :total, "total"]) || 0
        healthy = map_get_any(summary, [:healthy, "healthy"]) || 0

        status =
          normalize_status(
            map_get_any(summary, [:overall_status, "overall_status", :status, "status"])
          )

        item(%{
          id: "threat_intel_feeds",
          name: "Threat intel feeds",
          category: "intelligence",
          owner: "Threat Intel",
          surface: "Threat Intel",
          status: if(total == 0, do: :not_configured, else: status),
          coverage: coverage(healthy, total, "#{healthy}/#{total} healthy"),
          gaps: if(status == :healthy, do: [], else: ["Threat intel feed health is #{status}."]),
          recommended_action:
            if(status == :healthy,
              do: "Continue monitoring feed freshness.",
              else: "Review feed credentials, freshness, and error alerts."
            ),
          reason: "Derived from ThreatIntel.FeedHealthMonitor.get_overall_health/0.",
          metrics: summary
        })

      {:error, reason} ->
        unavailable_item(
          "threat_intel_feeds",
          "Threat intel feeds",
          "intelligence",
          "Threat Intel",
          "Threat intel feed monitor unavailable: #{inspect(reason)}.",
          "Start or wire feed health monitoring before certifying threat intel feeds."
        )
    end
  end

  defp parser_ingest_item(%{total_events: 0}) do
    item(%{
      id: "parser_ingest",
      name: "Parser / ingest",
      category: "ingest",
      owner: "Data Platform",
      surface: "Events",
      status: :degraded,
      coverage: coverage(0, 1, "No events in window"),
      gaps: ["No tenant events were ingested in the window."],
      recommended_action: "Verify parser, transport, and event persistence pipelines.",
      reason: "Telemetry query returned zero events for the tenant/window.",
      metrics: %{events_in_window: 0, event_types: 0}
    })
  end

  defp parser_ingest_item(telemetry) do
    item(%{
      id: "parser_ingest",
      name: "Parser / ingest",
      category: "ingest",
      owner: "Data Platform",
      surface: "Events",
      status: :healthy,
      last_seen: format_datetime(telemetry.last_seen),
      coverage: coverage(1, 1, "#{telemetry.total_events} events in window"),
      gaps: [],
      recommended_action: "Continue monitoring ingest latency and parser error counters.",
      reason: "Tenant telemetry is being persisted in the window.",
      metrics: %{
        events_in_window: telemetry.total_events,
        event_types: map_size(telemetry.by_type)
      }
    })
  end

  defp platform_visibility_summary([], now) do
    %{
      generated_at: format_datetime(now),
      total: 0,
      total_agents: 0,
      status_counts: %{
        active: 0,
        degraded: 0,
        unavailable: 0,
        not_reported: 0
      },
      records: [],
      reasons: ["No endpoint agents are enrolled for this tenant."],
      evidence_sources: [],
      last_seen: nil
    }
  end

  defp platform_visibility_summary(agents, now) do
    records = Enum.map(agents, &platform_visibility_record(&1, now))

    status_counts =
      Enum.reduce(records, %{active: 0, degraded: 0, unavailable: 0, not_reported: 0}, fn record,
                                                                                          counts ->
        status = String.to_atom(record.status)
        Map.update!(counts, status, &(&1 + 1))
      end)

    %{
      generated_at: format_datetime(now),
      total: length(records),
      total_agents: length(records),
      status_counts: status_counts,
      records: records,
      agents: records,
      reasons:
        records
        |> Enum.flat_map(& &1.reasons)
        |> Enum.uniq()
        |> Enum.take(10),
      evidence_sources:
        records
        |> Enum.map(& &1.evidence_source)
        |> Enum.reject(&is_nil/1)
        |> Enum.uniq()
        |> Enum.sort(),
      last_seen:
        agents
        |> Enum.map(&agent_last_seen/1)
        |> Enum.reject(&is_nil/1)
        |> max_datetime()
        |> format_datetime()
    }
  end

  defp platform_visibility_record(agent, now) do
    agent_id = agent |> map_get_any([:id, "id", :agent_id, "agent_id"]) |> to_string()
    health = registry_health(agent_id)
    agent_health_visibility = map_get_any(health, [:platform_visibility, "platform_visibility"])

    health_status =
      safe_call(%{}, fn -> Registry.get_agent_health_status_detail(agent_id) || %{} end)

    capabilities =
      PlatformCapabilities.for_agent(agent,
        status: agent_status(agent),
        health:
          Map.merge(health_status, %{
            driver_status: map_get_any(health, [:driver_status, "driver_status"]),
            platform_status: map_get_any(health, [:platform_status, "platform_status"]) || []
          }),
        config: map_get_any(agent, [:config, "config"]) || %{}
      )

    visibility =
      PlatformVisibility.summarize(agent,
        capabilities: capabilities,
        agent_health_visibility: agent_health_visibility,
        last_heartbeat_at: agent_last_seen(agent),
        checked_at: now
      )

    reported = is_map(agent_health_visibility)
    status = if reported, do: visibility.status, else: "not_reported"

    %{
      agent_id: agent_id,
      agentId: agent_id,
      hostname: map_get_any(agent, [:hostname, "hostname", :name, "name"]),
      platform: visibility.platform,
      status: status,
      state: status,
      reported: reported,
      source: visibility.source,
      evidence_source: platform_visibility_evidence_source(visibility, agent_health_visibility),
      evidenceSource: platform_visibility_evidence_source(visibility, agent_health_visibility),
      reasons: platform_visibility_reasons(visibility, reported),
      checked_at: visibility.checked_at,
      checkedAt: visibility.checked_at,
      last_seen: format_datetime(agent_last_seen(agent)),
      lastSeen: format_datetime(agent_last_seen(agent)),
      evidence: visibility.evidence
    }
  end

  defp registry_health(nil), do: %{}
  defp registry_health(""), do: %{}

  defp registry_health(agent_id) do
    case safe_call({:error, :unavailable}, fn -> Registry.get_health(agent_id) end) do
      {:ok, health} -> health
      _ -> %{}
    end
  end

  defp platform_visibility_evidence_source(visibility, agent_health_visibility) do
    map_get_any(agent_health_visibility, [
      :evidence_source,
      "evidence_source",
      :evidenceSource,
      "evidenceSource"
    ]) ||
      visibility.source
  end

  defp platform_visibility_reasons(visibility, true), do: visibility.reasons

  defp platform_visibility_reasons(_visibility, false) do
    ["agent_health_platform_visibility_not_reported"]
  end

  defp telemetry_summary(nil, _window_hours, _now),
    do: %{total_events: 0, by_type: %{}, last_seen: nil}

  defp telemetry_summary(organization_id, window_hours, now) do
    cutoff = DateTime.add(now, -window_hours * 3600, :second)
    latest_allowed = DateTime.add(now, @max_future_skew_seconds, :second)

    rows =
      safe_call([], fn ->
        from(e in Event,
          where:
            e.organization_id == ^organization_id and e.timestamp >= ^cutoff and
              e.timestamp <= ^latest_allowed,
          group_by: e.event_type,
          select: %{event_type: e.event_type, count: count(e.id), last_seen: max(e.timestamp)}
        )
        |> Repo.all()
      end)

    by_type =
      Map.new(rows, fn row ->
        {String.downcase(to_string(row.event_type || "unknown")),
         %{count: row.count || 0, last_seen: row.last_seen}}
      end)

    %{
      total_events: Enum.reduce(by_type, 0, fn {_type, data}, acc -> acc + data.count end),
      by_type: by_type,
      last_seen: rows |> Enum.map(& &1.last_seen) |> Enum.reject(&is_nil/1) |> max_datetime()
    }
  end

  defp count_matching_events(%{by_type: by_type}, keys) do
    Enum.reduce(by_type, 0, fn {event_type, data}, acc ->
      if Enum.any?(keys, &String.contains?(event_type, &1)), do: acc + data.count, else: acc
    end)
  end

  defp latest_matching_event(%{by_type: by_type}, keys) do
    by_type
    |> Enum.filter(fn {event_type, _data} ->
      Enum.any?(keys, &String.contains?(event_type, &1))
    end)
    |> Enum.map(fn {_event_type, data} -> data.last_seen end)
    |> Enum.reject(&is_nil/1)
    |> max_datetime()
  end

  defp item(attrs) do
    attrs
    |> Map.put_new(:last_seen, nil)
    |> Map.put_new(:coverage, %{covered: nil, total: nil, percent: nil, label: "Unknown"})
    |> Map.put_new(:gaps, [])
    |> Map.put_new(:metrics, %{})
    |> Map.update!(:status, &status_string/1)
  end

  defp unavailable_item(id, name, category, surface, reason, action) do
    item(%{
      id: id,
      name: name,
      category: category,
      owner: owner_for_category(category),
      surface: surface,
      status: :degraded,
      coverage: %{covered: nil, total: nil, percent: nil, label: "Unknown"},
      gaps: [reason],
      recommended_action: action,
      reason: reason
    })
  end

  defp coverage(_covered, 0, label), do: %{covered: 0, total: 0, percent: nil, label: label}

  defp coverage(covered, total, label) do
    %{covered: covered, total: total, percent: round(covered / total * 100), label: label}
  end

  defp aggregate_status(items) do
    statuses = Enum.map(items, & &1.status)

    cond do
      "down" in statuses -> "down"
      "degraded" in statuses -> "degraded"
      Enum.all?(statuses, &(&1 == "not_configured")) -> "not_configured"
      true -> "healthy"
    end
  end

  defp status_counts(items) do
    base = %{"healthy" => 0, "degraded" => 0, "down" => 0, "not_configured" => 0}
    Enum.reduce(items, base, fn item, acc -> Map.update!(acc, item.status, &(&1 + 1)) end)
  end

  defp normalize_status(nil), do: :degraded
  defp normalize_status(:failed), do: :down
  defp normalize_status(:critical), do: :down
  defp normalize_status(:unhealthy), do: :down

  defp normalize_status(status) when status in [:healthy, :degraded, :down, :not_configured],
    do: status

  defp normalize_status(status) when is_binary(status) do
    case String.downcase(status) do
      "healthy" -> :healthy
      "ok" -> :healthy
      "degraded" -> :degraded
      "warning" -> :degraded
      "stale" -> :degraded
      "down" -> :down
      "failed" -> :down
      "critical" -> :down
      "unhealthy" -> :down
      "not_configured" -> :not_configured
      "not configured" -> :not_configured
      "disabled" -> :not_configured
      _ -> :degraded
    end
  end

  defp normalize_status(_), do: :degraded

  defp status_string(status), do: status |> normalize_status() |> Atom.to_string()

  defp module_exports?(module, function, arity) do
    Code.ensure_loaded?(module) and function_exported?(module, function, arity)
  end

  defp safe_call(default, fun) do
    fun.()
  rescue
    e ->
      Logger.warning("Health Hub signal failed: #{Exception.message(e)}")
      default
  catch
    :exit, reason ->
      Logger.warning("Health Hub signal exited: #{inspect(reason)}")
      default
  end

  defp agent_status(agent),
    do: agent |> map_get_any([:status, "status"]) |> to_string() |> String.downcase()

  defp agent_last_seen(agent),
    do: map_get_any(agent, [:last_seen_at, "last_seen_at", :updated_at, "updated_at"])

  defp stale_agent?(agent, now) do
    case agent_last_seen(agent) do
      %DateTime{} = last_seen ->
        DateTime.diff(now, last_seen, :second) > 15 * 60

      %NaiveDateTime{} = last_seen ->
        NaiveDateTime.diff(DateTime.to_naive(now), last_seen, :second) > 15 * 60

      _ ->
        agent_status(agent) == "online"
    end
  end

  defp max_datetime([]), do: nil
  defp max_datetime(values), do: Enum.max_by(values, &datetime_sort_value/1)

  defp datetime_sort_value(%DateTime{} = dt), do: DateTime.to_unix(dt, :microsecond)

  defp datetime_sort_value(%NaiveDateTime{} = dt),
    do: dt |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_unix(:microsecond)

  defp datetime_sort_value(_), do: 0

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp format_datetime(%NaiveDateTime{} = dt) do
    dt
    |> DateTime.from_naive!("Etc/UTC")
    |> DateTime.to_iso8601()
  end

  defp format_datetime(value) when is_binary(value), do: value
  defp format_datetime(_), do: nil

  defp map_get_any(nil, _keys), do: nil

  defp map_get_any(map, keys) when is_map(map) do
    Enum.find_value(keys, fn key -> Map.get(map, key) end)
  end

  defp map_get_any(_value, _keys), do: nil

  defp maybe_gap(gaps, true, gap), do: [gap | gaps]
  defp maybe_gap(gaps, false, _gap), do: gaps

  defp endpoint_agents_action(:healthy),
    do: "Continue monitoring agent freshness and collector coverage."

  defp endpoint_agents_action(:down),
    do: "Restore agent connectivity before relying on endpoint controls."

  defp endpoint_agents_action(_),
    do: "Review offline/stale agents and redeploy or restart affected endpoints."

  defp endpoint_agents_reason(:healthy, online, total, _down, _stale),
    do: "#{online}/#{total} endpoint agents are active."

  defp endpoint_agents_reason(:down, _online, total, _down, _stale),
    do: "0/#{total} endpoint agents are active."

  defp endpoint_agents_reason(_, online, total, down, stale),
    do: "#{online}/#{total} active; #{down} offline; #{stale} stale."

  defp collector_gaps(:healthy, _name), do: []

  defp collector_gaps(_status, name),
    do: ["#{name} has no matching telemetry in the selected window."]

  defp collector_action(:healthy, name),
    do: "Continue monitoring #{name} event volume and freshness."

  defp collector_action(_status, name),
    do: "Verify #{name} configuration and parser mappings on active agents."

  defp collector_reason(:healthy, events, _total),
    do: "#{events} matching events were ingested in the window."

  defp collector_reason(:degraded, _events, total),
    do: "Tenant has #{total} events, but none matched this collector."

  defp collector_reason(:not_configured, _events, _total),
    do: "No tenant telemetry exists in the window."

  defp mobile_action(:healthy), do: "Continue monitoring mobile command freshness."

  defp mobile_action(:down),
    do: "Restore mobile command connectivity before using remote actions."

  defp mobile_action(_), do: "Review stale, compromised, and unenrolled mobile devices."

  defp integrations_gaps(:healthy, _degraded, _unhealthy), do: []

  defp integrations_gaps(_status, degraded, unhealthy),
    do: ["#{degraded} degraded and #{unhealthy} unhealthy integrations."]

  defp integrations_action(:healthy), do: "Continue synthetic checks for critical destinations."

  defp integrations_action(:not_configured),
    do: "Configure SIEM/SOAR/ticketing destinations or keep the surface disabled."

  defp integrations_action(_),
    do: "Review integration health checks and failing SOAR destinations."

  defp owner_for_category("mobile"), do: "Mobile"
  defp owner_for_category("ai"), do: "AI Security"
  defp owner_for_category("integrations"), do: "SecOps"
  defp owner_for_category("intelligence"), do: "Threat Intel"
  defp owner_for_category(_), do: "Platform"
end
