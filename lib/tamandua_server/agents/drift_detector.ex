defmodule TamanduaServer.Agents.DriftDetector do
  @moduledoc """
  Detects configuration drift in agents by comparing current configuration
  against established baselines.

  Supports:
  - On-demand drift detection
  - Scheduled periodic scans
  - Scan on agent reconnect
  - Drift categorization and severity assignment
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.{
    Agent,
    ConfigurationBaseline,
    ConfigurationDrift,
    ConfigurationScan,
    ComplianceStatus
  }

  @doc """
  Scans a single agent for configuration drift.

  Returns `{:ok, scan_result}` with drift details or `{:error, reason}`.
  """
  def scan_agent(agent_id, opts \\ []) do
    scan_type = Keyword.get(opts, :scan_type, "on_demand")
    triggered_by_id = Keyword.get(opts, :triggered_by_id)

    start_time = System.monotonic_time(:millisecond)

    with {:ok, agent} <- get_agent(agent_id),
         {:ok, baseline} <- get_active_baseline(agent_id),
         {:ok, current_config} <- get_current_config(agent) do

      drifts = detect_drifts(baseline, current_config, agent)
      duration_ms = System.monotonic_time(:millisecond) - start_time

      # Group drifts by severity
      severity_counts = count_by_severity(drifts)

      # Create scan record
      scan_attrs = %{
        agent_id: agent_id,
        organization_id: agent.organization_id,
        scan_type: scan_type,
        scanned_at: DateTime.utc_now(),
        duration_ms: duration_ms,
        drifts_detected: length(drifts),
        drifts_critical: severity_counts[:critical] || 0,
        drifts_high: severity_counts[:high] || 0,
        drifts_medium: severity_counts[:medium] || 0,
        drifts_low: severity_counts[:low] || 0,
        scan_result: "success",
        triggered_by_id: triggered_by_id
      }

      {:ok, scan} = %ConfigurationScan{}
      |> ConfigurationScan.changeset(scan_attrs)
      |> Repo.insert()

      # Persist detected drifts
      persist_drifts(drifts, baseline.id)

      # Update compliance status
      update_compliance_status(agent, drifts)

      # Broadcast drift detection event
      broadcast_drift_event(agent, drifts)

      {:ok, %{
        scan: scan,
        drifts: drifts,
        severity_counts: severity_counts,
        compliance_score: calculate_compliance_score(severity_counts)
      }}
    else
      {:error, :no_baseline} ->
        Logger.warning("[DriftDetector] No baseline found for agent #{agent_id}")
        {:error, :no_baseline}

      {:error, reason} = error ->
        Logger.error("[DriftDetector] Failed to scan agent #{agent_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Scans all agents in an organization for configuration drift.
  """
  def scan_organization(organization_id, opts \\ []) do
    agents = list_agents_for_organization(organization_id)
    scan_type = Keyword.get(opts, :scan_type, "scheduled")
    triggered_by_id = Keyword.get(opts, :triggered_by_id)

    results = Enum.map(agents, fn agent ->
      case scan_agent(agent.id, scan_type: scan_type, triggered_by_id: triggered_by_id) do
        {:ok, result} -> {:ok, agent.id, result}
        {:error, reason} -> {:error, agent.id, reason}
      end
    end)

    successes = Enum.filter(results, fn {status, _, _} -> status == :ok end)
    failures = Enum.filter(results, fn {status, _, _} -> status == :error end)

    {:ok, %{
      total: length(agents),
      scanned: length(successes),
      failed: length(failures),
      results: results
    }}
  end

  @doc """
  Detects drift between baseline and current configuration.
  """
  def detect_drifts(baseline, current_config, agent) do
    []
    |> detect_collector_drifts(baseline, current_config, agent)
    |> detect_response_drifts(baseline, current_config, agent)
    |> detect_network_drifts(baseline, current_config, agent)
    |> detect_path_drifts(baseline, current_config, agent)
    |> detect_resource_drifts(baseline, current_config, agent)
    |> detect_feature_drifts(baseline, current_config, agent)
    |> detect_rule_version_drifts(baseline, current_config, agent)
  end

  @doc """
  Gets drifts for a specific agent.
  """
  def get_agent_drifts(agent_id, opts \\ []) do
    status_filter = Keyword.get(opts, :status)
    severity_filter = Keyword.get(opts, :severity)
    limit = Keyword.get(opts, :limit, 100)

    query = from d in ConfigurationDrift,
      where: d.agent_id == ^agent_id,
      order_by: [desc: d.detected_at],
      limit: ^limit

    query =
      if status_filter do
        where(query, [d], d.status == ^status_filter)
      else
        query
      end

    query =
      if severity_filter do
        where(query, [d], d.severity == ^severity_filter)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Gets compliance summary for an organization.
  """
  def get_compliance_summary(organization_id) do
    from(cs in ComplianceStatus,
      where: cs.organization_id == ^organization_id,
      select: %{
        total_agents: count(cs.id),
        compliant: sum(fragment("CASE WHEN ? THEN 1 ELSE 0 END", cs.is_compliant)),
        non_compliant: sum(fragment("CASE WHEN NOT ? THEN 1 ELSE 0 END", cs.is_compliant)),
        avg_compliance_score: avg(cs.compliance_score),
        total_critical_drifts: sum(cs.critical_drifts),
        total_high_drifts: sum(cs.high_drifts),
        total_medium_drifts: sum(cs.medium_drifts),
        total_low_drifts: sum(cs.low_drifts)
      }
    )
    |> Repo.one()
  end

  # Private functions

  defp get_agent(agent_id) do
    case Repo.get(Agent, agent_id) do
      nil -> {:error, :not_found}
      agent -> {:ok, agent}
    end
  end

  defp get_active_baseline(agent_id) do
    case Repo.one(
      from b in ConfigurationBaseline,
        where: b.agent_id == ^agent_id and b.is_active == true,
        order_by: [desc: b.baseline_version],
        limit: 1
    ) do
      nil -> {:error, :no_baseline}
      baseline -> {:ok, baseline}
    end
  end

  defp get_current_config(agent) do
    # Get current configuration from agent
    # In production, this would query the agent or use cached config
    {:ok, agent.config || %{}}
  end

  defp list_agents_for_organization(organization_id) do
    Repo.all(
      from a in Agent,
        where: a.organization_id == ^organization_id,
        where: a.status in ["online", "isolated"]
    )
  end

  # Drift detection functions

  defp detect_collector_drifts(drifts, baseline, current, agent) do
    baseline_collectors = baseline.collector_settings || %{}
    current_collectors = extract_collectors(current)

    Enum.reduce(baseline_collectors, drifts, fn {collector, baseline_config}, acc ->
      current_config = Map.get(current_collectors, to_string(collector), %{})

      cond do
        baseline_config["enabled"] == true and current_config["enabled"] == false ->
          [create_drift(agent, "collector_disabled", "collectors", collector, baseline_config, current_config, "high") | acc]

        baseline_config["enabled"] == false and current_config["enabled"] == true ->
          [create_drift(agent, "collector_enabled", "collectors", collector, baseline_config, current_config, "medium") | acc]

        collector_settings_changed?(baseline_config, current_config) ->
          [create_drift(agent, "collector_settings_changed", "collectors", collector, baseline_config, current_config, "medium") | acc]

        true ->
          acc
      end
    end)
  end

  defp detect_response_drifts(drifts, baseline, current, agent) do
    baseline_response = baseline.response_permissions || %{}
    current_response = extract_response_permissions(current)

    acc = drifts

    # Check allowed actions
    acc =
      if baseline_response["allowed_actions"] != current_response["allowed_actions"] do
        [create_drift(agent, "response_permission_changed", "response", "allowed_actions",
          baseline_response["allowed_actions"], current_response["allowed_actions"], "high") | acc]
      else
        acc
      end

    # Check auto-response
    acc =
      if baseline_response["auto_response_enabled"] != current_response["auto_response_enabled"] do
        severity = if current_response["auto_response_enabled"], do: "critical", else: "high"
        [create_drift(agent, "response_permission_changed", "response", "auto_response",
          baseline_response["auto_response_enabled"], current_response["auto_response_enabled"], severity) | acc]
      else
        acc
      end

    acc
  end

  defp detect_network_drifts(drifts, baseline, current, agent) do
    baseline_network = baseline.network_settings || %{}
    current_network = extract_network_settings(current)

    Enum.reduce(baseline_network, drifts, fn {key, baseline_value}, acc ->
      current_value = Map.get(current_network, to_string(key))

      if baseline_value != current_value and not is_nil(baseline_value) do
        severity = if key in ["server_url", "tls_verify"], do: "critical", else: "medium"
        [create_drift(agent, "network_config_changed", "network", key, baseline_value, current_value, severity) | acc]
      else
        acc
      end
    end)
  end

  defp detect_path_drifts(drifts, baseline, current, agent) do
    baseline_paths = baseline.file_paths || %{}
    current_paths = extract_file_paths(current)

    Enum.reduce(baseline_paths, drifts, fn {key, baseline_value}, acc ->
      current_value = Map.get(current_paths, to_string(key))

      if baseline_value != current_value and not is_nil(baseline_value) do
        severity = if key in ["config_dir", "yara_rules_dir", "sigma_rules_dir"], do: "high", else: "medium"
        [create_drift(agent, "file_path_changed", "paths", key, baseline_value, current_value, severity) | acc]
      else
        acc
      end
    end)
  end

  defp detect_resource_drifts(drifts, baseline, current, agent) do
    baseline_limits = baseline.resource_limits || %{}
    current_limits = extract_resource_limits(current)

    Enum.reduce(baseline_limits, drifts, fn {key, baseline_value}, acc ->
      current_value = Map.get(current_limits, to_string(key))

      if baseline_value != current_value and not is_nil(baseline_value) do
        # Lowering limits is high severity, raising is medium
        severity =
          if is_number(baseline_value) and is_number(current_value) and current_value < baseline_value do
            "high"
          else
            "medium"
          end

        [create_drift(agent, "resource_limit_changed", "resources", key, baseline_value, current_value, severity) | acc]
      else
        acc
      end
    end)
  end

  defp detect_feature_drifts(drifts, baseline, current, agent) do
    baseline_features = baseline.enabled_features || %{}
    current_features = extract_enabled_features(current)

    Enum.reduce(baseline_features, drifts, fn {key, baseline_value}, acc ->
      current_value = Map.get(current_features, to_string(key))

      if baseline_value != current_value do
        # Disabling security features is critical
        severity =
          cond do
            baseline_value == true and current_value == false and key in ["yara_enabled", "sigma_enabled", "ml_enabled"] ->
              "critical"

            baseline_value == true and current_value == false ->
              "high"

            true ->
              "medium"
          end

        [create_drift(agent, "feature_toggled", "features", key, baseline_value, current_value, severity) | acc]
      else
        acc
      end
    end)
  end

  defp detect_rule_version_drifts(drifts, baseline, current, agent) do
    baseline_versions = baseline.rule_versions || %{}
    current_versions = extract_rule_versions(current)

    Enum.reduce(baseline_versions, drifts, fn {key, baseline_value}, acc ->
      current_value = Map.get(current_versions, to_string(key))

      if not is_nil(baseline_value) and baseline_value != current_value do
        [create_drift(agent, "rules_outdated", "rules", key, baseline_value, current_value, "medium") | acc]
      else
        acc
      end
    end)
  end

  # Helper functions

  defp collector_settings_changed?(baseline, current) do
    baseline["interval_ms"] != current["interval_ms"] or
      baseline["buffer_size"] != current["buffer_size"]
  end

  defp create_drift(agent, drift_type, category, field, expected, actual, severity) do
    %{
      agent_id: agent.id,
      organization_id: agent.organization_id,
      drift_type: drift_type,
      category: category,
      severity: severity,
      status: "detected",
      field_path: to_string(field),
      expected_value: %{"value" => expected},
      actual_value: %{"value" => actual},
      drift_details: %{
        "field" => field,
        "expected" => expected,
        "actual" => actual,
        "changed_at" => DateTime.utc_now() |> DateTime.to_iso8601()
      },
      detected_at: DateTime.utc_now()
    }
  end

  defp persist_drifts(drifts, baseline_id) do
    Enum.each(drifts, fn drift_data ->
      drift_data = Map.put(drift_data, :baseline_id, baseline_id)

      %ConfigurationDrift{}
      |> ConfigurationDrift.changeset(drift_data)
      |> Repo.insert()
    end)
  end

  defp update_compliance_status(agent, drifts) do
    severity_counts = count_by_severity(drifts)
    compliance_score = calculate_compliance_score(severity_counts)
    is_compliant = compliance_score >= 90.0

    now = DateTime.utc_now()

    attrs = %{
      agent_id: agent.id,
      organization_id: agent.organization_id,
      is_compliant: is_compliant,
      drift_count: length(drifts),
      last_scan_at: now,
      compliance_score: compliance_score,
      critical_drifts: severity_counts[:critical] || 0,
      high_drifts: severity_counts[:high] || 0,
      medium_drifts: severity_counts[:medium] || 0,
      low_drifts: severity_counts[:low] || 0
    }

    attrs =
      if is_compliant do
        Map.put(attrs, :last_compliant_at, now)
      else
        attrs
      end

    # Upsert compliance status
    case Repo.get_by(ComplianceStatus, agent_id: agent.id) do
      nil ->
        %ComplianceStatus{}
        |> ComplianceStatus.changeset(attrs)
        |> Repo.insert()

      status ->
        # Preserve non_compliant_since if transitioning to non-compliant
        attrs =
          if not is_compliant and status.is_compliant do
            Map.put(attrs, :non_compliant_since, now)
          else
            attrs
          end

        status
        |> ComplianceStatus.changeset(attrs)
        |> Repo.update()
    end
  end

  defp count_by_severity(drifts) do
    Enum.reduce(drifts, %{critical: 0, high: 0, medium: 0, low: 0}, fn drift, acc ->
      severity = String.to_existing_atom(drift.severity)
      Map.update(acc, severity, 1, &(&1 + 1))
    end)
  end

  defp calculate_compliance_score(severity_counts) do
    ComplianceStatus.calculate_score(
      severity_counts[:critical] || 0,
      severity_counts[:high] || 0,
      severity_counts[:medium] || 0,
      severity_counts[:low] || 0
    )
  end

  defp broadcast_drift_event(agent, drifts) do
    if length(drifts) > 0 do
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "agents:drift",
        {:drift_detected, %{
          agent_id: agent.id,
          hostname: agent.hostname,
          organization_id: agent.organization_id,
          drift_count: length(drifts),
          critical_count: Enum.count(drifts, &(&1.severity == "critical")),
          timestamp: DateTime.utc_now()
        }}
      )
    end
  end

  # Configuration extraction helpers (match ConfigurationBaseline)

  defp extract_collectors(config) do
    get_in(config, ["collectors"]) || %{}
  end

  defp extract_response_permissions(config) do
    %{
      "allowed_actions" => get_in(config, ["response", "allowed_actions"]) || [],
      "auto_response_enabled" => get_in(config, ["response", "auto_response_enabled"]) || false,
      "max_actions_per_hour" => get_in(config, ["response", "max_actions_per_hour"]) || 10
    }
  end

  defp extract_network_settings(config) do
    %{
      "server_url" => get_in(config, ["network", "server_url"]),
      "proxy_enabled" => get_in(config, ["network", "proxy_enabled"]) || false,
      "proxy_url" => get_in(config, ["network", "proxy_url"]),
      "tls_verify" => get_in(config, ["network", "tls_verify"]) || true
    }
  end

  defp extract_file_paths(config) do
    %{
      "quarantine_dir" => get_in(config, ["paths", "quarantine_dir"]),
      "log_dir" => get_in(config, ["paths", "log_dir"]),
      "config_dir" => get_in(config, ["paths", "config_dir"])
    }
  end

  defp extract_resource_limits(config) do
    %{
      "max_cpu_percent" => get_in(config, ["resource_limits", "max_cpu_percent"]) || 20,
      "max_memory_mb" => get_in(config, ["resource_limits", "max_memory_mb"]) || 512,
      "max_disk_mb" => get_in(config, ["resource_limits", "max_disk_mb"]) || 1024
    }
  end

  defp extract_enabled_features(config) do
    %{
      "yara_enabled" => get_in(config, ["detection", "yara_enabled"]) || false,
      "sigma_enabled" => get_in(config, ["detection", "sigma_enabled"]) || false,
      "ml_enabled" => get_in(config, ["detection", "ml_enabled"]) || false
    }
  end

  defp extract_rule_versions(config) do
    %{
      "yara_version" => get_in(config, ["rules", "yara_version"]),
      "sigma_version" => get_in(config, ["rules", "sigma_version"])
    }
  end
end
