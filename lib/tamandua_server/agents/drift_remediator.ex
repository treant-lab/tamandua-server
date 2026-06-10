defmodule TamanduaServer.Agents.DriftRemediator do
  @moduledoc """
  Handles automatic and manual remediation of configuration drift.

  Supports:
  - Revert to baseline configuration
  - Push corrected configuration to agent
  - Quarantine drifted agents
  - Manual approval workflows
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.{
    Agent,
    ConfigurationBaseline,
    ConfigurationDrift,
    ComplianceStatus
  }

  @doc """
  Remediates a specific drift by reverting to baseline configuration.

  Options:
  - `:require_approval` - Require manual approval before remediation (default: true)
  - `:approved_by_id` - User ID who approved the remediation
  - `:notify` - Send notification on completion (default: true)
  """
  def remediate_drift(drift_id, opts \\ []) do
    require_approval = Keyword.get(opts, :require_approval, true)
    approved_by_id = Keyword.get(opts, :approved_by_id)

    with {:ok, drift} <- get_drift(drift_id),
         :ok <- check_approval(require_approval, approved_by_id),
         {:ok, agent} <- get_agent(drift.agent_id),
         {:ok, baseline} <- get_baseline(drift.baseline_id) do

      # Mark remediation as started
      update_drift(drift, %{
        remediation_status: "in_progress",
        remediation_attempted_at: DateTime.utc_now()
      })

      # Perform remediation based on drift type
      result = case drift.category do
        "collectors" -> remediate_collector_drift(agent, baseline, drift)
        "response" -> remediate_response_drift(agent, baseline, drift)
        "network" -> remediate_network_drift(agent, baseline, drift)
        "paths" -> remediate_path_drift(agent, baseline, drift)
        "resources" -> remediate_resource_drift(agent, baseline, drift)
        "features" -> remediate_feature_drift(agent, baseline, drift)
        "rules" -> remediate_rule_drift(agent, baseline, drift)
        _ -> {:error, :unsupported_category}
      end

      case result do
        {:ok, _} ->
          update_drift(drift, %{
            remediation_status: "completed",
            remediation_completed_at: DateTime.utc_now(),
            status: "resolved",
            resolved_at: DateTime.utc_now()
          })

          broadcast_remediation_event(agent, drift, "success")
          {:ok, :remediated}

        {:error, reason} ->
          update_drift(drift, %{
            remediation_status: "failed",
            remediation_error: inspect(reason)
          })

          broadcast_remediation_event(agent, drift, "failed")
          {:error, reason}
      end
    end
  end

  @doc """
  Remediates all drifts for an agent by pushing full baseline configuration.
  """
  def remediate_agent(agent_id, opts \\ []) do
    approved_by_id = Keyword.get(opts, :approved_by_id)

    with {:ok, agent} <- get_agent(agent_id),
         {:ok, baseline} <- get_active_baseline(agent_id),
         {:ok, drifts} <- get_unresolved_drifts(agent_id) do

      Logger.info("[DriftRemediator] Remediating #{length(drifts)} drifts for agent #{agent_id}")

      # Push full baseline configuration to agent
      case push_baseline_config(agent, baseline) do
        {:ok, _} ->
          # Mark all drifts as resolved
          Enum.each(drifts, fn drift ->
            update_drift(drift, %{
              remediation_status: "completed",
              remediation_completed_at: DateTime.utc_now(),
              status: "resolved",
              resolved_at: DateTime.utc_now()
            })
          end)

          # Update compliance status
          update_agent_compliance(agent_id, true)

          broadcast_agent_remediation_event(agent, length(drifts))
          {:ok, %{drifts_remediated: length(drifts)}}

        {:error, reason} ->
          Logger.error("[DriftRemediator] Failed to remediate agent #{agent_id}: #{inspect(reason)}")
          {:error, reason}
      end
    end
  end

  @doc """
  Quarantines an agent with critical configuration drift.
  """
  def quarantine_drifted_agent(agent_id, reason, opts \\ []) do
    quarantined_by_id = Keyword.get(opts, :quarantined_by_id)

    with {:ok, agent} <- get_agent(agent_id) do
      # Send quarantine command to agent
      command = %{
        "type" => "quarantine",
        "reason" => reason,
        "quarantined_by" => quarantined_by_id,
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      case send_command_to_agent(agent, command) do
        {:ok, _} ->
          # Update agent status
          Repo.update!(Agent.changeset(agent, %{status: "isolated"}))

          # Create audit log
          log_quarantine(agent, reason, quarantined_by_id)

          {:ok, :quarantined}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc """
  Schedules a drift scan for all agents.
  """
  def schedule_drift_scans do
    # This would be called by a scheduled job (Oban, Quantum, etc.)
    organizations = list_all_organizations()

    Enum.each(organizations, fn org ->
      Task.start(fn ->
        TamanduaServer.Agents.DriftDetector.scan_organization(org.id, scan_type: "scheduled")
      end)
    end)

    :ok
  end

  @doc """
  Gets remediation recommendations for a drift.
  """
  def get_remediation_recommendation(drift_id) do
    with {:ok, drift} <- get_drift(drift_id) do
      recommendation = case {drift.category, drift.severity} do
        {"features", "critical"} ->
          %{
            action: "immediate_remediation",
            description: "Critical security feature disabled. Immediate remediation required.",
            auto_approve: false,
            notify_admin: true
          }

        {"response", "critical"} ->
          %{
            action: "immediate_remediation",
            description: "Response permissions changed. Review and remediate immediately.",
            auto_approve: false,
            notify_admin: true
          }

        {"network", "critical"} ->
          %{
            action: "quarantine_and_remediate",
            description: "Critical network configuration changed. Quarantine and remediate.",
            auto_approve: false,
            notify_admin: true
          }

        {_, "high"} ->
          %{
            action: "scheduled_remediation",
            description: "High severity drift. Schedule remediation within 24 hours.",
            auto_approve: false,
            notify_admin: true
          }

        {_, _} ->
          %{
            action: "review",
            description: "Review drift and decide on remediation approach.",
            auto_approve: true,
            notify_admin: false
          }
      end

      {:ok, recommendation}
    end
  end

  # Private functions

  defp get_drift(drift_id) do
    case Repo.get(ConfigurationDrift, drift_id) do
      nil -> {:error, :not_found}
      drift -> {:ok, drift}
    end
  end

  defp get_agent(agent_id) do
    case Repo.get(Agent, agent_id) do
      nil -> {:error, :not_found}
      agent -> {:ok, agent}
    end
  end

  defp get_baseline(baseline_id) do
    case Repo.get(ConfigurationBaseline, baseline_id) do
      nil -> {:error, :not_found}
      baseline -> {:ok, baseline}
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

  defp get_unresolved_drifts(agent_id) do
    drifts = Repo.all(
      from d in ConfigurationDrift,
        where: d.agent_id == ^agent_id and d.status != "resolved",
        order_by: [desc: d.severity]
    )

    {:ok, drifts}
  end

  defp check_approval(false, _), do: :ok
  defp check_approval(true, nil), do: {:error, :approval_required}
  defp check_approval(true, _approved_by_id), do: :ok

  defp update_drift(drift, attrs) do
    drift
    |> ConfigurationDrift.changeset(attrs)
    |> Repo.update()
  end

  # Remediation functions for each category

  defp remediate_collector_drift(agent, baseline, drift) do
    field = drift.field_path
    expected_config = get_in(baseline.collector_settings, [field])

    if expected_config do
      config_update = %{
        "collectors" => %{
          field => expected_config
        }
      }

      push_config_update(agent, config_update)
    else
      {:error, :invalid_baseline}
    end
  end

  defp remediate_response_drift(agent, baseline, drift) do
    config_update = %{
      "response" => baseline.response_permissions
    }

    push_config_update(agent, config_update)
  end

  defp remediate_network_drift(agent, baseline, drift) do
    config_update = %{
      "network" => baseline.network_settings
    }

    push_config_update(agent, config_update)
  end

  defp remediate_path_drift(agent, baseline, drift) do
    config_update = %{
      "paths" => baseline.file_paths
    }

    push_config_update(agent, config_update)
  end

  defp remediate_resource_drift(agent, baseline, drift) do
    config_update = %{
      "resource_limits" => baseline.resource_limits
    }

    push_config_update(agent, config_update)
  end

  defp remediate_feature_drift(agent, baseline, drift) do
    config_update = %{
      "detection" => %{
        "yara_enabled" => baseline.enabled_features["yara_enabled"],
        "sigma_enabled" => baseline.enabled_features["sigma_enabled"],
        "ml_enabled" => baseline.enabled_features["ml_enabled"]
      }
    }

    push_config_update(agent, config_update)
  end

  defp remediate_rule_drift(agent, baseline, _drift) do
    # Trigger rule update for the agent
    command = %{
      "type" => "update_rules",
      "yara_version" => baseline.rule_versions["yara_version"],
      "sigma_version" => baseline.rule_versions["sigma_version"],
      "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
    }

    send_command_to_agent(agent, command)
  end

  defp push_config_update(agent, config_update) do
    command = %{
      "type" => "config_update",
      "config" => config_update,
      "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
    }

    send_command_to_agent(agent, command)
  end

  defp push_baseline_config(agent, baseline) do
    full_config = %{
      "collectors" => baseline.collector_settings,
      "response" => baseline.response_permissions,
      "network" => baseline.network_settings,
      "paths" => baseline.file_paths,
      "resource_limits" => baseline.resource_limits,
      "detection" => %{
        "yara_enabled" => baseline.enabled_features["yara_enabled"],
        "sigma_enabled" => baseline.enabled_features["sigma_enabled"],
        "ml_enabled" => baseline.enabled_features["ml_enabled"]
      },
      "rules" => baseline.rule_versions
    }

    command = %{
      "type" => "config_update",
      "config" => full_config,
      "full_baseline" => true,
      "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
    }

    send_command_to_agent(agent, command)
  end

  defp send_command_to_agent(agent, command) do
    # Use existing agent command infrastructure
    TamanduaServer.Agents.send_command(agent.id, command)
  end

  defp update_agent_compliance(agent_id, is_compliant) do
    case Repo.get_by(ComplianceStatus, agent_id: agent_id) do
      nil -> :ok
      status ->
        attrs = %{
          is_compliant: is_compliant,
          drift_count: 0,
          critical_drifts: 0,
          high_drifts: 0,
          medium_drifts: 0,
          low_drifts: 0,
          compliance_score: 100.0,
          last_compliant_at: DateTime.utc_now()
        }

        status
        |> ComplianceStatus.changeset(attrs)
        |> Repo.update()
    end
  end

  defp broadcast_remediation_event(agent, drift, status) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "agents:drift",
      {:drift_remediated, %{
        agent_id: agent.id,
        hostname: agent.hostname,
        drift_id: drift.id,
        drift_type: drift.drift_type,
        status: status,
        timestamp: DateTime.utc_now()
      }}
    )
  end

  defp broadcast_agent_remediation_event(agent, drift_count) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "agents:drift",
      {:agent_remediated, %{
        agent_id: agent.id,
        hostname: agent.hostname,
        drifts_remediated: drift_count,
        timestamp: DateTime.utc_now()
      }}
    )
  end

  defp log_quarantine(agent, reason, quarantined_by_id) do
    TamanduaServer.Audit.log_event(
      "agent_quarantined",
      agent.organization_id,
      quarantined_by_id,
      %{
        agent_id: agent.id,
        hostname: agent.hostname,
        reason: reason,
        ip_address: agent.ip_address
      }
    )
  end

  defp list_all_organizations do
    Repo.all(TamanduaServer.Accounts.Organization)
  end
end
