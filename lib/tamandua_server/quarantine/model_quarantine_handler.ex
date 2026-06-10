defmodule TamanduaServer.Quarantine.ModelQuarantineHandler do
  @moduledoc """
  Handles model quarantine events from agents and coordinates responses.

  This module:
  - Processes quarantine receipts from agents
  - Creates alerts for quarantined models
  - Integrates with the Response Executor for restore operations
  - Provides policy-based auto-quarantine triggering
  """

  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Quarantine.ModelVault
  alias TamanduaServer.Response.Executor
  alias TamanduaServer.Response.Audit
  alias TamanduaServer.Detection.PreventionPolicy

  @doc """
  Handles a quarantine receipt from an agent.

  Creates an alert and stores the receipt in the vault.
  """
  @spec handle_quarantine_receipt(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def handle_quarantine_receipt(agent_id, receipt) do
    Logger.info("Received quarantine receipt from agent #{agent_id}: #{receipt["receipt_id"]}")

    # Store receipt with agent_id
    receipt_with_agent = Map.put(receipt, "agent_id", agent_id)

    case ModelVault.store_receipt(receipt_with_agent) do
      {:ok, receipt_id} ->
        # Create alert for the quarantine
        alert = create_quarantine_alert(agent_id, receipt)

        # Audit log
        Audit.log_action(:model_quarantined, %{
          receipt_id: receipt_id,
          original_path: receipt["original_path"],
          sha256: receipt["sha256"],
          reason: receipt["reason"],
          model_format: receipt["model_format"],
          affected_processes: length(receipt["affected_processes"] || [])
        }, agent_id, :system)

        {:ok, %{
          receipt_id: receipt_id,
          alert_id: alert && alert.id,
          status: "quarantined"
        }}

      {:error, reason} ->
        Logger.error("Failed to store quarantine receipt: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Initiates a model restore from the dashboard/API.

  Validates authorization, gets the recovery key from the vault,
  and sends the restore command to the agent.
  """
  @spec initiate_restore(String.t(), String.t(), map(), map()) ::
          {:ok, map()} | {:error, term()}
  def initiate_restore(receipt_id, restore_path, actor, authorization) do
    Logger.info("Restore initiated for receipt #{receipt_id} by #{actor["username"] || actor}")

    # Get receipt to find agent_id
    case ModelVault.get_receipt(receipt_id) do
      {:ok, receipt} ->
        agent_id = receipt.agent_id
        actor_name = actor["username"] || inspect(actor)

        # Get recovery key from vault (validates authorization)
        case ModelVault.initiate_restore(receipt_id, restore_path, actor_name, authorization) do
          {:ok, recovery_key} ->
            # Send restore command to agent
            send_restore_command(agent_id, receipt_id, restore_path, recovery_key, authorization)

          {:error, reason} ->
            {:error, reason}
        end

      {:error, :not_found} ->
        {:error, :receipt_not_found}
    end
  end

  @doc """
  Triggers automatic quarantine of a model on an agent.

  Used by detection systems when a malicious model is identified.
  """
  @spec trigger_auto_quarantine(String.t(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def trigger_auto_quarantine(agent_id, model_path, detection_info) do
    Logger.warning("Auto-quarantine triggered for model #{model_path} on agent #{agent_id}")

    # Check if auto-quarantine is enabled for this agent
    policy = PreventionPolicy.get_policy_for_agent(agent_id)

    if auto_quarantine_enabled?(policy) do
      # Determine reason from detection info
      reason = determine_quarantine_reason(detection_info)

      # Send quarantine command to agent
      command_params = %{
        path: model_path,
        reason: reason,
        detection_info: detection_info
      }

      case Executor.execute_action(agent_id, "model_quarantine", command_params) do
        {:ok, response} ->
          Logger.info("Model quarantine command sent to agent #{agent_id}")

          # The agent will send back a receipt which will be handled by handle_quarantine_receipt
          {:ok, %{
            status: "quarantine_initiated",
            agent_response: response
          }}

        {:error, reason} ->
          Logger.error("Failed to send quarantine command: #{inspect(reason)}")
          {:error, reason}
      end
    else
      Logger.info("Auto-quarantine disabled for agent #{agent_id}")
      {:error, :auto_quarantine_disabled}
    end
  end

  @doc """
  Handles restoration completion notification from an agent.
  """
  @spec handle_restoration_complete(String.t(), map()) :: :ok | {:error, term()}
  def handle_restoration_complete(agent_id, result) do
    receipt_id = result["receipt_id"]
    success = result["success"]

    Logger.info("Restoration complete for receipt #{receipt_id}: success=#{success}")

    restoration_record = %{
      timestamp: DateTime.utc_now(),
      initiated_by: "server",
      restore_path: result["restored_path"],
      success: success,
      error: result["error"]
    }

    ModelVault.record_restoration(receipt_id, restoration_record)
  end

  @doc """
  Lists quarantined models for an agent with stats.
  """
  @spec list_quarantined_models(String.t()) :: map()
  def list_quarantined_models(agent_id) do
    receipts = ModelVault.list_agent_receipts(agent_id)
    stats = ModelVault.get_stats(agent_id: agent_id)

    %{
      models: receipts,
      stats: stats
    }
  end

  @doc """
  Permanently deletes a quarantined model.

  Sends delete command to agent and marks receipt as deleted.
  """
  @spec delete_quarantined_model(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def delete_quarantined_model(receipt_id, actor) do
    case ModelVault.get_receipt(receipt_id) do
      {:ok, receipt} ->
        agent_id = receipt.agent_id
        actor_name = actor["username"] || inspect(actor)

        # Send delete command to agent
        command_params = %{receipt_id: receipt_id}

        case Executor.execute_action(agent_id, "model_quarantine_delete", command_params) do
          {:ok, _response} ->
            # Mark as deleted in vault
            ModelVault.mark_deleted(receipt_id, actor_name)
            {:ok, %{status: "deleted", receipt_id: receipt_id}}

          {:error, reason} ->
            {:error, reason}
        end

      {:error, :not_found} ->
        {:error, :receipt_not_found}
    end
  end

  ## Private Functions

  defp create_quarantine_alert(agent_id, receipt) do
    original_path = receipt["original_path"]
    sha256 = receipt["sha256"]
    reason = receipt["reason"]
    model_format = receipt["model_format"]
    detection_info = receipt["detection_info"]

    severity = severity_from_reason(reason)

    title = case reason do
      "malicious_payload" -> "Malicious Model Payload Detected and Quarantined"
      "neural_backdoor" -> "Neural Backdoor Detected in Model"
      "model_poisoning" -> "Poisoned ML Model Quarantined"
      "supply_chain_attack" -> "Supply Chain Attack - Malicious Model Quarantined"
      "behavioral_anomaly" -> "Model Behavioral Anomaly - Quarantined"
      "policy_violation" -> "Unauthorized Model Quarantined"
      _ -> "Suspicious AI Model Quarantined"
    end

    description = """
    An AI/ML model has been automatically quarantined due to security concerns.

    **Model Path:** #{original_path}
    **SHA256:** #{sha256}
    **Format:** #{model_format || "unknown"}
    **Reason:** #{reason}

    #{format_detection_details(detection_info)}

    The model has been encrypted and moved to the quarantine vault.
    Affected processes have been notified.
    """

    evidence = %{
      file_hashes: [%{sha256: sha256, path: original_path}],
      network: [],
      process: %{},
      registry: [],
      detection: %{
        rule_name: "Model Security Scan",
        rule_type: "model_quarantine",
        reason: reason,
        model_format: model_format
      }
    }

    mitre_tactics = case reason do
      "supply_chain_attack" -> ["initial-access", "persistence"]
      "malicious_payload" -> ["execution", "defense-evasion"]
      "neural_backdoor" -> ["persistence", "command-and-control"]
      _ -> ["execution"]
    end

    mitre_techniques = case reason do
      "supply_chain_attack" -> ["T1195.002"]
      "malicious_payload" -> ["T1059.006", "T1027"]
      "neural_backdoor" -> ["T1542"]
      _ -> ["T1204"]
    end

    alert_attrs = %{
      agent_id: agent_id,
      organization_id: get_org_id(agent_id),
      severity: severity,
      title: title,
      description: description,
      source_event_id: receipt["receipt_id"],
      event_ids: [receipt["receipt_id"]],
      evidence: evidence,
      raw_event: receipt,
      mitre_tactics: mitre_tactics,
      mitre_techniques: mitre_techniques,
      threat_score: threat_score_from_reason(reason),
      detection_metadata: %{
        detection_type: "model_quarantine",
        reason: reason,
        model_format: model_format,
        receipt_id: receipt["receipt_id"]
      }
    }

    case Alerts.create_alert(alert_attrs) do
      {:ok, alert} ->
        Logger.info("Created quarantine alert: #{alert.id}")
        alert

      {:error, reason} ->
        Logger.error("Failed to create quarantine alert: #{inspect(reason)}")
        nil
    end
  end

  defp send_restore_command(agent_id, receipt_id, restore_path, recovery_key, authorization) do
    command_params = %{
      receipt_id: receipt_id,
      restore_path: restore_path,
      recovery_key: recovery_key,
      auth_token: Map.get(authorization, :token, nil)
    }

    case Executor.execute_action(agent_id, "model_restore", command_params) do
      {:ok, response} ->
        Logger.info("Restore command sent to agent #{agent_id}")
        {:ok, %{
          status: "restore_initiated",
          agent_response: response
        }}

      {:error, reason} ->
        Logger.error("Failed to send restore command: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp auto_quarantine_enabled?(policy) do
    cond do
      is_map(policy) and Map.has_key?(policy, :model_auto_quarantine) ->
        policy.model_auto_quarantine

      is_map(policy) and Map.has_key?(policy, :category_settings) ->
        ai_settings = get_in(policy.category_settings, ["ai_security"]) || %{}
        ai_settings["auto_quarantine"] != false

      true ->
        # Default to enabled
        true
    end
  end

  defp determine_quarantine_reason(detection_info) do
    source = detection_info["detection_source"] || detection_info[:detection_source] || ""
    threat = detection_info["threat_name"] || detection_info[:threat_name] || ""

    cond do
      String.contains?(String.downcase(source), "backdoor") -> "neural_backdoor"
      String.contains?(String.downcase(source), "poison") -> "model_poisoning"
      String.contains?(String.downcase(source), "supply") -> "supply_chain_attack"
      String.contains?(String.downcase(threat), "payload") -> "malicious_payload"
      String.contains?(String.downcase(threat), "rce") -> "malicious_payload"
      true -> "security_scan_failed"
    end
  end

  defp severity_from_reason(reason) do
    case reason do
      "malicious_payload" -> "critical"
      "neural_backdoor" -> "critical"
      "supply_chain_attack" -> "critical"
      "model_poisoning" -> "high"
      "behavioral_anomaly" -> "high"
      "policy_violation" -> "medium"
      _ -> "high"
    end
  end

  defp threat_score_from_reason(reason) do
    case reason do
      "malicious_payload" -> 0.95
      "neural_backdoor" -> 0.90
      "supply_chain_attack" -> 0.95
      "model_poisoning" -> 0.85
      "behavioral_anomaly" -> 0.80
      "policy_violation" -> 0.70
      _ -> 0.80
    end
  end

  defp format_detection_details(nil), do: ""
  defp format_detection_details(info) when is_map(info) do
    details = []
    details = if info["detection_source"], do: details ++ ["Detection Source: #{info["detection_source"]}"], else: details
    details = if info["threat_name"], do: details ++ ["Threat: #{info["threat_name"]}"], else: details
    details = if info["confidence"], do: details ++ ["Confidence: #{Float.round(info["confidence"] * 100, 1)}%"], else: details

    if length(details) > 0 do
      "\n**Detection Details:**\n" <> Enum.join(details, "\n")
    else
      ""
    end
  end
  defp format_detection_details(_), do: ""

  defp get_org_id(agent_id) do
    try do
      TamanduaServer.Agents.OrgLookup.get_org_id(agent_id)
    rescue
      _ -> nil
    catch
      _, _ -> nil
    end
  end
end
