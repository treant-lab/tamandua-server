defmodule TamanduaServer.Response.MLResponse do
  @moduledoc """
  Automatic response actions triggered by ML detections.

  Actions are taken based on:
  - ML confidence score
  - Prevention policy settings
  - File/process context

  This module bridges the ML detection pipeline with the response executor,
  enabling automated quarantine and process termination for high-confidence
  malware detections.
  """

  require Logger

  alias TamanduaServer.Alerts
  alias TamanduaServer.Response.{Audit, Executor}
  alias TamanduaServer.Detection.PreventionPolicy

  @doc """
  Handle ML detection result and take appropriate action.

  ## Parameters

  - `sample` - The analyzed sample map containing file path, process info, hashes
  - `ml_result` - The ML prediction result map with :confidence and :prediction
  - `agent_id` - The agent ID where the sample was detected

  ## Returns

  - `{:ok, :quarantined, details}` - File was quarantined (and optionally process killed)
  - `{:ok, :alert_created, alert}` - Alert created but no automatic action taken
  - `:no_action` - Detection below thresholds, no action taken
  - `{:error, reason}` - Error during response execution
  """
  @spec handle_ml_detection(map(), map(), String.t()) ::
          {:ok, :quarantined, map()}
          | {:ok, :alert_created, map()}
          | :no_action
          | {:error, term()}
  def handle_ml_detection(sample, ml_result, agent_id) do
    _ = {sample, ml_result, agent_id}
    {:error, :organization_scope_required}
  end

  @spec handle_ml_detection(map(), map(), String.t(), String.t()) ::
          {:ok, :quarantined, map()}
          | {:ok, :alert_created, map()}
          | :no_action
          | {:error, term()}
  def handle_ml_detection(sample, ml_result, agent_id, organization_id) do
    with {:ok, canonical_organization_id, canonical_agent_id} <-
           validate_agent_scope(organization_id, agent_id),
         {:ok, policy} <-
           load_policy(canonical_organization_id, canonical_agent_id) do
      do_handle_ml_detection(
        sample,
        ml_result,
        canonical_agent_id,
        canonical_organization_id,
        policy
      )
    end
  end

  defp do_handle_ml_detection(sample, ml_result, agent_id, organization_id, policy) do
    # Check if ML response is enabled
    unless ml_response_enabled?(policy) do
      Logger.debug("ML response disabled for agent #{agent_id}")
      :no_action
    else
      confidence = ml_result[:confidence] || ml_result["confidence"] || 0.0
      prediction = ml_result[:prediction] || ml_result["prediction"]

      # Only act on malicious predictions
      if prediction in ["malicious", :malicious] do
        auto_quarantine_threshold = get_auto_quarantine_threshold(policy)
        alert_threshold = get_alert_threshold(policy)

        cond do
          confidence >= auto_quarantine_threshold ->
            auto_quarantine(sample, ml_result, agent_id, organization_id, policy)

          confidence >= alert_threshold ->
            create_alert_only(sample, ml_result, agent_id, organization_id)

          true ->
            Logger.debug("ML detection below thresholds (confidence: #{confidence})")
            :no_action
        end
      else
        Logger.debug("ML prediction not malicious: #{prediction}")
        :no_action
      end
    end
  end

  @doc """
  Check if automatic quarantine should be triggered for a given confidence score.
  """
  @spec should_auto_quarantine?(map(), float()) :: boolean()
  def should_auto_quarantine?(policy, confidence) do
    ml_response_enabled?(policy) and confidence >= get_auto_quarantine_threshold(policy)
  end

  # Private functions

  defp auto_quarantine(sample, ml_result, agent_id, organization_id, policy) do
    Logger.warning(
      "Auto-quarantine triggered for agent #{agent_id}: confidence #{ml_result[:confidence]}"
    )

    file_path = sample[:path] || sample[:file_path] || sample["path"]
    pid = sample[:pid] || sample[:process_id] || sample["pid"]

    with {:ok, alert} <-
           create_ml_alert(sample, ml_result, agent_id, organization_id, "auto_quarantine") do
      execute_auto_quarantine_after_alert(
        sample,
        agent_id,
        organization_id,
        policy,
        alert,
        file_path,
        pid
      )
    else
      {:error, reason} ->
        Logger.error("ML response stopped because alert persistence failed: #{inspect(reason)}")
        {:error, {:alert_creation_failed, reason}}
    end
  end

  defp execute_auto_quarantine_after_alert(
         sample,
         agent_id,
         organization_id,
         policy,
         alert,
         file_path,
         pid
       ) do
    # Track results
    results = %{
      alert_id: alert.id,
      quarantine_result: nil,
      kill_result: nil,
      file_path: file_path,
      pid: pid
    }

    # Quarantine the file
    quarantine_result =
      if file_path do
        case Executor.quarantine_file(agent_id, file_path,
               delete_after: false,
               actor: :system,
               organization_id: organization_id
             ) do
          {:ok, response} ->
            audit_action(:quarantine_file, sample, agent_id, organization_id, {:ok, response})
            Logger.info("File quarantined: #{file_path} on agent #{agent_id}")
            {:ok, response}

          {:error, reason} = error ->
            audit_action(:quarantine_file, sample, agent_id, organization_id, error)
            Logger.error("Failed to quarantine file #{file_path}: #{inspect(reason)}")
            error
        end
      else
        {:error, :no_file_path}
      end

    results = %{results | quarantine_result: quarantine_result}

    # Optionally kill the process if configured and we have a PID
    kill_result =
      if auto_kill_enabled?(policy) and pid do
        kill_process_if_running(sample, agent_id, organization_id)
      else
        nil
      end

    results = %{results | kill_result: kill_result}

    case quarantine_result do
      {:ok, _} ->
        {:ok, :quarantined, results}

      {:error, reason} ->
        # Even if quarantine failed, we still created an alert
        Logger.warning("Quarantine failed but alert created: #{inspect(reason)}")
        {:ok, :alert_created, %{alert: alert, error: reason}}
    end
  end

  defp kill_process_if_running(sample, agent_id, organization_id) do
    pid = sample[:pid] || sample[:process_id] || sample["pid"]

    if pid do
      Logger.info("Killing malicious process PID #{pid} on agent #{agent_id}")

      case Executor.kill_process(agent_id, pid,
             force: true,
             actor: :system,
             organization_id: organization_id
           ) do
        {:ok, response} ->
          audit_action(:kill_process, sample, agent_id, organization_id, {:ok, response})
          Logger.info("Process #{pid} killed on agent #{agent_id}")
          {:ok, response}

        {:error, reason} = error ->
          audit_action(:kill_process, sample, agent_id, organization_id, error)
          Logger.error("Failed to kill process #{pid}: #{inspect(reason)}")
          error
      end
    else
      Logger.debug("No PID available for process termination")
      {:error, :no_pid}
    end
  end

  defp create_alert_only(sample, ml_result, agent_id, organization_id) do
    Logger.info(
      "Creating ML detection alert for agent #{agent_id}: confidence #{ml_result[:confidence]}"
    )

    with {:ok, alert} <-
           create_ml_alert(sample, ml_result, agent_id, organization_id, "detection_only") do
      audit_action(:create_alert, sample, agent_id, organization_id, {
        :ok,
        %{alert_id: alert.id}
      })

      {:ok, :alert_created, %{alert: alert}}
    else
      {:error, reason} -> {:error, {:alert_creation_failed, reason}}
    end
  end

  defp create_ml_alert(sample, ml_result, agent_id, organization_id, response_type) do
    confidence = ml_result[:confidence] || ml_result["confidence"] || 0.0
    malware_family = ml_result[:malware_family] || ml_result["malware_family"]
    file_path = sample[:path] || sample[:file_path] || sample["path"]
    sha256 = sample[:sha256] || sample["sha256"]

    severity = severity_from_confidence(confidence)

    title =
      if malware_family do
        "ML Detection: #{malware_family}"
      else
        "ML Detection: Malicious File"
      end

    description = """
    Machine Learning analysis detected a malicious file with #{Float.round(confidence * 100, 1)}% confidence.

    File Path: #{file_path || "Unknown"}
    SHA256: #{sha256 || "Unknown"}
    Malware Family: #{malware_family || "Unknown"}
    Response Type: #{response_type}
    """

    evidence = %{
      file_hashes: [
        %{
          sha256: sha256,
          path: file_path
        }
      ],
      network: [],
      process: %{
        name: sample[:process_name] || sample["process_name"],
        path: file_path,
        pid: sample[:pid] || sample[:process_id]
      },
      registry: [],
      detection: %{
        rule_name: "ML Malware Detection",
        rule_type: "ml",
        confidence: confidence,
        malware_family: malware_family
      }
    }

    alert_attrs = %{
      agent_id: agent_id,
      organization_id: organization_id,
      severity: severity,
      title: title,
      description: description,
      source_event_id: sample[:event_id],
      event_ids: List.wrap(sample[:event_id]),
      evidence: evidence,
      raw_event: sample,
      mitre_tactics: [],
      mitre_techniques: [],
      threat_score: confidence,
      recommended_response: ml_recommended_response(severity),
      detection_metadata: %{
        detection_type: "ml",
        response_type: response_type,
        confidence: confidence,
        malware_family: malware_family,
        prediction: ml_result[:prediction] || ml_result["prediction"],
        model_version: ml_result[:model_version] || ml_result["model_version"],
        s_space_distance: ml_result[:s_space_distance] || ml_result["s_space_distance"]
      }
    }

    result =
      TamanduaServer.Repo.MultiTenant.with_organization(organization_id, fn ->
        Alerts.create_alert(alert_attrs)
      end)

    case result do
      {:ok, alert} ->
        Logger.info("ML alert created: #{alert.id}")
        {:ok, alert}

      {:error, reason} ->
        Logger.error("Failed to create ML alert: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    error ->
      Logger.error("Failed to create ML alert in tenant scope: #{inspect(error)}")
      {:error, {:alert_scope_failed, error}}
  end

  defp audit_action(action_type, sample, agent_id, organization_id, result) do
    details = %{
      file_path: sample[:path] || sample[:file_path] || sample["path"],
      sha256: sample[:sha256] || sample["sha256"],
      pid: sample[:pid] || sample[:process_id] || sample["pid"],
      process_name: sample[:process_name] || sample["process_name"],
      result: format_result(result)
    }

    Audit.log_action(action_type, details, agent_id, :system, organization_id)
  end

  defp format_result({:ok, response}), do: %{status: "success", response: response}
  defp format_result({:error, reason}), do: %{status: "error", reason: inspect(reason)}
  defp format_result(other), do: %{status: "unknown", value: inspect(other)}

  defp validate_agent_scope(organization_id, agent_id) do
    with {:ok, canonical_organization_id} <- canonical_uuid(organization_id),
         {:ok, canonical_agent_id} <- canonical_uuid(agent_id) do
      result =
        TamanduaServer.Repo.MultiTenant.with_organization(canonical_organization_id, fn ->
          TamanduaServer.Agents.get_agent_for_org(
            canonical_organization_id,
            canonical_agent_id
          )
        end)

      case result do
        {:ok, _agent} ->
          {:ok, canonical_organization_id, canonical_agent_id}

        {:error, :not_found} ->
          {:error, :agent_scope_mismatch}

        {:error, reason} ->
          {:error, {:agent_scope_validation_failed, reason}}
      end
    end
  rescue
    ArgumentError -> {:error, :invalid_tenant_identifier}
    error -> {:error, {:tenant_scope_failed, error}}
  end

  defp canonical_uuid(value) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, :invalid_tenant_identifier}
    end
  end

  defp canonical_uuid(_value), do: {:error, :invalid_tenant_identifier}

  defp load_policy(organization_id, agent_id) do
    policy =
      TamanduaServer.Repo.MultiTenant.with_organization(organization_id, fn ->
        PreventionPolicy.get_policy_for_agent(agent_id,
          organization_id: organization_id
        )
      end)

    {:ok, policy}
  rescue
    error -> {:error, {:policy_scope_failed, error}}
  end

  # Policy helper functions

  defp ml_response_enabled?(policy) do
    # Check if policy has ml_response_enabled field, default to true
    cond do
      is_map(policy) and Map.has_key?(policy, :ml_response_enabled) ->
        policy.ml_response_enabled

      is_map(policy) and Map.has_key?(policy, :category_settings) ->
        # Check ML-specific settings in category_settings
        ml_settings = get_in(policy.category_settings, ["malware_ml"]) || %{}
        ml_settings["mode"] != "disabled"

      true ->
        # Default to enabled
        true
    end
  end

  defp auto_kill_enabled?(policy) do
    cond do
      is_map(policy) and Map.has_key?(policy, :auto_kill_process) ->
        policy.auto_kill_process

      true ->
        # Default to false for safety
        false
    end
  end

  defp get_auto_quarantine_threshold(policy) do
    cond do
      is_map(policy) and Map.has_key?(policy, :auto_quarantine_threshold) ->
        policy.auto_quarantine_threshold

      is_map(policy) and Map.has_key?(policy, :category_settings) ->
        # Derive from aggressiveness level
        ml_settings = get_in(policy.category_settings, ["malware_ml"]) || %{}

        aggressiveness =
          ml_settings["aggressiveness"] || policy.global_aggressiveness || "moderate"

        threshold_from_aggressiveness(aggressiveness, :block)

      true ->
        # Default threshold
        0.90
    end
  end

  defp get_alert_threshold(policy) do
    cond do
      is_map(policy) and Map.has_key?(policy, :alert_threshold) ->
        policy.alert_threshold

      is_map(policy) and Map.has_key?(policy, :category_settings) ->
        ml_settings = get_in(policy.category_settings, ["malware_ml"]) || %{}

        aggressiveness =
          ml_settings["aggressiveness"] || policy.global_aggressiveness || "moderate"

        threshold_from_aggressiveness(aggressiveness, :alert)

      true ->
        0.75
    end
  end

  defp threshold_from_aggressiveness(aggressiveness, type) do
    thresholds = %{
      "disabled" => %{alert: 999.0, block: 999.0},
      "cautious" => %{alert: 0.85, block: 0.95},
      "moderate" => %{alert: 0.75, block: 0.90},
      "aggressive" => %{alert: 0.60, block: 0.80},
      "extra_aggressive" => %{alert: 0.45, block: 0.70}
    }

    level_thresholds = Map.get(thresholds, aggressiveness, thresholds["moderate"])
    Map.get(level_thresholds, type, 0.90)
  end

  defp severity_from_confidence(confidence) do
    cond do
      confidence >= 0.95 -> "critical"
      confidence >= 0.85 -> "high"
      confidence >= 0.70 -> "medium"
      confidence >= 0.50 -> "low"
      true -> "info"
    end
  end

  defp ml_recommended_response(severity) do
    triage =
      case to_string(severity) do
        "critical" ->
          "Triage immediately: isolate the affected host and preserve volatile evidence."

        "high" ->
          "Triage promptly: review the process chain and contain the host if confirmed."

        "medium" ->
          "Investigate the surrounding telemetry and validate against expected baseline activity."

        _ ->
          "Review the alert evidence and confirm whether the activity is expected."
      end

    triage <>
      " Validate the flagged sample (hash/path) against threat intelligence before acting."
  end
end
