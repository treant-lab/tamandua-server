defmodule TamanduaServer.Integrations.SOAR.CallbackHandler do
  @moduledoc """
  Handles callbacks from SOAR platforms when playbooks complete.

  Processes callback payloads from:
  - **XSOAR** - Investigation completion, playbook results
  - **Tines** - Webhook callbacks with workflow results

  Updates execution logs and optionally updates alert status based on
  playbook results.
  """

  require Logger

  alias TamanduaServer.Integrations.SOAR.{ExecutionLog, Tines}
  alias TamanduaServer.Alerts

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Handle a callback from a SOAR platform.

  ## Parameters

  - `platform` - "xsoar" or "tines"
  - `payload` - Raw callback payload from the SOAR platform

  ## Returns

  `{:ok, result}` with updated execution info, `{:error, reason}` on failure.
  """
  @spec handle_callback(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def handle_callback("xsoar", payload) do
    Logger.info("[CallbackHandler] Processing XSOAR callback")
    handle_xsoar_callback(payload)
  end

  def handle_callback("tines", payload) do
    Logger.info("[CallbackHandler] Processing Tines callback")
    handle_tines_callback(payload)
  end

  def handle_callback(platform, _payload) do
    Logger.warning("[CallbackHandler] Unknown platform: #{platform}")
    {:error, :unknown_platform}
  end

  @doc """
  Update an alert's status based on playbook result.

  Called when a playbook completes with actions that should update the alert.

  ## Parameters

  - `alert_id` - ID of the alert
  - `callback_result` - Parsed result from SOAR callback

  ## Returns

  `{:ok, alert}` or `{:error, reason}`.
  """
  @spec update_alert_from_callback(binary(), map()) :: {:ok, struct()} | {:error, term()}
  def update_alert_from_callback(alert_id, callback_result) do
    Logger.info("[CallbackHandler] Updating alert #{alert_id} from callback")

    # Determine alert status update based on callback
    status_update = determine_alert_update(callback_result)

    if status_update do
      try do
        Alerts.update_alert_status(alert_id, status_update)
      rescue
        e -> {:error, Exception.message(e)}
      end
    else
      {:ok, :no_update_needed}
    end
  end

  # ============================================================================
  # XSOAR Callback Handling
  # ============================================================================

  defp handle_xsoar_callback(payload) do
    # XSOAR sends callbacks with these fields:
    # - investigationId: The investigation/incident ID
    # - status: Investigation status (e.g., "Closed", "Active")
    # - result: Playbook execution result
    # - closeReason: Reason for closure if closed
    # - closeNotes: Notes on closure

    investigation_id = payload["investigationId"] || payload["id"]
    execution_id = payload["playbookRunId"] || payload["runId"] || investigation_id

    # Find the execution log by execution_id
    case find_execution_log(execution_id, "xsoar") do
      {:ok, log} ->
        # Parse XSOAR status
        status = normalize_xsoar_status(payload)

        result = %{
          investigation_id: investigation_id,
          status: payload["status"],
          close_reason: payload["closeReason"],
          close_notes: payload["closeNotes"],
          result: payload["result"],
          actions: payload["actions"] || []
        }

        {:ok, updated_log} = ExecutionLog.update_from_callback(log, %{
          status: status,
          result: result
        })

        # Check if we should update the alert
        if status == "completed" and log.alert_id do
          update_alert_from_callback(log.alert_id, result)
        end

        {:ok, %{
          execution_id: updated_log.id,
          status: status,
          platform: "xsoar",
          result: result
        }}

      {:error, :not_found} ->
        Logger.warning("[CallbackHandler] No execution log found for XSOAR callback: #{execution_id}")
        {:error, :execution_not_found}
    end
  end

  defp normalize_xsoar_status(payload) do
    case payload["status"] do
      "Closed" -> "completed"
      "Done" -> "completed"
      "Complete" -> "completed"
      "Active" -> "running"
      "Pending" -> "pending"
      "Error" -> "failed"
      "Failed" -> "failed"
      _ ->
        # Check if there's a result indicating completion
        if payload["result"] || payload["closeReason"] do
          "completed"
        else
          "running"
        end
    end
  end

  # ============================================================================
  # Tines Callback Handling
  # ============================================================================

  defp handle_tines_callback(payload) do
    # Use Tines module to parse the callback
    parsed = Tines.parse_webhook_callback(payload)

    # Find execution log using our embedded ID
    execution_id = parsed.execution_id || payload["tamandua_execution_id"]

    case find_execution_log(execution_id, "tines") do
      {:ok, log} ->
        result = %{
          story_id: parsed.story_id,
          story_name: parsed.story_name,
          event_id: parsed.event_id,
          agent_name: parsed.agent_name,
          result: parsed.result,
          error: parsed.error
        }

        status = parsed.status

        {:ok, updated_log} = ExecutionLog.update_from_callback(log, %{
          status: status,
          result: result,
          error_message: parsed.error
        })

        # Check if we should update the alert
        if status == "completed" and log.alert_id do
          update_alert_from_callback(log.alert_id, result)
        end

        {:ok, %{
          execution_id: updated_log.id,
          status: status,
          platform: "tines",
          result: result
        }}

      {:error, :not_found} ->
        Logger.warning("[CallbackHandler] No execution log found for Tines callback: #{execution_id}")
        {:error, :execution_not_found}
    end
  end

  # ============================================================================
  # Authentication Verification
  # ============================================================================

  @doc """
  Verify XSOAR callback authentication.

  XSOAR callbacks should include an API key in the `X-XSOAR-Auth` header.

  ## Parameters

  - `api_key` - Value from X-XSOAR-Auth header

  ## Returns

  `:ok` if valid, `{:error, :unauthorized}` if invalid.
  """
  @spec verify_xsoar_auth(String.t()) :: :ok | {:error, :unauthorized}
  def verify_xsoar_auth(api_key) do
    expected_key = get_xsoar_callback_key()

    if expected_key && Plug.Crypto.secure_compare(api_key, expected_key) do
      :ok
    else
      {:error, :unauthorized}
    end
  end

  @doc """
  Verify Tines webhook signature.

  Uses HMAC-SHA256 signature verification.

  ## Parameters

  - `raw_body` - Raw request body as string
  - `signature_header` - Value from X-Tines-Signature header

  ## Returns

  `:ok` if valid, `{:error, :invalid_signature}` if invalid.
  """
  @spec verify_tines_signature(String.t(), String.t()) :: :ok | {:error, atom()}
  def verify_tines_signature(raw_body, signature_header) do
    Tines.verify_webhook_signature(raw_body, signature_header)
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp find_execution_log(execution_id, _platform) when is_nil(execution_id) do
    {:error, :not_found}
  end

  defp find_execution_log(execution_id, _platform) do
    # Try to find by our log ID first (for Tines callbacks with tamandua_execution_id)
    case ExecutionLog.get(execution_id) do
      nil ->
        # Try finding by SOAR execution ID
        case ExecutionLog.get_by_execution_id(execution_id) do
          nil -> {:error, :not_found}
          log -> {:ok, log}
        end

      log ->
        {:ok, log}
    end
  end

  defp determine_alert_update(callback_result) do
    # Determine if and how to update the alert based on SOAR result
    cond do
      # XSOAR closed as resolved/true positive
      callback_result[:close_reason] in ["Resolved", "True Positive", "Confirmed"] ->
        %{status: "resolved", resolution: "soar_confirmed"}

      # XSOAR closed as false positive
      callback_result[:close_reason] in ["False Positive", "Duplicate", "Not Relevant"] ->
        %{status: "false_positive", resolution: "soar_dismissed"}

      # Check for specific actions in result
      result_contains_action?(callback_result, ["isolate", "quarantine", "block"]) ->
        %{status: "in_progress", notes: "SOAR action taken: containment"}

      result_contains_action?(callback_result, ["resolved", "remediated", "cleaned"]) ->
        %{status: "resolved", resolution: "soar_remediated"}

      # No specific update needed
      true ->
        nil
    end
  end

  defp result_contains_action?(callback_result, action_keywords) do
    result = callback_result[:result] || %{}
    actions = callback_result[:actions] || []
    notes = callback_result[:close_notes] || ""

    # Check in actions list
    action_match = Enum.any?(actions, fn action ->
      action_str = to_string(action) |> String.downcase()
      Enum.any?(action_keywords, &String.contains?(action_str, &1))
    end)

    # Check in result map (stringify values)
    result_match = result
    |> Map.values()
    |> Enum.any?(fn v ->
      v_str = to_string(v) |> String.downcase()
      Enum.any?(action_keywords, &String.contains?(v_str, &1))
    end)

    # Check in notes
    notes_match = action_keywords
    |> Enum.any?(&String.contains?(String.downcase(notes), &1))

    action_match or result_match or notes_match
  end

  defp get_xsoar_callback_key do
    config = Application.get_env(:tamandua_server, TamanduaServer.Integrations.SOAR.XSOAR, [])
    config[:callback_api_key] || config[:api_key]
  end
end
