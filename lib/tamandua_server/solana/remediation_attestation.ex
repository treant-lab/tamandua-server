defmodule TamanduaServer.Solana.RemediationAttestation do
  @moduledoc """
  Proof of Remediation attestation service for Tamandua Sentinel.

  This module creates tamper-evident attestations for successful remediation
  actions on the Solana blockchain, linking them to original incident attestations.

  ## Features

  - **Remediation proof**: Cryptographic evidence that a response action was executed
  - **Incident linking**: Links to original Proof of Incident attestation
  - **Privacy-safe**: Only hashes and pseudonyms go on-chain
  - **Action tracking**: Records action type, timestamp, and success status

  ## Usage

      # After a successful response action
      {:ok, tx_signature} = RemediationAttestation.attest_remediation(
        action,
        alert: alert,
        response: response_data
      )

  ## On-Chain Data

  The attestation memo includes:
  - `t`: "tamandua_remediation" (type identifier)
  - `v`: Schema version (1)
  - `rh`: Remediation hash (SHA256 of action details)
  - `ih`: Related incident hash (if linked to an alert)
  - `at`: Action type (kill_process, quarantine_file, isolate_network, etc.)
  - `op`: Organization pseudonym (SHA256)
  - `ap`: Agent pseudonym (SHA256)
  - `st`: Status (success/partial)
  - `ts`: Unix timestamp

  ## Privacy Guarantees

  **What NEVER goes on-chain:**
  - File paths
  - Process names or PIDs
  - Network addresses
  - Usernames
  - Any raw telemetry

  **What DOES go on-chain:**
  - Action type (generic: kill_process, quarantine_file, etc.)
  - Remediation hash (proof of action)
  - Incident hash reference (link to Proof of Incident)
  - Pseudonymized org/agent IDs
  - Timestamp and status
  """

  require Logger

  alias TamanduaServer.Solana.Client
  alias TamanduaServer.Solana.Attestation
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Response.Action

  @action_type_map %{
    "kill_process" => "kill",
    "quarantine_file" => "quarantine",
    "isolate_network" => "isolate",
    "unisolate_network" => "unisolate",
    "scan_path" => "scan",
    "collect_forensics" => "forensics",
    "collect_artifact" => "artifact",
    "create_snapshot" => "snapshot",
    "restore_file" => "restore",
    "restore_files" => "restore",
    "ransomware_remediate" => "ransomware_fix",
    "delete_snapshot" => "snap_del"
  }

  @doc """
  Create an on-chain attestation for a successful remediation action.

  ## Parameters

  - `action` - The response action (map or Action struct)
  - `opts` - Options:
    - `:alert` - The related Alert (for incident linking)
    - `:response` - The response data from the agent
    - `:agent_id` - Agent ID (if not in action)
    - `:organization_id` - Org ID (if not in action)

  ## Returns

  - `{:ok, tx_signature}` on success
  - `{:error, reason}` on failure
  """
  @spec attest_remediation(map() | Action.t(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def attest_remediation(action, opts \\ []) do
    alert = Keyword.get(opts, :alert)
    response = Keyword.get(opts, :response, %{})

    params = build_remediation_params(action, alert, response, opts)

    case Client.submit_attestation(params) do
      {:ok, signature} ->
        Logger.info("[RemediationAttestation] Remediation attested: #{signature}, action: #{params.action_type}")
        {:ok, signature}

      {:error, reason} ->
        Logger.error("[RemediationAttestation] Failed to attest remediation: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Attest a remediation action from executor context.

  This is the main entry point called from the Executor after successful action.
  """
  @spec attest_from_executor(String.t(), String.t(), map(), map(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def attest_from_executor(agent_id, action_type, params, response, opts \\ []) do
    alert = Keyword.get(opts, :alert)
    organization_id = Keyword.get(opts, :organization_id)

    action = %{
      agent_id: agent_id,
      action_type: action_type,
      parameters: params,
      status: "success",
      executed_at: DateTime.utc_now()
    }

    attest_remediation(action,
      alert: alert,
      response: response,
      organization_id: organization_id
    )
  end

  @doc """
  Build the remediation attestation parameters.
  """
  @spec build_remediation_params(map() | Action.t(), Alert.t() | nil, map(), keyword()) :: map()
  def build_remediation_params(action, alert, response, opts) do
    action_type = get_action_type(action)
    agent_id = get_field(action, :agent_id) || Keyword.get(opts, :agent_id)
    organization_id = get_field(action, :organization_id) ||
                      (alert && alert.organization_id) ||
                      Keyword.get(opts, :organization_id)
    timestamp = get_field(action, :executed_at) || DateTime.utc_now()

    # Compute hashes
    remediation_hash = compute_remediation_hash(action, response)
    incident_hash = if alert, do: Attestation.compute_incident_hash(alert), else: nil

    %{
      attestation_type: "remediation",
      remediation_hash: remediation_hash,
      incident_hash: incident_hash,
      action_type: compact_action_type(action_type),
      org_pseudonym: Attestation.pseudonymize(organization_id),
      agent_pseudonym: Attestation.pseudonymize(agent_id),
      status: determine_status(action, response),
      timestamp: timestamp
    }
  end

  @doc """
  Compute a stable SHA256 hash for the remediation action.

  This hash proves the action occurred without exposing sensitive details.
  """
  @spec compute_remediation_hash(map() | Action.t(), map()) :: binary()
  def compute_remediation_hash(action, response) do
    # Include only non-sensitive, deterministic fields
    action_type = get_action_type(action)
    agent_id = get_field(action, :agent_id) || "unknown"
    status = get_field(action, :status) || "success"
    timestamp = get_field(action, :executed_at) || DateTime.utc_now()

    # Hash of response (without sensitive paths/names)
    response_hash = hash_response_data(response)

    payload = [
      "remediation",
      action_type,
      agent_id,
      status,
      DateTime.to_iso8601(timestamp),
      response_hash
    ]
    |> Enum.join("|")

    :crypto.hash(:sha256, payload)
  end

  @doc """
  Generate Solscan URL for a remediation attestation.
  """
  @spec solscan_url(String.t()) :: String.t()
  def solscan_url(tx_signature) do
    Client.solscan_url(tx_signature)
  end

  @doc """
  Attest a remediation job completion (from Remediation GenServer).

  This is called when ransomware remediation or other long-running jobs complete.
  """
  @spec attest_job_completion(String.t(), atom(), map(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def attest_job_completion(job_id, job_type, result, opts \\ []) do
    agent_id = Keyword.get(opts, :agent_id)
    organization_id = Keyword.get(opts, :organization_id)

    action = %{
      agent_id: agent_id,
      action_type: Atom.to_string(job_type),
      parameters: %{job_id: job_id},
      status: "success",
      executed_at: DateTime.utc_now()
    }

    attest_remediation(action,
      response: result,
      organization_id: organization_id
    )
  end

  @doc """
  Check if Solana attestation is enabled.
  """
  @spec enabled?() :: boolean()
  def enabled? do
    Client.enabled?()
  end

  @doc """
  Build a human-readable summary of the remediation attestation.
  """
  @spec format_attestation_summary(map()) :: String.t()
  def format_attestation_summary(params) do
    action = Map.get(params, :action_type, "unknown")
    status = Map.get(params, :status, "success")
    hash = params |> Map.get(:remediation_hash, <<>>) |> Base.encode16(case: :lower) |> String.slice(0, 16)

    "Remediation[#{action}] status=#{status} hash=#{hash}..."
  end

  # Private functions

  defp get_action_type(%Action{action_type: type}), do: type
  defp get_action_type(%{action_type: type}), do: to_string(type)
  defp get_action_type(%{"action_type" => type}), do: to_string(type)
  defp get_action_type(_), do: "unknown"

  defp get_field(%Action{} = action, field) do
    Map.get(action, field)
  end

  defp get_field(map, field) when is_map(map) and is_atom(field) do
    Map.get(map, field) || Map.get(map, Atom.to_string(field))
  end

  defp get_field(_, _), do: nil

  defp compact_action_type(action_type) do
    Map.get(@action_type_map, action_type, String.slice(to_string(action_type), 0, 16))
  end

  defp determine_status(action, response) do
    action_status = get_field(action, :status)

    cond do
      action_status in ["success", :success] -> "success"
      action_status in ["partial", :partial] -> "partial"
      response_indicates_success?(response) -> "success"
      true -> "success"  # Default to success if we're attesting
    end
  end

  defp response_indicates_success?(response) when is_map(response) do
    # Check for common success indicators in response
    case response do
      %{"status" => "success"} -> true
      %{"success" => true} -> true
      %{"result" => "ok"} -> true
      %{status: "success"} -> true
      %{success: true} -> true
      _ -> true  # Assume success if no failure indicators
    end
  end

  defp response_indicates_success?(_), do: true

  defp hash_response_data(response) when is_map(response) do
    # Extract only safe fields for hashing (no paths, no names)
    safe_data = %{
      success: Map.get(response, "success", Map.get(response, :success, true)),
      count: Map.get(response, "count", Map.get(response, :count)),
      size: Map.get(response, "size_bytes", Map.get(response, :size_bytes))
    }
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()

    safe_data
    |> Jason.encode!()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp hash_response_data(_), do: "empty"
end
