defmodule TamanduaServer.Policies.ModelPolicy do
  @moduledoc """
  Policy engine for trust verification and blocking of AI models.

  Evaluates whether models from registries (HuggingFace, MLflow, W&B, Ollama)
  are trusted and allowed to be loaded based on their security scan results.

  ## Trust Thresholds

  - `< 0.1` - Trusted (clean)
  - `0.1 - 0.3` - Suspicious but allowed
  - `>= 0.3` - Blocked (high risk)

  ## Blocking Mechanisms

  1. **Automatic** - Based on risk_score from security scans
  2. **Explicit** - Manual blocks via `block_model/2`
  3. **Status-based** - Blocks pending, scanning, malicious statuses

  ## Example Usage

      # Check if model can be loaded
      case ModelPolicy.can_load?("meta-llama/Llama-2-7b") do
        {:ok, true} -> # Load the model
        {:ok, false, reason} -> # Block with reason
      end

      # Check trust status
      ModelPolicy.is_trusted?("meta-llama/Llama-2-7b")
      # => true

      # List all blocked models
      blocked = ModelPolicy.list_blocked()
      # => [%{model_id: "suspicious/model", risk_score: 0.85, ...}]

      # Manually block a model
      ModelPolicy.block_model("risky/model", "security_review")
  """

  use Agent

  require Logger

  alias TamanduaServer.Registries.ModelProvenance
  alias TamanduaServer.Repo
  import Ecto.Query

  @block_threshold 0.3
  @suspicious_threshold 0.1

  @doc """
  Starts the ModelPolicy Agent for explicit block list storage.

  Called automatically when the module is first used.
  """
  def start_link(_opts \\ []) do
    Agent.start_link(fn -> %{} end, name: __MODULE__)
  end

  @doc """
  Ensures the Agent is running.
  """
  def ensure_started do
    case Process.whereis(__MODULE__) do
      nil -> start_link()
      _pid -> {:ok, :already_started}
    end
  end

  @doc """
  Returns a normalized Model Guard status summary for API and UI consumers.
  """
  @spec model_guard_summary(map() | nil) :: map()
  def model_guard_summary(nil), do: unsupported_model_guard_summary()

  def model_guard_summary(%{scan_result: scan_result, status: status} = provenance) do
    scan_result = scan_result || %{}
    model_guard = scan_result[:model_guard] || scan_result["model_guard"] || %{}
    enforcement = model_guard[:enforcement] || model_guard["enforcement"] || "unsupported"
    normalized_enforcement = normalize_enforcement(enforcement)
    guard_status = model_guard[:status] || model_guard["status"] || status || "unsupported"
    decision = model_guard[:decision] || model_guard["decision"] || decision_from_provenance(provenance)
    action = model_guard[:action] || model_guard["action"] || action_from_guard(decision, normalized_enforcement)
    evidence = model_guard[:evidence] || model_guard["evidence"] || %{}

    %{
      status: normalize_guard_status(guard_status, enforcement),
      decision: decision,
      enforcement: normalized_enforcement,
      action: action,
      evidence: evidence,
      thresholds: model_guard[:thresholds] || model_guard["thresholds"] || %{},
      fp_rationale: model_guard[:fp_rationale] || model_guard["fp_rationale"],
      package_findings: evidence_value(evidence, :package_findings, []),
      package_findings_count: evidence_value(evidence, :package_findings_count, 0),
      package_scanner: evidence_value(evidence, :package_scanner, "not_collected"),
      external_model_scores: evidence_value(evidence, :external_model_scores, []),
      external_model_scores_count: evidence_value(evidence, :external_model_scores_count, 0),
      model_consensus: evidence_value(evidence, :model_consensus, %{}),
      model_consensus_state: evidence_value(evidence, :model_consensus_state, "not_collected"),
      enforcement_note: evidence_value(evidence, :enforcement_note, nil)
    }
  end

  def model_guard_summary(_), do: unsupported_model_guard_summary()

  @doc """
  Determines if a model can be loaded based on its provenance and policy.

  ## Parameters

  - `model_id` - Model identifier (e.g., "meta-llama/Llama-2-7b")

  ## Returns

  - `{:ok, true}` - Model is trusted and can be loaded
  - `{:ok, false, reason}` - Model is blocked, with reason:
    - `"explicitly_blocked"` - Manually blocked via `block_model/2`
    - `"unscanned"` - No provenance record exists
    - `"malicious_model"` - Scan detected as malicious
    - `"high_risk_score"` - Risk score >= 0.3
    - `"scan_pending"` - Scan has not started
    - `"scan_in_progress"` - Scan is currently running
    - `"unknown_status"` - Unknown status value
  """
  @spec can_load?(String.t()) :: {:ok, true} | {:ok, false, String.t()}
  def can_load?(model_id) when is_binary(model_id) do
    # Check explicit block list first
    if explicitly_blocked?(model_id) do
      {:ok, false, "explicitly_blocked"}
    else
      # Check provenance
      case get_latest_provenance(model_id) do
        nil ->
          {:ok, false, "unscanned"}

        %{status: "malicious"} = provenance ->
          if decision_only?(provenance) do
            {:ok, true}
          else
            {:ok, false, "malicious_model"}
          end

        %{status: "suspicious", risk_score: score} = provenance when score >= @block_threshold ->
          if decision_only?(provenance) do
            {:ok, true}
          else
            {:ok, false, "high_risk_score"}
          end

        %{status: "suspicious", risk_score: _score} ->
          # Suspicious but below block threshold
          {:ok, true}

        %{status: "clean"} ->
          {:ok, true}

        %{status: "pending"} ->
          {:ok, false, "scan_pending"}

        %{status: "scanning"} ->
          {:ok, false, "scan_in_progress"}

        %{status: "error"} ->
          {:ok, false, "scan_error"}

        _ ->
          {:ok, false, "unknown_status"}
      end
    end
  end

  @doc """
  Checks if a model is fully trusted (clean with low risk).

  ## Parameters

  - `model_id` - Model identifier

  ## Returns

  - `true` - Model is clean with risk_score < 0.1
  - `false` - Model is not trusted
  """
  @spec is_trusted?(String.t()) :: boolean()
  def is_trusted?(model_id) do
    case get_latest_provenance(model_id) do
      %{status: "clean", risk_score: score} when score < @suspicious_threshold ->
        true

      _ ->
        false
    end
  end

  @doc """
  Lists all blocked models based on risk score or malicious status.

  ## Returns

  List of maps with model information:

      [
        %{
          model_id: "suspicious/model",
          registry: "huggingface",
          risk_score: 0.85,
          status: "malicious",
          scanned_at: ~U[2024-01-15 10:30:00Z]
        }
      ]
  """
  @spec list_blocked() :: [map()]
  def list_blocked do
    query =
      from(p in ModelProvenance,
        where: p.risk_score >= ^@block_threshold or p.status == "malicious",
        order_by: [desc: p.risk_score],
        select: %{
          model_id: p.model_id,
          registry: p.registry,
          risk_score: p.risk_score,
          status: p.status,
          scanned_at: p.scanned_at,
          scan_result: p.scan_result
        }
      )

    query
    |> Repo.all()
    |> Enum.reject(&decision_only?/1)
    |> Enum.map(&Map.delete(&1, :scan_result))
  end

  @doc """
  Explicitly blocks a model with a reason.

  Blocked models will return `{:ok, false, "explicitly_blocked"}` from `can_load?/1`
  regardless of their scan status.

  ## Parameters

  - `model_id` - Model identifier
  - `reason` - Reason for blocking (e.g., "security_review", "manual_block")

  ## Returns

  - `:ok` - Model blocked successfully
  """
  @spec block_model(String.t(), String.t()) :: :ok
  def block_model(model_id, reason) do
    ensure_started()

    Agent.update(__MODULE__, fn blocks ->
      Map.put(blocks, model_id, %{
        blocked_at: DateTime.utc_now(),
        reason: reason
      })
    end)

    Logger.info("[ModelPolicy] Blocked model: #{model_id}, reason: #{reason}")
    :ok
  end

  @doc """
  Removes an explicit block from a model.

  ## Parameters

  - `model_id` - Model identifier

  ## Returns

  - `:ok` - Block removed successfully
  """
  @spec unblock_model(String.t()) :: :ok
  def unblock_model(model_id) do
    ensure_started()

    Agent.update(__MODULE__, fn blocks ->
      Map.delete(blocks, model_id)
    end)

    Logger.info("[ModelPolicy] Unblocked model: #{model_id}")
    :ok
  end

  @doc """
  Checks if a model is explicitly blocked.

  ## Parameters

  - `model_id` - Model identifier

  ## Returns

  - `true` - Model is explicitly blocked
  - `false` - Model is not explicitly blocked
  """
  @spec explicitly_blocked?(String.t()) :: boolean()
  def explicitly_blocked?(model_id) do
    ensure_started()

    Agent.get(__MODULE__, fn blocks ->
      Map.has_key?(blocks, model_id)
    end)
  end

  @doc """
  Returns the list of trusted model patterns from configuration.

  These patterns use glob-style matching (e.g., "meta-llama/*", "openai/*").

  ## Returns

  List of trusted patterns from application config.
  """
  @spec allow_list() :: [String.t()]
  def allow_list do
    Application.get_env(:tamandua_server, :trusted_model_patterns, [])
  end

  @doc """
  Gets the explicit block list.

  ## Returns

  Map of model_id => %{blocked_at: DateTime.t(), reason: String.t()}
  """
  @spec get_block_list() :: map()
  def get_block_list do
    ensure_started()
    Agent.get(__MODULE__, fn blocks -> blocks end)
  end

  @doc """
  Triggers auto-quarantine for a model that failed security scan.

  This function is called when:
  1. A model scan completes with malicious status
  2. A model's risk score exceeds the block threshold
  3. A behavioral anomaly is detected during model loading

  The function will:
  1. Block the model via `block_model/2`
  2. Find agents that have loaded this model
  3. Trigger quarantine on those agents via ModelQuarantineHandler

  ## Parameters

  - `model_id` - Model identifier (e.g., "meta-llama/Llama-2-7b")
  - `model_path` - Path to the model file on the agent (if known)
  - `agent_id` - Agent ID where the model was detected (optional)
  - `detection_info` - Map with detection details

  ## Returns

  - `{:ok, results}` - Quarantine triggered, with results per agent
  - `{:error, reason}` - Failed to trigger quarantine
  """
  @spec auto_quarantine(String.t(), String.t() | nil, String.t() | nil, map()) ::
          {:ok, list(map())} | {:error, term()}
  def auto_quarantine(model_id, model_path, agent_id, detection_info) do
    Logger.warning("[ModelPolicy] Auto-quarantine triggered for model: #{model_id}")

    # Block the model first
    reason = detection_info["reason"] || detection_info[:reason] || "security_scan_failed"
    block_model(model_id, reason)

    # If we have a specific agent and path, quarantine on that agent
    if agent_id && model_path do
      case TamanduaServer.Quarantine.ModelQuarantineHandler.trigger_auto_quarantine(
             agent_id,
             model_path,
             detection_info
           ) do
        {:ok, result} ->
          Logger.info("[ModelPolicy] Quarantine triggered on agent #{agent_id}")
          {:ok, [%{agent_id: agent_id, status: "quarantine_initiated", result: result}]}

        {:error, reason} ->
          Logger.error("[ModelPolicy] Failed to trigger quarantine: #{inspect(reason)}")
          {:error, reason}
      end
    else
      # Find all agents that might have this model and quarantine
      quarantine_on_known_agents(model_id, detection_info)
    end
  end

  @doc """
  Handles scan completion and triggers auto-quarantine if needed.

  Called by the scan pipeline when a model scan completes.

  ## Parameters

  - `model_id` - Model identifier
  - `scan_result` - Map with scan results including status and risk_score

  ## Returns

  - `:ok` - No action needed (model is clean)
  - `{:quarantine, results}` - Auto-quarantine was triggered
  """
  @spec handle_scan_complete(String.t(), map()) :: :ok | {:quarantine, list(map())}
  def handle_scan_complete(model_id, scan_result) do
    status = scan_result["status"] || scan_result[:status]
    risk_score = scan_result["risk_score"] || scan_result[:risk_score] || 0.0
    decision_only? = decision_only?(%{scan_result: scan_result})

    cond do
      status == "malicious" and not decision_only? ->
        detection_info = %{
          detection_source: "model_security_scan",
          reason: "malicious_model",
          threat_name: scan_result["threat_name"],
          confidence: risk_score
        }

        case auto_quarantine(model_id, nil, nil, detection_info) do
          {:ok, results} -> {:quarantine, results}
          {:error, _} -> :ok
        end

      risk_score >= @block_threshold and not decision_only? ->
        detection_info = %{
          detection_source: "model_security_scan",
          reason: "high_risk_score",
          confidence: risk_score
        }

        case auto_quarantine(model_id, nil, nil, detection_info) do
          {:ok, results} -> {:quarantine, results}
          {:error, _} -> :ok
        end

      true ->
        :ok
    end
  end

  # Private Functions

  defp get_latest_provenance(model_id) do
    query =
      from(p in ModelProvenance,
        where: p.model_id == ^model_id,
        order_by: [desc: p.downloaded_at],
        limit: 1
      )

    Repo.one(query)
  end

  defp unsupported_model_guard_summary do
    %{
      status: "unsupported",
      decision: "unknown",
      enforcement: "unsupported",
      action: "none",
      evidence: %{},
      thresholds: %{},
      fp_rationale: "No Model Guard scan evidence is available for this model.",
      package_findings: [],
      package_findings_count: 0,
      package_scanner: "not_collected",
      external_model_scores: [],
      external_model_scores_count: 0,
      model_consensus: %{},
      model_consensus_state: "not_collected",
      enforcement_note: "Model Guard evidence has not been collected."
    }
  end

  defp evidence_value(evidence, key, default) when is_map(evidence) do
    Map.get(evidence, key) || Map.get(evidence, to_string(key)) || default
  end

  defp evidence_value(_, _key, default), do: default

  defp normalize_guard_status(status, _enforcement) when status in [:failed, "failed", :error, "error"],
    do: "failed"

  defp normalize_guard_status(status, _enforcement) when status in [:degraded, "degraded"],
    do: "degraded"

  defp normalize_guard_status(status, _enforcement)
       when status in [:unsupported, "unsupported", :not_supported, "not_supported"],
       do: "unsupported"

  defp normalize_guard_status(_status, enforcement) when enforcement in [:decision_only, "decision_only"],
    do: "decision_only"

  defp normalize_guard_status(_status, enforcement) when enforcement in [:enforced, "enforced"],
    do: "enforced"

  defp normalize_guard_status(status, _enforcement) when status in ["pending", "scanning"],
    do: to_string(status)

  defp normalize_guard_status(_, _), do: "unsupported"

  defp normalize_enforcement(enforcement) when enforcement in [:decision_only, "decision_only"],
    do: "decision_only"

  defp normalize_enforcement(enforcement) when enforcement in [:enforced, "enforced"], do: "enforced"
  defp normalize_enforcement(enforcement) when enforcement in [:failed, "failed"], do: "failed"
  defp normalize_enforcement(enforcement) when enforcement in [:degraded, "degraded"], do: "degraded"
  defp normalize_enforcement(_), do: "unsupported"

  defp decision_from_provenance(%{status: "clean"}), do: "allow"
  defp decision_from_provenance(%{status: "suspicious"}), do: "review"
  defp decision_from_provenance(%{status: "malicious"}), do: "block"
  defp decision_from_provenance(_), do: "unknown"

  defp action_from_guard("block", "enforced"), do: "block_load"
  defp action_from_guard("block", "decision_only"), do: "report_only"
  defp action_from_guard("review", _), do: "allow_with_review"
  defp action_from_guard("allow", _), do: "allow"
  defp action_from_guard(_, _), do: "none"

  defp decision_only?(%{scan_result: scan_result}) when is_map(scan_result) do
    model_guard = scan_result[:model_guard] || scan_result["model_guard"] || %{}
    enforcement = model_guard[:enforcement] || model_guard["enforcement"]

    enforcement in [:decision_only, "decision_only"]
  end

  defp decision_only?(_), do: false

  defp quarantine_on_known_agents(model_id, detection_info) do
    # In a full implementation, this would:
    # 1. Query the AI Asset Inventory for agents that have loaded this model
    # 2. Get the model path on each agent
    # 3. Trigger quarantine on each agent
    #
    # For now, we log and return success (agents will need explicit paths)
    Logger.info(
      "[ModelPolicy] Model #{model_id} blocked - agents with this model should be quarantined"
    )

    # Try to find agents via AI inventory if available
    try do
      case TamanduaServer.AISecurity.AIInventory.find_agents_with_model(model_id) do
        {:ok, agents} when agents != [] ->
          results =
            Enum.map(agents, fn agent_info ->
              agent_id = agent_info[:agent_id] || agent_info["agent_id"]
              model_path = agent_info[:path] || agent_info["path"]

              if model_path do
                case TamanduaServer.Quarantine.ModelQuarantineHandler.trigger_auto_quarantine(
                       agent_id,
                       model_path,
                       detection_info
                     ) do
                  {:ok, result} ->
                    %{agent_id: agent_id, status: "quarantine_initiated", result: result}

                  {:error, reason} ->
                    %{agent_id: agent_id, status: "failed", error: inspect(reason)}
                end
              else
                %{agent_id: agent_id, status: "skipped", error: "no_path_available"}
              end
            end)

          {:ok, results}

        _ ->
          {:ok, []}
      end
    rescue
      _ ->
        # AI Inventory not available
        {:ok, []}
    catch
      _, _ ->
        {:ok, []}
    end
  end
end
