defmodule TamanduaServer.Detection.AdversarialFilter do
  @moduledoc """
  Adversarial input filter for ML inference pipeline.

  Integrates with the detection engine to reject adversarial inputs
  before they reach the model. Implements multi-layer detection:
  - Layer 1 (bounds): <5ms fast rejection
  - Layer 2 (anomaly): <50ms feature anomaly
  - Layer 3 (signature): <200ms perturbation detection
  """

  require Logger
  alias Phoenix.PubSub
  alias TamanduaServer.Detection.ML.AdversarialClient
  alias TamanduaServer.Alerts

  @rejection_threshold 0.7  # Confidence threshold for rejection

  @doc """
  Filter input through adversarial detection.

  Returns:
  - {:ok, :clean} - Input passed all checks
  - {:ok, :rejected, result} - Input detected as adversarial
  - {:error, reason} - Detection failed
  """
  @spec filter(list(float()), list(float()) | nil, keyword()) ::
    {:ok, :clean} | {:ok, :rejected, map()} | {:error, term()}
  def filter(features, reference \\ nil, opts \\ []) do
    run_all = Keyword.get(opts, :run_all_layers, false)
    agent_id = Keyword.get(opts, :agent_id, "unknown")
    organization_id = Keyword.get(opts, :organization_id)

    case AdversarialClient.check(features, reference, run_all) do
      {:ok, result} when result.is_adversarial and result.confidence >= @rejection_threshold ->
        # Log and alert
        log_rejection(agent_id, result)
        create_alert(agent_id, organization_id, result)
        broadcast_event(agent_id, result)
        {:ok, :rejected, result}

      {:ok, result} when result.is_adversarial ->
        # Detected but below threshold - log only
        Logger.info("[AdversarialFilter] Low-confidence detection",
          agent_id: agent_id,
          type: result.adversarial_type,
          confidence: result.confidence
        )
        {:ok, :clean}

      {:ok, _result} ->
        {:ok, :clean}

      {:error, reason} ->
        Logger.warning("[AdversarialFilter] Detection failed, allowing input",
          agent_id: agent_id,
          reason: inspect(reason)
        )
        # Fail open - allow input if detection fails
        {:ok, :clean}
    end
  end

  @doc """
  Filter batch of inputs.
  """
  @spec filter_batch(list(map()), keyword()) :: list({:ok, :clean | :rejected} | {:error, term()})
  def filter_batch(requests, opts \\ []) do
    agent_id = Keyword.get(opts, :agent_id, "unknown")
    organization_id = Keyword.get(opts, :organization_id)

    case AdversarialClient.batch_check(requests) do
      {:ok, results} ->
        Enum.zip(requests, results)
        |> Enum.map(fn {_req, result} ->
          if result.is_adversarial and result.confidence >= @rejection_threshold do
            log_rejection(agent_id, result)
            create_alert(agent_id, organization_id, result)
            {:ok, :rejected}
          else
            {:ok, :clean}
          end
        end)

      {:error, _reason} ->
        # Fail open for batch
        Enum.map(requests, fn _ -> {:ok, :clean} end)
    end
  end

  @doc """
  Check if input is adversarial without filtering (returns result only).
  """
  @spec check(list(float()), list(float()) | nil, keyword()) :: {:ok, map()} | {:error, term()}
  def check(features, reference \\ nil, opts \\ []) do
    run_all = Keyword.get(opts, :run_all_layers, false)
    AdversarialClient.check(features, reference, run_all)
  end

  @doc """
  Get detection statistics.
  """
  @spec get_statistics() :: {:ok, map()} | {:error, term()}
  def get_statistics do
    AdversarialClient.get_statistics()
  end

  @doc """
  Get current detection configuration.
  """
  @spec get_config() :: {:ok, map()} | {:error, term()}
  def get_config do
    AdversarialClient.get_config()
  end

  @doc """
  Update detection configuration.
  """
  @spec update_config(map()) :: {:ok, map()} | {:error, term()}
  def update_config(config_updates) do
    AdversarialClient.update_config(config_updates)
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp log_rejection(agent_id, result) do
    Logger.warning("[AdversarialFilter] Rejected adversarial input",
      agent_id: agent_id,
      type: result.adversarial_type,
      confidence: result.confidence,
      layer: result.detection_layer,
      details: result.details
    )
  end

  defp create_alert(agent_id, organization_id, result) do
    severity = if result.confidence > 0.9, do: "critical", else: "high"

    alert_params = %{
      title: "Adversarial input detected",
      message: "#{result.adversarial_type} attack detected with #{Float.round(result.confidence * 100, 1)}% confidence",
      severity: severity,
      category: "adversarial",
      agent_id: agent_id,
      rule_name: "adversarial_input_detection",
      metadata: %{
        adversarial_type: result.adversarial_type,
        confidence: result.confidence,
        detection_layer: result.detection_layer,
        details: result.details,
        latency_ms: result.latency_ms
      }
    }

    # Create alert with organization scope if provided
    result = if organization_id do
      Alerts.create_alert_for_org(organization_id, alert_params)
    else
      Alerts.create_alert(alert_params)
    end

    case result do
      {:ok, alert} ->
        Logger.debug("[AdversarialFilter] Alert created: #{alert.id}")
        {:ok, alert}

      {:error, reason} ->
        Logger.error("[AdversarialFilter] Failed to create alert: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp broadcast_event(agent_id, result) do
    PubSub.broadcast(
      TamanduaServer.PubSub,
      "adversarial:rejected",
      {:adversarial_rejected, %{
        agent_id: agent_id,
        adversarial_type: result.adversarial_type,
        confidence: result.confidence,
        detection_layer: result.detection_layer,
        timestamp: DateTime.utc_now()
      }}
    )
  end
end
