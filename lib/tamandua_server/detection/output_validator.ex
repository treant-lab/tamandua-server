defmodule TamanduaServer.Detection.OutputValidator do
  @moduledoc """
  Orchestrator for output validation combining PII, harmful content, and token anomaly checks.

  Subscribes to `inference:all` PubSub topic for automatic validation on `:inference_complete`.

  Usage:
      {:ok, result} = OutputValidator.validate(session)
      case result.overall_risk do
        :critical -> # Alert and block
        :high -> # Alert
        :medium -> # Log
        :low -> # Pass
      end
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub

  alias TamanduaServer.Detection.PIIDetector
  alias TamanduaServer.Detection.HarmfulContentClassifier
  alias TamanduaServer.Detection.TokenAnomalyDetector
  alias TamanduaServer.Detection.InferenceTracker

  # ============================================================================
  # Type Definitions
  # ============================================================================

  @type risk_level :: :low | :medium | :high | :critical

  @type validation_result :: %{
          pii: map(),
          harmful: map(),
          token_anomaly: map(),
          overall_risk: risk_level(),
          latency_ms: non_neg_integer(),
          violations: list(String.t())
        }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Validate output content from an inference session or raw text.

  Accepts either:
  - `InferenceTracker.Session` struct
  - Raw text string

  ## Options
    - `:skip_pii` - Skip PII detection (default: false)
    - `:skip_harmful` - Skip harmful content detection (default: false)
    - `:skip_token_anomaly` - Skip token anomaly detection (default: false)
    - `:agent_id` - Required if passing raw text for token anomaly check

  ## Returns
    `{:ok, validation_result}`
  """
  @spec validate(InferenceTracker.Session.t() | String.t(), keyword()) ::
          {:ok, validation_result()}
  def validate(session_or_text, opts \\ []) do
    GenServer.call(__MODULE__, {:validate, session_or_text, opts}, 10_000)
  end

  @doc """
  Validate output asynchronously.

  Returns a Task that can be awaited.
  """
  @spec validate_async(InferenceTracker.Session.t() | String.t(), keyword()) :: Task.t()
  def validate_async(session_or_text, opts \\ []) do
    Task.async(fn -> validate(session_or_text, opts) end)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Subscribe to inference events
    PubSub.subscribe(TamanduaServer.PubSub, "inference:all")

    Logger.info("[OutputValidator] Started")
    {:ok, %{}}
  end

  @impl true
  def handle_call({:validate, session_or_text, opts}, _from, state) do
    start_time = System.monotonic_time(:millisecond)

    {text, agent_id, token_count, session_id} = extract_validation_data(session_or_text, opts)

    # Run validation checks in parallel where possible
    skip_pii = Keyword.get(opts, :skip_pii, false)
    skip_harmful = Keyword.get(opts, :skip_harmful, false)
    skip_token_anomaly = Keyword.get(opts, :skip_token_anomaly, false)

    # Start parallel tasks
    pii_task =
      if skip_pii do
        Task.async(fn -> {:ok, default_pii_result()} end)
      else
        Task.async(fn -> PIIDetector.detect(text) end)
      end

    harmful_task =
      if skip_harmful do
        Task.async(fn -> {:ok, default_harmful_result()} end)
      else
        Task.async(fn -> HarmfulContentClassifier.classify(text, use_ml: true) end)
      end

    token_anomaly_task =
      if skip_token_anomaly or agent_id == nil or token_count == nil do
        Task.async(fn -> {:ok, default_token_anomaly_result()} end)
      else
        Task.async(fn -> TokenAnomalyDetector.detect(agent_id, token_count) end)
      end

    # Await results (with timeout). Classifiers can return {:error, _} (e.g.
    # HarmfulContentClassifier rescues internal exceptions into an error tuple),
    # so fall back to the same safe defaults the skip paths use instead of
    # crashing the caller on a MatchError.
    # Use Task.yield + Task.shutdown rather than Task.await: on timeout
    # Task.await EXITS the caller (the surrounding case cannot catch it),
    # whereas yield returns nil so we can fall back to safe defaults.
    pii_result =
      case Task.yield(pii_task, 5000) || Task.shutdown(pii_task) do
        {:ok, {:ok, r}} -> r
        _ -> default_pii_result()
      end

    harmful_result =
      case Task.yield(harmful_task, 5000) || Task.shutdown(harmful_task) do
        {:ok, {:ok, r}} -> r
        _ -> default_harmful_result()
      end

    token_anomaly_result =
      case Task.yield(token_anomaly_task, 5000) || Task.shutdown(token_anomaly_task) do
        {:ok, {:ok, r}} -> r
        _ -> default_token_anomaly_result()
      end

    # Calculate overall risk
    {overall_risk, violations} =
      calculate_risk(pii_result, harmful_result, token_anomaly_result)

    elapsed = System.monotonic_time(:millisecond) - start_time

    result = %{
      pii: pii_result,
      harmful: harmful_result,
      token_anomaly: token_anomaly_result,
      overall_risk: overall_risk,
      latency_ms: elapsed,
      violations: violations
    }

    # Create alert if high or critical risk
    if overall_risk in [:high, :critical] do
      create_alert(agent_id, session_id, result)
    end

    # Emit telemetry
    :telemetry.execute(
      [:tamandua, :output_validation, :complete],
      %{latency_ms: elapsed},
      %{
        overall_risk: overall_risk,
        has_pii: pii_result.has_pii,
        is_harmful: harmful_result.is_harmful,
        is_token_anomaly: token_anomaly_result.is_anomaly,
        violation_count: length(violations)
      }
    )

    {:reply, {:ok, result}, state}
  end

  @impl true
  def handle_info({:inference_complete, session}, state) do
    # Auto-validate completed inference sessions
    Task.start(fn ->
      try do
        text = get_response_text(session)

        if text && String.length(text) > 0 do
          {:ok, result} = validate(session)

          Logger.debug(
            "[OutputValidator] Auto-validated session #{session.session_id}: risk=#{result.overall_risk}"
          )
        end
      rescue
        e ->
          Logger.warning(
            "[OutputValidator] Auto-validation failed for session #{session.session_id}: #{Exception.message(e)}"
          )
      end
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp extract_validation_data(%InferenceTracker.Session{} = session, _opts) do
    text = get_response_text(session)
    agent_id = session.agent_id

    token_count =
      if session.metrics && session.metrics.token_count do
        session.metrics.token_count
      else
        nil
      end

    {text || "", agent_id, token_count, session.session_id}
  end

  defp extract_validation_data(text, opts) when is_binary(text) do
    agent_id = Keyword.get(opts, :agent_id)
    token_count = Keyword.get(opts, :token_count)
    session_id = Keyword.get(opts, :session_id)
    {text, agent_id, token_count, session_id}
  end

  defp get_response_text(%InferenceTracker.Session{response: nil}), do: nil

  defp get_response_text(%InferenceTracker.Session{response: response}) do
    response[:response_preview] || response["response_preview"]
  end

  defp default_pii_result do
    %{has_pii: false, pii_types: [], matches: [], latency_ms: 0}
  end

  defp default_harmful_result do
    %{
      is_harmful: false,
      category: nil,
      confidence: 0.0,
      matched_patterns: [],
      analysis_method: :regex,
      latency_ms: 0,
      severity: nil
    }
  end

  defp default_token_anomaly_result do
    %{is_anomaly: false, anomaly_score: 0.0, anomaly_type: nil, details: %{}}
  end

  defp calculate_risk(pii_result, harmful_result, token_anomaly_result) do
    violations = []

    # Critical: harmful content in violence or self_harm category
    violations =
      if harmful_result.is_harmful and harmful_result.category in [:violence, :self_harm] do
        violations ++ ["harmful_content:#{harmful_result.category}"]
      else
        violations
      end

    # High: PII detected
    violations =
      if pii_result.has_pii do
        pii_desc = pii_result.pii_types |> Enum.join(",")
        violations ++ ["pii_detected:#{pii_desc}"]
      else
        violations
      end

    # High: harmful content with high confidence
    violations =
      if harmful_result.is_harmful and harmful_result.confidence > 0.7 and
           harmful_result.category not in [:violence, :self_harm] do
        violations ++ ["harmful_content:#{harmful_result.category}"]
      else
        violations
      end

    # High: token anomaly with high score
    violations =
      if token_anomaly_result.is_anomaly and token_anomaly_result.anomaly_score > 0.9 do
        violations ++ ["token_anomaly:#{token_anomaly_result.anomaly_type}"]
      else
        violations
      end

    # Medium: harmful content with moderate confidence
    violations =
      if harmful_result.is_harmful and harmful_result.confidence >= 0.3 and
           harmful_result.confidence <= 0.7 and
           harmful_result.category not in [:violence, :self_harm] do
        violations ++ ["harmful_content_moderate:#{harmful_result.category}"]
      else
        violations
      end

    # Medium: token anomaly with moderate score
    violations =
      if token_anomaly_result.is_anomaly and token_anomaly_result.anomaly_score >= 0.5 and
           token_anomaly_result.anomaly_score <= 0.9 do
        violations ++ ["token_anomaly_moderate:#{token_anomaly_result.anomaly_type}"]
      else
        violations
      end

    # Determine overall risk level
    overall_risk =
      cond do
        harmful_result.is_harmful and harmful_result.category in [:violence, :self_harm] ->
          :critical

        pii_result.has_pii ->
          :high

        harmful_result.is_harmful and harmful_result.confidence > 0.7 ->
          :high

        token_anomaly_result.is_anomaly and token_anomaly_result.anomaly_score > 0.9 ->
          :high

        harmful_result.is_harmful and harmful_result.confidence >= 0.3 ->
          :medium

        token_anomaly_result.is_anomaly and token_anomaly_result.anomaly_score >= 0.5 ->
          :medium

        true ->
          :low
      end

    {overall_risk, violations}
  end

  defp create_alert(agent_id, session_id, result) do
    alert_attrs = %{
      agent_id: agent_id,
      type: "output_validation_violation",
      severity: risk_to_severity(result.overall_risk),
      title: "Output validation violation detected",
      description: build_alert_description(result),
      category: "ai_runtime",
      metadata: %{
        session_id: session_id,
        overall_risk: result.overall_risk,
        violations: result.violations,
        pii_types: result.pii.pii_types,
        harmful_category: result.harmful.category,
        token_anomaly_type: result.token_anomaly.anomaly_type
      }
    }

    # Try to create alert, but don't fail validation if alert creation fails
    try do
      case TamanduaServer.Alerts.create_alert(alert_attrs) do
        {:ok, alert} ->
          Logger.info(
            "[OutputValidator] Created alert #{alert.id} for agent #{agent_id}: risk=#{result.overall_risk}"
          )

        {:error, reason} ->
          Logger.warning(
            "[OutputValidator] Failed to create alert: #{inspect(reason)}"
          )
      end
    rescue
      e ->
        Logger.warning(
          "[OutputValidator] Alert creation error: #{Exception.message(e)}"
        )
    end
  end

  defp risk_to_severity(:critical), do: "critical"
  defp risk_to_severity(:high), do: "high"
  defp risk_to_severity(:medium), do: "medium"
  defp risk_to_severity(:low), do: "low"

  defp build_alert_description(result) do
    parts = []

    parts =
      if result.pii.has_pii do
        pii_types = Enum.join(result.pii.pii_types, ", ")
        parts ++ ["PII detected: #{pii_types}"]
      else
        parts
      end

    parts =
      if result.harmful.is_harmful do
        parts ++
          ["Harmful content: #{result.harmful.category} (confidence: #{Float.round(result.harmful.confidence, 2)})"]
      else
        parts
      end

    parts =
      if result.token_anomaly.is_anomaly do
        parts ++
          ["Token anomaly: #{result.token_anomaly.anomaly_type} (score: #{Float.round(result.token_anomaly.anomaly_score, 2)})"]
      else
        parts
      end

    case parts do
      [] -> "Output validation triggered with risk level: #{result.overall_risk}"
      _ -> Enum.join(parts, "; ")
    end
  end
end
