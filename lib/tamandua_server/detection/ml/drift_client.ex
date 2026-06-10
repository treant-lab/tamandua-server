defmodule TamanduaServer.Detection.ML.DriftClient do
  @moduledoc """
  HTTP client for ML service drift detection endpoints.

  Provides communication with the LLM drift detection endpoints:
  - Submit samples for drift monitoring
  - Check for drift
  - Retrieve statistics and alerts
  """

  require Logger

  @ml_service_url Application.compile_env(:tamandua_server, :ml_service_url, "http://localhost:8000")
  @timeout 30_000

  @doc """
  Check LLM output drift via ML service.
  """
  @spec check_llm_drift(String.t(), String.t(), list()) :: {:ok, map()} | {:error, term()}
  def check_llm_drift(agent_id, model_id, samples) do
    url = "#{ml_service_url()}/llm-drift/check"

    body = Jason.encode!(%{
      agent_id: agent_id,
      model_id: model_id,
      check_all_metrics: false
    })

    # First, submit samples
    submit_samples(samples)

    # Then check drift
    case Req.post(url, body: body, headers: json_headers(), receive_timeout: @timeout) do
      {:ok, %{status: 200, body: result}} ->
        {:ok, %{
          overall_drift_detected: result["overall_drift_detected"],
          drift_score: calculate_drift_score(result),
          token_drift: result["token_drift"],
          confidence_drift: result["confidence_drift"],
          alerts: result["alerts_generated"] || 0,
          recommendation: result["recommendation"]
        }}

      {:ok, %{status: status, body: body}} ->
        Logger.warning("[DriftClient] Unexpected status #{status}: #{inspect(body)}")
        {:error, {:http_error, status}}

      {:error, reason} ->
        Logger.error("[DriftClient] Request failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Submit a single sample for drift monitoring.
  """
  @spec submit_sample(map()) :: {:ok, map()} | {:error, term()}
  def submit_sample(sample) do
    url = "#{ml_service_url()}/llm-drift/sample"

    body = Jason.encode!(%{
      agent_id: sample.agent_id,
      model_id: sample.model_id,
      output_tokens: sample.output_tokens,
      confidence: sample.confidence,
      latency_ms: sample.latency_ms,
      response_category: sample.response_category,
      timestamp: DateTime.to_iso8601(sample.timestamp)
    })

    case Req.post(url, body: body, headers: json_headers(), receive_timeout: 5_000) do
      {:ok, %{status: 200, body: result}} -> {:ok, result}
      {:ok, %{status: status}} -> {:error, {:http_error, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Get active drift alerts from ML service.
  """
  @spec get_active_alerts() :: {:ok, list()} | {:error, term()}
  def get_active_alerts do
    url = "#{ml_service_url()}/llm-drift/alerts/active"

    case Req.get(url, headers: json_headers(), receive_timeout: @timeout) do
      {:ok, %{status: 200, body: alerts}} -> {:ok, alerts}
      {:ok, %{status: status}} -> {:error, {:http_error, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Get drift statistics from ML service.
  """
  @spec get_statistics() :: {:ok, map()} | {:error, term()}
  def get_statistics do
    url = "#{ml_service_url()}/llm-drift/statistics"

    case Req.get(url, headers: json_headers(), receive_timeout: @timeout) do
      {:ok, %{status: 200, body: stats}} -> {:ok, stats}
      {:ok, %{status: status}} -> {:error, {:http_error, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Get baseline information for a model.
  """
  @spec get_baseline(String.t()) :: {:ok, map()} | {:error, term()}
  def get_baseline(model_id) do
    url = "#{ml_service_url()}/llm-drift/baseline/#{model_id}"

    case Req.get(url, headers: json_headers(), receive_timeout: @timeout) do
      {:ok, %{status: 200, body: baseline}} -> {:ok, baseline}
      {:ok, %{status: 404}} -> {:error, :not_found}
      {:ok, %{status: status}} -> {:error, {:http_error, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Establish a new baseline for a model.
  """
  @spec establish_baseline(String.t(), list()) :: {:ok, map()} | {:error, term()}
  def establish_baseline(model_id, samples) do
    url = "#{ml_service_url()}/llm-drift/baseline/establish"

    body = Jason.encode!(%{
      model_id: model_id,
      samples: Enum.map(samples, fn s ->
        %{
          agent_id: s.agent_id,
          model_id: s.model_id,
          output_tokens: s.output_tokens,
          confidence: s.confidence,
          latency_ms: s.latency_ms,
          response_category: s.response_category,
          timestamp: DateTime.to_iso8601(s.timestamp)
        }
      end)
    })

    case Req.post(url, body: body, headers: json_headers(), receive_timeout: @timeout) do
      {:ok, %{status: 200, body: result}} -> {:ok, result}
      {:ok, %{status: status, body: body}} ->
        Logger.warning("[DriftClient] Baseline establishment failed #{status}: #{inspect(body)}")
        {:error, {:http_error, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Request root cause analysis from the ML service.

  Provides deep analysis of why drift occurred, including:
  - Feature attribution (which features caused drift)
  - Gradual drift detection (ADWIN algorithm)
  - Remediation recommendations
  """
  @spec request_root_cause_analysis(String.t(), map(), map()) :: {:ok, map()} | {:error, term()}
  def request_root_cause_analysis(model_id, baseline_data, current_data) do
    url = "#{ml_service_url()}/drift-root-cause/analyze"

    # Convert data maps to feature samples format
    features = baseline_data
      |> Map.keys()
      |> Enum.filter(fn key -> Map.has_key?(current_data, key) end)
      |> Enum.map(fn key ->
        %{
          feature_name: key,
          baseline_values: Map.get(baseline_data, key, []),
          current_values: Map.get(current_data, key, [])
        }
      end)

    body = Jason.encode!(%{
      features: features,
      model_id: model_id,
      include_gradual_analysis: true,
      include_recommendations: true
    })

    case Req.post(url, body: body, headers: json_headers(), receive_timeout: 60_000) do
      {:ok, %{status: 200, body: result}} ->
        {:ok, result}

      {:ok, %{status: status, body: body}} ->
        Logger.warning("[DriftClient] Root cause analysis failed #{status}: #{inspect(body)}")
        {:error, {:http_error, status}}

      {:error, reason} ->
        Logger.error("[DriftClient] Root cause analysis request failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Detect gradual drift using ADWIN algorithm.
  """
  @spec detect_gradual_drift(list(list(float())), keyword()) :: {:ok, map()} | {:error, term()}
  def detect_gradual_drift(time_series_data, opts \\ []) do
    url = "#{ml_service_url()}/drift-root-cause/gradual-drift"

    body = Jason.encode!(%{
      time_series_data: time_series_data,
      feature_names: Keyword.get(opts, :feature_names),
      adwin_delta: Keyword.get(opts, :adwin_delta, 0.002)
    })

    case Req.post(url, body: body, headers: json_headers(), receive_timeout: @timeout) do
      {:ok, %{status: 200, body: result}} -> {:ok, result}
      {:ok, %{status: status}} -> {:error, {:http_error, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Get drift root cause analysis history.
  """
  @spec get_root_cause_history(keyword()) :: {:ok, map()} | {:error, term()}
  def get_root_cause_history(opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    url = "#{ml_service_url()}/drift-root-cause/history?limit=#{limit}"

    case Req.get(url, headers: json_headers(), receive_timeout: @timeout) do
      {:ok, %{status: 200, body: result}} -> {:ok, result}
      {:ok, %{status: status}} -> {:error, {:http_error, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Get feature attribution for drift.
  """
  @spec calculate_feature_attribution(map(), map()) :: {:ok, list()} | {:error, term()}
  def calculate_feature_attribution(baseline_data, current_data) do
    url = "#{ml_service_url()}/drift-root-cause/attribution"

    features = baseline_data
      |> Map.keys()
      |> Enum.filter(fn key -> Map.has_key?(current_data, key) end)
      |> Enum.map(fn key ->
        %{
          feature_name: key,
          baseline_values: Map.get(baseline_data, key, []),
          current_values: Map.get(current_data, key, [])
        }
      end)

    body = Jason.encode!(%{features: features})

    case Req.post(url, body: body, headers: json_headers(), receive_timeout: @timeout) do
      {:ok, %{status: 200, body: result}} -> {:ok, result}
      {:ok, %{status: status}} -> {:error, {:http_error, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp submit_samples(samples) do
    url = "#{ml_service_url()}/llm-drift/samples/batch"

    body = Jason.encode!(Enum.map(samples, fn sample ->
      %{
        agent_id: sample.agent_id,
        model_id: sample.model_id,
        output_tokens: sample.output_tokens,
        confidence: sample.confidence,
        latency_ms: sample.latency_ms,
        response_category: sample.response_category,
        timestamp: DateTime.to_iso8601(sample.timestamp)
      }
    end))

    # Fire and forget batch submission
    Task.start(fn ->
      Req.post(url, body: body, headers: json_headers(), receive_timeout: @timeout)
    end)
  end

  defp calculate_drift_score(result) do
    scores = [
      get_in(result, ["token_drift", "value"]),
      get_in(result, ["confidence_drift", "value"])
    ]
    |> Enum.reject(&is_nil/1)

    if Enum.empty?(scores), do: 0.0, else: Enum.max(scores)
  end

  defp ml_service_url do
    Application.get_env(:tamandua_server, :ml_service_url, @ml_service_url)
  end

  defp json_headers do
    [{"content-type", "application/json"}, {"accept", "application/json"}]
  end
end
