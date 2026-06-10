defmodule TamanduaServer.Detection.ML.AdversarialClient do
  @moduledoc """
  HTTP client for ML service adversarial detection endpoints.

  Provides communication with the adversarial detection API:
  - Single input checking
  - Batch checking
  - Statistics retrieval
  - Configuration management
  """

  require Logger

  @ml_service_url Application.compile_env(:tamandua_server, :ml_service_url, "http://localhost:8000")
  @timeout 5_000  # 5 second timeout for fast-path detection

  @doc """
  Check if input features are adversarial.

  Returns {:ok, result} or {:error, reason}.
  """
  @spec check(list(float()), list(float()) | nil, boolean()) :: {:ok, map()} | {:error, term()}
  def check(features, reference_features \\ nil, run_all_layers \\ false) do
    url = "#{ml_service_url()}/adversarial/check"

    body = Jason.encode!(%{
      features: features,
      reference_features: reference_features,
      run_all_layers: run_all_layers
    })

    case Req.post(url, body: body, headers: json_headers(), receive_timeout: @timeout) do
      {:ok, %{status: 200, body: result}} ->
        {:ok, %{
          is_adversarial: result["is_adversarial"],
          adversarial_type: result["adversarial_type"],
          confidence: result["confidence"],
          detection_layer: result["detection_layer"],
          latency_ms: result["latency_ms"],
          details: result["details"]
        }}

      {:ok, %{status: status, body: body}} ->
        Logger.warning("[AdversarialClient] Unexpected status #{status}: #{inspect(body)}")
        {:error, {:http_error, status}}

      {:error, reason} ->
        Logger.error("[AdversarialClient] Request failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Check multiple inputs in batch.
  """
  @spec batch_check(list(map())) :: {:ok, list(map())} | {:error, term()}
  def batch_check(requests) do
    url = "#{ml_service_url()}/adversarial/batch-check"

    body = Jason.encode!(%{
      requests: Enum.map(requests, fn req ->
        %{
          features: req.features,
          reference_features: Map.get(req, :reference_features),
          run_all_layers: Map.get(req, :run_all_layers, false)
        }
      end)
    })

    case Req.post(url, body: body, headers: json_headers(), receive_timeout: @timeout * 2) do
      {:ok, %{status: 200, body: results}} ->
        {:ok, Enum.map(results, fn r ->
          %{
            is_adversarial: r["is_adversarial"],
            adversarial_type: r["adversarial_type"],
            confidence: r["confidence"],
            detection_layer: r["detection_layer"],
            latency_ms: r["latency_ms"],
            details: r["details"]
          }
        end)}

      {:ok, %{status: status}} -> {:error, {:http_error, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Get adversarial detection statistics.
  """
  @spec get_statistics() :: {:ok, map()} | {:error, term()}
  def get_statistics do
    url = "#{ml_service_url()}/adversarial/statistics"

    case Req.get(url, headers: json_headers(), receive_timeout: @timeout) do
      {:ok, %{status: 200, body: stats}} -> {:ok, stats}
      {:ok, %{status: status}} -> {:error, {:http_error, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Get current adversarial detection configuration.
  """
  @spec get_config() :: {:ok, map()} | {:error, term()}
  def get_config do
    url = "#{ml_service_url()}/adversarial/config"

    case Req.get(url, headers: json_headers(), receive_timeout: @timeout) do
      {:ok, %{status: 200, body: config}} -> {:ok, config}
      {:ok, %{status: status}} -> {:error, {:http_error, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Update adversarial detection configuration.
  """
  @spec update_config(map()) :: {:ok, map()} | {:error, term()}
  def update_config(config_updates) do
    url = "#{ml_service_url()}/adversarial/config"

    body = Jason.encode!(config_updates)

    case Req.post(url, body: body, headers: json_headers(), receive_timeout: @timeout) do
      {:ok, %{status: 200, body: result}} -> {:ok, result}
      {:ok, %{status: status}} -> {:error, {:http_error, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Reload feature baselines from disk.
  """
  @spec reload_baselines() :: {:ok, map()} | {:error, term()}
  def reload_baselines do
    url = "#{ml_service_url()}/adversarial/baselines/reload"

    case Req.post(url, body: "", headers: json_headers(), receive_timeout: @timeout) do
      {:ok, %{status: 200, body: result}} -> {:ok, result}
      {:ok, %{status: status}} -> {:error, {:http_error, status}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp ml_service_url do
    Application.get_env(:tamandua_server, :ml_service_url, @ml_service_url)
  end

  defp json_headers do
    [{"content-type", "application/json"}, {"accept", "application/json"}]
  end
end
