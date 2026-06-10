defmodule TamanduaServer.AISecurity.MLClient do
  @moduledoc """
  HTTP client for communicating with the Python ML service.

  Handles backdoor analysis requests to the ML service endpoint.
  The ML service performs weight distribution analysis and spectral (SVD)
  analysis to detect potential backdoors in AI/ML model files.

  ## Configuration

  The ML service URL can be configured via:
  - Environment variable: `ML_SERVICE_URL`
  - Application config: `config :tamandua_server, :ml_service_url`
  - Default: `http://localhost:8000`

  ## Timeout

  Analysis can take significant time for large models. Default timeout
  is 2 minutes (120,000ms). For very large models, consider increasing.

  ## Example

      iex> MLClient.analyze_backdoor("/path/to/model.safetensors")
      {:ok, %{
        analyzed: true,
        weight_score: 0.25,
        spectral_score: 0.30,
        combined_score: 0.28,
        is_suspicious: false,
        weight_outlier_layers: [],
        spectral_outlier_layers: [],
        analysis_time_ms: 1523
      }}
  """

  require Logger

  @default_ml_service_url "http://localhost:8000"
  @timeout 120_000  # 2 minutes for large models

  @doc """
  Analyze a model file for backdoor signatures.

  Calls POST /ai-security/analyze-backdoor on the ML service with
  the model file as multipart upload.

  ## Parameters

    * `file_path` - Absolute path to the model file to analyze

  ## Returns

    * `{:ok, result}` - Analysis completed successfully
    * `{:error, reason}` - Analysis failed

  ## Result Map

    * `:analyzed` - Boolean indicating if analysis was performed
    * `:weight_score` - Score from weight distribution analysis (0.0-1.0)
    * `:spectral_score` - Score from SVD analysis (0.0-1.0)
    * `:combined_score` - Weighted average: 0.4 * weight + 0.6 * spectral
    * `:is_suspicious` - Boolean, true if combined_score > 0.5
    * `:weight_outlier_layers` - List of layer names with weight anomalies
    * `:spectral_outlier_layers` - List of layer names with spectral anomalies
    * `:analysis_time_ms` - Time taken for analysis in milliseconds
    * `:error` - Error message if analysis failed (nil on success)

  ## Example

      iex> MLClient.analyze_backdoor("/models/llama-7b.safetensors")
      {:ok, %{analyzed: true, combined_score: 0.15, ...}}

      iex> MLClient.analyze_backdoor("/nonexistent/file.pt")
      {:error, "File not found: /nonexistent/file.pt"}
  """
  @spec analyze_backdoor(String.t()) :: {:ok, map()} | {:error, String.t()}
  def analyze_backdoor(file_path) when is_binary(file_path) do
    url = "#{ml_service_url()}/ai-security/analyze-backdoor"

    Logger.info("[MLClient] Starting backdoor analysis for #{file_path}")

    # Check if file exists first
    unless File.exists?(file_path) do
      Logger.warning("[MLClient] File not found: #{file_path}")
      {:error, "File not found: #{file_path}"}
    else
      # Use Req library for HTTP request with multipart file upload
      case Req.post(url,
        form_multipart: [file: {:file, file_path}],
        receive_timeout: @timeout,
        connect_options: [timeout: 10_000]
      ) do
        {:ok, %{status: 200, body: body}} ->
          Logger.info("[MLClient] Analysis completed for #{file_path}")
          {:ok, parse_backdoor_response(body)}

        {:ok, %{status: status, body: body}} ->
          error_msg = extract_error_message(body, status)
          Logger.warning("[MLClient] ML service returned #{status}: #{error_msg}")
          {:error, "ML service returned #{status}: #{error_msg}"}

        {:error, %Req.TransportError{reason: :timeout}} ->
          Logger.warning("[MLClient] Request timed out for #{file_path}")
          {:error, "Analysis timed out - model may be too large"}

        {:error, %Req.TransportError{reason: :econnrefused}} ->
          Logger.warning("[MLClient] ML service connection refused")
          {:error, "ML service unavailable - connection refused"}

        {:error, reason} ->
          Logger.warning("[MLClient] Request failed: #{inspect(reason)}")
          {:error, "ML service request failed: #{inspect(reason)}"}
      end
    end
  end

  @doc """
  Analyze a model file for backdoor signatures with full layer details.

  Similar to `analyze_backdoor/1` but also fetches detailed per-layer
  statistics needed for visualization charts. Makes additional calls to
  the weight and spectral endpoints to get layer-level breakdowns.

  ## Parameters

    * `file_path` - Absolute path to the model file to analyze

  ## Returns

    * `{:ok, result}` - Analysis completed with full layer details
    * `{:error, reason}` - Analysis failed

  ## Result Map

  Same as `analyze_backdoor/1` plus:
    * `:weight_details` - Per-layer weight statistics map
    * `:spectral_details` - Per-layer SVD results map

  ## Example

      iex> MLClient.analyze_backdoor_detailed("/models/llama-7b.safetensors")
      {:ok, %{
        analyzed: true,
        combined_score: 0.28,
        weight_details: %{layers: [%{name: "layer1.weight", ...}]},
        spectral_details: %{layers: [%{name: "classifier.weight", ...}]},
        ...
      }}
  """
  @spec analyze_backdoor_detailed(String.t()) :: {:ok, map()} | {:error, String.t()}
  def analyze_backdoor_detailed(file_path) when is_binary(file_path) do
    Logger.info("[MLClient] Starting detailed backdoor analysis for #{file_path}")

    with {:ok, combined} <- analyze_backdoor(file_path),
         {:ok, weight_details} <- analyze_weights_detailed(file_path),
         {:ok, spectral_details} <- analyze_spectral_detailed(file_path) do
      {:ok, Map.merge(combined, %{
        weight_details: weight_details,
        spectral_details: spectral_details
      })}
    end
  end

  # Fetch detailed weight analysis with per-layer statistics
  defp analyze_weights_detailed(file_path) do
    url = "#{ml_service_url()}/ai-security/analyze-weights"

    case Req.post(url,
      form_multipart: [file: {:file, file_path}],
      receive_timeout: @timeout,
      connect_options: [timeout: 10_000]
    ) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, parse_weight_details(body)}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        Logger.warning("[MLClient] Weight analysis returned #{status}: #{error_msg}")
        # Return empty details on error to allow combined analysis to continue
        {:ok, %{layers: []}}

      {:error, reason} ->
        Logger.warning("[MLClient] Weight detail request failed: #{inspect(reason)}")
        {:ok, %{layers: []}}
    end
  end

  # Fetch detailed spectral analysis with SVD results
  defp analyze_spectral_detailed(file_path) do
    url = "#{ml_service_url()}/ai-security/analyze-spectral"

    case Req.post(url,
      form_multipart: [file: {:file, file_path}],
      receive_timeout: @timeout,
      connect_options: [timeout: 10_000]
    ) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, parse_spectral_details(body)}

      {:ok, %{status: status, body: body}} ->
        error_msg = extract_error_message(body, status)
        Logger.warning("[MLClient] Spectral analysis returned #{status}: #{error_msg}")
        {:ok, %{layers: []}}

      {:error, reason} ->
        Logger.warning("[MLClient] Spectral detail request failed: #{inspect(reason)}")
        {:ok, %{layers: []}}
    end
  end

  # Parse weight analysis response into layer details
  defp parse_weight_details(body) when is_map(body) do
    layers = body["layer_results"] || []

    %{
      layers: Enum.map(layers, fn layer ->
        %{
          name: layer["name"] || "unknown",
          shape: layer["shape"] || [],
          mean: layer["mean"],
          std: layer["std"],
          skewness: layer["skewness"],
          kurtosis: layer["kurtosis"],
          sparsity: layer["sparsity"],
          z_score: layer["z_score"],
          anomaly_score: layer["anomaly_score"] || 0.0,
          is_outlier: layer["is_outlier"] || false
        }
      end)
    }
  end

  defp parse_weight_details(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> parse_weight_details(decoded)
      {:error, _} -> %{layers: []}
    end
  end

  defp parse_weight_details(_), do: %{layers: []}

  # Parse spectral analysis response into layer details
  defp parse_spectral_details(body) when is_map(body) do
    layers = body["layer_results"] || []

    %{
      layers: Enum.map(layers, fn layer ->
        %{
          name: layer["name"] || "unknown",
          shape: layer["shape"] || [],
          rank: layer["rank"],
          singular_values: layer["singular_values"] || [],
          sv_outliers: layer["sv_outliers"] || [],
          top_sv_ratio: layer["top_sv_ratio"],
          spectral_gap: layer["spectral_gap"],
          clustering_anomaly: layer["clustering_anomaly"] || false,
          anomaly_score: layer["anomaly_score"] || 0.0
        }
      end)
    }
  end

  defp parse_spectral_details(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> parse_spectral_details(decoded)
      {:error, _} -> %{layers: []}
    end
  end

  defp parse_spectral_details(_), do: %{layers: []}

  @doc """
  Check if the ML service is available and responding.

  Makes a lightweight request to verify connectivity.

  ## Returns

    * `{:ok, :healthy}` - Service is responding
    * `{:error, reason}` - Service is not available
  """
  @spec health_check() :: {:ok, :healthy} | {:error, String.t()}
  def health_check do
    url = "#{ml_service_url()}/health"

    case Req.get(url, receive_timeout: 5_000) do
      {:ok, %{status: status}} when status in 200..299 ->
        {:ok, :healthy}

      {:ok, %{status: status}} ->
        {:error, "ML service returned #{status}"}

      {:error, reason} ->
        {:error, "ML service unavailable: #{inspect(reason)}"}
    end
  end

  # Get the ML service URL from config or environment
  defp ml_service_url do
    Application.get_env(:tamandua_server, :ml_service_url, @default_ml_service_url)
  end

  # Parse the response body from the ML service
  defp parse_backdoor_response(body) when is_map(body) do
    %{
      analyzed: body["analyzed"] || false,
      weight_score: body["weight_score"],
      spectral_score: body["spectral_score"],
      combined_score: body["combined_score"],
      is_suspicious: body["is_suspicious"] || false,
      weight_outlier_layers: body["weight_outlier_layers"] || [],
      spectral_outlier_layers: body["spectral_outlier_layers"] || [],
      analysis_time_ms: body["analysis_time_ms"],
      error: body["error"]
    }
  end

  defp parse_backdoor_response(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> parse_backdoor_response(decoded)
      {:error, _} -> %{analyzed: false, error: "Invalid response format"}
    end
  end

  defp parse_backdoor_response(_), do: %{analyzed: false, error: "Invalid response"}

  # Extract error message from response body
  defp extract_error_message(body, status) when is_map(body) do
    body["detail"] || body["error"] || body["message"] || "HTTP #{status}"
  end

  defp extract_error_message(body, _status) when is_binary(body), do: body
  defp extract_error_message(_, status), do: "HTTP #{status}"
end
