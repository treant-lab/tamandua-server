defmodule TamanduaServer.Registries.Ollama do
  @moduledoc """
  Ollama local model registry connector.

  Provides integration with locally-running Ollama instances for:
  - Listing locally installed models
  - Retrieving model metadata and details
  - Searching models by name pattern
  - Triggering security scans on models

  ## Authentication

  Ollama runs locally and does not require authentication.

  ## Model ID Format

  Models are identified by "name" or "name:tag":
  - `"llama2"` - Uses default tag (latest)
  - `"llama2:7b"` - Specific tag/variant

  ## Configuration

  - `base_url` - Ollama API base URL (default: http://localhost:11434)
  - Environment variable `OLLAMA_URL` can also be used

  ## Example Usage

      # List installed models
      {:ok, models} = Ollama.list_models(%{})

      # Get specific model details
      {:ok, model} = Ollama.get_model("llama2:7b", %{})

      # Search for models
      {:ok, models} = Ollama.search_models("llama", %{})

      # Scan a model for security issues
      {:ok, scan} = Ollama.scan_model("llama2:7b", %{ml_service_url: "http://localhost:8000"})

      # Validate configuration (test connectivity)
      :ok = Ollama.validate_config(%{})
  """

  use TamanduaServer.Registries.Behaviour

  require Logger

  @default_base_url "http://localhost:11434"
  @request_timeout 30_000
  @validate_timeout 5_000

  @impl true
  def metadata do
    %{
      name: "Ollama",
      version: "1.0.0",
      type: :local_registry,
      description: "Ollama local model registry connector for Tamandua EDR",
      author: "Tamandua Team",
      capabilities: [:search, :scan]
    }
  end

  @impl true
  def list_models(config) do
    base_url = get_base_url(config)
    url = "#{base_url}/api/tags"

    with {:ok, response} <- make_request(:get, url, "", config, timeout: @request_timeout),
         {:ok, data} <- decode_json(response.body) do
      models =
        data
        |> Map.get("models", [])
        |> Enum.map(&parse_model/1)

      {:ok, models}
    end
  end

  @impl true
  def get_model(model_id, config) do
    base_url = get_base_url(config)
    url = "#{base_url}/api/show"

    body = Jason.encode!(%{"name" => model_id})

    with {:ok, response} <- make_request(:post, url, body, config,
           timeout: @request_timeout,
           content_type: "application/json"
         ),
         {:ok, data} <- decode_json(response.body) do
      model = parse_show_response(model_id, data)
      {:ok, model}
    end
  end

  @impl true
  def search_models(query, config) do
    case list_models(config) do
      {:ok, models} ->
        query_lower = String.downcase(query)

        filtered =
          Enum.filter(models, fn model ->
            String.contains?(String.downcase(model.name), query_lower) or
              String.contains?(String.downcase(model.id), query_lower)
          end)

        {:ok, filtered}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def scan_model(model_id, config) do
    # First, get model details to find metadata
    with {:ok, model} <- get_model(model_id, config),
         {:ok, scan_result} <- call_ml_service(model, config) do
      {:ok, scan_result}
    else
      {:error, :not_found} -> {:error, :not_found}
      {:error, _reason} -> {:error, :scan_failed}
    end
  end

  @impl true
  def validate_config(config) do
    base_url = get_base_url(config)
    url = "#{base_url}/api/tags"

    case make_request(:get, url, "", config, timeout: @validate_timeout) do
      {:ok, _} -> :ok
      {:error, :connection_refused} -> {:error, :connection_refused}
      {:error, {:network, reason}} -> {:error, {:network, reason}}
      {:error, :timeout} -> {:error, :timeout}
      {:error, reason} -> {:error, reason}
    end
  end

  # Private Functions

  defp parse_model(model_data) when is_map(model_data) do
    name = model_data["name"] || "unknown"

    # Parse the model name and tag
    {base_name, _tag} = parse_model_name(name)

    # Parse size
    size = model_data["size"] || 0

    # Parse modified timestamp
    modified_at = parse_timestamp(model_data["modified_at"])

    # Parse digest
    digest = model_data["digest"] || ""

    %{
      id: name,
      name: base_name,
      author: "ollama",
      downloads: 0,
      sha: extract_sha_from_digest(digest),
      last_modified: modified_at,
      metadata: %{
        size: size,
        full_name: name,
        digest: digest,
        format: model_data["format"],
        family: model_data["family"],
        families: model_data["families"],
        parameter_size: model_data["parameter_size"],
        quantization_level: model_data["quantization_level"]
      }
    }
  end

  defp parse_show_response(model_id, data) when is_map(data) do
    {base_name, _tag} = parse_model_name(model_id)

    details = data["details"] || %{}

    %{
      id: model_id,
      name: base_name,
      author: "ollama",
      downloads: 0,
      sha: "",
      last_modified: DateTime.utc_now(),
      metadata: %{
        modelfile: data["modelfile"],
        parameters: data["parameters"],
        template: data["template"],
        license: data["license"],
        details: details,
        system: extract_system_prompt(data["modelfile"]),
        format: details["format"],
        family: details["family"],
        families: details["families"],
        parameter_size: details["parameter_size"],
        quantization_level: details["quantization_level"]
      }
    }
  end

  defp parse_model_name(name) when is_binary(name) do
    case String.split(name, ":", parts: 2) do
      [base_name, tag] -> {base_name, tag}
      [base_name] -> {base_name, "latest"}
    end
  end

  defp extract_sha_from_digest(digest) when is_binary(digest) do
    # Digest format is typically "sha256:abc123..."
    case String.split(digest, ":", parts: 2) do
      [_algo, hash] -> hash
      [hash] -> hash
    end
  end

  defp extract_sha_from_digest(_), do: ""

  defp extract_system_prompt(nil), do: nil

  defp extract_system_prompt(modelfile) when is_binary(modelfile) do
    # Extract SYSTEM prompt from modelfile if present
    case Regex.run(~r/SYSTEM\s+(.+?)(?:\n|$)/s, modelfile) do
      [_, system] -> String.trim(system)
      nil -> nil
    end
  end

  defp parse_timestamp(nil), do: DateTime.utc_now()

  defp parse_timestamp(timestamp) when is_binary(timestamp) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, datetime, _offset} -> datetime
      {:error, _} -> DateTime.utc_now()
    end
  end

  defp parse_timestamp(_), do: DateTime.utc_now()

  defp get_base_url(config) do
    Map.get(config, :base_url) ||
      System.get_env("OLLAMA_URL") ||
      @default_base_url
  end

  defp make_request(method, url, body, _config, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @request_timeout)
    content_type = Keyword.get(opts, :content_type)

    headers = build_headers(content_type)

    request = Finch.build(method, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: timeout) do
      {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..299 ->
        {:ok, %{status: status, body: resp_body}}

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found}

      {:ok, %Finch.Response{status: 400, body: resp_body}} ->
        case decode_json(resp_body) do
          {:ok, %{"error" => error}} when is_binary(error) ->
            if String.contains?(error, "not found") do
              {:error, :not_found}
            else
              Logger.error("Ollama API error: #{error}")
              {:error, {:api_error, error}}
            end

          _ ->
            Logger.error("Ollama API: Bad request (400): #{inspect(resp_body)}")
            {:error, {:http_error, 400}}
        end

      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        Logger.error("Ollama API: Unexpected status #{status}: #{inspect(resp_body)}")
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: :econnrefused}} ->
        Logger.warning("Ollama API: Connection refused - Ollama not running")
        {:error, :connection_refused}

      {:error, %Mint.TransportError{reason: :timeout}} ->
        Logger.warning("Ollama API: Request timeout")
        {:error, :timeout}

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("Ollama API: Network error: #{inspect(reason)}")
        {:error, {:network, reason}}

      {:error, reason} ->
        Logger.error("Ollama API: Request failed: #{inspect(reason)}")
        {:error, {:network, reason}}
    end
  end

  defp build_headers(nil) do
    [
      {"accept", "application/json"},
      {"user-agent", "Tamandua-EDR/1.0"}
    ]
  end

  defp build_headers(content_type) do
    [
      {"content-type", content_type},
      {"accept", "application/json"},
      {"user-agent", "Tamandua-EDR/1.0"}
    ]
  end

  defp decode_json(body) do
    case Jason.decode(body) do
      {:ok, data} -> {:ok, data}
      {:error, reason} ->
        Logger.error("Failed to decode JSON: #{inspect(reason)}")
        {:error, :invalid_json}
    end
  end

  defp call_ml_service(model, config) do
    ml_service_url =
      Map.get(config, :ml_service_url) ||
        System.get_env("ML_SERVICE_URL") ||
        "http://localhost:8000"

    scan_url = "#{ml_service_url}/api/scan"

    # Prepare scan request payload
    payload = %{
      model_id: model.id,
      author: model.author,
      sha: model.sha,
      registry: "ollama",
      local: true,
      metadata: model.metadata
    }

    body = Jason.encode!(payload)

    headers = [
      {"content-type", "application/json"},
      {"accept", "application/json"}
    ]

    request = Finch.build(:post, scan_url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 60_000) do
      {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..299 ->
        case Jason.decode(resp_body) do
          {:ok, scan_data} ->
            {:ok,
             %{
               risk_score: scan_data["risk_score"] || 0.0,
               findings: scan_data["findings"] || [],
               scanned_at: DateTime.utc_now()
             }}

          {:error, _} ->
            {:error, :invalid_scan_response}
        end

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :scan_service_unavailable}

      {:error, _reason} ->
        {:error, :scan_failed}
    end
  end
end
