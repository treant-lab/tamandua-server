defmodule TamanduaServer.Registries.HuggingFace do
  @moduledoc """
  HuggingFace Hub registry connector.

  Provides integration with the HuggingFace Hub API for:
  - Listing and searching models
  - Retrieving detailed model metadata
  - Triggering security scans on models

  ## Authentication

  Authentication is optional for public models. For private models or
  higher rate limits, provide an HF_TOKEN:

      config = %{hf_token: System.get_env("HF_TOKEN")}
      HuggingFace.list_models(config)

  ## Rate Limiting

  The HuggingFace API has rate limits. This connector handles 429 responses
  gracefully by returning `{:error, :rate_limited}`.

  ## Example Usage

      # List trending models
      {:ok, models} = HuggingFace.list_models(%{limit: 10, sort: "downloads"})

      # Get specific model
      {:ok, model} = HuggingFace.get_model("meta-llama/Llama-2-7b-chat-hf", %{})

      # Search for models
      {:ok, models} = HuggingFace.search_models("pytorch llama", %{limit: 5})

      # Scan a model for security issues
      {:ok, scan} = HuggingFace.scan_model("suspicious/model", %{ml_service_url: "http://localhost:8000"})
  """

  use TamanduaServer.Registries.Behaviour

  require Logger

  @hf_api_base "https://huggingface.co/api"
  @request_timeout 30_000  # 30 seconds

  @impl true
  def metadata do
    %{
      name: "HuggingFace Hub",
      version: "1.0.0",
      type: :model_registry,
      description: "Official HuggingFace model registry connector",
      author: "Tamandua Team",
      capabilities: [:search, :scan, :pagination]
    }
  end

  @impl true
  def list_models(config) do
    limit = Map.get(config, :limit, 20)
    skip = Map.get(config, :offset, Map.get(config, :skip, 0))
    filter = Map.get(config, :filter, %{})
    sort = Map.get(config, :sort, "downloads")

    query_params = build_query_params(%{
      limit: limit,
      skip: skip,
      sort: sort,
      filter: filter
    })

    url = "#{@hf_api_base}/models?#{URI.encode_query(query_params)}"

    with {:ok, response} <- make_request(:get, url, "", config),
         {:ok, models_data} <- decode_json(response.body) do
      models = Enum.map(models_data, &parse_model/1)
      {:ok, models}
    end
  end

  @impl true
  def get_model(model_id, config) do
    url = "#{@hf_api_base}/models/#{URI.encode(model_id)}"

    with {:ok, response} <- make_request(:get, url, "", config),
         {:ok, model_data} <- decode_json(response.body) do
      model = parse_model(model_data)
      {:ok, model}
    end
  end

  @impl true
  def search_models(query, config) do
    limit = Map.get(config, :limit, 20)
    filter = Map.get(config, :filter, %{})

    query_params = build_query_params(%{
      search: query,
      limit: limit,
      filter: filter
    })

    url = "#{@hf_api_base}/models?#{URI.encode_query(query_params)}"

    with {:ok, response} <- make_request(:get, url, "", config),
         {:ok, models_data} <- decode_json(response.body) do
      models = Enum.map(models_data, &parse_model/1)
      {:ok, models}
    end
  end

  @impl true
  def scan_model(model_id, config) do
    # First, get model metadata to fetch file information
    with {:ok, model} <- get_model(model_id, config),
         {:ok, scan_result} <- call_ml_service(model, config) do
      {:ok, scan_result}
    else
      {:error, :not_found} -> {:error, :not_found}
      {:error, reason} -> {:error, :scan_failed}
    end
  end

  # Private Functions

  defp build_query_params(params) do
    params
    |> Map.take([:limit, :skip, :sort, :search])
    |> Map.merge(build_filter_params(params[:filter] || %{}))
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new()
  end

  defp build_filter_params(filter) when is_map(filter) do
    filter
    |> Enum.map(fn {key, value} -> {"filter", "#{key}:#{value}"} end)
    |> Map.new()
  end

  defp make_request(method, url, body, config) do
    headers = build_headers(config)

    request = Finch.build(method, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: @request_timeout) do
      {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..299 ->
        {:ok, %{status: status, body: resp_body}}

      {:ok, %Finch.Response{status: 401}} ->
        Logger.warning("HuggingFace API: Unauthorized (401)")
        {:error, :unauthorized}

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found}

      {:ok, %Finch.Response{status: 429}} ->
        Logger.warning("HuggingFace API: Rate limited (429)")
        {:error, :rate_limited}

      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        Logger.error("HuggingFace API: Unexpected status #{status}: #{inspect(resp_body)}")
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("HuggingFace API: Network error: #{inspect(reason)}")
        {:error, {:network, reason}}

      {:error, reason} ->
        Logger.error("HuggingFace API: Request failed: #{inspect(reason)}")
        {:error, {:network, reason}}
    end
  end

  defp build_headers(config) do
    base_headers = [
      {"accept", "application/json"},
      {"user-agent", "Tamandua-EDR/1.0"}
    ]

    case get_auth_header(config) do
      nil -> base_headers
      auth_header -> [auth_header | base_headers]
    end
  end

  defp get_auth_header(config) do
    token = Map.get(config, :hf_token) || System.get_env("HF_TOKEN")

    if token do
      {"authorization", "Bearer #{token}"}
    else
      nil
    end
  end

  defp decode_json(body) do
    case Jason.decode(body) do
      {:ok, data} -> {:ok, data}
      {:error, reason} ->
        Logger.error("Failed to decode JSON: #{inspect(reason)}")
        {:error, :invalid_json}
    end
  end

  defp parse_model(model_data) when is_map(model_data) do
    # Extract required fields
    id = model_data["id"] || model_data["modelId"] || "unknown"
    author = model_data["author"] || extract_author(id)
    name = model_data["id"] || id
    sha = model_data["sha"] || model_data["_id"] || ""
    downloads = model_data["downloads"] || 0
    last_modified = parse_datetime(model_data["lastModified"] || model_data["last_modified"])

    # Extract metadata
    metadata = %{
      tags: model_data["tags"] || [],
      siblings: model_data["siblings"] || [],
      task: extract_task(model_data["tags"] || []),
      pipeline_tag: model_data["pipeline_tag"] || model_data["pipelineTag"],
      library: extract_library(model_data["tags"] || [])
    }

    %{
      id: id,
      name: name,
      author: author,
      downloads: downloads,
      sha: sha,
      last_modified: last_modified,
      metadata: metadata
    }
  end

  defp extract_author(model_id) do
    case String.split(model_id, "/") do
      [author | _] -> author
      _ -> "unknown"
    end
  end

  defp extract_task(tags) when is_list(tags) do
    task_tags = ["text-generation", "text-classification", "translation",
                 "summarization", "question-answering", "image-classification"]

    Enum.find(tags, fn tag -> tag in task_tags end)
  end

  defp extract_library(tags) when is_list(tags) do
    library_tags = ["pytorch", "tensorflow", "jax", "onnx", "safetensors"]

    Enum.find(tags, fn tag -> tag in library_tags end)
  end

  defp parse_datetime(nil), do: DateTime.utc_now()
  defp parse_datetime(datetime_string) when is_binary(datetime_string) do
    case DateTime.from_iso8601(datetime_string) do
      {:ok, datetime, _offset} -> datetime
      {:error, _} -> DateTime.utc_now()
    end
  end
  defp parse_datetime(_), do: DateTime.utc_now()

  defp call_ml_service(model, config) do
    ml_service_url = Map.get(config, :ml_service_url) ||
                     System.get_env("ML_SERVICE_URL") ||
                     "http://localhost:8000"

    scan_url = "#{ml_service_url}/api/scan"

    # Prepare scan request payload
    payload = %{
      model_id: model.id,
      author: model.author,
      sha: model.sha,
      files: extract_file_urls(model),
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
            {:ok, %{
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

  defp extract_file_urls(model) do
    siblings = get_in(model, [:metadata, :siblings]) || []

    Enum.map(siblings, fn sibling ->
      %{
        filename: sibling["rfilename"],
        size: sibling["size"],
        url: build_file_url(model.id, sibling["rfilename"])
      }
    end)
  end

  defp build_file_url(model_id, filename) do
    "https://huggingface.co/#{model_id}/resolve/main/#{filename}"
  end
end
