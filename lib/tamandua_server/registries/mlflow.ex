defmodule TamanduaServer.Registries.MLflow do
  @moduledoc """
  MLflow Model Registry connector.

  Provides integration with MLflow's REST API v2 for:
  - Listing and searching registered models
  - Retrieving model version metadata
  - Triggering security scans on models

  ## Authentication

  Authentication is optional for local MLflow deployments. For authenticated
  servers, provide a token:

      config = %{tracking_uri: "https://mlflow.example.com", token: "your-token"}
      MLflow.list_models(config)

  Environment variables can also be used:
  - `MLFLOW_TRACKING_URI` - MLflow server URL
  - `MLFLOW_TRACKING_TOKEN` - Authentication token

  ## Model ID Format

  Models are identified by "name" or "name:version":
  - `"fraud-detection"` - Gets latest version
  - `"fraud-detection:3"` - Gets specific version 3

  ## Example Usage

      # List registered models
      {:ok, models} = MLflow.list_models(%{max_results: 10})

      # Get specific model version
      {:ok, model} = MLflow.get_model("fraud-detection:3", %{})

      # Search for models
      {:ok, models} = MLflow.search_models("fraud", %{limit: 5})

      # Scan a model for security issues
      {:ok, scan} = MLflow.scan_model("fraud-detection:3", %{ml_service_url: "http://localhost:8000"})
  """

  use TamanduaServer.Registries.Behaviour

  require Logger

  @mlflow_api_version "2.0"
  @default_tracking_uri "http://localhost:5000"
  @request_timeout 30_000

  @impl true
  def metadata do
    %{
      name: "MLflow Model Registry",
      version: "1.0.0",
      type: :model_registry,
      description: "MLflow Model Registry connector for Tamandua EDR",
      author: "Tamandua Team",
      capabilities: [:search, :scan, :versioning, :webhooks]
    }
  end

  @impl true
  def list_models(config) do
    tracking_uri = get_tracking_uri(config)
    max_results = Map.get(config, :max_results, Map.get(config, :limit, 100))
    page_token = Map.get(config, :page_token)

    query_params =
      %{}
      |> maybe_put("max_results", max_results)
      |> maybe_put("page_token", page_token)

    url = build_url(tracking_uri, "/api/#{@mlflow_api_version}/mlflow/registered-models/list", query_params)

    with {:ok, response} <- make_request(:get, url, "", config),
         {:ok, data} <- decode_json(response.body) do
      models =
        data
        |> Map.get("registered_models", [])
        |> Enum.map(&parse_registered_model/1)

      {:ok, models}
    end
  end

  @impl true
  def get_model(model_id, config) do
    tracking_uri = get_tracking_uri(config)
    {name, version} = parse_model_id(model_id)

    # First, get the registered model metadata
    with {:ok, registered_model} <- fetch_registered_model(tracking_uri, name, config) do
      if version do
        # Get specific version
        fetch_model_version(tracking_uri, name, version, registered_model, config)
      else
        # Get latest version from the registered model
        get_latest_version(tracking_uri, name, registered_model, config)
      end
    end
  end

  @impl true
  def search_models(query, config) do
    tracking_uri = get_tracking_uri(config)
    limit = Map.get(config, :limit, 100)

    # Build filter string - if query looks like a filter, use as-is
    # Otherwise, convert to name search
    filter =
      if String.contains?(query, ["LIKE", "=", ">", "<"]) do
        query
      else
        "name LIKE '%#{escape_filter_value(query)}%'"
      end

    body = Jason.encode!(%{
      "filter" => filter,
      "max_results" => limit
    })

    url = "#{tracking_uri}/api/#{@mlflow_api_version}/mlflow/model-versions/search"

    with {:ok, response} <- make_request(:post, url, body, config, content_type: "application/json"),
         {:ok, data} <- decode_json(response.body) do
      models =
        data
        |> Map.get("model_versions", [])
        |> Enum.map(&parse_model_version/1)

      {:ok, models}
    end
  end

  @impl true
  def scan_model(model_id, config) do
    # First, get model details to find artifact location
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
    tracking_uri = get_tracking_uri(config)

    # Test connectivity by fetching experiments (lightweight endpoint)
    url = "#{tracking_uri}/api/#{@mlflow_api_version}/mlflow/registered-models/list?max_results=1"

    case make_request(:get, url, "", config) do
      {:ok, _} -> :ok
      {:error, :unauthorized} -> {:error, :unauthorized}
      {:error, {:network, reason}} -> {:error, {:network, reason}}
      {:error, reason} -> {:error, reason}
    end
  end

  # Private Functions

  defp fetch_registered_model(tracking_uri, name, config) do
    url = build_url(tracking_uri, "/api/#{@mlflow_api_version}/mlflow/registered-models/get", %{
      "name" => name
    })

    with {:ok, response} <- make_request(:get, url, "", config),
         {:ok, data} <- decode_json(response.body) do
      {:ok, data["registered_model"]}
    end
  end

  defp fetch_model_version(tracking_uri, name, version, registered_model, config) do
    url = build_url(tracking_uri, "/api/#{@mlflow_api_version}/mlflow/model-versions/get", %{
      "name" => name,
      "version" => version
    })

    with {:ok, response} <- make_request(:get, url, "", config),
         {:ok, data} <- decode_json(response.body) do
      model_version = data["model_version"]
      model = parse_model_with_version(registered_model, model_version)
      {:ok, model}
    end
  end

  defp get_latest_version(tracking_uri, name, registered_model, config) do
    # Get latest version from registered model's latest_versions
    case get_in(registered_model, ["latest_versions"]) do
      [latest | _] ->
        version = latest["version"]
        fetch_model_version(tracking_uri, name, version, registered_model, config)

      _ ->
        # No versions available - return registered model info only
        {:ok, parse_registered_model(registered_model)}
    end
  end

  defp parse_registered_model(model_data) when is_map(model_data) do
    name = model_data["name"] || "unknown"
    latest_version = get_latest_version_from_registered(model_data)

    id =
      if latest_version do
        "#{name}:#{latest_version}"
      else
        name
      end

    %{
      id: id,
      name: name,
      author: extract_author_from_tags(model_data["tags"]),
      downloads: 0,  # MLflow doesn't track downloads
      sha: "",
      last_modified: parse_timestamp(model_data["last_updated_timestamp"]),
      metadata: %{
        description: model_data["description"],
        creation_timestamp: parse_timestamp(model_data["creation_timestamp"]),
        latest_versions: model_data["latest_versions"] || [],
        tags: parse_tags(model_data["tags"])
      }
    }
  end

  defp parse_model_with_version(registered_model, model_version) when is_map(model_version) do
    name = model_version["name"] || "unknown"
    version = model_version["version"] || "1"

    %{
      id: "#{name}:#{version}",
      name: name,
      author: extract_author_from_tags(model_version["tags"]) ||
              extract_author_from_tags(registered_model["tags"]),
      downloads: 0,
      sha: model_version["run_id"] || "",
      last_modified: parse_timestamp(model_version["creation_timestamp"]),
      metadata: %{
        version: version,
        current_stage: model_version["current_stage"],
        source: model_version["source"],
        run_id: model_version["run_id"],
        description: model_version["description"] || registered_model["description"],
        tags: parse_tags(model_version["tags"]),
        run_link: model_version["run_link"],
        status: model_version["status"]
      }
    }
  end

  defp parse_model_version(model_version) when is_map(model_version) do
    name = model_version["name"] || "unknown"
    version = model_version["version"] || "1"

    %{
      id: "#{name}:#{version}",
      name: name,
      author: extract_author_from_tags(model_version["tags"]),
      downloads: 0,
      sha: model_version["run_id"] || "",
      last_modified: parse_timestamp(model_version["creation_timestamp"]),
      metadata: %{
        version: version,
        current_stage: model_version["current_stage"],
        source: model_version["source"],
        run_id: model_version["run_id"],
        description: model_version["description"],
        tags: parse_tags(model_version["tags"])
      }
    }
  end

  defp parse_model_id(model_id) when is_binary(model_id) do
    case String.split(model_id, ":", parts: 2) do
      [name, version] -> {name, version}
      [name] -> {name, nil}
    end
  end

  defp get_latest_version_from_registered(model_data) do
    case get_in(model_data, ["latest_versions"]) do
      [latest | _] -> latest["version"]
      _ -> nil
    end
  end

  defp extract_author_from_tags(nil), do: "unknown"
  defp extract_author_from_tags(tags) when is_list(tags) do
    author_tag = Enum.find(tags, fn tag ->
      key = tag["key"] || ""
      String.downcase(key) in ["author", "owner", "created_by", "user"]
    end)

    case author_tag do
      %{"value" => value} -> value
      _ -> "unknown"
    end
  end

  defp parse_tags(nil), do: %{}
  defp parse_tags(tags) when is_list(tags) do
    tags
    |> Enum.map(fn tag -> {tag["key"], tag["value"]} end)
    |> Map.new()
  end

  defp parse_timestamp(nil), do: DateTime.utc_now()
  defp parse_timestamp(timestamp) when is_integer(timestamp) do
    # MLflow uses milliseconds
    case DateTime.from_unix(div(timestamp, 1000)) do
      {:ok, datetime} -> datetime
      {:error, _} -> DateTime.utc_now()
    end
  end
  defp parse_timestamp(_), do: DateTime.utc_now()

  defp build_url(base, path, params) when is_map(params) do
    query_string =
      params
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)
      |> URI.encode_query()

    if query_string == "" do
      "#{base}#{path}"
    else
      "#{base}#{path}?#{query_string}"
    end
  end

  defp make_request(method, url, body, config, opts \\ []) do
    headers = build_headers(config, opts)

    request = Finch.build(method, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: @request_timeout) do
      {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..299 ->
        {:ok, %{status: status, body: resp_body}}

      {:ok, %Finch.Response{status: 401}} ->
        Logger.warning("MLflow API: Unauthorized (401)")
        {:error, :unauthorized}

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found}

      {:ok, %Finch.Response{status: 400, body: resp_body}} ->
        # Check for RESOURCE_DOES_NOT_EXIST error
        case decode_json(resp_body) do
          {:ok, %{"error_code" => "RESOURCE_DOES_NOT_EXIST"}} ->
            {:error, :not_found}

          {:ok, %{"error_code" => code, "message" => message}} ->
            Logger.error("MLflow API: Error #{code}: #{message}")
            {:error, {:api_error, code}}

          _ ->
            Logger.error("MLflow API: Bad request (400): #{inspect(resp_body)}")
            {:error, {:http_error, 400}}
        end

      {:ok, %Finch.Response{status: 429}} ->
        Logger.warning("MLflow API: Rate limited (429)")
        {:error, :rate_limited}

      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        Logger.error("MLflow API: Unexpected status #{status}: #{inspect(resp_body)}")
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("MLflow API: Network error: #{inspect(reason)}")
        {:error, {:network, reason}}

      {:error, reason} ->
        Logger.error("MLflow API: Request failed: #{inspect(reason)}")
        {:error, {:network, reason}}
    end
  end

  defp build_headers(config, opts) do
    content_type = Keyword.get(opts, :content_type)

    base_headers = [
      {"accept", "application/json"},
      {"user-agent", "Tamandua-EDR/1.0"}
    ]

    base_headers =
      if content_type do
        [{"content-type", content_type} | base_headers]
      else
        base_headers
      end

    case get_auth_token(config) do
      nil -> base_headers
      token -> [{"authorization", "Bearer #{token}"} | base_headers]
    end
  end

  defp get_tracking_uri(config) do
    Map.get(config, :tracking_uri) ||
      System.get_env("MLFLOW_TRACKING_URI") ||
      @default_tracking_uri
  end

  defp get_auth_token(config) do
    Map.get(config, :token) || System.get_env("MLFLOW_TRACKING_TOKEN")
  end

  defp decode_json(body) do
    case Jason.decode(body) do
      {:ok, data} -> {:ok, data}
      {:error, reason} ->
        Logger.error("Failed to decode JSON: #{inspect(reason)}")
        {:error, :invalid_json}
    end
  end

  defp escape_filter_value(value) do
    value
    |> String.replace("'", "''")
    |> String.replace("\\", "\\\\")
  end

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
      source: get_in(model, [:metadata, :source]),
      run_id: get_in(model, [:metadata, :run_id]),
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

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
