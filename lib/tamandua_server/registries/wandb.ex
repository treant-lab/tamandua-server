defmodule TamanduaServer.Registries.WandB do
  @moduledoc """
  Weights & Biases (W&B) artifact registry connector.

  Provides integration with the W&B API for:
  - Listing and searching artifacts from projects
  - Retrieving artifact version metadata and file URLs
  - Triggering security scans on model artifacts

  ## Authentication

  W&B requires API key authentication. Provide via config or environment:

      config = %{entity: "my-org", project: "my-project", api_key: "your-api-key"}
      WandB.list_models(config)

  Environment variable: `WANDB_API_KEY`

  ## Artifact ID Format

  Artifacts are identified as "entity/project/artifact_name:version":
  - `"my-org/nlp-models/bert-classifier:v5"` - Specific version
  - `"my-org/nlp-models/bert-classifier"` - Latest version

  ## Example Usage

      # List project artifacts
      {:ok, artifacts} = WandB.list_models(%{entity: "org", project: "proj"})

      # Get specific artifact version
      {:ok, artifact} = WandB.get_model("org/proj/model:v2", %{})

      # Search artifacts
      {:ok, artifacts} = WandB.search_models("pytorch", %{entity: "org", project: "proj"})

      # Validate configuration
      :ok = WandB.validate_config(%{entity: "org", project: "proj", api_key: "key"})

      # Scan artifact for security issues
      {:ok, scan} = WandB.scan_model("org/proj/model:v2", %{ml_service_url: "http://localhost:8000"})
  """

  use TamanduaServer.Registries.Behaviour

  require Logger

  @wandb_api_base "https://api.wandb.ai"
  @request_timeout 30_000

  @impl true
  def metadata do
    %{
      name: "Weights & Biases",
      version: "1.0.0",
      type: :experiment_tracker,
      description: "W&B artifact registry connector for Tamandua EDR",
      author: "Tamandua Team",
      capabilities: [:search, :scan, :artifacts, :webhooks]
    }
  end

  @impl true
  def list_models(config) do
    with {:ok, _entity, _project, _api_key} <- validate_required_fields(config) do
      entity = config[:entity]
      project = config[:project]
      per_page = Map.get(config, :per_page, Map.get(config, :limit, 100))
      page = Map.get(config, :page, 1)

      # W&B uses GraphQL API for artifact queries
      query = build_artifacts_query(entity, project, per_page, page)
      api_base = Map.get(config, :api_base, @wandb_api_base)
      url = "#{api_base}/graphql"

      with {:ok, response} <- make_graphql_request(url, query, config),
           {:ok, data} <- decode_json(response.body) do
        artifacts =
          data
          |> get_in(["data", "project", "artifacts", "edges"])
          |> List.wrap()
          |> Enum.map(fn edge -> parse_artifact(edge["node"], entity, project) end)

        {:ok, artifacts}
      end
    else
      {:error, :invalid_config} -> {:error, :invalid_config}
      error -> error
    end
  end

  @impl true
  def get_model(model_id, config) do
    {entity, project, artifact_name, version} = parse_model_id(model_id)

    # Override entity/project from model_id if present
    config =
      config
      |> Map.put(:entity, entity || config[:entity])
      |> Map.put(:project, project || config[:project])

    api_base = Map.get(config, :api_base, @wandb_api_base)

    query =
      if version do
        build_artifact_version_query(entity, project, artifact_name, version)
      else
        build_artifact_latest_query(entity, project, artifact_name)
      end

    url = "#{api_base}/graphql"

    with {:ok, response} <- make_graphql_request(url, query, config),
         {:ok, data} <- decode_json(response.body) do
      artifact_data =
        if version do
          get_in(data, ["data", "project", "artifact"])
        else
          get_in(data, ["data", "project", "artifact"])
        end

      if artifact_data do
        model = parse_artifact(artifact_data, entity, project)
        {:ok, model}
      else
        {:error, :not_found}
      end
    end
  end

  @impl true
  def search_models(query, config) do
    # W&B doesn't have a dedicated search API, so we list and filter client-side
    case list_models(config) do
      {:ok, models} ->
        filtered =
          models
          |> Enum.filter(fn model ->
            name_match = String.contains?(String.downcase(model.name), String.downcase(query))

            tags_match =
              case model.metadata[:tags] do
                tags when is_list(tags) ->
                  Enum.any?(tags, fn tag ->
                    String.contains?(String.downcase(to_string(tag)), String.downcase(query))
                  end)

                tags when is_map(tags) ->
                  Enum.any?(Map.values(tags), fn val ->
                    String.contains?(String.downcase(to_string(val)), String.downcase(query))
                  end)

                _ ->
                  false
              end

            name_match or tags_match
          end)
          |> Enum.take(Map.get(config, :limit, 100))

        {:ok, filtered}

      error ->
        error
    end
  end

  @impl true
  def scan_model(model_id, config) do
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
    case validate_required_fields(config) do
      {:ok, entity, _project, _api_key} ->
        # Test connectivity by fetching entity info
        api_base = Map.get(config, :api_base, @wandb_api_base)
        query = build_entity_query(entity)
        url = "#{api_base}/graphql"

        case make_graphql_request(url, query, config) do
          {:ok, %{status: 200}} -> :ok
          {:ok, %{status: 401}} -> {:error, :unauthorized}
          {:ok, %{status: 403}} -> {:error, :forbidden}
          {:error, reason} -> {:error, reason}
        end

      {:error, :invalid_config} ->
        {:error, :invalid_config}
    end
  end

  # Private Functions

  defp validate_required_fields(config) do
    entity = Map.get(config, :entity)
    project = Map.get(config, :project)
    api_key = get_api_key(config)

    if entity && project && api_key do
      {:ok, entity, project, api_key}
    else
      {:error, :invalid_config}
    end
  end

  defp parse_model_id(model_id) when is_binary(model_id) do
    # Parse "entity/project/artifact_name:version" or "entity/project/artifact_name"
    case String.split(model_id, "/", parts: 3) do
      [entity, project, artifact_with_version] ->
        case String.split(artifact_with_version, ":", parts: 2) do
          [artifact_name, version] -> {entity, project, artifact_name, version}
          [artifact_name] -> {entity, project, artifact_name, nil}
        end

      [artifact_with_version] ->
        case String.split(artifact_with_version, ":", parts: 2) do
          [artifact_name, version] -> {nil, nil, artifact_name, version}
          [artifact_name] -> {nil, nil, artifact_name, nil}
        end

      _ ->
        {nil, nil, model_id, nil}
    end
  end

  defp parse_artifact(artifact_data, entity, project) when is_map(artifact_data) do
    name = artifact_data["artifactSequenceName"] || artifact_data["name"] || "unknown"
    version_index = artifact_data["versionIndex"]
    version = if version_index, do: "v#{version_index}", else: "latest"

    id = "#{entity}/#{project}/#{name}:#{version}"

    %{
      id: id,
      name: name,
      author: entity,
      downloads: 0,  # W&B doesn't expose download counts
      sha: artifact_data["digest"] || artifact_data["id"] || "",
      last_modified: parse_datetime(artifact_data["createdAt"] || artifact_data["updatedAt"]),
      metadata: %{
        entity: entity,
        project: project,
        version: version,
        version_index: version_index,
        description: artifact_data["description"],
        artifact_id: artifact_data["id"],
        artifact_type: artifact_data["artifactTypeName"] || artifact_data["type"],
        tags: parse_tags(artifact_data["aliases"]),
        manifest: artifact_data["manifest"],
        files: extract_files(artifact_data)
      }
    }
  end

  defp extract_files(artifact_data) do
    case get_in(artifact_data, ["manifest", "contents"]) do
      contents when is_list(contents) ->
        Enum.map(contents, fn file ->
          %{
            path: file["path"],
            size: file["size"],
            digest: file["digest"],
            url: file["url"]
          }
        end)

      _ ->
        []
    end
  end

  defp parse_tags(nil), do: []
  defp parse_tags(aliases) when is_list(aliases) do
    Enum.map(aliases, fn alias -> alias["alias"] || alias end)
  end
  defp parse_tags(_), do: []

  defp parse_datetime(nil), do: DateTime.utc_now()
  defp parse_datetime(datetime_string) when is_binary(datetime_string) do
    case DateTime.from_iso8601(datetime_string) do
      {:ok, datetime, _offset} -> datetime
      {:error, _} -> DateTime.utc_now()
    end
  end
  defp parse_datetime(_), do: DateTime.utc_now()

  defp build_artifacts_query(entity, project, per_page, page) do
    offset = (page - 1) * per_page

    """
    query {
      project(name: "#{project}", entityName: "#{entity}") {
        artifacts(first: #{per_page}, offset: #{offset}) {
          edges {
            node {
              id
              artifactSequenceName
              artifactTypeName
              description
              createdAt
              updatedAt
              versionIndex
              digest
              aliases {
                alias
              }
            }
          }
        }
      }
    }
    """
  end

  defp build_artifact_version_query(entity, project, artifact_name, version) do
    # Strip 'v' prefix if present
    version_num = String.replace_prefix(version, "v", "")

    """
    query {
      project(name: "#{project}", entityName: "#{entity}") {
        artifact(name: "#{artifact_name}:v#{version_num}") {
          id
          artifactSequenceName
          artifactTypeName
          description
          createdAt
          updatedAt
          versionIndex
          digest
          aliases {
            alias
          }
          manifest {
            contents {
              path
              size
              digest
              url
            }
          }
        }
      }
    }
    """
  end

  defp build_artifact_latest_query(entity, project, artifact_name) do
    """
    query {
      project(name: "#{project}", entityName: "#{entity}") {
        artifact(name: "#{artifact_name}:latest") {
          id
          artifactSequenceName
          artifactTypeName
          description
          createdAt
          updatedAt
          versionIndex
          digest
          aliases {
            alias
          }
          manifest {
            contents {
              path
              size
              digest
              url
            }
          }
        }
      }
    }
    """
  end

  defp build_entity_query(entity) do
    """
    query {
      entity(name: "#{entity}") {
        id
        name
      }
    }
    """
  end

  defp make_graphql_request(url, query, config) do
    headers = build_headers(config)
    body = Jason.encode!(%{"query" => query})

    request = Finch.build(:post, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: @request_timeout) do
      {:ok, %Finch.Response{status: status, body: resp_body}} when status in 200..299 ->
        {:ok, %{status: status, body: resp_body}}

      {:ok, %Finch.Response{status: 401}} ->
        Logger.warning("W&B API: Unauthorized (401)")
        {:error, :unauthorized}

      {:ok, %Finch.Response{status: 403}} ->
        Logger.warning("W&B API: Forbidden (403)")
        {:error, :forbidden}

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found}

      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        Logger.error("W&B API: Unexpected status #{status}: #{inspect(resp_body)}")
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("W&B API: Network error: #{inspect(reason)}")
        {:error, {:network, reason}}

      {:error, reason} ->
        Logger.error("W&B API: Request failed: #{inspect(reason)}")
        {:error, {:network, reason}}
    end
  end

  defp build_headers(config) do
    api_key = get_api_key(config)

    base_headers = [
      {"content-type", "application/json"},
      {"accept", "application/json"},
      {"user-agent", "Tamandua-EDR/1.0"}
    ]

    if api_key do
      [{"authorization", "Basic #{Base.encode64("api:#{api_key}")}"} | base_headers]
    else
      base_headers
    end
  end

  defp get_api_key(config) do
    Map.get(config, :api_key) || System.get_env("WANDB_API_KEY")
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
    ml_service_url = Map.get(config, :ml_service_url) ||
                     System.get_env("ML_SERVICE_URL") ||
                     "http://localhost:8000"

    scan_url = "#{ml_service_url}/api/scan"

    # Prepare scan request payload
    payload = %{
      model_id: model.id,
      author: model.author,
      sha: model.sha,
      files: model.metadata[:files] || [],
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
end
