defmodule TamanduaServerWeb.API.V1.ForensicsController do
  @moduledoc """
  Forensics Collection API controller.

  Provides endpoints for managing forensic artifact collections,
  including memory dumps, disk images, and file artifacts from
  endpoints under investigation.
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Forensics.Collector

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  List all forensic collections.

  Returns a paginated list of forensic collections with summary information.

  ## Parameters
    - page: Page number
    - per_page: Items per page
    - status: Filter by status (pending, collecting, completed, failed)
    - type: Filter by collection type (memory, disk, files, registry, logs)
    - agent_id: Filter by agent
  """
  def index(conn, params) do
    # Always scope to the caller's organization to prevent cross-tenant
    # enumeration of forensic collections.
    filters =
      %{organization_id: get_current_organization_id(conn)}
      |> maybe_put(:status, Map.get(params, "status"))
      |> maybe_put(:type, Map.get(params, "type"))
      |> maybe_put(:agent_id, Map.get(params, "agent_id"))

    case Collector.list_collections(filters) do
      {:ok, collections} ->
        json(conn, %{
          data: Enum.map(collections, &serialize_collection/1),
          meta: %{count: length(collections)}
        })

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Get a specific forensic collection with full details.

  Returns complete information about a collection including
  all artifacts, chain of custody, and analysis results.
  """
  def show(conn, %{"id" => id}) do
    org_id = get_current_organization_id(conn)

    case Collector.get_collection(id) do
      {:ok, collection} ->
        # Enforce tenant ownership; return not_found (not forbidden) so the
        # endpoint does not confirm existence of other tenants' collections.
        if Map.get(collection, :organization_id) == org_id do
          json(conn, %{
            data: serialize_collection_detail(collection)
          })
        else
          {:error, :not_found}
        end

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Create a new forensic collection request.

  Initiates a forensic collection from a specified endpoint.

  ## Parameters
    - agent_id: Target agent ID
    - type: Collection type (memory, disk, files, registry, logs, full)
    - paths: Specific paths to collect (for files type)
    - options: Collection-specific options
    - alert_id: Associated alert ID (optional)
    - case_id: Associated case ID (optional)
    - priority: Collection priority (low, normal, high, critical)
    - notes: Analyst notes
  """
  def create(conn, %{"agent_id" => agent_id, "type" => type} = params) do
    collection_params = %{
      agent_id: agent_id,
      organization_id: get_current_organization_id(conn),
      type: type,
      paths: Map.get(params, "paths", []),
      options: Map.get(params, "options", %{}),
      alert_id: Map.get(params, "alert_id"),
      case_id: Map.get(params, "case_id"),
      priority: Map.get(params, "priority", "normal"),
      notes: Map.get(params, "notes"),
      requested_by: get_current_user_id(conn)
    }

    case Collector.create_collection(collection_params) do
      {:ok, collection} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          data: serialize_collection_detail(collection),
          message: "Forensic collection initiated"
        })

      {:error, :agent_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent not found"})

      {:error, :agent_offline} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Agent is offline"})

      {:error, :invalid_type} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Invalid collection type"})

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, changeset}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  def create(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required parameters: agent_id and type"})
  end

  @doc """
  Download a forensic artifact.

  Returns the artifact file for download. Requires appropriate
  permissions and logs the download for chain of custody.

  ## Parameters
    - id: Collection ID
    - artifact_id: Specific artifact ID within the collection
  """
  def download(conn, %{"id" => id, "artifact_id" => artifact_id}) do
    with {:ok, collection} <- Collector.get_collection(id),
         {:ok, artifact} <- Collector.get_artifact(collection, artifact_id),
         :ok <- Collector.log_access(artifact, get_current_user_id(conn), "download") do
      conn
      |> put_resp_content_type(artifact.content_type || "application/octet-stream")
      |> put_resp_header(
        "content-disposition",
        "attachment; filename=\"#{artifact.filename}\""
      )
      |> send_file(200, artifact.path)
    else
      {:error, :not_found} ->
        {:error, :not_found}

      {:error, :artifact_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Artifact not found"})

      {:error, :file_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Artifact file not found on disk"})

      {:error, :unauthorized} ->
        {:error, :unauthorized}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  def download(conn, %{"id" => id}) do
    # Download entire collection as archive
    with {:ok, collection} <- Collector.get_collection(id),
         {:ok, archive_path} <- Collector.create_archive(collection),
         :ok <- Collector.log_access(collection, get_current_user_id(conn), "download_archive") do
      archive_name = "forensics_#{collection.id}_#{Date.utc_today()}.zip"

      conn
      |> put_resp_content_type("application/zip")
      |> put_resp_header("content-disposition", "attachment; filename=\"#{archive_name}\"")
      |> send_file(200, archive_path)
    else
      {:error, :not_found} ->
        {:error, :not_found}

      {:error, :collection_incomplete} ->
        conn
        |> put_status(:conflict)
        |> json(%{error: "Collection is still in progress"})

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Analyze a forensic collection.

  Triggers automated analysis on collected artifacts.

  ## Parameters
    - analysis_types: Types of analysis to run (malware, timeline, ioc_extraction, etc.)
    - options: Analysis-specific options
  """
  def analyze(conn, %{"id" => id} = params) do
    analysis_types = Map.get(params, "analysis_types", ["all"])
    options = Map.get(params, "options", %{})

    with {:ok, collection} <- Collector.get_collection(id),
         :ok <- validate_collection_complete(collection),
         {:ok, analysis} <- Collector.start_analysis(collection, analysis_types, options) do
      conn
      |> put_status(:accepted)
      |> json(%{
        data: %{
          analysis_id: analysis.id,
          collection_id: collection.id,
          analysis_types: analysis_types,
          status: analysis.status,
          started_at: format_datetime(analysis.started_at)
        },
        message: "Analysis initiated"
      })
    else
      {:error, :not_found} ->
        {:error, :not_found}

      {:error, :collection_incomplete} ->
        conn
        |> put_status(:conflict)
        |> json(%{error: "Collection must be complete before analysis"})

      {:error, :analysis_in_progress} ->
        conn
        |> put_status(:conflict)
        |> json(%{error: "Analysis already in progress"})

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  # Private functions

  defp serialize_collection(collection) do
    %{
      id: collection.id,
      agent_id: collection.agent_id,
      hostname: collection.hostname,
      type: collection.type,
      status: collection.status,
      priority: collection.priority,
      artifact_count: collection.artifact_count,
      total_size: collection.total_size,
      alert_id: collection.alert_id,
      case_id: collection.case_id,
      requested_by: collection.requested_by,
      started_at: format_datetime(collection.started_at),
      completed_at: format_datetime(collection.completed_at),
      created_at: format_datetime(collection.inserted_at)
    }
  end

  defp serialize_collection_detail(collection) do
    %{
      id: collection.id,
      agent_id: collection.agent_id,
      hostname: collection.hostname,
      type: collection.type,
      status: collection.status,
      priority: collection.priority,
      paths: collection.paths,
      options: collection.options,
      artifacts: Enum.map(collection.artifacts || [], &serialize_artifact/1),
      artifact_count: collection.artifact_count,
      total_size: collection.total_size,
      alert_id: collection.alert_id,
      case_id: collection.case_id,
      chain_of_custody: collection.chain_of_custody,
      analysis_results: collection.analysis_results,
      notes: collection.notes,
      requested_by: collection.requested_by,
      started_at: format_datetime(collection.started_at),
      completed_at: format_datetime(collection.completed_at),
      created_at: format_datetime(collection.inserted_at),
      updated_at: format_datetime(collection.updated_at)
    }
  end

  defp serialize_artifact(artifact) do
    %{
      id: artifact.id,
      name: artifact.name,
      type: artifact.type,
      size: artifact.size,
      hash_md5: artifact.hash_md5,
      hash_sha256: artifact.hash_sha256,
      source_path: artifact.source_path,
      collected_at: format_datetime(artifact.collected_at)
    }
  end

  defp validate_collection_complete(%{status: "completed"}), do: :ok
  defp validate_collection_complete(_), do: {:error, :collection_incomplete}

  defp get_current_user_id(conn) do
    case conn.assigns[:current_user] do
      nil -> nil
      user -> user.id
    end
  end

  defp get_current_organization_id(conn) do
    conn.assigns[:current_organization_id] ||
      case conn.assigns[:current_user] do
        nil -> nil
        user -> Map.get(user, :organization_id)
      end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, _key, ""), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp format_datetime(nil), do: nil
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
end
