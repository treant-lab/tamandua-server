defmodule TamanduaServer.Forensics.Collector do
  @moduledoc """
  Digital forensics collection and evidence management.

  Handles:
  - Forensic image collection from endpoints
  - Evidence chain of custody tracking
  - Artifact extraction and analysis
  - Forensic archive creation for legal/compliance
  """
  use GenServer
  require Logger

  alias TamanduaServer.Agents

  @collection_timeout 300_000  # 5 minutes

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Creates a new forensic collection request.
  """
  def create_collection(params) when is_map(params) do
    collection = %{
      id: generate_id(),
      agent_id: Map.get(params, :agent_id) || Map.get(params, "agent_id"),
      organization_id: Map.get(params, :organization_id) || Map.get(params, "organization_id"),
      type: Map.get(params, :type) || Map.get(params, "type") || "full",
      artifacts: Map.get(params, :artifacts) || Map.get(params, "artifacts") || ["all"],
      status: "pending",
      created_at: DateTime.utc_now(),
      created_by: Map.get(params, :user_id) || Map.get(params, "user_id"),
      evidence_chain: [
        %{
          action: "created",
          timestamp: DateTime.utc_now(),
          user: Map.get(params, :user_id) || Map.get(params, "user_id"),
          notes: "Collection initiated"
        }
      ],
      artifacts_collected: [],
      metadata: %{}
    }

    GenServer.call(__MODULE__, {:create_collection, collection})
  end

  @doc """
  Gets a forensic collection by ID.
  """
  def get_collection(collection_id) do
    GenServer.call(__MODULE__, {:get_collection, collection_id})
  end

  @doc """
  Lists all forensic collections with optional filtering.
  """
  def list_collections(filters \\ %{}) do
    GenServer.call(__MODULE__, {:list_collections, filters})
  end

  @doc """
  Gets a specific artifact from a collection.
  """
  def get_artifact(collection_id, artifact_id) do
    GenServer.call(__MODULE__, {:get_artifact, collection_id, artifact_id})
  end

  @doc """
  Creates a forensic archive for a collection.
  """
  def create_archive(collection_id) do
    GenServer.call(__MODULE__, {:create_archive, collection_id})
  end

  @doc """
  Logs access to forensic evidence (chain of custody).
  """
  def log_access(collection_id, user_id, action) do
    GenServer.call(__MODULE__, {:log_access, collection_id, user_id, action})
  end

  @doc """
  Starts forensic analysis on collected artifacts.
  """
  def start_analysis(collection_id, analysis_type, opts \\ %{}) do
    GenServer.call(__MODULE__, {:start_analysis, collection_id, analysis_type, opts})
  end

  @doc """
  Updates the status of a collection.
  """
  def update_status(collection_id, status) do
    GenServer.call(__MODULE__, {:update_status, collection_id, status})
  end

  @doc """
  Adds an artifact to a collection.
  """
  def add_artifact(collection_id, artifact) do
    GenServer.call(__MODULE__, {:add_artifact, collection_id, artifact})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    state = %{
      collections: %{},
      active_jobs: %{},
      archive_path: Application.get_env(:tamandua_server, :forensics_path, "/tmp/forensics")
    }

    # Ensure archive directory exists
    File.mkdir_p!(state.archive_path)

    {:ok, state}
  end

  @impl true
  def handle_call({:create_collection, collection}, _from, state) do
    collection_id = collection.id
    new_collections = Map.put(state.collections, collection_id, collection)

    # Trigger collection on agent
    if collection.agent_id do
      Task.start(fn ->
        trigger_agent_collection(collection)
      end)
    end

    {:reply, {:ok, collection}, %{state | collections: new_collections}}
  end

  @impl true
  def handle_call({:get_collection, collection_id}, _from, state) do
    case Map.get(state.collections, collection_id) do
      nil -> {:reply, {:error, :not_found}, state}
      collection -> {:reply, {:ok, collection}, state}
    end
  end

  @impl true
  def handle_call({:list_collections, filters}, _from, state) do
    collections =
      state.collections
      |> Map.values()
      |> filter_collections(filters)
      |> Enum.sort_by(& &1.created_at, {:desc, DateTime})

    {:reply, {:ok, collections}, state}
  end

  @impl true
  def handle_call({:get_artifact, collection_id, artifact_id}, _from, state) do
    result =
      with {:ok, collection} <- get_collection_from_state(state, collection_id),
           artifact <- find_artifact(collection.artifacts_collected, artifact_id) do
        {:ok, artifact}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:create_archive, collection_id}, _from, state) do
    result =
      with {:ok, collection} <- get_collection_from_state(state, collection_id) do
        archive_path = create_archive_file(collection, state.archive_path)
        {:ok, %{path: archive_path, collection_id: collection_id}}
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:log_access, collection_id, user_id, action}, _from, state) do
    case Map.get(state.collections, collection_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      collection ->
        entry = %{
          action: action,
          timestamp: DateTime.utc_now(),
          user: user_id,
          notes: "Access logged"
        }

        updated_collection = %{
          collection
          | evidence_chain: collection.evidence_chain ++ [entry]
        }

        new_collections = Map.put(state.collections, collection_id, updated_collection)
        {:reply, {:ok, updated_collection}, %{state | collections: new_collections}}
    end
  end

  @impl true
  def handle_call({:start_analysis, collection_id, analysis_type, opts}, _from, state) do
    case Map.get(state.collections, collection_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      collection ->
        analysis_job = %{
          id: generate_id(),
          collection_id: collection_id,
          type: analysis_type,
          status: "running",
          started_at: DateTime.utc_now(),
          options: opts
        }

        # Start analysis task
        Task.start(fn ->
          run_analysis(collection, analysis_type, opts)
        end)

        new_jobs = Map.put(state.active_jobs, analysis_job.id, analysis_job)
        {:reply, {:ok, analysis_job}, %{state | active_jobs: new_jobs}}
    end
  end

  @impl true
  def handle_call({:update_status, collection_id, status}, _from, state) do
    case Map.get(state.collections, collection_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      collection ->
        updated_collection = Map.put(collection, :status, status)
        new_collections = Map.put(state.collections, collection_id, updated_collection)
        {:reply, {:ok, updated_collection}, %{state | collections: new_collections}}
    end
  end

  @impl true
  def handle_call({:add_artifact, collection_id, artifact}, _from, state) do
    case Map.get(state.collections, collection_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      collection ->
        artifact_with_id = Map.put_new(artifact, :id, generate_id())

        updated_collection = %{
          collection
          | artifacts_collected: collection.artifacts_collected ++ [artifact_with_id]
        }

        new_collections = Map.put(state.collections, collection_id, updated_collection)
        {:reply, {:ok, updated_collection}, %{state | collections: new_collections}}
    end
  end

  @impl true
  def handle_info({:collection_complete, collection_id, artifacts}, state) do
    case Map.get(state.collections, collection_id) do
      nil ->
        {:noreply, state}

      collection ->
        updated_collection = %{
          collection
          | status: "completed",
            artifacts_collected: artifacts,
            evidence_chain:
              collection.evidence_chain ++
                [
                  %{
                    action: "completed",
                    timestamp: DateTime.utc_now(),
                    user: "system",
                    notes: "Collection completed with #{length(artifacts)} artifacts"
                  }
                ]
        }

        new_collections = Map.put(state.collections, collection_id, updated_collection)
        {:noreply, %{state | collections: new_collections}}
    end
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Private Functions

  defp generate_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end

  defp get_collection_from_state(state, collection_id) do
    case Map.get(state.collections, collection_id) do
      nil -> {:error, :not_found}
      collection -> {:ok, collection}
    end
  end

  defp find_artifact(artifacts, artifact_id) do
    Enum.find(artifacts, fn a -> a[:id] == artifact_id || a["id"] == artifact_id end)
  end

  defp filter_collections(collections, filters) do
    Enum.filter(collections, fn collection ->
      filter_match?(collection, filters)
    end)
  end

  defp filter_match?(collection, filters) do
    Enum.all?(filters, fn
      {:organization_id, org_id} -> Map.get(collection, :organization_id) == org_id
      {"organization_id", org_id} -> Map.get(collection, :organization_id) == org_id
      {:agent_id, agent_id} -> collection.agent_id == agent_id
      {:status, status} -> collection.status == status
      {:type, type} -> collection.type == type
      {"agent_id", agent_id} -> collection.agent_id == agent_id
      {"status", status} -> collection.status == status
      {"type", type} -> collection.type == type
      _ -> true
    end)
  end

  defp trigger_agent_collection(collection) do
    case Agents.get_agent(collection.agent_id) do
      {:ok, agent} ->
        command = %{
          type: "collect_forensics",
          collection_id: collection.id,
          artifacts: collection.artifacts,
          options: %{
            compress: true,
            encrypt: true
          }
        }

        Agents.send_command(agent.id, command)

      {:error, reason} ->
        Logger.error("Failed to trigger collection on agent: #{inspect(reason)}")
    end
  end

  defp create_archive_file(collection, base_path) do
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601() |> String.replace(~r/[:\-]/, "")
    archive_name = "forensics_#{collection.id}_#{timestamp}.tar.gz"
    archive_path = Path.join(base_path, archive_name)

    # Create metadata file
    metadata = %{
      collection_id: collection.id,
      agent_id: collection.agent_id,
      created_at: collection.created_at,
      evidence_chain: collection.evidence_chain,
      artifacts_count: length(collection.artifacts_collected),
      archive_created_at: DateTime.utc_now()
    }

    metadata_json = Jason.encode!(metadata, pretty: true)
    metadata_path = Path.join(base_path, "metadata_#{collection.id}.json")
    File.write!(metadata_path, metadata_json)

    # In production, would create actual tar.gz with artifacts
    # For now, just return the intended path
    archive_path
  end

  defp run_analysis(collection, analysis_type, _opts) do
    Logger.info("Running #{analysis_type} analysis on collection #{collection.id}")

    # Simulate analysis based on type
    case analysis_type do
      "timeline" ->
        build_timeline(collection)

      "ioc_extraction" ->
        extract_iocs(collection)

      "malware_scan" ->
        scan_for_malware(collection)

      _ ->
        Logger.warning("Unknown analysis type: #{analysis_type}")
    end
  end

  defp build_timeline(collection) do
    Logger.info("Building forensic timeline for #{collection.id}")
    # Timeline building logic
    :ok
  end

  defp extract_iocs(collection) do
    Logger.info("Extracting IOCs from #{collection.id}")
    # IOC extraction logic
    :ok
  end

  defp scan_for_malware(collection) do
    Logger.info("Scanning collection #{collection.id} for malware")
    # Malware scanning logic
    :ok
  end
end
