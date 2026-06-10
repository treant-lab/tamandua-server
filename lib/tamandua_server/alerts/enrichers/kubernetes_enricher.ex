defmodule TamanduaServer.Alerts.Enrichers.KubernetesEnricher do
  @moduledoc """
  Enriches alerts with Kubernetes pod metadata using k8s library.

  Caches pod information in ETS with 60-second TTL to minimize API calls.
  Handles deleted pods gracefully by returning last-known metadata.

  ## Usage

      enriched_alert = KubernetesEnricher.enrich(alert, container_id: "abc123")

  ## Cache Behavior

  - Pod metadata cached for 60 seconds
  - Expired entries trigger fresh K8s API lookup
  - Deleted pods retain last-known metadata until TTL
  """

  use GenServer
  require Logger

  @cache_table :k8s_pod_metadata_cache
  @cache_ttl 60_000  # 60 seconds in milliseconds
  @cache_cleanup_interval 120_000  # Cleanup every 2 minutes

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Enrich alert with Kubernetes pod context.

  ## Options

  - `:container_id` - Container ID to look up (from telemetry metadata)

  ## Returns

  Alert struct with `k8s_context` field populated if container found.

  ## Example

      enriched = KubernetesEnricher.enrich(alert, container_id: "abc123def456")
      enriched.k8s_context.namespace  # => "production"
      enriched.k8s_context.pod_name   # => "myapp-7d5f7-xk2h9"
  """
  @spec enrich(struct(), keyword()) :: struct()
  def enrich(alert, opts \\ []) do
    container_id = Keyword.get(opts, :container_id) ||
                   get_in(alert.metadata || %{}, ["container_id"]) ||
                   get_in(alert.enrichment || %{}, ["container_id"])

    if container_id && container_id != "" do
      case get_pod_metadata(container_id) do
        {:ok, pod_metadata} ->
          Map.put(alert, :k8s_context, pod_metadata)

        {:error, :not_found} ->
          # Container not in K8s or pod deleted
          alert

        {:error, reason} ->
          Logger.warning("K8s enrichment failed: #{inspect(reason)}")
          alert
      end
    else
      alert
    end
  end

  @doc """
  Get pod metadata for a container ID.

  Checks ETS cache first, falls back to K8s API.
  """
  @spec get_pod_metadata(String.t()) :: {:ok, map()} | {:error, atom()}
  def get_pod_metadata(container_id) do
    GenServer.call(__MODULE__, {:get_pod_metadata, container_id})
  end

  @doc """
  Clear the pod metadata cache.
  """
  def clear_cache do
    GenServer.cast(__MODULE__, :clear_cache)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    # Create ETS table for pod metadata cache
    :ets.new(@cache_table, [:set, :public, :named_table, read_concurrency: true])

    # Schedule periodic cache cleanup
    schedule_cleanup()

    # Initialize K8s connection
    conn = init_k8s_connection()

    {:ok, %{conn: conn}}
  end

  @impl true
  def handle_call({:get_pod_metadata, container_id}, _from, state) do
    result = case lookup_cache(container_id) do
      {:ok, metadata} ->
        {:ok, metadata}

      :miss ->
        # Fetch from K8s API
        case fetch_pod_metadata(container_id, state.conn) do
          {:ok, metadata} ->
            cache_metadata(container_id, metadata)
            {:ok, metadata}

          error ->
            error
        end
    end

    {:reply, result, state}
  end

  @impl true
  def handle_cast(:clear_cache, state) do
    :ets.delete_all_objects(@cache_table)
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_cache, state) do
    cleanup_expired_entries()
    schedule_cleanup()
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp init_k8s_connection do
    # Try in-cluster service account first, fall back to kubeconfig
    case K8s.Conn.from_service_account() do
      {:ok, conn} ->
        Logger.info("K8s connection initialized from service account")
        conn

      {:error, _} ->
        case K8s.Conn.from_file("~/.kube/config") do
          {:ok, conn} ->
            Logger.info("K8s connection initialized from kubeconfig")
            conn

          {:error, reason} ->
            Logger.warning("K8s connection failed: #{inspect(reason)}, enrichment disabled")
            nil
        end
    end
  rescue
    _e ->
      # K8s library not available or connection failed
      Logger.debug("K8s library not available, enrichment disabled")
      nil
  end

  defp lookup_cache(container_id) do
    case :ets.lookup(@cache_table, container_id) do
      [{^container_id, metadata, inserted_at}] ->
        if System.system_time(:millisecond) - inserted_at < @cache_ttl do
          {:ok, metadata}
        else
          :miss
        end

      [] ->
        :miss
    end
  end

  defp cache_metadata(container_id, metadata) do
    :ets.insert(@cache_table, {container_id, metadata, System.system_time(:millisecond)})
  end

  defp cleanup_expired_entries do
    now = System.system_time(:millisecond)
    cutoff = now - @cache_ttl

    # Use match_spec to find and delete expired entries
    match_spec = [{{:_, :_, :"$1"}, [{:<, :"$1", cutoff}], [true]}]
    :ets.select_delete(@cache_table, match_spec)
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup_cache, @cache_cleanup_interval)
  end

  defp fetch_pod_metadata(container_id, nil) do
    # K8s connection not available
    {:error, :no_k8s_connection}
  end

  defp fetch_pod_metadata(container_id, conn) do
    # List all pods across all namespaces to find container
    # Note: This is expensive but container ID isn't a label selector
    # In production, consider using a watch-based cache
    operation = K8s.Client.list("v1", "Pod", namespace: :all)

    case K8s.Client.run(conn, operation) do
      {:ok, %{"items" => pods}} ->
        case find_pod_by_container_id(pods, container_id) do
          nil ->
            {:error, :not_found}

          pod ->
            metadata = extract_pod_metadata(pod, container_id)
            {:ok, metadata}
        end

      {:error, %{status_code: 403}} ->
        Logger.warning("K8s API access forbidden - check RBAC permissions")
        {:error, :forbidden}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("K8s API error: #{Exception.message(e)}")
      {:error, :api_error}
  end

  defp find_pod_by_container_id(pods, target_container_id) do
    # Container ID is partial (12-64 chars), match substring
    Enum.find(pods, fn pod ->
      container_statuses =
        (get_in(pod, ["status", "containerStatuses"]) || []) ++
        (get_in(pod, ["status", "initContainerStatuses"]) || [])

      Enum.any?(container_statuses, fn status ->
        # Container ID format: "docker://abc123..." or "containerd://abc123..."
        container_id = status["containerID"] || ""
        String.contains?(container_id, target_container_id) ||
          String.contains?(target_container_id, String.replace(container_id, ~r/^[^\/]+:\/\//, ""))
      end)
    end)
  end

  defp extract_pod_metadata(pod, container_id) do
    %{
      namespace: get_in(pod, ["metadata", "namespace"]),
      pod_name: get_in(pod, ["metadata", "name"]),
      node_name: get_in(pod, ["spec", "nodeName"]),
      service_account: get_in(pod, ["spec", "serviceAccountName"]),
      labels: get_in(pod, ["metadata", "labels"]) || %{},
      annotations: get_in(pod, ["metadata", "annotations"]) || %{},
      container_id: container_id,
      pod_ip: get_in(pod, ["status", "podIP"]),
      phase: get_in(pod, ["status", "phase"])
    }
  end
end
