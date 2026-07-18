defmodule TamanduaServer.ThreatIntel.MISP do
  @moduledoc """
  MISP (Malware Information Sharing Platform) REST API client.

  Provides functionality to:
  - Connect to MISP instances
  - Fetch events with filters
  - Parse attributes to internal IOC format
  - Handle galaxy/cluster data for threat actor info
  - Support incremental synchronization

  ## Configuration

  MISP instances are stored in the database and can be configured
  via the API or UI. Each instance requires:
  - URL: The MISP instance base URL
  - API Key: Authentication key
  - Verify SSL: Whether to verify SSL certificates

  ## Usage

      # Fetch recent events
      MISP.fetch_events(instance, since: ~N[2024-01-01 00:00:00])

      # Parse MISP attributes to IOCs
      MISP.parse_attributes(event)

      # Fetch galaxies
      MISP.fetch_galaxies(instance)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.ThreatIntel.MISPInstance
  alias TamanduaServer.ThreatIntel.MISPEvent
  alias TamanduaServer.ThreatIntel.ThreatActor
  alias TamanduaServer.Detection.IOCs

  @recv_timeout 120_000

  # Default sync interval: 4 hours
  @default_sync_interval :timer.hours(4)

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  List all configured MISP instances.
  """
  @spec list_instances() :: [MISPInstance.t()]
  def list_instances do
    if Process.whereis(__MODULE__) do
      GenServer.call(__MODULE__, :list_instances)
    else
      load_instances()
    end
  end

  @doc """
  Add a new MISP instance.
  """
  @spec add_instance(map()) :: {:ok, MISPInstance.t()} | {:error, term()}
  def add_instance(attrs) do
    GenServer.call(__MODULE__, {:add_instance, attrs})
  end

  @doc """
  Update a MISP instance.
  """
  @spec update_instance(String.t(), map()) :: {:ok, MISPInstance.t()} | {:error, term()}
  def update_instance(id, attrs) do
    GenServer.call(__MODULE__, {:update_instance, id, attrs})
  end

  @doc """
  Remove a MISP instance.
  """
  @spec remove_instance(String.t()) :: :ok | {:error, term()}
  def remove_instance(id) do
    GenServer.call(__MODULE__, {:remove_instance, id})
  end

  @doc """
  Test connection to a MISP instance.
  """
  @spec test_connection(String.t()) :: {:ok, map()} | {:error, term()}
  def test_connection(instance_id) do
    GenServer.call(__MODULE__, {:test_connection, instance_id}, 30_000)
  end

  @doc """
  Trigger sync for all enabled instances.
  """
  @spec sync_all() :: :ok
  def sync_all do
    GenServer.cast(__MODULE__, :sync_all)
  end

  @doc """
  Trigger sync for a specific instance.
  """
  @spec sync_instance(String.t()) :: :ok
  def sync_instance(instance_id) do
    GenServer.cast(__MODULE__, {:sync_instance, instance_id})
  end

  @doc """
  Get sync status for all instances.
  """
  @spec get_sync_status() :: map()
  def get_sync_status do
    if Process.whereis(__MODULE__) do
      GenServer.call(__MODULE__, :get_sync_status)
    else
      %{status: "unavailable", reason: "misp_process_not_started", instances: %{}}
    end
  end

  @doc """
  List synced MISP events.
  """
  @spec list_events(keyword()) :: [MISPEvent.t()]
  def list_events(opts \\ []) do
    if Process.whereis(__MODULE__) do
      GenServer.call(__MODULE__, {:list_events, opts})
    else
      load_events(opts)
    end
  end

  @doc """
  Fetch events from a MISP instance.
  """
  @spec fetch_events(MISPInstance.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def fetch_events(%MISPInstance{} = instance, opts \\ []) do
    do_fetch_events(instance, opts)
  end

  @doc """
  Fetch galaxies from a MISP instance.
  """
  @spec fetch_galaxies(MISPInstance.t()) :: {:ok, [map()]} | {:error, term()}
  def fetch_galaxies(%MISPInstance{} = instance) do
    do_fetch_galaxies(instance)
  end

  @doc """
  Parse MISP attributes to internal IOC format.
  """
  @spec parse_attributes(map()) :: [map()]
  def parse_attributes(event) do
    do_parse_attributes(event)
  end

  @doc """
  Correlate an alert with MISP events.
  Returns matching MISP events and threat actor info.
  """
  @spec correlate_alert(map()) :: {:ok, map()} | {:error, :no_match}
  def correlate_alert(alert) do
    GenServer.call(__MODULE__, {:correlate_alert, alert})
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(opts) do
    state = %{
      sync_status: %{},
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      enabled: Keyword.get(opts, :enabled, true)
    }

    if state.enabled do
      # Schedule initial sync after startup
      Process.send_after(self(), :initial_sync, :timer.seconds(60))
      # Schedule periodic sync
      schedule_sync(state.sync_interval)
    end

    Logger.info("[MISP] Client initialized")
    {:ok, state}
  end

  @impl true
  def handle_call(:list_instances, _from, state) do
    instances = load_instances()
    {:reply, instances, state}
  end

  @impl true
  def handle_call({:add_instance, attrs}, _from, state) do
    result = create_instance(attrs)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:update_instance, id, attrs}, _from, state) do
    result = do_update_instance(id, attrs)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:remove_instance, id}, _from, state) do
    result = delete_instance(id)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:test_connection, instance_id}, _from, state) do
    result =
      case get_instance(instance_id) do
        nil -> {:error, :not_found}
        instance -> do_test_connection(instance)
      end

    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_sync_status, _from, state) do
    {:reply, state.sync_status, state}
  end

  @impl true
  def handle_call({:list_events, opts}, _from, state) do
    events = load_events(opts)
    {:reply, events, state}
  end

  @impl true
  def handle_call({:correlate_alert, alert}, _from, state) do
    result = do_correlate_alert(alert)
    {:reply, result, state}
  end

  @impl true
  def handle_cast(:sync_all, state) do
    parent = self()

    Task.start(fn ->
      results = do_sync_all()
      send(parent, {:sync_complete, results})
    end)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:sync_instance, instance_id}, state) do
    parent = self()

    Task.start(fn ->
      result = do_sync_instance(instance_id)
      send(parent, {:instance_sync_complete, instance_id, result})
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info(:initial_sync, state) do
    Logger.info("[MISP] Starting initial sync...")
    send(self(), {:do_sync, :initial})
    {:noreply, state}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    Logger.info("[MISP] Starting periodic sync...")
    send(self(), {:do_sync, :periodic})
    schedule_sync(state.sync_interval)
    {:noreply, state}
  end

  @impl true
  def handle_info({:do_sync, _type}, state) do
    parent = self()

    Task.start(fn ->
      results = do_sync_all()
      send(parent, {:sync_complete, results})
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info({:sync_complete, results}, state) do
    Logger.info("[MISP] Sync complete for #{map_size(results)} instances")
    new_status = Map.merge(state.sync_status, results)
    {:noreply, %{state | sync_status: new_status}}
  end

  @impl true
  def handle_info({:instance_sync_complete, instance_id, result}, state) do
    Logger.info("[MISP] Instance #{instance_id} sync complete")
    new_status = Map.put(state.sync_status, instance_id, result)
    {:noreply, %{state | sync_status: new_status}}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ============================================================================
  # Private Functions - Instance Management
  # ============================================================================

  defp load_instances do
    import Ecto.Query
    Repo.all(from(i in MISPInstance, order_by: [asc: i.name]))
  rescue
    _ -> []
  end

  defp get_instance(id) do
    Repo.get(MISPInstance, id)
  rescue
    _ -> nil
  end

  defp create_instance(attrs) do
    %MISPInstance{}
    |> MISPInstance.changeset(attrs)
    |> Repo.insert()
  end

  defp do_update_instance(id, attrs) do
    case get_instance(id) do
      nil ->
        {:error, :not_found}

      instance ->
        instance
        |> MISPInstance.changeset(attrs)
        |> Repo.update()
    end
  end

  defp delete_instance(id) do
    case get_instance(id) do
      nil -> {:error, :not_found}
      instance -> Repo.delete(instance)
    end
  end

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end

  # ============================================================================
  # Private Functions - Connection Testing
  # ============================================================================

  defp do_test_connection(%MISPInstance{url: url, api_key: api_key, verify_ssl: verify_ssl}) do
    headers = build_headers(api_key)
    _ssl_options = if verify_ssl, do: [], else: [ssl: [verify: :verify_none]]

    case Finch.build(:get, "#{url}/servers/getVersion", headers)
         |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, data} ->
            {:ok,
             %{
               connected: true,
               version: Map.get(data, "version"),
               perm_sync: Map.get(data, "perm_sync", false),
               perm_sighting: Map.get(data, "perm_sighting", false)
             }}

          _ ->
            {:error, :parse_error}
        end

      {:ok, %Finch.Response{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %Finch.Response{status: 403}} ->
        {:error, :forbidden}

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # Private Functions - Sync
  # ============================================================================

  defp do_sync_all do
    instances = load_instances()

    instances
    |> Enum.filter(& &1.enabled)
    |> Enum.reduce(%{}, fn instance, acc ->
      result = sync_single_instance(instance)
      Map.put(acc, instance.id, result)
    end)
  end

  defp do_sync_instance(instance_id) do
    case get_instance(instance_id) do
      nil -> {:error, :not_found}
      instance -> sync_single_instance(instance)
    end
  end

  defp sync_single_instance(%MISPInstance{} = instance) do
    Logger.info("[MISP] Syncing instance: #{instance.name}")

    with {:ok, events} <- do_fetch_events(instance, since: instance.last_sync),
         {:ok, ioc_count} <- process_events(instance, events),
         {:ok, _} <- update_last_sync(instance) do
      # Also sync galaxies for threat actor info
      sync_galaxies(instance)

      %{
        status: :ok,
        last_sync: DateTime.utc_now(),
        events_synced: length(events),
        iocs_imported: ioc_count
      }
    else
      {:error, reason} ->
        Logger.error("[MISP] Sync failed for #{instance.name}: #{inspect(reason)}")
        %{status: :error, error: inspect(reason), last_sync: instance.last_sync}
    end
  end

  defp update_last_sync(instance) do
    instance
    |> MISPInstance.changeset(%{last_sync: DateTime.utc_now()})
    |> Repo.update()
  end

  # ============================================================================
  # Private Functions - Event Fetching
  # ============================================================================

  defp do_fetch_events(%MISPInstance{url: url, api_key: api_key, verify_ssl: verify_ssl}, opts) do
    headers = build_headers(api_key)
    _ssl_options = if verify_ssl, do: [], else: [ssl: [verify: :verify_none]]

    # Build request body
    request_body = build_event_search_body(opts)

    case Finch.build(:post, "#{url}/events/restSearch", headers, Jason.encode!(request_body))
         |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_events_response(body)

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp build_event_search_body(opts) do
    base = %{
      "returnFormat" => "json",
      "enforceWarninglist" => true,
      "includeEventTags" => true,
      "includeGalaxy" => true
    }

    base
    |> maybe_add_timestamp(opts[:since])
    |> maybe_add_tags(opts[:tags])
    |> maybe_add_limit(opts[:limit])
    |> maybe_add_published(opts[:published])
  end

  defp maybe_add_timestamp(body, nil), do: body

  defp maybe_add_timestamp(body, %DateTime{} = dt) do
    Map.put(body, "timestamp", DateTime.to_unix(dt))
  end

  defp maybe_add_timestamp(body, %NaiveDateTime{} = dt) do
    Map.put(body, "timestamp", NaiveDateTime.diff(dt, ~N[1970-01-01 00:00:00]))
  end

  defp maybe_add_timestamp(body, timestamp) when is_binary(timestamp) do
    Map.put(body, "timestamp", timestamp)
  end

  defp maybe_add_tags(body, nil), do: body

  defp maybe_add_tags(body, tags) when is_list(tags) do
    Map.put(body, "tags", tags)
  end

  defp maybe_add_limit(body, nil), do: Map.put(body, "limit", 100)
  defp maybe_add_limit(body, limit), do: Map.put(body, "limit", limit)

  defp maybe_add_published(body, nil), do: body

  defp maybe_add_published(body, published) do
    Map.put(body, "published", published)
  end

  defp parse_events_response(body) do
    case Jason.decode(body) do
      {:ok, %{"response" => events}} when is_list(events) ->
        {:ok, Enum.map(events, &Map.get(&1, "Event"))}

      {:ok, events} when is_list(events) ->
        {:ok, events}

      {:ok, _} ->
        {:ok, []}

      {:error, reason} ->
        {:error, {:json_parse_error, reason}}
    end
  end

  # ============================================================================
  # Private Functions - Event Processing
  # ============================================================================

  defp process_events(instance, events) do
    iocs =
      events
      |> Enum.flat_map(&do_parse_attributes/1)
      |> Enum.map(fn ioc ->
        Map.merge(ioc, %{
          source: "misp:#{instance.name}",
          misp_instance_id: instance.id
        })
      end)

    # Store events in database
    Enum.each(events, fn event ->
      store_misp_event(instance, event)
    end)

    # Bulk add IOCs
    case IOCs.bulk_add_global(iocs, on_conflict: :nothing) do
      {:ok, %{successful: count}} ->
        # Refresh the detection engine ETS cache so workers see new IOCs
        if count > 0 do
          TamanduaServer.Detection.IOCReload.schedule()
        end

        {:ok, count}

      error ->
        error
    end
  end

  defp store_misp_event(instance, event) do
    attrs = %{
      misp_instance_id: instance.id,
      misp_event_id: Map.get(event, "id"),
      uuid: Map.get(event, "uuid"),
      info: Map.get(event, "info"),
      threat_level_id: parse_integer(Map.get(event, "threat_level_id")),
      analysis: parse_integer(Map.get(event, "analysis")),
      date: Map.get(event, "date"),
      published: Map.get(event, "published") == true or Map.get(event, "published") == "1",
      org_name: get_in(event, ["Org", "name"]),
      orgc_name: get_in(event, ["Orgc", "name"]),
      tags: extract_tags(event),
      galaxies: extract_galaxies(event),
      attribute_count: length(Map.get(event, "Attribute", [])),
      tlp: extract_tlp(event)
    }

    %MISPEvent{}
    |> MISPEvent.changeset(attrs)
    |> Repo.insert(
      on_conflict: :replace_all,
      conflict_target: [:misp_instance_id, :misp_event_id]
    )
  rescue
    e ->
      Logger.warning("[MISP] Failed to store event: #{inspect(e)}")
      nil
  end

  defp parse_integer(nil), do: nil
  defp parse_integer(val) when is_integer(val), do: val
  defp parse_integer(val) when is_binary(val), do: String.to_integer(val)

  # ============================================================================
  # Private Functions - Attribute Parsing
  # ============================================================================

  @doc false
  def do_parse_attributes(event) do
    attributes = Map.get(event, "Attribute", [])
    event_info = Map.get(event, "info", "unknown")
    tags = extract_tags(event)
    tlp = extract_tlp(event)
    mitre_ttps = extract_mitre_ttps(event)

    attributes
    |> Enum.map(fn attr ->
      parse_single_attribute(attr, event_info, tags, tlp, mitre_ttps)
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp parse_single_attribute(attr, event_info, tags, tlp, mitre_ttps) do
    misp_type = Map.get(attr, "type")
    value = Map.get(attr, "value", "")
    ioc_type = misp_type_to_ioc_type(misp_type)

    if ioc_type do
      %{
        type: ioc_type,
        value: normalize_value(ioc_type, value),
        severity: determine_severity(attr),
        description: event_info,
        tags: tags ++ extract_attribute_tags(attr),
        metadata: %{
          "misp_type" => misp_type,
          "misp_uuid" => Map.get(attr, "uuid"),
          "misp_category" => Map.get(attr, "category"),
          "to_ids" => Map.get(attr, "to_ids"),
          "tlp" => tlp,
          "mitre_ttps" => mitre_ttps,
          "comment" => Map.get(attr, "comment")
        }
      }
    else
      nil
    end
  end

  # Map MISP attribute types to internal IOC types
  defp misp_type_to_ioc_type(type) do
    case type do
      # IP types
      "ip-src" -> "ip"
      "ip-dst" -> "ip"
      "ip-dst|port" -> "ip"
      "ip-src|port" -> "ip"
      # Domain types
      "domain" -> "domain"
      "hostname" -> "domain"
      "domain|ip" -> "domain"
      # Hash types
      "md5" -> "hash_md5"
      "sha1" -> "hash_sha1"
      "sha256" -> "hash_sha256"
      "filename|md5" -> "hash_md5"
      "filename|sha1" -> "hash_sha1"
      "filename|sha256" -> "hash_sha256"
      # Store as sha256 for simplicity
      "ssdeep" -> "hash_sha256"
      "imphash" -> "hash_md5"
      "authentihash" -> "hash_sha256"
      # URL types
      "url" -> "url"
      "uri" -> "url"
      "link" -> "url"
      # Email types
      "email-src" -> "email"
      "email-dst" -> "email"
      "email" -> "email"
      # Not a direct IOC
      "email-subject" -> nil
      # Filename types
      "filename" -> "filename"
      "filepath" -> "filename"
      # Registry (store as filename for searchability)
      "regkey" -> "filename"
      "regkey|value" -> "filename"
      # Unsupported types
      _ -> nil
    end
  end

  defp normalize_value("ip", value) do
    # Handle ip|port format
    value
    |> String.split("|")
    |> List.first()
    |> String.trim()
    |> String.downcase()
  end

  defp normalize_value("domain", value) do
    # Handle domain|ip format
    value
    |> String.split("|")
    |> List.first()
    |> String.trim()
    |> String.downcase()
    |> String.trim_leading("www.")
  end

  defp normalize_value(type, value) when type in ["hash_md5", "hash_sha1", "hash_sha256"] do
    # Handle filename|hash format
    value
    |> String.split("|")
    |> List.last()
    |> String.trim()
    |> String.downcase()
  end

  defp normalize_value(_type, value), do: String.trim(value)

  defp determine_severity(attr) do
    to_ids = Map.get(attr, "to_ids")
    category = Map.get(attr, "category", "")

    cond do
      to_ids == true or to_ids == "1" ->
        case category do
          c when c in ["Payload delivery", "Payload installation", "External analysis"] ->
            "critical"

          c when c in ["Network activity", "Artifacts dropped"] ->
            "high"

          _ ->
            "high"
        end

      true ->
        "medium"
    end
  end

  defp extract_attribute_tags(attr) do
    attr
    |> Map.get("Tag", [])
    |> Enum.map(&Map.get(&1, "name", ""))
    |> Enum.reject(&(&1 == ""))
  end

  # ============================================================================
  # Private Functions - Tag/Galaxy Extraction
  # ============================================================================

  defp extract_tags(event) do
    event
    |> Map.get("Tag", [])
    |> Enum.map(&Map.get(&1, "name", ""))
    |> Enum.reject(&(&1 == ""))
    # TLP handled separately
    |> Enum.reject(&String.starts_with?(&1, "tlp:"))
    |> Enum.map(&sanitize_tag/1)
  end

  defp sanitize_tag(tag) do
    tag
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9\-_:]/, "-")
    |> String.slice(0, 50)
  end

  defp extract_tlp(event) do
    # Default to AMBER if not specified
    event
    |> Map.get("Tag", [])
    |> Enum.find_value(fn tag ->
      name = Map.get(tag, "name", "")

      if String.starts_with?(name, "tlp:") do
        String.replace(name, "tlp:", "") |> String.upcase()
      end
    end) || "AMBER"
  end

  defp extract_mitre_ttps(event) do
    event
    |> Map.get("Tag", [])
    |> Enum.filter(fn tag ->
      name = Map.get(tag, "name", "")
      String.starts_with?(name, "mitre-attack:")
    end)
    |> Enum.map(fn tag ->
      Map.get(tag, "name", "")
      |> String.replace("mitre-attack:", "")
    end)
  end

  defp extract_galaxies(event) do
    event
    |> Map.get("Galaxy", [])
    |> Enum.map(fn galaxy ->
      %{
        "name" => Map.get(galaxy, "name"),
        "type" => Map.get(galaxy, "type"),
        "clusters" => extract_clusters(galaxy)
      }
    end)
  end

  defp extract_clusters(galaxy) do
    galaxy
    |> Map.get("GalaxyCluster", [])
    |> Enum.map(fn cluster ->
      %{
        "value" => Map.get(cluster, "value"),
        "description" => Map.get(cluster, "description"),
        "uuid" => Map.get(cluster, "uuid")
      }
    end)
  end

  # ============================================================================
  # Private Functions - Galaxy Sync
  # ============================================================================

  defp do_fetch_galaxies(%MISPInstance{url: url, api_key: api_key, verify_ssl: verify_ssl}) do
    headers = build_headers(api_key)
    _ssl_options = if verify_ssl, do: [], else: [ssl: [verify: :verify_none]]

    case Finch.build(:get, "#{url}/galaxies", headers)
         |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, galaxies} when is_list(galaxies) ->
            {:ok, galaxies}

          _ ->
            {:ok, []}
        end

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp sync_galaxies(instance) do
    case do_fetch_galaxies(instance) do
      {:ok, galaxies} ->
        # Focus on threat actor galaxies
        threat_actor_galaxies =
          galaxies
          |> Enum.filter(fn g ->
            type = Map.get(g, "type", "")
            type in ["threat-actor", "intrusion-set", "mitre-intrusion-set"]
          end)

        Enum.each(threat_actor_galaxies, fn galaxy ->
          sync_galaxy_clusters(instance, galaxy)
        end)

        {:ok, length(threat_actor_galaxies)}

      {:error, reason} ->
        Logger.warning("[MISP] Failed to sync galaxies: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp sync_galaxy_clusters(instance, galaxy) do
    galaxy_id = Map.get(galaxy, "id")
    url = "#{instance.url}/galaxies/view/#{galaxy_id}"
    headers = build_headers(instance.api_key)
    _ssl_options = if instance.verify_ssl, do: [], else: [ssl: [verify: :verify_none]]

    case Finch.build(:get, url, headers)
         |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"Galaxy" => galaxy_data, "GalaxyCluster" => clusters}} ->
            Enum.each(clusters, fn cluster ->
              import_threat_actor_from_cluster(instance, galaxy_data, cluster)
            end)

          _ ->
            :ok
        end

      _ ->
        :ok
    end
  end

  defp import_threat_actor_from_cluster(instance, galaxy, cluster) do
    attrs = %{
      misp_instance_id: instance.id,
      misp_cluster_uuid: Map.get(cluster, "uuid"),
      name: Map.get(cluster, "value"),
      description: Map.get(cluster, "description"),
      galaxy_type: Map.get(galaxy, "type"),
      aliases: extract_aliases(cluster),
      motivation: extract_motivation(cluster),
      target_sectors: extract_target_sectors(cluster),
      origin_country: extract_country(cluster),
      ttps: extract_cluster_ttps(cluster),
      first_seen: extract_first_seen(cluster),
      last_seen: DateTime.utc_now(),
      metadata: %{
        "source" => "misp",
        "galaxy_name" => Map.get(galaxy, "name"),
        "cluster_id" => Map.get(cluster, "id")
      }
    }

    %ThreatActor{}
    |> ThreatActor.changeset(attrs)
    |> Repo.insert(
      on_conflict:
        {:replace,
         [:description, :aliases, :motivation, :target_sectors, :ttps, :last_seen, :metadata]},
      conflict_target: [:misp_cluster_uuid]
    )
  rescue
    e ->
      Logger.warning("[MISP] Failed to import threat actor: #{inspect(e)}")
      nil
  end

  defp extract_aliases(cluster) do
    meta = Map.get(cluster, "meta", %{})
    aliases = Map.get(meta, "synonyms", []) ++ Map.get(meta, "aliases", [])
    Enum.uniq(aliases)
  end

  defp extract_motivation(cluster) do
    meta = Map.get(cluster, "meta", %{})
    cfr_type = Map.get(meta, "cfr-type-of-incident", [])

    cond do
      Enum.any?(cfr_type, &String.contains?(&1, "Espionage")) -> "espionage"
      Enum.any?(cfr_type, &String.contains?(&1, "Crime")) -> "financial"
      Enum.any?(cfr_type, &String.contains?(&1, "Hacktivism")) -> "hacktivism"
      Enum.any?(cfr_type, &String.contains?(&1, "Sabotage")) -> "sabotage"
      true -> "unknown"
    end
  end

  defp extract_target_sectors(cluster) do
    meta = Map.get(cluster, "meta", %{})

    (Map.get(meta, "cfr-target-category", []) ++ Map.get(meta, "sectors", []))
    |> Enum.uniq()
  end

  defp extract_country(cluster) do
    meta = Map.get(cluster, "meta", %{})
    country = Map.get(meta, "country", [])

    case country do
      [c | _] -> c
      c when is_binary(c) -> c
      _ -> "Unknown"
    end
  end

  defp extract_cluster_ttps(cluster) do
    meta = Map.get(cluster, "meta", %{})

    (Map.get(meta, "mitre-attack-id", []) ++ Map.get(meta, "refs", []))
    |> Enum.filter(&String.match?(&1, ~r/^T\d{4}/))
    |> Enum.uniq()
  end

  defp extract_first_seen(cluster) do
    meta = Map.get(cluster, "meta", %{})
    date = Map.get(meta, "date", nil)

    case date do
      nil ->
        nil

      d when is_binary(d) ->
        case Date.from_iso8601(d) do
          {:ok, date} -> DateTime.new!(date, ~T[00:00:00], "Etc/UTC")
          _ -> nil
        end

      _ ->
        nil
    end
  end

  # ============================================================================
  # Private Functions - Alert Correlation
  # ============================================================================

  defp do_correlate_alert(alert) do
    import Ecto.Query

    # Extract IOCs from alert
    alert_iocs = extract_alert_iocs(alert)

    if Enum.empty?(alert_iocs) do
      {:error, :no_match}
    else
      # Search for matching MISP events
      matching_events =
        from(e in MISPEvent,
          where: fragment("? && ?", e.tags, ^Enum.take(alert_iocs, 10)),
          or_where: ilike(e.info, ^"%#{List.first(alert_iocs)}%"),
          limit: 5,
          order_by: [desc: e.inserted_at]
        )
        |> Repo.all()

      # Search for matching threat actors
      matching_actors =
        from(a in ThreatActor,
          where: fragment("? && ?", a.ttps, ^(alert.mitre_techniques || [])),
          limit: 3,
          order_by: [desc: a.last_seen]
        )
        |> Repo.all()

      if Enum.empty?(matching_events) and Enum.empty?(matching_actors) do
        {:error, :no_match}
      else
        {:ok,
         %{
           misp_events: Enum.map(matching_events, &serialize_event/1),
           threat_actors: Enum.map(matching_actors, &serialize_actor/1),
           correlation_score: calculate_correlation_score(matching_events, matching_actors)
         }}
      end
    end
  rescue
    _ -> {:error, :no_match}
  end

  defp extract_alert_iocs(alert) do
    enrichment = Map.get(alert, :enrichment, %{}) || %{}

    iocs = []

    # Extract IPs
    iocs = iocs ++ (Map.get(enrichment, "src_ips", []) || [])
    iocs = iocs ++ (Map.get(enrichment, "dst_ips", []) || [])

    # Extract domains
    iocs = iocs ++ (Map.get(enrichment, "domains", []) || [])

    # Extract hashes
    iocs = iocs ++ (Map.get(enrichment, "hashes", []) || [])

    # Extract from title/description
    title = Map.get(alert, :title, "") || ""
    iocs = iocs ++ extract_iocs_from_text(title)

    Enum.uniq(iocs)
  end

  defp extract_iocs_from_text(text) do
    ip_regex = ~r/\b(?:\d{1,3}\.){3}\d{1,3}\b/
    hash_regex = ~r/\b[a-fA-F0-9]{32,64}\b/

    ips = Regex.scan(ip_regex, text) |> List.flatten()
    hashes = Regex.scan(hash_regex, text) |> List.flatten()

    ips ++ hashes
  end

  defp calculate_correlation_score(events, actors) do
    event_score = min(length(events) * 20, 50)
    actor_score = min(length(actors) * 25, 50)
    event_score + actor_score
  end

  defp serialize_event(event) do
    %{
      id: event.id,
      misp_event_id: event.misp_event_id,
      uuid: event.uuid,
      info: event.info,
      threat_level: event.threat_level_id,
      date: event.date,
      org: event.org_name,
      tags: event.tags,
      tlp: event.tlp
    }
  end

  defp serialize_actor(actor) do
    %{
      id: actor.id,
      name: actor.name,
      aliases: actor.aliases,
      motivation: actor.motivation,
      origin_country: actor.origin_country,
      ttps: actor.ttps
    }
  end

  # ============================================================================
  # Private Functions - Event Loading
  # ============================================================================

  defp load_events(opts) do
    import Ecto.Query

    limit = Keyword.get(opts, :limit, 50)
    instance_id = Keyword.get(opts, :instance_id)

    base_query =
      from(e in MISPEvent,
        order_by: [desc: e.inserted_at],
        limit: ^limit
      )

    query =
      if instance_id do
        where(base_query, [e], e.misp_instance_id == ^instance_id)
      else
        base_query
      end

    Repo.all(query)
  rescue
    _ -> []
  end

  # ============================================================================
  # Private Functions - Helpers
  # ============================================================================

  defp build_headers(api_key) do
    [
      {"Authorization", api_key},
      {"Accept", "application/json"},
      {"Content-Type", "application/json"}
    ]
  end
end
