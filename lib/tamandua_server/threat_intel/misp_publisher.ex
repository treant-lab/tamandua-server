defmodule TamanduaServer.ThreatIntel.MISPPublisher do
  @moduledoc """
  MISP Publisher GenServer for bidirectional threat intelligence sharing.

  Provides a queued, batch-aware publishing pipeline that converts Tamandua
  alerts and confirmed IOCs into MISP events with proper TLP handling,
  MITRE ATT&CK tagging, and duplicate/conflict resolution.

  ## Features

  - **Alert -> MISP Event**: Converts confirmed alerts to MISP events with
    IP, domain, hash, and URL IOC attributes.
  - **Automatic IOC Sharing**: Publishes confirmed IOCs back to MISP communities
    via a periodic flush of the internal publish queue.
  - **TLP Handling**: Supports TLP:WHITE through TLP:RED with correct MISP
    distribution levels (0 = org only, 3 = all communities).
  - **Event Tagging**: Applies MITRE ATT&CK tags, severity, analysis status,
    and custom tags to published events.
  - **Batch Publishing**: Queues items internally and flushes in configurable
    batches to avoid overwhelming the MISP REST API.
  - **Conflict Resolution**: Checks for existing events by alert ID before
    creating a new one; merges attributes into existing events when a
    duplicate is detected.
  - **Publication Tracking**: Records every publication in the
    `misp_published_alerts` table for audit and deduplication.

  ## Configuration

  Publishing requires:
  - A MISP instance with `push_enabled = true`
  - An appropriate sharing group configured
  - A user with publish permissions on MISP

  ## Usage

      # Publish an alert (queued)
      MISPPublisher.enqueue_alert(alert_id, instance_id, tlp: "GREEN")

      # Publish immediately (bypasses queue)
      MISPPublisher.publish_alert(alert, instance_id)

      # Publish confirmed IOCs
      MISPPublisher.publish_iocs(iocs, instance_id, tlp: "AMBER")

      # Batch publish multiple alerts
      MISPPublisher.batch_publish(alert_ids, instance_id)

      # Get queue and publish stats
      MISPPublisher.get_stats()
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.ThreatIntel.MISPInstance
  alias TamanduaServer.Alerts.Alert

  @recv_timeout 120_000

  # Flush interval for the publish queue (30 seconds)
  @flush_interval :timer.seconds(30)

  # Maximum items to publish in a single flush cycle
  @max_batch_size 25

  # TLP to MISP distribution mapping
  @tlp_distribution %{
    "WHITE" => 3,   # All communities
    "GREEN" => 2,   # Connected communities
    "AMBER" => 1,   # This community only
    "RED"   => 0    # Your organization only
  }

  # MISP analysis status constants
  @analysis_completed  2

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Publish an alert as a new MISP event (synchronous, bypasses queue).

  ## Options
    - `:tlp` - Traffic Light Protocol level (WHITE, GREEN, AMBER, RED)
    - `:sharing_group_id` - MISP sharing group ID
    - `:publish` - Whether to auto-publish the event (default: false)
    - `:tags` - Additional tags to add

  ## Returns
    - `{:ok, misp_event_id}` on success
    - `{:error, reason}` on failure
  """
  @spec publish_alert(Alert.t() | String.t(), String.t(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def publish_alert(alert_or_id, instance_id, opts \\ [])

  def publish_alert(%Alert{} = alert, instance_id, opts) do
    GenServer.call(__MODULE__, {:publish_alert, alert, instance_id, opts}, 60_000)
  end

  def publish_alert(alert_id, instance_id, opts) when is_binary(alert_id) do
    case Repo.get(Alert, alert_id) do
      nil -> {:error, :alert_not_found}
      alert -> publish_alert(alert, instance_id, opts)
    end
  end

  @doc """
  Enqueue an alert for batch publishing. The alert will be published on the
  next flush cycle.
  """
  @spec enqueue_alert(String.t(), String.t(), keyword()) :: :ok
  def enqueue_alert(alert_id, instance_id, opts \\ []) do
    GenServer.cast(__MODULE__, {:enqueue, :alert, alert_id, instance_id, opts})
  end

  @doc """
  Publish a list of confirmed IOCs to a MISP instance.

  Each IOC map should contain `:type` and `:value` keys at minimum.
  """
  @spec publish_iocs([map()], String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def publish_iocs(iocs, instance_id, opts \\ []) when is_list(iocs) do
    GenServer.call(__MODULE__, {:publish_iocs, iocs, instance_id, opts}, 60_000)
  end

  @doc """
  Add a sighting to an attribute in MISP.

  A sighting indicates that an IOC was observed in your environment.
  """
  @spec add_sighting(String.t(), String.t(), integer(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def add_sighting(instance_id, attribute_uuid, sighting_type \\ 0, opts \\ []) do
    GenServer.call(
      __MODULE__,
      {:add_sighting, instance_id, attribute_uuid, sighting_type, opts},
      30_000
    )
  end

  @doc """
  Report a false positive for an IOC (convenience wrapper).
  """
  @spec report_false_positive(String.t(), String.t(), keyword()) ::
          {:ok, String.t()} | {:error, term()}
  def report_false_positive(instance_id, attribute_uuid, opts \\ []) do
    add_sighting(instance_id, attribute_uuid, 1, opts)
  end

  @doc """
  Batch publish multiple alerts (synchronous).

  Returns a summary of successful and failed publications.
  """
  @spec batch_publish([String.t()], String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def batch_publish(alert_ids, instance_id, opts \\ []) when is_list(alert_ids) do
    GenServer.call(__MODULE__, {:batch_publish, alert_ids, instance_id, opts}, 120_000)
  end

  @doc """
  Create a MISP event from scratch (not from an alert).
  """
  @spec create_event(String.t(), map(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def create_event(instance_id, event_data, opts \\ []) do
    GenServer.call(__MODULE__, {:create_event, instance_id, event_data, opts}, 60_000)
  end

  @doc """
  Add attributes to an existing MISP event.
  """
  @spec add_attributes(String.t(), String.t(), [map()]) :: {:ok, integer()} | {:error, term()}
  def add_attributes(instance_id, event_id, attributes) when is_list(attributes) do
    GenServer.call(__MODULE__, {:add_attributes, instance_id, event_id, attributes}, 60_000)
  end

  @doc """
  List sharing groups available on a MISP instance.
  """
  @spec list_sharing_groups(String.t()) :: {:ok, [map()]} | {:error, term()}
  def list_sharing_groups(instance_id) do
    GenServer.call(__MODULE__, {:list_sharing_groups, instance_id}, 30_000)
  end

  @doc """
  Get queue and publish statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Force-flush the publish queue immediately.
  """
  @spec flush_queue() :: :ok
  def flush_queue do
    GenServer.cast(__MODULE__, :flush_queue)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(_opts) do
    state = %{
      queue: :queue.new(),
      queue_size: 0,
      stats: %{
        total_published: 0,
        total_failed: 0,
        total_duplicates_merged: 0,
        total_iocs_shared: 0,
        total_sightings: 0,
        last_publish_at: nil,
        last_error: nil,
        by_instance: %{},
        by_tlp: %{"WHITE" => 0, "GREEN" => 0, "AMBER" => 0, "RED" => 0}
      }
    }

    schedule_flush()
    Logger.info("[MISPPublisher] Initialized with batch queue (flush every #{div(@flush_interval, 1000)}s)")
    {:ok, state}
  end

  @impl true
  def handle_call({:publish_alert, alert, instance_id, opts}, _from, state) do
    case get_push_instance(instance_id) do
      {:ok, instance} ->
        {result, new_state} = do_publish_alert_with_tracking(alert, instance, opts, state)
        {:reply, result, new_state}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:publish_iocs, iocs, instance_id, opts}, _from, state) do
    case get_push_instance(instance_id) do
      {:ok, instance} ->
        {result, new_state} = do_publish_iocs(iocs, instance, opts, state)
        {:reply, result, new_state}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:add_sighting, instance_id, attr_uuid, sighting_type, opts}, _from, state) do
    case get_instance(instance_id) do
      nil ->
        {:reply, {:error, :instance_not_found}, state}

      instance ->
        if instance.can_sighting do
          result = do_add_sighting(instance, attr_uuid, sighting_type, opts)

          new_stats =
            case result do
              {:ok, _} -> update_in(state.stats, [:total_sightings], &(&1 + 1))
              _ -> state.stats
            end

          {:reply, result, %{state | stats: new_stats}}
        else
          {:reply, {:error, :sighting_not_enabled}, state}
        end
    end
  end

  @impl true
  def handle_call({:batch_publish, alert_ids, instance_id, opts}, _from, state) do
    case get_push_instance(instance_id) do
      {:ok, instance} ->
        {result, new_state} = do_batch_publish(alert_ids, instance, opts, state)
        {:reply, {:ok, result}, new_state}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:create_event, instance_id, event_data, opts}, _from, state) do
    case get_push_instance(instance_id) do
      {:ok, instance} ->
        result = do_create_event(instance, event_data, opts)
        new_state = track_publish_result(state, instance_id, result, opts)
        {:reply, result, new_state}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:add_attributes, instance_id, event_id, attributes}, _from, state) do
    case get_push_instance(instance_id) do
      {:ok, instance} ->
        result = do_add_attributes(instance, event_id, attributes)
        {:reply, result, state}

      {:error, _} = err ->
        {:reply, err, state}
    end
  end

  @impl true
  def handle_call({:list_sharing_groups, instance_id}, _from, state) do
    case get_instance(instance_id) do
      nil -> {:reply, {:error, :instance_not_found}, state}
      instance -> {:reply, do_list_sharing_groups(instance), state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats =
      Map.merge(state.stats, %{
        queue_size: state.queue_size,
        flush_interval_seconds: div(@flush_interval, 1000),
        max_batch_size: @max_batch_size
      })

    {:reply, stats, state}
  end

  @impl true
  def handle_cast({:enqueue, type, id, instance_id, opts}, state) do
    item = %{type: type, id: id, instance_id: instance_id, opts: opts, enqueued_at: DateTime.utc_now()}
    new_queue = :queue.in(item, state.queue)
    {:noreply, %{state | queue: new_queue, queue_size: state.queue_size + 1}}
  end

  @impl true
  def handle_cast(:flush_queue, state) do
    new_state = do_flush_queue(state)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:flush_queue, state) do
    new_state = do_flush_queue(state)
    schedule_flush()
    {:noreply, new_state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private - Queue Flushing
  # ============================================================================

  defp schedule_flush do
    Process.send_after(self(), :flush_queue, @flush_interval)
  end

  defp do_flush_queue(%{queue_size: 0} = state), do: state

  defp do_flush_queue(state) do
    {items, remaining_queue, remaining_size} = dequeue_batch(state.queue, state.queue_size, @max_batch_size)

    if length(items) > 0 do
      Logger.info("[MISPPublisher] Flushing #{length(items)} queued items")
    end

    new_state =
      Enum.reduce(items, %{state | queue: remaining_queue, queue_size: remaining_size}, fn item, acc ->
        case item.type do
          :alert ->
            case Repo.get(Alert, item.id) do
              nil ->
                Logger.warning("[MISPPublisher] Queued alert #{item.id} not found, skipping")
                acc

              alert ->
                case get_push_instance(item.instance_id) do
                  {:ok, instance} ->
                    {_result, updated} = do_publish_alert_with_tracking(alert, instance, item.opts, acc)
                    updated

                  _ ->
                    acc
                end
            end

          _ ->
            acc
        end
      end)

    new_state
  end

  defp dequeue_batch(queue, size, max) do
    count = min(size, max)

    {items, new_queue} =
      Enum.reduce(1..count, {[], queue}, fn _, {acc, q} ->
        case :queue.out(q) do
          {{:value, item}, new_q} -> {[item | acc], new_q}
          {:empty, q2} -> {acc, q2}
        end
      end)

    {Enum.reverse(items), new_queue, max(size - count, 0)}
  end

  # ============================================================================
  # Private - Alert Publishing with Conflict Resolution
  # ============================================================================

  defp do_publish_alert_with_tracking(alert, instance, opts, state) do
    # Check for duplicate: has this alert already been published to this instance?
    case check_existing_publication(alert.id, instance.id) do
      {:existing, existing} ->
        # Merge new attributes into the existing MISP event
        Logger.info(
          "[MISPPublisher] Alert #{alert.id} already published as MISP event #{existing.misp_event_id}, merging attributes"
        )

        attrs = build_attributes_from_alert(alert)

        case do_add_attributes(instance, existing.misp_event_id, attrs) do
          {:ok, _count} ->
            new_stats = update_in(state.stats, [:total_duplicates_merged], &(&1 + 1))
            {{:ok, existing.misp_event_id}, %{state | stats: new_stats}}

          error ->
            {error, state}
        end

      :not_published ->
        # Publish as a new event
        tlp = Keyword.get(opts, :tlp, "AMBER")
        sharing_group_id = Keyword.get(opts, :sharing_group_id, List.first(instance.sharing_group_ids || []))
        auto_publish = Keyword.get(opts, :publish, false)
        extra_tags = Keyword.get(opts, :tags, [])

        event = build_event_from_alert(alert, tlp, sharing_group_id, auto_publish, extra_tags)
        result = send_event_to_misp(instance, event)

        new_state = track_publish_result(state, instance.id, result, opts)

        case result do
          {:ok, misp_event_id} ->
            record_publication(alert, instance, misp_event_id, opts)
            {{:ok, misp_event_id}, new_state}

          error ->
            {error, new_state}
        end
    end
  end

  defp check_existing_publication(alert_id, instance_id) do
    query =
      from(p in "misp_published_alerts",
        where: p.alert_id == type(^alert_id, :binary_id) and p.misp_instance_id == type(^instance_id, :binary_id),
        select: %{misp_event_id: p.misp_event_id, misp_event_uuid: p.misp_event_uuid},
        limit: 1
      )

    case Repo.one(query) do
      nil -> :not_published
      existing -> {:existing, existing}
    end
  rescue
    _ -> :not_published
  end

  defp record_publication(alert, instance, misp_event_id, opts) do
    tlp = Keyword.get(opts, :tlp, "AMBER")
    sharing_group_id = Keyword.get(opts, :sharing_group_id)
    auto_publish = Keyword.get(opts, :publish, false)
    extra_tags = Keyword.get(opts, :tags, [])

    attrs = build_attributes_from_alert(alert)
    tag_names = build_tags_from_alert(alert, tlp, extra_tags) |> Enum.map(& &1["name"])

    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.insert_all("misp_published_alerts", [
      %{
        id: Ecto.UUID.generate(),
        alert_id: alert.id,
        misp_instance_id: instance.id,
        misp_event_id: to_string(misp_event_id),
        published_at: now,
        tlp: tlp,
        sharing_group_id: sharing_group_id,
        auto_publish: auto_publish,
        attributes_count: length(attrs),
        tags: tag_names,
        inserted_at: now,
        updated_at: now
      }
    ], on_conflict: :nothing)
  rescue
    e ->
      Logger.warning("[MISPPublisher] Failed to record publication: #{inspect(e)}")
  end

  # ============================================================================
  # Private - IOC Publishing
  # ============================================================================

  defp do_publish_iocs(iocs, instance, opts, state) do
    tlp = Keyword.get(opts, :tlp, "AMBER")
    sharing_group_id = Keyword.get(opts, :sharing_group_id, List.first(instance.sharing_group_ids || []))
    auto_publish = Keyword.get(opts, :publish, false)

    distribution = Map.get(@tlp_distribution, tlp, 1)

    attributes =
      Enum.flat_map(iocs, fn ioc ->
        ioc_to_misp_attributes(ioc)
      end)

    if Enum.empty?(attributes) do
      {{:ok, %{published: 0, skipped: length(iocs)}}, state}
    else
      event = %{
        "info" => "[Tamandua EDR] Confirmed IOCs - #{Date.to_iso8601(Date.utc_today())}",
        "threat_level_id" => 2,
        "analysis" => @analysis_completed,
        "distribution" => distribution,
        "sharing_group_id" => sharing_group_id,
        "published" => auto_publish,
        "date" => Date.to_iso8601(Date.utc_today()),
        "Attribute" => attributes,
        "Tag" => [
          %{"name" => "tlp:#{String.downcase(tlp)}"},
          %{"name" => "source:tamandua-edr"},
          %{"name" => "type:ioc-export"}
        ]
      }

      result = send_event_to_misp(instance, event)
      new_stats = update_in(state.stats, [:total_iocs_shared], &(&1 + length(attributes)))
      new_state = track_publish_result(%{state | stats: new_stats}, instance.id, result, opts)

      case result do
        {:ok, event_id} ->
          {{:ok, %{published: length(attributes), misp_event_id: event_id}}, new_state}

        error ->
          {error, new_state}
      end
    end
  end

  defp ioc_to_misp_attributes(ioc) do
    type = to_string(ioc[:type] || ioc["type"] || "")
    value = to_string(ioc[:value] || ioc["value"] || "")

    if value == "" do
      []
    else
      misp_type = internal_type_to_misp(type)

      if misp_type do
        category = misp_category_for(misp_type)

        [
          %{
            "type" => misp_type,
            "category" => category,
            "value" => value,
            "to_ids" => true,
            "comment" => "Confirmed IOC from Tamandua EDR"
          }
        ]
      else
        []
      end
    end
  end

  defp internal_type_to_misp("ip"), do: "ip-dst"
  defp internal_type_to_misp("domain"), do: "domain"
  defp internal_type_to_misp("url"), do: "url"
  defp internal_type_to_misp("hash_md5"), do: "md5"
  defp internal_type_to_misp("hash_sha1"), do: "sha1"
  defp internal_type_to_misp("hash_sha256"), do: "sha256"
  defp internal_type_to_misp("email"), do: "email-src"
  defp internal_type_to_misp("filename"), do: "filename"
  defp internal_type_to_misp(_), do: nil

  defp misp_category_for(type) when type in ["ip-src", "ip-dst", "domain", "url"] do
    "Network activity"
  end

  defp misp_category_for(type) when type in ["md5", "sha1", "sha256", "filename"] do
    "Payload delivery"
  end

  defp misp_category_for(_), do: "External analysis"

  # ============================================================================
  # Private - Batch Publish
  # ============================================================================

  defp do_batch_publish(alert_ids, instance, opts, state) do
    results =
      Enum.map(alert_ids, fn alert_id ->
        case Repo.get(Alert, alert_id) do
          nil ->
            {alert_id, {:error, :alert_not_found}}

          alert ->
            {result, _} = do_publish_alert_with_tracking(alert, instance, opts, state)
            {alert_id, result}
        end
      end)

    successful = Enum.count(results, fn {_, r} -> match?({:ok, _}, r) end)
    failed = Enum.count(results, fn {_, r} -> match?({:error, _}, r) end)

    errors =
      results
      |> Enum.filter(fn {_, r} -> match?({:error, _}, r) end)
      |> Enum.map(fn {id, {:error, reason}} -> %{alert_id: id, error: inspect(reason)} end)

    summary = %{
      total: length(alert_ids),
      successful: successful,
      failed: failed,
      errors: errors
    }

    new_stats =
      state.stats
      |> Map.update!(:total_published, &(&1 + successful))
      |> Map.update!(:total_failed, &(&1 + failed))

    {summary, %{state | stats: new_stats}}
  end

  # ============================================================================
  # Private - MISP HTTP API
  # ============================================================================

  defp send_event_to_misp(instance, event) do
    headers = build_headers(instance.api_key)

    case Finch.build(:post, "#{instance.url}/events/add", headers, Jason.encode!(%{"Event" => event}))
         |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_event_response(body)

      {:ok, %Finch.Response{status: code, body: body}} ->
        Logger.error("[MISPPublisher] Failed to publish: HTTP #{code} - #{String.slice(body, 0..500)}")
        {:error, {:http_error, code, body}}

      {:error, reason} ->
        Logger.error("[MISPPublisher] HTTP error: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp do_add_sighting(instance, attribute_uuid, sighting_type, opts) do
    source = Keyword.get(opts, :source, "Tamandua EDR")
    timestamp = Keyword.get(opts, :timestamp, DateTime.to_unix(DateTime.utc_now()))

    sighting_data = %{
      "uuid" => attribute_uuid,
      "type" => sighting_type,
      "source" => source,
      "timestamp" => timestamp
    }

    headers = build_headers(instance.api_key)

    case Finch.build(:post, "#{instance.url}/sightings/add/#{attribute_uuid}", headers, Jason.encode!(sighting_data))
         |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"Sighting" => %{"id" => id}}} ->
            Logger.info("[MISPPublisher] Added sighting #{id}")
            {:ok, id}

          _ ->
            {:ok, "success"}
        end

      {:ok, %Finch.Response{status: code, body: body}} ->
        Logger.error("[MISPPublisher] Failed to add sighting: HTTP #{code} - #{body}")
        {:error, {:http_error, code}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_create_event(instance, event_data, opts) do
    tlp = Keyword.get(opts, :tlp, "AMBER")
    sharing_group_id = Keyword.get(opts, :sharing_group_id, List.first(instance.sharing_group_ids || []))
    auto_publish = Keyword.get(opts, :publish, false)

    distribution = Map.get(@tlp_distribution, tlp, 1)

    event = %{
      "info" => Map.get(event_data, :info, Map.get(event_data, "info", "Tamandua EDR Event")),
      "threat_level_id" => Map.get(event_data, :threat_level, Map.get(event_data, "threat_level", 2)),
      "analysis" => Map.get(event_data, :analysis, @analysis_completed),
      "distribution" => distribution,
      "sharing_group_id" => sharing_group_id,
      "published" => auto_publish,
      "date" => Date.to_iso8601(Date.utc_today()),
      "Attribute" => Map.get(event_data, :attributes, Map.get(event_data, "attributes", [])),
      "Tag" => [%{"name" => "tlp:#{String.downcase(tlp)}"}, %{"name" => "source:tamandua-edr"}]
    }

    send_event_to_misp(instance, event)
  end

  defp do_add_attributes(instance, event_id, attributes) do
    headers = build_headers(instance.api_key)

    results =
      Enum.map(attributes, fn attr ->
        case Finch.build(:post, "#{instance.url}/attributes/add/#{event_id}", headers, Jason.encode!(%{"Attribute" => attr}))
             |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
          {:ok, %Finch.Response{status: 200}} -> :ok
          _ -> :error
        end
      end)

    successful = Enum.count(results, &(&1 == :ok))
    {:ok, successful}
  end

  defp do_list_sharing_groups(instance) do
    headers = build_headers(instance.api_key)

    case Finch.build(:get, "#{instance.url}/sharing_groups", headers)
         |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"response" => groups}} when is_list(groups) ->
            parsed =
              Enum.map(groups, fn entry ->
                sg = Map.get(entry, "SharingGroup", entry)

                %{
                  id: Map.get(sg, "id"),
                  name: Map.get(sg, "name"),
                  description: Map.get(sg, "description"),
                  releasability: Map.get(sg, "releasability"),
                  active: Map.get(sg, "active")
                }
              end)

            {:ok, parsed}

          {:ok, groups} when is_list(groups) ->
            {:ok, groups}

          _ ->
            {:ok, []}
        end

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # Private - Event Building
  # ============================================================================

  defp build_event_from_alert(alert, tlp, sharing_group_id, publish, extra_tags) do
    distribution = Map.get(@tlp_distribution, tlp, 1)

    %{
      "info" => "[Tamandua EDR] #{alert.title}",
      "threat_level_id" => severity_to_threat_level(alert.severity),
      "analysis" => @analysis_completed,
      "distribution" => distribution,
      "sharing_group_id" => sharing_group_id,
      "published" => publish,
      "date" => Date.to_iso8601(Date.utc_today()),
      "Attribute" => build_attributes_from_alert(alert),
      "Tag" => build_tags_from_alert(alert, tlp, extra_tags)
    }
  end

  defp severity_to_threat_level("critical"), do: 1
  defp severity_to_threat_level("high"), do: 1
  defp severity_to_threat_level("medium"), do: 2
  defp severity_to_threat_level("low"), do: 3
  defp severity_to_threat_level(_), do: 4

  defp build_attributes_from_alert(alert) do
    enrichment = alert.enrichment || %{}

    # Source IPs
    src_ip_attrs =
      (Map.get(enrichment, "src_ips", []) || [])
      |> Enum.map(fn ip ->
        %{
          "type" => "ip-src",
          "category" => "Network activity",
          "value" => ip,
          "to_ids" => true,
          "comment" => "Source IP from Tamandua alert #{alert.id}"
        }
      end)

    # Destination IPs
    dst_ip_attrs =
      (Map.get(enrichment, "dst_ips", []) || [])
      |> Enum.map(fn ip ->
        %{
          "type" => "ip-dst",
          "category" => "Network activity",
          "value" => ip,
          "to_ids" => true,
          "comment" => "Destination IP from Tamandua alert #{alert.id}"
        }
      end)

    # Domains
    domain_attrs =
      (Map.get(enrichment, "domains", []) || [])
      |> Enum.map(fn domain ->
        %{
          "type" => "domain",
          "category" => "Network activity",
          "value" => domain,
          "to_ids" => true,
          "comment" => "Domain from Tamandua alert #{alert.id}"
        }
      end)

    # File hashes
    hash_attrs =
      (Map.get(enrichment, "hashes", %{}) || %{})
      |> Enum.flat_map(fn {hash_type, hash_value} ->
        misp_type =
          case hash_type do
            "md5" -> "md5"
            "sha1" -> "sha1"
            "sha256" -> "sha256"
            _ -> nil
          end

        if misp_type do
          [
            %{
              "type" => misp_type,
              "category" => "Payload delivery",
              "value" => hash_value,
              "to_ids" => true,
              "comment" => "File hash from Tamandua alert #{alert.id}"
            }
          ]
        else
          []
        end
      end)

    # URLs
    url_attrs =
      (Map.get(enrichment, "urls", []) || [])
      |> Enum.map(fn url ->
        %{
          "type" => "url",
          "category" => "Network activity",
          "value" => url,
          "to_ids" => true,
          "comment" => "URL from Tamandua alert #{alert.id}"
        }
      end)

    # Description text attribute
    desc_attrs =
      if alert.description do
        [
          %{
            "type" => "text",
            "category" => "Internal reference",
            "value" => alert.description,
            "to_ids" => false,
            "comment" => "Alert description"
          }
        ]
      else
        []
      end

    src_ip_attrs ++ dst_ip_attrs ++ domain_attrs ++ hash_attrs ++ url_attrs ++ desc_attrs
  end

  defp build_tags_from_alert(alert, tlp, extra_tags) do
    base_tags = [
      %{"name" => "tlp:#{String.downcase(tlp)}"},
      %{"name" => "source:tamandua-edr"},
      %{"name" => "severity:#{alert.severity}"}
    ]

    mitre_tags =
      (alert.mitre_techniques || [])
      |> Enum.map(fn technique -> %{"name" => "mitre-attack:#{technique}"} end)

    extra_tag_objects = Enum.map(extra_tags, fn tag -> %{"name" => tag} end)

    base_tags ++ mitre_tags ++ extra_tag_objects
  end

  # ============================================================================
  # Private - Response Parsing & Helpers
  # ============================================================================

  defp parse_event_response(body) do
    case Jason.decode(body) do
      {:ok, %{"Event" => %{"id" => id, "uuid" => uuid}}} ->
        Logger.info("[MISPPublisher] Published event #{id} (#{uuid})")
        {:ok, id}

      {:ok, %{"Event" => %{"id" => id}}} ->
        Logger.info("[MISPPublisher] Published event #{id}")
        {:ok, id}

      {:ok, %{"errors" => errors}} ->
        {:error, {:misp_error, errors}}

      {:error, reason} ->
        {:error, {:json_parse_error, reason}}
    end
  end

  defp get_instance(id) do
    Repo.get(MISPInstance, id)
  rescue
    _ -> nil
  end

  defp get_push_instance(instance_id) do
    case get_instance(instance_id) do
      nil ->
        {:error, :instance_not_found}

      instance ->
        if instance.push_enabled do
          {:ok, instance}
        else
          {:error, :push_not_enabled}
        end
    end
  end

  defp build_headers(api_key) do
    [
      {"Authorization", api_key},
      {"Accept", "application/json"},
      {"Content-Type", "application/json"}
    ]
  end

  defp track_publish_result(state, instance_id, result, opts) do
    tlp = Keyword.get(opts, :tlp, "AMBER")

    case result do
      {:ok, _} ->
        new_stats =
          state.stats
          |> Map.update!(:total_published, &(&1 + 1))
          |> Map.put(:last_publish_at, DateTime.utc_now())
          |> update_in([:by_instance, instance_id], fn
            nil -> 1
            n -> n + 1
          end)
          |> update_in([:by_tlp, tlp], fn
            nil -> 1
            n -> n + 1
          end)

        %{state | stats: new_stats}

      {:error, reason} ->
        new_stats =
          state.stats
          |> Map.update!(:total_failed, &(&1 + 1))
          |> Map.put(:last_error, %{reason: inspect(reason), at: DateTime.utc_now()})

        %{state | stats: new_stats}
    end
  end
end
