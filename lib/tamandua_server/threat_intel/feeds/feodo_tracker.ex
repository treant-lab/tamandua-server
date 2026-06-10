defmodule TamanduaServer.ThreatIntel.Feeds.FeodoTracker do
  @moduledoc """
  Feodo Tracker (Abuse.ch) Feed Integration.

  Tracks banking trojan C2 servers including:
  - Dridex
  - Emotet
  - TrickBot
  - QakBot (QBot)
  - BazarLoader

  All feeds are free and require no API key.
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  @default_sync_interval :timer.hours(4)
  @http_timeout 60_000

  # Feodo Tracker feeds
  @feeds %{
    ip_blocklist: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    ip_blocklist_recommended: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    ip_blocklist_aggressive: "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
    botnet_c2_json: "https://feodotracker.abuse.ch/downloads/botnetips.json",
    ip_blocklist_csv: "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Trigger manual sync of all feeds.
  """
  @spec sync_all() :: :ok
  def sync_all do
    GenServer.cast(__MODULE__, :sync_all)
  end

  @doc """
  Sync a specific feed.
  """
  @spec sync_feed(atom()) :: {:ok, integer()} | {:error, term()}
  def sync_feed(feed_name) do
    GenServer.call(__MODULE__, {:sync_feed, feed_name}, @http_timeout * 2)
  end

  @doc """
  Get detailed C2 information (JSON feed).
  """
  @spec get_c2_details() :: {:ok, [map()]} | {:error, term()}
  def get_c2_details do
    GenServer.call(__MODULE__, :get_c2_details, @http_timeout * 2)
  end

  @doc """
  Get current status.
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(opts) do
    state = %{
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      last_sync: nil,
      feed_status: %{},
      stats: %{
        iocs_imported: 0,
        by_malware: %{}
      }
    }

    if state.enabled do
      Process.send_after(self(), :initial_sync, :timer.seconds(15))
      schedule_sync(state.sync_interval)
      Logger.info("[FeodoTracker] Initialized")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:sync_feed, feed_name}, _from, state) do
    result = do_sync_feed(feed_name)
    {:reply, result, update_feed_status(state, feed_name, result)}
  end

  @impl true
  def handle_call(:get_c2_details, _from, state) do
    result = fetch_json_feed()
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      last_sync: state.last_sync,
      feed_status: state.feed_status,
      stats: state.stats,
      available_feeds: Map.keys(@feeds)
    }
    {:reply, status, state}
  end

  @impl true
  def handle_cast(:sync_all, state) do
    Task.start(fn -> do_sync_all() end)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:initial_sync, state) do
    Logger.info("[FeodoTracker] Starting initial sync...")
    Task.start(fn -> do_sync_all() end)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    Logger.info("[FeodoTracker] Starting periodic sync...")
    Task.start(fn -> do_sync_all() end)
    schedule_sync(state.sync_interval)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp do_sync_all do
    Logger.info("[FeodoTracker] Syncing all feeds...")

    # Sync the recommended blocklist (balanced)
    do_sync_feed(:ip_blocklist_recommended)

    # Sync the JSON feed for detailed malware attribution
    do_sync_json_feed()

    Logger.info("[FeodoTracker] Sync complete")
  end

  defp do_sync_feed(feed_name) do
    url = Map.get(@feeds, feed_name)

    unless url do
      {:error, :unknown_feed}
    else
      Logger.debug("[FeodoTracker] Fetching #{feed_name}")

      case Finch.build(:get, url) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          iocs = parse_text_feed(feed_name, body)

          Aggregator.ingest_batch("feodo_tracker", iocs)

          Logger.info("[FeodoTracker] Imported #{length(iocs)} IOCs from #{feed_name}")
          {:ok, length(iocs)}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_sync_json_feed do
    url = @feeds[:botnet_c2_json]

    case Finch.build(:get, url) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        iocs = parse_json_feed(body)

        Aggregator.ingest_batch("feodo_tracker", iocs)

        Logger.info("[FeodoTracker] Imported #{length(iocs)} IOCs with malware attribution")
        {:ok, length(iocs)}

      {:ok, %Finch.Response{status: code}} ->
        Logger.warning("[FeodoTracker] JSON feed returned HTTP #{code}")
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp fetch_json_feed do
    url = @feeds[:botnet_c2_json]

    case Finch.build(:get, url) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, data} when is_list(data) ->
            c2s = Enum.map(data, fn entry ->
              %{
                ip: entry["ip_address"],
                port: entry["port"],
                malware: entry["malware"],
                status: entry["status"],
                first_seen: entry["first_seen"],
                last_online: entry["last_online"],
                country: entry["country"],
                asn: entry["as_number"],
                as_name: entry["as_name"]
              }
            end)
            {:ok, c2s}

          {:error, reason} ->
            {:error, {:parse_error, reason}}
        end

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp parse_text_feed(feed_name, body) do
    severity = case feed_name do
      :ip_blocklist_aggressive -> "high"
      :ip_blocklist_recommended -> "critical"
      :ip_blocklist -> "high"
      _ -> "high"
    end

    confidence = case feed_name do
      :ip_blocklist_aggressive -> 0.7
      :ip_blocklist_recommended -> 0.95
      :ip_blocklist -> 0.85
      _ -> 0.8
    end

    body
    |> String.split("\n")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(String.starts_with?(&1, "#") or &1 == ""))
    |> Enum.map(fn line ->
      %{
        type: "ip",
        value: line,
        source: "feodo_tracker",
        severity: severity,
        confidence: confidence,
        tags: ["feodo", "banking_trojan", "c2"],
        metadata: %{
          "feed" => Atom.to_string(feed_name),
          "provider" => "abuse.ch"
        }
      }
    end)
    |> Enum.filter(&valid_ip?(&1.value))
  end

  defp parse_json_feed(body) do
    case Jason.decode(body) do
      {:ok, data} when is_list(data) ->
        Enum.map(data, fn entry ->
          malware = entry["malware"] || "unknown"
          status = entry["status"] || "unknown"

          %{
            type: "ip",
            value: entry["ip_address"],
            source: "feodo_tracker",
            severity: if(status == "online", do: "critical", else: "high"),
            confidence: if(status == "online", do: 0.95, else: 0.8),
            tags: ["feodo", malware_tag(malware), "c2", status],
            metadata: %{
              "malware" => malware,
              "port" => entry["port"],
              "status" => status,
              "first_seen" => entry["first_seen"],
              "last_online" => entry["last_online"],
              "country" => entry["country"],
              "asn" => entry["as_number"],
              "as_name" => entry["as_name"],
              "provider" => "abuse.ch"
            }
          }
        end)
        |> Enum.filter(&valid_ip?(&1.value))

      _ ->
        []
    end
  end

  defp malware_tag(malware) do
    malware
    |> String.downcase()
    |> String.replace(" ", "_")
    |> String.replace("-", "_")
  end

  defp valid_ip?(ip) do
    case :inet.parse_address(String.to_charlist(ip || "")) do
      {:ok, _} -> true
      _ -> false
    end
  end

  defp update_feed_status(state, feed_name, result) do
    status = case result do
      {:ok, count} -> %{status: :ok, count: count, last_sync: DateTime.utc_now()}
      {:error, reason} -> %{status: :error, error: inspect(reason)}
    end

    %{state | feed_status: Map.put(state.feed_status, feed_name, status)}
  end

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end
end
