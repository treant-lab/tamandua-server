defmodule TamanduaServer.ThreatIntel.Feeds.Spamhaus do
  @moduledoc """
  Spamhaus Feed Integration.

  Spamhaus provides high-quality IP blocklists:
  - DROP (Don't Route Or Peer) - Hijacked netblocks
  - EDROP - Extended DROP list
  - SBL - Spamhaus Block List
  - XBL - Exploited Bot List
  - PBL - Policy Block List (dynamic IPs)
  - DBL - Domain Block List

  The DROP/EDROP lists are free, other lists require subscription.
  """

  use GenServer
  require Logger
  import Bitwise

  alias TamanduaServer.ThreatIntel.Aggregator

  @default_sync_interval :timer.hours(12)  # DROP lists update daily
  @http_timeout 60_000

  # Spamhaus free feeds
  @free_feeds %{
    drop: "https://www.spamhaus.org/drop/drop.txt",
    edrop: "https://www.spamhaus.org/drop/edrop.txt",
    dropv6: "https://www.spamhaus.org/drop/dropv6.txt",
    asn_drop: "https://www.spamhaus.org/drop/asndrop.txt"
  }

  # DNSBL zones for real-time lookups (require appropriate use)
  @dnsbl_zones %{
    sbl: "sbl.spamhaus.org",
    xbl: "xbl.spamhaus.org",
    pbl: "pbl.spamhaus.org",
    dbl: "dbl.spamhaus.org",
    zen: "zen.spamhaus.org"  # Combined SBL+XBL+PBL
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Trigger manual sync of DROP lists.
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
  Check if an IP is in the DROP list.
  """
  @spec check_drop(String.t()) :: {:ok, map()} | :not_found
  def check_drop(ip) do
    GenServer.call(__MODULE__, {:check_drop, ip})
  end

  @doc """
  Perform DNSBL lookup for an IP.
  """
  @spec dnsbl_lookup(String.t(), atom()) :: {:listed, String.t()} | :not_listed | {:error, term()}
  def dnsbl_lookup(ip, zone \\ :zen) do
    GenServer.call(__MODULE__, {:dnsbl_lookup, ip, zone}, 10_000)
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
    # Create ETS tables for lookups
    :ets.new(:spamhaus_drop, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(:spamhaus_cidr, [:named_table, :bag, :public, read_concurrency: true])

    state = %{
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      last_sync: nil,
      feed_status: %{},
      stats: %{
        drop_count: 0,
        edrop_count: 0,
        cidr_count: 0
      }
    }

    if state.enabled do
      Process.send_after(self(), :initial_sync, :timer.seconds(35))
      schedule_sync(state.sync_interval)
      Logger.info("[Spamhaus] Initialized")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:sync_feed, feed_name}, _from, state) do
    result = do_sync_feed(feed_name)
    {:reply, result, update_feed_status(state, feed_name, result)}
  end

  @impl true
  def handle_call({:check_drop, ip}, _from, state) do
    result = do_check_drop(ip)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:dnsbl_lookup, ip, zone}, _from, state) do
    result = do_dnsbl_lookup(ip, zone)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      last_sync: state.last_sync,
      feed_status: state.feed_status,
      stats: %{
        drop_entries: :ets.info(:spamhaus_drop, :size),
        cidr_entries: :ets.info(:spamhaus_cidr, :size)
      },
      available_feeds: Map.keys(@free_feeds),
      dnsbl_zones: Map.keys(@dnsbl_zones)
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
    Logger.info("[Spamhaus] Starting initial sync...")
    Task.start(fn -> do_sync_all() end)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    Logger.info("[Spamhaus] Starting periodic sync...")
    Task.start(fn -> do_sync_all() end)
    schedule_sync(state.sync_interval)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Sync
  # ============================================================================

  defp do_sync_all do
    Logger.info("[Spamhaus] Syncing all DROP lists...")

    # Sync DROP
    do_sync_feed(:drop)

    # Sync EDROP
    do_sync_feed(:edrop)

    # Sync DROPv6
    do_sync_feed(:dropv6)

    Logger.info("[Spamhaus] Sync complete")
  end

  defp do_sync_feed(feed_name) do
    url = Map.get(@free_feeds, feed_name)

    unless url do
      {:error, :unknown_feed}
    else
      Logger.debug("[Spamhaus] Fetching #{feed_name}")

      case Finch.build(:get, url) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          count = parse_and_store_drop_list(feed_name, body)
          Logger.info("[Spamhaus] Imported #{count} entries from #{feed_name}")
          {:ok, count}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp parse_and_store_drop_list(feed_name, body) do
    iocs = body
    |> String.split("\n")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(String.starts_with?(&1, ";") or &1 == ""))
    |> Enum.map(fn line ->
      # Format: CIDR ; SBL_ID
      case String.split(line, ";") do
        [cidr | rest] ->
          cidr = String.trim(cidr)
          sbl_id = Enum.at(rest, 0, "") |> String.trim()

          # Parse CIDR to get base IP and mask
          {base_ip, mask} = parse_cidr(cidr)

          if base_ip do
            # Store CIDR for range lookups
            :ets.insert(:spamhaus_cidr, {base_ip, %{
              cidr: cidr,
              mask: mask,
              sbl_id: sbl_id,
              feed: feed_name
            }})

            # Store individual entry
            :ets.insert(:spamhaus_drop, {base_ip, %{
              cidr: cidr,
              sbl_id: sbl_id,
              feed: feed_name,
              added: DateTime.utc_now()
            }})

            severity = if feed_name == :edrop, do: "critical", else: "high"

            %{
              type: "ip",
              value: base_ip,
              source: "spamhaus",
              severity: severity,
              confidence: 0.95,  # Spamhaus is highly reliable
              tags: ["spamhaus", Atom.to_string(feed_name), "hijacked"],
              metadata: %{
                "cidr" => cidr,
                "sbl_id" => sbl_id,
                "feed" => Atom.to_string(feed_name),
                "provider" => "spamhaus"
              }
            }
          else
            nil
          end

        _ ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)

    Aggregator.ingest_batch("spamhaus", iocs)
    length(iocs)
  end

  # ============================================================================
  # Private Functions - Lookup
  # ============================================================================

  defp do_check_drop(ip) do
    # First check exact match
    case :ets.lookup(:spamhaus_drop, ip) do
      [{_, data}] ->
        {:ok, data}

      [] ->
        # Check CIDR ranges
        check_cidr_ranges(ip)
    end
  end

  defp check_cidr_ranges(ip) do
    case parse_ip(ip) do
      {:ok, ip_tuple} ->
        # Get all CIDR entries and check if IP falls within any range
        all_cidrs = :ets.tab2list(:spamhaus_cidr)

        Enum.find_value(all_cidrs, :not_found, fn {base_ip, data} ->
          if ip_in_cidr?(ip_tuple, base_ip, data.mask) do
            {:ok, data}
          else
            nil
          end
        end)

      :error ->
        :not_found
    end
  end

  defp do_dnsbl_lookup(ip, zone) do
    zone_name = Map.get(@dnsbl_zones, zone)

    unless zone_name do
      {:error, :unknown_zone}
    else
      # Reverse the IP for DNSBL query
      reversed = reverse_ip(ip)

      if reversed do
        query = "#{reversed}.#{zone_name}"

        case :inet_res.lookup(String.to_charlist(query), :in, :a) do
          [] ->
            :not_listed

          [{127, 0, 0, code} | _] ->
            {:listed, decode_spamhaus_code(zone, code)}

          _ ->
            :not_listed
        end
      else
        {:error, :invalid_ip}
      end
    end
  rescue
    _ -> {:error, :lookup_failed}
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp parse_cidr(cidr) do
    case String.split(cidr, "/") do
      [ip, mask_str] ->
        mask = case Integer.parse(mask_str) do
          {n, _} -> n
          :error -> 32
        end
        {String.trim(ip), mask}

      [ip] ->
        {String.trim(ip), 32}

      _ ->
        {nil, 0}
    end
  end

  defp parse_ip(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, tuple} -> {:ok, tuple}
      _ -> :error
    end
  end

  defp ip_in_cidr?({a, b, c, d}, base_ip, mask) do
    case parse_ip(base_ip) do
      {:ok, {ba, bb, bc, bd}} ->
        ip_int = (a <<< 24) + (b <<< 16) + (c <<< 8) + d
        base_int = (ba <<< 24) + (bb <<< 16) + (bc <<< 8) + bd
        mask_bits = 0xFFFFFFFF <<< (32 - mask) &&& 0xFFFFFFFF

        (ip_int &&& mask_bits) == (base_int &&& mask_bits)

      _ ->
        false
    end
  end

  defp ip_in_cidr?(_, _, _), do: false

  defp reverse_ip(ip) do
    case String.split(ip, ".") do
      [a, b, c, d] -> "#{d}.#{c}.#{b}.#{a}"
      _ -> nil
    end
  end

  defp decode_spamhaus_code(:sbl, code) do
    case code do
      2 -> "SBL - Spam source"
      3 -> "SBL CSS - Spam support service"
      4 -> "SBL XBL - Exploits/Botnet"
      _ -> "SBL listed"
    end
  end

  defp decode_spamhaus_code(:xbl, code) do
    case code do
      4 -> "CBL - Open proxy/Botnet"
      5 -> "CBL - SOCKS proxy"
      6 -> "CBL - HTTP proxy"
      7 -> "CBL - Botnet C2"
      _ -> "XBL listed"
    end
  end

  defp decode_spamhaus_code(:pbl, _code), do: "PBL - Dynamic IP"
  defp decode_spamhaus_code(:dbl, _code), do: "DBL - Malicious domain"
  defp decode_spamhaus_code(_, _), do: "Listed"

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
