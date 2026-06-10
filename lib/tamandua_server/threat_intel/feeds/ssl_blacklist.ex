defmodule TamanduaServer.ThreatIntel.Feeds.SSLBlacklist do
  @moduledoc """
  SSL Blacklist (Abuse.ch) Feed Integration.

  Tracks malicious SSL certificates and JA3 fingerprints:
  - Malicious SSL certificate SHA1 fingerprints
  - JA3/JA3S TLS fingerprints used by malware
  - Botnet C2 SSL certificates
  - Malware family attribution

  All feeds are free and require no API key.
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  @default_sync_interval :timer.hours(6)
  @http_timeout 60_000

  # SSLBL feeds
  @feeds %{
    ssl_cert_blacklist: "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
    ssl_ip_blacklist: "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    ssl_ip_blacklist_csv: "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
    ja3_fingerprints: "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
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
  Lookup a JA3 fingerprint.
  """
  @spec lookup_ja3(String.t()) :: {:ok, map()} | :not_found
  def lookup_ja3(ja3_hash) do
    GenServer.call(__MODULE__, {:lookup_ja3, ja3_hash})
  end

  @doc """
  Lookup an SSL certificate fingerprint.
  """
  @spec lookup_cert(String.t()) :: {:ok, map()} | :not_found
  def lookup_cert(sha1) do
    GenServer.call(__MODULE__, {:lookup_cert, sha1})
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
    # Create ETS tables for fast lookups
    :ets.new(:sslbl_ja3, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(:sslbl_certs, [:named_table, :set, :public, read_concurrency: true])

    state = %{
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      last_sync: nil,
      feed_status: %{},
      stats: %{
        ja3_count: 0,
        cert_count: 0,
        ip_count: 0
      }
    }

    if state.enabled do
      Process.send_after(self(), :initial_sync, :timer.seconds(20))
      schedule_sync(state.sync_interval)
      Logger.info("[SSLBlacklist] Initialized")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:sync_feed, feed_name}, _from, state) do
    result = do_sync_feed(feed_name)
    {:reply, result, update_feed_status(state, feed_name, result)}
  end

  @impl true
  def handle_call({:lookup_ja3, ja3_hash}, _from, state) do
    result = case :ets.lookup(:sslbl_ja3, String.downcase(ja3_hash)) do
      [{_, data}] -> {:ok, data}
      [] -> :not_found
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call({:lookup_cert, sha1}, _from, state) do
    result = case :ets.lookup(:sslbl_certs, String.downcase(sha1)) do
      [{_, data}] -> {:ok, data}
      [] -> :not_found
    end
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      last_sync: state.last_sync,
      feed_status: state.feed_status,
      stats: %{
        ja3_count: :ets.info(:sslbl_ja3, :size),
        cert_count: :ets.info(:sslbl_certs, :size)
      },
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
    Logger.info("[SSLBlacklist] Starting initial sync...")
    Task.start(fn -> do_sync_all() end)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    Logger.info("[SSLBlacklist] Starting periodic sync...")
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
    Logger.info("[SSLBlacklist] Syncing all feeds...")

    # Sync SSL certificates
    do_sync_feed(:ssl_cert_blacklist)

    # Sync JA3 fingerprints
    do_sync_feed(:ja3_fingerprints)

    # Sync IP blocklist with SSL info
    do_sync_feed(:ssl_ip_blacklist_csv)

    Logger.info("[SSLBlacklist] Sync complete")
  end

  defp do_sync_feed(feed_name) do
    url = Map.get(@feeds, feed_name)

    unless url do
      {:error, :unknown_feed}
    else
      Logger.debug("[SSLBlacklist] Fetching #{feed_name}")

      case Finch.build(:get, url) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          count = parse_and_store_feed(feed_name, body)
          Logger.info("[SSLBlacklist] Imported #{count} entries from #{feed_name}")
          {:ok, count}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp parse_and_store_feed(:ssl_cert_blacklist, body) do
    iocs = body
    |> String.split("\n")
    |> Enum.drop(9)  # Skip header comments
    |> Enum.reject(&(String.starts_with?(&1, "#") or &1 == ""))
    |> Enum.map(fn line ->
      case String.split(line, ",") do
        [timestamp, sha1, reason | _] ->
          cert_data = %{
            sha1: String.trim(sha1),
            reason: String.trim(reason, "\""),
            first_seen: String.trim(timestamp),
            source: "sslbl"
          }

          # Store in ETS for fast lookups
          :ets.insert(:sslbl_certs, {String.downcase(String.trim(sha1)), cert_data})

          %{
            type: "hash_sha1",
            value: String.downcase(String.trim(sha1)),
            source: "ssl_blacklist",
            severity: "high",
            confidence: 0.9,
            tags: ["ssl", "malicious_cert", extract_malware_tag(reason)],
            metadata: %{
              "reason" => String.trim(reason, "\""),
              "first_seen" => String.trim(timestamp),
              "provider" => "abuse.ch"
            }
          }

        _ ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)

    Aggregator.ingest_batch("ssl_blacklist", iocs)
    length(iocs)
  end

  defp parse_and_store_feed(:ja3_fingerprints, body) do
    iocs = body
    |> String.split("\n")
    |> Enum.drop(9)  # Skip header comments
    |> Enum.reject(&(String.starts_with?(&1, "#") or &1 == ""))
    |> Enum.map(fn line ->
      case String.split(line, ",") do
        [ja3_md5, ja3s_md5, description | _] ->
          ja3_data = %{
            ja3_md5: String.trim(ja3_md5),
            ja3s_md5: String.trim(ja3s_md5),
            description: String.trim(description, "\""),
            source: "sslbl"
          }

          # Store in ETS for fast lookups
          :ets.insert(:sslbl_ja3, {String.downcase(String.trim(ja3_md5)), ja3_data})

          # JA3 fingerprints stored as hash_md5 type
          %{
            type: "hash_md5",
            value: String.downcase(String.trim(ja3_md5)),
            source: "ssl_blacklist",
            severity: "high",
            confidence: 0.85,
            tags: ["ja3", "tls_fingerprint", extract_malware_tag(description)],
            metadata: %{
              "ja3s_md5" => String.trim(ja3s_md5),
              "description" => String.trim(description, "\""),
              "ioc_subtype" => "ja3",
              "provider" => "abuse.ch"
            }
          }

        _ ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)

    Aggregator.ingest_batch("ssl_blacklist", iocs)
    length(iocs)
  end

  defp parse_and_store_feed(:ssl_ip_blacklist_csv, body) do
    iocs = body
    |> String.split("\n")
    |> Enum.drop(9)  # Skip header comments
    |> Enum.reject(&(String.starts_with?(&1, "#") or &1 == ""))
    |> Enum.map(fn line ->
      case String.split(line, ",") do
        [timestamp, ip, port, sha1, reason | _] ->
          %{
            type: "ip",
            value: String.trim(ip),
            source: "ssl_blacklist",
            severity: "critical",
            confidence: 0.9,
            tags: ["ssl", "c2", extract_malware_tag(reason)],
            metadata: %{
              "port" => String.trim(port),
              "ssl_sha1" => String.trim(sha1),
              "reason" => String.trim(reason, "\""),
              "first_seen" => String.trim(timestamp),
              "provider" => "abuse.ch"
            }
          }

        _ ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.filter(&valid_ip?(&1.value))

    Aggregator.ingest_batch("ssl_blacklist", iocs)
    length(iocs)
  end

  defp parse_and_store_feed(:ssl_ip_blacklist, body) do
    iocs = body
    |> String.split("\n")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(String.starts_with?(&1, "#") or &1 == ""))
    |> Enum.map(fn ip ->
      %{
        type: "ip",
        value: ip,
        source: "ssl_blacklist",
        severity: "high",
        confidence: 0.85,
        tags: ["ssl", "malicious"],
        metadata: %{"provider" => "abuse.ch"}
      }
    end)
    |> Enum.filter(&valid_ip?(&1.value))

    Aggregator.ingest_batch("ssl_blacklist", iocs)
    length(iocs)
  end

  defp parse_and_store_feed(_, _), do: 0

  defp extract_malware_tag(description) do
    desc_lower = String.downcase(description || "")

    cond do
      String.contains?(desc_lower, "cobalt") -> "cobalt_strike"
      String.contains?(desc_lower, "emotet") -> "emotet"
      String.contains?(desc_lower, "trickbot") -> "trickbot"
      String.contains?(desc_lower, "dridex") -> "dridex"
      String.contains?(desc_lower, "qakbot") or String.contains?(desc_lower, "qbot") -> "qakbot"
      String.contains?(desc_lower, "bazarloader") or String.contains?(desc_lower, "bazar") -> "bazarloader"
      String.contains?(desc_lower, "asyncrat") -> "asyncrat"
      String.contains?(desc_lower, "njrat") -> "njrat"
      String.contains?(desc_lower, "metasploit") -> "metasploit"
      true -> "malware"
    end
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
