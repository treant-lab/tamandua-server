defmodule TamanduaServer.ThreatIntel.Feeds.EmergingThreats do
  @moduledoc """
  Emerging Threats Open Source Feed Integration.

  Provides free threat intelligence from the Emerging Threats community:
  - Compromised IP lists
  - Malware C2 IPs
  - Tor exit nodes
  - Known botnets
  - DShield blocklists

  These feeds are free and require no API key.
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  @default_sync_interval :timer.hours(6)
  @http_timeout 60_000

  # Free Emerging Threats feeds
  @feeds %{
    compromised_ips: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    emerging_block_ips: "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    emerging_dshield: "https://rules.emergingthreats.net/fwrules/emerging-dshield-Block-IPs.txt",
    emerging_botcc: "https://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules",
    emerging_drop: "https://rules.emergingthreats.net/fwrules/emerging-PIX-DROP.rules",
    tor_exit_nodes: "https://rules.emergingthreats.net/blockrules/tor-exit-nodes.txt",
    ciarmy_bad_guys: "https://www.ciarmy.com/list/ci-badguys.txt"
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
  Get current status.
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  List available feeds.
  """
  @spec list_feeds() :: [atom()]
  def list_feeds do
    Map.keys(@feeds)
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
        errors: 0
      }
    }

    if state.enabled do
      Process.send_after(self(), :initial_sync, :timer.seconds(30))
      schedule_sync(state.sync_interval)
      Logger.info("[EmergingThreats] Initialized with #{map_size(@feeds)} feeds")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:sync_feed, feed_name}, _from, state) do
    result = do_sync_feed(feed_name, state)
    {:reply, result, update_feed_status(state, feed_name, result)}
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
    Logger.info("[EmergingThreats] Starting initial sync...")
    Task.start(fn -> do_sync_all() end)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    Logger.info("[EmergingThreats] Starting periodic sync...")
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
    Logger.info("[EmergingThreats] Syncing all feeds...")

    results = Enum.map(@feeds, fn {name, url} ->
      result = do_fetch_and_parse(name, url)
      Process.sleep(1000)  # Rate limiting
      {name, result}
    end)

    successful = Enum.count(results, fn {_, r} -> match?({:ok, _}, r) end)
    Logger.info("[EmergingThreats] Sync complete - #{successful}/#{map_size(@feeds)} feeds successful")

    results
  end

  defp do_sync_feed(feed_name, _state) do
    case Map.get(@feeds, feed_name) do
      nil -> {:error, :unknown_feed}
      url -> do_fetch_and_parse(feed_name, url)
    end
  end

  defp do_fetch_and_parse(feed_name, url) do
    Logger.debug("[EmergingThreats] Fetching #{feed_name}")

    case Finch.build(:get, url) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        iocs = parse_feed(feed_name, body)

        # Submit to aggregator
        Aggregator.ingest_batch("emerging_threats", iocs)

        Logger.info("[EmergingThreats] Imported #{length(iocs)} IOCs from #{feed_name}")
        {:ok, length(iocs)}

      {:ok, %Finch.Response{status: code}} ->
        Logger.warning("[EmergingThreats] #{feed_name} returned HTTP #{code}")
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("[EmergingThreats] #{feed_name} error: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp parse_feed(feed_name, body) do
    source = "emerging_threats_#{feed_name}"
    severity = feed_severity(feed_name)
    tags = feed_tags(feed_name)

    body
    |> String.split("\n")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(String.starts_with?(&1, "#") or &1 == ""))
    |> Enum.map(fn line ->
      # Handle various formats
      value = extract_ip_from_line(line)

      if valid_ip?(value) do
        %{
          type: "ip",
          value: value,
          source: source,
          severity: severity,
          confidence: feed_confidence(feed_name),
          tags: tags,
          metadata: %{
            "feed" => Atom.to_string(feed_name),
            "provider" => "emerging_threats"
          }
        }
      else
        nil
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq_by(& &1.value)
  end

  defp extract_ip_from_line(line) do
    # Handle different formats
    cond do
      # CIDR notation - extract base IP
      String.contains?(line, "/") ->
        String.split(line, "/") |> List.first() |> String.trim()

      # Snort/Suricata rule format
      String.contains?(line, "alert") ->
        extract_ip_from_rule(line)

      # Tab-separated with comments
      String.contains?(line, "\t") ->
        String.split(line, "\t") |> List.first() |> String.trim()

      # Comma-separated
      String.contains?(line, ",") ->
        String.split(line, ",") |> List.first() |> String.trim()

      # Plain IP
      true ->
        String.trim(line)
    end
  end

  defp extract_ip_from_rule(rule) do
    # Extract IP from Snort-style rule: alert ip $HOME_NET any -> [1.2.3.4] any
    case Regex.run(~r/\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?/, rule) do
      [_, ip] -> ip
      _ -> ""
    end
  end

  defp valid_ip?(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, _} -> true
      _ -> false
    end
  end

  defp feed_severity(:compromised_ips), do: "high"
  defp feed_severity(:emerging_block_ips), do: "high"
  defp feed_severity(:emerging_dshield), do: "high"
  defp feed_severity(:emerging_botcc), do: "critical"
  defp feed_severity(:emerging_drop), do: "high"
  defp feed_severity(:tor_exit_nodes), do: "medium"
  defp feed_severity(:ciarmy_bad_guys), do: "high"
  defp feed_severity(_), do: "medium"

  defp feed_confidence(:compromised_ips), do: 0.8
  defp feed_confidence(:emerging_block_ips), do: 0.85
  defp feed_confidence(:emerging_dshield), do: 0.8
  defp feed_confidence(:emerging_botcc), do: 0.9
  defp feed_confidence(:emerging_drop), do: 0.85
  defp feed_confidence(:tor_exit_nodes), do: 0.95
  defp feed_confidence(:ciarmy_bad_guys), do: 0.75
  defp feed_confidence(_), do: 0.7

  defp feed_tags(:compromised_ips), do: ["compromised", "et"]
  defp feed_tags(:emerging_block_ips), do: ["block", "et"]
  defp feed_tags(:emerging_dshield), do: ["dshield", "block", "et"]
  defp feed_tags(:emerging_botcc), do: ["botnet", "c2", "et"]
  defp feed_tags(:emerging_drop), do: ["drop", "et"]
  defp feed_tags(:tor_exit_nodes), do: ["tor", "anonymizer"]
  defp feed_tags(:ciarmy_bad_guys), do: ["ciarmy", "malicious"]
  defp feed_tags(_), do: ["et"]

  defp update_feed_status(state, feed_name, result) do
    status = case result do
      {:ok, count} -> %{status: :ok, count: count, last_sync: DateTime.utc_now()}
      {:error, reason} -> %{status: :error, error: inspect(reason), last_sync: nil}
    end

    new_feed_status = Map.put(state.feed_status, feed_name, status)
    %{state | feed_status: new_feed_status}
  end

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end
end
