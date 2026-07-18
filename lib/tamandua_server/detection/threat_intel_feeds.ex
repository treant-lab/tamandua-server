defmodule TamanduaServer.Detection.ThreatIntelFeeds do
  @moduledoc """
  Threat Intelligence Feed Configuration and Management.

  Manages connections to various threat intel feeds:
  - Abuse.ch (free, no API key required)
  - AlienVault OTX (free tier available)
  - MISP (self-hosted or community)
  - VirusTotal (requires API key)
  - Shodan (requires API key)

  Also supports custom feed URLs.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Detection.IOCs

  # ============================================================================
  # Feed URLs (Free Feeds - No API Key Required)
  # ============================================================================

  @abusech_feeds %{
    # Malware Bazaar - Recent malware samples
    malware_bazaar_recent: "https://bazaar.abuse.ch/export/txt/sha256/recent/",
    malware_bazaar_full: "https://bazaar.abuse.ch/export/txt/sha256/full/",

    # Feodo Tracker - Banking trojan C2s
    feodo_ip_blocklist: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    feodo_ip_recommended: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",

    # SSL Blacklist - Malicious SSL certificates
    ssl_blacklist: "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
    ssl_ja3: "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",

    # URLHaus - Malicious URLs
    urlhaus_urls: "https://urlhaus.abuse.ch/downloads/text/",
    urlhaus_payloads: "https://urlhaus.abuse.ch/downloads/payloads/",

    # ThreatFox - IOC sharing
    threatfox_iocs: "https://threatfox.abuse.ch/export/csv/recent/",

    # Botnet C2 IPs
    botnet_c2_ips: "https://feodotracker.abuse.ch/downloads/botnetips.json"
  }

  @external_free_feeds %{
    # EmergingThreats
    et_compromised_ips: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",

    # Spamhaus DROP (Don't Route Or Peer)
    spamhaus_drop: "https://www.spamhaus.org/drop/drop.txt",
    spamhaus_edrop: "https://www.spamhaus.org/drop/edrop.txt",

    # FireHOL IP Lists (aggregated)
    firehol_level1:
      "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",

    # Tor Exit Nodes
    tor_exit_nodes: "https://check.torproject.org/torbulkexitlist",

    # Known Phishing Domains
    openphish: "https://openphish.com/feed.txt",
    phishtank: "http://data.phishtank.com/data/online-valid.csv",

    # Ransomware Tracker (archived but useful)
    ransomware_abuse: "https://ransomware.abuse.ch/downloads/RW_IPBL.txt",

    # C2 Intel Feeds
    c2_all_domains:
      "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2swithURLwithIP.csv"
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
  def sync_all do
    GenServer.cast(__MODULE__, :sync_all)
  end

  @doc """
  Sync a specific feed by name.
  """
  def sync_feed(feed_name) do
    GenServer.cast(__MODULE__, {:sync_feed, feed_name})
  end

  @doc """
  Get feed sync status.
  """
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  Configure API keys for premium feeds.
  """
  def configure_api_key(provider, api_key) when provider in [:misp, :otx, :virustotal, :shodan] do
    GenServer.call(__MODULE__, {:configure_api_key, provider, api_key})
  end

  @doc """
  Add a custom feed URL.
  """
  def add_custom_feed(name, url, opts \\ []) do
    GenServer.call(__MODULE__, {:add_custom_feed, name, url, opts})
  end

  # ============================================================================
  # GenServer Implementation
  # ============================================================================

  @impl true
  def init(opts) do
    # Read configuration from application env, falling back to opts and defaults
    app_config = Application.get_env(:tamandua_server, __MODULE__, [])

    enabled =
      Keyword.get(
        opts,
        :enabled,
        if(is_list(app_config), do: Keyword.get(app_config, :enabled, true), else: true)
      )

    sync_interval_hours =
      if is_list(app_config), do: Keyword.get(app_config, :sync_interval_hours, 4), else: 4

    sync_interval = Keyword.get(opts, :sync_interval, :timer.hours(sync_interval_hours))

    initial_delay_seconds =
      if is_list(app_config),
        do: Keyword.get(app_config, :initial_sync_delay_seconds, 30),
        else: 30

    feed_config = if is_list(app_config), do: Keyword.get(app_config, :feeds, %{}), else: %{}

    # Auto-enable OTX if API key is set via environment
    otx_key = System.get_env("OTX_API_KEY")
    misp_key = System.get_env("MISP_API_KEY")
    misp_url = System.get_env("MISP_URL")

    state = %{
      api_keys: %{
        misp: %{url: misp_url, key: misp_key, verify_ssl: true},
        otx: %{key: otx_key},
        virustotal: %{key: nil},
        shodan: %{key: nil}
      },
      custom_feeds: [],
      sync_status: %{},
      last_sync: nil,
      enabled: enabled,
      sync_interval: sync_interval,
      initial_delay_seconds: initial_delay_seconds,
      feed_config: feed_config
    }

    if state.enabled do
      # Log feed configuration on startup
      free_feed_count = map_size(@abusech_feeds) + map_size(@external_free_feeds)

      enabled_config_feeds =
        Enum.count(feed_config, fn {_name, cfg} ->
          is_map(cfg) and Map.get(cfg, :enabled, false)
        end)

      Logger.info(
        "[ThreatIntelFeeds] Enabled with #{free_feed_count} built-in feeds, #{enabled_config_feeds} configured feeds"
      )

      Logger.info(
        "[ThreatIntelFeeds] Sync interval: #{sync_interval_hours}h, initial sync in #{initial_delay_seconds}s"
      )

      if otx_key, do: Logger.info("[ThreatIntelFeeds] AlienVault OTX API key configured")

      if misp_key && misp_url,
        do: Logger.info("[ThreatIntelFeeds] MISP configured at #{misp_url}")

      # Log individual free feed status
      Enum.each(feed_config, fn {name, cfg} ->
        if is_map(cfg) and Map.get(cfg, :enabled, false) do
          Logger.debug(
            "[ThreatIntelFeeds] Feed enabled: #{name} - #{Map.get(cfg, :description, "")}"
          )
        end
      end)

      # Schedule initial sync after configurable delay (default 30s to let other services start)
      Process.send_after(self(), :initial_sync, :timer.seconds(initial_delay_seconds))

      # Schedule periodic sync
      schedule_sync(state.sync_interval)
    else
      Logger.info("[ThreatIntelFeeds] Disabled by configuration")
    end

    {:ok, state}
  end

  @impl true
  def handle_cast(:sync_all, state) do
    parent = self()

    Task.start(fn ->
      results = do_sync_all_with_results(state)
      send(parent, {:sync_complete, results})
    end)

    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_cast({:sync_feed, feed_name}, state) do
    parent = self()

    Task.start(fn ->
      result = do_sync_feed_with_result(feed_name, state)
      send(parent, {:feed_sync_complete, feed_name, result})
    end)

    {:noreply, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    # Build comprehensive feed status including sync interval and health
    stale_threshold = state.sync_interval * 2
    {total_iocs, iocs_by_type, iocs_by_source} = feed_ioc_counts(state)

    feed_health =
      Enum.reduce(state.sync_status, %{}, fn {name, info}, acc ->
        health =
          cond do
            info[:status] == :error ->
              "error"

            info[:last_sync] == nil ->
              "pending"

            DateTime.diff(DateTime.utc_now(), info[:last_sync], :millisecond) > stale_threshold ->
              "stale"

            true ->
              "ok"
          end

        Map.put(acc, name, Map.put(info, :health, health))
      end)

    status = %{
      enabled: state.enabled,
      last_sync: state.last_sync,
      sync_interval: state.sync_interval,
      sync_status: feed_health,
      feed_status: feed_health,
      feed_config: Map.get(state, :feed_config, %{}),
      api_keys: state.api_keys,
      configured_providers: get_configured_providers(state),
      custom_feeds: state.custom_feeds,
      total_iocs: total_iocs,
      iocs_by_type: iocs_by_type,
      iocs_by_source: iocs_by_source
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call({:configure_api_key, provider, api_key}, _from, state) do
    new_keys = put_in(state.api_keys, [provider, :key], api_key)
    {:reply, :ok, %{state | api_keys: new_keys}}
  end

  @impl true
  def handle_call({:add_custom_feed, name, url, opts}, _from, state) do
    feed = %{
      name: name,
      url: url,
      type: Keyword.get(opts, :type, :plain_text),
      ioc_type: Keyword.get(opts, :ioc_type, :auto),
      severity: Keyword.get(opts, :severity, "medium"),
      confidence: Keyword.get(opts, :confidence, 0.7),
      headers: Keyword.get(opts, :headers, [])
    }

    {:reply, :ok, %{state | custom_feeds: [feed | state.custom_feeds]}}
  end

  @impl true
  def handle_info(:initial_sync, state) do
    Logger.info("[ThreatIntelFeeds] Starting initial sync...")
    parent = self()

    Task.start(fn ->
      try do
        results = do_sync_all_with_results(state)
        send(parent, {:sync_complete, results})
      rescue
        e -> Logger.error("[ThreatIntelFeeds] Sync crashed: #{Exception.message(e)}")
      catch
        :exit, reason -> Logger.error("[ThreatIntelFeeds] Sync task exited: #{inspect(reason)}")
      end
    end)

    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    Logger.info("[ThreatIntelFeeds] Starting periodic sync...")
    parent = self()

    Task.start(fn ->
      try do
        results = do_sync_all_with_results(state)
        send(parent, {:sync_complete, results})
      rescue
        e -> Logger.error("[ThreatIntelFeeds] Periodic sync crashed: #{Exception.message(e)}")
      catch
        :exit, reason ->
          Logger.error("[ThreatIntelFeeds] Periodic sync exited: #{inspect(reason)}")
      end
    end)

    schedule_sync(state.sync_interval)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info({:sync_complete, results}, state) do
    Logger.info(
      "[ThreatIntelFeeds] Sync complete, updating status for #{map_size(results)} feeds"
    )

    new_status = Map.merge(state.sync_status, results)
    # Admit a durable, coalesced IOC snapshot rebuild after all feed writes.
    reload_receipt = TamanduaServer.Detection.IOCReload.schedule()

    if match?({:error, _}, reload_receipt) do
      Logger.error("[ThreatIntelFeeds] IOC reload admission failed: #{inspect(reload_receipt)}")
    end

    # Trigger retroactive scan for newly inserted IOCs
    try do
      new_iocs = collect_new_iocs_from_results(results)

      if length(new_iocs) > 0 do
        Logger.info(
          "[ThreatIntelFeeds] Triggering retroactive scan for #{length(new_iocs)} new IOCs"
        )

        TamanduaServer.ThreatIntel.RetroactiveScanner.scan_new_iocs(new_iocs)
      end
    catch
      _, _ -> :ok
    end

    {:noreply, %{state | sync_status: new_status}}
  end

  @impl true
  def handle_info({:feed_sync_complete, feed_name, result}, state) do
    Logger.info("[ThreatIntelFeeds] Feed #{feed_name} sync complete")
    new_status = Map.put(state.sync_status, feed_name, result)

    case TamanduaServer.Detection.IOCReload.schedule() do
      {:ok, _receipt} ->
        :ok

      {:error, reason} ->
        Logger.error("[ThreatIntelFeeds] IOC reload admission failed: #{inspect(reason)}")
    end

    {:noreply, %{state | sync_status: new_status}}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  defp feed_ioc_counts(%{enabled: false}), do: {0, %{}, %{}}

  defp feed_ioc_counts(_state) do
    {IOCs.count(), IOCs.count_by_type(), IOCs.count_by_source()}
  end

  # ============================================================================
  # Private Functions - Feed Sync
  # ============================================================================

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end

  defp do_sync_all_with_results(state) do
    results = %{}

    # Sync Abuse.ch feeds (always enabled, no API key)
    abusech_results = sync_abusech_feeds_with_results()
    results = Map.merge(results, abusech_results)

    # Sync external free feeds
    external_results = sync_external_feeds_with_results()
    results = Map.merge(results, external_results)

    # Sync premium feeds if configured
    results =
      if state.api_keys.otx.key do
        otx_result = sync_otx_feed_with_result(state.api_keys.otx.key)
        Map.put(results, :alienvault_otx, otx_result)
      else
        results
      end

    results =
      if state.api_keys.misp.key do
        misp_result = sync_misp_feed_with_result(state.api_keys.misp)
        Map.put(results, :misp, misp_result)
      else
        results
      end

    # Sync custom feeds
    custom_results =
      Enum.reduce(state.custom_feeds, %{}, fn feed, acc ->
        result = sync_custom_feed_with_result(feed)
        Map.put(acc, String.to_atom(feed.name), result)
      end)

    results = Map.merge(results, custom_results)

    Logger.info("[ThreatIntelFeeds] Sync complete - #{map_size(results)} feeds processed")
    results
  end

  defp do_sync_feed_with_result(feed_name, state) do
    atom_name = if is_binary(feed_name), do: String.to_existing_atom(feed_name), else: feed_name

    cond do
      Map.has_key?(@abusech_feeds, atom_name) ->
        url = Map.get(@abusech_feeds, atom_name)
        fetch_and_parse_feed_with_result(atom_name, url)

      Map.has_key?(@external_free_feeds, atom_name) ->
        url = Map.get(@external_free_feeds, atom_name)
        fetch_and_parse_feed_with_result(atom_name, url)

      Enum.find(state.custom_feeds, &(&1.name == to_string(feed_name))) ->
        feed = Enum.find(state.custom_feeds, &(&1.name == to_string(feed_name)))
        sync_custom_feed_with_result(feed)

      true ->
        Logger.warning("[ThreatIntelFeeds] Unknown feed: #{feed_name}")
        %{status: :error, error: "Unknown feed", last_sync: nil, count: 0}
    end
  rescue
    ArgumentError ->
      Logger.warning("[ThreatIntelFeeds] Invalid feed name: #{feed_name}")
      %{status: :error, error: "Invalid feed name", last_sync: nil, count: 0}
  end

  defp do_sync_all(state) do
    do_sync_all_with_results(state)
  end

  defp do_sync_feed(feed_name, state) do
    atom_name = String.to_existing_atom(feed_name)

    cond do
      Map.has_key?(@abusech_feeds, atom_name) ->
        url = Map.get(@abusech_feeds, atom_name)
        fetch_and_parse_feed(atom_name, url)

      Map.has_key?(@external_free_feeds, atom_name) ->
        url = Map.get(@external_free_feeds, atom_name)
        fetch_and_parse_feed(atom_name, url)

      Enum.find(state.custom_feeds, &(&1.name == feed_name)) ->
        feed = Enum.find(state.custom_feeds, &(&1.name == feed_name))
        sync_custom_feed(feed)

      true ->
        Logger.warning("[ThreatIntelFeeds] Unknown feed: #{feed_name}")
    end
  rescue
    ArgumentError ->
      Logger.warning("[ThreatIntelFeeds] Invalid feed name: #{feed_name}")
  end

  defp sync_abusech_feeds do
    sync_abusech_feeds_with_results()
  end

  defp sync_abusech_feeds_with_results do
    Logger.info("[ThreatIntelFeeds] Syncing Abuse.ch feeds...")

    Enum.reduce(@abusech_feeds, %{}, fn {name, url}, acc ->
      result =
        try do
          fetch_and_parse_feed_with_result(name, url)
        rescue
          e ->
            Logger.error("[ThreatIntelFeeds] Failed to sync #{name}: #{inspect(e)}")
            %{status: :error, error: Exception.message(e), last_sync: nil, count: 0}
        catch
          :exit, reason ->
            Logger.error("[ThreatIntelFeeds] Process exit syncing #{name}: #{inspect(reason)}")
            %{status: :error, error: "process_exit", last_sync: nil, count: 0}
        end

      Map.put(acc, name, result)
    end)
  end

  defp sync_external_feeds do
    sync_external_feeds_with_results()
  end

  defp sync_external_feeds_with_results do
    Logger.info("[ThreatIntelFeeds] Syncing external free feeds...")

    Enum.reduce(@external_free_feeds, %{}, fn {name, url}, acc ->
      result =
        try do
          fetch_and_parse_feed_with_result(name, url)
        rescue
          e ->
            Logger.error("[ThreatIntelFeeds] Failed to sync #{name}: #{inspect(e)}")
            %{status: :error, error: Exception.message(e), last_sync: nil, count: 0}
        catch
          :exit, reason ->
            Logger.error("[ThreatIntelFeeds] Process exit syncing #{name}: #{inspect(reason)}")
            %{status: :error, error: "process_exit", last_sync: nil, count: 0}
        end

      Map.put(acc, name, result)
    end)
  end

  defp fetch_and_parse_feed(name, url) do
    fetch_and_parse_feed_with_result(name, url)
  end

  defp fetch_and_parse_feed_with_result(name, url) do
    Logger.debug("[ThreatIntelFeeds] Fetching #{name} from #{url}")

    case Finch.build(:get, url) |> Finch.request(TamanduaServer.Finch, receive_timeout: 60_000) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        iocs = parse_feed_content(name, body)
        Logger.info("[ThreatIntelFeeds] Parsed #{length(iocs)} IOCs from #{name}")

        # This trusted feed populates the shared IOC catalog.
        case IOCs.bulk_add_global(iocs, on_conflict: :nothing) do
          {:ok, result} ->
            Logger.info("[ThreatIntelFeeds] Stored #{result.successful} new IOCs from #{name}")

            %{
              status: :ok,
              last_sync: DateTime.utc_now(),
              count: length(iocs),
              inserted: result.successful
            }

          {:error, reason} ->
            Logger.error(
              "[ThreatIntelFeeds] Failed to store IOCs from #{name}: #{inspect(reason)}"
            )

            %{
              status: :error,
              error: "IOC storage failed",
              last_sync: nil,
              count: length(iocs)
            }
        end

      {:ok, %Finch.Response{status: code}} ->
        Logger.warning("[ThreatIntelFeeds] HTTP #{code} for #{name}")
        %{status: :error, error: "HTTP #{code}", last_sync: nil, count: 0}

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("[ThreatIntelFeeds] HTTP error for #{name}: #{inspect(reason)}")
        %{status: :error, error: inspect(reason), last_sync: nil, count: 0}

      {:error, reason} ->
        Logger.error("[ThreatIntelFeeds] Request failed for #{name}: #{inspect(reason)}")
        %{status: :error, error: inspect(reason), last_sync: nil, count: 0}
    end
  rescue
    e ->
      Logger.error("[ThreatIntelFeeds] Exception fetching #{name}: #{Exception.message(e)}")
      %{status: :error, error: Exception.message(e), last_sync: nil, count: 0}
  catch
    :exit, reason ->
      Logger.error("[ThreatIntelFeeds] Process exit fetching #{name}: #{inspect(reason)}")
      %{status: :error, error: "process_exit", last_sync: nil, count: 0}
  end

  defp parse_feed_content(name, body) do
    cond do
      # Abuse.ch CSV formats
      name in [:ssl_blacklist, :ssl_ja3, :threatfox_iocs] ->
        parse_csv_feed(body, name)

      # JSON formats
      name in [:botnet_c2_ips] ->
        parse_json_feed(body, name)

      # PhishTank CSV
      name == :phishtank ->
        parse_phishtank(body)

      # Plain text IP/domain lists
      true ->
        parse_plain_text_feed(body, name)
    end
  end

  defp parse_plain_text_feed(body, name) do
    source = Atom.to_string(name)
    {ioc_type, severity} = determine_ioc_metadata(name)

    body
    |> String.split("\n")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(String.starts_with?(&1, "#") or &1 == ""))
    |> Enum.map(fn line ->
      # Handle CIDR notation
      value =
        if String.contains?(line, "/"), do: String.split(line, "/") |> List.first(), else: line

      %{
        type: ioc_type,
        value: String.downcase(value),
        source: source,
        severity: severity,
        tags: [source],
        description: "From #{source} threat feed"
      }
    end)
    |> Enum.filter(&valid_ioc?/1)
  end

  defp parse_csv_feed(body, name) do
    source = Atom.to_string(name)

    body
    |> String.split("\n")
    # Skip header
    |> Enum.drop(1)
    |> Enum.reject(&(String.starts_with?(&1, "#") or &1 == ""))
    |> Enum.map(fn line ->
      parts = String.split(line, ",")
      parse_csv_line(name, parts, source)
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp parse_csv_line(:ssl_blacklist, [_timestamp, sha1, _cn, _ip], source) do
    %{
      type: "hash_sha1",
      value: String.downcase(sha1),
      source: source,
      severity: "high",
      tags: ["ssl", "malicious_cert"],
      description: "Malicious SSL certificate from #{source}"
    }
  end

  defp parse_csv_line(:ssl_ja3, [ja3_hash, _desc, _malware], source) do
    # JA3 fingerprints don't have a standard IOC type, use filename as a catch-all
    %{
      type: "filename",
      value: String.downcase(String.trim(ja3_hash, "\"")),
      source: source,
      severity: "medium",
      tags: ["ja3", "tls_fingerprint"],
      description: "JA3 TLS fingerprint from #{source}"
    }
  end

  defp parse_csv_line(:threatfox_iocs, [_date, ioc_type, ioc_value, _threat_type | _rest], source) do
    %{
      type: normalize_ioc_type_to_db(ioc_type),
      value: String.downcase(String.trim(ioc_value, "\"")),
      source: source,
      severity: "high",
      tags: ["threatfox"],
      description: "IOC from ThreatFox"
    }
  end

  defp parse_csv_line(_, _, _), do: nil

  defp parse_json_feed(body, name) do
    source = Atom.to_string(name)

    case Jason.decode(body) do
      {:ok, data} when is_list(data) ->
        Enum.map(data, fn entry ->
          malware = Map.get(entry, "malware", "unknown")

          %{
            type: "ip",
            value: Map.get(entry, "ip_address", Map.get(entry, "ip", "")),
            source: source,
            severity: "critical",
            tags: [source, malware] |> Enum.reject(&is_nil/1),
            description: "Botnet C2 IP - #{malware}"
          }
        end)

      {:ok, %{"data" => data}} when is_list(data) ->
        Enum.map(data, fn entry ->
          %{
            type: "ip",
            value: Map.get(entry, "ip_address", Map.get(entry, "ip", "")),
            source: source,
            severity: "critical",
            tags: [source],
            description: "C2 IP from #{source}"
          }
        end)

      _ ->
        Logger.warning("[ThreatIntelFeeds] Failed to parse JSON for #{name}")
        []
    end
  end

  defp parse_phishtank(body) do
    body
    |> String.split("\n")
    |> Enum.drop(1)
    |> Enum.map(fn line ->
      case String.split(line, ",") do
        [_id, url | _rest] ->
          %{
            type: "url",
            value: String.trim(url, "\""),
            source: "phishtank",
            severity: "high",
            tags: ["phishing"],
            description: "Phishing URL from PhishTank"
          }

        _ ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp sync_otx_feed(api_key) do
    sync_otx_feed_with_result(api_key)
  end

  defp sync_otx_feed_with_result(api_key) do
    Logger.info("[ThreatIntelFeeds] Syncing AlienVault OTX...")

    headers = [{"X-OTX-API-KEY", api_key}]
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50"

    case Finch.build(:get, url, headers)
         |> Finch.request(TamanduaServer.Finch, receive_timeout: 60_000) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"results" => pulses}} ->
            iocs = Enum.flat_map(pulses, &parse_otx_pulse/1)
            Logger.info("[ThreatIntelFeeds] Parsed #{length(iocs)} IOCs from OTX")

            case IOCs.bulk_add_global(iocs, on_conflict: :nothing) do
              {:ok, result} ->
                %{
                  status: :ok,
                  last_sync: DateTime.utc_now(),
                  count: length(iocs),
                  inserted: result.successful
                }

              {:error, reason} ->
                Logger.error("[ThreatIntelFeeds] Failed to store OTX IOCs: #{inspect(reason)}")

                %{
                  status: :error,
                  error: "IOC storage failed",
                  last_sync: nil,
                  count: length(iocs)
                }
            end

          _ ->
            Logger.warning("[ThreatIntelFeeds] Failed to parse OTX response")
            %{status: :error, error: "Parse error", last_sync: nil, count: 0}
        end

      {:ok, %Finch.Response{status: code}} ->
        Logger.warning("[ThreatIntelFeeds] OTX returned HTTP #{code}")
        %{status: :error, error: "HTTP #{code}", last_sync: nil, count: 0}

      {:error, reason} ->
        Logger.error("[ThreatIntelFeeds] OTX error: #{inspect(reason)}")
        %{status: :error, error: inspect(reason), last_sync: nil, count: 0}
    end
  end

  defp parse_otx_pulse(pulse) do
    indicators = Map.get(pulse, "indicators", [])
    pulse_name = Map.get(pulse, "name", "unknown")
    tags = Map.get(pulse, "tags", []) ++ ["otx"]

    Enum.map(indicators, fn indicator ->
      %{
        type: normalize_otx_type_to_db(Map.get(indicator, "type")),
        value: String.downcase(Map.get(indicator, "indicator", "")),
        source: "alienvault_otx",
        severity: "high",
        description: pulse_name,
        tags: tags
      }
    end)
    |> Enum.filter(fn ioc -> ioc.type != nil end)
  end

  defp sync_misp_feed(config) do
    sync_misp_feed_with_result(config)
  end

  defp sync_misp_feed_with_result(%{url: url, key: api_key, verify_ssl: _verify_ssl})
       when is_binary(url) and is_binary(api_key) do
    Logger.info("[ThreatIntelFeeds] Syncing MISP...")

    headers = [
      {"Authorization", api_key},
      {"Accept", "application/json"},
      {"Content-Type", "application/json"}
    ]

    # Get recent events (last 30 days)
    body =
      Jason.encode!(%{
        "returnFormat" => "json",
        "timestamp" => "30d",
        "enforceWarninglist" => true
      })

    case Finch.build(:post, "#{url}/events/restSearch", headers, body)
         |> Finch.request(TamanduaServer.Finch, receive_timeout: 120_000) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, %{"response" => events}} ->
            iocs = Enum.flat_map(events, &parse_misp_event/1)
            Logger.info("[ThreatIntelFeeds] Parsed #{length(iocs)} IOCs from MISP")

            case IOCs.bulk_add_global(iocs, on_conflict: :nothing) do
              {:ok, result} ->
                %{
                  status: :ok,
                  last_sync: DateTime.utc_now(),
                  count: length(iocs),
                  inserted: result.successful
                }

              {:error, reason} ->
                Logger.error("[ThreatIntelFeeds] Failed to store MISP IOCs: #{inspect(reason)}")

                %{
                  status: :error,
                  error: "IOC storage failed",
                  last_sync: nil,
                  count: length(iocs)
                }
            end

          _ ->
            Logger.warning("[ThreatIntelFeeds] Failed to parse MISP response")
            %{status: :error, error: "Parse error", last_sync: nil, count: 0}
        end

      {:ok, %Finch.Response{status: code}} ->
        Logger.warning("[ThreatIntelFeeds] MISP returned HTTP #{code}")
        %{status: :error, error: "HTTP #{code}", last_sync: nil, count: 0}

      {:error, reason} ->
        Logger.error("[ThreatIntelFeeds] MISP error: #{inspect(reason)}")
        %{status: :error, error: inspect(reason), last_sync: nil, count: 0}
    end
  end

  defp sync_misp_feed_with_result(_), do: %{status: :disabled, last_sync: nil, count: 0}

  defp parse_misp_event(%{"Event" => event}) do
    attributes = Map.get(event, "Attribute", [])
    event_info = Map.get(event, "info", "unknown")
    tags = extract_misp_tags(event)

    Enum.map(attributes, fn attr ->
      %{
        type: normalize_misp_type_to_db(Map.get(attr, "type")),
        value: String.downcase(Map.get(attr, "value", "")),
        source: "misp",
        severity: "high",
        description: event_info,
        tags: tags
      }
    end)
    |> Enum.filter(fn ioc -> ioc.type != nil end)
  end

  defp parse_misp_event(_), do: []

  defp sync_custom_feed(feed) do
    sync_custom_feed_with_result(feed)
  end

  defp sync_custom_feed_with_result(feed) do
    Logger.info("[ThreatIntelFeeds] Syncing custom feed: #{feed.name}")

    headers = Enum.map(feed.headers, fn {k, v} -> {k, v} end)

    case Finch.build(:get, feed.url, headers)
         |> Finch.request(TamanduaServer.Finch, receive_timeout: 60_000) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        iocs = parse_custom_feed(body, feed)
        Logger.info("[ThreatIntelFeeds] Parsed #{length(iocs)} IOCs from #{feed.name}")

        case IOCs.bulk_add_global(iocs, on_conflict: :nothing) do
          {:ok, result} ->
            %{
              status: :ok,
              last_sync: DateTime.utc_now(),
              count: length(iocs),
              inserted: result.successful
            }

          {:error, reason} ->
            Logger.error(
              "[ThreatIntelFeeds] Failed to store custom feed #{feed.name} IOCs: #{inspect(reason)}"
            )

            %{
              status: :error,
              error: "IOC storage failed",
              last_sync: nil,
              count: length(iocs)
            }
        end

      {:ok, %Finch.Response{status: code}} ->
        Logger.warning("[ThreatIntelFeeds] Custom feed #{feed.name} returned HTTP #{code}")
        %{status: :error, error: "HTTP #{code}", last_sync: nil, count: 0}

      {:error, reason} ->
        Logger.error("[ThreatIntelFeeds] Custom feed #{feed.name} error: #{inspect(reason)}")
        %{status: :error, error: inspect(reason), last_sync: nil, count: 0}
    end
  end

  defp parse_custom_feed(body, feed) do
    case feed.type do
      :plain_text ->
        body
        |> String.split("\n")
        |> Enum.map(&String.trim/1)
        |> Enum.reject(&(String.starts_with?(&1, "#") or &1 == ""))
        |> Enum.map(fn value ->
          %{
            type: determine_ioc_type_from_value_to_db(value),
            value: String.downcase(value),
            source: feed.name,
            severity: feed.severity,
            tags: [feed.name],
            description: "IOC from custom feed #{feed.name}"
          }
        end)

      :json ->
        case Jason.decode(body) do
          {:ok, data} when is_list(data) ->
            Enum.map(data, fn entry ->
              %{
                type: determine_ioc_type_from_value_to_db(Map.get(entry, "value", "")),
                value: String.downcase(Map.get(entry, "value", "")),
                source: feed.name,
                severity: Map.get(entry, "severity", feed.severity),
                tags: [feed.name] ++ Map.get(entry, "tags", []),
                description: Map.get(entry, "description", "IOC from #{feed.name}")
              }
            end)

          _ ->
            []
        end

      _ ->
        []
    end
  end

  # ============================================================================
  # Retroactive Scan Helpers
  # ============================================================================

  # Collect recently inserted IOCs from sync results so the retroactive scanner
  # can search historical telemetry for matches. We fetch the most recent IOCs
  # from the database that match the inserted count from each feed sync.
  defp collect_new_iocs_from_results(results) do
    total_inserted =
      results
      |> Enum.map(fn {_feed, result} ->
        cond do
          is_map(result) -> Map.get(result, :inserted, 0)
          true -> 0
        end
      end)
      |> Enum.sum()

    if total_inserted > 0 do
      # Fetch the most recently inserted IOCs (these are the new ones)
      IOCs.list_recent(min(total_inserted, 5000))
      |> Enum.map(fn ioc ->
        %{type: ioc.type, value: ioc.value, source: ioc.source, inserted_at: ioc.inserted_at}
      end)
    else
      []
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  # Maps feed names to database-compatible IOC types
  # Database types: hash_md5, hash_sha256, hash_sha1, ip, domain, url, email, filename
  defp determine_ioc_metadata(name) do
    case name do
      n when n in [:feodo_ip_blocklist, :feodo_ip_recommended, :botnet_c2_ips] ->
        {"ip", "critical"}

      n when n in [:et_compromised_ips, :firehol_level1] ->
        {"ip", "high"}

      n when n in [:spamhaus_drop, :spamhaus_edrop] ->
        {"ip", "high"}

      :tor_exit_nodes ->
        {"ip", "medium"}

      n when n in [:openphish, :phishtank] ->
        {"url", "high"}

      n when n in [:urlhaus_urls] ->
        {"url", "critical"}

      n when n in [:malware_bazaar_recent, :malware_bazaar_full] ->
        {"hash_sha256", "critical"}

      :c2_all_domains ->
        {"domain", "critical"}

      :ransomware_abuse ->
        {"ip", "critical"}

      _ ->
        {"ip", "medium"}
    end
  end

  defp valid_ioc?(%{value: value, type: ioc_type}) do
    case ioc_type do
      "ip" -> valid_ipv4?(value) or valid_ipv6?(value)
      "domain" -> valid_domain?(value)
      "url" -> String.starts_with?(value, ["http://", "https://"])
      "hash_sha256" -> String.length(value) == 64 and Regex.match?(~r/^[a-f0-9]+$/, value)
      "hash_sha1" -> String.length(value) == 40 and Regex.match?(~r/^[a-f0-9]+$/, value)
      "hash_md5" -> String.length(value) == 32 and Regex.match?(~r/^[a-f0-9]+$/, value)
      _ -> true
    end
  end

  defp valid_ipv4?(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, {_, _, _, _}} -> true
      _ -> false
    end
  end

  defp valid_ipv6?(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, {_, _, _, _, _, _, _, _}} -> true
      _ -> false
    end
  end

  defp valid_domain?(domain) do
    Regex.match?(~r/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/, domain)
  end

  # Determines IOC type from value pattern - returns database-compatible types
  defp determine_ioc_type_from_value_to_db(value) do
    cond do
      Regex.match?(~r/^[a-f0-9]{64}$/i, value) -> "hash_sha256"
      Regex.match?(~r/^[a-f0-9]{40}$/i, value) -> "hash_sha1"
      Regex.match?(~r/^[a-f0-9]{32}$/i, value) -> "hash_md5"
      Regex.match?(~r/^https?:\/\//, value) -> "url"
      valid_ipv4?(value) or valid_ipv6?(value) -> "ip"
      valid_domain?(value) -> "domain"
      # Default to filename for unknown types
      true -> "filename"
    end
  end

  # Normalizes IOC type strings to database-compatible format
  defp normalize_ioc_type_to_db(type) do
    case String.downcase(type || "") do
      "ip" <> _ -> "ip"
      "domain" <> _ -> "domain"
      "url" <> _ -> "url"
      "sha256" <> _ -> "hash_sha256"
      "sha1" <> _ -> "hash_sha1"
      "md5" <> _ -> "hash_md5"
      "email" <> _ -> "email"
      "filename" <> _ -> "filename"
      _ -> nil
    end
  end

  # OTX indicator type to database type mapping
  defp normalize_otx_type_to_db(type) do
    case type do
      "IPv4" -> "ip"
      "IPv6" -> "ip"
      "domain" -> "domain"
      "hostname" -> "domain"
      "URL" -> "url"
      "FileHash-SHA256" -> "hash_sha256"
      "FileHash-SHA1" -> "hash_sha1"
      "FileHash-MD5" -> "hash_md5"
      "email" -> "email"
      _ -> nil
    end
  end

  # MISP attribute type to database type mapping
  defp normalize_misp_type_to_db(type) do
    case type do
      "ip-dst" -> "ip"
      "ip-src" -> "ip"
      "domain" -> "domain"
      "hostname" -> "domain"
      "url" -> "url"
      "sha256" -> "hash_sha256"
      "sha1" -> "hash_sha1"
      "md5" -> "hash_md5"
      "email-src" -> "email"
      "email-dst" -> "email"
      "filename" -> "filename"
      _ -> nil
    end
  end

  defp parse_misp_confidence(true), do: 0.9
  defp parse_misp_confidence(false), do: 0.6

  defp extract_misp_tags(event) do
    event
    |> Map.get("Tag", [])
    |> Enum.map(&Map.get(&1, "name", ""))
    |> Enum.reject(&(&1 == ""))
  end

  defp extract_misp_mitre(event) do
    event
    |> Map.get("Tag", [])
    |> Enum.map(&Map.get(&1, "name", ""))
    |> Enum.filter(&String.starts_with?(&1, "mitre-attack:"))
    |> Enum.map(&String.replace(&1, "mitre-attack:", ""))
  end

  defp extract_otx_mitre(pulse) do
    pulse
    |> Map.get("attack_ids", [])
    |> Enum.map(&Map.get(&1, "id", ""))
    |> Enum.reject(&(&1 == ""))
  end

  defp get_configured_providers(state) do
    %{
      # Always enabled
      abusech: true,
      # Always enabled
      external_feeds: true,
      otx: state.api_keys.otx.key != nil,
      misp: state.api_keys.misp.key != nil,
      virustotal: state.api_keys.virustotal.key != nil,
      shodan: state.api_keys.shodan.key != nil
    }
  end
end
