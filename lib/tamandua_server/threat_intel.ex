defmodule TamanduaServer.ThreatIntel do
  @moduledoc """
  Aggregates threat intelligence from multiple sources.

  Manages IOC feeds, provides lookup capabilities, and tracks statistics
  for threat indicators across the platform.

  ## Features
  - ETS-based IOC storage for fast lookups
  - Support for multiple feed sources (OTX, AbuseIPDB, etc.)
  - Automatic feed refresh scheduling
  - Statistics tracking by indicator type

  ## Usage

      # Lookup an indicator
      TamanduaServer.ThreatIntel.lookup(:ip, "192.168.1.1")

      # Get current stats
      TamanduaServer.ThreatIntel.get_stats()

      # Manually refresh all feeds
      TamanduaServer.ThreatIntel.refresh_feeds()
  """

  use GenServer
  require Logger

  @ets_table :threat_intel_iocs
  @stats_table :threat_intel_stats

  # Refresh feeds every 6 hours by default
  @default_refresh_interval :timer.hours(6)

  # Supported indicator types
  @indicator_types [:ip, :domain, :hash_md5, :hash_sha1, :hash_sha256, :url, :email, :cve]

  # Feed configurations
  @default_feeds [
    %{
      name: "otx",
      enabled: false,
      url: "https://otx.alienvault.com/api/v1/pulses/subscribed",
      api_key_env: "OTX_API_KEY",
      last_update: nil,
      status: :pending
    },
    %{
      name: "abuseipdb",
      enabled: false,
      url: "https://api.abuseipdb.com/api/v2/blacklist",
      api_key_env: "ABUSEIPDB_API_KEY",
      last_update: nil,
      status: :pending
    },
    %{
      name: "urlhaus",
      enabled: false,
      url: "https://urlhaus.abuse.ch/downloads/csv_recent/",
      api_key_env: nil,
      last_update: nil,
      status: :pending
    },
    %{
      name: "malwarebazaar",
      enabled: false,
      url: "https://bazaar.abuse.ch/export/txt/sha256/recent/",
      api_key_env: nil,
      last_update: nil,
      status: :pending
    }
  ]

  # ------------------------------------------------------------------
  # Client API
  # ------------------------------------------------------------------

  @doc """
  Starts the ThreatIntel GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Returns aggregated statistics about the threat intelligence data.

  ## Returns
  A map containing:
  - `:total_iocs` - Total number of IOCs in the cache
  - `:by_type` - Count of IOCs per indicator type
  - `:by_source` - Count of IOCs per feed source
  - `:last_update` - Timestamp of the most recent update
  - `:feeds_active` - Number of active feeds
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Lists all active (non-expired) IOCs.

  ## Options
  - `:type` - Filter by indicator type
  - `:source` - Filter by feed source
  - `:limit` - Maximum number of results (default: 100)

  ## Returns
  A list of IOC maps.
  """
  @spec list_active_iocs(keyword()) :: [map()]
  def list_active_iocs(opts \\ []) do
    GenServer.call(__MODULE__, {:list_active_iocs, opts})
  end

  @doc """
  Lists all active (non-expired) IOCs with pagination.

  ## Options
  - `:type` - Filter by indicator type
  - `:source` - Filter by feed source
  - `:page` - Page number (default: 1)
  - `:per_page` - Items per page (default: 50)

  ## Returns
  `{iocs, total_count}` tuple
  """
  @spec list_active_iocs_paginated(keyword()) :: {[map()], integer()}
  def list_active_iocs_paginated(opts \\ []) do
    GenServer.call(__MODULE__, {:list_active_iocs_paginated, opts})
  end

  @doc """
  Looks up an indicator in the threat intelligence cache.

  ## Parameters
  - `indicator_type` - One of #{inspect(@indicator_types)}
  - `indicator_value` - The value to lookup

  ## Returns
  - `{:ok, ioc}` if found
  - `:not_found` if not in cache
  """
  @spec lookup(atom(), String.t()) :: {:ok, map()} | :not_found
  def lookup(indicator_type, indicator_value) do
    case Process.whereis(__MODULE__) do
      nil ->
        :not_found

      _pid ->
        GenServer.call(__MODULE__, {:lookup, indicator_type, indicator_value}, 500)
    end
  catch
    :exit, reason ->
      Logger.debug("[ThreatIntel] lookup unavailable: #{inspect(reason)}")
      :not_found
  end

  @doc """
  Adds a new IOC to the cache.

  ## Parameters
  - `ioc_data` - Map containing:
    - `:type` - Indicator type (required)
    - `:value` - Indicator value (required)
    - `:source` - Feed source (default: "manual")
    - `:severity` - Severity level (default: "medium")
    - `:description` - Optional description
    - `:tags` - Optional list of tags
    - `:expires_at` - Optional expiration timestamp

  ## Returns
  - `{:ok, ioc}` on success
  - `{:error, reason}` on failure
  """
  @spec add_ioc(map()) :: {:ok, map()} | {:error, term()}
  def add_ioc(ioc_data) do
    GenServer.call(__MODULE__, {:add_ioc, ioc_data})
  end

  @doc """
  Triggers a refresh of all enabled feeds.

  ## Returns
  - `:ok` - Refresh started
  """
  @spec refresh_feeds() :: :ok
  def refresh_feeds do
    GenServer.cast(__MODULE__, :refresh_feeds)
  end

  @doc """
  Returns the current status of all configured feeds.

  ## Returns
  A list of feed status maps containing:
  - `:name` - Feed name
  - `:enabled` - Whether the feed is enabled
  - `:status` - Current status (:pending, :ok, :error)
  - `:last_update` - Timestamp of last successful update
  - `:ioc_count` - Number of IOCs from this feed
  """
  @spec get_feed_status() :: [map()]
  def get_feed_status do
    GenServer.call(__MODULE__, :get_feed_status)
  end

  # ------------------------------------------------------------------
  # GenServer Callbacks
  # ------------------------------------------------------------------

  @impl true
  def init(opts) do
    # Create ETS tables
    :ets.new(@ets_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@stats_table, [:named_table, :set, :public, read_concurrency: true])

    # Initialize stats
    initialize_stats()

    # Load feeds configuration
    feeds = Keyword.get(opts, :feeds, @default_feeds)
    refresh_interval = Keyword.get(opts, :refresh_interval, @default_refresh_interval)

    state = %{
      feeds: feeds,
      refresh_interval: refresh_interval,
      refresh_timer: nil
    }

    # Schedule initial feed refresh
    state = schedule_refresh(state)

    Logger.info("ThreatIntel started with #{length(feeds)} configured feeds")

    {:ok, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = compile_stats(state)
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:list_active_iocs, opts}, _from, state) do
    iocs = do_list_active_iocs(opts)
    {:reply, iocs, state}
  end

  @impl true
  def handle_call({:list_active_iocs_paginated, opts}, _from, state) do
    result = do_list_active_iocs_paginated(opts)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:lookup, type, value}, _from, state) do
    result = do_lookup(type, value)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:add_ioc, ioc_data}, _from, state) do
    result = do_add_ioc(ioc_data)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_feed_status, _from, state) do
    status = Enum.map(state.feeds, fn feed ->
      ioc_count = count_iocs_by_source(feed.name)
      Map.put(feed, :ioc_count, ioc_count)
    end)
    {:reply, status, state}
  end

  @impl true
  def handle_cast(:refresh_feeds, state) do
    state = do_refresh_feeds(state)
    {:noreply, state}
  end

  @impl true
  def handle_info(:scheduled_refresh, state) do
    Logger.info("Starting scheduled feed refresh")
    state = do_refresh_feeds(state)
    state = schedule_refresh(state)
    {:noreply, state}
  end

  @impl true
  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ------------------------------------------------------------------
  # Private Functions
  # ------------------------------------------------------------------

  defp initialize_stats do
    now = DateTime.utc_now()

    :ets.insert(@stats_table, {:total_iocs, 0})
    :ets.insert(@stats_table, {:last_update, now})

    Enum.each(@indicator_types, fn type ->
      :ets.insert(@stats_table, {{:by_type, type}, 0})
    end)
  end

  defp schedule_refresh(%{refresh_interval: interval} = state) do
    if state.refresh_timer, do: Process.cancel_timer(state.refresh_timer)
    timer = Process.send_after(self(), :scheduled_refresh, interval)
    %{state | refresh_timer: timer}
  end

  defp compile_stats(state) do
    [{:total_iocs, total}] = :ets.lookup(@stats_table, :total_iocs)
    [{:last_update, last_update}] = :ets.lookup(@stats_table, :last_update)

    by_type =
      @indicator_types
      |> Enum.map(fn type ->
        case :ets.lookup(@stats_table, {:by_type, type}) do
          [{{:by_type, ^type}, count}] -> {type, count}
          [] -> {type, 0}
        end
      end)
      |> Enum.into(%{})

    by_source =
      state.feeds
      |> Enum.map(fn feed -> {feed.name, count_iocs_by_source(feed.name)} end)
      |> Enum.into(%{})

    feeds_active = Enum.count(state.feeds, & &1.enabled)

    %{
      total_iocs: total,
      by_type: by_type,
      by_source: by_source,
      last_update: last_update,
      feeds_active: feeds_active
    }
  end

  defp do_list_active_iocs(opts) do
    limit = Keyword.get(opts, :limit, 100)
    type_filter = Keyword.get(opts, :type)
    source_filter = Keyword.get(opts, :source)
    now = DateTime.utc_now()

    @ets_table
    |> :ets.tab2list()
    |> Enum.map(fn {_key, ioc} -> ioc end)
    |> Enum.filter(fn ioc ->
      not_expired = is_nil(ioc.expires_at) or DateTime.compare(ioc.expires_at, now) == :gt
      type_match = is_nil(type_filter) or ioc.type == type_filter
      source_match = is_nil(source_filter) or ioc.source == source_filter
      not_expired and type_match and source_match
    end)
    |> Enum.take(limit)
  end

  defp do_list_active_iocs_paginated(opts) do
    page = Keyword.get(opts, :page, 1)
    per_page = Keyword.get(opts, :per_page, 50)
    type_filter = Keyword.get(opts, :type)
    source_filter = Keyword.get(opts, :source)
    now = DateTime.utc_now()

    # Filter all IOCs
    filtered_iocs =
      @ets_table
      |> :ets.tab2list()
      |> Enum.map(fn {_key, ioc} -> ioc end)
      |> Enum.filter(fn ioc ->
        not_expired = is_nil(ioc.expires_at) or DateTime.compare(ioc.expires_at, now) == :gt
        type_match = is_nil(type_filter) or ioc.type == type_filter
        source_match = is_nil(source_filter) or ioc.source == source_filter
        not_expired and type_match and source_match
      end)

    total_count = length(filtered_iocs)

    # Apply pagination
    offset = (page - 1) * per_page
    iocs =
      filtered_iocs
      |> Enum.drop(offset)
      |> Enum.take(per_page)

    {iocs, total_count}
  end

  defp do_lookup(type, value) do
    key = {type, value}

    case :ets.lookup(@ets_table, key) do
      [{^key, ioc}] ->
        if is_expired?(ioc) do
          :ets.delete(@ets_table, key)
          decrement_stats(type, ioc.source)
          :not_found
        else
          {:ok, ioc}
        end

      [] ->
        :not_found
    end
  end

  defp do_add_ioc(ioc_data) do
    with {:ok, type} <- validate_type(ioc_data[:type]),
         {:ok, value} <- validate_value(ioc_data[:value]) do
      ioc = %{
        type: type,
        value: value,
        source: Map.get(ioc_data, :source, "manual"),
        severity: Map.get(ioc_data, :severity, "medium"),
        description: Map.get(ioc_data, :description),
        tags: Map.get(ioc_data, :tags, []),
        expires_at: Map.get(ioc_data, :expires_at),
        inserted_at: DateTime.utc_now()
      }

      key = {type, value}
      is_new = :ets.lookup(@ets_table, key) == []
      :ets.insert(@ets_table, {key, ioc})

      if is_new do
        increment_stats(type, ioc.source)
      end

      {:ok, ioc}
    else
      {:error, _} = error -> error
    end
  end

  defp validate_type(nil), do: {:error, :missing_type}
  defp validate_type(type) when type in @indicator_types, do: {:ok, type}
  defp validate_type(type) when is_binary(type) do
    case String.to_existing_atom(type) do
      atom when atom in @indicator_types -> {:ok, atom}
      _ -> {:error, :invalid_type}
    end
  rescue
    ArgumentError -> {:error, :invalid_type}
  end
  defp validate_type(_), do: {:error, :invalid_type}

  defp validate_value(nil), do: {:error, :missing_value}
  defp validate_value(""), do: {:error, :empty_value}
  defp validate_value(value) when is_binary(value), do: {:ok, value}
  defp validate_value(_), do: {:error, :invalid_value}

  defp is_expired?(%{expires_at: nil}), do: false
  defp is_expired?(%{expires_at: expires_at}) do
    DateTime.compare(expires_at, DateTime.utc_now()) == :lt
  end

  defp increment_stats(type, source) do
    :ets.update_counter(@stats_table, :total_iocs, 1)
    :ets.update_counter(@stats_table, {:by_type, type}, {2, 1}, {{:by_type, type}, 0})
    :ets.update_counter(@stats_table, {:by_source, source}, {2, 1}, {{:by_source, source}, 0})
    :ets.insert(@stats_table, {:last_update, DateTime.utc_now()})
  end

  defp decrement_stats(type, source) do
    :ets.update_counter(@stats_table, :total_iocs, {2, -1, 0, 0})
    :ets.update_counter(@stats_table, {:by_type, type}, {2, -1, 0, 0}, {{:by_type, type}, 0})
    :ets.update_counter(@stats_table, {:by_source, source}, {2, -1, 0, 0}, {{:by_source, source}, 0})
  end

  defp count_iocs_by_source(source) do
    case :ets.lookup(@stats_table, {:by_source, source}) do
      [{{:by_source, ^source}, count}] -> count
      [] -> 0
    end
  end

  defp do_refresh_feeds(state) do
    Logger.info("Refreshing threat intelligence feeds")

    updated_feeds =
      Enum.map(state.feeds, fn feed ->
        if feed_available?(feed) do
          refresh_feed(feed)
        else
          Logger.debug("Skipping feed #{feed.name}: API key not configured")
          feed
        end
      end)

    %{state | feeds: updated_feeds}
  end

  # A feed is available if it does not require an API key, or its API key
  # is present in the environment.
  defp feed_available?(%{api_key_env: nil}), do: true
  defp feed_available?(%{api_key_env: env_var}) do
    get_api_key(env_var) != nil
  end

  defp refresh_feed(feed) do
    Logger.info("Refreshing feed: #{feed.name}")

    api_key = get_api_key(feed.api_key_env)

    case fetch_feed(feed, api_key) do
      {:ok, iocs} ->
        Enum.each(iocs, &do_add_ioc/1)
        Logger.info("Feed #{feed.name} refreshed with #{length(iocs)} IOCs")
        %{feed | status: :ok, last_update: DateTime.utc_now()}

      {:error, reason} ->
        Logger.error("Failed to refresh feed #{feed.name}: #{inspect(reason)}")
        %{feed | status: :error}
    end
  end

  # ------------------------------------------------------------------
  # API Key Helper
  # ------------------------------------------------------------------

  @doc false
  defp get_api_key(env_var) when is_binary(env_var) do
    case System.get_env(env_var) do
      nil -> nil
      "" -> nil
      key -> key
    end
  end

  defp get_api_key(nil), do: nil

  # ------------------------------------------------------------------
  # HTTP helpers
  # ------------------------------------------------------------------

  @recv_timeout 30_000

  defp http_get(url, headers) do
    Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout)
  end

  defp http_post(url, body, headers) do
    Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout)
  end

  # ------------------------------------------------------------------
  # Feed-specific fetch implementations
  # ------------------------------------------------------------------

  defp fetch_feed(%{name: "otx"} = _feed, api_key) do
    fetch_otx_feed(api_key)
  end

  defp fetch_feed(%{name: "abuseipdb"} = _feed, api_key) do
    fetch_abuseipdb_feed(api_key)
  end

  defp fetch_feed(%{name: "urlhaus"} = _feed, _api_key) do
    fetch_urlhaus_feed()
  end

  defp fetch_feed(%{name: "malwarebazaar"} = _feed, _api_key) do
    fetch_malwarebazaar_feed()
  end

  defp fetch_feed(feed, _api_key) do
    Logger.warning("Unknown feed: #{feed.name}")
    {:error, :unknown_feed}
  end

  # ------------------------------------------------------------------
  # OTX AlienVault
  # ------------------------------------------------------------------

  defp fetch_otx_feed(api_key) do
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = [{"X-OTX-API-KEY", api_key}, {"Accept", "application/json"}]

    case http_get(url, headers) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_otx_response(body)

      {:ok, %Finch.Response{status: status}} ->
        Logger.error("OTX feed returned HTTP #{status}")
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("OTX feed request failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp parse_otx_response(body) do
    case Jason.decode(body) do
      {:ok, %{"results" => pulses}} when is_list(pulses) ->
        iocs =
          pulses
          |> Enum.flat_map(fn pulse ->
            tags = Map.get(pulse, "tags", [])
            pulse_name = Map.get(pulse, "name", "")

            pulse
            |> Map.get("indicators", [])
            |> Enum.flat_map(fn indicator ->
              case map_otx_indicator_type(Map.get(indicator, "type")) do
                nil ->
                  []

                ioc_type ->
                  [
                    %{
                      type: ioc_type,
                      value: Map.get(indicator, "indicator", ""),
                      source: "otx",
                      confidence: 0.8,
                      severity: :high,
                      first_seen: DateTime.utc_now(),
                      tags: tags,
                      metadata: %{
                        "pulse_name" => pulse_name,
                        "title" => Map.get(indicator, "title", ""),
                        "description" => Map.get(indicator, "description", "")
                      }
                    }
                  ]
              end
            end)
          end)

        {:ok, iocs}

      {:ok, _} ->
        Logger.warning("OTX response did not contain expected 'results' key")
        {:ok, []}

      {:error, reason} ->
        Logger.error("Failed to parse OTX JSON: #{inspect(reason)}")
        {:error, :json_parse_error}
    end
  end

  defp map_otx_indicator_type("IPv4"), do: :ip
  defp map_otx_indicator_type("IPv6"), do: :ip
  defp map_otx_indicator_type("domain"), do: :domain
  defp map_otx_indicator_type("hostname"), do: :domain
  defp map_otx_indicator_type("URL"), do: :url
  defp map_otx_indicator_type("email"), do: :email
  defp map_otx_indicator_type("FileHash-MD5"), do: :hash_md5
  defp map_otx_indicator_type("FileHash-SHA1"), do: :hash_sha1
  defp map_otx_indicator_type("FileHash-SHA256"), do: :hash_sha256
  defp map_otx_indicator_type("CVE"), do: :cve
  defp map_otx_indicator_type(_), do: nil

  # ------------------------------------------------------------------
  # AbuseIPDB
  # ------------------------------------------------------------------

  defp fetch_abuseipdb_feed(api_key) do
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = [{"Key", api_key}, {"Accept", "application/json"}]

    case http_get(url, headers) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_abuseipdb_response(body)

      {:ok, %Finch.Response{status: status}} ->
        Logger.error("AbuseIPDB feed returned HTTP #{status}")
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("AbuseIPDB feed request failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp parse_abuseipdb_response(body) do
    case Jason.decode(body) do
      {:ok, %{"data" => data}} when is_list(data) ->
        iocs =
          Enum.map(data, fn entry ->
            abuse_score = Map.get(entry, "abuseConfidenceScore", 0)
            confidence = abuse_score / 100.0

            severity =
              cond do
                abuse_score >= 90 -> :critical
                abuse_score >= 60 -> :high
                true -> :medium
              end

            %{
              type: :ip,
              value: Map.get(entry, "ipAddress", ""),
              source: "abuseipdb",
              confidence: confidence,
              severity: severity,
              first_seen: DateTime.utc_now(),
              tags: ["blacklist"],
              metadata: %{
                "abuse_confidence_score" => abuse_score,
                "country_code" => Map.get(entry, "countryCode"),
                "last_reported_at" => Map.get(entry, "lastReportedAt")
              }
            }
          end)

        {:ok, iocs}

      {:ok, _} ->
        Logger.warning("AbuseIPDB response did not contain expected 'data' key")
        {:ok, []}

      {:error, reason} ->
        Logger.error("Failed to parse AbuseIPDB JSON: #{inspect(reason)}")
        {:error, :json_parse_error}
    end
  end

  # ------------------------------------------------------------------
  # URLhaus (no API key required)
  # ------------------------------------------------------------------

  defp fetch_urlhaus_feed do
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    headers = [{"Accept", "application/json"}]

    case http_get(url, headers) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_urlhaus_response(body)

      {:ok, %Finch.Response{status: status}} ->
        Logger.error("URLhaus feed returned HTTP #{status}")
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("URLhaus feed request failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp parse_urlhaus_response(body) do
    case Jason.decode(body) do
      {:ok, %{"urls" => urls}} when is_list(urls) ->
        iocs =
          Enum.map(urls, fn entry ->
            url_status = Map.get(entry, "url_status", "unknown")
            threat = Map.get(entry, "threat", "unknown")

            severity =
              case url_status do
                "online" -> :critical
                "offline" -> :medium
                _ -> :medium
              end

            confidence =
              case url_status do
                "online" -> 0.9
                "offline" -> 0.5
                _ -> 0.4
              end

            %{
              type: :url,
              value: Map.get(entry, "url", ""),
              source: "urlhaus",
              confidence: confidence,
              severity: severity,
              first_seen: DateTime.utc_now(),
              tags: [threat, url_status] |> Enum.reject(&is_nil/1),
              metadata: %{
                "threat" => threat,
                "url_status" => url_status,
                "host" => Map.get(entry, "host"),
                "date_added" => Map.get(entry, "date_added"),
                "reporter" => Map.get(entry, "reporter")
              }
            }
          end)

        {:ok, iocs}

      {:ok, _} ->
        Logger.warning("URLhaus response did not contain expected 'urls' key")
        {:ok, []}

      {:error, reason} ->
        Logger.error("Failed to parse URLhaus JSON: #{inspect(reason)}")
        {:error, :json_parse_error}
    end
  end

  # ------------------------------------------------------------------
  # MalwareBazaar (no API key required)
  # ------------------------------------------------------------------

  defp fetch_malwarebazaar_feed do
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = [{"Content-Type", "application/x-www-form-urlencoded"}, {"Accept", "application/json"}]
    body = "query=get_recent&selector=100"

    case http_post(url, body, headers) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        parse_malwarebazaar_response(resp_body)

      {:ok, %Finch.Response{status: status}} ->
        Logger.error("MalwareBazaar feed returned HTTP #{status}")
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("MalwareBazaar feed request failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp parse_malwarebazaar_response(body) do
    case Jason.decode(body) do
      {:ok, %{"data" => data}} when is_list(data) ->
        iocs =
          Enum.map(data, fn entry ->
            signature = Map.get(entry, "signature", "unknown")
            file_type = Map.get(entry, "file_type", "unknown")

            %{
              type: :hash_sha256,
              value: Map.get(entry, "sha256_hash", ""),
              source: "malwarebazaar",
              confidence: 0.95,
              severity: :critical,
              first_seen: DateTime.utc_now(),
              tags: [signature, file_type] |> Enum.reject(&(&1 == "unknown" or is_nil(&1))),
              metadata: %{
                "sha256_hash" => Map.get(entry, "sha256_hash"),
                "md5_hash" => Map.get(entry, "md5_hash"),
                "sha1_hash" => Map.get(entry, "sha1_hash"),
                "file_type" => file_type,
                "file_size" => Map.get(entry, "file_size"),
                "signature" => signature,
                "reporter" => Map.get(entry, "reporter"),
                "first_seen" => Map.get(entry, "first_seen"),
                "file_name" => Map.get(entry, "file_name")
              }
            }
          end)

        {:ok, iocs}

      {:ok, %{"query_status" => "no_results"}} ->
        Logger.info("MalwareBazaar returned no results")
        {:ok, []}

      {:ok, _} ->
        Logger.warning("MalwareBazaar response did not contain expected 'data' key")
        {:ok, []}

      {:error, reason} ->
        Logger.error("Failed to parse MalwareBazaar JSON: #{inspect(reason)}")
        {:error, :json_parse_error}
    end
  end
end
