defmodule TamanduaServer.Detection.ThreatIntel.AlienVault do
  @moduledoc """
  AlienVault Open Threat Exchange (OTX) API integration.

  Provides indicator lookups and pulse subscriptions using the OTX API.
  Supports various indicator types including IP, domain, hostname, URL, file hashes, and CVEs.

  ## API Documentation
  https://otx.alienvault.com/api

  ## Usage

      # Configure API key
      AlienVault.configure("your-otx-api-key")

      # Lookup an indicator
      AlienVault.get_indicator(:ipv4, "192.168.1.1")
      AlienVault.get_indicator(:domain, "evil.com")
      AlienVault.get_indicator(:file, "sha256hash...")

      # Get related pulses for an indicator
      AlienVault.get_pulses(:ipv4, "192.168.1.1")

      # Get subscribed pulses (threat intelligence feeds)
      AlienVault.get_subscribed_pulses()

  ## Configuration

  Set the `OTX_API_KEY` environment variable or configure via:

      config :tamandua_server, :threat_intel,
        alienvault_api_key: "your-api-key"
  """

  use GenServer
  require Logger

  @api_base "https://otx.alienvault.com/api/v1"
  @http_timeout 30_000
  @recv_timeout 30_000

  # Cache TTL: 6 hours for indicator lookups
  @cache_ttl :timer.hours(6)

  @ets_table :alienvault_cache

  # Valid indicator types
  @indicator_types [:ipv4, :ipv6, :domain, :hostname, :url, :file, :cve, :nids, :mutex, :email]

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the AlienVault OTX integration GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Configure the AlienVault OTX API key.

  ## Examples

      iex> configure("your-otx-api-key")
      :ok
  """
  @spec configure(String.t()) :: :ok
  def configure(api_key) when is_binary(api_key) do
    GenServer.call(__MODULE__, {:configure, api_key})
  end

  @doc """
  Lookup an indicator in AlienVault OTX.

  ## Supported Types
  - `:ipv4` - IPv4 address
  - `:ipv6` - IPv6 address
  - `:domain` - Domain name
  - `:hostname` - Hostname (FQDN)
  - `:url` - Full URL
  - `:file` - File hash (MD5, SHA1, SHA256)
  - `:cve` - CVE identifier
  - `:nids` - Network IDS signature
  - `:mutex` - Mutex name
  - `:email` - Email address

  ## Examples

      iex> get_indicator(:ipv4, "192.168.1.1")
      {:ok, %{
        indicator: "192.168.1.1",
        type: :ipv4,
        pulse_count: 5,
        validation: %{
          result: "valid",
          source: "..."
        },
        geo: %{
          country_code: "US",
          country_name: "United States",
          city: "New York",
          latitude: 40.7128,
          longitude: -74.0060,
          asn: "AS12345"
        },
        reputation: 2,
        first_seen: ~U[2024-01-15 10:00:00Z],
        last_seen: ~U[2024-01-20 15:30:00Z],
        related_pulses: [...]
      }}

      iex> get_indicator(:domain, "notmalicious.com")
      {:ok, %{found: false}}
  """
  @spec get_indicator(atom(), String.t()) :: {:ok, map()} | {:error, term()}
  def get_indicator(type, indicator) when type in @indicator_types and is_binary(indicator) do
    GenServer.call(__MODULE__, {:get_indicator, type, indicator}, 60_000)
  end

  @doc """
  Get general information about an indicator.

  Returns basic details without fetching full pulse data.
  """
  @spec get_indicator_general(atom(), String.t()) :: {:ok, map()} | {:error, term()}
  def get_indicator_general(type, indicator) when type in @indicator_types and is_binary(indicator) do
    GenServer.call(__MODULE__, {:get_indicator_general, type, indicator}, 60_000)
  end

  @doc """
  Get pulses (threat intelligence reports) associated with an indicator.

  ## Examples

      iex> get_pulses(:ipv4, "192.168.1.1")
      {:ok, [
        %{
          id: "abc123",
          name: "Emotet C2 Infrastructure",
          description: "...",
          author_name: "AlienVault",
          created: ~U[2024-01-15 10:00:00Z],
          modified: ~U[2024-01-20 15:30:00Z],
          indicators: [...],
          tags: ["emotet", "c2", "banking"],
          tlp: "white",
          references: [...]
        },
        ...
      ]}
  """
  @spec get_pulses(atom(), String.t()) :: {:ok, [map()]} | {:error, term()}
  def get_pulses(type, indicator) when type in @indicator_types and is_binary(indicator) do
    GenServer.call(__MODULE__, {:get_pulses, type, indicator}, 60_000)
  end

  @doc """
  Get subscribed pulses (your threat intelligence feed).

  This returns pulses you're subscribed to in OTX.

  ## Options
  - `:limit` - Maximum number of pulses to return (default: 50)
  - `:modified_since` - Only return pulses modified after this datetime

  ## Examples

      iex> get_subscribed_pulses(limit: 100)
      {:ok, %{
        pulses: [...],
        count: 100,
        next: "cursor_token"
      }}
  """
  @spec get_subscribed_pulses(keyword()) :: {:ok, map()} | {:error, term()}
  def get_subscribed_pulses(opts \\ []) do
    GenServer.call(__MODULE__, {:get_subscribed_pulses, opts}, 60_000)
  end

  @doc """
  Get details for a specific pulse by ID.

  ## Examples

      iex> get_pulse("abc123def456")
      {:ok, %{
        id: "abc123def456",
        name: "Emotet Campaign Q1 2024",
        description: "...",
        indicators: [...],
        ...
      }}
  """
  @spec get_pulse(String.t()) :: {:ok, map()} | {:error, term()}
  def get_pulse(pulse_id) when is_binary(pulse_id) do
    GenServer.call(__MODULE__, {:get_pulse, pulse_id}, 60_000)
  end

  @doc """
  Search for pulses by query string.

  ## Examples

      iex> search_pulses("emotet", limit: 20)
      {:ok, %{
        pulses: [...],
        count: 20
      }}
  """
  @spec search_pulses(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def search_pulses(query, opts \\ []) when is_binary(query) do
    GenServer.call(__MODULE__, {:search_pulses, query, opts}, 60_000)
  end

  @doc """
  Get passive DNS data for a domain or IP.

  ## Examples

      iex> get_passive_dns(:domain, "evil.com")
      {:ok, %{
        passive_dns: [
          %{address: "192.168.1.1", hostname: "evil.com", first: ~U[...], last: ~U[...]},
          ...
        ]
      }}
  """
  @spec get_passive_dns(atom(), String.t()) :: {:ok, map()} | {:error, term()}
  def get_passive_dns(type, indicator) when type in [:ipv4, :ipv6, :domain, :hostname] do
    GenServer.call(__MODULE__, {:get_passive_dns, type, indicator}, 60_000)
  end

  @doc """
  Get URL analysis data.

  Returns information about a URL including any associated malware.

  ## Examples

      iex> get_url_analysis("http://evil.com/malware.exe")
      {:ok, %{
        url: "http://evil.com/malware.exe",
        domain: "evil.com",
        hostname: "evil.com",
        result: %{urlworker: %{...}},
        httpcode: 200,
        page_type: "text/html"
      }}
  """
  @spec get_url_analysis(String.t()) :: {:ok, map()} | {:error, term()}
  def get_url_analysis(url) when is_binary(url) do
    GenServer.call(__MODULE__, {:get_url_analysis, url}, 60_000)
  end

  @doc """
  Get file analysis data by hash.

  Returns information about a file hash including sandbox results.

  ## Examples

      iex> get_file_analysis("sha256hash...")
      {:ok, %{
        sha256: "...",
        sha1: "...",
        md5: "...",
        file_type: "PE32 executable",
        size: 123456,
        analysis: %{
          info: %{...},
          plugins: %{...}
        }
      }}
  """
  @spec get_file_analysis(String.t()) :: {:ok, map()} | {:error, term()}
  def get_file_analysis(hash) when is_binary(hash) do
    GenServer.call(__MODULE__, {:get_file_analysis, hash}, 60_000)
  end

  @doc """
  Get current service status.

  ## Examples

      iex> get_status()
      %{
        configured: true,
        cache_size: 1234,
        stats: %{lookups: 100, cache_hits: 80, api_calls: 20}
      }
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  Clear the local cache.
  """
  @spec clear_cache() :: :ok
  def clear_cache do
    GenServer.call(__MODULE__, :clear_cache)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    # Create ETS cache
    :ets.new(@ets_table, [:named_table, :set, :public, read_concurrency: true])

    api_key = Keyword.get(opts, :api_key) ||
              Application.get_env(:tamandua_server, :threat_intel)[:alienvault_api_key] ||
              System.get_env("OTX_API_KEY")

    state = %{
      api_key: api_key,
      stats: %{
        lookups: 0,
        cache_hits: 0,
        api_calls: 0,
        errors: 0
      }
    }

    Logger.info("[AlienVault] Initialized, API key #{if api_key, do: "configured", else: "not configured"}")

    {:ok, state}
  end

  @impl true
  def handle_call({:configure, api_key}, _from, state) do
    Logger.info("[AlienVault] API key configured")
    {:reply, :ok, %{state | api_key: api_key}}
  end

  @impl true
  def handle_call({:get_indicator, type, indicator}, _from, state) do
    state = update_stats(state, :lookup)

    case get_cached(type, indicator) do
      {:ok, cached} ->
        state = update_stats(state, :cache_hit)
        {:reply, {:ok, cached}, state}

      :miss ->
        {result, state} = do_get_indicator(type, indicator, state)
        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:get_indicator_general, type, indicator}, _from, state) do
    state = update_stats(state, :lookup)
    {result, state} = do_get_indicator_general(type, indicator, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_pulses, type, indicator}, _from, state) do
    {result, state} = do_get_pulses(type, indicator, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_subscribed_pulses, opts}, _from, state) do
    {result, state} = do_get_subscribed_pulses(opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_pulse, pulse_id}, _from, state) do
    {result, state} = do_get_pulse(pulse_id, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:search_pulses, query, opts}, _from, state) do
    {result, state} = do_search_pulses(query, opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_passive_dns, type, indicator}, _from, state) do
    {result, state} = do_get_passive_dns(type, indicator, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_url_analysis, url}, _from, state) do
    {result, state} = do_get_url_analysis(url, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_file_analysis, hash}, _from, state) do
    {result, state} = do_get_file_analysis(hash, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      configured: state.api_key != nil,
      cache_size: :ets.info(@ets_table, :size),
      stats: state.stats
    }
    {:reply, status, state}
  end

  @impl true
  def handle_call(:clear_cache, _from, state) do
    :ets.delete_all_objects(@ets_table)
    Logger.info("[AlienVault] Cache cleared")
    {:reply, :ok, state}
  end

  # ============================================================================
  # Private Functions - API Calls
  # ============================================================================

  defp do_get_indicator(type, indicator, state) do
    if state.api_key do
      type_str = indicator_type_to_string(type)
      url = "#{@api_base}/indicators/#{type_str}/#{URI.encode(indicator)}/general"

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          result = parse_indicator_response(type, indicator, data)
          cache_result(type, indicator, result)
          {{:ok, result}, state}

        {:error, :not_found, state} ->
          result = %{found: false, indicator: indicator, type: type}
          cache_result(type, indicator, result)
          {{:ok, result}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_get_indicator_general(type, indicator, state) do
    if state.api_key do
      type_str = indicator_type_to_string(type)
      url = "#{@api_base}/indicators/#{type_str}/#{URI.encode(indicator)}/general"

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          result = parse_indicator_general(type, indicator, data)
          {{:ok, result}, state}

        {:error, :not_found, state} ->
          {{:ok, %{found: false}}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_get_pulses(type, indicator, state) do
    if state.api_key do
      type_str = indicator_type_to_string(type)
      url = "#{@api_base}/indicators/#{type_str}/#{URI.encode(indicator)}/general"

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          pulses = Map.get(data, "pulse_info", %{}) |> Map.get("pulses", [])
          parsed_pulses = Enum.map(pulses, &parse_pulse/1)
          {{:ok, parsed_pulses}, state}

        {:error, :not_found, state} ->
          {{:ok, []}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_get_subscribed_pulses(opts, state) do
    if state.api_key do
      limit = Keyword.get(opts, :limit, 50)
      modified_since = Keyword.get(opts, :modified_since)

      url = "#{@api_base}/pulses/subscribed?limit=#{limit}"
      url = if modified_since do
        "#{url}&modified_since=#{DateTime.to_iso8601(modified_since)}"
      else
        url
      end

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          result = %{
            pulses: Map.get(data, "results", []) |> Enum.map(&parse_pulse/1),
            count: Map.get(data, "count", 0),
            next: Map.get(data, "next")
          }
          {{:ok, result}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_get_pulse(pulse_id, state) do
    if state.api_key do
      url = "#{@api_base}/pulses/#{pulse_id}"

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          result = parse_pulse_detail(data)
          {{:ok, result}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_search_pulses(query, opts, state) do
    if state.api_key do
      limit = Keyword.get(opts, :limit, 20)
      url = "#{@api_base}/search/pulses?q=#{URI.encode(query)}&limit=#{limit}"

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          result = %{
            pulses: Map.get(data, "results", []) |> Enum.map(&parse_pulse/1),
            count: Map.get(data, "count", 0)
          }
          {{:ok, result}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_get_passive_dns(type, indicator, state) do
    if state.api_key do
      type_str = indicator_type_to_string(type)
      url = "#{@api_base}/indicators/#{type_str}/#{URI.encode(indicator)}/passive_dns"

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          passive_dns = Map.get(data, "passive_dns", [])
          parsed = Enum.map(passive_dns, &parse_passive_dns_entry/1)
          {{:ok, %{passive_dns: parsed}}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_get_url_analysis(url_to_analyze, state) do
    if state.api_key do
      encoded_url = Base.url_encode64(url_to_analyze, padding: false)
      api_url = "#{@api_base}/indicators/url/#{encoded_url}/general"

      case execute_get_request(api_url, state) do
        {:ok, data, state} ->
          result = parse_url_analysis(url_to_analyze, data)
          {{:ok, result}, state}

        {:error, :not_found, state} ->
          {{:ok, %{found: false, url: url_to_analyze}}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp do_get_file_analysis(hash, state) do
    if state.api_key do
      url = "#{@api_base}/indicators/file/#{hash}/analysis"

      case execute_get_request(url, state) do
        {:ok, data, state} ->
          result = parse_file_analysis(hash, data)
          {{:ok, result}, state}

        {:error, :not_found, state} ->
          {{:ok, %{found: false, hash: hash}}, state}

        {:error, reason, state} ->
          {{:error, reason}, state}
      end
    else
      {{:error, :no_api_key}, state}
    end
  end

  defp execute_get_request(url, state) do
    headers = [
      {"X-OTX-API-KEY", state.api_key},
      {"Accept", "application/json"}
    ]

    state = update_stats(state, :api_call)

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, data} -> {:ok, data, state}
          {:error, _} -> {:error, :json_parse_error, update_stats(state, :error)}
        end

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found, state}

      {:ok, %Finch.Response{status: 403}} ->
        Logger.warning("[AlienVault] API key invalid or rate limited")
        {:error, :forbidden, update_stats(state, :error)}

      {:ok, %Finch.Response{status: status}} ->
        Logger.warning("[AlienVault] HTTP #{status}")
        {:error, {:http_error, status}, update_stats(state, :error)}

      {:error, reason} ->
        Logger.error("[AlienVault] HTTP error: #{inspect(reason)}")
        {:error, reason, update_stats(state, :error)}
    end
  end

  # ============================================================================
  # Private Functions - Response Parsers
  # ============================================================================

  defp parse_indicator_response(type, indicator, data) do
    pulse_info = Map.get(data, "pulse_info", %{})
    validation = Map.get(data, "validation", [])
    geo = Map.get(data, "geo", %{}) || Map.get(data, "country_name") && data || %{}

    %{
      found: true,
      indicator: indicator,
      type: type,
      pulse_count: Map.get(pulse_info, "count", 0),
      validation: parse_validation(validation),
      geo: parse_geo(geo),
      reputation: Map.get(data, "reputation", 0),
      asn: Map.get(data, "asn"),
      city: Map.get(data, "city") || Map.get(geo, "city"),
      country_code: Map.get(data, "country_code") || Map.get(geo, "country_code"),
      country_name: Map.get(data, "country_name") || Map.get(geo, "country_name"),
      first_seen: parse_timestamp(Map.get(data, "first_seen")),
      last_seen: parse_timestamp(Map.get(data, "last_seen")),
      related_pulses: Map.get(pulse_info, "pulses", []) |> Enum.map(&parse_pulse/1) |> Enum.take(10),
      sections: Map.get(data, "sections", []),
      whois: Map.get(data, "whois"),
      source: "alienvault"
    }
  end

  defp parse_indicator_general(type, indicator, data) do
    %{
      found: true,
      indicator: indicator,
      type: type,
      pulse_count: get_in(data, ["pulse_info", "count"]) || 0,
      reputation: Map.get(data, "reputation", 0),
      asn: Map.get(data, "asn"),
      country_code: Map.get(data, "country_code"),
      source: "alienvault"
    }
  end

  defp parse_pulse(pulse) do
    %{
      id: Map.get(pulse, "id"),
      name: Map.get(pulse, "name"),
      description: Map.get(pulse, "description"),
      author_name: Map.get(pulse, "author_name") || get_in(pulse, ["author", "username"]),
      created: parse_timestamp(Map.get(pulse, "created")),
      modified: parse_timestamp(Map.get(pulse, "modified")),
      indicator_count: Map.get(pulse, "indicator_count", 0),
      tags: Map.get(pulse, "tags", []),
      tlp: Map.get(pulse, "tlp", "white"),
      references: Map.get(pulse, "references", []),
      adversary: Map.get(pulse, "adversary"),
      targeted_countries: Map.get(pulse, "targeted_countries", []),
      industries: Map.get(pulse, "industries", []),
      malware_families: Map.get(pulse, "malware_families", []),
      attack_ids: Map.get(pulse, "attack_ids", []) |> Enum.map(&Map.get(&1, "id"))
    }
  end

  defp parse_pulse_detail(data) do
    base = parse_pulse(data)

    indicators = Map.get(data, "indicators", [])
    |> Enum.map(fn ind ->
      %{
        id: Map.get(ind, "id"),
        indicator: Map.get(ind, "indicator"),
        type: Map.get(ind, "type"),
        created: parse_timestamp(Map.get(ind, "created")),
        title: Map.get(ind, "title"),
        description: Map.get(ind, "description"),
        role: Map.get(ind, "role")
      }
    end)

    Map.put(base, :indicators, indicators)
  end

  defp parse_validation([]), do: nil
  defp parse_validation(validation) when is_list(validation) do
    Enum.map(validation, fn v ->
      %{
        source: Map.get(v, "source"),
        name: Map.get(v, "name"),
        message: Map.get(v, "message")
      }
    end)
  end
  defp parse_validation(_), do: nil

  defp parse_geo(nil), do: nil
  defp parse_geo(geo) when is_map(geo) do
    %{
      country_code: Map.get(geo, "country_code") || Map.get(geo, "country_code2"),
      country_name: Map.get(geo, "country_name"),
      city: Map.get(geo, "city"),
      region: Map.get(geo, "region"),
      latitude: Map.get(geo, "latitude"),
      longitude: Map.get(geo, "longitude"),
      asn: Map.get(geo, "asn"),
      area_code: Map.get(geo, "area_code"),
      postal_code: Map.get(geo, "postal_code"),
      continent_code: Map.get(geo, "continent_code"),
      flag_title: Map.get(geo, "flag_title"),
      flag_url: Map.get(geo, "flag_url")
    }
  end

  defp parse_passive_dns_entry(entry) do
    %{
      address: Map.get(entry, "address"),
      hostname: Map.get(entry, "hostname"),
      record_type: Map.get(entry, "record_type"),
      first: parse_timestamp(Map.get(entry, "first")),
      last: parse_timestamp(Map.get(entry, "last")),
      asn: Map.get(entry, "asn"),
      country: Map.get(entry, "flag_title")
    }
  end

  defp parse_url_analysis(url, data) do
    %{
      found: true,
      url: url,
      domain: Map.get(data, "domain"),
      hostname: Map.get(data, "hostname"),
      alexa: Map.get(data, "alexa"),
      whois: Map.get(data, "whois"),
      pulse_count: get_in(data, ["pulse_info", "count"]) || 0,
      related_pulses: get_in(data, ["pulse_info", "pulses"]) || [],
      source: "alienvault"
    }
  end

  defp parse_file_analysis(hash, data) do
    analysis = Map.get(data, "analysis", %{})
    info = Map.get(analysis, "info", %{})
    plugins = Map.get(analysis, "plugins", %{})

    %{
      found: true,
      hash: hash,
      file_type: Map.get(info, "file_type"),
      file_class: Map.get(info, "file_class"),
      file_size: Map.get(info, "filesize"),
      md5: Map.get(info, "md5"),
      sha1: Map.get(info, "sha1"),
      sha256: Map.get(info, "sha256"),
      ssdeep: Map.get(info, "ssdeep"),
      exiftool: Map.get(plugins, "exiftool", %{}),
      pe_info: Map.get(plugins, "peinfo", %{}),
      yara: Map.get(plugins, "yarascan", %{}),
      cuckoo: Map.get(plugins, "cuckoo", %{}),
      source: "alienvault"
    }
  end

  # ============================================================================
  # Private Functions - Caching
  # ============================================================================

  defp get_cached(type, indicator) do
    cache_key = {type, indicator}

    case :ets.lookup(@ets_table, cache_key) do
      [{^cache_key, data, inserted_at}] ->
        age = System.monotonic_time(:millisecond) - inserted_at
        if age < @cache_ttl do
          {:ok, data}
        else
          :ets.delete(@ets_table, cache_key)
          :miss
        end

      [] ->
        :miss
    end
  end

  defp cache_result(type, indicator, data) do
    cache_key = {type, indicator}
    :ets.insert(@ets_table, {cache_key, data, System.monotonic_time(:millisecond)})
  end

  # ============================================================================
  # Private Functions - Helpers
  # ============================================================================

  defp indicator_type_to_string(:ipv4), do: "IPv4"
  defp indicator_type_to_string(:ipv6), do: "IPv6"
  defp indicator_type_to_string(:domain), do: "domain"
  defp indicator_type_to_string(:hostname), do: "hostname"
  defp indicator_type_to_string(:url), do: "url"
  defp indicator_type_to_string(:file), do: "file"
  defp indicator_type_to_string(:cve), do: "cve"
  defp indicator_type_to_string(:nids), do: "nids"
  defp indicator_type_to_string(:mutex), do: "mutex"
  defp indicator_type_to_string(:email), do: "email"

  defp update_stats(state, type) do
    case type do
      :lookup -> update_in(state.stats.lookups, &(&1 + 1))
      :cache_hit -> update_in(state.stats.cache_hits, &(&1 + 1))
      :api_call -> update_in(state.stats.api_calls, &(&1 + 1))
      :error -> update_in(state.stats.errors, &(&1 + 1))
    end
  end

  defp parse_timestamp(nil), do: nil
  defp parse_timestamp(""), do: nil
  defp parse_timestamp(%DateTime{} = dt), do: dt
  defp parse_timestamp(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ ->
        case NaiveDateTime.from_iso8601(str) do
          {:ok, ndt} -> DateTime.from_naive!(ndt, "Etc/UTC")
          _ -> nil
        end
    end
  end
  defp parse_timestamp(_), do: nil
end
