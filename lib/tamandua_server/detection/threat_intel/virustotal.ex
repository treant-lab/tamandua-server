defmodule TamanduaServer.Detection.ThreatIntel.VirusTotal do
  @moduledoc """
  VirusTotal API v3 integration for threat intelligence lookups.

  Provides hash, IP, domain, and URL reputation lookups using the VirusTotal API.
  Implements rate limiting and caching to comply with API limits.

  ## API Limits (Free Tier)
  - 4 requests per minute
  - 500 requests per day

  ## Usage

      # Configure API key (usually via environment variable)
      VirusTotal.configure("your-api-key")

      # Lookup a file hash
      VirusTotal.lookup_hash("abc123...")

      # Lookup an IP address
      VirusTotal.lookup_ip("192.168.1.1")

      # Submit a file for analysis
      VirusTotal.submit_file("/path/to/file.exe")

  ## Configuration

  Set the `VT_API_KEY` environment variable or configure via:

      config :tamandua_server, :threat_intel,
        virustotal_api_key: "your-api-key"
  """

  use GenServer
  require Logger

  @api_base "https://www.virustotal.com/api/v3"
  @http_timeout 30_000
  @recv_timeout 30_000

  # Rate limiting: 4 requests per minute for free tier
  @rate_limit_requests 4
  @rate_limit_window :timer.minutes(1)

  # Cache TTL: 24 hours
  @cache_ttl :timer.hours(24)

  @ets_table :virustotal_cache

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the VirusTotal integration GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Configure the VirusTotal API key.

  ## Examples

      iex> configure("your-api-key")
      :ok
  """
  @spec configure(String.t()) :: :ok
  def configure(api_key) when is_binary(api_key) do
    GenServer.call(__MODULE__, {:configure, api_key})
  end

  @doc """
  Lookup a file hash (MD5, SHA1, or SHA256) in VirusTotal.

  Returns detection statistics and threat classification.

  ## Examples

      iex> lookup_hash("abc123def456...")
      {:ok, %{
        sha256: "abc123...",
        detection_stats: %{malicious: 45, suspicious: 3, harmless: 10, undetected: 12},
        popular_threat_classification: %{
          suggested_threat_label: "trojan.emotet/generic",
          popular_threat_category: [%{value: "trojan", count: 42}],
          popular_threat_name: [%{value: "emotet", count: 38}]
        },
        signature_info: %{verified: false, signer: nil},
        first_submission_date: ~U[2024-01-15 10:00:00Z],
        last_analysis_date: ~U[2024-01-20 15:30:00Z],
        names: ["malware.exe", "payload.bin"],
        tags: ["emotet", "trojan", "banking"],
        type_description: "Win32 EXE"
      }}

      iex> lookup_hash("notfound123...")
      {:ok, %{found: false}}
  """
  @spec lookup_hash(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_hash(hash) when is_binary(hash) do
    normalized = String.downcase(hash)
    GenServer.call(__MODULE__, {:lookup_hash, normalized}, 60_000)
  end

  @doc """
  Lookup an IP address in VirusTotal.

  Returns reputation data, ASN info, and detected URLs/files.

  ## Examples

      iex> lookup_ip("192.168.1.1")
      {:ok, %{
        ip: "192.168.1.1",
        detection_stats: %{malicious: 5, suspicious: 2, harmless: 50, undetected: 3},
        asn: 12345,
        as_owner: "Example ISP",
        country: "US",
        continent: "NA",
        network: "192.168.0.0/16",
        whois: "...",
        last_analysis_date: ~U[2024-01-20 15:30:00Z]
      }}
  """
  @spec lookup_ip(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_ip(ip) when is_binary(ip) do
    GenServer.call(__MODULE__, {:lookup_ip, ip}, 60_000)
  end

  @doc """
  Lookup a domain in VirusTotal.

  Returns reputation data, registrar info, and associated detections.

  ## Examples

      iex> lookup_domain("evil.com")
      {:ok, %{
        domain: "evil.com",
        detection_stats: %{malicious: 15, suspicious: 5, harmless: 30, undetected: 10},
        registrar: "Example Registrar",
        creation_date: ~U[2020-01-01 00:00:00Z],
        categories: %{"Fortinet" => "malware", "Sophos" => "malicious"},
        popularity_ranks: %{"Alexa" => 1000000},
        last_analysis_date: ~U[2024-01-20 15:30:00Z]
      }}
  """
  @spec lookup_domain(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_domain(domain) when is_binary(domain) do
    normalized = String.downcase(domain)
    GenServer.call(__MODULE__, {:lookup_domain, normalized}, 60_000)
  end

  @doc """
  Lookup a URL in VirusTotal.

  The URL is base64-encoded for the API request.

  ## Examples

      iex> lookup_url("http://evil.com/malware.exe")
      {:ok, %{
        url: "http://evil.com/malware.exe",
        detection_stats: %{malicious: 20, suspicious: 5, harmless: 25, undetected: 10},
        categories: %{"Fortinet" => "malware"},
        final_url: "http://evil.com/malware.exe",
        title: "Malware Download",
        last_analysis_date: ~U[2024-01-20 15:30:00Z]
      }}
  """
  @spec lookup_url(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_url(url) when is_binary(url) do
    GenServer.call(__MODULE__, {:lookup_url, url}, 60_000)
  end

  @doc """
  Submit a file to VirusTotal for analysis.

  Returns submission ID for tracking the analysis.

  ## Examples

      iex> submit_file("/path/to/suspicious.exe")
      {:ok, %{
        analysis_id: "abc123...",
        sha256: "def456...",
        permalink: "https://www.virustotal.com/gui/file/..."
      }}
  """
  @spec submit_file(String.t()) :: {:ok, map()} | {:error, term()}
  def submit_file(path) when is_binary(path) do
    GenServer.call(__MODULE__, {:submit_file, path}, 120_000)
  end

  @doc """
  Get the analysis results for a submitted file.

  ## Examples

      iex> get_analysis("analysis-id-123")
      {:ok, %{status: "completed", stats: %{malicious: 45, ...}}}
  """
  @spec get_analysis(String.t()) :: {:ok, map()} | {:error, term()}
  def get_analysis(analysis_id) when is_binary(analysis_id) do
    GenServer.call(__MODULE__, {:get_analysis, analysis_id}, 60_000)
  end

  @doc """
  Get current service status including rate limit info.

  ## Examples

      iex> get_status()
      %{
        configured: true,
        rate_limit: %{remaining: 3, reset_in_ms: 45000},
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
              Application.get_env(:tamandua_server, :threat_intel)[:virustotal_api_key] ||
              System.get_env("VT_API_KEY")

    state = %{
      api_key: api_key,
      rate_limit: %{
        requests: 0,
        window_start: System.monotonic_time(:millisecond)
      },
      stats: %{
        lookups: 0,
        cache_hits: 0,
        api_calls: 0,
        errors: 0,
        rate_limited: 0
      }
    }

    Logger.info("[VirusTotal] Initialized, API key #{if api_key, do: "configured", else: "not configured"}")

    {:ok, state}
  end

  @impl true
  def handle_call({:configure, api_key}, _from, state) do
    Logger.info("[VirusTotal] API key configured")
    {:reply, :ok, %{state | api_key: api_key}}
  end

  @impl true
  def handle_call({:lookup_hash, hash}, _from, state) do
    state = update_stats(state, :lookup)

    case get_cached(:hash, hash) do
      {:ok, cached} ->
        state = update_stats(state, :cache_hit)
        {:reply, {:ok, cached}, state}

      :miss ->
        {result, state} = do_lookup_hash(hash, state)
        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:lookup_ip, ip}, _from, state) do
    state = update_stats(state, :lookup)

    case get_cached(:ip, ip) do
      {:ok, cached} ->
        state = update_stats(state, :cache_hit)
        {:reply, {:ok, cached}, state}

      :miss ->
        {result, state} = do_lookup_ip(ip, state)
        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:lookup_domain, domain}, _from, state) do
    state = update_stats(state, :lookup)

    case get_cached(:domain, domain) do
      {:ok, cached} ->
        state = update_stats(state, :cache_hit)
        {:reply, {:ok, cached}, state}

      :miss ->
        {result, state} = do_lookup_domain(domain, state)
        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:lookup_url, url}, _from, state) do
    state = update_stats(state, :lookup)

    # URL cache key is the URL itself
    case get_cached(:url, url) do
      {:ok, cached} ->
        state = update_stats(state, :cache_hit)
        {:reply, {:ok, cached}, state}

      :miss ->
        {result, state} = do_lookup_url(url, state)
        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:submit_file, path}, _from, state) do
    {result, state} = do_submit_file(path, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_analysis, analysis_id}, _from, state) do
    {result, state} = do_get_analysis(analysis_id, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    now = System.monotonic_time(:millisecond)
    elapsed = now - state.rate_limit.window_start
    reset_in = max(0, @rate_limit_window - elapsed)
    remaining = max(0, @rate_limit_requests - state.rate_limit.requests)

    status = %{
      configured: state.api_key != nil,
      rate_limit: %{
        remaining: remaining,
        reset_in_ms: reset_in,
        limit_per_minute: @rate_limit_requests
      },
      cache_size: :ets.info(@ets_table, :size),
      stats: state.stats
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call(:clear_cache, _from, state) do
    :ets.delete_all_objects(@ets_table)
    Logger.info("[VirusTotal] Cache cleared")
    {:reply, :ok, state}
  end

  # ============================================================================
  # Private Functions - API Calls
  # ============================================================================

  defp do_lookup_hash(hash, state) do
    case check_rate_limit(state) do
      {:ok, state} ->
        if state.api_key do
          url = "#{@api_base}/files/#{hash}"
          execute_get_request(url, state, :hash, hash, &parse_file_response/1)
        else
          {{:error, :no_api_key}, state}
        end

      {:rate_limited, state} ->
        {{:error, :rate_limited}, update_stats(state, :rate_limited)}
    end
  end

  defp do_lookup_ip(ip, state) do
    case check_rate_limit(state) do
      {:ok, state} ->
        if state.api_key do
          url = "#{@api_base}/ip_addresses/#{ip}"
          execute_get_request(url, state, :ip, ip, &parse_ip_response/1)
        else
          {{:error, :no_api_key}, state}
        end

      {:rate_limited, state} ->
        {{:error, :rate_limited}, update_stats(state, :rate_limited)}
    end
  end

  defp do_lookup_domain(domain, state) do
    case check_rate_limit(state) do
      {:ok, state} ->
        if state.api_key do
          url = "#{@api_base}/domains/#{domain}"
          execute_get_request(url, state, :domain, domain, &parse_domain_response/1)
        else
          {{:error, :no_api_key}, state}
        end

      {:rate_limited, state} ->
        {{:error, :rate_limited}, update_stats(state, :rate_limited)}
    end
  end

  defp do_lookup_url(url, state) do
    case check_rate_limit(state) do
      {:ok, state} ->
        if state.api_key do
          # URL needs to be base64 encoded (without padding)
          url_id = Base.url_encode64(url, padding: false)
          api_url = "#{@api_base}/urls/#{url_id}"
          execute_get_request(api_url, state, :url, url, &parse_url_response/1)
        else
          {{:error, :no_api_key}, state}
        end

      {:rate_limited, state} ->
        {{:error, :rate_limited}, update_stats(state, :rate_limited)}
    end
  end

  defp do_submit_file(path, state) do
    case check_rate_limit(state) do
      {:ok, state} ->
        if state.api_key do
          case File.read(path) do
            {:ok, content} ->
              submit_file_content(content, Path.basename(path), state)

            {:error, reason} ->
              {{:error, {:file_read_error, reason}}, state}
          end
        else
          {{:error, :no_api_key}, state}
        end

      {:rate_limited, state} ->
        {{:error, :rate_limited}, update_stats(state, :rate_limited)}
    end
  end

  defp submit_file_content(content, filename, state) do
    url = "#{@api_base}/files"

    # Build multipart form data
    boundary = "----VTBoundary#{:erlang.system_time(:millisecond)}"

    body = """
    --#{boundary}\r
    Content-Disposition: form-data; name="file"; filename="#{filename}"\r
    Content-Type: application/octet-stream\r
    \r
    #{content}\r
    --#{boundary}--\r
    """

    headers = [
      {"x-apikey", state.api_key},
      {"Content-Type", "multipart/form-data; boundary=#{boundary}"}
    ]

    state = update_stats(state, :api_call)

    case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout * 2) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, %{"data" => data}} ->
            result = %{
              analysis_id: get_in(data, ["id"]),
              type: get_in(data, ["type"]),
              links: get_in(data, ["links"])
            }
            {{:ok, result}, state}

          {:error, _} ->
            {{:error, :json_parse_error}, update_stats(state, :error)}
        end

      {:ok, %Finch.Response{status: 429}} ->
        Logger.warning("[VirusTotal] Rate limit exceeded during file submission")
        {{:error, :rate_limited}, update_stats(state, :rate_limited)}

      {:ok, %Finch.Response{status: status}} ->
        Logger.warning("[VirusTotal] HTTP #{status} during file submission")
        {{:error, {:http_error, status}}, update_stats(state, :error)}

      {:error, reason} ->
        Logger.error("[VirusTotal] HTTP error during file submission: #{inspect(reason)}")
        {{:error, reason}, update_stats(state, :error)}
    end
  end

  defp do_get_analysis(analysis_id, state) do
    case check_rate_limit(state) do
      {:ok, state} ->
        if state.api_key do
          url = "#{@api_base}/analyses/#{analysis_id}"
          headers = [{"x-apikey", state.api_key}]

          state = update_stats(state, :api_call)

          case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
            {:ok, %Finch.Response{status: 200, body: body}} ->
              case Jason.decode(body) do
                {:ok, %{"data" => data}} ->
                  attrs = Map.get(data, "attributes", %{})
                  result = %{
                    status: Map.get(attrs, "status"),
                    stats: Map.get(attrs, "stats", %{}),
                    results: Map.get(attrs, "results", %{})
                  }
                  {{:ok, result}, state}

                {:error, _} ->
                  {{:error, :json_parse_error}, update_stats(state, :error)}
              end

            {:ok, %Finch.Response{status: status}} ->
              {{:error, {:http_error, status}}, update_stats(state, :error)}

            {:error, reason} ->
              {{:error, reason}, update_stats(state, :error)}
          end
        else
          {{:error, :no_api_key}, state}
        end

      {:rate_limited, state} ->
        {{:error, :rate_limited}, update_stats(state, :rate_limited)}
    end
  end

  defp execute_get_request(url, state, cache_type, cache_key, parse_fn) do
    headers = [{"x-apikey", state.api_key}]
    state = update_stats(state, :api_call)

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"data" => data}} ->
            result = parse_fn.(data)
            cache_result(cache_type, cache_key, result)
            {{:ok, result}, state}

          {:error, _} ->
            {{:error, :json_parse_error}, update_stats(state, :error)}
        end

      {:ok, %Finch.Response{status: 404}} ->
        result = %{found: false}
        cache_result(cache_type, cache_key, result)
        {{:ok, result}, state}

      {:ok, %Finch.Response{status: 429}} ->
        Logger.warning("[VirusTotal] Rate limit exceeded")
        {{:error, :rate_limited}, update_stats(state, :rate_limited)}

      {:ok, %Finch.Response{status: status}} ->
        Logger.warning("[VirusTotal] HTTP #{status} for #{cache_type} lookup")
        {{:error, {:http_error, status}}, update_stats(state, :error)}

      {:error, reason} ->
        Logger.error("[VirusTotal] HTTP error: #{inspect(reason)}")
        {{:error, reason}, update_stats(state, :error)}
    end
  end

  # ============================================================================
  # Private Functions - Response Parsers
  # ============================================================================

  defp parse_file_response(data) do
    attrs = Map.get(data, "attributes", %{})
    stats = Map.get(attrs, "last_analysis_stats", %{})
    threat_class = Map.get(attrs, "popular_threat_classification", %{})

    %{
      found: true,
      sha256: Map.get(attrs, "sha256"),
      sha1: Map.get(attrs, "sha1"),
      md5: Map.get(attrs, "md5"),
      detection_stats: %{
        malicious: Map.get(stats, "malicious", 0),
        suspicious: Map.get(stats, "suspicious", 0),
        harmless: Map.get(stats, "harmless", 0),
        undetected: Map.get(stats, "undetected", 0)
      },
      popular_threat_classification: %{
        suggested_threat_label: Map.get(threat_class, "suggested_threat_label"),
        popular_threat_category: Map.get(threat_class, "popular_threat_category", [])
          |> Enum.map(&%{value: &1["value"], count: &1["count"]}),
        popular_threat_name: Map.get(threat_class, "popular_threat_name", [])
          |> Enum.map(&%{value: &1["value"], count: &1["count"]})
      },
      type_description: Map.get(attrs, "type_description"),
      type_tag: Map.get(attrs, "type_tag"),
      meaningful_name: Map.get(attrs, "meaningful_name"),
      names: Map.get(attrs, "names", []) |> Enum.take(10),
      tags: Map.get(attrs, "tags", []),
      signature_info: parse_signature_info(attrs),
      first_submission_date: parse_unix_timestamp(Map.get(attrs, "first_submission_date")),
      last_analysis_date: parse_unix_timestamp(Map.get(attrs, "last_analysis_date")),
      times_submitted: Map.get(attrs, "times_submitted"),
      sandbox_verdicts: parse_sandbox_verdicts(attrs),
      source: "virustotal"
    }
  end

  defp parse_ip_response(data) do
    attrs = Map.get(data, "attributes", %{})
    stats = Map.get(attrs, "last_analysis_stats", %{})

    %{
      found: true,
      ip: Map.get(data, "id"),
      detection_stats: %{
        malicious: Map.get(stats, "malicious", 0),
        suspicious: Map.get(stats, "suspicious", 0),
        harmless: Map.get(stats, "harmless", 0),
        undetected: Map.get(stats, "undetected", 0)
      },
      asn: Map.get(attrs, "asn"),
      as_owner: Map.get(attrs, "as_owner"),
      country: Map.get(attrs, "country"),
      continent: Map.get(attrs, "continent"),
      network: Map.get(attrs, "network"),
      regional_internet_registry: Map.get(attrs, "regional_internet_registry"),
      whois: Map.get(attrs, "whois"),
      last_analysis_date: parse_unix_timestamp(Map.get(attrs, "last_analysis_date")),
      reputation: Map.get(attrs, "reputation"),
      tags: Map.get(attrs, "tags", []),
      source: "virustotal"
    }
  end

  defp parse_domain_response(data) do
    attrs = Map.get(data, "attributes", %{})
    stats = Map.get(attrs, "last_analysis_stats", %{})

    %{
      found: true,
      domain: Map.get(data, "id"),
      detection_stats: %{
        malicious: Map.get(stats, "malicious", 0),
        suspicious: Map.get(stats, "suspicious", 0),
        harmless: Map.get(stats, "harmless", 0),
        undetected: Map.get(stats, "undetected", 0)
      },
      registrar: Map.get(attrs, "registrar"),
      creation_date: parse_unix_timestamp(Map.get(attrs, "creation_date")),
      last_update_date: parse_unix_timestamp(Map.get(attrs, "last_update_date")),
      categories: Map.get(attrs, "categories", %{}),
      popularity_ranks: Map.get(attrs, "popularity_ranks", %{}),
      last_analysis_date: parse_unix_timestamp(Map.get(attrs, "last_analysis_date")),
      reputation: Map.get(attrs, "reputation"),
      whois: Map.get(attrs, "whois"),
      tags: Map.get(attrs, "tags", []),
      source: "virustotal"
    }
  end

  defp parse_url_response(data) do
    attrs = Map.get(data, "attributes", %{})
    stats = Map.get(attrs, "last_analysis_stats", %{})

    %{
      found: true,
      url: Map.get(attrs, "url"),
      detection_stats: %{
        malicious: Map.get(stats, "malicious", 0),
        suspicious: Map.get(stats, "suspicious", 0),
        harmless: Map.get(stats, "harmless", 0),
        undetected: Map.get(stats, "undetected", 0)
      },
      categories: Map.get(attrs, "categories", %{}),
      final_url: Map.get(attrs, "last_final_url"),
      title: Map.get(attrs, "title"),
      last_analysis_date: parse_unix_timestamp(Map.get(attrs, "last_analysis_date")),
      first_submission_date: parse_unix_timestamp(Map.get(attrs, "first_submission_date")),
      times_submitted: Map.get(attrs, "times_submitted"),
      reputation: Map.get(attrs, "reputation"),
      tags: Map.get(attrs, "tags", []),
      source: "virustotal"
    }
  end

  defp parse_signature_info(attrs) do
    sig_info = Map.get(attrs, "signature_info", %{})
    %{
      verified: sig_info["verified"] == "Signed",
      signer: Map.get(sig_info, "subject"),
      issuer: Map.get(sig_info, "issuer"),
      serial_number: Map.get(sig_info, "serial number"),
      valid_from: Map.get(sig_info, "valid from"),
      valid_to: Map.get(sig_info, "valid to")
    }
  end

  defp parse_sandbox_verdicts(attrs) do
    attrs
    |> Map.get("sandbox_verdicts", %{})
    |> Enum.take(5)
    |> Enum.map(fn {sandbox, verdict} ->
      %{
        sandbox: sandbox,
        category: Map.get(verdict, "category"),
        confidence: Map.get(verdict, "confidence"),
        malware_names: Map.get(verdict, "malware_names", [])
      }
    end)
  end

  # ============================================================================
  # Private Functions - Caching
  # ============================================================================

  defp get_cached(type, key) do
    cache_key = {type, key}

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

  defp cache_result(type, key, data) do
    cache_key = {type, key}
    :ets.insert(@ets_table, {cache_key, data, System.monotonic_time(:millisecond)})
  end

  # ============================================================================
  # Private Functions - Rate Limiting
  # ============================================================================

  defp check_rate_limit(state) do
    now = System.monotonic_time(:millisecond)
    elapsed = now - state.rate_limit.window_start

    cond do
      elapsed > @rate_limit_window ->
        # Window expired, reset
        new_rate_limit = %{requests: 1, window_start: now}
        {:ok, %{state | rate_limit: new_rate_limit}}

      state.rate_limit.requests < @rate_limit_requests ->
        # Under limit
        new_rate_limit = %{state.rate_limit | requests: state.rate_limit.requests + 1}
        {:ok, %{state | rate_limit: new_rate_limit}}

      true ->
        # Rate limited
        {:rate_limited, state}
    end
  end

  # ============================================================================
  # Private Functions - Helpers
  # ============================================================================

  defp update_stats(state, type) do
    case type do
      :lookup -> update_in(state.stats.lookups, &(&1 + 1))
      :cache_hit -> update_in(state.stats.cache_hits, &(&1 + 1))
      :api_call -> update_in(state.stats.api_calls, &(&1 + 1))
      :error -> update_in(state.stats.errors, &(&1 + 1))
      :rate_limited -> update_in(state.stats.rate_limited, &(&1 + 1))
    end
  end

  defp parse_unix_timestamp(nil), do: nil
  defp parse_unix_timestamp(timestamp) when is_integer(timestamp) do
    DateTime.from_unix!(timestamp)
  end
  defp parse_unix_timestamp(_), do: nil
end
