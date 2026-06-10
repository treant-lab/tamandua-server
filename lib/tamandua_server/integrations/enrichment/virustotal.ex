defmodule TamanduaServer.Integrations.Enrichment.VirusTotal do
  @moduledoc """
  VirusTotal Integration for Threat Intelligence Enrichment

  Provides enrichment capabilities using VirusTotal API v3:
  - File hash lookup (MD5, SHA1, SHA256)
  - URL analysis
  - Domain reputation
  - IP address analysis
  - File submission for scanning
  - MITRE ATT&CK mappings

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.Enrichment.VirusTotal,
        api_key: "your-api-key",
        premium: false,  # Set to true for premium API features
        rate_limit: 4,   # Requests per minute (free tier)
        cache_ttl_seconds: 3600

  """

  use GenServer
  require Logger

  @base_url "https://www.virustotal.com/api/v3"
  @default_timeout_ms 30_000
  @default_cache_ttl 3600  # 1 hour

  defstruct [
    :config,
    :api_key,
    :cache,
    :rate_limiter,
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Lookup a file hash (MD5, SHA1, or SHA256).
  """
  @spec lookup_hash(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_hash(hash) do
    GenServer.call(__MODULE__, {:lookup_hash, hash}, 30_000)
  end

  @doc """
  Analyze a URL.
  """
  @spec analyze_url(String.t()) :: {:ok, map()} | {:error, term()}
  def analyze_url(url) do
    GenServer.call(__MODULE__, {:analyze_url, url}, 60_000)
  end

  @doc """
  Get domain information.
  """
  @spec lookup_domain(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_domain(domain) do
    GenServer.call(__MODULE__, {:lookup_domain, domain}, 30_000)
  end

  @doc """
  Get IP address information.
  """
  @spec lookup_ip(String.t()) :: {:ok, map()} | {:error, term()}
  def lookup_ip(ip) do
    GenServer.call(__MODULE__, {:lookup_ip, ip}, 30_000)
  end

  @doc """
  Submit a file for scanning.
  """
  @spec submit_file(binary(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def submit_file(file_content, filename) do
    GenServer.call(__MODULE__, {:submit_file, file_content, filename}, 120_000)
  end

  @doc """
  Get scan results for a submitted file.
  """
  @spec get_analysis(String.t()) :: {:ok, map()} | {:error, term()}
  def get_analysis(analysis_id) do
    GenServer.call(__MODULE__, {:get_analysis, analysis_id}, 30_000)
  end

  @doc """
  Enrich multiple IOCs in batch.
  """
  @spec enrich_batch([map()]) :: {:ok, [map()]} | {:error, term()}
  def enrich_batch(iocs) do
    GenServer.call(__MODULE__, {:enrich_batch, iocs}, 120_000)
  end

  @doc """
  Test the connection.
  """
  @spec test_connection() :: {:ok, String.t()} | {:error, term()}
  def test_connection do
    GenServer.call(__MODULE__, :test_connection, 30_000)
  end

  @doc """
  Get enrichment statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting VirusTotal Enrichment Integration")

    config = load_config(opts)

    state = %__MODULE__{
      config: config,
      api_key: config.api_key,
      cache: %{},
      rate_limiter: init_rate_limiter(config),
      stats: %{
        hash_lookups: 0,
        url_analyses: 0,
        domain_lookups: 0,
        ip_lookups: 0,
        file_submissions: 0,
        cache_hits: 0,
        api_calls: 0,
        errors: 0,
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:lookup_hash, hash}, _from, state) do
    normalized_hash = String.downcase(hash)

    case check_cache(state, {:hash, normalized_hash}) do
      {:hit, result} ->
        new_stats = update_stat(state.stats, :cache_hits)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      :miss ->
        case wait_for_rate_limit(state) do
          {:ok, new_state} ->
            case get_request(new_state, "/files/#{normalized_hash}") do
              {:ok, response} ->
                result = format_hash_result(response)
                final_state = cache_result(new_state, {:hash, normalized_hash}, result)
                new_stats = update_stat(final_state.stats, :hash_lookups)
                {:reply, {:ok, result}, %{final_state | stats: new_stats}}

              {:error, :not_found} ->
                {:reply, {:ok, %{found: false, hash: normalized_hash}}, new_state}

              error ->
                {:reply, error, update_error_stat(new_state)}
            end

          {:error, :rate_limited} ->
            {:reply, {:error, :rate_limited}, state}
        end
    end
  end

  @impl true
  def handle_call({:analyze_url, url}, _from, state) do
    url_id = Base.url_encode64(url, padding: false)

    case check_cache(state, {:url, url_id}) do
      {:hit, result} ->
        new_stats = update_stat(state.stats, :cache_hits)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      :miss ->
        case wait_for_rate_limit(state) do
          {:ok, new_state} ->
            # First check if URL was already analyzed
            case get_request(new_state, "/urls/#{url_id}") do
              {:ok, response} ->
                result = format_url_result(response)
                final_state = cache_result(new_state, {:url, url_id}, result)
                new_stats = update_stat(final_state.stats, :url_analyses)
                {:reply, {:ok, result}, %{final_state | stats: new_stats}}

              {:error, :not_found} ->
                # Submit URL for analysis
                case submit_url(new_state, url) do
                  {:ok, analysis_id} ->
                    # Poll for results
                    result = poll_analysis(new_state, analysis_id)
                    {:reply, result, new_state}

                  error ->
                    {:reply, error, new_state}
                end

              error ->
                {:reply, error, update_error_stat(new_state)}
            end

          {:error, :rate_limited} ->
            {:reply, {:error, :rate_limited}, state}
        end
    end
  end

  @impl true
  def handle_call({:lookup_domain, domain}, _from, state) do
    case check_cache(state, {:domain, domain}) do
      {:hit, result} ->
        new_stats = update_stat(state.stats, :cache_hits)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      :miss ->
        case wait_for_rate_limit(state) do
          {:ok, new_state} ->
            case get_request(new_state, "/domains/#{domain}") do
              {:ok, response} ->
                result = format_domain_result(response)
                final_state = cache_result(new_state, {:domain, domain}, result)
                new_stats = update_stat(final_state.stats, :domain_lookups)
                {:reply, {:ok, result}, %{final_state | stats: new_stats}}

              {:error, :not_found} ->
                {:reply, {:ok, %{found: false, domain: domain}}, new_state}

              error ->
                {:reply, error, update_error_stat(new_state)}
            end

          {:error, :rate_limited} ->
            {:reply, {:error, :rate_limited}, state}
        end
    end
  end

  @impl true
  def handle_call({:lookup_ip, ip}, _from, state) do
    case check_cache(state, {:ip, ip}) do
      {:hit, result} ->
        new_stats = update_stat(state.stats, :cache_hits)
        {:reply, {:ok, result}, %{state | stats: new_stats}}

      :miss ->
        case wait_for_rate_limit(state) do
          {:ok, new_state} ->
            case get_request(new_state, "/ip_addresses/#{ip}") do
              {:ok, response} ->
                result = format_ip_result(response)
                final_state = cache_result(new_state, {:ip, ip}, result)
                new_stats = update_stat(final_state.stats, :ip_lookups)
                {:reply, {:ok, result}, %{final_state | stats: new_stats}}

              {:error, :not_found} ->
                {:reply, {:ok, %{found: false, ip: ip}}, new_state}

              error ->
                {:reply, error, update_error_stat(new_state)}
            end

          {:error, :rate_limited} ->
            {:reply, {:error, :rate_limited}, state}
        end
    end
  end

  @impl true
  def handle_call({:submit_file, file_content, filename}, _from, state) do
    case wait_for_rate_limit(state) do
      {:ok, new_state} ->
        case upload_file(new_state, file_content, filename) do
          {:ok, response} ->
            analysis_id = get_in(response, ["data", "id"])
            new_stats = update_stat(new_state.stats, :file_submissions)
            {:reply, {:ok, analysis_id}, %{new_state | stats: new_stats}}

          error ->
            {:reply, error, update_error_stat(new_state)}
        end

      {:error, :rate_limited} ->
        {:reply, {:error, :rate_limited}, state}
    end
  end

  @impl true
  def handle_call({:get_analysis, analysis_id}, _from, state) do
    case wait_for_rate_limit(state) do
      {:ok, new_state} ->
        case get_request(new_state, "/analyses/#{analysis_id}") do
          {:ok, response} ->
            result = format_analysis_result(response)
            {:reply, {:ok, result}, new_state}

          error ->
            {:reply, error, new_state}
        end

      {:error, :rate_limited} ->
        {:reply, {:error, :rate_limited}, state}
    end
  end

  @impl true
  def handle_call({:enrich_batch, iocs}, _from, state) do
    results = Enum.map(iocs, fn ioc ->
      type = ioc[:type] || ioc["type"]
      value = ioc[:value] || ioc["value"]

      result = case type do
        t when t in ["hash", "sha256", "sha1", "md5", :hash, :sha256, :sha1, :md5] ->
          case lookup_hash_internal(state, value) do
            {:ok, data} -> Map.put(data, :ioc, ioc)
            _ -> %{found: false, ioc: ioc}
          end

        t when t in ["domain", :domain] ->
          case lookup_domain_internal(state, value) do
            {:ok, data} -> Map.put(data, :ioc, ioc)
            _ -> %{found: false, ioc: ioc}
          end

        t when t in ["ip", :ip] ->
          case lookup_ip_internal(state, value) do
            {:ok, data} -> Map.put(data, :ioc, ioc)
            _ -> %{found: false, ioc: ioc}
          end

        t when t in ["url", :url] ->
          case lookup_url_internal(state, value) do
            {:ok, data} -> Map.put(data, :ioc, ioc)
            _ -> %{found: false, ioc: ioc}
          end

        _ ->
          %{found: false, ioc: ioc, error: "Unsupported IOC type"}
      end

      # Small delay between requests for rate limiting
      Process.sleep(250)
      result
    end)

    {:reply, {:ok, results}, state}
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request(state, "/users/current") do
      {:ok, _} ->
        {:reply, {:ok, "Connected to VirusTotal"}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_config(opts) do
    app_config = Application.get_env(:tamandua_server, __MODULE__, [])

    %{
      api_key: opts[:api_key] || app_config[:api_key],
      premium: opts[:premium] || app_config[:premium] || false,
      rate_limit: opts[:rate_limit] || app_config[:rate_limit] || 4,
      cache_ttl: opts[:cache_ttl_seconds] || app_config[:cache_ttl_seconds] || @default_cache_ttl,
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms
    }
  end

  defp init_rate_limiter(config) do
    %{
      requests_per_minute: config.rate_limit,
      window_start: DateTime.utc_now(),
      request_count: 0
    }
  end

  defp wait_for_rate_limit(state) do
    now = DateTime.utc_now()
    window_age = DateTime.diff(now, state.rate_limiter.window_start, :second)

    cond do
      # Reset window if more than 60 seconds have passed
      window_age >= 60 ->
        new_limiter = %{state.rate_limiter | window_start: now, request_count: 1}
        {:ok, %{state | rate_limiter: new_limiter}}

      # Within rate limit
      state.rate_limiter.request_count < state.rate_limiter.requests_per_minute ->
        new_limiter = %{state.rate_limiter | request_count: state.rate_limiter.request_count + 1}
        {:ok, %{state | rate_limiter: new_limiter}}

      # Rate limited - wait for window to reset
      true ->
        wait_time = (60 - window_age) * 1000
        if wait_time > 0 and wait_time < 60_000 do
          Process.sleep(wait_time)
          new_limiter = %{state.rate_limiter | window_start: DateTime.utc_now(), request_count: 1}
          {:ok, %{state | rate_limiter: new_limiter}}
        else
          {:error, :rate_limited}
        end
    end
  end

  defp check_cache(state, key) do
    case Map.get(state.cache, key) do
      nil ->
        :miss

      {result, timestamp} ->
        age = DateTime.diff(DateTime.utc_now(), timestamp, :second)
        if age < state.config.cache_ttl do
          {:hit, result}
        else
          :miss
        end
    end
  end

  defp cache_result(state, key, result) do
    new_cache = Map.put(state.cache, key, {result, DateTime.utc_now()})
    %{state | cache: new_cache}
  end

  defp format_hash_result(response) do
    data = response["data"] || response
    attributes = data["attributes"] || %{}
    stats = attributes["last_analysis_stats"] || %{}

    %{
      found: true,
      hash: data["id"],
      sha256: attributes["sha256"],
      sha1: attributes["sha1"],
      md5: attributes["md5"],
      type_description: attributes["type_description"],
      file_type: attributes["type_tag"],
      size: attributes["size"],
      names: attributes["names"] || [],
      first_submission: attributes["first_submission_date"],
      last_analysis_date: attributes["last_analysis_date"],
      reputation: attributes["reputation"],
      stats: %{
        malicious: stats["malicious"] || 0,
        suspicious: stats["suspicious"] || 0,
        harmless: stats["harmless"] || 0,
        undetected: stats["undetected"] || 0
      },
      detection_ratio: "#{stats["malicious"] || 0}/#{(stats["malicious"] || 0) + (stats["undetected"] || 0)}",
      verdict: determine_verdict(stats),
      tags: attributes["tags"] || [],
      popular_threat_classification: attributes["popular_threat_classification"],
      sandbox_verdicts: attributes["sandbox_verdicts"],
      sigma_analysis_stats: attributes["sigma_analysis_stats"],
      crowdsourced_yara_results: attributes["crowdsourced_yara_results"]
    }
  end

  defp format_url_result(response) do
    data = response["data"] || response
    attributes = data["attributes"] || %{}
    stats = attributes["last_analysis_stats"] || %{}

    %{
      found: true,
      url: attributes["url"],
      final_url: attributes["last_final_url"],
      first_submission: attributes["first_submission_date"],
      last_analysis_date: attributes["last_analysis_date"],
      reputation: attributes["reputation"],
      stats: %{
        malicious: stats["malicious"] || 0,
        suspicious: stats["suspicious"] || 0,
        harmless: stats["harmless"] || 0,
        undetected: stats["undetected"] || 0
      },
      verdict: determine_verdict(stats),
      categories: attributes["categories"] || %{},
      tags: attributes["tags"] || [],
      title: attributes["title"],
      trackers: attributes["trackers"]
    }
  end

  defp format_domain_result(response) do
    data = response["data"] || response
    attributes = data["attributes"] || %{}
    stats = attributes["last_analysis_stats"] || %{}

    %{
      found: true,
      domain: data["id"],
      registrar: attributes["registrar"],
      creation_date: attributes["creation_date"],
      last_modification_date: attributes["last_modification_date"],
      last_analysis_date: attributes["last_analysis_date"],
      reputation: attributes["reputation"],
      stats: %{
        malicious: stats["malicious"] || 0,
        suspicious: stats["suspicious"] || 0,
        harmless: stats["harmless"] || 0,
        undetected: stats["undetected"] || 0
      },
      verdict: determine_verdict(stats),
      categories: attributes["categories"] || %{},
      tags: attributes["tags"] || [],
      whois: attributes["whois"],
      dns_records: attributes["last_dns_records"]
    }
  end

  defp format_ip_result(response) do
    data = response["data"] || response
    attributes = data["attributes"] || %{}
    stats = attributes["last_analysis_stats"] || %{}

    %{
      found: true,
      ip: data["id"],
      asn: attributes["asn"],
      as_owner: attributes["as_owner"],
      country: attributes["country"],
      continent: attributes["continent"],
      network: attributes["network"],
      last_analysis_date: attributes["last_analysis_date"],
      reputation: attributes["reputation"],
      stats: %{
        malicious: stats["malicious"] || 0,
        suspicious: stats["suspicious"] || 0,
        harmless: stats["harmless"] || 0,
        undetected: stats["undetected"] || 0
      },
      verdict: determine_verdict(stats),
      tags: attributes["tags"] || [],
      whois: attributes["whois"]
    }
  end

  defp format_analysis_result(response) do
    data = response["data"] || response
    attributes = data["attributes"] || %{}
    stats = attributes["stats"] || %{}

    %{
      id: data["id"],
      status: attributes["status"],
      stats: stats,
      results: attributes["results"],
      date: attributes["date"]
    }
  end

  defp determine_verdict(stats) do
    malicious = stats["malicious"] || 0
    suspicious = stats["suspicious"] || 0

    cond do
      malicious >= 5 -> :malicious
      malicious >= 1 -> :suspicious
      suspicious >= 3 -> :suspicious
      true -> :clean
    end
  end

  defp submit_url(state, url) do
    body = URI.encode_query(%{url: url})

    headers = [
      {"x-apikey", state.api_key},
      {"Content-Type", "application/x-www-form-urlencoded"}
    ]

    options = [
      timeout: state.config.timeout_ms,
      recv_timeout: state.config.timeout_ms
    ]

    case Finch.build(:post, "#{@base_url}/urls", headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: 200, body: resp_body}} ->
        response = Jason.decode!(resp_body)
        {:ok, get_in(response, ["data", "id"])}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  end

  defp upload_file(state, file_content, filename) do
    # For files > 32MB, get upload URL first
    if byte_size(file_content) > 32 * 1024 * 1024 do
      upload_large_file(state, file_content, filename)
    else
      upload_small_file(state, file_content, filename)
    end
  end

  defp upload_small_file(state, file_content, filename) do
    boundary = "----VTBoundary#{:crypto.strong_rand_bytes(8) |> Base.encode16()}"

    body = """
    --#{boundary}\r
    Content-Disposition: form-data; name="file"; filename="#{filename}"\r
    Content-Type: application/octet-stream\r
    \r
    #{file_content}\r
    --#{boundary}--\r
    """

    headers = [
      {"x-apikey", state.api_key},
      {"Content-Type", "multipart/form-data; boundary=#{boundary}"}
    ]

    options = [
      timeout: 120_000,
      recv_timeout: 120_000
    ]

    case Finch.build(:post, "#{@base_url}/files", headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: 200, body: resp_body}} ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        {:error, reason}
    end
  end

  defp upload_large_file(state, file_content, filename) do
    # Get upload URL for large files
    case get_request(state, "/files/upload_url") do
      {:ok, response} ->
        upload_url = response["data"]

        # Upload to the provided URL
        boundary = "----VTBoundary#{:crypto.strong_rand_bytes(8) |> Base.encode16()}"

        body = """
        --#{boundary}\r
        Content-Disposition: form-data; name="file"; filename="#{filename}"\r
        Content-Type: application/octet-stream\r
        \r
        #{file_content}\r
        --#{boundary}--\r
        """

        headers = [
          {"x-apikey", state.api_key},
          {"Content-Type", "multipart/form-data; boundary=#{boundary}"}
        ]

        options = [timeout: 300_000, recv_timeout: 300_000]

        case Finch.build(:post, upload_url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
          {:ok, %{status_code: 200, body: resp_body}} ->
            {:ok, Jason.decode!(resp_body)}

          {:ok, %{status_code: code, body: resp_body}} ->
            {:error, "HTTP #{code}: #{resp_body}"}

          {:error, %{reason: reason}} ->
            {:error, reason}
        end

      error ->
        error
    end
  end

  defp poll_analysis(state, analysis_id, attempts \\ 0) do
    if attempts >= 30 do
      {:error, :analysis_timeout}
    else
      case get_request(state, "/analyses/#{analysis_id}") do
        {:ok, response} ->
          status = get_in(response, ["data", "attributes", "status"])

          if status == "completed" do
            {:ok, format_analysis_result(response)}
          else
            Process.sleep(10_000)  # Wait 10 seconds
            poll_analysis(state, analysis_id, attempts + 1)
          end

        error ->
          error
      end
    end
  end

  # Internal lookup functions for batch processing
  defp lookup_hash_internal(state, hash) do
    case get_request(state, "/files/#{String.downcase(hash)}") do
      {:ok, response} -> {:ok, format_hash_result(response)}
      error -> error
    end
  end

  defp lookup_domain_internal(state, domain) do
    case get_request(state, "/domains/#{domain}") do
      {:ok, response} -> {:ok, format_domain_result(response)}
      error -> error
    end
  end

  defp lookup_ip_internal(state, ip) do
    case get_request(state, "/ip_addresses/#{ip}") do
      {:ok, response} -> {:ok, format_ip_result(response)}
      error -> error
    end
  end

  defp lookup_url_internal(state, url) do
    url_id = Base.url_encode64(url, padding: false)
    case get_request(state, "/urls/#{url_id}") do
      {:ok, response} -> {:ok, format_url_result(response)}
      error -> error
    end
  end

  defp get_request(state, endpoint) do
    url = "#{@base_url}#{endpoint}"

    headers = [
      {"x-apikey", state.api_key},
      {"Accept", "application/json"}
    ]

    options = [
      timeout: state.config.timeout_ms,
      recv_timeout: state.config.timeout_ms
    ]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: 200, body: resp_body}} ->
        {:ok, Jason.decode!(resp_body)}

      {:ok, %{status_code: 404}} ->
        {:error, :not_found}

      {:ok, %{status_code: 429}} ->
        {:error, :rate_limited}

      {:ok, %{status_code: code, body: resp_body}} ->
        Logger.error("VirusTotal API error: HTTP #{code} - #{resp_body}")
        {:error, "HTTP #{code}: #{resp_body}"}

      {:error, %{reason: reason}} ->
        Logger.error("VirusTotal connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("VirusTotal exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp update_stat(stats, key) do
    stats
    |> Map.update(key, 1, &(&1 + 1))
    |> Map.update(:api_calls, 1, &(&1 + 1))
    |> Map.put(:last_activity, DateTime.utc_now())
  end

  defp update_error_stat(state) do
    new_stats = Map.update(state.stats, :errors, 1, &(&1 + 1))
    %{state | stats: new_stats}
  end
end
