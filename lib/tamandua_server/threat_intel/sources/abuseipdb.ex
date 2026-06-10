defmodule TamanduaServer.ThreatIntel.Sources.AbuseIPDB do
  @moduledoc """
  AbuseIPDB API integration for IP reputation and abuse reports.

  AbuseIPDB is a project dedicated to helping combat the spread of hackers,
  spammers, and abusive activity on the internet. It provides IP reputation
  data based on abuse reports from users.

  ## API Limits (Free Tier)
  - 1,000 requests per day
  - Rate limited to avoid abuse

  ## Usage

      # Configure API key
      AbuseIPDB.configure("your-api-key")

      # Check an IP address
      AbuseIPDB.check_ip("192.168.1.1")

      # Report an abusive IP
      AbuseIPDB.report_ip("1.2.3.4",
        categories: [18, 22],  # Brute force, Web attack
        comment: "SSH brute force attempt detected"
      )

      # Get IP address reports
      AbuseIPDB.get_reports("1.2.3.4", max_age_days: 90)

  ## Configuration

  Set the `ABUSEIPDB_API_KEY` environment variable or configure via:

      config :tamandua_server, :threat_intel,
        abuseipdb_api_key: "your-api-key"
  """

  use GenServer
  require Logger

  @api_base "https://api.abuseipdb.com/api/v2"
  @http_timeout 30_000
  @recv_timeout 30_000

  # Rate limiting: conservative for free tier
  @rate_limit_requests 100
  @rate_limit_window :timer.hours(1)

  # Cache TTL: 12 hours for IP checks
  @cache_ttl :timer.hours(12)

  @ets_table :abuseipdb_cache

  # AbuseIPDB category codes
  @categories %{
    3 => "Fraud Orders",
    4 => "DDoS Attack",
    5 => "FTP Brute-Force",
    6 => "Ping of Death",
    7 => "Phishing",
    8 => "Fraud VoIP",
    9 => "Open Proxy",
    10 => "Web Spam",
    11 => "Email Spam",
    12 => "Blog Spam",
    13 => "VPN IP",
    14 => "Port Scan",
    15 => "Hacking",
    16 => "SQL Injection",
    17 => "Spoofing",
    18 => "Brute-Force",
    19 => "Bad Web Bot",
    20 => "Exploited Host",
    21 => "Web App Attack",
    22 => "SSH",
    23 => "IoT Targeted"
  }

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the AbuseIPDB integration GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Configure the AbuseIPDB API key.

  ## Examples

      iex> configure("your-api-key")
      :ok
  """
  @spec configure(String.t()) :: :ok
  def configure(api_key) when is_binary(api_key) do
    GenServer.call(__MODULE__, {:configure, api_key})
  end

  @doc """
  Check an IP address for abuse reports.

  Returns abuse confidence score (0-100) and recent reports.

  ## Options
    - `:max_age_days` - Maximum age of reports to consider (default: 90, max: 365)
    - `:verbose` - Include detailed report list (default: false)

  ## Examples

      iex> check_ip("192.168.1.1")
      {:ok, %{
        ip_address: "192.168.1.1",
        is_public: true,
        ip_version: 4,
        is_whitelisted: false,
        abuse_confidence_score: 85,
        country_code: "CN",
        usage_type: "Data Center/Web Hosting/Transit",
        isp: "China Telecom",
        domain: "chinatelecom.cn",
        hostnames: [],
        total_reports: 1234,
        num_distinct_users: 89,
        last_reported_at: ~U[2024-01-20 15:30:00Z],
        categories: [18, 22],  # Brute-force, SSH
        is_tor: false,
        reports: []  # Only if verbose: true
      }}

      iex> check_ip("127.0.0.1")
      {:ok, %{is_public: false, abuse_confidence_score: 0}}
  """
  @spec check_ip(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def check_ip(ip, opts \\ []) when is_binary(ip) do
    GenServer.call(__MODULE__, {:check_ip, ip, opts}, 60_000)
  end

  @doc """
  Report an IP address for abusive behavior.

  ## Parameters
    - `ip` - IP address to report
    - `opts` - Options:
      - `:categories` - List of category IDs (required)
      - `:comment` - Description of the abuse (optional but recommended)
      - `:timestamp` - When the abuse occurred (optional, default: now)

  ## Category IDs
  Use `get_categories/0` to see all available categories. Common ones:
    - 18: Brute-Force
    - 22: SSH
    - 21: Web App Attack
    - 15: Hacking
    - 14: Port Scan

  ## Examples

      iex> report_ip("1.2.3.4",
      ...>   categories: [18, 22],
      ...>   comment: "SSH brute force attempt detected on port 22"
      ...> )
      {:ok, %{
        ip_address: "1.2.3.4",
        abuse_confidence_score: 90
      }}
  """
  @spec report_ip(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def report_ip(ip, opts) when is_binary(ip) do
    GenServer.call(__MODULE__, {:report_ip, ip, opts}, 60_000)
  end

  @doc """
  Get detailed reports for an IP address.

  ## Options
    - `:max_age_days` - Maximum age of reports (default: 90, max: 365)
    - `:page` - Page number for pagination (default: 1)
    - `:per_page` - Results per page (default: 25, max: 100)

  ## Examples

      iex> get_reports("1.2.3.4", max_age_days: 90)
      {:ok, [
        %{
          reported_at: ~U[2024-01-20 15:30:00Z],
          comment: "SSH brute force",
          categories: [18, 22],
          reporter_id: 12345,
          reporter_country_code: "US"
        },
        ...
      ]}
  """
  @spec get_reports(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_reports(ip, opts \\ []) when is_binary(ip) do
    GenServer.call(__MODULE__, {:get_reports, ip, opts}, 60_000)
  end

  @doc """
  Get the list of blacklisted IP addresses.

  ## Options
    - `:confidence_minimum` - Minimum abuse confidence score (0-100, default: 90)
    - `:limit` - Maximum number of results (default: 100, max: 10000)

  ## Examples

      iex> get_blacklist(confidence_minimum: 95, limit: 1000)
      {:ok, [
        %{
          ip_address: "1.2.3.4",
          abuse_confidence_score: 100,
          last_reported_at: ~U[2024-01-20 15:30:00Z]
        },
        ...
      ]}
  """
  @spec get_blacklist(keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_blacklist(opts \\ []) do
    GenServer.call(__MODULE__, {:get_blacklist, opts}, 60_000)
  end

  @doc """
  Bulk report multiple IPs at once.

  ## Parameters
    - `reports` - List of report maps, each containing:
      - `:ip` - IP address (required)
      - `:categories` - List of category IDs (required)
      - `:comment` - Description (optional)
      - `:timestamp` - When abuse occurred (optional)

  ## Examples

      iex> bulk_report([
      ...>   %{ip: "1.2.3.4", categories: [18], comment: "SSH brute force"},
      ...>   %{ip: "5.6.7.8", categories: [21], comment: "SQL injection attempt"}
      ...> ])
      {:ok, %{saved: 2, errors: []}}
  """
  @spec bulk_report([map()]) :: {:ok, map()} | {:error, term()}
  def bulk_report(reports) when is_list(reports) do
    GenServer.call(__MODULE__, {:bulk_report, reports}, 120_000)
  end

  @doc """
  Get available abuse categories.

  Returns a map of category ID to description.
  """
  @spec get_categories() :: map()
  def get_categories, do: @categories

  @doc """
  Get current service status including rate limit info.

  ## Examples

      iex> get_status()
      %{
        configured: true,
        rate_limit: %{remaining: 95, reset_in_ms: 3540000},
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
              Application.get_env(:tamandua_server, :threat_intel)[:abuseipdb_api_key] ||
              System.get_env("ABUSEIPDB_API_KEY")

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
        rate_limited: 0,
        reports_submitted: 0
      }
    }

    Logger.info("[AbuseIPDB] Initialized, API key #{if api_key, do: "configured", else: "not configured"}")

    {:ok, state}
  end

  @impl true
  def handle_call({:configure, api_key}, _from, state) do
    Logger.info("[AbuseIPDB] API key configured")
    {:reply, :ok, %{state | api_key: api_key}}
  end

  @impl true
  def handle_call({:check_ip, ip, opts}, _from, state) do
    state = update_stats(state, :lookup)

    case get_cached(:check, ip) do
      {:ok, cached} ->
        state = update_stats(state, :cache_hit)
        {:reply, {:ok, cached}, state}

      :miss ->
        {result, state} = do_check_ip(ip, opts, state)
        {:reply, result, state}
    end
  end

  @impl true
  def handle_call({:report_ip, ip, opts}, _from, state) do
    {result, state} = do_report_ip(ip, opts, state)

    state = if match?({:ok, _}, result) do
      update_stats(state, :reports_submitted)
    else
      state
    end

    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_reports, ip, opts}, _from, state) do
    {result, state} = do_get_reports(ip, opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_blacklist, opts}, _from, state) do
    {result, state} = do_get_blacklist(opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:bulk_report, reports}, _from, state) do
    {result, state} = do_bulk_report(reports, state)

    state = if match?({:ok, _}, result) do
      update_stats(state, :reports_submitted, length(reports))
    else
      state
    end

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
        limit_per_hour: @rate_limit_requests
      },
      cache_size: :ets.info(@ets_table, :size),
      stats: state.stats
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call(:clear_cache, _from, state) do
    :ets.delete_all_objects(@ets_table)
    Logger.info("[AbuseIPDB] Cache cleared")
    {:reply, :ok, state}
  end

  # ============================================================================
  # Private Functions - API Calls
  # ============================================================================

  defp do_check_ip(ip, opts, state) do
    case check_rate_limit(state) do
      {:ok, state} ->
        if state.api_key do
          max_age_days = Keyword.get(opts, :max_age_days, 90) |> min(365)
          verbose = Keyword.get(opts, :verbose, false)

          url = "#{@api_base}/check"
          query = URI.encode_query([
            ipAddress: ip,
            maxAgeInDays: max_age_days,
            verbose: verbose
          ])

          full_url = "#{url}?#{query}"
          headers = [
            {"Key", state.api_key},
            {"Accept", "application/json"}
          ]

          case execute_get_request(full_url, headers, state) do
            {:ok, data, state} ->
              result = parse_check_response(data)
              cache_result(:check, ip, result)
              {{:ok, result}, state}

            {:error, reason, state} ->
              {{:error, reason}, state}
          end
        else
          {{:error, :no_api_key}, state}
        end

      {:rate_limited, state} ->
        {{:error, :rate_limited}, update_stats(state, :rate_limited)}
    end
  end

  defp do_report_ip(ip, opts, state) do
    case check_rate_limit(state) do
      {:ok, state} ->
        if state.api_key do
          categories = Keyword.fetch!(opts, :categories)
          comment = Keyword.get(opts, :comment, "")
          timestamp = Keyword.get(opts, :timestamp)

          unless is_list(categories) and length(categories) > 0 do
            {{:error, :categories_required}, state}
          else
            url = "#{@api_base}/report"

            body_params = [
              {"ip", ip},
              {"categories", Enum.join(categories, ",")},
              {"comment", comment}
            ]

            body_params = if timestamp do
              [{"timestamp", DateTime.to_iso8601(timestamp)} | body_params]
            else
              body_params
            end

            body = URI.encode_query(body_params)
            headers = [
              {"Key", state.api_key},
              {"Accept", "application/json"},
              {"Content-Type", "application/x-www-form-urlencoded"}
            ]

            case execute_post_request(url, body, headers, state) do
              {:ok, data, state} ->
                result = parse_report_response(data)
                # Invalidate cache for this IP
                :ets.delete(@ets_table, {:check, ip})
                {{:ok, result}, state}

              {:error, reason, state} ->
                {{:error, reason}, state}
            end
          end
        else
          {{:error, :no_api_key}, state}
        end

      {:rate_limited, state} ->
        {{:error, :rate_limited}, update_stats(state, :rate_limited)}
    end
  end

  defp do_get_reports(ip, opts, state) do
    case check_rate_limit(state) do
      {:ok, state} ->
        if state.api_key do
          max_age_days = Keyword.get(opts, :max_age_days, 90) |> min(365)
          page = Keyword.get(opts, :page, 1)
          per_page = Keyword.get(opts, :per_page, 25) |> min(100)

          url = "#{@api_base}/reports"
          query = URI.encode_query([
            ipAddress: ip,
            maxAgeInDays: max_age_days,
            page: page,
            perPage: per_page
          ])

          full_url = "#{url}?#{query}"
          headers = [
            {"Key", state.api_key},
            {"Accept", "application/json"}
          ]

          case execute_get_request(full_url, headers, state) do
            {:ok, data, state} ->
              reports = parse_reports_response(data)
              {{:ok, reports}, state}

            {:error, reason, state} ->
              {{:error, reason}, state}
          end
        else
          {{:error, :no_api_key}, state}
        end

      {:rate_limited, state} ->
        {{:error, :rate_limited}, update_stats(state, :rate_limited)}
    end
  end

  defp do_get_blacklist(opts, state) do
    case check_rate_limit(state) do
      {:ok, state} ->
        if state.api_key do
          confidence_minimum = Keyword.get(opts, :confidence_minimum, 90)
          limit = Keyword.get(opts, :limit, 100) |> min(10000)

          url = "#{@api_base}/blacklist"
          query = URI.encode_query([
            confidenceMinimum: confidence_minimum,
            limit: limit
          ])

          full_url = "#{url}?#{query}"
          headers = [
            {"Key", state.api_key},
            {"Accept", "application/json"}
          ]

          case execute_get_request(full_url, headers, state) do
            {:ok, data, state} ->
              blacklist = parse_blacklist_response(data)
              {{:ok, blacklist}, state}

            {:error, reason, state} ->
              {{:error, reason}, state}
          end
        else
          {{:error, :no_api_key}, state}
        end

      {:rate_limited, state} ->
        {{:error, :rate_limited}, update_stats(state, :rate_limited)}
    end
  end

  defp do_bulk_report(reports, state) do
    # Report each IP sequentially (AbuseIPDB doesn't have a bulk endpoint)
    results = Enum.map(reports, fn report ->
      ip = Map.fetch!(report, :ip)
      opts = [
        categories: Map.fetch!(report, :categories),
        comment: Map.get(report, :comment, ""),
        timestamp: Map.get(report, :timestamp)
      ]

      case do_report_ip(ip, opts, state) do
        {{:ok, _}, new_state} ->
          state = new_state
          {:ok, ip}

        {{:error, reason}, new_state} ->
          state = new_state
          {:error, {ip, reason}}
      end
    end)

    saved = Enum.count(results, &match?({:ok, _}, &1))
    errors = Enum.filter(results, &match?({:error, _}, &1))

    {{:ok, %{saved: saved, errors: errors}}, state}
  end

  defp execute_get_request(url, headers, state) do
    state = update_stats(state, :api_call)

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"data" => data}} -> {:ok, data, state}
          {:ok, data} -> {:ok, data, state}
          {:error, _} -> {:error, :json_parse_error, update_stats(state, :error)}
        end

      {:ok, %Finch.Response{status: 429}} ->
        Logger.warning("[AbuseIPDB] Rate limit exceeded")
        {:error, :rate_limited, update_stats(state, :rate_limited)}

      {:ok, %Finch.Response{status: 401}} ->
        Logger.warning("[AbuseIPDB] Invalid API key")
        {:error, :invalid_api_key, update_stats(state, :error)}

      {:ok, %Finch.Response{status: 422, body: body}} ->
        Logger.warning("[AbuseIPDB] Unprocessable entity: #{body}")
        {:error, :invalid_request, update_stats(state, :error)}

      {:ok, %Finch.Response{status: status}} ->
        Logger.warning("[AbuseIPDB] HTTP #{status}")
        {:error, {:http_error, status}, update_stats(state, :error)}

      {:error, reason} ->
        Logger.error("[AbuseIPDB] HTTP error: #{inspect(reason)}")
        {:error, reason, update_stats(state, :error)}
    end
  end

  defp execute_post_request(url, body, headers, state) do
    state = update_stats(state, :api_call)

    case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        case Jason.decode(response_body) do
          {:ok, %{"data" => data}} -> {:ok, data, state}
          {:ok, data} -> {:ok, data, state}
          {:error, _} -> {:error, :json_parse_error, update_stats(state, :error)}
        end

      {:ok, %Finch.Response{status: 429}} ->
        {:error, :rate_limited, update_stats(state, :rate_limited)}

      {:ok, %Finch.Response{status: status, body: error_body}} ->
        Logger.warning("[AbuseIPDB] HTTP #{status}: #{error_body}")
        {:error, {:http_error, status}, update_stats(state, :error)}

      {:error, reason} ->
        {:error, reason, update_stats(state, :error)}
    end
  end

  # ============================================================================
  # Private Functions - Response Parsers
  # ============================================================================

  defp parse_check_response(data) do
    %{
      ip_address: Map.get(data, "ipAddress"),
      is_public: Map.get(data, "isPublic", false),
      ip_version: Map.get(data, "ipVersion", 4),
      is_whitelisted: Map.get(data, "isWhitelisted", false),
      abuse_confidence_score: Map.get(data, "abuseConfidenceScore", 0),
      country_code: Map.get(data, "countryCode"),
      country_name: Map.get(data, "countryName"),
      usage_type: Map.get(data, "usageType"),
      isp: Map.get(data, "isp"),
      domain: Map.get(data, "domain"),
      hostnames: Map.get(data, "hostnames", []),
      total_reports: Map.get(data, "totalReports", 0),
      num_distinct_users: Map.get(data, "numDistinctUsers", 0),
      last_reported_at: parse_timestamp(Map.get(data, "lastReportedAt")),
      is_tor: Map.get(data, "isTor", false),
      reports: parse_reports_list(Map.get(data, "reports", [])),
      source: "abuseipdb"
    }
  end

  defp parse_report_response(data) do
    %{
      ip_address: Map.get(data, "ipAddress"),
      abuse_confidence_score: Map.get(data, "abuseConfidenceScore", 0)
    }
  end

  defp parse_reports_response(data) do
    results = Map.get(data, "results", [])
    parse_reports_list(results)
  end

  defp parse_reports_list(reports) when is_list(reports) do
    Enum.map(reports, &parse_report/1)
  end
  defp parse_reports_list(_), do: []

  defp parse_report(report) do
    %{
      reported_at: parse_timestamp(Map.get(report, "reportedAt")),
      comment: Map.get(report, "comment"),
      categories: Map.get(report, "categories", []),
      reporter_id: Map.get(report, "reporterId"),
      reporter_country_code: Map.get(report, "reporterCountryCode"),
      reporter_country_name: Map.get(report, "reporterCountryName")
    }
  end

  defp parse_blacklist_response(data) do
    data
    |> Map.get("data", [])
    |> Enum.map(fn entry ->
      %{
        ip_address: Map.get(entry, "ipAddress"),
        abuse_confidence_score: Map.get(entry, "abuseConfidenceScore"),
        last_reported_at: parse_timestamp(Map.get(entry, "lastReportedAt")),
        country_code: Map.get(entry, "countryCode"),
        usage_type: Map.get(entry, "usageType"),
        is_tor: Map.get(entry, "isTor", false)
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

  defp update_stats(state, type, increment \\ 1) do
    %{state | stats: Map.update!(state.stats, type, &(&1 + increment))}
  end

  defp parse_timestamp(nil), do: nil
  defp parse_timestamp(""), do: nil
  defp parse_timestamp(%DateTime{} = dt), do: dt
  defp parse_timestamp(str) when is_binary(str) do
    case DateTime.from_iso8601(str) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end
  defp parse_timestamp(_), do: nil
end
