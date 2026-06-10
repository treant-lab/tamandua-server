defmodule TamanduaServer.ThreatIntel.Feeds.CrowdStrikeIntel do
  @moduledoc """
  CrowdStrike Falcon Intelligence Feed Integration.

  CrowdStrike provides premium threat intelligence including:
  - Adversary intelligence (BEAR, SPIDER, KITTEN groups, etc.)
  - Malware analysis and attribution
  - Custom IOC feeds from Falcon X sandbox
  - Vulnerability intelligence with adversary exploitation data
  - Intelligence reports and bulletins

  ## Configuration

      config :tamandua_server, TamanduaServer.ThreatIntel.Feeds.CrowdStrikeIntel,
        client_id: "YOUR_CLIENT_ID",
        client_secret: "YOUR_CLIENT_SECRET",
        cloud: "us-1",  # or "us-2", "eu-1", "us-gov-1"
        enabled: true

  ## API Access

  Requires CrowdStrike Falcon subscription with Falcon Intelligence add-on.
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  # Regional cloud URLs
  @cloud_urls %{
    "us-1" => "https://api.crowdstrike.com",
    "us-2" => "https://api.us-2.crowdstrike.com",
    "eu-1" => "https://api.eu-1.crowdstrike.com",
    "us-gov-1" => "https://api.laggar.gcw.crowdstrike.com"
  }

  @default_sync_interval :timer.hours(4)
  @http_timeout 60_000
  @token_refresh_buffer 300

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Lookup an indicator for enrichment.
  """
  @spec lookup(atom(), String.t()) :: {:ok, map()} | {:error, term()}
  def lookup(indicator_type, value) do
    GenServer.call(__MODULE__, {:lookup, indicator_type, value}, @http_timeout)
  end

  @doc """
  Get adversary (threat actor) intelligence.
  """
  @spec get_adversary(String.t()) :: {:ok, map()} | {:error, term()}
  def get_adversary(adversary_id) do
    GenServer.call(__MODULE__, {:get_adversary, adversary_id}, @http_timeout)
  end

  @doc """
  List adversaries with optional filters.
  """
  @spec list_adversaries(keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_adversaries(opts \\ []) do
    GenServer.call(__MODULE__, {:list_adversaries, opts}, @http_timeout)
  end

  @doc """
  Search adversaries by criteria.
  """
  @spec search_adversaries(map()) :: {:ok, [map()]} | {:error, term()}
  def search_adversaries(criteria) do
    GenServer.call(__MODULE__, {:search_adversaries, criteria}, @http_timeout)
  end

  @doc """
  Get malware family intelligence.
  """
  @spec get_malware(String.t()) :: {:ok, map()} | {:error, term()}
  def get_malware(malware_id) do
    GenServer.call(__MODULE__, {:get_malware, malware_id}, @http_timeout)
  end

  @doc """
  Get intelligence report by ID.
  """
  @spec get_report(String.t()) :: {:ok, map()} | {:error, term()}
  def get_report(report_id) do
    GenServer.call(__MODULE__, {:get_report, report_id}, @http_timeout)
  end

  @doc """
  List recent intelligence reports.
  """
  @spec list_reports(keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_reports(opts \\ []) do
    GenServer.call(__MODULE__, {:list_reports, opts}, @http_timeout)
  end

  @doc """
  Download custom IOCs.
  """
  @spec download_iocs(keyword()) :: {:ok, integer()} | {:error, term()}
  def download_iocs(opts \\ []) do
    GenServer.call(__MODULE__, {:download_iocs, opts}, @http_timeout * 5)
  end

  @doc """
  Submit file hash for sandbox analysis.
  """
  @spec submit_for_analysis(String.t()) :: {:ok, map()} | {:error, term()}
  def submit_for_analysis(sha256) do
    GenServer.call(__MODULE__, {:submit_for_analysis, sha256}, @http_timeout)
  end

  @doc """
  Get sandbox analysis report.
  """
  @spec get_analysis_report(String.t()) :: {:ok, map()} | {:error, term()}
  def get_analysis_report(analysis_id) do
    GenServer.call(__MODULE__, {:get_analysis_report, analysis_id}, @http_timeout)
  end

  @doc """
  Trigger manual sync.
  """
  @spec sync_all() :: :ok
  def sync_all do
    GenServer.cast(__MODULE__, :sync_all)
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
    cloud = Keyword.get(opts, :cloud) || System.get_env("CROWDSTRIKE_CLOUD") || "us-1"
    base_url = Map.get(@cloud_urls, cloud, @cloud_urls["us-1"])

    state = %{
      client_id: Keyword.get(opts, :client_id) || System.get_env("CROWDSTRIKE_CLIENT_ID"),
      client_secret: Keyword.get(opts, :client_secret) || System.get_env("CROWDSTRIKE_CLIENT_SECRET"),
      cloud: cloud,
      base_url: base_url,
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      access_token: nil,
      token_expires_at: nil,
      last_sync: nil,
      stats: %{
        lookups: 0,
        iocs_imported: 0,
        adversaries_fetched: 0,
        reports_fetched: 0,
        errors: 0
      }
    }

    if state.enabled && state.client_id && state.client_secret do
      send(self(), :authenticate)
      Logger.info("[CrowdStrike] Initialized for cloud #{cloud}")
    else
      Logger.info("[CrowdStrike] Disabled - no credentials configured")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:lookup, indicator_type, value}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_lookup(indicator_type, value, state)
      new_stats = Map.update!(state.stats, :lookups, &(&1 + 1))
      {:reply, result, %{state | stats: new_stats}}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_adversary, adversary_id}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_get_adversary(adversary_id, state)
      new_stats = Map.update!(state.stats, :adversaries_fetched, &(&1 + 1))
      {:reply, result, %{state | stats: new_stats}}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:list_adversaries, opts}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_list_adversaries(opts, state)
      {:reply, result, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:search_adversaries, criteria}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_search_adversaries(criteria, state)
      {:reply, result, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_malware, malware_id}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_get_malware(malware_id, state)
      {:reply, result, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_report, report_id}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_get_report(report_id, state)
      new_stats = Map.update!(state.stats, :reports_fetched, &(&1 + 1))
      {:reply, result, %{state | stats: new_stats}}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:list_reports, opts}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_list_reports(opts, state)
      {:reply, result, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:download_iocs, opts}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_download_iocs(opts, state)
      {:reply, result, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:submit_for_analysis, sha256}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_submit_for_analysis(sha256, state)
      {:reply, result, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_analysis_report, analysis_id}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_get_analysis_report(analysis_id, state)
      {:reply, result, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      configured: state.client_id != nil and state.client_secret != nil,
      authenticated: state.access_token != nil,
      cloud: state.cloud,
      last_sync: state.last_sync,
      stats: state.stats
    }
    {:reply, status, state}
  end

  @impl true
  def handle_cast(:sync_all, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      Task.start(fn -> do_sync_all(state) end)
      {:noreply, %{state | last_sync: DateTime.utc_now()}}
    else
      {:error, _} -> {:noreply, state}
    end
  end

  @impl true
  def handle_info(:authenticate, state) do
    case do_authenticate(state) do
      {:ok, new_state} ->
        Process.send_after(self(), :initial_sync, :timer.seconds(30))
        schedule_sync(new_state.sync_interval)
        schedule_token_refresh(new_state)
        {:noreply, new_state}

      {:error, reason} ->
        Logger.error("[CrowdStrike] Authentication failed: #{inspect(reason)}")
        Process.send_after(self(), :authenticate, :timer.minutes(5))
        {:noreply, state}
    end
  end

  @impl true
  def handle_info(:initial_sync, state) do
    if state.access_token do
      Logger.info("[CrowdStrike] Starting initial sync...")
      Task.start(fn -> do_sync_all(state) end)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    if state.access_token do
      Logger.info("[CrowdStrike] Starting periodic sync...")
      Task.start(fn -> do_sync_all(state) end)
      schedule_sync(state.sync_interval)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:refresh_token, state) do
    case do_authenticate(state) do
      {:ok, new_state} ->
        schedule_token_refresh(new_state)
        {:noreply, new_state}

      {:error, _} ->
        Process.send_after(self(), :refresh_token, :timer.minutes(1))
        {:noreply, state}
    end
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - Authentication
  # ============================================================================

  defp do_authenticate(state) do
    unless state.client_id and state.client_secret do
      {:error, :not_configured}
    else
      url = "#{state.base_url}/oauth2/token"

      headers = [
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Accept", "application/json"}
      ]

      body = URI.encode_query(%{
        "client_id" => state.client_id,
        "client_secret" => state.client_secret
      })

      case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 201, body: resp_body}} ->
          case Jason.decode(resp_body) do
            {:ok, %{"access_token" => token, "expires_in" => expires_in}} ->
              expires_at = DateTime.add(DateTime.utc_now(), expires_in, :second)
              Logger.info("[CrowdStrike] Authenticated successfully")
              {:ok, %{state | access_token: token, token_expires_at: expires_at}}

            {:error, reason} ->
              {:error, {:parse_error, reason}}
          end

        {:ok, %Finch.Response{status: code, body: body}} ->
          Logger.error("[CrowdStrike] Auth failed with HTTP #{code}: #{body}")
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp ensure_authenticated(state) do
    cond do
      state.access_token == nil ->
        do_authenticate(state)

      DateTime.compare(state.token_expires_at, DateTime.add(DateTime.utc_now(), @token_refresh_buffer, :second)) == :lt ->
        do_authenticate(state)

      true ->
        {:ok, state}
    end
  end

  # ============================================================================
  # Private Functions - API Calls
  # ============================================================================

  defp do_lookup(indicator_type, value, state) do
    ioc_type = indicator_type_to_cs_type(indicator_type)
    url = "#{state.base_url}/intel/combined/indicators/v1"

    headers = api_headers(state.access_token)

    params = URI.encode_query(%{
      "filter" => "type:'#{ioc_type}'+value:'#{value}'",
      "limit" => 1
    })

    case Finch.build(:get, "#{url}?#{params}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_indicator_response(body, indicator_type)

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_get_adversary(adversary_id, state) do
    url = "#{state.base_url}/intel/entities/actors/v1"

    headers = api_headers(state.access_token)
    params = URI.encode_query(%{"ids" => adversary_id})

    case Finch.build(:get, "#{url}?#{params}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_adversary_response(body)

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_list_adversaries(opts, state) do
    url = "#{state.base_url}/intel/combined/actors/v1"

    headers = api_headers(state.access_token)

    params = %{
      "limit" => Keyword.get(opts, :limit, 50),
      "sort" => "name|asc"
    }

    params = if opts[:filter] do
      Map.put(params, "filter", opts[:filter])
    else
      params
    end

    case Finch.build(:get, "#{url}?#{URI.encode_query(params)}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_adversaries_list(body)

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_search_adversaries(criteria, state) do
    filter = build_adversary_filter(criteria)
    do_list_adversaries([filter: filter, limit: Map.get(criteria, :limit, 50)], state)
  end

  defp do_get_malware(malware_id, state) do
    url = "#{state.base_url}/intel/entities/malware/v1"

    headers = api_headers(state.access_token)
    params = URI.encode_query(%{"ids" => malware_id})

    case Finch.build(:get, "#{url}?#{params}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_malware_response(body)

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_get_report(report_id, state) do
    url = "#{state.base_url}/intel/entities/reports/v1"

    headers = api_headers(state.access_token)
    params = URI.encode_query(%{"ids" => report_id})

    case Finch.build(:get, "#{url}?#{params}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_report_response(body)

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_list_reports(opts, state) do
    url = "#{state.base_url}/intel/combined/reports/v1"

    headers = api_headers(state.access_token)

    params = %{
      "limit" => Keyword.get(opts, :limit, 20),
      "sort" => "created_date|desc"
    }

    params = if opts[:filter] do
      Map.put(params, "filter", opts[:filter])
    else
      params
    end

    case Finch.build(:get, "#{url}?#{URI.encode_query(params)}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_reports_list(body)

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_download_iocs(opts, state) do
    Logger.info("[CrowdStrike] Downloading custom IOCs...")

    url = "#{state.base_url}/intel/combined/indicators/v1"

    headers = api_headers(state.access_token)

    # Build filter for recent high-confidence IOCs
    since = Keyword.get(opts, :since, DateTime.add(DateTime.utc_now(), -7, :day))
    since_timestamp = DateTime.to_unix(since)

    filter = "published_date:>#{since_timestamp}"

    params = %{
      "limit" => Keyword.get(opts, :limit, 5000),
      "filter" => filter,
      "sort" => "published_date|desc"
    }

    case Finch.build(:get, "#{url}?#{URI.encode_query(params)}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout * 3) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"resources" => indicators}} ->
            iocs = Enum.map(indicators, &parse_indicator_to_ioc/1)
            |> Enum.reject(&is_nil/1)

            # Submit to aggregator
            Aggregator.ingest_batch("crowdstrike", iocs)

            Logger.info("[CrowdStrike] Imported #{length(iocs)} IOCs")
            {:ok, length(iocs)}

          _ ->
            {:ok, 0}
        end

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_submit_for_analysis(sha256, state) do
    url = "#{state.base_url}/falconx/entities/submissions/v1"

    headers = api_headers(state.access_token) ++ [{"Content-Type", "application/json"}]

    body = Jason.encode!(%{
      "sandbox" => [%{
        "sha256" => sha256,
        "environment_id" => 160,  # Windows 10 64-bit
        "enable_tor" => false
      }]
    })

    case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: resp_body}} ->
        case Jason.decode(resp_body) do
          {:ok, %{"resources" => [%{"id" => analysis_id} | _]}} ->
            {:ok, %{analysis_id: analysis_id, status: "submitted"}}

          _ ->
            {:error, :parse_error}
        end

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_get_analysis_report(analysis_id, state) do
    url = "#{state.base_url}/falconx/entities/reports/v1"

    headers = api_headers(state.access_token)
    params = URI.encode_query(%{"ids" => analysis_id})

    case Finch.build(:get, "#{url}?#{params}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_analysis_report(body)

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_sync_all(state) do
    Logger.info("[CrowdStrike] Syncing all intelligence...")

    # Download IOCs from last 7 days
    do_download_iocs([since: DateTime.add(DateTime.utc_now(), -7, :day)], state)

    Logger.info("[CrowdStrike] Sync complete")
  end

  # ============================================================================
  # Private Functions - Parsing
  # ============================================================================

  defp parse_indicator_response(body, indicator_type) do
    case Jason.decode(body) do
      {:ok, %{"resources" => [indicator | _]}} ->
        {:ok, %{
          found: true,
          type: indicator_type,
          value: indicator["indicator"],
          malicious_confidence: indicator["malicious_confidence"],
          kill_chains: indicator["kill_chains"] || [],
          actors: indicator["actors"] || [],
          malware_families: indicator["malware_families"] || [],
          labels: indicator["labels"] || [],
          published_date: indicator["published_date"],
          last_updated: indicator["last_updated"],
          reports: indicator["reports"] || [],
          metadata: %{
            provider: "crowdstrike",
            id: indicator["id"]
          }
        }}

      {:ok, %{"resources" => []}} ->
        {:ok, %{found: false}}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_adversary_response(body) do
    case Jason.decode(body) do
      {:ok, %{"resources" => [adversary | _]}} ->
        {:ok, %{
          id: adversary["id"],
          name: adversary["name"],
          description: adversary["description"],
          short_description: adversary["short_description"],
          known_as: adversary["known_as"] || [],
          actor_type: adversary["actor_type"],
          motivation: extract_motivations(adversary),
          capability: adversary["capability"],
          origins: adversary["origins"] || [],
          target_countries: adversary["target_countries"] || [],
          target_industries: adversary["target_industries"] || [],
          target_regions: adversary["target_regions"] || [],
          kill_chain: adversary["kill_chain"] || [],
          first_activity_date: adversary["first_activity_date"],
          last_activity_date: adversary["last_activity_date"],
          active: adversary["active"],
          url: adversary["url"],
          rich_text_description: adversary["rich_text_description"],
          metadata: %{
            provider: "crowdstrike",
            ecrime_kill_chain: adversary["ecrime_kill_chain"],
            slug: adversary["slug"]
          }
        }}

      {:ok, %{"resources" => []}} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_adversaries_list(body) do
    case Jason.decode(body) do
      {:ok, %{"resources" => adversaries}} ->
        parsed = Enum.map(adversaries, fn a ->
          %{
            id: a["id"],
            name: a["name"],
            known_as: a["known_as"] || [],
            actor_type: a["actor_type"],
            motivation: extract_motivations(a),
            target_industries: a["target_industries"] || [],
            active: a["active"],
            last_activity_date: a["last_activity_date"]
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_malware_response(body) do
    case Jason.decode(body) do
      {:ok, %{"resources" => [malware | _]}} ->
        {:ok, %{
          id: malware["id"],
          name: malware["name"],
          aliases: malware["aliases"] || [],
          description: malware["description"],
          short_description: malware["short_description"],
          capabilities: malware["capabilities"] || [],
          actors: malware["actors"] || [],
          target_industries: malware["target_industries"] || [],
          target_countries: malware["target_countries"] || [],
          first_activity_date: malware["first_activity_date"],
          last_activity_date: malware["last_activity_date"],
          kill_chain: malware["kill_chain"] || [],
          url: malware["url"],
          metadata: %{
            provider: "crowdstrike",
            slug: malware["slug"]
          }
        }}

      {:ok, %{"resources" => []}} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_report_response(body) do
    case Jason.decode(body) do
      {:ok, %{"resources" => [report | _]}} ->
        {:ok, %{
          id: report["id"],
          name: report["name"],
          description: report["description"],
          short_description: report["short_description"],
          report_type: report["type"],
          created_date: report["created_date"],
          last_modified_date: report["last_modified_date"],
          target_industries: report["target_industries"] || [],
          target_countries: report["target_countries"] || [],
          actors: report["actors"] || [],
          malware: report["malware"] || [],
          url: report["url"],
          tags: report["tags"] || [],
          motivation: report["motivations"] || [],
          metadata: %{
            provider: "crowdstrike",
            slug: report["slug"]
          }
        }}

      {:ok, %{"resources" => []}} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_reports_list(body) do
    case Jason.decode(body) do
      {:ok, %{"resources" => reports}} ->
        parsed = Enum.map(reports, fn r ->
          %{
            id: r["id"],
            name: r["name"],
            report_type: r["type"],
            created_date: r["created_date"],
            target_industries: r["target_industries"] || [],
            actors: r["actors"] || []
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_analysis_report(body) do
    case Jason.decode(body) do
      {:ok, %{"resources" => [report | _]}} ->
        sandbox = report["sandbox"] || [%{}] |> List.first()

        {:ok, %{
          analysis_id: report["id"],
          sha256: sandbox["sha256"],
          verdict: sandbox["verdict"],
          threat_score: sandbox["threat_score"],
          classification: sandbox["classification"] || [],
          processes: sandbox["processes"] || [],
          network_connections: sandbox["network_connections"] || [],
          dns_requests: sandbox["dns_requests"] || [],
          http_requests: sandbox["http_requests"] || [],
          extracted_files: sandbox["extracted_files"] || [],
          extracted_interesting_strings: sandbox["extracted_interesting_strings"] || [],
          mitre_attacks: sandbox["mitre_attacks"] || [],
          signatures: sandbox["signatures"] || [],
          environment_description: sandbox["environment_description"],
          submit_time: report["submit_time"],
          metadata: %{
            provider: "crowdstrike",
            environment_id: sandbox["environment_id"]
          }
        }}

      {:ok, %{"resources" => []}} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_indicator_to_ioc(indicator) do
    ioc_type = cs_type_to_db_type(indicator["type"])

    if ioc_type do
      confidence = case indicator["malicious_confidence"] do
        "high" -> 0.9
        "medium" -> 0.7
        "low" -> 0.5
        _ -> 0.6
      end

      %{
        type: ioc_type,
        value: String.downcase(indicator["indicator"] || ""),
        source: "crowdstrike",
        severity: severity_from_confidence(indicator["malicious_confidence"]),
        confidence: confidence,
        tags: ["crowdstrike"] ++ (indicator["labels"] || []),
        metadata: %{
          "kill_chains" => indicator["kill_chains"],
          "actors" => indicator["actors"],
          "malware_families" => indicator["malware_families"],
          "published_date" => indicator["published_date"],
          "provider" => "crowdstrike"
        }
      }
    else
      nil
    end
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp api_headers(token) do
    [
      {"Authorization", "Bearer #{token}"},
      {"Accept", "application/json"}
    ]
  end

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end

  defp schedule_token_refresh(%{token_expires_at: expires_at}) do
    refresh_at = DateTime.add(expires_at, -@token_refresh_buffer, :second)
    delay = max(DateTime.diff(refresh_at, DateTime.utc_now(), :millisecond), 0)
    Process.send_after(self(), :refresh_token, delay)
  end

  defp indicator_type_to_cs_type(:ip), do: "ip_address"
  defp indicator_type_to_cs_type(:domain), do: "domain"
  defp indicator_type_to_cs_type(:hash), do: "hash_sha256"
  defp indicator_type_to_cs_type(:hash_md5), do: "hash_md5"
  defp indicator_type_to_cs_type(:hash_sha1), do: "hash_sha1"
  defp indicator_type_to_cs_type(:hash_sha256), do: "hash_sha256"
  defp indicator_type_to_cs_type(:url), do: "url"
  defp indicator_type_to_cs_type(_), do: "ip_address"

  defp cs_type_to_db_type("ip_address"), do: "ip"
  defp cs_type_to_db_type("ip_address_block"), do: "ip"
  defp cs_type_to_db_type("domain"), do: "domain"
  defp cs_type_to_db_type("url"), do: "url"
  defp cs_type_to_db_type("hash_sha256"), do: "hash_sha256"
  defp cs_type_to_db_type("hash_sha1"), do: "hash_sha1"
  defp cs_type_to_db_type("hash_md5"), do: "hash_md5"
  defp cs_type_to_db_type("email_address"), do: "email"
  defp cs_type_to_db_type("file_name"), do: "filename"
  defp cs_type_to_db_type(_), do: nil

  defp severity_from_confidence("high"), do: "critical"
  defp severity_from_confidence("medium"), do: "high"
  defp severity_from_confidence("low"), do: "medium"
  defp severity_from_confidence(_), do: "medium"

  defp extract_motivations(adversary) do
    motivations = adversary["motivations"] || []
    case motivations do
      [m | _] -> m["value"] || "unknown"
      _ -> adversary["actor_type"] || "unknown"
    end
  end

  defp build_adversary_filter(criteria) do
    filters = []

    filters = if criteria[:actor_type] do
      ["actor_type:'#{criteria[:actor_type]}'" | filters]
    else
      filters
    end

    filters = if criteria[:motivation] do
      ["motivations.value:'#{criteria[:motivation]}'" | filters]
    else
      filters
    end

    filters = if criteria[:target_industry] do
      ["target_industries:'#{criteria[:target_industry]}'" | filters]
    else
      filters
    end

    filters = if criteria[:active] != nil do
      ["active:#{criteria[:active]}" | filters]
    else
      filters
    end

    Enum.join(filters, "+")
  end
end
