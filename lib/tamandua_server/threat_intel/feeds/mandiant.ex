defmodule TamanduaServer.ThreatIntel.Feeds.Mandiant do
  @moduledoc """
  Mandiant (Google) Threat Intelligence Feed Integration.

  Mandiant provides premium threat intelligence including:
  - Threat actor tracking (FIN groups, APT groups)
  - Malware families and variants
  - Campaign intelligence
  - Vulnerability intelligence with exploitation status
  - Real-time IOC feeds

  ## Configuration

      config :tamandua_server, TamanduaServer.ThreatIntel.Feeds.Mandiant,
        api_key: "YOUR_API_KEY",
        api_secret: "YOUR_API_SECRET",
        enabled: true,
        sync_interval_hours: 4

  ## API Access

  Requires Mandiant Advantage Threat Intelligence subscription.
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  @base_url "https://api.intelligence.mandiant.com"
  @token_url "https://api.intelligence.mandiant.com/token"

  @default_sync_interval :timer.hours(4)
  @http_timeout 60_000
  @token_refresh_buffer 300  # Refresh token 5 minutes before expiry

  # IOC types to sync
  @ioc_types [:ip, :domain, :fqdn, :url, :md5, :sha1, :sha256]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Lookup an indicator for enrichment data.
  """
  @spec lookup(atom(), String.t()) :: {:ok, map()} | {:error, term()}
  def lookup(indicator_type, value) do
    GenServer.call(__MODULE__, {:lookup, indicator_type, value}, @http_timeout)
  end

  @doc """
  Get threat actor intelligence by name.
  """
  @spec get_threat_actor(String.t()) :: {:ok, map()} | {:error, term()}
  def get_threat_actor(actor_name) do
    GenServer.call(__MODULE__, {:get_threat_actor, actor_name}, @http_timeout)
  end

  @doc """
  List threat actors with optional filters.
  """
  @spec list_threat_actors(keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_threat_actors(opts \\ []) do
    GenServer.call(__MODULE__, {:list_threat_actors, opts}, @http_timeout)
  end

  @doc """
  Get malware family information.
  """
  @spec get_malware(String.t()) :: {:ok, map()} | {:error, term()}
  def get_malware(malware_name) do
    GenServer.call(__MODULE__, {:get_malware, malware_name}, @http_timeout)
  end

  @doc """
  Get vulnerability intelligence.
  """
  @spec get_vulnerability(String.t()) :: {:ok, map()} | {:error, term()}
  def get_vulnerability(cve_id) do
    GenServer.call(__MODULE__, {:get_vulnerability, cve_id}, @http_timeout)
  end

  @doc """
  Get campaign information.
  """
  @spec get_campaign(String.t()) :: {:ok, map()} | {:error, term()}
  def get_campaign(campaign_id) do
    GenServer.call(__MODULE__, {:get_campaign, campaign_id}, @http_timeout)
  end

  @doc """
  Search for campaigns by criteria.
  """
  @spec search_campaigns(map()) :: {:ok, [map()]} | {:error, term()}
  def search_campaigns(criteria) do
    GenServer.call(__MODULE__, {:search_campaigns, criteria}, @http_timeout)
  end

  @doc """
  Download IOCs for a specific time range.
  """
  @spec download_iocs(DateTime.t(), DateTime.t()) :: {:ok, integer()} | {:error, term()}
  def download_iocs(start_time, end_time) do
    GenServer.call(__MODULE__, {:download_iocs, start_time, end_time}, @http_timeout * 5)
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
    state = %{
      api_key: Keyword.get(opts, :api_key) || System.get_env("MANDIANT_API_KEY"),
      api_secret: Keyword.get(opts, :api_secret) || System.get_env("MANDIANT_API_SECRET"),
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      access_token: nil,
      token_expires_at: nil,
      last_sync: nil,
      sync_status: %{},
      stats: %{
        lookups: 0,
        iocs_imported: 0,
        actors_fetched: 0,
        errors: 0
      }
    }

    if state.enabled && state.api_key && state.api_secret do
      # Authenticate on startup
      send(self(), :authenticate)
      Logger.info("[Mandiant] Initialized with credentials configured")
    else
      Logger.info("[Mandiant] Disabled - no credentials configured")
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
  def handle_call({:get_threat_actor, actor_name}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_get_threat_actor(actor_name, state)
      new_stats = Map.update!(state.stats, :actors_fetched, &(&1 + 1))
      {:reply, result, %{state | stats: new_stats}}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:list_threat_actors, opts}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_list_threat_actors(opts, state)
      {:reply, result, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_malware, malware_name}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_get_malware(malware_name, state)
      {:reply, result, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_vulnerability, cve_id}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_get_vulnerability(cve_id, state)
      {:reply, result, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:get_campaign, campaign_id}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_get_campaign(campaign_id, state)
      {:reply, result, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:search_campaigns, criteria}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_search_campaigns(criteria, state)
      {:reply, result, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:download_iocs, start_time, end_time}, _from, state) do
    with {:ok, state} <- ensure_authenticated(state) do
      result = do_download_iocs(start_time, end_time, state)
      {:reply, result, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      configured: state.api_key != nil and state.api_secret != nil,
      authenticated: state.access_token != nil,
      last_sync: state.last_sync,
      sync_status: state.sync_status,
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
        # Schedule initial sync
        Process.send_after(self(), :initial_sync, :timer.seconds(30))
        schedule_sync(new_state.sync_interval)
        {:noreply, new_state}

      {:error, reason} ->
        Logger.error("[Mandiant] Authentication failed: #{inspect(reason)}")
        # Retry authentication after delay
        Process.send_after(self(), :authenticate, :timer.minutes(5))
        {:noreply, state}
    end
  end

  @impl true
  def handle_info(:initial_sync, state) do
    if state.access_token do
      Logger.info("[Mandiant] Starting initial sync...")
      Task.start(fn -> do_sync_all(state) end)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    if state.access_token do
      Logger.info("[Mandiant] Starting periodic sync...")
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

      {:error, reason} ->
        Logger.error("[Mandiant] Token refresh failed: #{inspect(reason)}")
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
    unless state.api_key and state.api_secret do
      {:error, :not_configured}
    else
      headers = [
        {"Content-Type", "application/x-www-form-urlencoded"},
        {"Accept", "application/json"}
      ]

      # Base64 encode credentials
      credentials = Base.encode64("#{state.api_key}:#{state.api_secret}")
      auth_headers = [{"Authorization", "Basic #{credentials}"} | headers]

      body = URI.encode_query(%{
        "grant_type" => "client_credentials"
      })

      case Finch.build(:post, @token_url, auth_headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: resp_body}} ->
          case Jason.decode(resp_body) do
            {:ok, %{"access_token" => token, "expires_in" => expires_in}} ->
              expires_at = DateTime.add(DateTime.utc_now(), expires_in, :second)
              Logger.info("[Mandiant] Authenticated successfully, token expires in #{expires_in}s")
              {:ok, %{state | access_token: token, token_expires_at: expires_at}}

            {:error, reason} ->
              {:error, {:parse_error, reason}}
          end

        {:ok, %Finch.Response{status: code, body: body}} ->
          Logger.error("[Mandiant] Auth failed with HTTP #{code}: #{body}")
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
        # Token is about to expire, refresh
        do_authenticate(state)

      true ->
        {:ok, state}
    end
  end

  # ============================================================================
  # Private Functions - API Calls
  # ============================================================================

  defp do_lookup(indicator_type, value, state) do
    endpoint = indicator_type_to_endpoint(indicator_type)
    url = "#{@base_url}/v4/#{endpoint}/#{URI.encode(value)}"

    headers = [
      {"Authorization", "Bearer #{state.access_token}"},
      {"Accept", "application/json"},
      {"X-App-Name", "Tamandua-EDR"}
    ]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_indicator_response(body, indicator_type)

      {:ok, %Finch.Response{status: 404}} ->
        {:ok, %{found: false}}

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_get_threat_actor(actor_name, state) do
    # First search for the actor
    url = "#{@base_url}/v4/actor"

    headers = [
      {"Authorization", "Bearer #{state.access_token}"},
      {"Accept", "application/json"},
      {"X-App-Name", "Tamandua-EDR"}
    ]

    params = URI.encode_query(%{"text" => actor_name, "limit" => 10})

    case Finch.build(:get, "#{url}?#{params}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_threat_actor_response(body)

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_list_threat_actors(opts, state) do
    url = "#{@base_url}/v4/actor"

    headers = [
      {"Authorization", "Bearer #{state.access_token}"},
      {"Accept", "application/json"},
      {"X-App-Name", "Tamandua-EDR"}
    ]

    params = build_actor_params(opts)

    case Finch.build(:get, "#{url}?#{params}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_threat_actors_list(body)

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_get_malware(malware_name, state) do
    url = "#{@base_url}/v4/malware"

    headers = [
      {"Authorization", "Bearer #{state.access_token}"},
      {"Accept", "application/json"},
      {"X-App-Name", "Tamandua-EDR"}
    ]

    params = URI.encode_query(%{"text" => malware_name, "limit" => 10})

    case Finch.build(:get, "#{url}?#{params}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_malware_response(body)

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_get_vulnerability(cve_id, state) do
    url = "#{@base_url}/v4/vulnerability/#{URI.encode(cve_id)}"

    headers = [
      {"Authorization", "Bearer #{state.access_token}"},
      {"Accept", "application/json"},
      {"X-App-Name", "Tamandua-EDR"}
    ]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_vulnerability_response(body)

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found}

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_get_campaign(campaign_id, state) do
    url = "#{@base_url}/v4/campaign/#{URI.encode(campaign_id)}"

    headers = [
      {"Authorization", "Bearer #{state.access_token}"},
      {"Accept", "application/json"},
      {"X-App-Name", "Tamandua-EDR"}
    ]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_campaign_response(body)

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found}

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_search_campaigns(criteria, state) do
    url = "#{@base_url}/v4/campaign"

    headers = [
      {"Authorization", "Bearer #{state.access_token}"},
      {"Accept", "application/json"},
      {"X-App-Name", "Tamandua-EDR"}
    ]

    params = build_campaign_params(criteria)

    case Finch.build(:get, "#{url}?#{params}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        parse_campaigns_list(body)

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_download_iocs(start_time, end_time, state) do
    Logger.info("[Mandiant] Downloading IOCs from #{start_time} to #{end_time}")

    total_imported = Enum.reduce(@ioc_types, 0, fn ioc_type, acc ->
      case download_ioc_type(ioc_type, start_time, end_time, state) do
        {:ok, count} -> acc + count
        {:error, _} -> acc
      end
    end)

    Logger.info("[Mandiant] Imported #{total_imported} IOCs total")
    {:ok, total_imported}
  end

  defp download_ioc_type(ioc_type, start_time, end_time, state) do
    endpoint = indicator_type_to_endpoint(ioc_type)
    url = "#{@base_url}/v4/#{endpoint}"

    headers = [
      {"Authorization", "Bearer #{state.access_token}"},
      {"Accept", "application/json"},
      {"X-App-Name", "Tamandua-EDR"}
    ]

    params = URI.encode_query(%{
      "start_epoch" => DateTime.to_unix(start_time),
      "end_epoch" => DateTime.to_unix(end_time),
      "limit" => 10000
    })

    case Finch.build(:get, "#{url}?#{params}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout * 3) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"indicators" => indicators}} ->
            iocs = Enum.map(indicators, fn ind ->
              parse_indicator_to_ioc(ind, ioc_type)
            end)

            # Submit to aggregator
            Aggregator.ingest_batch("mandiant", iocs)

            Logger.info("[Mandiant] Imported #{length(iocs)} #{ioc_type} IOCs")
            {:ok, length(iocs)}

          _ ->
            {:ok, 0}
        end

      {:ok, %Finch.Response{status: code}} ->
        Logger.warning("[Mandiant] IOC download for #{ioc_type} returned #{code}")
        {:error, {:http_error, code}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_sync_all(state) do
    Logger.info("[Mandiant] Syncing all intelligence...")

    # Download IOCs from last 7 days
    end_time = DateTime.utc_now()
    start_time = DateTime.add(end_time, -7, :day)

    do_download_iocs(start_time, end_time, state)

    Logger.info("[Mandiant] Sync complete")
  end

  # ============================================================================
  # Private Functions - Parsing
  # ============================================================================

  defp parse_indicator_response(body, indicator_type) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          found: true,
          type: indicator_type,
          value: data["id"] || data["value"],
          mscore: data["mscore"],
          last_seen: data["last_seen"],
          first_seen: data["first_seen"],
          attributed_associations: parse_associations(data["attributed_associations"]),
          threat_rating: data["threat_rating"],
          is_publishable: data["is_publishable"],
          sources: data["sources"] || [],
          mitre_attack: parse_mitre_attack(data["mitre_attack"]),
          metadata: %{
            provider: "mandiant",
            report_count: data["report_count"]
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_threat_actor_response(body) do
    case Jason.decode(body) do
      {:ok, %{"actors" => [actor | _]}} ->
        {:ok, %{
          id: actor["id"],
          name: actor["name"],
          description: actor["description"],
          aliases: extract_aliases(actor),
          motivation: extract_motivation(actor),
          target_industries: actor["industries"] || [],
          target_countries: actor["countries"] || [],
          tools: actor["tools"] || [],
          malware: actor["malware"] || [],
          ttps: parse_mitre_attack(actor["mitre_attack"]),
          last_activity: actor["last_activity_time"],
          first_seen: actor["first_seen"],
          metadata: %{
            provider: "mandiant",
            mandiant_id: actor["id"]
          }
        }}

      {:ok, %{"actors" => []}} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_threat_actors_list(body) do
    case Jason.decode(body) do
      {:ok, %{"actors" => actors}} ->
        parsed = Enum.map(actors, fn actor ->
          %{
            id: actor["id"],
            name: actor["name"],
            aliases: extract_aliases(actor),
            motivation: extract_motivation(actor),
            target_industries: actor["industries"] || [],
            last_activity: actor["last_activity_time"]
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_malware_response(body) do
    case Jason.decode(body) do
      {:ok, %{"malware" => [malware | _]}} ->
        {:ok, %{
          id: malware["id"],
          name: malware["name"],
          description: malware["description"],
          aliases: malware["aliases"] || [],
          operating_systems: malware["operating_systems"] || [],
          capabilities: malware["capabilities"] || [],
          actors: malware["actors"] || [],
          yara_rule_available: malware["yara"] != nil,
          detections: malware["detections"] || [],
          last_seen: malware["last_seen"],
          first_seen: malware["first_seen"],
          metadata: %{
            provider: "mandiant",
            mandiant_id: malware["id"]
          }
        }}

      {:ok, %{"malware" => []}} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_vulnerability_response(body) do
    case Jason.decode(body) do
      {:ok, vuln} ->
        {:ok, %{
          cve_id: vuln["cve_id"],
          title: vuln["title"],
          description: vuln["description"],
          cvss_v3_score: vuln["cvss_v3"]["base_score"],
          cvss_v3_vector: vuln["cvss_v3"]["vector_string"],
          exploited_in_wild: vuln["exploitation_state"] == "exploited",
          exploitation_likelihood: vuln["exploitation_vectors"]["likelihood"],
          risk_rating: vuln["risk_rating"],
          affected_products: vuln["affected_products"] || [],
          associated_actors: vuln["actors"] || [],
          associated_malware: vuln["malware"] || [],
          available_patches: vuln["available_patches"] || [],
          workarounds: vuln["workarounds"] || [],
          publish_date: vuln["publish_date"],
          metadata: %{
            provider: "mandiant",
            mandiant_analysis: true
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_campaign_response(body) do
    case Jason.decode(body) do
      {:ok, campaign} ->
        {:ok, %{
          id: campaign["id"],
          name: campaign["name"],
          description: campaign["description"],
          short_name: campaign["short_name"],
          actors: campaign["actors"] || [],
          malware: campaign["malware"] || [],
          industries: campaign["industries"] || [],
          countries: campaign["countries"] || [],
          start_date: campaign["campaign_start"],
          end_date: campaign["campaign_end"],
          status: if(campaign["campaign_end"], do: "concluded", else: "active"),
          ttps: parse_mitre_attack(campaign["mitre_attack"]),
          metadata: %{
            provider: "mandiant",
            mandiant_id: campaign["id"]
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_campaigns_list(body) do
    case Jason.decode(body) do
      {:ok, %{"campaigns" => campaigns}} ->
        parsed = Enum.map(campaigns, fn campaign ->
          %{
            id: campaign["id"],
            name: campaign["name"],
            actors: campaign["actors"] || [],
            industries: campaign["industries"] || [],
            start_date: campaign["campaign_start"],
            status: if(campaign["campaign_end"], do: "concluded", else: "active")
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_indicator_to_ioc(indicator, ioc_type) do
    db_type = ioc_type_to_db_type(ioc_type)
    mscore = indicator["mscore"] || 0

    %{
      type: db_type,
      value: String.downcase(indicator["id"] || indicator["value"] || ""),
      source: "mandiant",
      severity: severity_from_mscore(mscore),
      confidence: mscore / 100.0,
      tags: ["mandiant"] ++ extract_indicator_tags(indicator),
      metadata: %{
        "mscore" => mscore,
        "last_seen" => indicator["last_seen"],
        "first_seen" => indicator["first_seen"],
        "threat_rating" => indicator["threat_rating"],
        "provider" => "mandiant"
      }
    }
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end

  defp schedule_token_refresh(%{token_expires_at: expires_at}) do
    # Refresh 5 minutes before expiry
    refresh_at = DateTime.add(expires_at, -@token_refresh_buffer, :second)
    delay = max(DateTime.diff(refresh_at, DateTime.utc_now(), :millisecond), 0)
    Process.send_after(self(), :refresh_token, delay)
  end

  defp indicator_type_to_endpoint(:ip), do: "indicator/ipv4"
  defp indicator_type_to_endpoint(:domain), do: "indicator/domain"
  defp indicator_type_to_endpoint(:fqdn), do: "indicator/fqdn"
  defp indicator_type_to_endpoint(:url), do: "indicator/url"
  defp indicator_type_to_endpoint(:md5), do: "indicator/md5"
  defp indicator_type_to_endpoint(:sha1), do: "indicator/sha1"
  defp indicator_type_to_endpoint(:sha256), do: "indicator/sha256"
  defp indicator_type_to_endpoint(_), do: "indicator/ipv4"

  defp ioc_type_to_db_type(:ip), do: "ip"
  defp ioc_type_to_db_type(:domain), do: "domain"
  defp ioc_type_to_db_type(:fqdn), do: "domain"
  defp ioc_type_to_db_type(:url), do: "url"
  defp ioc_type_to_db_type(:md5), do: "hash_md5"
  defp ioc_type_to_db_type(:sha1), do: "hash_sha1"
  defp ioc_type_to_db_type(:sha256), do: "hash_sha256"
  defp ioc_type_to_db_type(_), do: "ip"

  defp severity_from_mscore(score) when score >= 80, do: "critical"
  defp severity_from_mscore(score) when score >= 60, do: "high"
  defp severity_from_mscore(score) when score >= 40, do: "medium"
  defp severity_from_mscore(_), do: "low"

  defp parse_associations(nil), do: []
  defp parse_associations(associations) do
    Enum.map(associations, fn assoc ->
      %{
        name: assoc["name"],
        type: assoc["type"]
      }
    end)
  end

  defp parse_mitre_attack(nil), do: []
  defp parse_mitre_attack(mitre) do
    techniques = mitre["attack_pattern"] || []
    Enum.map(techniques, fn tech ->
      tech["attack_pattern_identifier"] || tech["id"]
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp extract_aliases(actor) do
    (actor["aliases"] || [])
    |> Enum.map(fn a ->
      if is_map(a), do: a["name"], else: a
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp extract_motivation(actor) do
    case actor["motivations"] do
      [m | _] -> m["name"] || m
      _ -> "unknown"
    end
  end

  defp extract_indicator_tags(indicator) do
    tags = []

    tags = if indicator["associated_hashes"], do: ["has_hashes" | tags], else: tags
    tags = if indicator["sources"], do: ["multi_source" | tags], else: tags
    tags = if indicator["threat_rating"] == "high", do: ["high_threat" | tags], else: tags

    tags
  end

  defp build_actor_params(opts) do
    params = %{"limit" => Keyword.get(opts, :limit, 50)}

    params = if opts[:text] do
      Map.put(params, "text", opts[:text])
    else
      params
    end

    params = if opts[:since] do
      Map.put(params, "last_activity_timestamp", DateTime.to_unix(opts[:since]))
    else
      params
    end

    URI.encode_query(params)
  end

  defp build_campaign_params(criteria) do
    params = %{"limit" => Map.get(criteria, :limit, 50)}

    params = if criteria[:text] do
      Map.put(params, "text", criteria[:text])
    else
      params
    end

    params = if criteria[:actor] do
      Map.put(params, "actor", criteria[:actor])
    else
      params
    end

    URI.encode_query(params)
  end
end
