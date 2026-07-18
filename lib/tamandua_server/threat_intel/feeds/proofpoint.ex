defmodule TamanduaServer.ThreatIntel.Feeds.Proofpoint do
  @moduledoc """
  Proofpoint Emerging Threats Intelligence Feed Integration.

  Proofpoint provides threat intelligence focused on:
  - Email-based threats (phishing, BEC, malspam)
  - Malware delivery campaigns
  - Threat actor tracking (TA numbers)
  - IP reputation data
  - Domain reputation
  - Emerging Threats Pro rules

  ## Configuration

      config :tamandua_server, TamanduaServer.ThreatIntel.Feeds.Proofpoint,
        api_key: "YOUR_API_KEY",
        principal: "YOUR_PRINCIPAL",
        enabled: true

  ## API Access

  Requires Proofpoint Threat Intelligence subscription.
  """

  use GenServer
  require Logger

  alias TamanduaServer.ThreatIntel.Aggregator

  @base_url "https://api.threatinsight.proofpoint.com"
  @et_url "https://rules.emergingthreatspro.com"

  @default_sync_interval :timer.hours(4)
  @http_timeout 60_000

  # Campaign types

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get threat insight for a domain.
  """
  @spec domain_lookup(String.t()) :: {:ok, map()} | {:error, term()}
  def domain_lookup(domain) do
    GenServer.call(__MODULE__, {:domain_lookup, domain}, @http_timeout)
  end

  @doc """
  Get threat insight for an IP address.
  """
  @spec ip_lookup(String.t()) :: {:ok, map()} | {:error, term()}
  def ip_lookup(ip) do
    GenServer.call(__MODULE__, {:ip_lookup, ip}, @http_timeout)
  end

  @doc """
  Get threat actor information.
  """
  @spec get_threat_actor(String.t()) :: {:ok, map()} | {:error, term()}
  def get_threat_actor(actor_id) do
    GenServer.call(__MODULE__, {:get_threat_actor, actor_id}, @http_timeout)
  end

  @doc """
  List threat actors.
  """
  @spec list_threat_actors(keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_threat_actors(opts \\ []) do
    GenServer.call(__MODULE__, {:list_threat_actors, opts}, @http_timeout)
  end

  @doc """
  Get campaign details.
  """
  @spec get_campaign(String.t()) :: {:ok, map()} | {:error, term()}
  def get_campaign(campaign_id) do
    GenServer.call(__MODULE__, {:get_campaign, campaign_id}, @http_timeout)
  end

  @doc """
  List recent campaigns.
  """
  @spec list_campaigns(keyword()) :: {:ok, [map()]} | {:error, term()}
  def list_campaigns(opts \\ []) do
    GenServer.call(__MODULE__, {:list_campaigns, opts}, @http_timeout)
  end

  @doc """
  Get forensic data for a threat.
  """
  @spec get_forensics(String.t()) :: {:ok, map()} | {:error, term()}
  def get_forensics(threat_id) do
    GenServer.call(__MODULE__, {:get_forensics, threat_id}, @http_timeout)
  end

  @doc """
  Download Emerging Threats Pro IP blocklist.
  """
  @spec download_et_blocklist() :: {:ok, integer()} | {:error, term()}
  def download_et_blocklist do
    GenServer.call(__MODULE__, :download_et_blocklist, @http_timeout * 3)
  end

  @doc """
  Get Very Attacked People (VAP) list.
  """
  @spec get_vap_users(keyword()) :: {:ok, [map()]} | {:error, term()}
  def get_vap_users(opts \\ []) do
    GenServer.call(__MODULE__, {:get_vap_users, opts}, @http_timeout)
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
      api_key: Keyword.get(opts, :api_key) || System.get_env("PROOFPOINT_API_KEY"),
      principal: Keyword.get(opts, :principal) || System.get_env("PROOFPOINT_PRINCIPAL"),
      et_key: Keyword.get(opts, :et_key) || System.get_env("PROOFPOINT_ET_KEY"),
      enabled: Keyword.get(opts, :enabled, true),
      sync_interval: Keyword.get(opts, :sync_interval, @default_sync_interval),
      last_sync: nil,
      stats: %{
        lookups: 0,
        iocs_imported: 0,
        campaigns_fetched: 0,
        errors: 0
      }
    }

    if state.enabled && state.api_key do
      Process.send_after(self(), :initial_sync, :timer.seconds(30))
      schedule_sync(state.sync_interval)
      Logger.info("[Proofpoint] Initialized with credentials configured")
    else
      Logger.info("[Proofpoint] Disabled - no credentials configured")
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:domain_lookup, domain}, _from, state) do
    result = do_domain_lookup(domain, state)
    new_stats = Map.update!(state.stats, :lookups, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:ip_lookup, ip}, _from, state) do
    result = do_ip_lookup(ip, state)
    new_stats = Map.update!(state.stats, :lookups, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_threat_actor, actor_id}, _from, state) do
    result = do_get_threat_actor(actor_id, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:list_threat_actors, opts}, _from, state) do
    result = do_list_threat_actors(opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_campaign, campaign_id}, _from, state) do
    result = do_get_campaign(campaign_id, state)
    new_stats = Map.update!(state.stats, :campaigns_fetched, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:list_campaigns, opts}, _from, state) do
    result = do_list_campaigns(opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_forensics, threat_id}, _from, state) do
    result = do_get_forensics(threat_id, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:download_et_blocklist, _from, state) do
    result = do_download_et_blocklist(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:get_vap_users, opts}, _from, state) do
    result = do_get_vap_users(opts, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      enabled: state.enabled,
      configured: state.api_key != nil,
      et_configured: state.et_key != nil,
      last_sync: state.last_sync,
      stats: state.stats
    }
    {:reply, status, state}
  end

  @impl true
  def handle_cast(:sync_all, state) do
    if state.api_key or state.et_key do
      Task.start(fn -> do_sync_all(state) end)
    end
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:initial_sync, state) do
    Logger.info("[Proofpoint] Starting initial sync...")
    Task.start(fn -> do_sync_all(state) end)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(:periodic_sync, state) do
    Logger.info("[Proofpoint] Starting periodic sync...")
    Task.start(fn -> do_sync_all(state) end)
    schedule_sync(state.sync_interval)
    {:noreply, %{state | last_sync: DateTime.utc_now()}}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions - API Calls
  # ============================================================================

  defp do_domain_lookup(domain, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/v2/domain/#{URI.encode(domain)}"

      headers = api_headers(state)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_domain_response(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:ok, %{found: false}}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_ip_lookup(ip, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/v2/ip/#{URI.encode(ip)}"

      headers = api_headers(state)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_ip_response(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:ok, %{found: false}}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_get_threat_actor(actor_id, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/v2/threat/actor/#{URI.encode(actor_id)}"

      headers = api_headers(state)

      case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_threat_actor_response(body)

        {:ok, %Finch.Response{status: 404}} ->
          {:error, :not_found}

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_list_threat_actors(opts, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/v2/threat/actors"

      headers = api_headers(state)

      params = %{
        "limit" => Keyword.get(opts, :limit, 50)
      }

      case Finch.build(:get, "#{url}?#{URI.encode_query(params)}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_threat_actors_list(body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_get_campaign(campaign_id, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/v2/campaign/#{URI.encode(campaign_id)}"

      headers = api_headers(state)

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
  end

  defp do_list_campaigns(opts, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/v2/campaigns"

      headers = api_headers(state)

      # Calculate time range - default to last 7 days
      end_time = DateTime.utc_now()
      start_time = Keyword.get(opts, :since, DateTime.add(end_time, -7, :day))

      params = %{
        "startTime" => DateTime.to_iso8601(start_time),
        "endTime" => DateTime.to_iso8601(end_time),
        "limit" => Keyword.get(opts, :limit, 50)
      }

      case Finch.build(:get, "#{url}?#{URI.encode_query(params)}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_campaigns_list(body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_get_forensics(threat_id, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/v2/forensics"

      headers = api_headers(state)

      params = %{"threatId" => threat_id}

      case Finch.build(:get, "#{url}?#{URI.encode_query(params)}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_forensics_response(body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_download_et_blocklist(state) do
    unless state.et_key do
      {:error, :not_configured}
    else
      Logger.info("[Proofpoint] Downloading ET Pro blocklist...")

      # ET Pro provides multiple blocklists
      blocklists = [
        {"#{@et_url}/#{state.et_key}/reputation/iprepdata.txt", :ip},
        {"#{@et_url}/#{state.et_key}/reputation/domainrepdata.txt", :domain}
      ]

      total = Enum.reduce(blocklists, 0, fn {url, ioc_type}, acc ->
        case download_and_parse_blocklist(url, ioc_type) do
          {:ok, count} -> acc + count
          {:error, _} -> acc
        end
      end)

      Logger.info("[Proofpoint] Downloaded #{total} IOCs from ET Pro")
      {:ok, total}
    end
  end

  defp download_and_parse_blocklist(url, ioc_type) do
    case Finch.build(:get, url) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout * 2) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        iocs = parse_et_blocklist(body, ioc_type)

        # Submit to aggregator
        Aggregator.ingest_batch("proofpoint_et", iocs)

        {:ok, length(iocs)}

      {:ok, %Finch.Response{status: code}} ->
        {:error, {:http_error, code}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  defp do_get_vap_users(opts, state) do
    unless state.api_key do
      {:error, :not_configured}
    else
      url = "#{@base_url}/v2/people/vap"

      headers = api_headers(state)

      # Time window defaults to last 90 days
      window = Keyword.get(opts, :window, 90)

      params = %{
        "window" => window,
        "size" => Keyword.get(opts, :limit, 50)
      }

      case Finch.build(:get, "#{url}?#{URI.encode_query(params)}", headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @http_timeout) do
        {:ok, %Finch.Response{status: 200, body: body}} ->
          parse_vap_response(body)

        {:ok, %Finch.Response{status: code}} ->
          {:error, {:http_error, code}}

        {:error, %Mint.TransportError{reason: reason}} ->
          {:error, reason}
      end
    end
  end

  defp do_sync_all(state) do
    Logger.info("[Proofpoint] Syncing all intelligence...")

    # Download ET blocklists if configured
    if state.et_key do
      do_download_et_blocklist(state)
    end

    # Sync recent campaigns if API is configured
    if state.api_key do
      case do_list_campaigns([since: DateTime.add(DateTime.utc_now(), -7, :day)], state) do
        {:ok, campaigns} ->
          # Extract IOCs from campaigns
          iocs = Enum.flat_map(campaigns, &extract_campaign_iocs/1)
          Aggregator.ingest_batch("proofpoint", iocs)
          Logger.info("[Proofpoint] Extracted #{length(iocs)} IOCs from campaigns")

        {:error, reason} ->
          Logger.warning("[Proofpoint] Failed to fetch campaigns: #{inspect(reason)}")
      end
    end

    Logger.info("[Proofpoint] Sync complete")
  end

  # ============================================================================
  # Private Functions - Parsing
  # ============================================================================

  defp parse_domain_response(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          found: true,
          domain: data["domain"],
          category: data["category"],
          threat_score: data["threatScore"],
          categories: data["categories"] || [],
          first_seen: data["firstSeen"],
          last_seen: data["lastSeen"],
          campaigns: data["campaigns"] || [],
          threat_actors: data["threatActors"] || [],
          associated_ips: data["associatedIPs"] || [],
          whois: data["whois"],
          metadata: %{
            provider: "proofpoint"
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_ip_response(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          found: true,
          ip: data["ip"],
          category: data["category"],
          threat_score: data["threatScore"],
          blacklist_feeds: data["blacklistFeeds"] || [],
          first_seen: data["firstSeen"],
          last_seen: data["lastSeen"],
          campaigns: data["campaigns"] || [],
          threat_actors: data["threatActors"] || [],
          geo: %{
            country: data["geo"]["country"],
            city: data["geo"]["city"],
            asn: data["geo"]["asn"],
            org: data["geo"]["org"]
          },
          metadata: %{
            provider: "proofpoint"
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_threat_actor_response(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          id: data["id"],
          name: data["name"],
          description: data["description"],
          aliases: data["aliases"] || [],
          motivation: data["motivation"],
          target_sectors: data["targetSectors"] || [],
          target_regions: data["targetRegions"] || [],
          ttps: data["ttps"] || [],
          malware_families: data["malwareFamilies"] || [],
          first_seen: data["firstSeen"],
          last_seen: data["lastSeen"],
          campaigns: data["campaigns"] || [],
          metadata: %{
            provider: "proofpoint",
            proofpoint_id: data["id"]
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_threat_actors_list(body) do
    case Jason.decode(body) do
      {:ok, %{"actors" => actors}} ->
        parsed = Enum.map(actors, fn a ->
          %{
            id: a["id"],
            name: a["name"],
            aliases: a["aliases"] || [],
            motivation: a["motivation"],
            target_sectors: a["targetSectors"] || [],
            last_seen: a["lastSeen"]
          }
        end)
        {:ok, parsed}

      {:ok, data} when is_list(data) ->
        parsed = Enum.map(data, fn a ->
          %{
            id: a["id"],
            name: a["name"],
            aliases: a["aliases"] || [],
            motivation: a["motivation"]
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_campaign_response(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          id: data["id"],
          name: data["name"],
          description: data["description"],
          campaign_type: data["campaignType"],
          start_date: data["startDate"],
          end_date: data["endDate"],
          actors: data["actors"] || [],
          malware_families: data["malwareFamilies"] || [],
          techniques: data["techniques"] || [],
          targets: data["targets"] || [],
          urls: data["urls"] || [],
          attachments: data["attachments"] || [],
          senders: data["senders"] || [],
          message_count: data["messageCount"],
          metadata: %{
            provider: "proofpoint"
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_campaigns_list(body) do
    case Jason.decode(body) do
      {:ok, %{"campaigns" => campaigns}} ->
        parsed = Enum.map(campaigns, fn c ->
          %{
            id: c["id"],
            name: c["name"],
            campaign_type: c["campaignType"],
            actors: c["actors"] || [],
            start_date: c["startDate"],
            message_count: c["messageCount"]
          }
        end)
        {:ok, parsed}

      {:ok, data} when is_list(data) ->
        parsed = Enum.map(data, fn c ->
          %{
            id: c["id"],
            name: c["name"],
            campaign_type: c["campaignType"]
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_forensics_response(body) do
    case Jason.decode(body) do
      {:ok, data} ->
        {:ok, %{
          threat_id: data["threatId"],
          scope: data["scope"],
          platforms: data["platforms"] || [],
          behaviors: data["behaviors"] || [],
          network: %{
            dns_lookups: get_in(data, ["network", "dns"]) || [],
            http_requests: get_in(data, ["network", "http"]) || [],
            connections: get_in(data, ["network", "connections"]) || []
          },
          files: %{
            created: get_in(data, ["files", "created"]) || [],
            modified: get_in(data, ["files", "modified"]) || [],
            deleted: get_in(data, ["files", "deleted"]) || []
          },
          registry: get_in(data, ["registry"]) || [],
          screenshots: data["screenshots"] || [],
          metadata: %{
            provider: "proofpoint"
          }
        }}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_vap_response(body) do
    case Jason.decode(body) do
      {:ok, %{"users" => users}} ->
        parsed = Enum.map(users, fn u ->
          %{
            email: u["identity"]["emails"] |> List.first(),
            name: u["identity"]["name"],
            department: u["identity"]["department"],
            title: u["identity"]["title"],
            attack_index: u["attackIndex"],
            threat_statistics: %{
              total_threats: u["threatStatistics"]["total"],
              malware: u["threatStatistics"]["malware"],
              phishing: u["threatStatistics"]["phishing"],
              spam: u["threatStatistics"]["spam"]
            }
          }
        end)
        {:ok, parsed}

      {:error, reason} ->
        {:error, {:parse_error, reason}}
    end
  end

  defp parse_et_blocklist(body, ioc_type) do
    db_type = case ioc_type do
      :ip -> "ip"
      :domain -> "domain"
      _ -> "ip"
    end

    body
    |> String.split("\n")
    |> Enum.reject(&(String.starts_with?(&1, "#") or &1 == ""))
    |> Enum.map(fn line ->
      # ET format: indicator,category,score
      case String.split(line, ",") do
        [value | rest] ->
          category = Enum.at(rest, 0, "unknown")
          score = Enum.at(rest, 1, "50") |> parse_score()

          %{
            type: db_type,
            value: String.downcase(String.trim(value)),
            source: "proofpoint_et",
            severity: severity_from_score(score),
            confidence: score / 100.0,
            tags: ["emerging_threats", category],
            metadata: %{
              "category" => category,
              "et_score" => score,
              "provider" => "proofpoint_et"
            }
          }

        _ ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp extract_campaign_iocs(campaign) do
    iocs = []

    # Extract URLs
    urls = Enum.map(campaign[:urls] || [], fn url ->
      %{
        type: "url",
        value: url,
        source: "proofpoint",
        severity: "high",
        confidence: 0.9,
        tags: ["proofpoint", "campaign", campaign[:campaign_type] || "unknown"],
        metadata: %{
          "campaign_id" => campaign[:id],
          "campaign_name" => campaign[:name],
          "provider" => "proofpoint"
        }
      }
    end)

    # Extract sender domains
    domains = Enum.flat_map(campaign[:senders] || [], fn sender ->
      case String.split(sender, "@") do
        [_, domain] ->
          [%{
            type: "domain",
            value: String.downcase(domain),
            source: "proofpoint",
            severity: "high",
            confidence: 0.8,
            tags: ["proofpoint", "malicious_sender"],
            metadata: %{
              "campaign_id" => campaign[:id],
              "provider" => "proofpoint"
            }
          }]

        _ ->
          []
      end
    end)

    urls ++ domains ++ iocs
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp api_headers(state) do
    auth = Base.encode64("#{state.principal}:#{state.api_key}")

    [
      {"Authorization", "Basic #{auth}"},
      {"Accept", "application/json"}
    ]
  end

  defp schedule_sync(interval) do
    Process.send_after(self(), :periodic_sync, interval)
  end

  defp parse_score(str) do
    case Integer.parse(String.trim(str)) do
      {n, _} -> n
      :error -> 50
    end
  end

  defp severity_from_score(score) when score >= 80, do: "critical"
  defp severity_from_score(score) when score >= 60, do: "high"
  defp severity_from_score(score) when score >= 40, do: "medium"
  defp severity_from_score(_), do: "low"
end
