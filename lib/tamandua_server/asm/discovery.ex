defmodule TamanduaServer.ASM.Discovery do
  @moduledoc """
  Attack Surface Management - Asset Discovery Module

  Provides comprehensive external attack surface discovery capabilities:

  - Domain enumeration (subdomain discovery via DNS)
  - Certificate Transparency log monitoring
  - IP range scanning (Shodan integration)
  - Cloud asset discovery (AWS/Azure/GCP)
  - Passive DNS reconnaissance
  - WHOIS information gathering

  Comparable to Censys ASM and Mandiant Attack Surface Management.
  """

  use GenServer
  require Logger

  alias TamanduaServer.ASM.{Exposure, RiskScoring, Monitor}

  # Discovery method types
  @discovery_methods [:dns_enum, :ct_logs, :shodan, :cloud, :passive_dns, :whois]

  # Common subdomains to enumerate
  @common_subdomains ~w(
    www api app mail smtp ftp ssh vpn remote admin portal
    dev staging test qa uat prod production demo beta
    blog shop store support help docs wiki
    cdn static media assets images files
    db database mysql postgres redis mongo
    git gitlab github bitbucket jenkins ci cd
    grafana prometheus kibana elastic logs monitoring
    auth login sso oauth identity idp
    backup archive old legacy
    internal intranet extranet
    m mobile ios android
    ws websocket realtime
    status health
  )

  # Well-known port list for scanning
  @common_ports [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900,
    5984, 6379, 8000, 8008, 8080, 8443, 8888, 9000, 9200, 9300, 27017
  ]

  # State structure
  defstruct [
    :assets,              # Discovered assets (ETS table)
    :domains,             # Monitored root domains
    :ip_ranges,           # Monitored IP ranges
    :cloud_accounts,      # Connected cloud accounts
    :discovery_jobs,      # Running discovery jobs
    :discovery_history,   # History of discovery runs
    :config,              # Configuration
    :stats                # Statistics
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Add a root domain to monitor for asset discovery.
  """
  @spec add_domain(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def add_domain(domain, opts \\ %{}) do
    GenServer.call(__MODULE__, {:add_domain, domain, opts})
  end

  @doc """
  Remove a domain from monitoring.
  """
  @spec remove_domain(String.t()) :: :ok
  def remove_domain(domain) do
    GenServer.call(__MODULE__, {:remove_domain, domain})
  end

  @doc """
  List all monitored domains.
  """
  @spec list_domains() :: [map()]
  def list_domains do
    GenServer.call(__MODULE__, :list_domains)
  end

  @doc """
  Add an IP range to monitor.
  """
  @spec add_ip_range(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def add_ip_range(cidr, opts \\ %{}) do
    GenServer.call(__MODULE__, {:add_ip_range, cidr, opts})
  end

  @doc """
  Start a discovery scan for a domain or IP range.
  """
  @spec start_discovery(map()) :: {:ok, String.t()} | {:error, term()}
  def start_discovery(params) do
    GenServer.call(__MODULE__, {:start_discovery, params})
  end

  @doc """
  Get the status of a discovery job.
  """
  @spec get_discovery_status(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_discovery_status(job_id) do
    GenServer.call(__MODULE__, {:get_discovery_status, job_id})
  end

  @doc """
  Get all discovered assets.
  """
  @spec list_assets(keyword()) :: [map()]
  def list_assets(opts \\ []) do
    GenServer.call(__MODULE__, {:list_assets, opts})
  end

  @doc """
  Get a specific asset by ID.
  """
  @spec get_asset(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_asset(asset_id) do
    GenServer.call(__MODULE__, {:get_asset, asset_id})
  end

  @doc """
  Get discovered subdomains for a domain.
  """
  @spec get_subdomains(String.t()) :: [map()]
  def get_subdomains(domain) do
    GenServer.call(__MODULE__, {:get_subdomains, domain})
  end

  @doc """
  Get discovery statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Configure Shodan API key.
  """
  @spec configure_shodan(String.t()) :: :ok
  def configure_shodan(api_key) do
    GenServer.cast(__MODULE__, {:configure_shodan, api_key})
  end

  @doc """
  Link a cloud account for asset discovery.
  """
  @spec link_cloud_account(atom(), map()) :: {:ok, map()} | {:error, term()}
  def link_cloud_account(provider, credentials) do
    GenServer.call(__MODULE__, {:link_cloud_account, provider, credentials})
  end

  @doc """
  Manually add an asset to the inventory.
  """
  @spec add_asset(map()) :: {:ok, map()} | {:error, term()}
  def add_asset(asset_data) do
    GenServer.call(__MODULE__, {:add_asset, asset_data})
  end

  @doc """
  Delete an asset from the inventory.
  """
  @spec delete_asset(String.t()) :: :ok | {:error, :not_found}
  def delete_asset(asset_id) do
    GenServer.call(__MODULE__, {:delete_asset, asset_id})
  end

  @doc """
  Get Certificate Transparency logs for a domain.
  """
  @spec get_ct_logs(String.t()) :: {:ok, [map()]} | {:error, term()}
  def get_ct_logs(domain) do
    GenServer.call(__MODULE__, {:get_ct_logs, domain}, 30_000)
  end

  # ============================================================================
  # GenServer Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting Attack Surface Management - Discovery Service")

    # Create ETS table for assets
    assets_table = :ets.new(:asm_assets, [:named_table, :set, :public, read_concurrency: true])

    state = %__MODULE__{
      assets: assets_table,
      domains: %{},
      ip_ranges: %{},
      cloud_accounts: %{},
      discovery_jobs: %{},
      discovery_history: [],
      config: build_config(opts),
      stats: initial_stats()
    }

    # Schedule periodic discovery
    schedule_periodic_discovery()

    {:ok, state}
  end

  @impl true
  def handle_call({:add_domain, domain, opts}, _from, state) do
    normalized = normalize_domain(domain)

    if valid_domain?(normalized) do
      domain_entry = %{
        domain: normalized,
        organization_id: opts[:organization_id],
        added_at: DateTime.utc_now(),
        last_scan: nil,
        auto_discover: Map.get(opts, :auto_discover, true),
        notify_changes: Map.get(opts, :notify_changes, true),
        status: :pending
      }

      new_domains = Map.put(state.domains, normalized, domain_entry)
      new_stats = update_stats(state.stats, :domains_monitored, map_size(new_domains))

      # Trigger initial discovery
      if domain_entry.auto_discover do
        send(self(), {:trigger_discovery, :domain, normalized})
      end

      {:reply, {:ok, domain_entry}, %{state | domains: new_domains, stats: new_stats}}
    else
      {:reply, {:error, :invalid_domain}, state}
    end
  end

  @impl true
  def handle_call({:remove_domain, domain}, _from, state) do
    normalized = normalize_domain(domain)
    new_domains = Map.delete(state.domains, normalized)
    new_stats = update_stats(state.stats, :domains_monitored, map_size(new_domains))

    # Remove associated assets
    delete_assets_for_domain(state.assets, normalized)

    {:reply, :ok, %{state | domains: new_domains, stats: new_stats}}
  end

  @impl true
  def handle_call(:list_domains, _from, state) do
    domains = Map.values(state.domains)
    {:reply, domains, state}
  end

  @impl true
  def handle_call({:add_ip_range, cidr, opts}, _from, state) do
    case parse_cidr(cidr) do
      {:ok, parsed} ->
        range_entry = %{
          cidr: cidr,
          parsed: parsed,
          organization_id: opts[:organization_id],
          added_at: DateTime.utc_now(),
          last_scan: nil,
          auto_discover: Map.get(opts, :auto_discover, true),
          status: :pending
        }

        new_ranges = Map.put(state.ip_ranges, cidr, range_entry)
        {:reply, {:ok, range_entry}, %{state | ip_ranges: new_ranges}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:start_discovery, params}, _from, state) do
    job_id = generate_job_id()
    target = params[:target] || params[:domain] || params[:cidr]
    methods = params[:methods] || @discovery_methods

    job = %{
      id: job_id,
      target: target,
      methods: methods,
      status: :running,
      started_at: DateTime.utc_now(),
      completed_at: nil,
      results: %{},
      errors: [],
      progress: 0
    }

    new_jobs = Map.put(state.discovery_jobs, job_id, job)

    # Start async discovery
    Task.start(fn ->
      run_discovery(job_id, target, methods, state.config)
    end)

    {:reply, {:ok, job_id}, %{state | discovery_jobs: new_jobs}}
  end

  @impl true
  def handle_call({:get_discovery_status, job_id}, _from, state) do
    case Map.get(state.discovery_jobs, job_id) do
      nil -> {:reply, {:error, :not_found}, state}
      job -> {:reply, {:ok, job}, state}
    end
  end

  @impl true
  def handle_call({:list_assets, opts}, _from, state) do
    assets = get_all_assets(state.assets)

    # Apply filters
    filtered = assets
    |> filter_by_type(opts[:type])
    |> filter_by_domain(opts[:domain])
    |> filter_by_risk(opts[:risk_level])
    |> filter_by_status(opts[:status])
    |> maybe_limit(opts[:limit])
    |> maybe_offset(opts[:offset])

    {:reply, filtered, state}
  end

  @impl true
  def handle_call({:get_asset, asset_id}, _from, state) do
    case :ets.lookup(state.assets, asset_id) do
      [{^asset_id, asset}] -> {:reply, {:ok, asset}, state}
      [] -> {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_subdomains, domain}, _from, state) do
    normalized = normalize_domain(domain)
    subdomains = get_all_assets(state.assets)
    |> Enum.filter(fn a ->
      a.type == :subdomain and String.ends_with?(a.value, normalized)
    end)

    {:reply, subdomains, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    assets = get_all_assets(state.assets)

    stats = Map.merge(state.stats, %{
      total_assets: length(assets),
      by_type: Enum.group_by(assets, & &1.type) |> Enum.map(fn {k, v} -> {k, length(v)} end) |> Map.new(),
      by_risk: Enum.group_by(assets, & &1.risk_level) |> Enum.map(fn {k, v} -> {k, length(v)} end) |> Map.new(),
      domains_monitored: map_size(state.domains),
      ip_ranges_monitored: map_size(state.ip_ranges),
      cloud_accounts_linked: map_size(state.cloud_accounts),
      active_jobs: Enum.count(state.discovery_jobs, fn {_, j} -> j.status == :running end)
    })

    {:reply, stats, state}
  end

  @impl true
  def handle_call({:link_cloud_account, provider, credentials}, _from, state) do
    account = %{
      provider: provider,
      account_id: credentials[:account_id] || generate_account_id(),
      linked_at: DateTime.utc_now(),
      status: :pending,
      last_sync: nil,
      assets_discovered: 0
    }

    # Validate credentials
    case validate_cloud_credentials(provider, credentials) do
      :ok ->
        account_key = "#{provider}_#{account.account_id}"
        new_accounts = Map.put(state.cloud_accounts, account_key, Map.put(account, :status, :active))

        # Trigger cloud discovery
        send(self(), {:trigger_cloud_discovery, provider, credentials})

        {:reply, {:ok, account}, %{state | cloud_accounts: new_accounts}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:add_asset, asset_data}, _from, state) do
    asset = build_asset(asset_data)
    :ets.insert(state.assets, {asset.id, asset})

    new_stats = increment_stats(state.stats, :assets_discovered)
    {:reply, {:ok, asset}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:delete_asset, asset_id}, _from, state) do
    case :ets.lookup(state.assets, asset_id) do
      [{^asset_id, _}] ->
        :ets.delete(state.assets, asset_id)
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :not_found}, state}
    end
  end

  @impl true
  def handle_call({:get_ct_logs, domain}, _from, state) do
    result = fetch_ct_logs(domain, state.config)
    {:reply, result, state}
  end

  @impl true
  def handle_cast({:configure_shodan, api_key}, state) do
    new_config = Map.put(state.config, :shodan_api_key, api_key)
    {:noreply, %{state | config: new_config}}
  end

  @impl true
  def handle_info({:trigger_discovery, :domain, domain}, state) do
    Logger.info("Triggering domain discovery for: #{domain}")

    Task.start(fn ->
      # DNS enumeration
      subdomains = enumerate_subdomains(domain, state.config)

      # CT log search
      ct_domains = case fetch_ct_logs(domain, state.config) do
        {:ok, logs} -> Enum.map(logs, & &1[:common_name]) |> Enum.uniq()
        _ -> []
      end

      all_discoveries = Enum.uniq(subdomains ++ ct_domains)

      # Store discovered assets
      Enum.each(all_discoveries, fn subdomain ->
        asset = build_subdomain_asset(subdomain, domain)
        GenServer.cast(__MODULE__, {:store_asset, asset})
      end)

      # Notify monitor of new assets
      Monitor.notify_discovery(:domain, domain, all_discoveries)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info({:trigger_cloud_discovery, provider, credentials}, state) do
    Logger.info("Triggering cloud discovery for: #{provider}")

    Task.start(fn ->
      assets = discover_cloud_assets(provider, credentials, state.config)

      Enum.each(assets, fn asset ->
        GenServer.cast(__MODULE__, {:store_asset, asset})
      end)

      Monitor.notify_discovery(:cloud, provider, assets)
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info(:periodic_discovery, state) do
    Logger.debug("Running periodic asset discovery")

    # Re-scan all domains
    Enum.each(state.domains, fn {domain, config} ->
      if config.auto_discover do
        send(self(), {:trigger_discovery, :domain, domain})
      end
    end)

    schedule_periodic_discovery()
    {:noreply, state}
  end

  @impl true
  def handle_info({:discovery_complete, job_id, results}, state) do
    case Map.get(state.discovery_jobs, job_id) do
      nil ->
        {:noreply, state}

      job ->
        updated_job = %{job |
          status: :completed,
          completed_at: DateTime.utc_now(),
          results: results,
          progress: 100
        }

        new_jobs = Map.put(state.discovery_jobs, job_id, updated_job)
        new_history = [updated_job | Enum.take(state.discovery_history, 99)]

        {:noreply, %{state | discovery_jobs: new_jobs, discovery_history: new_history}}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_cast({:store_asset, asset}, state) do
    existing = case :ets.lookup(state.assets, asset.id) do
      [{_, existing}] -> existing
      [] -> nil
    end

    if existing do
      # Update existing asset
      updated = merge_asset(existing, asset)
      :ets.insert(state.assets, {updated.id, updated})

      # Check for changes
      if asset_changed?(existing, updated) do
        Monitor.notify_change(:asset_updated, updated, existing)
      end
    else
      # New asset
      :ets.insert(state.assets, {asset.id, asset})
      Monitor.notify_change(:asset_discovered, asset, nil)

      # Trigger exposure analysis for new assets
      Exposure.analyze_asset(asset)
    end

    {:noreply, state}
  end

  # ============================================================================
  # Discovery Functions
  # ============================================================================

  defp run_discovery(job_id, target, methods, config) do
    results = Enum.reduce(methods, %{}, fn method, acc ->
      result = case method do
        :dns_enum -> enumerate_subdomains(target, config)
        :ct_logs -> fetch_ct_logs(target, config) |> elem(1)
        :shodan -> shodan_search(target, config)
        :cloud -> [] # Handled separately via cloud account linking
        :passive_dns -> passive_dns_lookup(target, config)
        :whois -> whois_lookup(target, config)
      end

      Map.put(acc, method, result)
    end)

    send(__MODULE__, {:discovery_complete, job_id, results})
  end

  defp enumerate_subdomains(domain, _config) do
    # Enumerate common subdomains via DNS
    found = @common_subdomains
    |> Enum.map(fn sub -> "#{sub}.#{domain}" end)
    |> Enum.filter(&dns_resolves?/1)

    # Also try zone transfer (usually blocked but worth trying)
    zone_results = try_zone_transfer(domain)

    Enum.uniq(found ++ zone_results)
  end

  defp dns_resolves?(hostname) do
    case :inet.gethostbyname(String.to_charlist(hostname)) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end

  defp try_zone_transfer(domain) do
    # Attempt AXFR zone transfer (usually blocked)
    # This is a simplified implementation
    case :inet_res.lookup(String.to_charlist(domain), :in, :ns) do
      [] -> []
      nameservers ->
        # In production, would attempt zone transfer via each NS
        # For now, return empty as most servers block AXFR
        Logger.debug("Found #{length(nameservers)} nameservers for #{domain}")
        []
    end
  end

  defp fetch_ct_logs(domain, config) do
    # Query Certificate Transparency logs via crt.sh
    url = "https://crt.sh/?q=%.#{domain}&output=json"

    case http_get(url, config) do
      {:ok, body} ->
        case Jason.decode(body) do
          {:ok, entries} ->
            logs = Enum.map(entries, fn entry ->
              %{
                id: entry["id"],
                common_name: entry["common_name"],
                issuer: entry["issuer_name"],
                not_before: entry["not_before"],
                not_after: entry["not_after"],
                logged_at: entry["entry_timestamp"]
              }
            end)
            {:ok, logs}

          {:error, _} ->
            {:error, :parse_error}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp shodan_search(target, config) do
    api_key = config[:shodan_api_key]

    if api_key do
      # Search Shodan for the target
      query = if String.contains?(target, ".") and not String.match?(target, ~r/^\d+\.\d+\.\d+\.\d+/) do
        "hostname:#{target}"
      else
        "ip:#{target}"
      end

      url = "https://api.shodan.io/shodan/host/search?key=#{api_key}&query=#{URI.encode(query)}"

      case http_get(url, config) do
        {:ok, body} ->
          case Jason.decode(body) do
            {:ok, %{"matches" => matches}} ->
              Enum.map(matches, fn match ->
                %{
                  ip: match["ip_str"],
                  port: match["port"],
                  transport: match["transport"],
                  product: match["product"],
                  version: match["version"],
                  os: match["os"],
                  hostnames: match["hostnames"] || [],
                  vulns: match["vulns"] || [],
                  location: %{
                    country: match["location"]["country_code"],
                    city: match["location"]["city"]
                  }
                }
              end)

            _ -> []
          end

        _ -> []
      end
    else
      Logger.debug("Shodan API key not configured")
      []
    end
  end

  defp passive_dns_lookup(domain, config) do
    # Use passive DNS services for historical resolution data
    # This could integrate with services like SecurityTrails, Farsight, etc.

    # For now, basic DNS lookup for common record types
    records = []

    # A records
    a_records = case :inet_res.lookup(String.to_charlist(domain), :in, :a) do
      [] -> []
      ips -> Enum.map(ips, fn ip -> %{type: :a, value: :inet.ntoa(ip) |> to_string()} end)
    end

    # MX records
    mx_records = case :inet_res.lookup(String.to_charlist(domain), :in, :mx) do
      [] -> []
      mxs -> Enum.map(mxs, fn {priority, host} -> %{type: :mx, priority: priority, value: to_string(host)} end)
    end

    # TXT records
    txt_records = case :inet_res.lookup(String.to_charlist(domain), :in, :txt) do
      [] -> []
      txts -> Enum.map(txts, fn txt -> %{type: :txt, value: to_string(txt)} end)
    end

    records ++ a_records ++ mx_records ++ txt_records
  end

  defp whois_lookup(domain, _config) do
    # WHOIS lookup for domain registration info
    # In production, would use a WHOIS library or API

    %{
      domain: domain,
      registrar: nil,
      created_date: nil,
      expiry_date: nil,
      nameservers: [],
      status: :lookup_pending
    }
  end

  defp discover_cloud_assets(provider, credentials, _config) do
    case provider do
      :aws -> discover_aws_assets(credentials)
      :azure -> discover_azure_assets(credentials)
      :gcp -> discover_gcp_assets(credentials)
      _ -> []
    end
  end

  defp discover_aws_assets(_credentials) do
    # Integrate with TamanduaServer.Cloud.AWS for asset discovery
    # Would enumerate: EC2 instances, ELBs, CloudFront, API Gateway, etc.

    # Placeholder - in production, calls AWS APIs
    []
  end

  defp discover_azure_assets(_credentials) do
    # Integrate with TamanduaServer.Cloud.Azure for asset discovery
    # Would enumerate: VMs, App Services, Front Door, API Management, etc.
    []
  end

  defp discover_gcp_assets(_credentials) do
    # Integrate with TamanduaServer.Cloud.GCP for asset discovery
    # Would enumerate: Compute Engine, Cloud Run, Load Balancers, etc.
    []
  end

  # ============================================================================
  # Asset Management Functions
  # ============================================================================

  defp build_asset(data) do
    %{
      id: data[:id] || generate_asset_id(data),
      type: data[:type] || :unknown,
      value: data[:value],
      domain: data[:domain],
      ip_addresses: data[:ip_addresses] || [],
      ports: data[:ports] || [],
      services: data[:services] || [],
      certificates: data[:certificates] || [],
      technologies: data[:technologies] || [],
      cloud_provider: data[:cloud_provider],
      cloud_region: data[:cloud_region],
      cloud_resource_id: data[:cloud_resource_id],
      first_seen: data[:first_seen] || DateTime.utc_now(),
      last_seen: DateTime.utc_now(),
      risk_level: data[:risk_level] || :unknown,
      risk_score: data[:risk_score] || 0,
      exposures: data[:exposures] || [],
      vulnerabilities: data[:vulnerabilities] || [],
      status: data[:status] || :active,
      tags: data[:tags] || [],
      metadata: data[:metadata] || %{}
    }
  end

  defp build_subdomain_asset(subdomain, parent_domain) do
    # Resolve the subdomain
    ip_addresses = case :inet.gethostbyname(String.to_charlist(subdomain)) do
      {:ok, {:hostent, _, _, :inet, _, addrs}} ->
        Enum.map(addrs, &(:inet.ntoa(&1) |> to_string()))
      _ -> []
    end

    build_asset(%{
      type: :subdomain,
      value: subdomain,
      domain: parent_domain,
      ip_addresses: ip_addresses
    })
  end

  defp merge_asset(existing, new) do
    %{existing |
      ip_addresses: Enum.uniq(existing.ip_addresses ++ new.ip_addresses),
      ports: Enum.uniq(existing.ports ++ new.ports),
      services: Enum.uniq(existing.services ++ new.services),
      technologies: Enum.uniq(existing.technologies ++ new.technologies),
      last_seen: DateTime.utc_now(),
      exposures: merge_exposures(existing.exposures, new.exposures),
      vulnerabilities: merge_vulnerabilities(existing.vulnerabilities, new.vulnerabilities)
    }
  end

  defp merge_exposures(existing, new) do
    # Merge exposures, keeping the most recent
    all = existing ++ new
    all
    |> Enum.group_by(& &1[:id])
    |> Enum.map(fn {_id, items} -> List.last(items) end)
  end

  defp merge_vulnerabilities(existing, new) do
    all = existing ++ new
    all
    |> Enum.group_by(& &1[:cve_id])
    |> Enum.map(fn {_id, items} -> List.last(items) end)
  end

  defp asset_changed?(old, new) do
    old.ip_addresses != new.ip_addresses or
    old.ports != new.ports or
    old.services != new.services or
    old.risk_level != new.risk_level
  end

  defp get_all_assets(table) do
    :ets.tab2list(table)
    |> Enum.map(fn {_id, asset} -> asset end)
  end

  defp delete_assets_for_domain(table, domain) do
    :ets.tab2list(table)
    |> Enum.filter(fn {_id, asset} -> asset.domain == domain end)
    |> Enum.each(fn {id, _} -> :ets.delete(table, id) end)
  end

  # ============================================================================
  # Filter Functions
  # ============================================================================

  defp filter_by_type(assets, nil), do: assets
  defp filter_by_type(assets, type) do
    type_atom = if is_binary(type), do: String.to_atom(type), else: type
    Enum.filter(assets, & &1.type == type_atom)
  end

  defp filter_by_domain(assets, nil), do: assets
  defp filter_by_domain(assets, domain) do
    Enum.filter(assets, & &1.domain == domain)
  end

  defp filter_by_risk(assets, nil), do: assets
  defp filter_by_risk(assets, level) do
    level_atom = if is_binary(level), do: String.to_atom(level), else: level
    Enum.filter(assets, & &1.risk_level == level_atom)
  end

  defp filter_by_status(assets, nil), do: assets
  defp filter_by_status(assets, status) do
    status_atom = if is_binary(status), do: String.to_atom(status), else: status
    Enum.filter(assets, & &1.status == status_atom)
  end

  defp maybe_limit(assets, nil), do: assets
  defp maybe_limit(assets, limit), do: Enum.take(assets, limit)

  defp maybe_offset(assets, nil), do: assets
  defp maybe_offset(assets, 0), do: assets
  defp maybe_offset(assets, offset), do: Enum.drop(assets, offset)

  # ============================================================================
  # Utility Functions
  # ============================================================================

  defp build_config(opts) do
    %{
      shodan_api_key: Keyword.get(opts, :shodan_api_key, System.get_env("SHODAN_API_KEY")),
      discovery_interval: Keyword.get(opts, :discovery_interval, :timer.hours(24)),
      ct_log_enabled: Keyword.get(opts, :ct_log_enabled, true),
      passive_dns_enabled: Keyword.get(opts, :passive_dns_enabled, true),
      http_timeout: Keyword.get(opts, :http_timeout, 30_000)
    }
  end

  defp initial_stats do
    %{
      domains_monitored: 0,
      ip_ranges_monitored: 0,
      assets_discovered: 0,
      discovery_runs: 0,
      last_discovery: nil,
      started_at: DateTime.utc_now()
    }
  end

  defp update_stats(stats, key, value) do
    Map.put(stats, key, value)
  end

  defp increment_stats(stats, key) do
    Map.update(stats, key, 1, & &1 + 1)
  end

  defp normalize_domain(domain) do
    domain
    |> String.downcase()
    |> String.trim()
    |> String.replace(~r/^(https?:\/\/)?(www\.)?/, "")
    |> String.replace(~r/\/.*$/, "")
  end

  defp valid_domain?(domain) do
    Regex.match?(~r/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/, domain)
  end

  defp parse_cidr(cidr) do
    # Basic CIDR validation
    case String.split(cidr, "/") do
      [ip, prefix] ->
        case :inet.parse_address(String.to_charlist(ip)) do
          {:ok, addr} ->
            case Integer.parse(prefix) do
              {prefix_int, ""} when prefix_int >= 0 and prefix_int <= 32 ->
                {:ok, %{address: addr, prefix: prefix_int}}
              _ ->
                {:error, :invalid_prefix}
            end
          {:error, _} ->
            {:error, :invalid_ip}
        end
      _ ->
        {:error, :invalid_cidr_format}
    end
  end

  defp validate_cloud_credentials(:aws, credentials) do
    if credentials[:access_key_id] && credentials[:secret_access_key] do
      :ok
    else
      {:error, :missing_credentials}
    end
  end

  defp validate_cloud_credentials(:azure, credentials) do
    if credentials[:subscription_id] && credentials[:tenant_id] do
      :ok
    else
      {:error, :missing_credentials}
    end
  end

  defp validate_cloud_credentials(:gcp, credentials) do
    if credentials[:project_id] && (credentials[:service_account_key] || credentials[:application_default]) do
      :ok
    else
      {:error, :missing_credentials}
    end
  end

  defp validate_cloud_credentials(_, _), do: {:error, :unsupported_provider}

  defp generate_job_id do
    "disc_#{:crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)}"
  end

  defp generate_asset_id(data) do
    input = "#{data[:type]}_#{data[:value]}_#{data[:domain]}"
    :crypto.hash(:sha256, input) |> Base.encode16(case: :lower) |> String.slice(0, 16)
  end

  defp generate_account_id do
    :crypto.strong_rand_bytes(6) |> Base.encode16(case: :lower)
  end

  defp http_get(url, config) do
    timeout = config[:http_timeout] || 30_000

    # Use Finch for HTTP requests
    # This is a simplified implementation
    try do
      case :httpc.request(:get, {String.to_charlist(url), []}, [timeout: timeout], []) do
        {:ok, {{_, 200, _}, _, body}} ->
          {:ok, to_string(body)}
        {:ok, {{_, status, _}, _, _}} ->
          {:error, {:http_error, status}}
        {:error, reason} ->
          {:error, reason}
      end
    catch
      :exit, _ -> {:error, :timeout}
    end
  end

  defp schedule_periodic_discovery do
    # Run discovery every 24 hours
    Process.send_after(self(), :periodic_discovery, :timer.hours(24))
  end
end
