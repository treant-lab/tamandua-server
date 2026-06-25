defmodule TamanduaServerWeb.API.V1.ASMController do
  @moduledoc """
  Controller for Attack Surface Management (ASM) API endpoints.

  Provides endpoints for:
  - Asset discovery and management
  - Exposure analysis
  - Risk scoring
  - Change monitoring
  - Attack surface visualization
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.ASM.{Discovery, Exposure, RiskScoring, Monitor}

  action_fallback TamanduaServerWeb.FallbackController

  # ===========================================================================
  # Discovery Endpoints
  # ===========================================================================

  @doc """
  List all monitored domains.
  """
  def list_domains(conn, _params) do
    domains = Discovery.list_domains()
    json(conn, %{data: domains})
  end

  @doc """
  Add a domain to monitor.
  """
  def add_domain(conn, %{"domain" => domain} = params) do
    opts = %{
      organization_id: conn.assigns[:current_user][:organization_id],
      auto_discover: Map.get(params, "auto_discover", true),
      notify_changes: Map.get(params, "notify_changes", true)
    }

    case Discovery.add_domain(domain, opts) do
      {:ok, domain_entry} ->
        conn
        |> put_status(:created)
        |> json(%{data: domain_entry, message: "Domain added successfully"})

      {:error, :invalid_domain} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: %{message: "Invalid domain format"}})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Failed to add domain", details: inspect(reason)}})
    end
  end

  @doc """
  Remove a monitored domain.
  """
  def remove_domain(conn, %{"domain" => domain}) do
    :ok = Discovery.remove_domain(domain)
    json(conn, %{message: "Domain removed successfully"})
  end

  @doc """
  Add an IP range to monitor.
  """
  def add_ip_range(conn, %{"cidr" => cidr} = params) do
    opts = %{
      organization_id: conn.assigns[:current_user][:organization_id],
      auto_discover: Map.get(params, "auto_discover", true)
    }

    case Discovery.add_ip_range(cidr, opts) do
      {:ok, range_entry} ->
        conn
        |> put_status(:created)
        |> json(%{data: range_entry})

      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: %{message: "Invalid IP range", details: inspect(reason)}})
    end
  end

  @doc """
  Start a discovery scan.
  """
  def start_discovery(conn, params) do
    discovery_params = %{
      target: params["target"] || params["domain"] || params["cidr"],
      methods: parse_methods(params["methods"])
    }

    case Discovery.start_discovery(discovery_params) do
      {:ok, job_id} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          data: %{job_id: job_id},
          message: "Discovery scan started"
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Failed to start discovery", details: inspect(reason)}})
    end
  end

  @doc """
  Get discovery job status.
  """
  def discovery_status(conn, %{"job_id" => job_id}) do
    case Discovery.get_discovery_status(job_id) do
      {:ok, status} ->
        json(conn, %{data: status})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: %{message: "Discovery job not found"}})
    end
  end

  # ===========================================================================
  # Asset Endpoints
  # ===========================================================================

  @doc """
  List all discovered assets.
  """
  def list_assets(conn, params) do
    opts = [
      type: params["type"],
      domain: params["domain"],
      risk_level: params["risk_level"],
      status: params["status"],
      limit: parse_int(params["limit"], 100),
      offset: parse_int(params["offset"], 0)
    ]

    assets = Discovery.list_assets(opts)

    json(conn, %{
      data: assets,
      meta: %{
        total: length(assets),
        limit: opts[:limit],
        offset: opts[:offset]
      }
    })
  end

  @doc """
  Get a specific asset.
  """
  def get_asset(conn, %{"id" => asset_id}) do
    case Discovery.get_asset(asset_id) do
      {:ok, asset} ->
        # Also get exposures and risk
        exposures = case Exposure.get_exposures(asset_id) do
          {:ok, e} -> e
          _ -> nil
        end

        risk = case RiskScoring.get_risk(asset_id) do
          {:ok, r} -> r
          _ -> nil
        end

        json(conn, %{
          data: %{
            asset: asset,
            exposures: exposures,
            risk: risk
          }
        })

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: %{message: "Asset not found"}})
    end
  end

  @doc """
  Add an asset manually.
  """
  def add_asset(conn, params) do
    asset_data = %{
      type: safe_to_existing_atom(params["type"] || "unknown", ~w(domain subdomain ip service certificate host webapp api cloud unknown)) || :unknown,
      value: params["value"],
      domain: params["domain"],
      ip_addresses: params["ip_addresses"] || [],
      tags: params["tags"] || []
    }

    case Discovery.add_asset(asset_data) do
      {:ok, asset} ->
        conn
        |> put_status(:created)
        |> json(%{data: asset})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Failed to add asset", details: inspect(reason)}})
    end
  end

  @doc """
  Delete an asset.
  """
  def delete_asset(conn, %{"id" => asset_id}) do
    case Discovery.delete_asset(asset_id) do
      :ok ->
        json(conn, %{message: "Asset deleted successfully"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: %{message: "Asset not found"}})
    end
  end

  @doc """
  Get subdomains for a domain.
  """
  def get_subdomains(conn, %{"domain" => domain}) do
    subdomains = Discovery.get_subdomains(domain)
    json(conn, %{data: subdomains, meta: %{count: length(subdomains)}})
  end

  @doc """
  Get Certificate Transparency logs for a domain.
  """
  def get_ct_logs(conn, %{"domain" => domain}) do
    case Discovery.get_ct_logs(domain) do
      {:ok, logs} ->
        json(conn, %{data: logs, meta: %{count: length(logs)}})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Failed to fetch CT logs", details: inspect(reason)}})
    end
  end

  # ===========================================================================
  # Exposure Endpoints
  # ===========================================================================

  @doc """
  Analyze an asset for exposures.
  """
  def analyze_asset(conn, %{"id" => asset_id}) do
    case Discovery.get_asset(asset_id) do
      {:ok, asset} ->
        case Exposure.analyze_asset(asset) do
          {:ok, result} ->
            json(conn, %{data: result})

          {:error, reason} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: %{message: "Analysis failed", details: inspect(reason)}})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: %{message: "Asset not found"}})
    end
  end

  @doc """
  Analyze all assets for a domain.
  """
  def analyze_domain(conn, %{"domain" => domain}) do
    case Exposure.analyze_domain(domain) do
      {:ok, results} ->
        json(conn, %{
          data: results,
          meta: %{
            assets_analyzed: length(results),
            average_exposure_score: calculate_average(results, :exposure_score)
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Domain analysis failed", details: inspect(reason)}})
    end
  end

  @doc """
  Get exposure analysis for an asset.
  """
  def get_exposures(conn, %{"id" => asset_id}) do
    case Exposure.get_exposures(asset_id) do
      {:ok, exposures} ->
        json(conn, %{data: exposures})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: %{message: "Exposure data not found"}})
    end
  end

  @doc """
  List all exposures with filters.
  """
  def list_exposures(conn, params) do
    opts = [
      severity: params["severity"],
      type: params["type"],
      status: params["status"],
      limit: parse_int(params["limit"], 100)
    ]

    exposures = Exposure.list_exposures(opts)
    json(conn, %{data: exposures, meta: %{count: length(exposures)}})
  end

  @doc """
  Perform a port scan on a target.
  """
  def port_scan(conn, %{"target" => target} = params) do
    opts = [
      ports: parse_ports(params["ports"]),
      timeout: parse_int(params["timeout"], 5000)
    ]

    case Exposure.port_scan(target, opts) do
      {:ok, results} ->
        open_ports = Enum.filter(results, & &1.open)
        json(conn, %{
          data: %{
            target: target,
            results: results,
            open_ports: open_ports,
            summary: %{
              total_scanned: length(results),
              open: length(open_ports),
              closed: length(results) - length(open_ports)
            }
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Port scan failed", details: inspect(reason)}})
    end
  end

  @doc """
  Analyze TLS configuration.
  """
  def analyze_tls(conn, %{"host" => host} = params) do
    port = parse_int(params["port"], 443)

    case Exposure.analyze_tls(host, port) do
      {:ok, result} ->
        json(conn, %{data: result})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "TLS analysis failed", details: inspect(reason)}})
    end
  end

  @doc """
  Check security headers.
  """
  def check_headers(conn, %{"url" => url}) do
    case Exposure.check_headers(url) do
      {:ok, result} ->
        json(conn, %{data: result})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Header check failed", details: inspect(reason)}})
    end
  end

  @doc """
  Get aggregate exposure metrics.
  """
  def exposure_metrics(conn, _params) do
    metrics = Exposure.get_aggregate_metrics()
    json(conn, %{data: metrics})
  end

  # ===========================================================================
  # Risk Scoring Endpoints
  # ===========================================================================

  @doc """
  Calculate risk score for an asset.
  """
  def calculate_risk(conn, %{"id" => asset_id}) do
    case RiskScoring.calculate_risk(asset_id) do
      {:ok, result} ->
        json(conn, %{data: result})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Risk calculation failed", details: inspect(reason)}})
    end
  end

  @doc """
  Get risk score for an asset.
  """
  def get_risk(conn, %{"id" => asset_id}) do
    case RiskScoring.get_risk(asset_id) do
      {:ok, risk} ->
        json(conn, %{data: risk})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: %{message: "Risk score not found"}})
    end
  end

  @doc """
  List all risk scores.
  """
  def list_risks(conn, params) do
    opts = [
      level: params["level"],
      min_score: parse_int(params["min_score"]),
      sort: parse_sort(params["sort"]),
      limit: parse_int(params["limit"], 100)
    ]

    risks = RiskScoring.list_risks(opts)
    json(conn, %{data: risks, meta: %{count: length(risks)}})
  end

  @doc """
  Get top riskiest assets.
  """
  def top_risks(conn, params) do
    limit = parse_int(params["limit"], 10)
    risks = RiskScoring.get_top_risks(limit)
    json(conn, %{data: risks})
  end

  @doc """
  Get risk trend for an asset.
  """
  def risk_trend(conn, %{"id" => asset_id} = params) do
    opts = [days: parse_int(params["days"], 30)]

    case RiskScoring.get_risk_trend(asset_id, opts) do
      {:ok, trend} ->
        json(conn, %{data: trend})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: %{message: "Risk trend data not found"}})
    end
  end

  @doc """
  Get aggregate risk metrics.
  """
  def aggregate_risk(conn, _params) do
    metrics = RiskScoring.get_aggregate_risk()
    json(conn, %{data: metrics})
  end

  @doc """
  Get risk distribution.
  """
  def risk_distribution(conn, _params) do
    distribution = RiskScoring.get_risk_distribution()
    json(conn, %{data: distribution})
  end

  @doc """
  Compare risks between assets.
  """
  def compare_risks(conn, %{"asset_ids" => asset_ids}) when is_list(asset_ids) do
    comparisons = RiskScoring.compare_risks(asset_ids)
    json(conn, %{data: comparisons})
  end

  @doc """
  Recalculate all risk scores.
  """
  def recalculate_risks(conn, _params) do
    case RiskScoring.recalculate_all() do
      {:ok, count} ->
        json(conn, %{
          message: "Risk recalculation complete",
          data: %{assets_processed: count}
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Recalculation failed", details: inspect(reason)}})
    end
  end

  # ===========================================================================
  # Change Monitoring Endpoints
  # ===========================================================================

  @doc """
  Get recent changes.
  """
  def list_changes(conn, params) do
    opts = [
      type: params["type"],
      severity: params["severity"],
      from: parse_datetime(params["from"]),
      to: parse_datetime(params["to"]),
      limit: parse_int(params["limit"], 100)
    ]

    changes = Monitor.get_changes(opts)
    json(conn, %{data: changes, meta: %{count: length(changes)}})
  end

  @doc """
  Get changes for a specific asset.
  """
  def asset_changes(conn, %{"id" => asset_id} = params) do
    opts = [
      from: parse_datetime(params["from"]),
      to: parse_datetime(params["to"]),
      limit: parse_int(params["limit"], 50)
    ]

    changes = Monitor.get_asset_changes(asset_id, opts)
    json(conn, %{data: changes, meta: %{count: length(changes)}})
  end

  @doc """
  Get change summary.
  """
  def change_summary(conn, params) do
    opts = [days: parse_int(params["days"], 7)]
    summary = Monitor.get_change_summary(opts)
    json(conn, %{data: summary})
  end

  @doc """
  List alert rules.
  """
  def list_alert_rules(conn, _params) do
    rules = Monitor.list_alert_rules()
    json(conn, %{data: rules})
  end

  @doc """
  Add an alert rule.
  """
  def add_alert_rule(conn, params) do
    rule = %{
      name: params["name"],
      change_types: parse_change_types(params["change_types"]),
      conditions: parse_conditions(params["conditions"]),
      severity: parse_severity(params["severity"]),
      enabled: Map.get(params, "enabled", true)
    }

    case Monitor.add_alert_rule(rule) do
      {:ok, rule_id} ->
        conn
        |> put_status(:created)
        |> json(%{data: %{rule_id: rule_id}, message: "Alert rule created"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Failed to create rule", details: inspect(reason)}})
    end
  end

  @doc """
  Remove an alert rule.
  """
  def remove_alert_rule(conn, %{"id" => rule_id}) do
    :ok = Monitor.remove_alert_rule(rule_id)
    json(conn, %{message: "Alert rule removed"})
  end

  @doc """
  Generate a change report.
  """
  def change_report(conn, params) do
    opts = [days: parse_int(params["days"], 7)]

    case Monitor.generate_report(opts) do
      {:ok, report} ->
        json(conn, %{data: report})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Report generation failed", details: inspect(reason)}})
    end
  end

  # ===========================================================================
  # Dashboard / Overview Endpoints
  # ===========================================================================

  @doc """
  Get ASM dashboard overview.
  """
  def dashboard(conn, _params) do
    discovery_stats = Discovery.get_stats()
    exposure_metrics = Exposure.get_aggregate_metrics()
    risk_metrics = RiskScoring.get_aggregate_risk()
    change_summary = Monitor.get_change_summary(days: 7)

    dashboard_data = %{
      summary: %{
        total_assets: discovery_stats[:total_assets] || 0,
        domains_monitored: discovery_stats[:domains_monitored] || 0,
        total_exposures: exposure_metrics[:total_exposures] || 0,
        average_risk_score: risk_metrics[:average_risk_score] || 0,
        critical_assets: risk_metrics[:total_critical] || 0,
        high_risk_assets: risk_metrics[:total_high] || 0,
        changes_this_week: change_summary[:total_changes] || 0
      },
      assets_by_type: discovery_stats[:by_type] || %{},
      assets_by_risk: risk_metrics || %{},
      exposures_by_severity: exposure_metrics[:exposures_by_severity] || %{},
      top_risks: RiskScoring.get_top_risks(5),
      recent_changes: Monitor.get_changes(limit: 10),
      trend: risk_metrics[:trend_summary] || %{}
    }

    json(conn, %{data: dashboard_data})
  end

  @doc """
  Get attack surface overview.
  """
  def attack_surface(conn, _params) do
    assets = Discovery.list_assets(limit: 1000)
    exposure_metrics = Exposure.get_aggregate_metrics()
    risk_distribution = RiskScoring.get_risk_distribution()

    surface_data = %{
      total_assets: length(assets),
      asset_breakdown: %{
        subdomains: Enum.count(assets, & &1.type == :subdomain),
        ips: Enum.count(assets, & &1.type == :ip),
        cloud_resources: Enum.count(assets, & &1.type == :cloud),
        external: Enum.count(assets, & &1.type == :external)
      },
      exposure_summary: exposure_metrics,
      risk_distribution: risk_distribution,
      internet_facing: Enum.count(assets, fn a ->
        length(a[:ip_addresses] || []) > 0
      end),
      with_vulnerabilities: exposure_metrics[:assets_with_critical_exposures] || 0
    }

    json(conn, %{data: surface_data})
  end

  @doc """
  Get discovery statistics.
  """
  def discovery_stats(conn, _params) do
    stats = Discovery.get_stats()
    json(conn, %{data: stats})
  end

  @doc """
  Get monitoring statistics.
  """
  def monitoring_stats(conn, _params) do
    stats = Monitor.get_stats()
    json(conn, %{data: stats})
  end

  # ===========================================================================
  # Cloud Integration Endpoints
  # ===========================================================================

  @doc """
  Link a cloud account.
  """
  def link_cloud(conn, %{"provider" => provider} = params) do
    provider_atom = safe_to_existing_atom(provider, ~w(aws azure gcp)) || :unknown

    credentials = %{
      account_id: params["account_id"],
      access_key_id: params["access_key_id"],
      secret_access_key: params["secret_access_key"],
      subscription_id: params["subscription_id"],
      tenant_id: params["tenant_id"],
      project_id: params["project_id"],
      service_account_key: params["service_account_key"]
    }

    case Discovery.link_cloud_account(provider_atom, credentials) do
      {:ok, account} ->
        conn
        |> put_status(:created)
        |> json(%{data: account, message: "Cloud account linked successfully"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "Failed to link cloud account", details: inspect(reason)}})
    end
  end

  @doc """
  Configure Shodan API key.
  """
  def configure_shodan(conn, %{"api_key" => api_key}) do
    :ok = Discovery.configure_shodan(api_key)
    json(conn, %{message: "Shodan API key configured"})
  end

  # ===========================================================================
  # Helper Functions
  # ===========================================================================

  defp parse_int(value), do: parse_int(value, nil)
  defp parse_int(nil, default), do: default
  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, ""} -> int
      _ -> default
    end
  end

  @allowed_methods ~w(dns_enum ct_logs passive_dns port_scan web_crawl shodan censys whois)

  defp parse_methods(nil), do: [:dns_enum, :ct_logs, :passive_dns]
  defp parse_methods(methods) when is_list(methods) do
    methods
    |> Enum.map(&safe_to_existing_atom(&1, @allowed_methods))
    |> Enum.reject(&is_nil/1)
  end
  defp parse_methods(methods) when is_binary(methods) do
    methods
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.map(&safe_to_existing_atom(&1, @allowed_methods))
    |> Enum.reject(&is_nil/1)
  end

  defp parse_ports(nil), do: nil
  defp parse_ports(ports) when is_list(ports) do
    ports
    |> Enum.map(&parse_port/1)
    |> Enum.reject(&is_nil/1)
  end
  defp parse_ports(ports) when is_binary(ports) do
    ports
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.map(&parse_port/1)
    |> Enum.reject(&is_nil/1)
  end

  defp parse_port(port) when is_integer(port) and port >= 1 and port <= 65_535, do: port
  defp parse_port(port) when is_binary(port) do
    case Integer.parse(port) do
      {int, ""} when int >= 1 and int <= 65_535 -> int
      _ -> nil
    end
  end
  defp parse_port(_), do: nil

  @allowed_sort_fields ~w(risk_score discovered_at name type severity last_seen)

  defp parse_sort(nil), do: nil
  defp parse_sort(sort) when is_binary(sort), do: safe_to_existing_atom(sort, @allowed_sort_fields)
  defp parse_sort(sort), do: sort

  @allowed_severities ~w(low medium high critical info)

  defp parse_severity(nil), do: nil
  defp parse_severity(severity) when is_binary(severity), do: safe_to_existing_atom(severity, @allowed_severities)
  defp parse_severity(severity), do: severity

  defp parse_datetime(nil), do: nil
  defp parse_datetime(datetime) when is_binary(datetime) do
    case DateTime.from_iso8601(datetime) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  @allowed_change_types ~w(all new removed changed risk_increased risk_decreased)

  defp parse_change_types(nil), do: [:all]
  defp parse_change_types(types) when is_list(types) do
    types
    |> Enum.map(fn t ->
      if is_binary(t), do: safe_to_existing_atom(t, @allowed_change_types), else: t
    end)
    |> Enum.reject(&is_nil/1)
  end

  @allowed_condition_fields ~w(type severity risk_score domain ip port)
  @allowed_condition_operators ~w(eq ne gt lt gte lte contains starts_with ends_with in)

  defp parse_conditions(nil), do: []
  defp parse_conditions(conditions) when is_list(conditions) do
    conditions
    |> Enum.map(fn c ->
      field = safe_to_existing_atom(c["field"], @allowed_condition_fields)
      operator = safe_to_existing_atom(c["operator"], @allowed_condition_operators)
      if field && operator, do: {field, operator, c["value"]}, else: nil
    end)
    |> Enum.reject(&is_nil/1)
  end

  defp calculate_average([], _key), do: 0
  defp calculate_average(items, key) do
    sum = Enum.sum(Enum.map(items, & &1[key] || 0))
    round(sum / length(items))
  end
end
