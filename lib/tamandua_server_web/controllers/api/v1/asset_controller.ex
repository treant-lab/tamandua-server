defmodule TamanduaServerWeb.API.V1.AssetController do
  @moduledoc """
  Asset Inventory API controller.

  Provides CRUD operations for managing the asset inventory,
  including endpoints for vulnerability scanning and risk assessment.
  """
  use TamanduaServerWeb, :controller

  alias TamanduaServer.Inventory.AssetManager

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  List all assets.

  Returns a paginated list of assets with summary information.

  ## Parameters
    - page: Page number
    - per_page: Items per page
    - type: Filter by asset type (endpoint, server, network_device)
    - status: Filter by status (online, offline, unknown)
    - criticality: Filter by criticality level
    - search: Search by hostname or IP
  """
  def index(conn, params) do
    options = %{
      page: Map.get(params, "page", 1),
      per_page: Map.get(params, "per_page", 20),
      type: Map.get(params, "type"),
      status: Map.get(params, "status"),
      criticality: Map.get(params, "criticality"),
      search: Map.get(params, "search"),
      tags: Map.get(params, "tags"),
      sort_by: Map.get(params, "sort_by", "hostname"),
      sort_order: Map.get(params, "sort_order", "asc")
    }

    case AssetManager.list_assets(options) do
      {:ok, assets, pagination} ->
        json(conn, %{
          data: Enum.map(assets, &serialize_asset/1),
          meta: pagination
        })

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Get a specific asset with full details.

  Returns complete asset information including installed software,
  network interfaces, and security posture.
  """
  def show(conn, %{"id" => id}) do
    case AssetManager.get_asset(id) do
      {:ok, asset} ->
        json(conn, %{
          data: serialize_asset_detail(asset)
        })

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Create a new asset manually.

  ## Parameters
    - hostname: Asset hostname
    - ip_addresses: List of IP addresses
    - type: Asset type
    - criticality: Criticality level (low, medium, high, critical)
    - tags: Optional tags for grouping
  """
  def create(conn, %{"asset" => asset_params}) do
    case AssetManager.create_asset(asset_params) do
      {:ok, asset} ->
        conn
        |> put_status(:created)
        |> json(%{
          data: serialize_asset_detail(asset),
          message: "Asset created successfully"
        })

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, changeset}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  def create(conn, params) do
    create(conn, %{"asset" => params})
  end

  @doc """
  Update an existing asset.
  """
  def update(conn, %{"id" => id} = params) do
    asset_params = Map.get(params, "asset", params)

    with {:ok, asset} <- AssetManager.get_asset(id),
         {:ok, updated} <- AssetManager.update_asset(asset, asset_params) do
      json(conn, %{
        data: serialize_asset_detail(updated),
        message: "Asset updated successfully"
      })
    else
      {:error, :not_found} ->
        {:error, :not_found}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, changeset}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Delete an asset.
  """
  def delete(conn, %{"id" => id}) do
    with {:ok, asset} <- AssetManager.get_asset(id),
         {:ok, _} <- AssetManager.delete_asset(asset) do
      send_resp(conn, :no_content, "")
    else
      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Trigger a vulnerability scan for an asset.

  Initiates an on-demand vulnerability scan for the specified asset.

  ## Parameters
    - scan_type: Type of scan (quick, full, custom)
    - options: Scan-specific options
  """
  def trigger_scan(conn, %{"id" => id} = params) do
    scan_type = Map.get(params, "scan_type", "quick")
    options = Map.get(params, "options", %{})

    with {:ok, asset} <- AssetManager.get_asset(id),
         {:ok, scan} <- AssetManager.trigger_vulnerability_scan(asset, scan_type, options) do
      conn
      |> put_status(:accepted)
      |> json(%{
        data: %{
          scan_id: scan.id,
          asset_id: asset.id,
          scan_type: scan_type,
          status: scan.status,
          started_at: format_datetime(scan.started_at)
        },
        message: "Vulnerability scan initiated"
      })
    else
      {:error, :not_found} ->
        {:error, :not_found}

      {:error, :agent_offline} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: "Asset agent is offline"})

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Get vulnerabilities for an asset.

  Returns a list of known vulnerabilities affecting the asset.

  ## Parameters
    - severity: Filter by severity (critical, high, medium, low)
    - status: Filter by status (open, patched, mitigated, accepted)
  """
  def vulnerabilities(conn, %{"id" => id} = params) do
    options = %{
      severity: Map.get(params, "severity"),
      status: Map.get(params, "status"),
      page: Map.get(params, "page", 1),
      per_page: Map.get(params, "per_page", 50)
    }

    with {:ok, _asset} <- AssetManager.get_asset(id),
         {:ok, vulnerabilities, pagination} <- AssetManager.list_vulnerabilities(id, options) do
      json(conn, %{
        data: Enum.map(vulnerabilities, &serialize_vulnerability/1),
        meta: Map.merge(pagination, %{
          summary: %{
            critical: Enum.count(vulnerabilities, &(&1.severity == "critical")),
            high: Enum.count(vulnerabilities, &(&1.severity == "high")),
            medium: Enum.count(vulnerabilities, &(&1.severity == "medium")),
            low: Enum.count(vulnerabilities, &(&1.severity == "low"))
          }
        })
      })
    else
      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Calculate and return risk score for an asset.

  Computes a risk score based on vulnerabilities, criticality,
  exposure, and security controls.
  """
  def risk_score(conn, %{"id" => id} = params) do
    include_breakdown = Map.get(params, "include_breakdown", true)

    with {:ok, asset} <- AssetManager.get_asset(id),
         {:ok, risk_assessment} <- AssetManager.calculate_risk_score(asset) do
      response = %{
        data: %{
          asset_id: asset.id,
          hostname: asset.hostname,
          risk_score: risk_assessment.score,
          risk_level: risk_assessment.level,
          trend: risk_assessment.trend,
          last_assessed_at: format_datetime(risk_assessment.assessed_at)
        }
      }

      response =
        if include_breakdown do
          put_in(response, [:data, :breakdown], %{
            vulnerability_score: risk_assessment.vulnerability_score,
            criticality_score: risk_assessment.criticality_score,
            exposure_score: risk_assessment.exposure_score,
            control_effectiveness: risk_assessment.control_effectiveness,
            factors: risk_assessment.factors
          })
        else
          response
        end

      json(conn, response)
    else
      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  @doc """
  Analyze software license metadata for an asset.

  This is a conservative metadata review based on installed software inventory.
  It does not make legal compliance claims.
  """
  def license_compliance(conn, %{"id" => id}) do
    with {:ok, asset} <- AssetManager.get_asset(id),
         {:ok, analysis} <- AssetManager.analyze_license_metadata(asset) do
      json(conn, %{
        data: %{
          asset_id: analysis.asset_id,
          hostname: analysis.hostname,
          generated_at: format_datetime(analysis.generated_at),
          summary: analysis.summary,
          findings: analysis.findings,
          software: analysis.software,
          caveat:
            "License risk is classified from inventory-provided license metadata only; unknown entries need enrichment before compliance conclusions."
        }
      })
    else
      {:error, :not_found} ->
        {:error, :not_found}

      {:error, reason} ->
        {:error, to_string(reason)}
    end
  end

  # Private functions

  defp serialize_asset(asset) do
    %{
      id: asset.id,
      hostname: asset.hostname,
      ip_addresses: asset.ip_addresses,
      type: asset.type,
      os_type: asset.os_type,
      os_version: asset.os_version,
      status: asset.status,
      criticality: asset.criticality,
      risk_score: asset.risk_score,
      agent_id: asset.agent_id,
      tags: asset.tags,
      last_seen_at: format_datetime(asset.last_seen_at),
      created_at: format_datetime(asset.inserted_at)
    }
  end

  defp serialize_asset_detail(asset) do
    %{
      id: asset.id,
      hostname: asset.hostname,
      ip_addresses: asset.ip_addresses,
      mac_addresses: asset.mac_addresses,
      type: asset.type,
      os_type: asset.os_type,
      os_version: asset.os_version,
      status: asset.status,
      criticality: asset.criticality,
      risk_score: asset.risk_score,
      agent_id: asset.agent_id,
      agent_version: asset.agent_version,
      tags: asset.tags,
      location: asset.location,
      owner: asset.owner,
      department: asset.department,
      installed_software: asset.installed_software,
      network_interfaces: asset.network_interfaces,
      open_ports: asset.open_ports,
      security_controls: asset.security_controls,
      vulnerability_count: asset.vulnerability_count,
      last_scan_at: format_datetime(asset.last_scan_at),
      last_seen_at: format_datetime(asset.last_seen_at),
      created_at: format_datetime(asset.inserted_at),
      updated_at: format_datetime(asset.updated_at)
    }
  end

  defp serialize_vulnerability(vuln) do
    %{
      id: vuln.id,
      cve_id: vuln.cve_id,
      title: vuln.title,
      description: vuln.description,
      severity: vuln.severity,
      cvss_score: vuln.cvss_score,
      status: vuln.status,
      affected_software: vuln.affected_software,
      remediation: vuln.remediation,
      discovered_at: format_datetime(vuln.discovered_at),
      patched_at: format_datetime(vuln.patched_at)
    }
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%NaiveDateTime{} = dt), do: NaiveDateTime.to_iso8601(dt)
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
end
