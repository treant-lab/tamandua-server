defmodule TamanduaServerWeb.API.V1.ExposureController do
  @moduledoc """
  Controller for Exposure Prioritization API endpoints.

  Provides attack surface mapping, vulnerability prioritization,
  crown jewels identification, and remediation planning.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.AISecurity.ExposureAgent

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  Generate an attack surface map of the environment.
  """
  def attack_surface_map(conn, params) do
    asset_id = Map.get(params, "asset_id")

    # generate_attack_surface_map/1 takes an optional asset_id
    # and wraps analyze_attack_surface/0 which returns comprehensive data
    case ExposureAgent.generate_attack_surface_map(asset_id) do
      {:ok, surface_map} ->
        json(conn, %{
          data: %{
            timestamp: surface_map.timestamp,
            total_assets: surface_map.total_assets,
            total_vulnerabilities: surface_map.total_vulnerabilities,
            critical_exposures: surface_map.critical_exposures,
            high_risk_assets: surface_map.high_risk_assets,
            crown_jewels: surface_map.crown_jewels,
            attack_paths: surface_map.attack_paths,
            org_breach_probability: surface_map.org_breach_probability,
            attack_surface: surface_map.attack_surface,
            top_risks: surface_map.top_risks,
            risk_by_category: surface_map.risk_by_category,
            remediation_summary: surface_map.remediation_summary
          }
        })

      {:error, :scan_in_progress} ->
        conn
        |> put_status(:conflict)
        |> json(%{error: %{message: "An attack surface scan is already in progress"}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to generate attack surface map", details: reason}})
    end
  end

  @doc """
  Get prioritized list of vulnerabilities based on exploitability and impact.
  """
  def prioritized_vulnerabilities(conn, params) do
    options = %{
      severity_threshold: Map.get(params, "severity_threshold", "medium"),
      exploitability: Map.get(params, "exploitability", "all"),
      asset_criticality: Map.get(params, "asset_criticality", "all"),
      age_days: Map.get(params, "age_days"),
      has_exploit: Map.get(params, "has_exploit"),
      limit: Map.get(params, "limit", 100),
      offset: Map.get(params, "offset", 0)
    }

    case ExposureAgent.get_prioritized_vulnerabilities(options) do
      {:ok, result} ->
        json(conn, %{
          data: %{
            vulnerabilities: Enum.map(result.vulnerabilities, fn vuln ->
              %{
                id: vuln.id,
                cve_id: vuln.cve_id,
                title: vuln.title,
                severity: vuln.severity,
                cvss_score: vuln.cvss_score,
                epss_score: vuln.epss_score,
                priority_score: vuln.priority_score,
                affected_assets: vuln.affected_assets,
                exploit_available: vuln.exploit_available,
                in_the_wild: vuln.in_the_wild,
                remediation_available: vuln.remediation_available,
                discovered_at: vuln.discovered_at
              }
            end),
            total_count: result.total_count,
            critical_count: result.critical_count,
            exploitable_count: result.exploitable_count
          },
          meta: %{
            limit: options.limit,
            offset: options.offset
          }
        })

      {:error, :invalid_severity} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: %{message: "Invalid severity threshold specified"}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to get prioritized vulnerabilities", details: reason}})
    end
  end

  @doc """
  Identify and analyze crown jewels (critical assets).
  """
  def crown_jewels(conn, params) do
    _category = Map.get(params, "category")

    # identify_crown_jewels/0 returns a list of crown jewel assets directly
    case ExposureAgent.identify_crown_jewels() do
      {:ok, crown_jewel_list} ->
        json(conn, %{
          data: %{
            crown_jewels: Enum.map(crown_jewel_list, fn asset ->
              %{
                asset_id: asset.asset_id,
                hostname: asset.hostname,
                score: asset.score,
                level: asset.level,
                factors: asset.factors,
                is_crown_jewel: asset.is_crown_jewel
              }
            end),
            total_count: length(crown_jewel_list)
          }
        })

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to identify crown jewels", details: reason}})
    end
  end

  @doc """
  Generate a remediation plan for identified exposures.
  """
  def generate_remediation_plan(conn, params) do
    asset_id = Map.get(params, "asset_id")

    # generate_remediation_plan/1 takes an optional asset_id
    # Returns prioritized remediation actions from the queue
    case ExposureAgent.generate_remediation_plan(asset_id) do
      {:ok, plan} ->
        json(conn, %{
          data: %{
            actions: plan.actions,
            total_actions: plan.total_actions,
            total_effort_hours: plan.total_effort_hours,
            total_risk_reduction: plan.total_risk_reduction,
            actions_by_type: plan.actions_by_type,
            priority_summary: plan.priority_summary,
            generated_at: plan.generated_at
          }
        })

      {:error, :no_targets_specified} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: %{message: "At least one vulnerability or asset must be specified"}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to generate remediation plan", details: reason}})
    end
  end
end
