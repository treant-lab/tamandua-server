defmodule TamanduaServerWeb.API.V1.CollaborationController do
  @moduledoc """
  Controller for Collaboration Security API endpoints.

  Provides monitoring and security analysis for collaboration platforms
  including event tracking, risk assessment, external sharing analysis,
  and content scanning.
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.Integrations.CollaborationSecurity

  action_fallback TamanduaServerWeb.FallbackController

  @doc """
  List collaboration security events with filtering options.
  """
  def events(conn, params) do
    filters = %{
      platform: Map.get(params, "platform"),
      event_type: Map.get(params, "event_type"),
      severity: Map.get(params, "severity"),
      user_id: Map.get(params, "user_id"),
      start_time: Map.get(params, "start_time"),
      end_time: Map.get(params, "end_time"),
      page: Map.get(params, "page", 1),
      page_size: Map.get(params, "page_size", 50)
    }

    case CollaborationSecurity.list_events(filters) do
      {:ok, result} ->
        json(conn, %{
          data: Enum.map(result.events, fn event ->
            %{
              id: event.id,
              platform: event.platform,
              event_type: event.event_type,
              severity: event.severity,
              user: event.user,
              resource: event.resource,
              action: event.action,
              details: event.details,
              risk_indicators: event.risk_indicators,
              timestamp: event.timestamp
            }
          end),
          meta: %{
            total_count: result.total_count,
            page: result.page,
            page_size: result.page_size,
            total_pages: result.total_pages
          }
        })

      {:error, :invalid_platform} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: %{message: "Invalid platform specified"}})

      {:error, :invalid_time_range} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: %{message: "Invalid time range specified"}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to list collaboration events", details: reason}})
    end
  end

  @doc """
  Analyze collaboration risks across platforms.
  """
  def risks(conn, params) do
    options = %{
      platforms: Map.get(params, "platforms", []),
      risk_categories: Map.get(params, "risk_categories", []),
      time_range: Map.get(params, "time_range", "7d"),
      include_user_analysis: Map.get(params, "include_user_analysis", true),
      include_trending: Map.get(params, "include_trending", true)
    }

    case CollaborationSecurity.analyze_risks(options) do
      {:ok, analysis} ->
        json(conn, %{
          data: %{
            overall_risk_score: analysis.overall_risk_score,
            risk_trend: analysis.risk_trend,
            risks_by_category: analysis.risks_by_category,
            risks_by_platform: analysis.risks_by_platform,
            top_risks: Enum.map(analysis.top_risks, fn risk ->
              %{
                id: risk.id,
                category: risk.category,
                description: risk.description,
                severity: risk.severity,
                affected_users: risk.affected_users,
                affected_resources: risk.affected_resources,
                recommendations: risk.recommendations
              }
            end),
            risky_users: analysis.risky_users,
            trending_risks: analysis.trending_risks,
            analyzed_at: analysis.analyzed_at
          }
        })

      {:error, :no_platforms_configured} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "No collaboration platforms are configured"}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to analyze collaboration risks", details: reason}})
    end
  end

  @doc """
  Analyze external sharing activities and risks.
  """
  def external_sharing(conn, params) do
    options = %{
      platforms: Map.get(params, "platforms", []),
      time_range: Map.get(params, "time_range", "30d"),
      include_guest_users: Map.get(params, "include_guest_users", true),
      include_anonymous_links: Map.get(params, "include_anonymous_links", true),
      sensitivity_threshold: Map.get(params, "sensitivity_threshold", "medium")
    }

    case CollaborationSecurity.analyze_external_sharing(options) do
      {:ok, analysis} ->
        json(conn, %{
          data: %{
            summary: %{
              total_external_shares: analysis.total_external_shares,
              shares_with_sensitive_data: analysis.shares_with_sensitive_data,
              anonymous_links_count: analysis.anonymous_links_count,
              guest_users_count: analysis.guest_users_count,
              expired_shares: analysis.expired_shares
            },
            external_domains: analysis.external_domains,
            risky_shares: Enum.map(analysis.risky_shares, fn share ->
              %{
                id: share.id,
                resource: share.resource,
                shared_with: share.shared_with,
                sharing_type: share.sharing_type,
                permissions: share.permissions,
                sensitivity: share.sensitivity,
                risk_level: share.risk_level,
                risk_factors: share.risk_factors,
                shared_by: share.shared_by,
                shared_at: share.shared_at,
                expires_at: share.expires_at
              }
            end),
            top_external_collaborators: analysis.top_external_collaborators,
            recommendations: analysis.recommendations,
            analyzed_at: analysis.analyzed_at
          }
        })

      {:error, :no_platforms_configured} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: %{message: "No collaboration platforms are configured"}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to analyze external sharing", details: reason}})
    end
  end

  @doc """
  Scan content for security risks and policy violations.
  """
  def scan_content(conn, params) do
    scan_params = %{
      resource_id: Map.get(params, "resource_id"),
      resource_url: Map.get(params, "resource_url"),
      platform: Map.get(params, "platform"),
      scan_types: Map.get(params, "scan_types", ["dlp", "malware", "compliance"]),
      policies: Map.get(params, "policies", []),
      deep_scan: Map.get(params, "deep_scan", false)
    }

    with {:ok, _} <- validate_scan_params(scan_params),
         {:ok, result} <- CollaborationSecurity.scan_content(scan_params) do
      json(conn, %{
        data: %{
          scan_id: result.scan_id,
          resource_id: result.resource_id,
          status: result.status,
          findings: Enum.map(result.findings, fn finding ->
            %{
              type: finding.type,
              severity: finding.severity,
              category: finding.category,
              description: finding.description,
              location: finding.location,
              matched_policy: finding.matched_policy,
              confidence: finding.confidence,
              remediation: finding.remediation
            }
          end),
          summary: %{
            total_findings: result.total_findings,
            critical_findings: result.critical_findings,
            sensitive_data_detected: result.sensitive_data_detected,
            malware_detected: result.malware_detected,
            policy_violations: result.policy_violations
          },
          scan_duration_ms: result.scan_duration_ms,
          scanned_at: result.scanned_at
        }
      })
    else
      {:error, :missing_resource} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: %{message: "Either resource_id or resource_url must be provided"}})

      {:error, :resource_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: %{message: "Resource not found"}})

      {:error, :unsupported_platform} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: %{message: "Unsupported collaboration platform"}})

      {:error, :scan_in_progress} ->
        conn
        |> put_status(:conflict)
        |> json(%{error: %{message: "A scan is already in progress for this resource"}})

      {:error, reason} ->
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: %{message: "Failed to scan content", details: reason}})
    end
  end

  # Private functions

  defp validate_scan_params(%{resource_id: nil, resource_url: nil}) do
    {:error, :missing_resource}
  end

  defp validate_scan_params(_params), do: {:ok, :valid}
end
