defmodule TamanduaServerWeb.API.V1.EmailSecurityController do
  @moduledoc """
  API Controller for Email Security features.

  Provides endpoints for:
  - Email security integration management (M365, Google Workspace)
  - Phishing triage and analysis
  - Email-to-endpoint correlation
  - Attack chain visualization
  - User risk scoring
  - Quarantine management
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.EmailSecurity.{Microsoft365, GoogleWorkspace, EmailCorrelator}
  alias TamanduaServer.Detection.PhishingTriage

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :organization_integrations]
    when action in [:configure_m365, :configure_google]
  )

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :response_execute]
    when action in [:m365_release_quarantine]
  )

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :threat_intel_read]
    when action in [:m365_threat_intel]
  )

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :alerts_create]
    when action in [:analyze_email, :analyze_url, :detonate_url]
  )

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :alerts_update]
    when action in [:submit_feedback]
  )

  plug(
    TamanduaServerWeb.Plugs.RBAC,
    [permission: :alerts_read]
    when action in [
           :index,
           :m365_quarantine,
           :m365_security_alerts,
           :m365_search_emails,
           :google_gmail_logs,
           :google_dlp_incidents,
           :google_user_security,
           :google_login_events,
           :get_analysis,
           :check_sender,
           :check_domain,
           :analyze_campaign,
           :triage_stats,
           :list_attack_chains,
           :get_attack_chain,
           :get_user_risk,
           :get_user_chains,
           :correlation_stats,
           :dashboard
         ]
  )

  # ============================================================================
  # Integration Status
  # ============================================================================

  @doc """
  Get status of all email security integrations.
  """
  def index(conn, _params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      m365_status =
        try do
          case Microsoft365.get_status(organization_id) do
            {:ok, status} -> status
            _ -> %{connected: false, enabled: false}
          end
        rescue
          _ -> %{connected: false, enabled: false, error: "Service unavailable"}
        end

      google_status =
        try do
          case GoogleWorkspace.get_status(organization_id) do
            {:ok, status} -> status
            _ -> %{connected: false, enabled: false}
          end
        rescue
          _ -> %{connected: false, enabled: false, error: "Service unavailable"}
        end

      correlator_stats =
        try do
          case EmailCorrelator.get_stats(organization_id) do
            {:ok, stats} -> stats
            _ -> %{}
          end
        rescue
          _ -> %{}
        end

      triage_stats =
        try do
          case PhishingTriage.get_stats(organization_id) do
            {:ok, stats} -> stats
            _ -> %{}
          end
        rescue
          _ -> %{}
        end

      json(conn, %{
        integrations: %{
          microsoft365: m365_status,
          google_workspace: google_status
        },
        correlator: correlator_stats,
        triage: triage_stats
      })
    end
  end

  # ============================================================================
  # Microsoft 365 Integration
  # ============================================================================

  @doc """
  Configure Microsoft 365 integration.
  """
  def configure_m365(conn, params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      with {:ok, config} <-
             partial_provider_config(
               params,
               ~w(tenant_id client_id client_secret enabled poll_interval_ms),
               ~w(client_secret)
             ),
           :ok <-
             Microsoft365.update_config(
               organization_id,
               Map.put(config, :organization_id, organization_id)
             ) do
        json(conn, %{status: "ok", message: "Microsoft 365 integration configured"})
      else
        {:error, reason} ->
          conn |> put_status(:bad_request) |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Get Microsoft 365 threat intelligence.
  """
  def m365_threat_intel(conn, params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      opts = [
        limit: bounded_limit(params["limit"], 100, 500)
      ]

      case Microsoft365.get_threat_intel(organization_id, opts) do
        {:ok, indicators} ->
          json(conn, %{indicators: indicators, count: length(indicators)})

        {:error, reason} ->
          conn
          |> put_status(integration_error_status(reason, :service_unavailable))
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  List Microsoft 365 quarantine.
  """
  def m365_quarantine(conn, params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      opts = [
        limit: bounded_limit(params["limit"], 50, 250)
      ]

      case Microsoft365.list_quarantine(organization_id, opts) do
        {:ok, messages} ->
          json(conn, %{messages: messages, count: length(messages)})

        {:error, reason} ->
          conn
          |> put_status(integration_error_status(reason, :service_unavailable))
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Release email from Microsoft 365 quarantine.
  """
  def m365_release_quarantine(conn, %{"message_id" => message_id} = params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      opts = [
        allow_sender: params["allow_sender"] == true,
        report_false_positive: params["report_false_positive"] == true
      ]

      case Microsoft365.release_from_quarantine(organization_id, message_id, opts) do
        :ok ->
          json(conn, %{status: "ok", message: "Email released from quarantine"})

        {:error, reason} ->
          conn
          |> put_status(integration_error_status(reason, :bad_request))
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Get Microsoft 365 security alerts.
  """
  def m365_security_alerts(conn, params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      opts =
        [
          limit: bounded_limit(params["limit"], 100, 500),
          category: params["category"],
          severity: params["severity"],
          status: params["status"]
        ]
        |> Enum.reject(fn {_, v} -> is_nil(v) end)

      case Microsoft365.get_security_alerts(organization_id, opts) do
        {:ok, alerts} ->
          json(conn, %{alerts: alerts, count: length(alerts)})

        {:error, reason} ->
          conn
          |> put_status(integration_error_status(reason, :service_unavailable))
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Search emails in Microsoft 365.
  """
  def m365_search_emails(conn, %{"query" => query} = params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      opts = [
        limit: bounded_limit(params["limit"], 25, 250),
        offset: bounded_offset(params["offset"])
      ]

      case Microsoft365.search_emails(organization_id, query, opts) do
        {:ok, results} ->
          json(conn, %{results: results, count: length(results)})

        {:error, reason} ->
          conn
          |> put_status(integration_error_status(reason, :service_unavailable))
          |> json(%{error: inspect(reason)})
      end
    end
  end

  # ============================================================================
  # Google Workspace Integration
  # ============================================================================

  @doc """
  Configure Google Workspace integration.
  """
  def configure_google(conn, params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      with {:ok, config} <-
             partial_provider_config(
               params,
               ~w(service_account_key admin_email enabled poll_interval_ms),
               ~w(service_account_key)
             ),
           :ok <-
             GoogleWorkspace.update_config(
               organization_id,
               Map.put(config, :organization_id, organization_id)
             ) do
        json(conn, %{status: "ok", message: "Google Workspace integration configured"})
      else
        {:error, reason} ->
          conn |> put_status(:bad_request) |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Get Google Workspace Gmail logs.
  """
  def google_gmail_logs(conn, params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      end_time = DateTime.utc_now()
      hours = bounded_hours(params["hours"], 24, 24 * 30)
      start_time = DateTime.add(end_time, -hours, :hour)

      opts = [
        limit: bounded_limit(params["limit"], 100, 500)
      ]

      case GoogleWorkspace.get_gmail_logs(organization_id, start_time, end_time, opts) do
        {:ok, logs} ->
          json(conn, %{logs: logs, count: length(logs)})

        {:error, reason} ->
          conn
          |> put_status(integration_error_status(reason, :service_unavailable))
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Get Google Workspace DLP incidents.
  """
  def google_dlp_incidents(conn, params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      opts = [
        limit: bounded_limit(params["limit"], 100, 500)
      ]

      case GoogleWorkspace.get_dlp_incidents(organization_id, opts) do
        {:ok, incidents} ->
          json(conn, %{incidents: incidents, count: length(incidents)})

        {:error, reason} ->
          conn
          |> put_status(integration_error_status(reason, :service_unavailable))
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Get user security info from Google Workspace.
  """
  def google_user_security(conn, %{"email" => email}) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      case GoogleWorkspace.get_user_security(organization_id, email) do
        {:ok, info} ->
          json(conn, info)

        {:error, reason} ->
          conn
          |> put_status(:not_found)
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Get Google Workspace login events.
  """
  def google_login_events(conn, params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      opts = [
        limit: bounded_limit(params["limit"], 100, 500)
      ]

      case GoogleWorkspace.get_login_events(organization_id, opts) do
        {:ok, events} ->
          json(conn, %{events: events, count: length(events)})

        {:error, reason} ->
          conn
          |> put_status(integration_error_status(reason, :service_unavailable))
          |> json(%{error: inspect(reason)})
      end
    end
  end

  # ============================================================================
  # Phishing Triage
  # ============================================================================

  @doc """
  Submit email for phishing analysis.
  """
  def analyze_email(conn, params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      email_data = %{
        raw_content: params["raw_content"],
        headers: params["headers"] || %{},
        body: params["body"],
        html_body: params["html_body"],
        subject: params["subject"],
        from: params["from"],
        attachments: params["attachments"] || [],
        reported_by: params["reported_by"],
        organization_id: organization_id,
        agent_id: params["agent_id"]
      }

      case PhishingTriage.analyze_email_for_organization(organization_id, email_data) do
        {:ok, result} ->
          json(conn, result)

        {:error, reason} ->
          conn
          |> put_status(error_status(reason, :bad_request))
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Get phishing analysis result.
  """
  def get_analysis(conn, %{"id" => analysis_id}) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      case PhishingTriage.get_analysis(organization_id, analysis_id) do
        {:ok, result} ->
          json(conn, result)

        {:error, :not_found} ->
          conn
          |> put_status(:not_found)
          |> json(%{error: "Analysis not found"})
      end
    end
  end

  @doc """
  Submit feedback on analysis verdict.
  """
  def submit_feedback(conn, %{"id" => analysis_id, "feedback" => feedback} = params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      feedback_atom =
        case feedback do
          "correct" -> :correct
          "incorrect" -> :incorrect
          _ -> :invalid
        end

      metadata = params["metadata"] || %{}

      case PhishingTriage.submit_feedback(organization_id, analysis_id, feedback_atom, metadata) do
        :ok ->
          json(conn, %{status: "ok"})

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "Analysis not found"})

        {:error, reason} ->
          conn |> put_status(:bad_request) |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Deep URL analysis.
  """
  def analyze_url(conn, %{"url" => url} = params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      opts = [
        fetch_content: params["fetch_content"] == true,
        max_redirects: bounded_limit(params["max_redirects"], 5, 20),
        organization_id: organization_id
      ]

      case PhishingTriage.analyze_url_deep(url, opts) do
        {:ok, result} ->
          json(conn, result)

        {:error, reason} ->
          conn
          |> put_status(:bad_request)
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Detonate URL in sandbox.
  """
  def detonate_url(conn, %{"url" => url} = params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      opts = [
        timeout: bounded_limit(params["timeout"], 30, 300),
        screenshot: params["screenshot"] != false,
        network: params["network"] != false,
        organization_id: organization_id
      ]

      case PhishingTriage.detonate_url(url, opts) do
        {:ok, result} ->
          json(conn, result)

        {:error, reason} ->
          conn
          |> put_status(:service_unavailable)
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Check sender reputation.
  """
  def check_sender(conn, %{"email" => email}) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      case PhishingTriage.check_sender_reputation(organization_id, email) do
        {:ok, result} ->
          json(conn, result)

        {:error, reason} ->
          conn
          |> put_status(:bad_request)
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Detect domain spoofing.
  """
  def check_domain(conn, %{"domain" => domain}) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      case PhishingTriage.detect_domain_spoofing(domain) do
        {:ok, result} ->
          json(conn, result)

        {:error, reason} ->
          conn
          |> put_status(:bad_request)
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Analyze phishing campaign.
  """
  def analyze_campaign(conn, %{"email_id" => email_id}) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      case PhishingTriage.analyze_campaign(organization_id, email_id) do
        {:ok, result} ->
          json(conn, result)

        {:error, reason} ->
          conn
          |> put_status(:not_found)
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Get phishing triage statistics.
  """
  def triage_stats(conn, _params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      {:ok, stats} = PhishingTriage.get_stats(organization_id)
      json(conn, stats)
    end
  end

  # ============================================================================
  # Email Correlation
  # ============================================================================

  @doc """
  Get attack chains.
  """
  def list_attack_chains(conn, params) do
    organization_id = current_organization_id(conn)

    opts =
      [
        limit: bounded_limit(params["limit"], 100, 500),
        min_severity: parse_severity(params["min_severity"])
      ]
      |> Enum.reject(fn {_, v} -> is_nil(v) end)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      case EmailCorrelator.list_attack_chains(organization_id, opts) do
        {:ok, chains} ->
          json(conn, %{chains: chains, count: length(chains)})

        {:error, reason} ->
          conn
          |> put_status(:service_unavailable)
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Get attack chain for specific email.
  """
  def get_attack_chain(conn, %{"email_id" => email_id}) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      case EmailCorrelator.get_attack_chain(organization_id, email_id) do
        {:ok, chain} ->
          json(conn, chain)

        {:error, :not_found} ->
          conn
          |> put_status(:not_found)
          |> json(%{error: "Attack chain not found"})
      end
    end
  end

  @doc """
  Get user risk score.
  """
  def get_user_risk(conn, %{"email" => email}) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      case EmailCorrelator.get_user_risk(organization_id, email) do
        {:ok, risk} ->
          json(conn, risk)

        {:error, :not_found} ->
          conn
          |> put_status(:not_found)
          |> json(%{error: "User not found"})
      end
    end
  end

  @doc """
  Get attack chains for user.
  """
  def get_user_chains(conn, %{"email" => email} = params) do
    organization_id = current_organization_id(conn)

    opts = [
      limit: bounded_limit(params["limit"], 50, 250)
    ]

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      case EmailCorrelator.get_user_chains(organization_id, email, opts) do
        {:ok, chains} ->
          json(conn, %{chains: chains, count: length(chains)})

        {:error, reason} ->
          conn
          |> put_status(:service_unavailable)
          |> json(%{error: inspect(reason)})
      end
    end
  end

  @doc """
  Get correlation statistics.
  """
  def correlation_stats(conn, _params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      case EmailCorrelator.get_stats(organization_id) do
        {:ok, stats} ->
          json(conn, stats)

        {:error, reason} ->
          conn |> put_status(:service_unavailable) |> json(%{error: inspect(reason)})
      end
    end
  end

  # ============================================================================
  # Email Security Dashboard Data
  # ============================================================================

  @doc """
  Get email security dashboard overview.
  """
  def dashboard(conn, params) do
    organization_id = current_organization_id(conn)

    if not valid_org?(organization_id) do
      forbidden(conn)
    else
      hours = bounded_hours(params["hours"], 24, 24 * 30)

      # Gather stats from all sources
      triage_stats =
        try do
          case PhishingTriage.get_stats(organization_id) do
            {:ok, stats} -> stats
            _ -> %{}
          end
        rescue
          _ -> %{}
        end

      correlator_stats =
        try do
          case EmailCorrelator.get_stats(organization_id) do
            {:ok, stats} -> stats
            _ -> %{}
          end
        rescue
          _ -> %{}
        end

      # Get attack chains for the dashboard
      recent_chains =
        case EmailCorrelator.list_attack_chains(organization_id,
               limit: 10,
               min_severity: :medium
             ) do
          {:ok, chains} ->
            chains

          {:error, reason} ->
            Logger.warning("Email security dashboard attack chains failed: #{inspect(reason)}")
            []
        end

      # Build dashboard data
      dashboard_data = %{
        stats: %{
          emails_analyzed: triage_stats[:total_analyzed] || 0,
          phishing_detected: triage_stats[:malicious_detected] || 0,
          suspicious_flagged: triage_stats[:suspicious_detected] || 0,
          attack_chains: correlator_stats[:chains_built] || 0,
          attachments_tracked: correlator_stats[:attachments_tracked] || 0,
          payloads_executed: correlator_stats[:processes_correlated] || 0
        },
        recent_attack_chains: recent_chains,
        integration_status: %{
          microsoft365: get_integration_status(:microsoft365, organization_id),
          google_workspace: get_integration_status(:google_workspace, organization_id)
        },
        time_range_hours: hours
      }

      json(conn, dashboard_data)
    end
  end

  # ============================================================================
  # Helpers
  # ============================================================================

  defp current_organization_id(conn) do
    conn.assigns[:current_organization_id] || conn.assigns[:organization_id] ||
      conn.assigns[:org_id]
  end

  defp valid_org?(organization_id), do: is_binary(organization_id) and organization_id != ""

  defp forbidden(conn) do
    conn
    |> put_status(:forbidden)
    |> json(%{error: "Organization context required"})
  end

  defp error_status(reason, _fallback)
       when reason in [:forbidden, :organization_required],
       do: :forbidden

  defp error_status(_reason, fallback), do: fallback

  defp parse_severity(nil), do: nil
  defp parse_severity("critical"), do: :critical
  defp parse_severity("high"), do: :high
  defp parse_severity("medium"), do: :medium
  defp parse_severity("low"), do: :low
  defp parse_severity(_), do: nil

  defp parse_int(nil, default), do: default

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(value, _default) when is_integer(value), do: value
  defp parse_int(_, default), do: default

  defp bounded_limit(value, default, max_limit) do
    value
    |> parse_int(default)
    |> max(1)
    |> min(max_limit)
  end

  defp bounded_offset(value) do
    value
    |> parse_int(0)
    |> max(0)
  end

  defp bounded_hours(value, default, max_hours) do
    value
    |> parse_int(default)
    |> max(1)
    |> min(max_hours)
  end

  defp partial_provider_config(params, allowed_keys, secret_keys) do
    Enum.reduce_while(allowed_keys, {:ok, %{}}, fn key, {:ok, config} ->
      if Map.has_key?(params, key) do
        value = Map.get(params, key)

        cond do
          key in secret_keys and is_nil(value) ->
            {:halt, {:error, :secret_cannot_be_null}}

          key == "enabled" ->
            enabled = value == true or value == "true"
            {:cont, {:ok, Map.put(config, :enabled, enabled)}}

          true ->
            {:cont, {:ok, Map.put(config, String.to_existing_atom(key), value)}}
        end
      else
        {:cont, {:ok, config}}
      end
    end)
  end

  defp get_integration_status(:microsoft365, organization_id) do
    try do
      case Microsoft365.get_status(organization_id) do
        {:ok, status} -> status
        _ -> %{connected: false, enabled: false}
      end
    rescue
      _ -> %{connected: false, enabled: false}
    end
  end

  defp get_integration_status(:google_workspace, organization_id) do
    try do
      case GoogleWorkspace.get_status(organization_id) do
        {:ok, status} -> status
        _ -> %{connected: false, enabled: false}
      end
    rescue
      _ -> %{connected: false, enabled: false}
    end
  end

  defp integration_error_status(:integration_not_configured, _fallback), do: :not_found
  defp integration_error_status(:organization_required, _fallback), do: :forbidden
  defp integration_error_status(_reason, fallback), do: fallback
end
