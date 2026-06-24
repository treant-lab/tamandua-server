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

  # ============================================================================
  # Integration Status
  # ============================================================================

  @doc """
  Get status of all email security integrations.
  """
  def index(conn, _params) do
    m365_status = try do
      case Microsoft365.get_status() do
        {:ok, status} -> status
        _ -> %{connected: false, enabled: false}
      end
    rescue
      _ -> %{connected: false, enabled: false, error: "Service unavailable"}
    end

    google_status = try do
      case GoogleWorkspace.get_status() do
        {:ok, status} -> status
        _ -> %{connected: false, enabled: false}
      end
    rescue
      _ -> %{connected: false, enabled: false, error: "Service unavailable"}
    end

    correlator_stats = try do
      EmailCorrelator.get_stats()
    rescue
      _ -> %{}
    end

    triage_stats = try do
      PhishingTriage.get_stats()
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

  # ============================================================================
  # Microsoft 365 Integration
  # ============================================================================

  @doc """
  Configure Microsoft 365 integration.
  """
  def configure_m365(conn, params) do
    config = %{
      tenant_id: params["tenant_id"],
      client_id: params["client_id"],
      client_secret: params["client_secret"],
      enabled: params["enabled"] == true or params["enabled"] == "true",
      poll_interval_ms: params["poll_interval_ms"] || 60_000
    }

    case Microsoft365.update_config(config) do
      :ok ->
        json(conn, %{status: "ok", message: "Microsoft 365 integration configured"})
      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Get Microsoft 365 threat intelligence.
  """
  def m365_threat_intel(conn, params) do
    opts = [
      limit: bounded_limit(params["limit"], 100, 500)
    ]

    case Microsoft365.get_threat_intel(opts) do
      {:ok, indicators} ->
        json(conn, %{indicators: indicators, count: length(indicators)})
      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  List Microsoft 365 quarantine.
  """
  def m365_quarantine(conn, params) do
    opts = [
      limit: bounded_limit(params["limit"], 50, 250)
    ]

    case Microsoft365.list_quarantine(opts) do
      {:ok, messages} ->
        json(conn, %{messages: messages, count: length(messages)})
      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Release email from Microsoft 365 quarantine.
  """
  def m365_release_quarantine(conn, %{"message_id" => message_id} = params) do
    opts = [
      allow_sender: params["allow_sender"] == true,
      report_false_positive: params["report_false_positive"] == true
    ]

    case Microsoft365.release_from_quarantine(message_id, opts) do
      :ok ->
        json(conn, %{status: "ok", message: "Email released from quarantine"})
      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Get Microsoft 365 security alerts.
  """
  def m365_security_alerts(conn, params) do
    opts = [
      limit: bounded_limit(params["limit"], 100, 500),
      category: params["category"],
      severity: params["severity"],
      status: params["status"]
    ] |> Enum.reject(fn {_, v} -> is_nil(v) end)

    case Microsoft365.get_security_alerts(opts) do
      {:ok, alerts} ->
        json(conn, %{alerts: alerts, count: length(alerts)})
      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Search emails in Microsoft 365.
  """
  def m365_search_emails(conn, %{"query" => query} = params) do
    opts = [
      limit: bounded_limit(params["limit"], 25, 250),
      offset: bounded_offset(params["offset"])
    ]

    case Microsoft365.search_emails(query, opts) do
      {:ok, results} ->
        json(conn, %{results: results, count: length(results)})
      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: inspect(reason)})
    end
  end

  # ============================================================================
  # Google Workspace Integration
  # ============================================================================

  @doc """
  Configure Google Workspace integration.
  """
  def configure_google(conn, params) do
    config = %{
      service_account_key: params["service_account_key"],
      admin_email: params["admin_email"],
      enabled: params["enabled"] == true or params["enabled"] == "true",
      poll_interval_ms: params["poll_interval_ms"] || 60_000
    }

    case GoogleWorkspace.update_config(config) do
      :ok ->
        json(conn, %{status: "ok", message: "Google Workspace integration configured"})
      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Get Google Workspace Gmail logs.
  """
  def google_gmail_logs(conn, params) do
    end_time = DateTime.utc_now()
    hours = bounded_hours(params["hours"], 24, 24 * 30)
    start_time = DateTime.add(end_time, -hours, :hour)

    opts = [
      limit: bounded_limit(params["limit"], 100, 500)
    ]

    case GoogleWorkspace.get_gmail_logs(start_time, end_time, opts) do
      {:ok, logs} ->
        json(conn, %{logs: logs, count: length(logs)})
      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Get Google Workspace DLP incidents.
  """
  def google_dlp_incidents(conn, params) do
    opts = [
      limit: bounded_limit(params["limit"], 100, 500)
    ]

    case GoogleWorkspace.get_dlp_incidents(opts) do
      {:ok, incidents} ->
        json(conn, %{incidents: incidents, count: length(incidents)})
      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Get user security info from Google Workspace.
  """
  def google_user_security(conn, %{"email" => email}) do
    case GoogleWorkspace.get_user_security(email) do
      {:ok, info} ->
        json(conn, info)
      {:error, reason} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Get Google Workspace login events.
  """
  def google_login_events(conn, params) do
    opts = [
      limit: bounded_limit(params["limit"], 100, 500)
    ]

    case GoogleWorkspace.get_login_events(opts) do
      {:ok, events} ->
        json(conn, %{events: events, count: length(events)})
      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: inspect(reason)})
    end
  end

  # ============================================================================
  # Phishing Triage
  # ============================================================================

  @doc """
  Submit email for phishing analysis.
  """
  def analyze_email(conn, params) do
    email_data = %{
      raw_content: params["raw_content"],
      headers: params["headers"] || %{},
      body: params["body"],
      html_body: params["html_body"],
      subject: params["subject"],
      from: params["from"],
      attachments: params["attachments"] || [],
      reported_by: params["reported_by"],
      organization_id: params["organization_id"]
    }

    case PhishingTriage.analyze_email(email_data) do
      {:ok, result} ->
        json(conn, result)
      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Get phishing analysis result.
  """
  def get_analysis(conn, %{"id" => analysis_id}) do
    case PhishingTriage.get_analysis(analysis_id) do
      {:ok, result} ->
        json(conn, result)
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Analysis not found"})
    end
  end

  @doc """
  Submit feedback on analysis verdict.
  """
  def submit_feedback(conn, %{"id" => analysis_id, "feedback" => feedback} = params) do
    feedback_atom = case feedback do
      "correct" -> :correct
      "incorrect" -> :incorrect
      _ -> :correct
    end

    metadata = params["metadata"] || %{}

    PhishingTriage.submit_feedback(analysis_id, feedback_atom, metadata)
    json(conn, %{status: "ok"})
  end

  @doc """
  Deep URL analysis.
  """
  def analyze_url(conn, %{"url" => url} = params) do
    opts = [
      fetch_content: params["fetch_content"] == true,
      max_redirects: bounded_limit(params["max_redirects"], 5, 20)
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

  @doc """
  Detonate URL in sandbox.
  """
  def detonate_url(conn, %{"url" => url} = params) do
    opts = [
      timeout: bounded_limit(params["timeout"], 30, 300),
      screenshot: params["screenshot"] != false,
      network: params["network"] != false
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

  @doc """
  Check sender reputation.
  """
  def check_sender(conn, %{"email" => email}) do
    case PhishingTriage.check_sender_reputation(email) do
      {:ok, result} ->
        json(conn, result)
      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Detect domain spoofing.
  """
  def check_domain(conn, %{"domain" => domain}) do
    case PhishingTriage.detect_domain_spoofing(domain) do
      {:ok, result} ->
        json(conn, result)
      {:error, reason} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Analyze phishing campaign.
  """
  def analyze_campaign(conn, %{"email_id" => email_id}) do
    case PhishingTriage.analyze_campaign(email_id) do
      {:ok, result} ->
        json(conn, result)
      {:error, reason} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Get phishing triage statistics.
  """
  def triage_stats(conn, _params) do
    stats = PhishingTriage.get_stats()
    json(conn, stats)
  end

  # ============================================================================
  # Email Correlation
  # ============================================================================

  @doc """
  Get attack chains.
  """
  def list_attack_chains(conn, params) do
    opts = [
      limit: bounded_limit(params["limit"], 100, 500),
      min_severity: parse_severity(params["min_severity"])
    ] |> Enum.reject(fn {_, v} -> is_nil(v) end)

    case EmailCorrelator.list_attack_chains(opts) do
      {:ok, chains} ->
        json(conn, %{chains: chains, count: length(chains)})
      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Get attack chain for specific email.
  """
  def get_attack_chain(conn, %{"email_id" => email_id}) do
    case EmailCorrelator.build_attack_chain(email_id) do
      {:ok, chain} ->
        json(conn, chain)
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Attack chain not found"})
    end
  end

  @doc """
  Get user risk score.
  """
  def get_user_risk(conn, %{"email" => email}) do
    case EmailCorrelator.get_user_risk(email) do
      {:ok, risk} ->
        json(conn, risk)
      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "User not found"})
    end
  end

  @doc """
  Get attack chains for user.
  """
  def get_user_chains(conn, %{"email" => email} = params) do
    opts = [
      limit: bounded_limit(params["limit"], 50, 250)
    ]

    case EmailCorrelator.get_user_chains(email, opts) do
      {:ok, chains} ->
        json(conn, %{chains: chains, count: length(chains)})
      {:error, reason} ->
        conn
        |> put_status(:service_unavailable)
        |> json(%{error: inspect(reason)})
    end
  end

  @doc """
  Get correlation statistics.
  """
  def correlation_stats(conn, _params) do
    stats = EmailCorrelator.get_stats()
    json(conn, stats)
  end

  # ============================================================================
  # Email Security Dashboard Data
  # ============================================================================

  @doc """
  Get email security dashboard overview.
  """
  def dashboard(conn, params) do
    hours = bounded_hours(params["hours"], 24, 24 * 30)

    # Gather stats from all sources
    triage_stats = try do
      PhishingTriage.get_stats()
    rescue
      _ -> %{}
    end

    correlator_stats = try do
      EmailCorrelator.get_stats()
    rescue
      _ -> %{}
    end

    # Get attack chains for the dashboard
    recent_chains =
      case EmailCorrelator.list_attack_chains(limit: 10, min_severity: :medium) do
        {:ok, chains} -> chains
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
        microsoft365: get_integration_status(:microsoft365),
        google_workspace: get_integration_status(:google_workspace)
      },
      time_range_hours: hours
    }

    json(conn, dashboard_data)
  end

  # ============================================================================
  # Helpers
  # ============================================================================

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

  defp get_integration_status(:microsoft365) do
    try do
      case Microsoft365.get_status() do
        {:ok, status} -> status
        _ -> %{connected: false, enabled: false}
      end
    rescue
      _ -> %{connected: false, enabled: false}
    end
  end

  defp get_integration_status(:google_workspace) do
    try do
      case GoogleWorkspace.get_status() do
        {:ok, status} -> status
        _ -> %{connected: false, enabled: false}
      end
    rescue
      _ -> %{connected: false, enabled: false}
    end
  end
end
