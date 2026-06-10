defmodule TamanduaServer.Alerts.Notifier.Email do
  @moduledoc """
  Email notification delivery via Swoosh.

  Sends HTML-formatted alert emails with evidence, MITRE techniques,
  and recommended actions.
  """

  use Swoosh.Mailer, otp_app: :tamandua_server

  import Swoosh.Email
  require Logger

  alias TamanduaServer.Alerts.Alert

  @doc """
  Send an alert notification email to recipients.

  ## Examples

      iex> send_alert_email(alert, ["analyst@company.com"])
      {:ok, %Swoosh.Email{}}
  """
  def send_alert_email(%Alert{} = alert, recipients) when is_list(recipients) do
    send_alert_email(Map.from_struct(alert), recipients)
  end

  def send_alert_email(alert, recipients) when is_map(alert) and is_list(recipients) do
    email =
      new()
      |> to(format_recipients(recipients))
      |> from({"Tamandua EDR", from_address()})
      |> subject(format_subject(alert))
      |> html_body(render_alert_email(alert))
      |> text_body(render_alert_text(alert))

    case deliver(email) do
      {:ok, _} = result ->
        Logger.info("[Email] Sent alert #{alert.id} to #{length(recipients)} recipient(s)")
        result

      {:error, reason} = error ->
        Logger.error("[Email] Failed to send alert #{alert.id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Send a digest email with multiple alerts.
  """
  def send_digest(alerts, users) when is_list(alerts) and is_list(users) do
    recipients = Enum.map(users, & &1.email)

    severity_counts = Enum.frequencies_by(alerts, & &1.severity)
    total = length(alerts)

    subject = "[Tamandua EDR] Alert Digest - #{total} alert(s)"

    email =
      new()
      |> to(format_recipients(recipients))
      |> from({"Tamandua EDR", from_address()})
      |> subject(subject)
      |> html_body(render_digest_email(alerts, severity_counts))
      |> text_body(render_digest_text(alerts, severity_counts))

    case deliver(email) do
      {:ok, _} = result ->
        Logger.info("[Email] Sent digest with #{total} alerts to #{length(recipients)} recipient(s)")
        result

      {:error, reason} = error ->
        Logger.error("[Email] Failed to send digest: #{inspect(reason)}")
        error
    end
  end

  # ===========================================================================
  # Email Rendering
  # ===========================================================================

  defp render_alert_email(alert) do
    """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #{severity_color(alert.severity)}; color: white; padding: 20px; border-radius: 5px 5px 0 0; }
        .header h1 { margin: 0; font-size: 24px; }
        .severity-badge { display: inline-block; padding: 4px 12px; border-radius: 3px; font-weight: bold; text-transform: uppercase; font-size: 12px; }
        .content { background: #f9f9f9; padding: 20px; border-radius: 0 0 5px 5px; }
        .section { margin: 20px 0; }
        .section h2 { font-size: 18px; margin-bottom: 10px; color: #555; }
        .evidence-item { background: white; padding: 10px; margin: 5px 0; border-left: 3px solid #{severity_color(alert.severity)}; }
        .evidence-label { font-weight: bold; color: #666; }
        .mitre-tag { display: inline-block; background: #3b82f6; color: white; padding: 3px 8px; margin: 2px; border-radius: 3px; font-size: 12px; }
        .button { display: inline-block; background: #{severity_color(alert.severity)}; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 10px 0; }
        .footer { text-align: center; color: #999; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🚨 Security Alert</h1>
          <span class="severity-badge" style="background: #{severity_badge_color(alert.severity)};">#{String.upcase(to_string(alert.severity))}</span>
        </div>
        <div class="content">
          <div class="section">
            <h2>#{alert.title}</h2>
            <p>#{alert.description || "No description available"}</p>
          </div>

          #{render_alert_details(alert)}
          #{render_evidence_section(alert)}
          #{render_mitre_section(alert)}
          #{render_recommendations_section(alert)}

          <div class="section">
            <a href="#{alert_url(alert)}" class="button">View Alert in Dashboard</a>
            <a href="#{investigate_url(alert)}" class="button" style="background: #6366f1;">Investigate</a>
          </div>
        </div>

        <div class="footer">
          <p>Tamandua EDR | Alert ID: #{alert.id}</p>
          <p>Generated at #{format_timestamp(alert.inserted_at)}</p>
        </div>
      </div>
    </body>
    </html>
    """
  end

  defp render_alert_text(alert) do
    """
    TAMANDUA EDR - SECURITY ALERT
    #{"=" |> String.duplicate(60)}

    SEVERITY: #{String.upcase(to_string(alert.severity))}
    TITLE: #{alert.title}

    #{alert.description || "No description available"}

    ALERT DETAILS
    -------------
    Alert ID: #{alert.id}
    Agent ID: #{alert.agent_id}
    Time: #{format_timestamp(alert.inserted_at)}
    #{if alert.threat_score, do: "Threat Score: #{round(alert.threat_score * 100)}/100\n", else: ""}
    #{render_mitre_text(alert)}

    ACTIONS
    -------
    View Alert: #{alert_url(alert)}
    Investigate: #{investigate_url(alert)}

    ---
    This is an automated alert from Tamandua EDR.
    """
  end

  defp render_digest_email(alerts, severity_counts) do
    critical = Map.get(severity_counts, "critical", 0)
    high = Map.get(severity_counts, "high", 0)
    medium = Map.get(severity_counts, "medium", 0)
    low = Map.get(severity_counts, "low", 0)

    alert_rows = alerts
    |> Enum.take(10)
    |> Enum.map(&render_digest_row/1)
    |> Enum.join("\n")

    """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 700px; margin: 0 auto; padding: 20px; }
        .header { background: #1f2937; color: white; padding: 20px; border-radius: 5px 5px 0 0; }
        .summary { display: flex; justify-content: space-around; padding: 20px; background: #f3f4f6; }
        .stat { text-align: center; }
        .stat-value { font-size: 32px; font-weight: bold; }
        .stat-label { color: #6b7280; font-size: 14px; }
        .alert-list { background: white; padding: 20px; }
        .alert-row { padding: 15px; margin: 10px 0; border-left: 4px solid #ddd; background: #f9fafb; }
        .footer { text-align: center; color: #999; font-size: 12px; margin-top: 30px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>📊 Alert Digest</h1>
          <p>Summary of recent security alerts</p>
        </div>

        <div class="summary">
          #{if critical > 0, do: "<div class='stat'><div class='stat-value' style='color: #ef4444;'>#{critical}</div><div class='stat-label'>Critical</div></div>", else: ""}
          #{if high > 0, do: "<div class='stat'><div class='stat-value' style='color: #f97316;'>#{high}</div><div class='stat-label'>High</div></div>", else: ""}
          #{if medium > 0, do: "<div class='stat'><div class='stat-value' style='color: #eab308;'>#{medium}</div><div class='stat-label'>Medium</div></div>", else: ""}
          #{if low > 0, do: "<div class='stat'><div class='stat-value' style='color: #3b82f6;'>#{low}</div><div class='stat-label'>Low</div></div>", else: ""}
        </div>

        <div class="alert-list">
          <h2>Recent Alerts</h2>
          #{alert_rows}
        </div>

        <div style="text-align: center; padding: 20px;">
          <a href="#{dashboard_url()}" style="display: inline-block; background: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px;">
            View All Alerts
          </a>
        </div>

        <div class="footer">
          <p>Tamandua EDR Alert Digest</p>
          <p>Generated at #{format_timestamp(DateTime.utc_now())}</p>
        </div>
      </div>
    </body>
    </html>
    """
  end

  defp render_digest_text(alerts, severity_counts) do
    """
    TAMANDUA EDR - ALERT DIGEST
    #{"=" |> String.duplicate(60)}

    SUMMARY
    -------
    Critical: #{Map.get(severity_counts, "critical", 0)}
    High: #{Map.get(severity_counts, "high", 0)}
    Medium: #{Map.get(severity_counts, "medium", 0)}
    Low: #{Map.get(severity_counts, "low", 0)}

    RECENT ALERTS
    -------------
    #{alerts |> Enum.take(10) |> Enum.map(&render_digest_text_row/1) |> Enum.join("\n\n")}

    ---
    View all alerts: #{dashboard_url()}
    """
  end

  defp render_digest_row(alert) do
    """
    <div class="alert-row" style="border-left-color: #{severity_color(alert.severity)};">
      <strong style="color: #{severity_color(alert.severity)};">#{String.upcase(to_string(alert.severity))}</strong> - #{alert.title}
      <br>
      <small style="color: #6b7280;">#{format_timestamp(alert.inserted_at)} | Agent: #{alert.agent_id}</small>
    </div>
    """
  end

  defp render_digest_text_row(alert) do
    "[#{String.upcase(to_string(alert.severity))}] #{alert.title}\n  Time: #{format_timestamp(alert.inserted_at)} | Agent: #{alert.agent_id}"
  end

  defp render_alert_details(alert) do
    """
    <div class="section">
      <h2>Alert Details</h2>
      <div class="evidence-item">
        <div><span class="evidence-label">Alert ID:</span> #{alert.id}</div>
        <div><span class="evidence-label">Agent:</span> #{alert.agent_id}</div>
        <div><span class="evidence-label">Time:</span> #{format_timestamp(alert.inserted_at)}</div>
        #{if alert.threat_score, do: "<div><span class=\"evidence-label\">Threat Score:</span> #{round(alert.threat_score * 100)}/100</div>", else: ""}
        <div><span class="evidence-label">Status:</span> #{alert.status || "new"}</div>
      </div>
    </div>
    """
  end

  defp render_evidence_section(alert) do
    evidence = alert.evidence || %{}

    if map_size(evidence) > 0 do
      evidence_items = evidence
      |> Enum.map(fn {key, value} ->
        "<div class=\"evidence-item\"><span class=\"evidence-label\">#{format_key(key)}:</span> #{format_value(value)}</div>"
      end)
      |> Enum.join("\n")

      """
      <div class="section">
        <h2>Evidence</h2>
        #{evidence_items}
      </div>
      """
    else
      ""
    end
  end

  defp render_mitre_section(alert) do
    techniques = alert.mitre_techniques || []
    tactics = alert.mitre_tactics || []

    if Enum.empty?(techniques) and Enum.empty?(tactics) do
      ""
    else
      """
      <div class="section">
        <h2>MITRE ATT&CK</h2>
        #{if !Enum.empty?(tactics), do: "<p><strong>Tactics:</strong> #{Enum.join(tactics, ", ")}</p>", else: ""}
        #{if !Enum.empty?(techniques), do: "<p><strong>Techniques:</strong><br>#{Enum.map(techniques, fn t -> "<span class='mitre-tag'>#{t}</span>" end) |> Enum.join(" ")}</p>", else: ""}
      </div>
      """
    end
  end

  defp render_mitre_text(alert) do
    techniques = alert.mitre_techniques || []
    tactics = alert.mitre_tactics || []

    parts = []

    parts = if !Enum.empty?(tactics), do: ["MITRE Tactics: #{Enum.join(tactics, ", ")}" | parts], else: parts
    parts = if !Enum.empty?(techniques), do: ["MITRE Techniques: #{Enum.join(techniques, ", ")}" | parts], else: parts

    Enum.join(parts, "\n")
  end

  defp render_recommendations_section(alert) do
    recommendations = build_recommendations(alert)

    if Enum.empty?(recommendations) do
      ""
    else
      rec_items = recommendations
      |> Enum.map(&"<li>#{&1}</li>")
      |> Enum.join("\n")

      """
      <div class="section">
        <h2>Recommended Actions</h2>
        <ul>
          #{rec_items}
        </ul>
      </div>
      """
    end
  end

  defp build_recommendations(alert) do
    base_recs = [
      "Review the alert evidence and determine if this is a true positive",
      "Check related alerts from the same agent or time window",
      "Investigate the affected process/file/network connection"
    ]

    severity_recs = case alert.severity do
      "critical" ->
        [
          "⚠️ CRITICAL: Investigate immediately and consider isolating the affected endpoint",
          "Engage incident response team"
        ]
      "high" ->
        ["Prioritize investigation within 1 hour"]
      _ ->
        []
    end

    severity_recs ++ base_recs
  end

  # ===========================================================================
  # Formatting Helpers
  # ===========================================================================

  defp format_recipients(recipients) when is_list(recipients) do
    Enum.map(recipients, fn
      email when is_binary(email) -> {email, email}
      %{email: email, name: name} -> {name, email}
      %{email: email} -> {email, email}
    end)
  end

  defp format_subject(alert) do
    "[#{String.upcase(to_string(alert.severity))}] #{alert.title}"
  end

  defp format_key(key) when is_atom(key), do: key |> Atom.to_string() |> format_key()
  defp format_key(key) when is_binary(key) do
    key
    |> String.replace("_", " ")
    |> String.split(" ")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp format_value(value) when is_map(value) do
    value
    |> Enum.map(fn {k, v} -> "#{format_key(k)}: #{v}" end)
    |> Enum.join(", ")
  end
  defp format_value(value) when is_list(value), do: Enum.join(value, ", ")
  defp format_value(value), do: to_string(value)

  defp format_timestamp(%DateTime{} = dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  end
  defp format_timestamp(%NaiveDateTime{} = ndt) do
    ndt
    |> DateTime.from_naive!("Etc/UTC")
    |> format_timestamp()
  end
  defp format_timestamp(_), do: "Unknown"

  defp severity_color("critical"), do: "#dc2626"
  defp severity_color("high"), do: "#f97316"
  defp severity_color("medium"), do: "#eab308"
  defp severity_color("low"), do: "#3b82f6"
  defp severity_color("info"), do: "#6b7280"
  defp severity_color(_), do: "#6b7280"

  defp severity_badge_color("critical"), do: "rgba(220, 38, 38, 0.9)"
  defp severity_badge_color("high"), do: "rgba(249, 115, 22, 0.9)"
  defp severity_badge_color("medium"), do: "rgba(234, 179, 8, 0.9)"
  defp severity_badge_color(_), do: "rgba(59, 130, 246, 0.9)"

  defp alert_url(alert) do
    base_url = Application.get_env(:tamandua_server, :base_url, "http://localhost:4000")
    "#{base_url}/alerts/#{alert.id}"
  end

  defp investigate_url(alert) do
    base_url = Application.get_env(:tamandua_server, :base_url, "http://localhost:4000")
    "#{base_url}/investigate?alert_id=#{alert.id}"
  end

  defp dashboard_url do
    base_url = Application.get_env(:tamandua_server, :base_url, "http://localhost:4000")
    "#{base_url}/dashboard"
  end

  defp from_address do
    Application.get_env(:tamandua_server, :notification_from_email, "alerts@tamandua.local")
  end
end
