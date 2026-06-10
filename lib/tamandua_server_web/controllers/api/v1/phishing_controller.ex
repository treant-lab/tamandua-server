defmodule TamanduaServerWeb.API.V1.PhishingController do
  @moduledoc """
  API Controller for the Phishing Email Analysis and Triage Engine.

  Provides endpoints for:
  - Submitting emails for phishing analysis (raw EML or parsed JSON)
  - Retrieving analysis reports
  - Listing detected phishing campaigns
  - Viewing aggregate phishing statistics
  - Simplified user-reported phishing submissions
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.Detection.Phishing

  action_fallback TamanduaServerWeb.FallbackController

  # ============================================================================
  # POST /api/v1/phishing/analyze
  # ============================================================================

  @doc """
  Submit an email for phishing analysis.

  Accepts either:
  - Raw EML content in `raw_content` field
  - Pre-parsed JSON with `headers`, `body`, `html_body`, `attachments`, etc.

  Returns a full analysis report with verdict, confidence, component scores,
  extracted IOCs, and recommended actions.
  """
  def analyze(conn, params) do
    email_data = %{
      raw_content: params["raw_content"],
      headers: normalize_headers(params["headers"]),
      body: params["body"],
      html_body: params["html_body"],
      subject: params["subject"],
      from: params["from"],
      to: params["to"],
      reply_to: params["reply_to"],
      return_path: params["return_path"],
      message_id: params["message_id"],
      attachments: normalize_attachments(params["attachments"]),
      reported_by: params["reported_by"] || get_current_user_id(conn),
      organization_id: params["organization_id"] || get_org_id(conn),
      agent_id: params["agent_id"]
    }

    case Phishing.analyze(email_data) do
      {:ok, report} ->
        conn
        |> put_status(:ok)
        |> json(%{
          data: serialize_report(report)
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Analysis failed", reason: inspect(reason)})
    end
  rescue
    e ->
      Logger.error("[PhishingController] analyze error: #{Exception.message(e)}")
      conn
      |> put_status(:internal_server_error)
      |> json(%{error: "Internal error during phishing analysis"})
  end

  # ============================================================================
  # GET /api/v1/phishing/report/:id
  # ============================================================================

  @doc """
  Retrieve a previously-generated phishing analysis report.
  """
  def report(conn, %{"id" => report_id}) do
    case Phishing.get_report(report_id) do
      {:ok, report} ->
        json(conn, %{data: serialize_report(report)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Report not found", id: report_id})
    end
  end

  # ============================================================================
  # GET /api/v1/phishing/campaigns
  # ============================================================================

  @doc """
  List detected phishing campaigns.

  Query params:
  - `status` - Filter by campaign status ("active", "pending")
  - `limit` - Maximum results (default 50)
  """
  def campaigns(conn, params) do
    opts = [
      status: params["status"],
      limit: parse_int(params["limit"], 50)
    ]

    campaigns = Phishing.list_campaigns(opts)

    json(conn, %{
      data: Enum.map(campaigns, &serialize_campaign/1),
      total: length(campaigns)
    })
  rescue
    e ->
      Logger.error("[PhishingController] campaigns error: #{Exception.message(e)}")
      conn
      |> put_status(503)
      |> json(%{error: "Phishing analysis service unavailable", data: [], total: 0})
  end

  # ============================================================================
  # GET /api/v1/phishing/stats
  # ============================================================================

  @doc """
  Get aggregate phishing analysis statistics.
  """
  def stats(conn, _params) do
    stats = Phishing.get_stats()

    json(conn, %{
      data: %{
        total_analyzed: stats.total_analyzed,
        verdicts: stats.verdicts,
        avg_score: stats.avg_score,
        campaigns_detected: stats.campaigns_detected,
        attachments_detonated: stats.attachments_detonated,
        urls_checked: stats.urls_checked,
        cached_submissions: stats[:cached_submissions] || 0,
        active_campaigns: stats[:active_campaigns] || 0,
        uptime_seconds: stats[:uptime_seconds] || 0,
        started_at: format_datetime(stats[:started_at])
      }
    })
  rescue
    e ->
      Logger.error("[PhishingController] stats error: #{Exception.message(e)}")
      conn
      |> put_status(503)
      |> json(%{error: "Phishing stats service unavailable", data: %{total_analyzed: 0, verdicts: %{}, avg_score: 0.0}})
  end

  # ============================================================================
  # POST /api/v1/phishing/report-phish
  # ============================================================================

  @doc """
  Simplified endpoint for user-reported phishing.

  Accepts minimal fields: `from`, `subject`, `body`, and optional
  `headers` and `attachments`. Designed for end-user phish-report buttons.
  """
  def report_phish(conn, params) do
    submission = %{
      "from" => params["from"],
      "subject" => params["subject"],
      "body" => params["body"],
      "html_body" => params["html_body"],
      "headers" => params["headers"],
      "attachments" => params["attachments"],
      "reported_by" => params["reported_by"] || get_current_user_id(conn),
      "organization_id" => params["organization_id"] || get_org_id(conn)
    }

    case Phishing.report_phish(submission) do
      {:ok, report} ->
        conn
        |> put_status(:created)
        |> json(%{
          data: serialize_report(report),
          message: "Thank you for reporting. Analysis complete."
        })

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to analyze reported email", reason: inspect(reason)})
    end
  rescue
    e ->
      Logger.error("[PhishingController] report_phish error: #{Exception.message(e)}")
      conn
      |> put_status(:internal_server_error)
      |> json(%{error: "Internal error processing phishing report"})
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp serialize_report(report) when is_map(report) do
    %{
      id: report[:id],
      submitted_at: format_datetime(report[:submitted_at]),
      completed_at: format_datetime(report[:completed_at]),
      verdict: report[:verdict],
      confidence: report[:confidence],
      score: report[:score],
      component_scores: report[:component_scores],
      header_analysis: serialize_analysis(report[:header_analysis]),
      url_analysis: serialize_url_analysis(report[:url_analysis]),
      attachment_analysis: serialize_attachment_analysis(report[:attachment_analysis]),
      sender_analysis: serialize_sender_analysis(report[:sender_analysis]),
      content_analysis: serialize_analysis(report[:content_analysis]),
      campaign: report[:campaign],
      iocs: report[:iocs],
      recommendations: serialize_recommendations(report[:recommendations]),
      subject: report[:subject],
      from: report[:from],
      to: report[:to],
      message_id: report[:message_id],
      organization_id: report[:organization_id],
      submitted_by: report[:submitted_by]
    }
  end

  defp serialize_analysis(nil), do: nil
  defp serialize_analysis(analysis) when is_map(analysis) do
    %{
      score: analysis[:score],
      findings: serialize_findings(analysis[:findings])
    }
    |> maybe_add(:spf, analysis[:spf])
    |> maybe_add(:dkim, analysis[:dkim])
    |> maybe_add(:dmarc, analysis[:dmarc])
    |> maybe_add(:received_hops, analysis[:received_hops])
  end

  defp serialize_url_analysis(nil), do: nil
  defp serialize_url_analysis(analysis) do
    %{
      score: analysis[:score],
      total_urls: analysis[:total_urls],
      shorteners_found: analysis[:shorteners_found],
      homograph_attacks: analysis[:homograph_attacks],
      malicious_urls: analysis[:malicious_urls],
      urls: Enum.map(analysis[:urls] || [], fn u ->
        %{
          url: u.url,
          host: u.host,
          score: u.score,
          findings: serialize_findings(u.findings),
          is_shortener: u.is_shortener,
          homograph_detected: u.homograph_detected,
          typosquat_detected: u.typosquat_detected,
          ioc_match: u.ioc_match,
          defanged: u.defanged
        }
      end)
    }
  end

  defp serialize_attachment_analysis(nil), do: nil
  defp serialize_attachment_analysis(analysis) do
    %{
      score: analysis[:score],
      total: analysis[:total],
      attachments: Enum.map(analysis[:attachments] || [], fn a ->
        %{
          filename: a.filename,
          extension: a.extension,
          content_type: a.content_type,
          detected_type: a.detected_type,
          size: a.size,
          score: a.score,
          findings: serialize_findings(a.findings),
          hashes: a.hashes,
          sandbox_submission_id: a.sandbox_submission_id
        }
      end)
    }
  end

  defp serialize_sender_analysis(nil), do: nil
  defp serialize_sender_analysis(analysis) do
    %{
      score: analysis[:score],
      email: analysis[:email],
      domain: analysis[:domain],
      display_name: analysis[:display_name],
      findings: serialize_findings(analysis[:findings]),
      typosquat: %{
        detected: analysis[:typosquat][:detected],
        brand: analysis[:typosquat][:brand],
        description: analysis[:typosquat][:description]
      }
    }
  end

  defp serialize_findings(nil), do: []
  defp serialize_findings(findings) when is_list(findings) do
    Enum.map(findings, fn
      {type, description, points} ->
        %{type: type, description: description, points: points}
      {type, description} ->
        %{type: type, description: description}
      other ->
        %{raw: inspect(other)}
    end)
  end

  defp serialize_recommendations(nil), do: []
  defp serialize_recommendations(recs) when is_list(recs) do
    Enum.map(recs, fn
      %{action: action, priority: priority, reason: reason} ->
        %{action: action, priority: priority, reason: reason}
      other ->
        other
    end)
  end

  defp serialize_campaign(campaign) when is_map(campaign) do
    %{
      id: campaign[:id],
      name: campaign[:name],
      sender_domain: campaign[:sender_domain],
      email_count: campaign[:email_count],
      first_seen: format_datetime(campaign[:first_seen]),
      last_seen: format_datetime(campaign[:last_seen]),
      status: campaign[:status],
      url_hosts: campaign[:url_hosts] || [],
      attach_hashes: campaign[:attach_hashes] || []
    }
  end

  defp normalize_headers(nil), do: %{}
  defp normalize_headers(headers) when is_map(headers), do: headers
  defp normalize_headers(_), do: %{}

  defp normalize_attachments(nil), do: []
  defp normalize_attachments(attachments) when is_list(attachments) do
    Enum.map(attachments, fn att ->
      %{
        filename: att["filename"],
        content_type: att["content_type"],
        size: att["size"],
        content: decode_content(att["content_base64"]),
        content_bytes: decode_content(att["content_base64"]),
        md5: att["md5"],
        sha1: att["sha1"],
        sha256: att["sha256"]
      }
    end)
  end
  defp normalize_attachments(_), do: []

  defp decode_content(nil), do: nil
  defp decode_content(base64) when is_binary(base64) do
    case Base.decode64(base64) do
      {:ok, bytes} -> bytes
      :error -> nil
    end
  end
  defp decode_content(_), do: nil

  defp get_current_user_id(conn) do
    case conn.assigns[:current_user] do
      %{id: id} -> id
      _ -> nil
    end
  end

  defp get_org_id(conn) do
    conn.assigns[:organization_id] || conn.assigns[:org_id]
  end

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_datetime(%NaiveDateTime{} = ndt), do: NaiveDateTime.to_iso8601(ndt)
  defp format_datetime(other), do: to_string(other)

  defp parse_int(nil, default), do: default
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(_, default), do: default

  defp maybe_add(map, _key, nil), do: map
  defp maybe_add(map, key, val), do: Map.put(map, key, val)
end
