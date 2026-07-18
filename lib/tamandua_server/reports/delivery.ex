defmodule TamanduaServer.Reports.Delivery do
  @moduledoc """
  Report delivery system supporting multiple delivery methods:
  - Email (via Swoosh)
  - S3 upload
  - SFTP upload
  - Webhook notification
  - Local filesystem
  """

  require Logger

  alias TamanduaServer.Mailer
  import Swoosh.Email

  @doc """
  Deliver a report using the specified method.

  ## Options
  - `:method` - Delivery method (:email, :s3, :sftp, :webhook, :file)
  - `:recipients` - Email addresses (for email delivery)
  - `:bucket` - S3 bucket name (for S3 delivery)
  - `:s3_path` - S3 object key/path
  - `:sftp_host` - SFTP server hostname
  - `:sftp_path` - SFTP destination path
  - `:sftp_username` - SFTP username
  - `:sftp_password` - SFTP password
  - `:webhook_url` - Webhook URL
  - `:file_path` - Local file path
  - `:filename` - Output filename
  - `:format` - Report format (:pdf, :html, :csv, :json)
  """
  def deliver(report_data, report_content, opts \\ []) do
    method = opts[:method] || :email

    case method do
      :email -> deliver_email(report_data, report_content, opts)
      :s3 -> deliver_s3(report_data, report_content, opts)
      :sftp -> deliver_sftp(report_data, report_content, opts)
      :webhook -> deliver_webhook(report_data, report_content, opts)
      :file -> deliver_file(report_data, report_content, opts)
      _ -> {:error, {:unsupported_delivery_method, method}}
    end
  end

  # ============================================================================
  # Email Delivery
  # ============================================================================

  defp deliver_email(report_data, content, opts) do
    recipients = opts[:recipients] || []

    if Enum.empty?(recipients) do
      {:error, :no_recipients}
    else
      subject = opts[:subject] || "Tamandua EDR Report: #{report_data["title"]}"
      format = opts[:format] || :pdf
      filename = build_filename(report_data, format)

      content_type = get_content_type(format)

      email = new()
      |> to(recipients)
      |> from({"Tamandua EDR", "noreply@tamandua.local"})
      |> subject(subject)
      |> html_body(email_html_body(report_data))
      |> text_body(email_text_body(report_data))
      |> attachment(
        Swoosh.Attachment.new(
          {:data, content},
          filename: filename,
          content_type: content_type
        )
      )

      case Mailer.deliver(email) do
        {:ok, _} ->
          Logger.info("Report delivered via email to #{length(recipients)} recipient(s)")
          {:ok, :delivered}

        {:error, reason} ->
          Logger.error("Failed to deliver report via email: #{inspect(reason)}")
          {:error, {:email_delivery_failed, reason}}
      end
    end
  end

  # ============================================================================
  # S3 Delivery
  # ============================================================================

  defp deliver_s3(report_data, content, opts) do
    bucket = opts[:bucket]
    s3_path = opts[:s3_path] || build_s3_path(report_data, opts[:format] || :pdf)

    if is_nil(bucket) do
      {:error, :missing_s3_bucket}
    else
      # Use ExAws to upload to S3
      try do
        content_type = get_content_type(opts[:format] || :pdf)

        ExAws.S3.put_object(bucket, s3_path, content, [
          content_type: content_type,
          acl: :private
        ])
        |> ExAws.request()

        Logger.info("Report delivered to S3: s3://#{bucket}/#{s3_path}")
        {:ok, :delivered}
      rescue
        e ->
          Logger.error("S3 upload failed: #{inspect(e)}")
          {:error, {:s3_upload_failed, inspect(e)}}
      end
    end
  end

  # ============================================================================
  # SFTP Delivery
  # ============================================================================

  defp deliver_sftp(report_data, content, opts) do
    host = opts[:sftp_host]
    path = opts[:sftp_path]
    username = opts[:sftp_username]
    password = opts[:sftp_password]

    if is_nil(host) or is_nil(path) or is_nil(username) do
      {:error, :missing_sftp_credentials}
    else
      try do
        filename = build_filename(report_data, opts[:format] || :pdf)
        full_path = Path.join(path, filename)

        # Use ssh_sftp (requires :ssh application)
        :ssh.start()

        connect_opts = [
          {:user, String.to_charlist(username)},
          {:silently_accept_hosts, true}
        ]

        connect_opts = if password do
          connect_opts ++ [password: String.to_charlist(password)]
        else
          connect_opts
        end

        {:ok, conn} = :ssh_sftp.start_channel(String.to_charlist(host), connect_opts)

        :ok = :ssh_sftp.write_file(conn, String.to_charlist(full_path), content)

        :ssh_sftp.stop_channel(conn)

        Logger.info("Report delivered via SFTP to #{host}:#{full_path}")
        {:ok, :delivered}
      rescue
        e ->
          Logger.error("SFTP upload failed: #{inspect(e)}")
          {:error, {:sftp_upload_failed, inspect(e)}}
      end
    end
  end

  # ============================================================================
  # Webhook Delivery
  # ============================================================================

  defp deliver_webhook(report_data, content, opts) do
    url = opts[:webhook_url]

    if is_nil(url) do
      {:error, :missing_webhook_url}
    else
      # Prepare webhook payload
      payload = %{
        event: "report.generated",
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
        report: %{
          id: report_data["id"],
          title: report_data["title"],
          template_id: report_data["template_id"],
          generated_at: report_data["generated_at"],
          period: report_data["period"],
          format: to_string(opts[:format] || :pdf)
        },
        content: Base.encode64(content)
      }

      case Req.post(url, json: payload) do
        {:ok, %{status: status}} when status in 200..299 ->
          Logger.info("Report notification sent to webhook: #{url}")
          {:ok, :delivered}

        {:ok, %{status: status}} ->
          Logger.error("Webhook returned non-success status: #{status}")
          {:error, {:webhook_failed, status}}

        {:error, reason} ->
          Logger.error("Webhook request failed: #{inspect(reason)}")
          {:error, {:webhook_failed, reason}}
      end
    end
  end

  # ============================================================================
  # File System Delivery
  # ============================================================================

  defp deliver_file(_report_data, content, opts) do
    file_path = opts[:file_path]

    if is_nil(file_path) do
      {:error, :missing_file_path}
    else
      # Ensure directory exists
      file_path
      |> Path.dirname()
      |> File.mkdir_p!()

      case File.write(file_path, content) do
        :ok ->
          Logger.info("Report saved to file: #{file_path}")
          {:ok, :delivered}

        {:error, reason} ->
          Logger.error("File write failed: #{inspect(reason)}")
          {:error, {:file_write_failed, reason}}
      end
    end
  end

  # ============================================================================
  # Helper Functions
  # ============================================================================

  defp build_filename(report_data, format) do
    title = report_data["title"] || "report"
    sanitized = title
      |> String.replace(~r/[^\w\s-]/, "")
      |> String.replace(~r/\s+/, "_")
      |> String.downcase()

    date = Date.utc_today() |> Date.to_iso8601()
    "#{sanitized}_#{date}.#{format}"
  end

  defp build_s3_path(report_data, format) do
    date = Date.utc_today()
    year = date.year
    month = String.pad_leading("#{date.month}", 2, "0")
    filename = build_filename(report_data, format)

    "reports/#{year}/#{month}/#{filename}"
  end

  defp get_content_type(:pdf), do: "application/pdf"
  defp get_content_type(:html), do: "text/html"
  defp get_content_type(:csv), do: "text/csv"
  defp get_content_type(:json), do: "application/json"
  defp get_content_type(_), do: "application/octet-stream"

  defp email_html_body(report_data) do
    """
    <html>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #333;">
      <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #0066cc;">#{report_data["title"]}</h2>
        <p>A new report has been generated from Tamandua EDR.</p>

        <table style="width: 100%; margin: 20px 0; border-collapse: collapse;">
          <tr>
            <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Report Type:</strong></td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">#{report_data["template_name"]}</td>
          </tr>
          <tr>
            <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Period:</strong></td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">#{get_in(report_data, ["period", "from"])} to #{get_in(report_data, ["period", "to"])}</td>
          </tr>
          <tr>
            <td style="padding: 8px; border-bottom: 1px solid #eee;"><strong>Generated:</strong></td>
            <td style="padding: 8px; border-bottom: 1px solid #eee;">#{report_data["generated_at"]}</td>
          </tr>
        </table>

        <p>The full report is attached to this email.</p>

        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="font-size: 12px; color: #999;">
          This is an automated message from Tamandua EDR.<br>
          Do not reply to this email.
        </p>
      </div>
    </body>
    </html>
    """
  end

  defp email_text_body(report_data) do
    """
    #{report_data["title"]}

    A new report has been generated from Tamandua EDR.

    Report Type: #{report_data["template_name"]}
    Period: #{get_in(report_data, ["period", "from"])} to #{get_in(report_data, ["period", "to"])}
    Generated: #{report_data["generated_at"]}

    The full report is attached to this email.

    --
    This is an automated message from Tamandua EDR.
    Do not reply to this email.
    """
  end
end
