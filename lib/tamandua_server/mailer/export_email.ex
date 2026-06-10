defmodule TamanduaServer.Mailer.ExportEmail do
  @moduledoc """
  Email templates for alert export delivery.
  """

  import Swoosh.Email

  @doc """
  Sends an export email with attachment.
  """
  def deliver_export_email(recipients, subject, message, file_path) do
    filename = Path.basename(file_path)

    new()
    |> to(recipients)
    |> from({"Tamandua EDR", "noreply@treantlab.org"})
    |> subject(subject)
    |> html_body(build_html_body(message, filename))
    |> text_body(build_text_body(message, filename))
    |> attachment(file_path)
    |> TamanduaServer.Mailer.deliver()
  end

  defp build_html_body(message, filename) do
    """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
          line-height: 1.6;
          color: #333;
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }
        .header {
          background: #1f2937;
          color: white;
          padding: 20px;
          border-radius: 8px 8px 0 0;
        }
        .content {
          background: #f9fafb;
          padding: 20px;
          border: 1px solid #e5e7eb;
          border-top: none;
          border-radius: 0 0 8px 8px;
        }
        .attachment {
          background: white;
          border: 1px solid #e5e7eb;
          border-radius: 6px;
          padding: 15px;
          margin-top: 20px;
        }
        .attachment-icon {
          display: inline-block;
          width: 40px;
          height: 40px;
          background: #eff6ff;
          border-radius: 6px;
          text-align: center;
          line-height: 40px;
          margin-right: 10px;
          font-size: 20px;
        }
        .footer {
          margin-top: 20px;
          padding-top: 20px;
          border-top: 1px solid #e5e7eb;
          font-size: 12px;
          color: #6b7280;
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1 style="margin: 0;">Alert Export Report</h1>
      </div>
      <div class="content">
        <p>#{message}</p>

        <div class="attachment">
          <span class="attachment-icon">📄</span>
          <strong>#{filename}</strong>
        </div>

        <p style="margin-top: 20px; font-size: 14px; color: #6b7280;">
          This export was generated on #{format_datetime(DateTime.utc_now())}.
        </p>
      </div>
      <div class="footer">
        <p>This is an automated message from Tamandua EDR. Please do not reply to this email.</p>
      </div>
    </body>
    </html>
    """
  end

  defp build_text_body(message, filename) do
    """
    Alert Export Report
    ===================

    #{message}

    Attached: #{filename}

    Generated: #{format_datetime(DateTime.utc_now())}

    ---
    This is an automated message from Tamandua EDR. Please do not reply to this email.
    """
  end

  defp format_datetime(dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S UTC")
  end
end
