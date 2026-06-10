defmodule TamanduaServer.Mailer.NotificationEmail do
  @moduledoc """
  Email templates for notifications.
  """
  import Swoosh.Email

  def send_notification_email(to_email, subject, body) do
    from_email = Application.get_env(:tamandua_server, :notification_from_email, "noreply@treantlab.org")
    from_name = Application.get_env(:tamandua_server, :notification_from_name, "Tamandua EDR")

    new()
    |> to(to_email)
    |> from({from_name, from_email})
    |> subject(subject)
    |> html_body(build_html_body(subject, body))
    |> text_body(body)
    |> TamanduaServer.Mailer.deliver()
  end

  defp build_html_body(subject, body) do
    """
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
          background-color: #1e40af;
          color: white;
          padding: 20px;
          border-radius: 8px 8px 0 0;
        }
        .content {
          background-color: #f9fafb;
          padding: 20px;
          border: 1px solid #e5e7eb;
          border-top: none;
        }
        .footer {
          background-color: #f3f4f6;
          padding: 15px;
          text-align: center;
          font-size: 12px;
          color: #6b7280;
          border-radius: 0 0 8px 8px;
        }
        .button {
          display: inline-block;
          padding: 12px 24px;
          background-color: #1e40af;
          color: white;
          text-decoration: none;
          border-radius: 6px;
          margin-top: 15px;
        }
        .body-content {
          white-space: pre-wrap;
          word-wrap: break-word;
        }
      </style>
    </head>
    <body>
      <div class="header">
        <h1 style="margin: 0; font-size: 24px;">#{subject}</h1>
      </div>
      <div class="content">
        <div class="body-content">#{body}</div>
      </div>
      <div class="footer">
        <p>This is an automated notification from Tamandua EDR</p>
        <p>To manage your notification preferences, visit your account settings</p>
      </div>
    </body>
    </html>
    """
  end
end
