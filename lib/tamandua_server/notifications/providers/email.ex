defmodule TamanduaServer.Notifications.Providers.Email do
  @moduledoc """
  Email notification provider.

  Uses Swoosh with SMTP configuration.
  """

  @behaviour TamanduaServer.Notifications.Providers.Base

  import Swoosh.Email

  @impl true
  def send_notification(integration, rendered_title, rendered_body) do
    config = integration.config

    # Build email
    email =
      new()
      |> from(config["from"] || config[:from])
      |> to(config["to"] || config[:to] || config["from"] || config[:from])
      |> subject(rendered_title)
      |> text_body(rendered_body)
      |> html_body(markdown_to_html(rendered_body))

    # Send via SMTP
    case deliver_email(email, config) do
      {:ok, _} -> {:ok, %{status: "sent"}}
      {:error, reason} -> {:error, inspect(reason)}
    end
  end

  @impl true
  def test_connection(config) do
    test_email =
      new()
      |> from(config["from"] || config[:from])
      |> to(config["to"] || config[:to] || config["from"] || config[:from])
      |> subject("Tamandua EDR Test Notification")
      |> text_body("✅ Your email integration is configured correctly!")
      |> html_body("<p>✅ <strong>Your email integration is configured correctly!</strong></p>")

    case deliver_email(test_email, config) do
      {:ok, _} -> {:ok, "Test email sent successfully"}
      {:error, reason} -> {:error, inspect(reason)}
    end
  end

  # Private helpers

  defp deliver_email(email, config) do
    # Build SMTP adapter config
    adapter_config = [
      relay: config["smtp_host"] || config[:smtp_host],
      port: config["smtp_port"] || config[:smtp_port] || 587,
      username: config["username"] || config[:username],
      password: config["password"] || config[:password],
      tls: :if_available,
      ssl: false,
      retries: 2
    ]

    # Use Swoosh SMTP adapter
    TamanduaServer.Mailer.deliver(email, config: adapter_config)
  end

  defp markdown_to_html(text) do
    # Basic markdown conversion (in production, use Earmark or similar)
    text
    |> String.replace(~r/\*\*(.+?)\*\*/, "<strong>\\1</strong>")
    |> String.replace(~r/\*(.+?)\*/, "<em>\\1</em>")
    |> String.replace("\n\n", "</p><p>")
    |> String.replace("\n", "<br>")
    |> then(&("<p>#{&1}</p>"))
  end
end
