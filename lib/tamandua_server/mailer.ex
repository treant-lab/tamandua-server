defmodule TamanduaServer.Mailer do
  @moduledoc """
  Swoosh mailer for sending email notifications from the Tamandua EDR platform.

  Configuration is set in config/config.exs (or runtime.exs for production).

  Example production configuration with SMTP:

      config :tamandua_server, TamanduaServer.Mailer,
        adapter: Swoosh.Adapters.SMTP,
        relay: "smtp.example.com",
        port: 587,
        username: "alerts@example.com",
        password: "secret",
        tls: :always

  Example with Mailgun:

      config :tamandua_server, TamanduaServer.Mailer,
        adapter: Swoosh.Adapters.Mailgun,
        api_key: "key-xxx",
        domain: "mg.example.com"
  """

  use Swoosh.Mailer, otp_app: :tamandua_server
end
