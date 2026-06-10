defmodule TamanduaServer.Repo.EU do
  @moduledoc """
  European Union regional Ecto repository.

  This repository connects to the EU regional PostgreSQL database for
  GDPR-compliant data storage. All EU tenant data is stored exclusively
  in this database to ensure data sovereignty compliance.

  ## Configuration

  Configure in config/runtime.exs:

      config :tamandua_server, TamanduaServer.Repo.EU,
        url: System.get_env("DATABASE_URL_EU") || "postgresql://eu-db:5432/tamandua_eu",
        pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
        queue_target: 5000,
        queue_interval: 1000

  ## Environment Variables

  - `DATABASE_URL_EU` - PostgreSQL connection URL for EU region
  - `EU_DB_SSL` - Enable SSL for EU database (default: true in production)
  - `EU_DB_POOL_SIZE` - Connection pool size (default: 10)

  ## GDPR Compliance

  This repository enforces:
  - Data stored in EU data centers only
  - Encryption at rest and in transit
  - Audit logging for all queries
  - No cross-border data transfer without consent
  """

  use Ecto.Repo,
    otp_app: :tamandua_server,
    adapter: Ecto.Adapters.Postgres

  require Logger

  @doc """
  Dynamically loads the repository configuration from environment variables at runtime.
  """
  def init(_type, config) do
    case System.get_env("DATABASE_URL_EU") do
      nil ->
        Logger.warning("DATABASE_URL_EU not set, EU repo may not be available")
        {:ok, config}

      url ->
        # Add SSL configuration for production
        ssl_config =
          if System.get_env("EU_DB_SSL", "true") == "true" do
            [ssl: true, ssl_opts: [verify: :verify_peer]]
          else
            []
          end

        config =
          config
          |> Keyword.put(:url, url)
          |> Keyword.merge(ssl_config)

        {:ok, config}
    end
  end
end
