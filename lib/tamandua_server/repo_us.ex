defmodule TamanduaServer.Repo.US do
  @moduledoc """
  United States regional Ecto repository.

  This repository connects to the US regional PostgreSQL database for
  CCPA-compliant data storage. All US tenant data is stored exclusively
  in this database.

  ## Configuration

  Configure in config/runtime.exs:

      config :tamandua_server, TamanduaServer.Repo.US,
        url: System.get_env("DATABASE_URL_US") || "postgresql://us-db:5432/tamandua_us",
        pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
        queue_target: 5000,
        queue_interval: 1000

  ## Environment Variables

  - `DATABASE_URL_US` - PostgreSQL connection URL for US region
  - `US_DB_SSL` - Enable SSL for US database (default: true in production)
  - `US_DB_POOL_SIZE` - Connection pool size (default: 10)
  """

  use Ecto.Repo,
    otp_app: :tamandua_server,
    adapter: Ecto.Adapters.Postgres

  require Logger

  def init(_type, config) do
    case System.get_env("DATABASE_URL_US") do
      nil ->
        Logger.warning("DATABASE_URL_US not set, US repo may not be available")
        {:ok, config}

      url ->
        ssl_config =
          if System.get_env("US_DB_SSL", "true") == "true" do
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
