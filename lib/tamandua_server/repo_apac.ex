defmodule TamanduaServer.Repo.APAC do
  @moduledoc """
  Asia-Pacific regional Ecto repository.

  This repository connects to the APAC regional PostgreSQL database.
  All APAC tenant data is stored exclusively in this database.

  ## Configuration

  Configure in config/runtime.exs:

      config :tamandua_server, TamanduaServer.Repo.APAC,
        url: System.get_env("DATABASE_URL_APAC") || "postgresql://apac-db:5432/tamandua_apac",
        pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
        queue_target: 5000,
        queue_interval: 1000

  ## Environment Variables

  - `DATABASE_URL_APAC` - PostgreSQL connection URL for APAC region
  - `APAC_DB_SSL` - Enable SSL for APAC database (default: true in production)
  - `APAC_DB_POOL_SIZE` - Connection pool size (default: 10)
  """

  use Ecto.Repo,
    otp_app: :tamandua_server,
    adapter: Ecto.Adapters.Postgres

  require Logger

  def init(_type, config) do
    case System.get_env("DATABASE_URL_APAC") do
      nil ->
        Logger.warning("DATABASE_URL_APAC not set, APAC repo may not be available")
        {:ok, config}

      url ->
        ssl_config =
          if System.get_env("APAC_DB_SSL", "true") == "true" do
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
