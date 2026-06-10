defmodule TamanduaServer.Repo.JP do
  @moduledoc """
  Japan regional Ecto repository.
  """
  use Ecto.Repo,
    otp_app: :tamandua_server,
    adapter: Ecto.Adapters.Postgres

  require Logger

  def init(_type, config) do
    case System.get_env("DATABASE_URL_JP") do
      nil -> {:ok, config}
      url -> {:ok, Keyword.put(config, :url, url)}
    end
  end
end
