defmodule TamanduaServer.AuthorityRepo do
  @moduledoc """
  Default-off PostgreSQL pool for narrowly provisioned cross-tenant authority.

  This repository is never a fallback for `TamanduaServer.Repo`, never carries
  request tenant context, and is not an application migration repository.
  """

  use Ecto.Repo,
    otp_app: :tamandua_server,
    adapter: Ecto.Adapters.Postgres

  def enabled? do
    Application.get_env(:tamandua_server, :authority_repo_enabled, false) == true
  end
end
