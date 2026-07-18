defmodule TamanduaServer.IocSnapshotAuthorityRepo do
  @moduledoc """
  Default-off, read-only pool for the IOC snapshot authority v1 capability.

  The application supervises this repository only when `authority_v1` is
  explicitly selected. Provider initialization requires the pool and provider
  switches to agree before the supervision tree starts.
  """

  use Ecto.Repo,
    otp_app: :tamandua_server,
    adapter: Ecto.Adapters.Postgres

  def enabled? do
    Application.get_env(:tamandua_server, :ioc_snapshot_authority_repo_enabled, false) == true
  end
end
