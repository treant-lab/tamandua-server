defmodule TamanduaServer.AgenticRestoreAuthorityRepo do
  @moduledoc """
  Default-off pool for the agentic restore v1 tenant-discovery capability.

  This identity is separate from both the runtime repository and the retention
  authority. It is not a migration repository and never receives tenant data.
  """

  use Ecto.Repo,
    otp_app: :tamandua_server,
    adapter: Ecto.Adapters.Postgres

  def enabled? do
    Application.get_env(:tamandua_server, :agentic_restore_authority_repo_enabled, false) ==
      true
  end
end
