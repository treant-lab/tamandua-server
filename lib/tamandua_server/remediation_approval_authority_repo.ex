defmodule TamanduaServer.RemediationApprovalAuthorityRepo do
  @moduledoc "Default-off, read-only pool for remediation approval tenant discovery v1."

  use Ecto.Repo,
    otp_app: :tamandua_server,
    adapter: Ecto.Adapters.Postgres

  def enabled? do
    Application.get_env(:tamandua_server, :remediation_approval_authority_repo_enabled, false) ==
      true
  end
end
