defmodule TamanduaServer.EnrollmentLocatorRepo do
  @moduledoc """
  Default-off pool for the enrollment digest locator v1 capability.

  This pool may return only an installation token ID and its tenant ID. It is
  separate from runtime, retention, and agentic-restore database identities.
  """

  use Ecto.Repo,
    otp_app: :tamandua_server,
    adapter: Ecto.Adapters.Postgres

  def enabled? do
    Application.get_env(:tamandua_server, :enrollment_locator_repo_enabled, false) == true
  end
end
