defmodule TamanduaServer.Workers.ScreenCaptureRetentionWorker do
  @moduledoc """
  Erases expired screen-capture bytes and one-time upload credentials.

  The global job uses the bounded retention authority to discover organization
  IDs that have expired artifacts. Every mutation then runs inside that
  organization's RLS context through `ScreenCaptureArtifacts.cleanup_expired/1`.
  """

  use Oban.Worker,
    queue: :default,
    max_attempts: 3,
    unique: [period: 240]

  alias TamanduaServer.LiveResponse.ScreenCaptureArtifacts
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Workers.RetentionOrganizationDiscovery

  require Logger

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) when map_size(args) == 0 do
    with {:ok, organization_ids} <- organizations_due_for_cleanup() do
      cleaned =
        Enum.reduce(organization_ids, 0, fn organization_id, total ->
          {:ok, count} =
            MultiTenant.with_organization(organization_id, fn ->
              ScreenCaptureArtifacts.cleanup_expired(organization_id)
            end)

          total + count
        end)

      Logger.info(
        "[ScreenCaptureRetentionWorker] expired_artifacts=#{cleaned} organizations=#{length(organization_ids)}"
      )

      :ok
    end
  end

  def perform(%Oban.Job{}), do: {:discard, :unexpected_arguments}

  @doc false
  def organizations_due_for_cleanup(now \\ DateTime.utc_now()) do
    RetentionOrganizationDiscovery.discover(now)
  end
end
