defmodule TamanduaServer.Workers.EvidenceSessionRetentionWorker do
  use Oban.Worker, queue: :default, max_attempts: 3, unique: [period: 240]

  alias TamanduaServer.LiveResponse.{
    EvidenceSessionDiffs,
    EvidenceSessionExports
  }

  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Workers.RetentionOrganizationDiscovery

  @impl true
  def perform(%Oban.Job{args: args}) when map_size(args) == 0 do
    with {:ok, organization_ids} <- organizations_due() do
      Enum.each(organization_ids, fn organization_id ->
        MultiTenant.with_organization(organization_id, fn ->
          EvidenceSessionExports.cleanup_expired(organization_id)
          EvidenceSessionDiffs.cleanup_expired(organization_id)
        end)
      end)

      :ok
    end
  end

  def perform(%Oban.Job{}), do: {:discard, :unexpected_arguments}

  @doc false
  def organizations_due(now \\ DateTime.utc_now()),
    do: RetentionOrganizationDiscovery.discover(now)
end
