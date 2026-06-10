defmodule TamanduaServer.Jobs.PolicyDeploymentJob do
  @moduledoc """
  Oban job for executing scheduled policy deployments.
  """

  use Oban.Worker,
    queue: :policy_deployments,
    max_attempts: 3

  require Logger

  alias TamanduaServer.Agents.{PolicyDeployer, PolicyDeployment}
  alias TamanduaServer.Repo

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"deployment_id" => deployment_id}}) do
    Logger.info("Executing scheduled policy deployment: #{deployment_id}")

    deployment = Repo.get(PolicyDeployment, deployment_id)

    if deployment && deployment.status == "pending" do
      # Update status to in_progress
      deployment
      |> Ecto.Changeset.change(%{
        status: "in_progress",
        started_at: DateTime.utc_now()
      })
      |> Repo.update!()

      # Execute deployment based on strategy
      case deployment.strategy do
        "scheduled" ->
          # Deploy immediately (it was scheduled, now it's time)
          PolicyDeployer.deploy_to_all_agents(deployment)
          PolicyDeployer.complete_deployment(deployment)

        "phased" ->
          # Start phased rollout
          PolicyDeployer.start_phased_deployment(deployment)

        _ ->
          Logger.error("Invalid deployment strategy: #{deployment.strategy}")
          {:error, :invalid_strategy}
      end

      :ok
    else
      Logger.warning("Deployment #{deployment_id} not found or not in pending state")
      {:error, :invalid_deployment}
    end
  end
end
