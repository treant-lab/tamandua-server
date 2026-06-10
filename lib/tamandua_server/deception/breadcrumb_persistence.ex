defmodule TamanduaServer.Deception.BreadcrumbPersistence do
  @moduledoc """
  Helper module for persisting breadcrumb deployments to the database.

  This bridges the in-memory Breadcrumbs GenServer state with the
  persistent database storage for tracking and auditing.
  """

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Deception.BreadcrumbDeployment

  @doc """
  Persist a breadcrumb deployment to the database.
  """
  def persist_deployment(breadcrumb) do
    attrs = %{
      id: breadcrumb.id,
      agent_id: breadcrumb.agent_id,
      type: to_string(breadcrumb.type),
      path: breadcrumb.path,
      content_hash: breadcrumb.content_hash,
      canary_token: breadcrumb.canary_token,
      deployed_at: breadcrumb.deployed_at,
      last_rotated_at: breadcrumb.last_rotated_at,
      status: to_string(breadcrumb.status),
      access_count: breadcrumb.access_count,
      metadata: breadcrumb.metadata
    }

    %BreadcrumbDeployment{}
    |> BreadcrumbDeployment.changeset(attrs)
    |> Repo.insert(
      on_conflict: {:replace_all_except, [:id, :inserted_at]},
      conflict_target: :id
    )
    |> case do
      {:ok, deployment} ->
        Logger.debug("Persisted breadcrumb deployment: #{deployment.id}")
        {:ok, deployment}

      {:error, changeset} ->
        Logger.error("Failed to persist breadcrumb: #{inspect(changeset.errors)}")
        {:error, changeset}
    end
  end

  @doc """
  Persist multiple breadcrumb deployments in a batch.
  """
  def persist_deployments(breadcrumbs) when is_list(breadcrumbs) do
    results =
      Enum.map(breadcrumbs, fn breadcrumb ->
        persist_deployment(breadcrumb)
      end)

    successful = Enum.count(results, fn {status, _} -> status == :ok end)
    failed = Enum.count(results, fn {status, _} -> status == :error end)

    Logger.info("Persisted #{successful} breadcrumbs (#{failed} failed)")

    {:ok, %{successful: successful, failed: failed, results: results}}
  end

  @doc """
  Load breadcrumb deployments from the database for an agent.
  """
  def load_deployments(agent_id) do
    from(b in BreadcrumbDeployment,
      where: b.agent_id == ^agent_id and b.status in ["active", "accessed"],
      order_by: [desc: b.deployed_at]
    )
    |> Repo.all()
    |> Enum.map(&deployment_to_map/1)
  end

  @doc """
  Load all active breadcrumb deployments.
  """
  def load_all_active do
    from(b in BreadcrumbDeployment,
      where: b.status in ["active", "accessed"],
      order_by: [desc: b.deployed_at]
    )
    |> Repo.all()
    |> Enum.map(&deployment_to_map/1)
  end

  @doc """
  Update breadcrumb status in the database.
  """
  def update_status(breadcrumb_id, status) do
    from(b in BreadcrumbDeployment, where: b.id == ^breadcrumb_id)
    |> Repo.update_all(set: [status: to_string(status), updated_at: DateTime.utc_now()])
    |> case do
      {1, _} ->
        Logger.debug("Updated breadcrumb #{breadcrumb_id} status to #{status}")
        :ok

      {0, _} ->
        Logger.warning("Breadcrumb #{breadcrumb_id} not found for status update")
        {:error, :not_found}
    end
  end

  @doc """
  Delete a breadcrumb deployment from the database.
  """
  def delete_deployment(breadcrumb_id) do
    from(b in BreadcrumbDeployment, where: b.id == ^breadcrumb_id)
    |> Repo.delete_all()
    |> case do
      {1, _} ->
        Logger.debug("Deleted breadcrumb deployment: #{breadcrumb_id}")
        :ok

      {0, _} ->
        Logger.warning("Breadcrumb #{breadcrumb_id} not found for deletion")
        {:error, :not_found}
    end
  end

  @doc """
  Get breadcrumb deployment statistics.
  """
  def get_statistics do
    total_query =
      from(b in BreadcrumbDeployment,
        select: count(b.id)
      )

    active_query =
      from(b in BreadcrumbDeployment,
        where: b.status == "active",
        select: count(b.id)
      )

    accessed_query =
      from(b in BreadcrumbDeployment,
        where: b.status == "accessed",
        select: count(b.id)
      )

    by_type_query =
      from(b in BreadcrumbDeployment,
        group_by: b.type,
        select: {b.type, count(b.id)}
      )

    by_agent_query =
      from(b in BreadcrumbDeployment,
        where: b.status in ["active", "accessed"],
        group_by: b.agent_id,
        select: {b.agent_id, count(b.id)}
      )

    %{
      total: Repo.one(total_query),
      active: Repo.one(active_query),
      accessed: Repo.one(accessed_query),
      by_type: Repo.all(by_type_query) |> Map.new(),
      by_agent: Repo.all(by_agent_query) |> Map.new()
    }
  rescue
    e ->
      Logger.error("Error fetching breadcrumb statistics: #{inspect(e)}")
      %{error: "Failed to fetch statistics"}
  end

  # Private helpers

  defp deployment_to_map(deployment) do
    %{
      id: deployment.id,
      agent_id: deployment.agent_id,
      type: String.to_existing_atom(deployment.type),
      path: deployment.path,
      content_hash: deployment.content_hash,
      canary_token: deployment.canary_token,
      deployed_at: deployment.deployed_at,
      last_rotated_at: deployment.last_rotated_at,
      status: String.to_existing_atom(deployment.status),
      access_count: deployment.access_count,
      metadata: deployment.metadata
    }
  rescue
    _ ->
      Logger.warning("Failed to convert deployment to map: #{deployment.id}")
      nil
  end
end
