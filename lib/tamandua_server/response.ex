defmodule TamanduaServer.Response do
  @moduledoc """
  The Response context.
  Handles response actions management.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Response.Action

  @doc """
  Create a response action record.
  """
  def create_action(attrs) do
    %Action{}
    |> Action.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a response action with results.
  """
  def update_action_result(%Action{} = action, attrs) do
    action
    |> Action.result_changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Get a response action by ID.
  """
  def get_action!(id), do: Repo.get!(Action, id)

  @doc """
  List response actions with filters.

  Supports filtering by:
  - :organization_id - Required for multi-tenant isolation
  - :agent_id - Filter by specific agent
  - :alert_id - Filter by specific alert
  - :status - Filter by action status
  """
  def list_actions(filters \\ %{}) do
    query = from(a in Action, order_by: [desc: a.inserted_at])

    query = if filters[:organization_id] do
      where(query, [a], a.organization_id == ^filters[:organization_id])
    else
      query
    end

    query = if filters[:agent_id] do
      where(query, [a], a.agent_id == ^filters[:agent_id])
    else
      query
    end

    query = if filters[:alert_id] do
      where(query, [a], a.alert_id == ^filters[:alert_id])
    else
      query
    end

    query = if filters[:status] do
      where(query, [a], a.status == ^filters[:status])
    else
      query
    end

    Repo.all(query)
  end

  @doc """
  Get pending actions for an agent.
  Used when an agent comes online to execute queued actions.
  """
  def get_pending_actions(agent_id) do
    from(a in Action,
      where: a.agent_id == ^agent_id and a.status == "pending",
      order_by: [asc: a.inserted_at]
    )
    |> Repo.all()
  end
end
