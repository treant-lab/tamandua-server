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
  def list_actions(filters \\ %{})

  def list_actions(%{organization_id: organization_id} = filters)
      when is_binary(organization_id) and organization_id != "" do
    query =
      from(a in Action,
        where: a.organization_id == ^organization_id,
        order_by: [desc: a.inserted_at]
      )

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

    query = if filters[:action_type] do
      where(query, [a], a.action_type == ^filters[:action_type])
    else
      query
    end

    query = if filters[:requested_by_id] do
      where(query, [a], a.executed_by_id == ^filters[:requested_by_id])
    else
      query
    end

    query = if filters[:since] do
      where(query, [a], a.inserted_at >= ^filters[:since])
    else
      query
    end

    query = if filters[:until] do
      where(query, [a], a.inserted_at <= ^filters[:until])
    else
      query
    end

    limit = filters |> Map.get(:limit, 100) |> normalize_limit()
    offset = filters |> Map.get(:offset, 0) |> normalize_offset()

    query
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  def list_actions(_filters), do: []

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

  defp normalize_limit(value) when is_integer(value), do: value |> max(1) |> min(100)
  defp normalize_limit(_value), do: 100

  defp normalize_offset(value) when is_integer(value), do: max(value, 0)
  defp normalize_offset(_value), do: 0
end
