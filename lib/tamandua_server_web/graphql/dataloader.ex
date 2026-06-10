defmodule TamanduaServerWeb.GraphQL.DataLoader do
  @moduledoc """
  Dataloader configuration for efficient batched data loading.
  """

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Telemetry.Event
  alias TamanduaServer.Accounts.{User, Organization}

  def data do
    Dataloader.Ecto.new(Repo, query: &query/2)
  end

  def query(Agent, args) do
    query = Agent

    query = if args[:organization_id] do
      where(query, [a], a.organization_id == ^args[:organization_id])
    else
      query
    end

    query = if args[:status] do
      where(query, [a], a.status == ^args[:status])
    else
      query
    end

    order_by(query, [a], [desc: a.last_seen_at])
  end

  def query(Alert, args) do
    query = Alert

    query = if args[:organization_id] do
      where(query, [a], a.organization_id == ^args[:organization_id])
    else
      query
    end

    query = if args[:agent_id] do
      where(query, [a], a.agent_id == ^args[:agent_id])
    else
      query
    end

    query = if args[:status] do
      where(query, [a], a.status == ^args[:status])
    else
      query
    end

    query = if args[:severity] do
      where(query, [a], a.severity == ^args[:severity])
    else
      query
    end

    query = if args[:limit] do
      limit(query, ^args[:limit])
    else
      query
    end

    order_by(query, [a], [desc: a.inserted_at])
  end

  def query(Event, args) do
    query = Event

    query = if args[:agent_id] do
      where(query, [e], e.agent_id == ^args[:agent_id])
    else
      query
    end

    query = if args[:event_type] do
      where(query, [e], e.event_type == ^args[:event_type])
    else
      query
    end

    query = if args[:since] do
      where(query, [e], e.timestamp >= ^args[:since])
    else
      query
    end

    query = if args[:limit] do
      limit(query, ^args[:limit])
    else
      query
    end

    order_by(query, [e], [desc: e.timestamp])
  end

  def query(User, args) do
    query = User

    query = if args[:organization_id] do
      where(query, [u], u.organization_id == ^args[:organization_id])
    else
      query
    end

    order_by(query, [u], [asc: u.email])
  end

  def query(Organization, _args) do
    order_by(Organization, [o], [asc: o.name])
  end

  def query(queryable, _args) do
    queryable
  end
end
