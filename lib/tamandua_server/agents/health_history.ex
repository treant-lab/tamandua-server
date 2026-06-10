defmodule TamanduaServer.Agents.HealthHistory do
  @moduledoc """
  Schema for agent health score history.

  Stores periodic snapshots of agent health scores for trending and analysis.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "agent_health_history" do
    belongs_to :agent, Agent, type: :binary_id

    field :health_score, :integer
    field :category, :string

    # Score breakdown
    field :uptime_score, :integer
    field :cpu_score, :integer
    field :memory_score, :integer
    field :throughput_score, :integer
    field :error_rate_score, :integer
    field :coverage_score, :integer
    field :compliance_score, :integer

    field :issues, :map

    field :recorded_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(history, attrs) do
    history
    |> cast(attrs, [
      :agent_id,
      :health_score,
      :category,
      :uptime_score,
      :cpu_score,
      :memory_score,
      :throughput_score,
      :error_rate_score,
      :coverage_score,
      :compliance_score,
      :issues,
      :recorded_at
    ])
    |> validate_required([:agent_id, :health_score, :category, :recorded_at])
    |> validate_inclusion(:category, ~w(excellent good fair poor))
    |> validate_number(:health_score, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> foreign_key_constraint(:agent_id)
  end

  @doc """
  Record a health score snapshot.
  """
  def record_snapshot(agent_id, health_score_data) do
    attrs = Map.merge(health_score_data, %{
      agent_id: agent_id,
      recorded_at: DateTime.utc_now()
    })

    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Get health history for an agent.
  """
  def get_history(agent_id, hours \\ 168) do
    cutoff = DateTime.utc_now() |> DateTime.add(-hours * 3600, :second)

    from(h in __MODULE__,
      where: h.agent_id == ^agent_id,
      where: h.recorded_at >= ^cutoff,
      order_by: [desc: h.recorded_at]
    )
    |> Repo.all()
  end

  @doc """
  Get health trend for an agent.
  """
  def get_trend(agent_id, hours \\ 24) do
    history = get_history(agent_id, hours)

    if length(history) < 2 do
      :insufficient_data
    else
      scores = Enum.map(history, & &1.health_score)
      first_half = Enum.take(scores, div(length(scores), 2))
      second_half = Enum.drop(scores, div(length(scores), 2))

      avg_first = Enum.sum(first_half) / max(length(first_half), 1)
      avg_second = Enum.sum(second_half) / max(length(second_half), 1)

      diff = avg_second - avg_first

      cond do
        diff > 5 -> :improving
        diff < -5 -> :degrading
        true -> :stable
      end
    end
  end

  @doc """
  Get agents by health category.
  """
  def get_agents_by_category(category, hours \\ 1) do
    cutoff = DateTime.utc_now() |> DateTime.add(-hours * 3600, :second)

    # Get latest health record for each agent
    subquery = from(h in __MODULE__,
      where: h.recorded_at >= ^cutoff,
      distinct: h.agent_id,
      order_by: [desc: h.recorded_at],
      select: %{agent_id: h.agent_id, category: h.category, health_score: h.health_score}
    )

    from(s in subquery(subquery),
      where: s.category == ^category,
      select: s
    )
    |> Repo.all()
  end

  @doc """
  Clean up old history records (retention policy).
  """
  def cleanup_old_records(retention_days \\ 30) do
    cutoff = DateTime.utc_now() |> DateTime.add(-retention_days * 86400, :second)

    from(h in __MODULE__,
      where: h.recorded_at < ^cutoff
    )
    |> Repo.delete_all()
  end
end
