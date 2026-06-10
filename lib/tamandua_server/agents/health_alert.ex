defmodule TamanduaServer.Agents.HealthAlert do
  @moduledoc """
  Schema for agent health alerts.

  Tracks critical health events that require attention.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Repo
  alias Phoenix.PubSub

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "agent_health_alerts" do
    belongs_to :agent, Agent, type: :binary_id

    field :alert_type, :string
    field :severity, :string
    field :message, :string
    field :details, :map

    field :acknowledged, :boolean, default: false
    field :acknowledged_by, :string
    field :acknowledged_at, :utc_datetime
    field :resolved, :boolean, default: false
    field :resolved_at, :utc_datetime
    field :resolution_notes, :string

    field :triggered_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(alert, attrs) do
    alert
    |> cast(attrs, [
      :agent_id,
      :alert_type,
      :severity,
      :message,
      :details,
      :acknowledged,
      :acknowledged_by,
      :acknowledged_at,
      :resolved,
      :resolved_at,
      :resolution_notes,
      :triggered_at
    ])
    |> validate_required([:agent_id, :alert_type, :severity, :message, :triggered_at])
    |> validate_inclusion(:alert_type, ~w(score_drop resource_exhaustion pattern_detected maintenance_required))
    |> validate_inclusion(:severity, ~w(critical warning info))
    |> foreign_key_constraint(:agent_id)
  end

  @doc """
  Create a health alert.
  """
  def create_alert(agent_id, attrs) do
    attrs = Map.merge(attrs, %{
      agent_id: agent_id,
      triggered_at: DateTime.utc_now()
    })

    result = %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()

    # Broadcast alert
    case result do
      {:ok, alert} ->
        PubSub.broadcast(
          TamanduaServer.PubSub,
          "agent_health_alerts",
          {:health_alert, alert}
        )

        PubSub.broadcast(
          TamanduaServer.PubSub,
          "agent:#{agent_id}",
          {:health_alert, alert}
        )

        {:ok, alert}

      error ->
        error
    end
  end

  @doc """
  Acknowledge an alert.
  """
  def acknowledge(alert_id, user_id) do
    alert = Repo.get(__MODULE__, alert_id)

    if alert do
      alert
      |> changeset(%{
        acknowledged: true,
        acknowledged_by: user_id,
        acknowledged_at: DateTime.utc_now()
      })
      |> Repo.update()
    else
      {:error, :not_found}
    end
  end

  @doc """
  Resolve an alert.
  """
  def resolve(alert_id, resolution_notes \\ nil) do
    alert = Repo.get(__MODULE__, alert_id)

    if alert do
      alert
      |> changeset(%{
        resolved: true,
        resolved_at: DateTime.utc_now(),
        resolution_notes: resolution_notes
      })
      |> Repo.update()
    else
      {:error, :not_found}
    end
  end

  @doc """
  Get unresolved alerts for an agent.
  """
  def get_unresolved(agent_id) do
    from(a in __MODULE__,
      where: a.agent_id == ^agent_id,
      where: a.resolved == false,
      order_by: [desc: a.triggered_at]
    )
    |> Repo.all()
  end

  @doc """
  Get all unresolved alerts.
  """
  def get_all_unresolved do
    from(a in __MODULE__,
      where: a.resolved == false,
      order_by: [desc: a.triggered_at]
    )
    |> Repo.all()
  end

  @doc """
  Get critical unresolved alerts.
  """
  def get_critical_unresolved do
    from(a in __MODULE__,
      where: a.resolved == false,
      where: a.severity == "critical",
      order_by: [desc: a.triggered_at]
    )
    |> Repo.all()
  end

  @doc """
  Get alert statistics.
  """
  def get_statistics(hours \\ 24) do
    cutoff = DateTime.utc_now() |> DateTime.add(-hours * 3600, :second)

    from(a in __MODULE__,
      where: a.triggered_at >= ^cutoff,
      select: %{
        total: count(a.id),
        critical: fragment("COUNT(CASE WHEN severity = 'critical' THEN 1 END)"),
        warning: fragment("COUNT(CASE WHEN severity = 'warning' THEN 1 END)"),
        info: fragment("COUNT(CASE WHEN severity = 'info' THEN 1 END)"),
        unresolved: fragment("COUNT(CASE WHEN resolved = false THEN 1 END)"),
        acknowledged: fragment("COUNT(CASE WHEN acknowledged = true THEN 1 END)")
      }
    )
    |> Repo.one()
  end

  @doc """
  Clean up old resolved alerts.
  """
  def cleanup_old_alerts(retention_days \\ 90) do
    cutoff = DateTime.utc_now() |> DateTime.add(-retention_days * 86400, :second)

    from(a in __MODULE__,
      where: a.resolved == true,
      where: a.resolved_at < ^cutoff
    )
    |> Repo.delete_all()
  end
end
