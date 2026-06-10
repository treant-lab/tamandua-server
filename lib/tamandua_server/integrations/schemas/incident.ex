defmodule TamanduaServer.Integrations.Schemas.Incident do
  @moduledoc """
  Schema for integration incidents (downtime events).
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "integration_incidents" do
    field :integration_id, :binary_id

    field :incident_type, :string
    field :severity, :string
    field :status, :string

    field :started_at, :utc_datetime
    field :resolved_at, :utc_datetime
    field :acknowledged_at, :utc_datetime

    field :resolution_time_seconds, :integer
    field :resolution_notes, :string

    field :error_message, :string
    field :metadata, :map

    field :alert_sent, :boolean
    field :alert_sent_at, :utc_datetime

    timestamps()
  end

  @required_fields [:integration_id, :incident_type, :severity, :started_at]
  @optional_fields [
    :status, :resolved_at, :acknowledged_at, :resolution_time_seconds,
    :resolution_notes, :error_message, :metadata, :alert_sent, :alert_sent_at
  ]

  def changeset(incident, attrs) do
    incident
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:incident_type, [
      "connection_failure",
      "high_error_rate",
      "rate_limit",
      "credential_expiry",
      "sync_lag"
    ])
    |> validate_inclusion(:severity, ["critical", "high", "medium", "low"])
    |> validate_inclusion(:status, ["open", "acknowledged", "resolved"])
  end

  @doc """
  Create or update an incident.
  If an open incident of the same type exists, update it instead of creating a new one.
  """
  def create_or_update(integration_id, incident_type, attrs) do
    incident_type_str = to_string(incident_type)

    # Check for existing open incident
    case get_open_incident(integration_id, incident_type_str) do
      nil ->
        # Create new incident
        %__MODULE__{
          integration_id: integration_id,
          incident_type: incident_type_str,
          status: "open",
          started_at: DateTime.utc_now()
        }
        |> changeset(attrs)
        |> Repo.insert()

      existing ->
        # Update existing incident
        existing
        |> changeset(attrs)
        |> Repo.update()
    end
  end

  @doc """
  Resolve an incident.
  """
  def resolve(incident_id, resolution_notes \\ nil) do
    case Repo.get(__MODULE__, incident_id) do
      nil ->
        {:error, :not_found}

      incident ->
        now = DateTime.utc_now()
        resolution_time = DateTime.diff(now, incident.started_at)

        incident
        |> changeset(%{
          status: "resolved",
          resolved_at: now,
          resolution_time_seconds: resolution_time,
          resolution_notes: resolution_notes
        })
        |> Repo.update()
    end
  end

  @doc """
  Acknowledge an incident.
  """
  def acknowledge(incident_id) do
    case Repo.get(__MODULE__, incident_id) do
      nil ->
        {:error, :not_found}

      incident ->
        incident
        |> changeset(%{
          status: "acknowledged",
          acknowledged_at: DateTime.utc_now()
        })
        |> Repo.update()
    end
  end

  @doc """
  Auto-resolve incidents when health is restored.
  """
  def auto_resolve(integration_id, incident_type) do
    incident_type_str = to_string(incident_type)

    case get_open_incident(integration_id, incident_type_str) do
      nil ->
        :ok

      incident ->
        resolve(incident.id, "Auto-resolved: Health check successful")
    end
  end

  @doc """
  Get open incident of a specific type.
  """
  def get_open_incident(integration_id, incident_type) do
    from(i in __MODULE__,
      where: i.integration_id == ^integration_id and
             i.incident_type == ^incident_type and
             i.status in ["open", "acknowledged"],
      order_by: [desc: i.started_at],
      limit: 1
    )
    |> Repo.one()
  end

  @doc """
  List all open incidents for an integration.
  """
  def list_open(integration_id) do
    from(i in __MODULE__,
      where: i.integration_id == ^integration_id and i.status in ["open", "acknowledged"],
      order_by: [desc: i.started_at]
    )
    |> Repo.all()
  end

  @doc """
  List recent incidents.
  """
  def list_recent(integration_id, limit \\ 50) do
    from(i in __MODULE__,
      where: i.integration_id == ^integration_id,
      order_by: [desc: i.started_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  List incidents for a date range.
  """
  def list_for_date_range(integration_id, start_datetime, end_datetime) do
    from(i in __MODULE__,
      where: i.integration_id == ^integration_id and
             i.started_at >= ^start_datetime and
             i.started_at <= ^end_datetime,
      order_by: [asc: i.started_at]
    )
    |> Repo.all()
  end

  @doc """
  Mark alert as sent.
  """
  def mark_alert_sent(incident_id) do
    case Repo.get(__MODULE__, incident_id) do
      nil ->
        {:error, :not_found}

      incident ->
        incident
        |> changeset(%{
          alert_sent: true,
          alert_sent_at: DateTime.utc_now()
        })
        |> Repo.update()
    end
  end
end
