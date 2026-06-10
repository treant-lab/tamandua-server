defmodule TamanduaServer.InsiderThreat.Investigation do
  @moduledoc """
  Investigation workflows and case management for insider threats.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query, except: [update: 2]

  alias TamanduaServer.Repo
  alias TamanduaServer.Accounts.{User, Organization}
  alias TamanduaServer.InsiderThreat.Alert
  alias TamanduaServer.Telemetry.Event

  @type t :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "insider_threat_investigations" do
    field :title, :string
    field :description, :string
    field :status, :string, default: "open"
    field :priority, :string, default: "medium"
    field :findings, :string
    field :evidence, {:array, :map}, default: []
    field :timeline, {:array, :map}, default: []
    field :investigation_started_at, :utc_datetime_usec
    field :investigation_completed_at, :utc_datetime_usec
    field :outcome, :string
    field :action_taken, :string

    belongs_to :subject, User, foreign_key: :subject_user_id
    belongs_to :organization, Organization
    belongs_to :lead_investigator, User, foreign_key: :lead_investigator_id
    belongs_to :assigned_to, User, foreign_key: :assigned_to_id

    has_many :alerts, Alert, foreign_key: :investigation_id

    timestamps()
  end

  @doc false
  def changeset(investigation, attrs) do
    investigation
    |> cast(attrs, [
      :title,
      :description,
      :status,
      :priority,
      :findings,
      :evidence,
      :timeline,
      :investigation_started_at,
      :investigation_completed_at,
      :outcome,
      :action_taken,
      :subject_user_id,
      :organization_id,
      :lead_investigator_id,
      :assigned_to_id
    ])
    |> validate_required([:title, :subject_user_id, :organization_id, :status, :priority])
    |> validate_inclusion(:status, ~w(open investigating on_hold closed))
    |> validate_inclusion(:priority, ~w(critical high medium low))
    |> foreign_key_constraint(:subject_user_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:lead_investigator_id)
    |> foreign_key_constraint(:assigned_to_id)
  end

  @doc """
  Create a new investigation.
  """
  @spec create(map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def create(attrs) do
    attrs = Map.put_new(attrs, :investigation_started_at, DateTime.utc_now())

    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update an investigation.
  """
  @spec update(t(), map()) :: {:ok, t()} | {:error, Ecto.Changeset.t()}
  def update(investigation, attrs) do
    investigation
    |> changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Get investigation by ID.
  """
  @spec get(Ecto.UUID.t()) :: t() | nil
  def get(id) do
    Repo.get(__MODULE__, id)
    |> Repo.preload([:subject, :organization, :lead_investigator, :assigned_to, :alerts])
  end

  @doc """
  List investigations for an organization.
  """
  @spec list_by_organization(Ecto.UUID.t(), map()) :: [t()]
  def list_by_organization(organization_id, opts \\ %{}) do
    query =
      from(i in __MODULE__,
        where: i.organization_id == ^organization_id,
        order_by: [desc: i.inserted_at]
      )

    query
    |> apply_filters(opts)
    |> Repo.all()
    |> Repo.preload([:subject, :lead_investigator, :assigned_to])
  end

  @doc """
  Add evidence to an investigation.
  """
  @spec add_evidence(t(), map()) :: {:ok, t()} | {:error, any()}
  def add_evidence(investigation, evidence_item) do
    evidence_entry = %{
      id: Ecto.UUID.generate(),
      type: evidence_item[:type],
      description: evidence_item[:description],
      data: evidence_item[:data],
      collected_at: DateTime.utc_now(),
      collected_by: evidence_item[:collected_by]
    }

    updated_evidence = investigation.evidence ++ [evidence_entry]

    update(investigation, %{evidence: updated_evidence})
  end

  @doc """
  Add timeline entry to an investigation.
  """
  @spec add_timeline_entry(t(), map()) :: {:ok, t()} | {:error, any()}
  def add_timeline_entry(investigation, entry) do
    timeline_entry = %{
      id: Ecto.UUID.generate(),
      timestamp: entry[:timestamp] || DateTime.utc_now(),
      event_type: entry[:event_type],
      description: entry[:description],
      details: entry[:details] || %{},
      recorded_by: entry[:recorded_by]
    }

    updated_timeline =
      (investigation.timeline ++ [timeline_entry])
      |> Enum.sort_by(& &1.timestamp, DateTime)

    update(investigation, %{timeline: updated_timeline})
  end

  @doc """
  Close an investigation.
  """
  @spec close(t(), String.t(), String.t()) :: {:ok, t()} | {:error, any()}
  def close(investigation, outcome, action_taken) do
    update(investigation, %{
      status: "closed",
      investigation_completed_at: DateTime.utc_now(),
      outcome: outcome,
      action_taken: action_taken
    })
  end

  @doc """
  Get user activity timeline for investigation.
  """
  @spec get_user_timeline(Ecto.UUID.t(), DateTime.t(), DateTime.t()) :: [map()]
  def get_user_timeline(user_id, start_time, end_time) do
    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time,
        order_by: [asc: e.inserted_at],
        select: %{
          id: e.id,
          timestamp: e.inserted_at,
          event_type: e.event_type,
          payload: e.payload,
          agent_id: e.agent_id
        }
      )

    Repo.all(query)
  end

  @doc """
  Get user access log (data accessed).
  """
  @spec get_user_access_log(Ecto.UUID.t(), DateTime.t(), DateTime.t()) :: [map()]
  def get_user_access_log(user_id, start_time, end_time) do
    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.event_type in ["file_access", "data_read", "database_query"] and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time,
        order_by: [asc: e.inserted_at],
        select: %{
          timestamp: e.inserted_at,
          resource: fragment("payload->>'file_path'"),
          operation: e.event_type,
          bytes: fragment("COALESCE((payload->>'bytes_read')::bigint, 0)"),
          classification: fragment("payload->>'classification'")
        }
      )

    Repo.all(query)
  end

  @doc """
  Get user network activity.
  """
  @spec get_user_network_activity(Ecto.UUID.t(), DateTime.t(), DateTime.t()) :: [map()]
  def get_user_network_activity(user_id, start_time, end_time) do
    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.event_type in ["network_connection", "file_transfer"] and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time,
        order_by: [asc: e.inserted_at],
        select: %{
          timestamp: e.inserted_at,
          remote_ip: fragment("payload->>'remote_ip'"),
          remote_host: fragment("payload->>'remote_host'"),
          remote_port: fragment("COALESCE((payload->>'remote_port')::integer, 0)"),
          protocol: fragment("payload->>'protocol'"),
          bytes_sent: fragment("COALESCE((payload->>'bytes_sent')::bigint, 0)"),
          bytes_received: fragment("COALESCE((payload->>'bytes_received')::bigint, 0)")
        }
      )

    Repo.all(query)
  end

  @doc """
  Get user authentication log.
  """
  @spec get_user_auth_log(Ecto.UUID.t(), DateTime.t(), DateTime.t()) :: [map()]
  def get_user_auth_log(user_id, start_time, end_time) do
    query =
      from(e in Event,
        where:
          e.user_id == ^user_id and
            e.event_type in ["authentication_success", "authentication_failure"] and
            e.inserted_at >= ^start_time and
            e.inserted_at <= ^end_time,
        order_by: [asc: e.inserted_at],
        select: %{
          timestamp: e.inserted_at,
          success: fragment("CASE WHEN event_type = 'authentication_success' THEN true ELSE false END"),
          source_ip: fragment("payload->>'source_ip'"),
          location: fragment("payload->>'location'"),
          auth_method: fragment("payload->>'auth_method'"),
          failure_reason: fragment("payload->>'failure_reason'")
        }
      )

    Repo.all(query)
  end

  @doc """
  Generate investigation report.
  """
  @spec generate_report(t()) :: map()
  def generate_report(investigation) do
    investigation = Repo.preload(investigation, [:subject, :alerts, :lead_investigator])

    %{
      investigation_id: investigation.id,
      title: investigation.title,
      subject: %{
        id: investigation.subject.id,
        name: investigation.subject.name,
        email: investigation.subject.email,
        role: investigation.subject.role
      },
      status: investigation.status,
      priority: investigation.priority,
      started_at: investigation.investigation_started_at,
      completed_at: investigation.investigation_completed_at,
      duration_hours:
        if(investigation.investigation_completed_at,
          do:
            DateTime.diff(
              investigation.investigation_completed_at,
              investigation.investigation_started_at,
              :hour
            ),
          else: nil
        ),
      lead_investigator:
        if(investigation.lead_investigator,
          do: %{
            id: investigation.lead_investigator.id,
            name: investigation.lead_investigator.name
          },
          else: nil
        ),
      alerts_count: length(investigation.alerts),
      alerts_severity_breakdown:
        investigation.alerts
        |> Enum.group_by(& &1.severity)
        |> Enum.map(fn {severity, alerts} -> {severity, length(alerts)} end)
        |> Map.new(),
      evidence_count: length(investigation.evidence),
      timeline_events_count: length(investigation.timeline),
      findings: investigation.findings,
      outcome: investigation.outcome,
      action_taken: investigation.action_taken,
      generated_at: DateTime.utc_now()
    }
  end

  @doc """
  Export investigation data for compliance/legal hold.
  """
  @spec export_for_legal_hold(t()) :: {:ok, map()} | {:error, any()}
  def export_for_legal_hold(investigation) do
    investigation = Repo.preload(investigation, [:subject, :alerts, :lead_investigator])

    # Get all activity for subject user during investigation period
    timeline =
      get_user_timeline(
        investigation.subject_user_id,
        investigation.investigation_started_at,
        investigation.investigation_completed_at || DateTime.utc_now()
      )

    access_log =
      get_user_access_log(
        investigation.subject_user_id,
        investigation.investigation_started_at,
        investigation.investigation_completed_at || DateTime.utc_now()
      )

    network_activity =
      get_user_network_activity(
        investigation.subject_user_id,
        investigation.investigation_started_at,
        investigation.investigation_completed_at || DateTime.utc_now()
      )

    auth_log =
      get_user_auth_log(
        investigation.subject_user_id,
        investigation.investigation_started_at,
        investigation.investigation_completed_at || DateTime.utc_now()
      )

    export_data = %{
      investigation: generate_report(investigation),
      subject_user: %{
        id: investigation.subject.id,
        name: investigation.subject.name,
        email: investigation.subject.email,
        role: investigation.subject.role
      },
      activity: %{
        timeline: timeline,
        access_log: access_log,
        network_activity: network_activity,
        authentication_log: auth_log
      },
      alerts: Enum.map(investigation.alerts, &serialize_alert/1),
      evidence: investigation.evidence,
      exported_at: DateTime.utc_now(),
      exported_for: "legal_hold"
    }

    {:ok, export_data}
  end

  # Private helpers

  defp apply_filters(query, opts) do
    query
    |> filter_by_status(opts[:status])
    |> filter_by_priority(opts[:priority])
    |> filter_by_subject(opts[:subject_user_id])
    |> apply_limit(opts[:limit])
  end

  defp filter_by_status(query, nil), do: query

  defp filter_by_status(query, status) do
    from(i in query, where: i.status == ^status)
  end

  defp filter_by_priority(query, nil), do: query

  defp filter_by_priority(query, priority) do
    from(i in query, where: i.priority == ^priority)
  end

  defp filter_by_subject(query, nil), do: query

  defp filter_by_subject(query, subject_user_id) do
    from(i in query, where: i.subject_user_id == ^subject_user_id)
  end

  defp apply_limit(query, nil), do: query

  defp apply_limit(query, limit) do
    from(i in query, limit: ^limit)
  end

  defp serialize_alert(alert) do
    %{
      id: alert.id,
      risk_score: alert.risk_score,
      severity: alert.severity,
      indicators: alert.indicators,
      trend: alert.trend,
      status: alert.status,
      created_at: alert.inserted_at
    }
  end
end
