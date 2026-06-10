defmodule TamanduaServer.Investigations.CaseInvestigation do
  @moduledoc """
  Schema for security case investigations.

  Represents a manual investigation case that can be opened by analysts
  to track security incidents, link alerts and events, and document findings.

  This is separate from the AgenticAnalyst investigations which are automated.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.User

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses ~w(open in_progress closed archived)
  @severities ~w(critical high medium low info)

  schema "case_investigations" do
    field :title, :string
    field :description, :string
    field :status, :string, default: "open"
    field :severity, :string, default: "medium"

    # Linked entities
    field :alert_ids, {:array, :binary_id}, default: []
    field :event_ids, {:array, :binary_id}, default: []

    # Investigation content
    field :notes, :string
    field :findings, :string
    field :timeline, :map, default: %{}

    # Tags and MITRE mapping
    field :tags, {:array, :string}, default: []
    field :mitre_tactics, {:array, :string}, default: []
    field :mitre_techniques, {:array, :string}, default: []

    # Relationships
    belongs_to :assigned_user, User, foreign_key: :assigned_to
    belongs_to :creator, User, foreign_key: :created_by
    field :organization_id, :binary_id

    timestamps()
  end

  @doc """
  Creates a changeset for a case investigation.
  """
  def changeset(investigation, attrs) do
    investigation
    |> cast(attrs, [
      :title,
      :description,
      :status,
      :severity,
      :assigned_to,
      :created_by,
      :alert_ids,
      :event_ids,
      :notes,
      :findings,
      :timeline,
      :tags,
      :mitre_tactics,
      :mitre_techniques,
      :organization_id
    ])
    |> validate_required([:title, :created_by])
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:severity, @severities)
    |> validate_length(:title, min: 3, max: 255)
  end

  @doc """
  Creates a changeset for creating a new investigation.
  """
  def create_changeset(investigation, attrs) do
    investigation
    |> changeset(attrs)
    |> put_change(:status, "open")
  end

  @doc """
  Creates a changeset for updating an investigation.
  """
  def update_changeset(investigation, attrs) do
    changeset(investigation, attrs)
  end

  @doc """
  Adds an alert to the investigation.
  """
  def add_alert(investigation, alert_id) do
    current_ids = investigation.alert_ids || []
    if alert_id in current_ids do
      investigation
    else
      change(investigation, alert_ids: current_ids ++ [alert_id])
    end
  end

  @doc """
  Adds an event to the investigation.
  """
  def add_event(investigation, event_id) do
    current_ids = investigation.event_ids || []
    if event_id in current_ids do
      investigation
    else
      change(investigation, event_ids: current_ids ++ [event_id])
    end
  end

  @doc """
  Returns the list of valid statuses.
  """
  def statuses, do: @statuses

  @doc """
  Returns the list of valid severities.
  """
  def severities, do: @severities
end
