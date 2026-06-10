defmodule TamanduaServer.Support.Ticket do
  @moduledoc """
  Support ticket schema with enterprise SLA tracking.

  ## Fields

  - **subject** - Brief description of the issue
  - **description** - Detailed description
  - **priority** - P1 (critical), P2 (high), P3 (medium), P4 (low)
  - **status** - open, in_progress, pending_customer, resolved, closed
  - **category** - license, security, performance, feature_request, other

  ## SLA Tracking

  - **response_deadline** - When first response is due
  - **resolution_deadline** - When resolution is due
  - **first_response_at** - When first response was provided
  - **resolved_at** - When ticket was resolved
  - **response_sla_breached** - Whether response SLA was missed
  - **resolution_sla_breached** - Whether resolution SLA was missed

  ## Escalation

  - **escalation_level** - Current escalation tier (0 = none)
  - **escalated_at** - When ticket was last escalated
  - **escalation_reason** - Why it was escalated
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @priorities ~w(p1 p2 p3 p4)
  @statuses ~w(open in_progress pending_customer resolved closed)
  @categories ~w(license security performance feature_request other)

  schema "support_tickets" do
    field :subject, :string
    field :description, :string
    field :priority, :string, default: "p3"
    field :status, :string, default: "open"
    field :category, :string

    field :response_deadline, :utc_datetime
    field :resolution_deadline, :utc_datetime
    field :first_response_at, :utc_datetime
    field :resolved_at, :utc_datetime
    field :response_sla_breached, :boolean, default: false
    field :resolution_sla_breached, :boolean, default: false

    field :escalation_level, :integer, default: 0
    field :escalated_at, :utc_datetime
    field :escalation_reason, :string

    field :metadata, :map, default: %{}

    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :created_by, TamanduaServer.Accounts.User
    belongs_to :assigned_to, TamanduaServer.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @doc """
  Changeset for creating/updating tickets.
  """
  def changeset(ticket, attrs) do
    ticket
    |> cast(attrs, [:subject, :description, :priority, :status, :category,
                    :organization_id, :created_by_id, :assigned_to_id,
                    :response_deadline, :resolution_deadline, :first_response_at,
                    :resolved_at, :response_sla_breached, :resolution_sla_breached,
                    :escalation_level, :escalated_at, :escalation_reason, :metadata])
    |> validate_required([:subject, :priority, :status, :organization_id])
    |> validate_inclusion(:priority, @priorities)
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:category, @categories ++ [nil])
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:created_by_id)
    |> foreign_key_constraint(:assigned_to_id)
  end

  @doc """
  Get list of valid priorities.
  """
  def priorities, do: @priorities

  @doc """
  Get list of valid statuses.
  """
  def statuses, do: @statuses

  @doc """
  Get list of valid categories.
  """
  def categories, do: @categories
end
