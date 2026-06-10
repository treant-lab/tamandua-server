defmodule TamanduaServer.AISecurity.Investigation do
  @moduledoc """
  Ecto schema for AgenticAnalyst investigations.

  Stores the state and results of autonomous security investigations,
  including hypotheses, evidence, and recommendations.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Alerts.Alert

  @statuses ~w(pending triaging investigating hypothesis_validation evidence_collection
               action_recommendation awaiting_review resolved escalated)

  @priorities ~w(critical high medium low info)

  schema "investigations" do
    field :status, :string, default: "pending"
    field :priority, :string
    field :hypotheses, :map, default: %{}
    field :evidence, :map, default: %{}
    field :recommendations, :map, default: %{}
    field :triage_result, :map, default: %{}
    field :started_at, :utc_datetime
    field :completed_at, :utc_datetime

    belongs_to :alert, Alert, type: :string

    timestamps()
  end

  @doc """
  Creates a changeset for an investigation.

  ## Parameters

    - investigation: The investigation struct to update
    - attrs: Map of attributes to apply

  ## Validations

    - Requires alert_id
    - Validates status is one of the valid investigation states
    - Validates priority is one of: critical, high, medium, low, info
  """
  def changeset(investigation, attrs) do
    investigation
    |> cast(attrs, [
      :alert_id,
      :status,
      :priority,
      :hypotheses,
      :evidence,
      :recommendations,
      :triage_result,
      :started_at,
      :completed_at
    ])
    |> validate_required([:alert_id])
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:priority, @priorities)
  end

  @doc """
  Creates a changeset for starting a new investigation.
  Sets started_at to the current time.
  """
  def start_changeset(investigation, attrs) do
    investigation
    |> changeset(attrs)
    |> put_change(:started_at, DateTime.utc_now() |> DateTime.truncate(:second))
    |> put_change(:status, "triaging")
  end

  @doc """
  Creates a changeset for completing an investigation.
  Sets completed_at to the current time.
  """
  def complete_changeset(investigation, attrs) do
    investigation
    |> changeset(attrs)
    |> put_change(:completed_at, DateTime.utc_now() |> DateTime.truncate(:second))
    |> validate_inclusion(:status, ["resolved", "escalated"])
  end
end
