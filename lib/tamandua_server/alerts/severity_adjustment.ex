defmodule TamanduaServer.Alerts.SeverityAdjustment do
  @moduledoc """
  Schema for severity adjustment audit trail.

  Tracks manual severity changes to alerts, including the reason for adjustment,
  who made the change, and approval workflow for critical downgrades.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "severity_adjustments" do
    field :old_severity, :string
    field :new_severity, :string
    field :reason, :string
    field :notes, :string
    field :requires_approval, :boolean, default: false
    field :approved, :boolean
    field :approved_at, :utc_datetime_usec
    field :rejection_reason, :string
    field :metadata, :map, default: %{}

    belongs_to :alert, Alert
    belongs_to :adjusted_by, User, foreign_key: :adjusted_by_id
    belongs_to :approved_by, User, foreign_key: :approved_by_id
    belongs_to :organization, Organization

    timestamps(updated_at: false)
  end

  @valid_severities ~w(critical high medium low info)
  @critical_downgrades [
    {"critical", "high"},
    {"critical", "medium"},
    {"critical", "low"},
    {"critical", "info"},
    {"high", "medium"},
    {"high", "low"},
    {"high", "info"}
  ]

  def valid_severities, do: @valid_severities
  def critical_downgrades, do: @critical_downgrades

  @doc false
  def changeset(adjustment, attrs) do
    adjustment
    |> cast(attrs, [
      :alert_id,
      :old_severity,
      :new_severity,
      :reason,
      :notes,
      :requires_approval,
      :approved,
      :approved_at,
      :approved_by_id,
      :rejection_reason,
      :metadata,
      :adjusted_by_id,
      :organization_id
    ])
    |> validate_required([:alert_id, :old_severity, :new_severity, :reason, :adjusted_by_id, :organization_id])
    |> validate_inclusion(:old_severity, @valid_severities)
    |> validate_inclusion(:new_severity, @valid_severities)
    |> validate_length(:reason, min: 10, max: 1000)
    |> validate_length(:notes, max: 2000)
    |> validate_severity_change()
    |> set_requires_approval()
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:adjusted_by_id)
    |> foreign_key_constraint(:approved_by_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc false
  def approval_changeset(adjustment, attrs) do
    adjustment
    |> cast(attrs, [:approved, :approved_at, :approved_by_id, :rejection_reason])
    |> validate_required([:approved])
    |> validate_approval_fields()
    |> foreign_key_constraint(:approved_by_id)
  end

  defp validate_severity_change(changeset) do
    old_severity = get_field(changeset, :old_severity)
    new_severity = get_field(changeset, :new_severity)

    if old_severity == new_severity do
      add_error(changeset, :new_severity, "must be different from old severity")
    else
      changeset
    end
  end

  defp set_requires_approval(changeset) do
    old_severity = get_field(changeset, :old_severity)
    new_severity = get_field(changeset, :new_severity)

    requires_approval = {old_severity, new_severity} in @critical_downgrades

    put_change(changeset, :requires_approval, requires_approval)
  end

  defp validate_approval_fields(changeset) do
    approved = get_change(changeset, :approved)

    case approved do
      true ->
        changeset
        |> validate_required([:approved_by_id, :approved_at])

      false ->
        changeset
        |> validate_required([:rejection_reason])
        |> validate_length(:rejection_reason, min: 10, max: 1000)

      _ ->
        changeset
    end
  end

  @doc """
  Checks if a severity adjustment requires approval based on old and new severity.
  """
  def requires_approval?(old_severity, new_severity) do
    {old_severity, new_severity} in @critical_downgrades
  end
end
