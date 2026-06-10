defmodule TamanduaServer.Agents.ComplianceStatus do
  @moduledoc """
  Schema for agent compliance status tracking.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Agents.Agent

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "agent_compliance_status" do
    belongs_to :agent, Agent
    belongs_to :organization, Organization

    field :is_compliant, :boolean, default: true
    field :drift_count, :integer, default: 0
    field :last_scan_at, :utc_datetime
    field :last_compliant_at, :utc_datetime
    field :non_compliant_since, :utc_datetime
    field :compliance_score, :float, default: 100.0

    field :critical_drifts, :integer, default: 0
    field :high_drifts, :integer, default: 0
    field :medium_drifts, :integer, default: 0
    field :low_drifts, :integer, default: 0

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(status, attrs) do
    status
    |> cast(attrs, [
      :agent_id,
      :organization_id,
      :is_compliant,
      :drift_count,
      :last_scan_at,
      :last_compliant_at,
      :non_compliant_since,
      :compliance_score,
      :critical_drifts,
      :high_drifts,
      :medium_drifts,
      :low_drifts
    ])
    |> validate_required([:agent_id, :organization_id])
    |> validate_number(:compliance_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 100.0)
    |> validate_number(:drift_count, greater_than_or_equal_to: 0)
    |> validate_number(:critical_drifts, greater_than_or_equal_to: 0)
    |> validate_number(:high_drifts, greater_than_or_equal_to: 0)
    |> validate_number(:medium_drifts, greater_than_or_equal_to: 0)
    |> validate_number(:low_drifts, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:organization_id)
    |> unique_constraint(:agent_id)
  end

  @doc """
  Calculates compliance score based on drift severity.
  """
  def calculate_score(critical, high, medium, low) do
    # Critical: -25 points each, High: -10, Medium: -5, Low: -2
    deductions = (critical * 25) + (high * 10) + (medium * 5) + (low * 2)
    max(0.0, 100.0 - deductions)
  end
end
