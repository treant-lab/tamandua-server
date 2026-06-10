defmodule TamanduaServer.Agents.ConfigurationDrift do
  @moduledoc """
  Schema for agent configuration drift detection results.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Agents.{Agent, ConfigurationBaseline}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @drift_types ~w(
    collector_disabled
    collector_enabled
    collector_settings_changed
    response_permission_changed
    network_config_changed
    file_path_changed
    resource_limit_changed
    feature_toggled
    rules_outdated
    unauthorized_change
  )

  @categories ~w(
    collectors
    response
    network
    paths
    resources
    features
    rules
  )

  @severities ~w(critical high medium low)
  @statuses ~w(detected acknowledged investigating resolved ignored)

  schema "agent_configuration_drifts" do
    belongs_to :agent, Agent
    belongs_to :organization, Organization
    belongs_to :baseline, ConfigurationBaseline
    belongs_to :resolved_by, User

    field :drift_type, :string
    field :category, :string
    field :severity, :string, default: "medium"
    field :status, :string, default: "detected"

    field :field_path, :string
    field :expected_value, :map
    field :actual_value, :map
    field :drift_details, :map, default: %{}

    field :remediation_action, :string
    field :remediation_status, :string
    field :remediation_attempted_at, :utc_datetime
    field :remediation_completed_at, :utc_datetime
    field :remediation_error, :string

    field :resolved_at, :utc_datetime
    field :resolution_notes, :string
    field :detected_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(drift, attrs) do
    drift
    |> cast(attrs, [
      :agent_id,
      :organization_id,
      :baseline_id,
      :drift_type,
      :category,
      :severity,
      :status,
      :field_path,
      :expected_value,
      :actual_value,
      :drift_details,
      :remediation_action,
      :remediation_status,
      :remediation_attempted_at,
      :remediation_completed_at,
      :remediation_error,
      :resolved_at,
      :resolved_by_id,
      :resolution_notes,
      :detected_at
    ])
    |> validate_required([:agent_id, :organization_id, :drift_type, :category, :detected_at])
    |> validate_inclusion(:drift_type, @drift_types)
    |> validate_inclusion(:category, @categories)
    |> validate_inclusion(:severity, @severities)
    |> validate_inclusion(:status, @statuses)
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:baseline_id)
  end

  @doc """
  Returns all valid drift types.
  """
  def drift_types, do: @drift_types

  @doc """
  Returns all valid categories.
  """
  def categories, do: @categories

  @doc """
  Returns all valid severities.
  """
  def severities, do: @severities

  @doc """
  Returns all valid statuses.
  """
  def statuses, do: @statuses
end
