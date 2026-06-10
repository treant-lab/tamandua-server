defmodule TamanduaServer.Agents.ConfigurationScan do
  @moduledoc """
  Schema for agent configuration scan history.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Agents.Agent

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @scan_types ~w(scheduled on_demand reconnect manual)
  @scan_results ~w(success partial_failure failure)

  schema "agent_configuration_scans" do
    belongs_to :agent, Agent
    belongs_to :organization, Organization
    belongs_to :triggered_by, User

    field :scan_type, :string, default: "scheduled"
    field :scanned_at, :utc_datetime
    field :duration_ms, :integer
    field :drifts_detected, :integer, default: 0
    field :drifts_critical, :integer, default: 0
    field :drifts_high, :integer, default: 0
    field :drifts_medium, :integer, default: 0
    field :drifts_low, :integer, default: 0
    field :scan_result, :string
    field :error_message, :string

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(scan, attrs) do
    scan
    |> cast(attrs, [
      :agent_id,
      :organization_id,
      :scan_type,
      :scanned_at,
      :duration_ms,
      :drifts_detected,
      :drifts_critical,
      :drifts_high,
      :drifts_medium,
      :drifts_low,
      :scan_result,
      :error_message,
      :triggered_by_id
    ])
    |> validate_required([:organization_id, :scanned_at])
    |> validate_inclusion(:scan_type, @scan_types)
    |> validate_inclusion(:scan_result, @scan_results)
    |> validate_number(:duration_ms, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:agent_id)
    |> foreign_key_constraint(:organization_id)
  end

  @doc """
  Returns all valid scan types.
  """
  def scan_types, do: @scan_types

  @doc """
  Returns all valid scan results.
  """
  def scan_results, do: @scan_results
end
