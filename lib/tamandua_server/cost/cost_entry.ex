defmodule TamanduaServer.Cost.CostEntry do
  @moduledoc """
  Schema for cost tracking entries.
  Records daily costs by resource type for cost analysis and optimization.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @resource_types ~w(agent storage network ml integration other)
  @usage_units ~w(cpu_hours memory_gb storage_gb bandwidth_gb api_calls count)

  schema "cost_entries" do
    field :date, :date
    field :resource_type, :string
    field :resource_id, :string
    field :cost_usd, :decimal
    field :usage_amount, :decimal
    field :usage_unit, :string
    field :metadata, :map

    belongs_to :organization, TamanduaServer.Accounts.Organization

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(cost_entry, attrs) do
    cost_entry
    |> cast(attrs, [:organization_id, :date, :resource_type, :resource_id, :cost_usd, :usage_amount, :usage_unit, :metadata])
    |> validate_required([:organization_id, :date, :resource_type, :cost_usd])
    |> validate_inclusion(:resource_type, @resource_types)
    |> validate_inclusion(:usage_unit, @usage_units, message: "must be one of: #{Enum.join(@usage_units, ", ")}")
    |> validate_number(:cost_usd, greater_than_or_equal_to: 0)
    |> validate_number(:usage_amount, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:organization_id)
  end

  def resource_types, do: @resource_types
  def usage_units, do: @usage_units
end
