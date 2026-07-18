defmodule TamanduaServer.FleetQueries.FleetQueryRun do
  @moduledoc """
  Persisted execution of one live osquery SQL statement across a set of agents.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.FleetQueries.FleetQueryTarget

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses ~w(queued running completed completed_with_errors failed)

  schema "fleet_query_runs" do
    field :query, :string
    field :query_hash, :string
    field :status, :string, default: "queued"
    field :requested_agent_ids, {:array, :binary_id}, default: []
    field :filters, :map, default: %{}
    field :options, :map, default: %{}
    field :target_count, :integer, default: 0
    field :queued_count, :integer, default: 0
    field :skipped_count, :integer, default: 0
    field :completed_count, :integer, default: 0
    field :failed_count, :integer, default: 0
    field :started_at, :utc_datetime
    field :completed_at, :utc_datetime

    belongs_to :organization, Organization
    belongs_to :created_by_user, User
    has_many :targets, FleetQueryTarget

    timestamps(type: :utc_datetime)
  end

  def statuses, do: @statuses

  def changeset(run, attrs) do
    run
    |> cast(attrs, [
      :organization_id,
      :created_by_user_id,
      :query,
      :query_hash,
      :status,
      :requested_agent_ids,
      :filters,
      :options,
      :target_count,
      :queued_count,
      :skipped_count,
      :completed_count,
      :failed_count,
      :started_at,
      :completed_at
    ])
    |> validate_required([:organization_id, :query, :query_hash, :status])
    |> validate_inclusion(:status, @statuses)
    |> validate_number(:target_count, greater_than_or_equal_to: 0)
    |> validate_number(:queued_count, greater_than_or_equal_to: 0)
    |> validate_number(:skipped_count, greater_than_or_equal_to: 0)
    |> validate_number(:completed_count, greater_than_or_equal_to: 0)
    |> validate_number(:failed_count, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:created_by_user_id)
  end
end
