defmodule TamanduaServer.Cost.CostRecommendation do
  @moduledoc """
  Schema for cost optimization recommendations.
  Identifies opportunities to reduce spending.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @recommendation_types ~w(overprovisioned_agent excessive_retention unused_integration inefficient_query
                          storage_optimization underutilized_resource duplicate_data idle_agent
                          high_bandwidth_usage expensive_ml_calls)
  @severities ~w(low medium high)
  @efforts ~w(one_click easy moderate complex)
  @statuses ~w(new acknowledged implemented dismissed)

  schema "cost_recommendations" do
    field :recommendation_type, :string
    field :severity, :string
    field :title, :string
    field :description, :string
    field :resource_type, :string
    field :resource_id, :string
    field :current_cost_usd, :decimal
    field :estimated_savings_usd, :decimal
    field :savings_percent, :decimal
    field :implementation_effort, :string
    field :action_payload, :map
    field :status, :string
    field :implemented_at, :utc_datetime
    field :dismissed_at, :utc_datetime
    field :dismissal_reason, :string
    field :metadata, :map

    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :implemented_by_user, TamanduaServer.Accounts.User, foreign_key: :implemented_by
    belongs_to :dismissed_by_user, TamanduaServer.Accounts.User, foreign_key: :dismissed_by

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(recommendation, attrs) do
    recommendation
    |> cast(attrs, [:organization_id, :recommendation_type, :severity, :title, :description,
                    :resource_type, :resource_id, :current_cost_usd, :estimated_savings_usd,
                    :savings_percent, :implementation_effort, :action_payload, :status,
                    :implemented_by, :implemented_at, :dismissed_by, :dismissed_at, :dismissal_reason, :metadata])
    |> validate_required([:organization_id, :recommendation_type, :severity, :title, :description,
                         :resource_type, :current_cost_usd, :estimated_savings_usd])
    |> validate_inclusion(:recommendation_type, @recommendation_types)
    |> validate_inclusion(:severity, @severities)
    |> validate_inclusion(:implementation_effort, @efforts)
    |> validate_inclusion(:status, @statuses)
    |> validate_number(:current_cost_usd, greater_than_or_equal_to: 0)
    |> validate_number(:estimated_savings_usd, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:organization_id)
  end

  def recommendation_types, do: @recommendation_types
  def severities, do: @severities
  def efforts, do: @efforts
  def statuses, do: @statuses
end
