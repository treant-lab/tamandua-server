defmodule TamanduaServer.Baselines.BaselineDrift do
  @moduledoc """
  Schema for tracking baseline drift over time.

  Records when baselines change significantly, which may indicate
  evolving threats or changes in normal behavior.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "baseline_drifts" do
    field :baseline_type, :string
    field :baseline_key, :string
    field :drift_percent, :float
    field :direction, :string
    field :previous_value, :map
    field :current_value, :map
    field :detected_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(baseline_drift, attrs) do
    baseline_drift
    |> cast(attrs, [
      :baseline_type,
      :baseline_key,
      :drift_percent,
      :direction,
      :previous_value,
      :current_value,
      :detected_at
    ])
    |> validate_required([
      :baseline_type,
      :baseline_key,
      :drift_percent,
      :detected_at
    ])
    |> validate_inclusion(:direction, ["increasing", "decreasing", "stable", "unknown"])
  end
end
