defmodule TamanduaServer.Telemetry.CorrelationFeedback do
  @moduledoc """
  Analyst feedback for persisted event correlations and incident candidates.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "correlation_feedback" do
    field(:target_type, :string)
    field(:target_id, :binary_id)
    field(:verdict, :string)
    field(:notes, :string)
    field(:metadata, :map, default: %{})

    belongs_to(:organization, Organization)
    belongs_to(:user, User)

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(feedback, attrs) do
    feedback
    |> cast(attrs, [
      :organization_id,
      :target_type,
      :target_id,
      :verdict,
      :notes,
      :user_id,
      :metadata
    ])
    |> validate_required([:organization_id, :target_type, :target_id, :verdict])
    |> validate_inclusion(:target_type, ~w(event_correlation incident_candidate))
    |> validate_inclusion(
      :verdict,
      ~w(true_positive false_positive benign suspicious useful not_useful)
    )
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:user_id)
  end
end
