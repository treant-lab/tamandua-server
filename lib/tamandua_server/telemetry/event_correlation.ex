defmodule TamanduaServer.Telemetry.EventCorrelation do
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Telemetry.Event

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "event_correlations" do
    field(:score, :integer)
    field(:relation_types, {:array, :string}, default: [])
    field(:reasons, {:array, :string}, default: [])
    field(:shared_entities, {:array, :string}, default: [])
    field(:metadata, :map, default: %{})

    belongs_to(:source_event, Event)
    belongs_to(:target_event, Event)
    belongs_to(:organization, Organization)

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(correlation, attrs) do
    correlation
    |> cast(attrs, [
      :source_event_id,
      :target_event_id,
      :organization_id,
      :score,
      :relation_types,
      :reasons,
      :shared_entities,
      :metadata
    ])
    |> validate_required([:source_event_id, :target_event_id, :organization_id, :score])
    |> validate_number(:score, greater_than_or_equal_to: 0, less_than_or_equal_to: 100)
    |> validate_different_events()
    |> unique_constraint([:source_event_id, :target_event_id],
      name: :event_correlations_unique_pair
    )
    |> foreign_key_constraint(:source_event_id)
    |> foreign_key_constraint(:target_event_id)
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_different_events(changeset) do
    source_id = get_field(changeset, :source_event_id)
    target_id = get_field(changeset, :target_event_id)

    if source_id && target_id && source_id == target_id do
      add_error(changeset, :target_event_id, "cannot correlate an event with itself")
    else
      changeset
    end
  end
end
