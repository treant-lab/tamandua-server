defmodule TamanduaServer.Telemetry.Event do
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Agents.Agent

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "events" do
    field :event_type, :string
    field :timestamp, :utc_datetime_usec
    field :payload, :map, default: %{}
    field :severity, :string, default: "info"
    field :sha256, :binary
    field :enrichment, :map, default: %{}
    field :detections, {:array, :map}, default: []
    field :archived, :boolean, default: false
    field :sampled, :boolean, default: false

    belongs_to :agent, Agent
    belongs_to :organization, Organization

    # The migration uses created_at instead of Ecto's default inserted_at
    timestamps(inserted_at: :created_at, updated_at: false)
  end

  @doc false
  def changeset(event, attrs) do
    attrs = normalize_timestamp(attrs)

    event
    |> cast(attrs, [
      :event_type,
      :timestamp,
      :payload,
      :severity,
      :sha256,
      :enrichment,
      :detections,
      :agent_id,
      :organization_id,
      :archived,
      :sampled
    ])
    |> validate_required([:agent_id, :event_type, :timestamp, :payload])
    |> foreign_key_constraint(:agent_id)
  end

  # Ensure the timestamp has microsecond precision so it is accepted by
  # the :utc_datetime_usec Ecto type. Agents may send timestamps with
  # millisecond (or second) precision which would otherwise be rejected.
  defp normalize_timestamp(%{timestamp: %DateTime{} = dt} = attrs) do
    %{attrs | timestamp: DateTime.truncate(dt, :microsecond)}
  end

  defp normalize_timestamp(%{"timestamp" => %DateTime{} = dt} = attrs) do
    %{attrs | "timestamp" => DateTime.truncate(dt, :microsecond)}
  end

  defp normalize_timestamp(attrs), do: attrs
end
