defmodule TamanduaServer.ThreatIntel.MISPEvent do
  @moduledoc """
  Ecto schema for synced MISP events.

  Stores event metadata from MISP including:
  - Event info and threat level
  - Organization details
  - Tags and galaxies
  - TLP (Traffic Light Protocol) classification
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.ThreatIntel.MISPInstance

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "misp_events" do
    field :misp_event_id, :string
    field :uuid, :string
    field :info, :string
    field :threat_level_id, :integer
    field :analysis, :integer
    field :date, :string
    field :published, :boolean, default: false

    # Organization info
    field :org_name, :string
    field :orgc_name, :string

    # Metadata
    field :tags, {:array, :string}, default: []
    field :galaxies, {:array, :map}, default: []
    field :attribute_count, :integer, default: 0
    field :tlp, :string, default: "AMBER"

    # Attribution
    field :threat_actor_name, :string
    field :campaign_name, :string
    field :malware_family, :string

    belongs_to :misp_instance, MISPInstance

    timestamps()
  end

  @required_fields ~w(misp_instance_id misp_event_id)a
  @optional_fields ~w(
    uuid info threat_level_id analysis date published
    org_name orgc_name tags galaxies attribute_count tlp
    threat_actor_name campaign_name malware_family
  )a

  @doc false
  def changeset(event, attrs) do
    event
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:tlp, ~w(WHITE GREEN AMBER RED))
    |> validate_number(:threat_level_id, greater_than_or_equal_to: 1, less_than_or_equal_to: 4)
    |> unique_constraint([:misp_instance_id, :misp_event_id])
    |> foreign_key_constraint(:misp_instance_id)
  end

  @doc """
  Returns human-readable threat level.
  """
  def threat_level_name(1), do: "High"
  def threat_level_name(2), do: "Medium"
  def threat_level_name(3), do: "Low"
  def threat_level_name(4), do: "Undefined"
  def threat_level_name(_), do: "Unknown"

  @doc """
  Returns human-readable analysis status.
  """
  def analysis_status(0), do: "Initial"
  def analysis_status(1), do: "Ongoing"
  def analysis_status(2), do: "Completed"
  def analysis_status(_), do: "Unknown"
end
