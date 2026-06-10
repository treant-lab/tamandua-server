defmodule TamanduaServer.DarkWeb.ThreatActor do
  @moduledoc """
  Schema for threat actor profiles from dark web.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "dark_web_threat_actors" do
    field :name, :string
    field :aliases, {:array, :string}
    field :actor_type, :string
    field :description, :string
    field :ttps, {:array, :string}
    field :target_industries, {:array, :string}
    field :target_countries, {:array, :string}
    field :first_seen, :utc_datetime
    field :last_seen, :utc_datetime
    field :activity_level, :string
    field :sophistication, :string
    field :source, :string
    field :source_urls, {:array, :string}
    field :associated_malware, {:array, :string}
    field :ransom_amounts, :map
    field :known_victims, {:array, :string}
    field :raw_data, :map

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(name source)a
  @optional_fields ~w(aliases actor_type description ttps target_industries target_countries
                     first_seen last_seen activity_level sophistication source_urls
                     associated_malware ransom_amounts known_victims raw_data)a

  def changeset(actor, attrs) do
    actor
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:actor_type, [
      "ransomware_group",
      "apt_group",
      "cybercrime_group",
      "hacktivist",
      "insider_threat",
      "unknown"
    ], allow_nil: true)
    |> validate_inclusion(:activity_level, ["active", "dormant", "retired"], allow_nil: true)
    |> validate_inclusion(:sophistication, ["low", "medium", "high", "advanced"], allow_nil: true)
    |> unique_constraint([:name, :source])
  end
end
