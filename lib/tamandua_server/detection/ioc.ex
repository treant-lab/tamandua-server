defmodule TamanduaServer.Detection.IOC do
  @moduledoc """
  Schema for Indicators of Compromise.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "iocs" do
    field :type, :string  # hash_md5, hash_sha256, ip, domain, url, email
    field :value, :string
    field :description, :string
    field :enabled, :boolean, default: true
    field :source, :string
    field :source_ref, :string
    field :severity, :string, default: "medium"
    field :confidence, :float
    field :tags, {:array, :string}, default: []
    field :metadata, :map, default: %{}
    field :first_seen, :utc_datetime_usec
    field :last_seen, :utc_datetime_usec
    field :expires_at, :utc_datetime_usec
    field :malware_family, :string
    field :threat_actor, :string
    field :campaign, :string
    field :mitre_tactics, {:array, :string}, default: []
    field :mitre_techniques, {:array, :string}, default: []
    field :organization_id, :binary_id

    timestamps()
  end

  @required_fields [:type, :value]
  @optional_fields [
    :description, :enabled, :source, :source_ref, :severity, :confidence,
    :tags, :metadata, :first_seen, :last_seen, :expires_at,
    :malware_family, :threat_actor, :campaign,
    :mitre_tactics, :mitre_techniques, :organization_id
  ]

  def changeset(ioc, attrs) do
    ioc
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:type, ["hash_md5", "hash_sha256", "hash_sha1", "ip", "domain", "url", "email", "filename"])
    |> validate_inclusion(:severity, ["low", "medium", "high", "critical"])
    |> validate_number(:confidence, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> unique_constraint([:type, :value])
  end
end
