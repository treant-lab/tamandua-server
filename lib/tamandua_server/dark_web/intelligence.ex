defmodule TamanduaServer.DarkWeb.Intelligence do
  @moduledoc """
  Schema for dark web intelligence findings.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "dark_web_intelligence" do
    field :intelligence_type, :string
    field :title, :string
    field :description, :string
    field :content, :string
    field :url, :string
    field :source, :string
    field :source_id, :string
    field :severity, :string
    field :keywords_matched, {:array, :string}
    field :threat_actors, {:array, :string}
    field :organizations_mentioned, {:array, :string}
    field :iocs, {:array, :string}
    field :cvees, {:array, :string}
    field :first_seen, :utc_datetime
    field :last_seen, :utc_datetime
    field :status, :string
    field :incident_id, :binary_id
    field :raw_data, :map

    belongs_to :assigned_to, TamanduaServer.Accounts.User
    has_many :workflows, TamanduaServer.DarkWeb.ResponseWorkflow

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(intelligence_type title source severity status)a
  @optional_fields ~w(description content url source_id keywords_matched threat_actors
                     organizations_mentioned iocs cvees first_seen last_seen assigned_to_id
                     incident_id raw_data)a

  def changeset(intelligence, attrs) do
    intelligence
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:intelligence_type, [
      "threat_actor_chatter",
      "ransomware_negotiation",
      "data_leak",
      "vulnerability_exploit",
      "credential_marketplace"
    ])
    |> validate_inclusion(:severity, ["critical", "high", "medium", "low"])
    |> validate_inclusion(:status, ["new", "investigating", "resolved", "false_positive"])
    |> unique_constraint([:source, :source_id])
  end
end
