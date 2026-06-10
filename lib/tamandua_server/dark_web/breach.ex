defmodule TamanduaServer.DarkWeb.Breach do
  @moduledoc """
  Schema for dark web breach records.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "dark_web_breaches" do
    field :breach_name, :string
    field :domain, :string
    field :breach_date, :utc_datetime
    field :added_date, :utc_datetime
    field :modified_date, :utc_datetime
    field :pwn_count, :integer
    field :description, :string
    field :data_classes, {:array, :string}
    field :is_verified, :boolean
    field :is_fabricated, :boolean
    field :is_sensitive, :boolean
    field :is_retired, :boolean
    field :is_spam_list, :boolean
    field :is_malware, :boolean
    field :logo_path, :string
    field :source, :string
    field :source_id, :string
    field :raw_data, :map

    has_many :credentials, TamanduaServer.DarkWeb.Credential

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(breach_name source)a
  @optional_fields ~w(domain breach_date added_date modified_date pwn_count description
                     data_classes is_verified is_fabricated is_sensitive is_retired
                     is_spam_list is_malware logo_path source_id raw_data)a

  def changeset(breach, attrs) do
    breach
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:source, ["hibp", "intel471", "flashpoint", "custom"])
    |> unique_constraint([:source, :source_id])
  end
end
