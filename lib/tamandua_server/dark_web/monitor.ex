defmodule TamanduaServer.DarkWeb.Monitor do
  @moduledoc """
  Schema for dark web monitoring configurations.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "dark_web_monitors" do
    field :name, :string
    field :monitor_type, :string
    field :keywords, {:array, :string}
    field :domains, {:array, :string}
    field :email_patterns, {:array, :string}
    field :is_active, :boolean
    field :severity, :string
    field :alert_on_match, :boolean
    field :notification_channels, {:array, :string}
    field :last_check, :utc_datetime
    field :match_count, :integer

    belongs_to :created_by, TamanduaServer.Accounts.User

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(name monitor_type)a
  @optional_fields ~w(keywords domains email_patterns is_active severity alert_on_match
                     notification_channels last_check match_count created_by_id)a

  def changeset(monitor, attrs) do
    monitor
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:monitor_type, ["credentials", "keywords", "domains", "threat_actors"])
    |> validate_inclusion(:severity, ["critical", "high", "medium", "low"])
  end
end
