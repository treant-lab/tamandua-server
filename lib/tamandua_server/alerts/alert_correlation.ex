defmodule TamanduaServer.Alerts.AlertCorrelation do
  @moduledoc """
  Schema for alert correlations - tracks relationships between alerts.
  """
  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Accounts.Organization

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  @correlation_types ~w(temporal ioc technique network user pattern)
  @valid_attrs [:alert_id, :related_alert_id, :correlation_type, :confidence,
                :similarity_score, :metadata, :organization_id]

  schema "alert_correlations" do
    field :correlation_type, :string
    field :confidence, :float, default: 0.0
    field :similarity_score, :float, default: 0.0
    field :metadata, :map, default: %{}

    belongs_to :alert, Alert
    belongs_to :related_alert, Alert
    belongs_to :organization, Organization

    timestamps()
  end

  @doc false
  def changeset(correlation, attrs) do
    correlation
    |> cast(attrs, @valid_attrs)
    |> validate_required([:alert_id, :related_alert_id, :correlation_type, :organization_id])
    |> validate_inclusion(:correlation_type, @correlation_types)
    |> validate_number(:confidence, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_number(:similarity_score, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> validate_different_alerts()
    |> unique_constraint([:alert_id, :related_alert_id, :correlation_type], name: :unique_alert_correlation)
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:related_alert_id)
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_different_alerts(changeset) do
    alert_id = get_field(changeset, :alert_id)
    related_id = get_field(changeset, :related_alert_id)

    if alert_id && related_id && alert_id == related_id do
      add_error(changeset, :related_alert_id, "cannot correlate an alert with itself")
    else
      changeset
    end
  end
end
