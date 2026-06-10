defmodule TamanduaServer.Alerts.VerdictFeedbackLog do
  @moduledoc """
  Audit log entry for verdict changes on alerts.

  Every time an analyst sets or changes a verdict, a log entry is created
  for audit trail and feedback analytics.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.User
  alias TamanduaServer.Alerts.Alert

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "verdict_feedback_log" do
    field :previous_verdict, :string
    field :new_verdict, :string
    field :notes, :string
    field :suppression_rule_created, :boolean, default: false
    field :baseline_updated, :boolean, default: false
    field :metadata, :map, default: %{}

    belongs_to :alert, Alert
    belongs_to :user, User

    timestamps(type: :utc_datetime_usec)
  end

  @doc false
  def changeset(log, attrs) do
    log
    |> cast(attrs, [
      :alert_id, :user_id,
      :previous_verdict, :new_verdict, :notes,
      :suppression_rule_created, :baseline_updated,
      :metadata
    ])
    |> validate_required([:alert_id, :new_verdict])
    |> validate_inclusion(:new_verdict, ~w(unconfirmed true_positive false_positive benign suspicious))
    |> foreign_key_constraint(:alert_id)
    |> foreign_key_constraint(:user_id)
  end
end
