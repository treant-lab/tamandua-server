defmodule TamanduaServer.DarkWeb.ResponseWorkflow do
  @moduledoc """
  Schema for breach response workflows.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "dark_web_response_workflows" do
    field :workflow_type, :string
    field :status, :string
    field :triggered_at, :utc_datetime
    field :completed_at, :utc_datetime
    field :error_message, :string
    field :actions_taken, {:array, :string}
    field :metadata, :map

    belongs_to :credential, TamanduaServer.DarkWeb.Credential
    belongs_to :intelligence, TamanduaServer.DarkWeb.Intelligence
    belongs_to :executed_by, TamanduaServer.Accounts.User

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(workflow_type status triggered_at)a
  @optional_fields ~w(credential_id intelligence_id completed_at error_message
                     actions_taken executed_by_id metadata)a

  def changeset(workflow, attrs) do
    workflow
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:workflow_type, [
      "password_reset",
      "account_disable",
      "mfa_enforce",
      "user_notify",
      "create_incident",
      "security_team_notify"
    ])
    |> validate_inclusion(:status, ["pending", "in_progress", "completed", "failed"])
  end
end
