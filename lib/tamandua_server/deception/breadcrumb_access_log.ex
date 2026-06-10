defmodule TamanduaServer.Deception.BreadcrumbAccessLog do
  @moduledoc """
  Schema for tracking breadcrumb access events.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Deception.BreadcrumbDeployment
  alias TamanduaServer.Alerts.Alert

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "breadcrumb_access_log" do
    field :agent_id, :string
    field :accessed_at, :utc_datetime
    field :process_name, :string
    field :pid, :integer
    field :user, :string
    field :access_type, :string
    field :tamper_detected, :boolean, default: false
    field :original_hash, :string
    field :new_hash, :string
    field :additional_data, :map, default: %{}

    belongs_to :breadcrumb, BreadcrumbDeployment, foreign_key: :breadcrumb_id
    belongs_to :alert, Alert, foreign_key: :alert_id

    timestamps()
  end

  @doc false
  def changeset(access_log, attrs) do
    access_log
    |> cast(attrs, [
      :breadcrumb_id,
      :agent_id,
      :accessed_at,
      :process_name,
      :pid,
      :user,
      :access_type,
      :alert_id,
      :tamper_detected,
      :original_hash,
      :new_hash,
      :additional_data
    ])
    |> validate_required([
      :agent_id,
      :accessed_at,
      :access_type
    ])
    |> validate_inclusion(:access_type, [
      "read",
      "write",
      "delete",
      "execute",
      "modify",
      "rename",
      "move"
    ])
    |> foreign_key_constraint(:breadcrumb_id)
    |> foreign_key_constraint(:alert_id)
  end
end
