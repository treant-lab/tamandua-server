defmodule TamanduaServer.Fim.Change do
  @moduledoc """
  Schema for FIM change events.

  Records detected file integrity changes.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "fim_changes" do
    field :agent_id, :string
    field :path, :string
    field :change_type, :string
    field :previous_hash, :string
    field :current_hash, :string
    field :previous_size, :integer
    field :current_size, :integer
    field :previous_permissions, :string
    field :current_permissions, :string
    field :previous_owner, :string
    field :current_owner, :string
    field :category, :string
    field :compliance_impact, {:array, :string}, default: []
    field :whitelisted, :boolean, default: false
    field :whitelist_reason, :string
    field :modifier_pid, :integer
    field :modifier_process, :string
    field :entropy, :float
    field :severity, :string
    field :detected_at, :utc_datetime
    field :reviewed, :boolean, default: false
    field :reviewed_by, :string
    field :reviewed_at, :utc_datetime
    field :remediated, :boolean, default: false
    field :remediation_action, :string
    field :remediated_at, :utc_datetime

    timestamps()
  end

  @doc false
  def changeset(change, attrs) do
    change
    |> cast(attrs, [
      :agent_id,
      :path,
      :change_type,
      :previous_hash,
      :current_hash,
      :previous_size,
      :current_size,
      :previous_permissions,
      :current_permissions,
      :previous_owner,
      :current_owner,
      :category,
      :compliance_impact,
      :whitelisted,
      :whitelist_reason,
      :modifier_pid,
      :modifier_process,
      :entropy,
      :severity,
      :detected_at,
      :reviewed,
      :reviewed_by,
      :reviewed_at,
      :remediated,
      :remediation_action,
      :remediated_at
    ])
    |> validate_required([:agent_id, :path, :change_type, :severity, :detected_at])
  end
end
