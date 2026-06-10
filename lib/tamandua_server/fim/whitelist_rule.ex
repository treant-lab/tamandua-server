defmodule TamanduaServer.Fim.WhitelistRule do
  @moduledoc """
  Schema for FIM whitelist rules.

  Defines expected file changes that should not trigger alerts.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "fim_whitelist_rules" do
    field :agent_id, :string
    field :pattern, :string
    field :allowed_changes, {:array, :string}, default: []
    field :reason, :string
    field :expires, :integer, default: 0
    field :added_by, :string
    field :enabled, :boolean, default: true

    timestamps()
  end

  @doc false
  def changeset(rule, attrs) do
    rule
    |> cast(attrs, [
      :agent_id,
      :pattern,
      :allowed_changes,
      :reason,
      :expires,
      :added_by,
      :enabled
    ])
    |> validate_required([:agent_id, :pattern, :reason, :added_by])
  end
end
