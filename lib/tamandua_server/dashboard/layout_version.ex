defmodule TamanduaServer.Dashboard.LayoutVersion do
  @moduledoc """
  Schema for dashboard layout version history.

  Tracks all changes to layouts for audit and rollback purposes.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Dashboard.Layout
  alias TamanduaServer.Accounts.User

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "dashboard_layout_versions" do
    field :version, :integer
    field :widgets, {:array, :map}
    field :settings, :map
    field :change_description, :string

    belongs_to :layout, Layout
    belongs_to :created_by, User

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(version, attrs) do
    version
    |> cast(attrs, [:layout_id, :version, :widgets, :settings, :change_description, :created_by_id])
    |> validate_required([:layout_id, :version, :widgets, :settings])
    |> foreign_key_constraint(:layout_id)
    |> foreign_key_constraint(:created_by_id)
  end
end
