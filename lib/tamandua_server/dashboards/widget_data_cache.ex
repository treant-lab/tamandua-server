defmodule TamanduaServer.Dashboards.WidgetDataCache do
  @moduledoc """
  Schema for caching widget data to improve dashboard performance.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "widget_data_cache" do
    field :cache_key, :string
    field :data, :map
    field :expires_at, :utc_datetime_usec

    belongs_to :widget, TamanduaServer.Dashboards.Widget

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(widget_id cache_key data expires_at)a

  def changeset(cache, attrs) do
    cache
    |> cast(attrs, @required_fields)
    |> validate_required(@required_fields)
    |> unique_constraint([:widget_id, :cache_key])
    |> foreign_key_constraint(:widget_id)
  end

  @doc """
  Checks if the cache is expired.
  """
  def expired?(%__MODULE__{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end
end
