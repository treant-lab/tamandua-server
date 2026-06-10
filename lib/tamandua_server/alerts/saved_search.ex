defmodule TamanduaServer.Alerts.SavedSearch do
  @moduledoc """
  Schema for saved alert searches.

  Supports personal and shared searches, search templates, and versioning.
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "saved_searches" do
    field :name, :string
    field :description, :string
    field :filter_json, :map
    field :is_shared, :boolean, default: false
    field :is_template, :boolean, default: false
    field :is_starred, :boolean, default: false
    field :category, :string
    field :version, :integer, default: 1
    field :usage_count, :integer, default: 0
    field :last_used_at, :utc_datetime_usec

    belongs_to :parent, __MODULE__, foreign_key: :parent_id, type: :binary_id
    belongs_to :user, User
    belongs_to :organization, Organization

    has_many :versions, __MODULE__, foreign_key: :parent_id

    timestamps()
  end

  @doc false
  def changeset(saved_search, attrs) do
    saved_search
    |> cast(attrs, [
      :name,
      :description,
      :filter_json,
      :is_shared,
      :is_template,
      :is_starred,
      :category,
      :version,
      :parent_id,
      :user_id,
      :organization_id,
      :usage_count,
      :last_used_at
    ])
    |> validate_required([:name, :filter_json, :user_id, :organization_id])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_inclusion(:category, [
      nil,
      "detection",
      "investigation",
      "compliance",
      "forensics",
      "threat_hunting",
      "custom"
    ])
    |> validate_filter_structure()
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:parent_id)
  end

  @doc """
  Validates the filter JSON structure.
  """
  defp validate_filter_structure(changeset) do
    case get_change(changeset, :filter_json) do
      nil ->
        changeset

      filter when is_map(filter) ->
        if valid_filter_structure?(filter) do
          changeset
        else
          add_error(changeset, :filter_json, "invalid filter structure")
        end

      _ ->
        add_error(changeset, :filter_json, "must be a map")
    end
  end

  # Validates that the filter has the expected structure
  defp valid_filter_structure?(filter) when is_map(filter) do
    # Must have either conditions or quick_filter
    has_conditions = Map.has_key?(filter, "conditions") || Map.has_key?(filter, :conditions)
    has_quick_filter = Map.has_key?(filter, "quick_filter") || Map.has_key?(filter, :quick_filter)

    has_conditions || has_quick_filter
  end

  defp valid_filter_structure?(_), do: false

  @doc """
  Increments usage count and updates last_used_at timestamp.
  """
  def record_usage_changeset(saved_search) do
    saved_search
    |> change(%{
      usage_count: saved_search.usage_count + 1,
      last_used_at: DateTime.utc_now()
    })
  end

  @doc """
  Creates a new version of the search.
  """
  def create_version_changeset(saved_search, attrs) do
    new_version = saved_search.version + 1
    parent_id = saved_search.parent_id || saved_search.id

    %__MODULE__{}
    |> cast(attrs, [:name, :description, :filter_json, :category])
    |> put_change(:version, new_version)
    |> put_change(:parent_id, parent_id)
    |> put_change(:user_id, saved_search.user_id)
    |> put_change(:organization_id, saved_search.organization_id)
    |> put_change(:is_shared, saved_search.is_shared)
    |> put_change(:is_template, saved_search.is_template)
    |> validate_required([:name, :filter_json, :user_id, :organization_id])
  end
end
