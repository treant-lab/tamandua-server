defmodule TamanduaServer.Filtering.SavedFilter do
  @moduledoc """
  Schema for saved filters.

  Supports:
  - Personal and shared filters
  - Filter templates
  - Filter categories
  - Pin/favorite filters
  - Usage tracking
  - Filter versioning
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Filtering.FilterParser

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "saved_filters" do
    field :name, :string
    field :description, :string
    field :filter_json, :map
    field :category, :string
    field :scope, :string, default: "alerts"

    # Sharing
    field :is_public, :boolean, default: false
    field :is_template, :boolean, default: false
    field :is_pinned, :boolean, default: false
    field :shared_with_team, :boolean, default: false

    # Usage tracking
    field :usage_count, :integer, default: 0
    field :last_used_at, :utc_datetime_usec

    # Versioning
    field :version, :integer, default: 1

    belongs_to :user, User
    belongs_to :organization, Organization
    belongs_to :parent, __MODULE__, foreign_key: :parent_id, type: :binary_id

    has_many :versions, __MODULE__, foreign_key: :parent_id

    timestamps()
  end

  @valid_categories [
    "alerts",
    "agents",
    "events",
    "telemetry",
    "threats",
    "investigations",
    "compliance",
    "forensics",
    "threat_hunting",
    "custom"
  ]

  @valid_scopes [
    "alerts",
    "agents",
    "events",
    "telemetry",
    "users",
    "investigations"
  ]

  @doc false
  def changeset(saved_filter, attrs) do
    saved_filter
    |> cast(attrs, [
      :name,
      :description,
      :filter_json,
      :category,
      :scope,
      :is_public,
      :is_template,
      :is_pinned,
      :shared_with_team,
      :user_id,
      :organization_id,
      :parent_id,
      :version,
      :usage_count,
      :last_used_at
    ])
    |> validate_required([:name, :filter_json, :user_id, :organization_id])
    |> validate_length(:name, min: 1, max: 255)
    |> validate_length(:description, max: 1000)
    |> validate_inclusion(:category, [nil | @valid_categories])
    |> validate_inclusion(:scope, @valid_scopes)
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
        case FilterParser.validate(filter) do
          {:ok, _validated} ->
            changeset

          {:error, reason} ->
            add_error(changeset, :filter_json, "invalid filter structure: #{reason}")
        end

      _ ->
        add_error(changeset, :filter_json, "must be a map")
    end
  end

  @doc """
  Increments usage count and updates last_used_at timestamp.
  """
  def record_usage_changeset(saved_filter) do
    saved_filter
    |> change(%{
      usage_count: saved_filter.usage_count + 1,
      last_used_at: DateTime.utc_now()
    })
  end

  @doc """
  Creates a new version of the filter.
  """
  def create_version_changeset(saved_filter, attrs) do
    new_version = saved_filter.version + 1
    parent_id = saved_filter.parent_id || saved_filter.id

    %__MODULE__{}
    |> cast(attrs, [:name, :description, :filter_json, :category, :scope])
    |> put_change(:version, new_version)
    |> put_change(:parent_id, parent_id)
    |> put_change(:user_id, saved_filter.user_id)
    |> put_change(:organization_id, saved_filter.organization_id)
    |> put_change(:is_public, saved_filter.is_public)
    |> put_change(:is_template, saved_filter.is_template)
    |> validate_required([:name, :filter_json, :user_id, :organization_id])
    |> validate_filter_structure()
  end

  @doc """
  Returns list of valid categories.
  """
  def valid_categories, do: @valid_categories

  @doc """
  Returns list of valid scopes.
  """
  def valid_scopes, do: @valid_scopes
end
