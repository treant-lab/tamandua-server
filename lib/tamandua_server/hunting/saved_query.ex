defmodule TamanduaServer.Hunting.SavedQuery do
  @moduledoc """
  Schema for saved hunt queries with library features.
  Supports templates, categories (MITRE tactics), sharing, scheduling, and community features.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @query_types ~w(hunt sigma yara nl custom sql)
  @visibility_types ~w(private organization public)

  schema "saved_queries" do
    field :name, :string
    field :description, :string
    field :query, :string
    field :query_type, :string, default: "hunt"
    field :category, :string
    field :tags, {:array, :string}, default: []
    field :is_template, :boolean, default: false
    field :is_public, :boolean, default: false
    field :use_count, :integer, default: 0
    field :last_used_at, :utc_datetime

    # Library features
    field :is_favorite, :boolean, default: false
    field :visibility, :string, default: "private"
    field :parameters, :map, default: %{}

    # Performance tracking
    field :avg_execution_time_ms, :integer
    field :last_execution_time_ms, :integer

    # Community features
    field :upvotes, :integer, default: 0
    field :downvotes, :integer, default: 0
    field :rating, :float, default: 0.0
    field :download_count, :integer, default: 0

    # MITRE ATT&CK mapping
    field :mitre_tactics, {:array, :string}, default: []
    field :mitre_techniques, {:array, :string}, default: []

    # Author tracking
    field :author_name, :string
    field :author_organization, :string

    # Version control
    field :version, :string, default: "1.0.0"

    belongs_to :user, TamanduaServer.Accounts.User, foreign_key: :created_by
    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :parent, TamanduaServer.Hunting.SavedQuery

    has_many :schedules, TamanduaServer.Hunting.QuerySchedule
    has_many :ratings, TamanduaServer.Hunting.QueryRating
    has_many :comments, TamanduaServer.Hunting.QueryComment

    timestamps()
  end

  @doc false
  def changeset(saved_query, attrs) do
    saved_query
    |> cast(attrs, [
      :name, :description, :query, :query_type, :category,
      :tags, :is_template, :is_public, :created_by, :organization_id,
      :is_favorite, :visibility, :parameters,
      :mitre_tactics, :mitre_techniques,
      :author_name, :author_organization, :version, :parent_id
    ])
    |> validate_required([:name, :query])
    |> validate_inclusion(:query_type, @query_types)
    |> validate_inclusion(:visibility, @visibility_types)
    |> validate_length(:name, min: 1, max: 255)
    |> validate_length(:query, min: 1, max: 50_000)
    |> validate_parameters()
  end

  def increment_use_changeset(saved_query) do
    saved_query
    |> change(%{
      use_count: (saved_query.use_count || 0) + 1,
      last_used_at: DateTime.utc_now() |> DateTime.truncate(:second)
    })
  end

  def update_performance_changeset(saved_query, execution_time_ms) do
    current_avg = saved_query.avg_execution_time_ms || 0
    use_count = saved_query.use_count || 0

    new_avg =
      if use_count > 0 do
        div(current_avg * use_count + execution_time_ms, use_count + 1)
      else
        execution_time_ms
      end

    saved_query
    |> change(%{
      avg_execution_time_ms: new_avg,
      last_execution_time_ms: execution_time_ms
    })
  end

  def increment_download_changeset(saved_query) do
    saved_query
    |> change(%{
      download_count: (saved_query.download_count || 0) + 1
    })
  end

  defp validate_parameters(changeset) do
    case get_field(changeset, :parameters) do
      params when is_map(params) ->
        # Validate each parameter has required fields
        valid? =
          Enum.all?(params, fn {_name, config} ->
            is_map(config) and
              Map.has_key?(config, "type") and
              config["type"] in ["string", "number", "date", "boolean"]
          end)

        if valid? do
          changeset
        else
          add_error(changeset, :parameters, "invalid parameter configuration")
        end

      _ ->
        changeset
    end
  end
end
