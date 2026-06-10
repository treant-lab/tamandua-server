defmodule TamanduaServer.Hunting.QueryTemplate do
  @moduledoc """
  Schema for pre-built threat hunting query templates.

  Templates are MITRE ATT&CK mapped queries that security analysts can use
  as starting points for investigations.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "query_templates" do
    field :name, :string
    field :description, :string
    field :category, :string
    field :subcategory, :string
    field :query, :string
    field :query_format, :string, default: "tql"
    field :tags, {:array, :string}, default: []
    field :mitre_techniques, {:array, :string}, default: []
    field :severity, :string
    field :is_built_in, :boolean, default: false
    field :is_public, :boolean, default: false
    field :usage_count, :integer, default: 0
    field :variables, :map, default: %{}

    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :created_by, TamanduaServer.Accounts.User

    timestamps()
  end

  @required_fields ~w(name query category)a
  @optional_fields ~w(description subcategory query_format tags mitre_techniques severity is_built_in is_public organization_id created_by_id variables)a

  @categories ~w(
    initial_access
    execution
    persistence
    privilege_escalation
    defense_evasion
    credential_access
    discovery
    lateral_movement
    collection
    command_and_control
    exfiltration
    impact
    general
  )

  @severities ~w(info low medium high critical)

  def changeset(template, attrs) do
    template
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:category, @categories)
    |> validate_inclusion(:severity, @severities)
    |> validate_length(:name, min: 3, max: 200)
    |> validate_length(:description, max: 2000)
    |> validate_query()
  end

  defp validate_query(changeset) do
    query = get_field(changeset, :query)
    query_format = get_field(changeset, :query_format)

    if query do
      case TamanduaServer.Hunting.QueryDSL.validate(query, String.to_atom(query_format)) do
        {:ok, _warnings} ->
          changeset

        {:error, errors} ->
          error_msg = Enum.map_join(errors, "; ", & &1.message)
          add_error(changeset, :query, "Invalid query: #{error_msg}")
      end
    else
      changeset
    end
  end

  @doc """
  List all query templates for a given organization.
  """
  def list_templates(organization_id, opts \\ []) do
    category = Keyword.get(opts, :category)
    search = Keyword.get(opts, :search)

    from(t in __MODULE__,
      where: t.organization_id == ^organization_id or t.is_public == true or t.is_built_in == true,
      order_by: [desc: t.usage_count, asc: t.name]
    )
    |> maybe_filter_category(category)
    |> maybe_search(search)
    |> TamanduaServer.Repo.all()
  end

  @doc """
  List built-in templates grouped by category.
  """
  def list_built_in_templates do
    from(t in __MODULE__,
      where: t.is_built_in == true,
      order_by: [asc: t.category, asc: t.name]
    )
    |> TamanduaServer.Repo.all()
    |> Enum.group_by(& &1.category)
  end

  @doc """
  Increment usage count for a template.
  """
  def increment_usage(template_id) do
    from(t in __MODULE__, where: t.id == ^template_id)
    |> TamanduaServer.Repo.update_all(inc: [usage_count: 1])
  end

  @doc """
  Render a template with variable substitution.
  """
  def render(template, variables \\ %{}) do
    # Merge template default variables with provided variables
    all_vars = Map.merge(template.variables, variables)

    # Replace {{variable}} placeholders
    rendered_query =
      Enum.reduce(all_vars, template.query, fn {key, value}, acc ->
        String.replace(acc, "{{#{key}}}", to_string(value))
      end)

    %{template | query: rendered_query}
  end

  defp maybe_filter_category(query, nil), do: query

  defp maybe_filter_category(query, category) do
    where(query, [t], t.category == ^category)
  end

  defp maybe_search(query, nil), do: query

  defp maybe_search(query, search_term) do
    pattern = "%#{search_term}%"

    where(
      query,
      [t],
      ilike(t.name, ^pattern) or
        ilike(t.description, ^pattern) or
        ^search_term in t.tags
    )
  end

  @doc """
  Get popular templates (most used).
  """
  def popular_templates(organization_id, limit \\ 10) do
    from(t in __MODULE__,
      where: t.organization_id == ^organization_id or t.is_public == true or t.is_built_in == true,
      order_by: [desc: t.usage_count],
      limit: ^limit
    )
    |> TamanduaServer.Repo.all()
  end

  @doc """
  Get templates by MITRE technique.
  """
  def by_mitre_technique(technique_id, organization_id) do
    from(t in __MODULE__,
      where:
        (t.organization_id == ^organization_id or t.is_public == true or t.is_built_in == true) and
          ^technique_id in t.mitre_techniques,
      order_by: [desc: t.usage_count, asc: t.name]
    )
    |> TamanduaServer.Repo.all()
  end
end
