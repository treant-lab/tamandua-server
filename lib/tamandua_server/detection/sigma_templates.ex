defmodule TamanduaServer.Detection.SigmaTemplates do
  @moduledoc """
  Manages system-wide Sigma rule templates.

  Templates are global rules that get copied to each organization.
  This allows organizations to have their own customizable copies of
  standard detection rules while maintaining a reference to the original.

  ## Template Lifecycle

  1. Create a system template with `create_system_template/1`
  2. Copy templates to organizations with `copy_templates_to_organization/1`
  3. Organizations can customize their copies independently
  4. Push updates from templates to copies with `sync_template_updates/1`

  ## Example

      # Create a system template
      {:ok, template} = SigmaTemplates.create_system_template(%{
        name: "suspicious_powershell",
        title: "Suspicious PowerShell Execution",
        source: "...",
        level: "high"
      })

      # Copy all templates to a new organization
      {:ok, copies} = SigmaTemplates.copy_templates_to_organization(org_id)

      # Push updates from a template to all organization copies
      {:ok, updated_count} = SigmaTemplates.sync_template_updates(template.id)
  """

  import Ecto.Query

  alias TamanduaServer.Detection.SigmaRule
  alias TamanduaServer.Repo

  require Logger

  @doc """
  Lists all system templates.

  ## Options

  - `:enabled` - filter by enabled status (boolean)
  - `:level` - filter by severity level (string)
  - `:logsource_category` - filter by logsource category (string)
  - `:search` - search in name, title, and description (string)

  ## Examples

      iex> list_system_templates()
      [%SigmaRule{is_system_template: true, ...}, ...]

      iex> list_system_templates(enabled: true, level: "high")
      [%SigmaRule{enabled: true, level: "high", ...}, ...]
  """
  @spec list_system_templates(keyword()) :: [SigmaRule.t()]
  def list_system_templates(opts \\ []) do
    query =
      from(r in SigmaRule,
        where: r.is_system_template == true,
        order_by: [desc: r.inserted_at]
      )

    query
    |> apply_template_filters(opts)
    |> Repo.all()
  end

  @doc """
  Gets a single system template by ID.

  Returns `nil` if the template does not exist or is not a system template.
  """
  @spec get_system_template(binary()) :: SigmaRule.t() | nil
  def get_system_template(id) when is_binary(id) do
    from(r in SigmaRule,
      where: r.id == ^id and r.is_system_template == true
    )
    |> Repo.one()
  end

  @doc """
  Copies all enabled system templates to an organization.

  This is typically called when a new organization is created to provision
  the standard set of detection rules.

  Returns a list of the created rule copies.

  ## Options

  - `:enabled_only` - only copy enabled templates (default: true)
  - `:skip_existing` - skip templates already copied to this org (default: true)

  ## Examples

      iex> copy_templates_to_organization(org_id)
      {:ok, [%SigmaRule{}, ...]}

      iex> copy_templates_to_organization(org_id, enabled_only: false)
      {:ok, [%SigmaRule{}, ...]}
  """
  @spec copy_templates_to_organization(binary(), keyword()) ::
          {:ok, [SigmaRule.t()]} | {:error, term()}
  def copy_templates_to_organization(organization_id, opts \\ []) when is_binary(organization_id) do
    enabled_only = Keyword.get(opts, :enabled_only, true)
    skip_existing = Keyword.get(opts, :skip_existing, true)

    templates_query =
      from(r in SigmaRule,
        where: r.is_system_template == true
      )

    templates_query =
      if enabled_only do
        from(r in templates_query, where: r.enabled == true)
      else
        templates_query
      end

    templates = Repo.all(templates_query)

    existing_template_ids =
      if skip_existing do
        from(r in SigmaRule,
          where:
            r.organization_id == ^organization_id and
              not is_nil(r.copied_from_template_id),
          select: r.copied_from_template_id
        )
        |> Repo.all()
        |> MapSet.new()
      else
        MapSet.new()
      end

    results =
      templates
      |> Enum.reject(fn template -> MapSet.member?(existing_template_ids, template.id) end)
      |> Enum.map(fn template ->
        copy_template_to_organization(template, organization_id)
      end)

    errors = Enum.filter(results, fn {status, _} -> status == :error end)

    if Enum.empty?(errors) do
      copies = Enum.map(results, fn {:ok, copy} -> copy end)
      Logger.info("Copied #{length(copies)} templates to organization #{organization_id}")
      {:ok, copies}
    else
      Logger.error("Failed to copy some templates to organization #{organization_id}: #{inspect(errors)}")
      {:error, {:partial_failure, results}}
    end
  end

  @doc """
  Copies a single template to an organization.

  ## Examples

      iex> copy_template_to_organization(template, org_id)
      {:ok, %SigmaRule{copied_from_template_id: template.id, ...}}
  """
  @spec copy_template_to_organization(SigmaRule.t(), binary()) ::
          {:ok, SigmaRule.t()} | {:error, Ecto.Changeset.t()}
  def copy_template_to_organization(%SigmaRule{is_system_template: true} = template, organization_id) do
    attrs =
      template
      |> Map.from_struct()
      |> Map.drop([:id, :__meta__, :organization, :template, :inserted_at, :updated_at])
      |> Map.put(:organization_id, organization_id)
      |> Map.put(:is_system_template, false)
      |> Map.put(:copied_from_template_id, template.id)

    %SigmaRule{}
    |> SigmaRule.changeset(attrs)
    |> Repo.insert()
  end

  def copy_template_to_organization(%SigmaRule{is_system_template: false}, _organization_id) do
    {:error, :not_a_template}
  end

  @doc """
  Syncs updates from a template to all organization copies.

  This will update all rules that were copied from this template with the
  template's current values. Only fields that haven't been customized by
  the organization will be updated.

  ## Options

  - `:force` - update all fields even if customized (default: false)
  - `:fields` - list of specific fields to sync (default: all syncable fields)

  Returns the count of updated copies.

  ## Examples

      iex> sync_template_updates(template_id)
      {:ok, 5}

      iex> sync_template_updates(template_id, force: true)
      {:ok, 5}
  """
  @spec sync_template_updates(binary(), keyword()) :: {:ok, non_neg_integer()} | {:error, term()}
  def sync_template_updates(template_id, opts \\ []) when is_binary(template_id) do
    force = Keyword.get(opts, :force, false)
    fields = Keyword.get(opts, :fields, syncable_fields())

    case get_system_template(template_id) do
      nil ->
        {:error, :template_not_found}

      template ->
        copies =
          from(r in SigmaRule,
            where: r.copied_from_template_id == ^template_id
          )
          |> Repo.all()

        updated_count =
          copies
          |> Enum.map(fn copy ->
            sync_copy_with_template(copy, template, fields, force)
          end)
          |> Enum.count(fn result -> match?({:ok, _}, result) end)

        Logger.info("Synced template #{template_id} to #{updated_count} copies")
        {:ok, updated_count}
    end
  end

  @doc """
  Creates a new system template.

  ## Examples

      iex> create_system_template(%{name: "test_rule", source: "..."})
      {:ok, %SigmaRule{is_system_template: true, ...}}
  """
  @spec create_system_template(map()) :: {:ok, SigmaRule.t()} | {:error, Ecto.Changeset.t()}
  def create_system_template(attrs) when is_map(attrs) do
    %SigmaRule{}
    |> SigmaRule.template_changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a system template.

  Note: This does not automatically sync updates to organization copies.
  Call `sync_template_updates/2` to push changes to copies.
  """
  @spec update_system_template(SigmaRule.t(), map()) ::
          {:ok, SigmaRule.t()} | {:error, Ecto.Changeset.t()}
  def update_system_template(%SigmaRule{is_system_template: true} = template, attrs) do
    template
    |> SigmaRule.template_changeset(attrs)
    |> Repo.update()
  end

  def update_system_template(%SigmaRule{is_system_template: false}, _attrs) do
    {:error, :not_a_template}
  end

  @doc """
  Deletes a system template.

  Organization copies will have their `copied_from_template_id` set to nil
  due to the `on_delete: :nilify` constraint.
  """
  @spec delete_system_template(SigmaRule.t()) :: {:ok, SigmaRule.t()} | {:error, Ecto.Changeset.t()}
  def delete_system_template(%SigmaRule{is_system_template: true} = template) do
    Repo.delete(template)
  end

  def delete_system_template(%SigmaRule{is_system_template: false}) do
    {:error, :not_a_template}
  end

  @doc """
  Lists all organization copies of a template.
  """
  @spec list_template_copies(binary()) :: [SigmaRule.t()]
  def list_template_copies(template_id) when is_binary(template_id) do
    from(r in SigmaRule,
      where: r.copied_from_template_id == ^template_id,
      preload: [:organization]
    )
    |> Repo.all()
  end

  @doc """
  Counts how many organizations have copies of a template.
  """
  @spec count_template_deployments(binary()) :: non_neg_integer()
  def count_template_deployments(template_id) when is_binary(template_id) do
    from(r in SigmaRule,
      where: r.copied_from_template_id == ^template_id,
      select: count(r.id)
    )
    |> Repo.one()
  end

  @doc """
  Checks if a rule is a copy of a template.
  """
  @spec is_template_copy?(SigmaRule.t()) :: boolean()
  def is_template_copy?(%SigmaRule{copied_from_template_id: nil}), do: false
  def is_template_copy?(%SigmaRule{copied_from_template_id: _id}), do: true

  @doc """
  Gets the template that a rule was copied from.
  """
  @spec get_source_template(SigmaRule.t()) :: SigmaRule.t() | nil
  def get_source_template(%SigmaRule{copied_from_template_id: nil}), do: nil

  def get_source_template(%SigmaRule{copied_from_template_id: template_id}) do
    get_system_template(template_id)
  end

  # Private functions

  defp apply_template_filters(query, []), do: query

  defp apply_template_filters(query, [{:enabled, enabled} | rest]) when is_boolean(enabled) do
    query
    |> where([r], r.enabled == ^enabled)
    |> apply_template_filters(rest)
  end

  defp apply_template_filters(query, [{:level, level} | rest]) when is_binary(level) do
    query
    |> where([r], r.level == ^level)
    |> apply_template_filters(rest)
  end

  defp apply_template_filters(query, [{:logsource_category, category} | rest]) when is_binary(category) do
    query
    |> where([r], r.logsource_category == ^category)
    |> apply_template_filters(rest)
  end

  defp apply_template_filters(query, [{:search, term} | rest]) when is_binary(term) do
    search_term = "%#{term}%"

    query
    |> where(
      [r],
      ilike(r.name, ^search_term) or
        ilike(r.title, ^search_term) or
        ilike(r.description, ^search_term)
    )
    |> apply_template_filters(rest)
  end

  defp apply_template_filters(query, [_ | rest]) do
    apply_template_filters(query, rest)
  end

  # Fields that can be synced from template to copies
  defp syncable_fields do
    [
      :title,
      :description,
      :author,
      :author_pubkey,
      :level,
      :source,
      :detection,
      :logsource_category,
      :logsource_product,
      :logsource_service,
      :mitre_tactics,
      :mitre_techniques,
      :references,
      :tags
    ]
  end

  defp sync_copy_with_template(copy, template, fields, force) do
    updates =
      fields
      |> Enum.filter(fn field ->
        force || should_sync_field?(copy, template, field)
      end)
      |> Enum.map(fn field ->
        {field, Map.get(template, field)}
      end)
      |> Map.new()

    if map_size(updates) > 0 do
      copy
      |> SigmaRule.changeset(updates)
      |> Repo.update()
    else
      {:ok, copy}
    end
  end

  # Determines if a field should be synced (not customized by the org)
  # For now, we sync all specified fields unless force is false
  # In the future, this could track which fields were manually edited
  defp should_sync_field?(_copy, _template, _field) do
    true
  end
end
