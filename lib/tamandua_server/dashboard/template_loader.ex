defmodule TamanduaServer.Dashboard.TemplateLoader do
  @moduledoc """
  Loads pre-built dashboard layout templates from JSON files.

  Templates are stored in priv/layout_templates/ and can be loaded
  into the database for use across organizations.
  """

  alias TamanduaServer.Dashboard.LayoutManager
  alias TamanduaServer.Repo

  @templates_dir Application.app_dir(:tamandua_server, "priv/layout_templates")

  @doc """
  Loads all templates from the templates directory into the database
  for a given organization.

  Returns {:ok, count} on success with the number of templates loaded.
  """
  def load_all_templates(organization_id) do
    templates = list_template_files()

    loaded =
      Enum.reduce(templates, 0, fn template_path, count ->
        case load_template(template_path, organization_id) do
          {:ok, _layout} -> count + 1
          {:error, _} -> count
        end
      end)

    {:ok, loaded}
  end

  @doc """
  Loads a single template file into the database.
  """
  def load_template(template_path, organization_id) do
    with {:ok, content} <- File.read(template_path),
         {:ok, template_data} <- Jason.decode(content),
         {:ok, layout} <- create_layout_from_template(template_data, organization_id) do
      {:ok, layout}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Lists all template JSON files in the templates directory.
  """
  def list_template_files do
    if File.exists?(@templates_dir) do
      @templates_dir
      |> File.ls!()
      |> Enum.filter(&String.ends_with?(&1, ".json"))
      |> Enum.map(&Path.join(@templates_dir, &1))
    else
      []
    end
  end

  @doc """
  Gets a specific template by filename.
  """
  def get_template(filename) when is_binary(filename) do
    template_path = Path.join(@templates_dir, filename)

    if File.exists?(template_path) do
      case File.read(template_path) do
        {:ok, content} ->
          Jason.decode(content)

        error ->
          error
      end
    else
      {:error, :not_found}
    end
  end

  @doc """
  Ensures default templates exist for an organization.
  Called during organization setup or first login.
  """
  def ensure_default_templates(organization_id) do
    # Check if templates already exist
    existing = LayoutManager.list_public_templates(organization_id)

    if Enum.empty?(existing) do
      load_all_templates(organization_id)
    else
      {:ok, 0}
    end
  end

  # Private helpers

  defp create_layout_from_template(template_data, organization_id) do
    # Check if template already exists
    case Repo.get_by(TamanduaServer.Dashboard.Layout,
      name: template_data["name"],
      organization_id: organization_id,
      is_template: true
    ) do
      nil ->
        # Create new template
        attrs =
          template_data
          |> Map.put("organization_id", organization_id)
          |> Map.put("is_template", true)
          |> Map.put("is_public", true)
          |> Map.delete("version")
          |> Map.delete("exported_at")

        LayoutManager.create_layout(attrs)

      existing ->
        # Template already exists, optionally update it
        {:ok, existing}
    end
  end
end
