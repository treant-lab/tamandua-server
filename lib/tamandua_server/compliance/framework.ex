defmodule TamanduaServer.Compliance.Framework do
  @moduledoc """
  Compliance Framework Loader and Manager

  Loads compliance framework definitions from YAML files and provides
  framework metadata and control information.
  """

  require Logger

  @frameworks_dir Path.join([
    :code.priv_dir(:tamandua_server),
    "compliance_frameworks"
  ])

  defmodule FrameworkDefinition do
    @moduledoc "Compliance framework definition"
    defstruct [
      :id,
      :name,
      :full_name,
      :version,
      :description,
      :url,
      :categories,
      :controls
    ]
  end

  defmodule ControlDefinition do
    @moduledoc "Control definition from YAML"
    defstruct [
      :id,
      :control_id,
      :title,
      :description,
      :category,
      :subcategory,
      :severity,
      :automated,
      :evidence_types,
      :validation_query,
      :remediation_steps
    ]
  end

  @doc """
  Load all framework definitions from YAML files
  """
  def load_all_frameworks do
    if File.dir?(@frameworks_dir) do
      @frameworks_dir
      |> File.ls!()
      |> Enum.filter(&String.ends_with?(&1, ".yml"))
      |> Enum.map(&load_framework/1)
      |> Enum.reject(&is_nil/1)
    else
      Logger.warning("Compliance frameworks directory not found: #{@frameworks_dir}")
      []
    end
  end

  @doc """
  Load a specific framework by filename
  """
  def load_framework(filename) do
    path = Path.join(@frameworks_dir, filename)

    case YamlElixir.read_from_file(path) do
      {:ok, data} ->
        parse_framework(data, filename)

      {:error, reason} ->
        Logger.error("Failed to load framework #{filename}: #{inspect(reason)}")
        nil
    end
  rescue
    e ->
      Logger.error("Exception loading framework #{filename}: #{inspect(e)}")
      nil
  end

  @doc """
  Get framework by ID
  """
  def get_framework(framework_id) when is_atom(framework_id) do
    filename = "#{framework_id}.yml"
    load_framework(filename)
  end

  def get_framework(framework_id) when is_binary(framework_id) do
    get_framework(String.to_existing_atom(framework_id))
  end

  @doc """
  List all available frameworks
  """
  def list_frameworks do
    load_all_frameworks()
    |> Enum.map(fn framework ->
      %{
        id: framework.id,
        name: framework.name,
        full_name: framework.full_name,
        version: framework.version,
        description: framework.description,
        control_count: length(framework.controls),
        categories: framework.categories
      }
    end)
  end

  @doc """
  Get all controls for a framework
  """
  def get_controls(framework_id) do
    case get_framework(framework_id) do
      nil -> []
      framework -> framework.controls
    end
  end

  @doc """
  Get a specific control by ID
  """
  def get_control(framework_id, control_id) do
    get_controls(framework_id)
    |> Enum.find(&(&1.id == control_id))
  end

  @doc """
  Search controls by category
  """
  def get_controls_by_category(framework_id, category) do
    get_controls(framework_id)
    |> Enum.filter(&(&1.category == category))
  end

  @doc """
  Get controls by severity
  """
  def get_controls_by_severity(framework_id, severity) do
    get_controls(framework_id)
    |> Enum.filter(&(&1.severity == severity))
  end

  @doc """
  Get automated controls
  """
  def get_automated_controls(framework_id) do
    get_controls(framework_id)
    |> Enum.filter(& &1.automated)
  end

  # Private Functions

  defp parse_framework(data, filename) do
    framework_id = filename
    |> String.replace(".yml", "")
    |> String.to_atom()

    %FrameworkDefinition{
      id: framework_id,
      name: data["name"],
      full_name: data["full_name"],
      version: data["version"],
      description: data["description"],
      url: data["url"],
      categories: parse_categories(data),
      controls: parse_controls(data["controls"] || [])
    }
  end

  defp parse_categories(data) do
    cond do
      Map.has_key?(data, "categories") -> data["categories"]
      Map.has_key?(data, "trust_principles") -> data["trust_principles"]
      Map.has_key?(data, "functions") -> data["functions"]
      Map.has_key?(data, "domains") -> data["domains"]
      true -> []
    end
  end

  defp parse_controls(controls) when is_list(controls) do
    Enum.map(controls, &parse_control/1)
  end

  defp parse_controls(_), do: []

  defp parse_control(control_data) when is_map(control_data) do
    %ControlDefinition{
      id: control_data["id"],
      control_id: control_data["control_id"],
      title: control_data["title"],
      description: control_data["description"],
      category: parse_atom(control_data["category"]),
      subcategory: parse_atom(control_data["subcategory"]),
      severity: parse_atom(control_data["severity"]),
      automated: control_data["automated"] || false,
      evidence_types: parse_evidence_types(control_data["evidence_types"]),
      validation_query: control_data["validation_query"],
      remediation_steps: control_data["remediation_steps"] || []
    }
  end

  defp parse_atom(nil), do: nil
  defp parse_atom(value) when is_atom(value), do: value
  defp parse_atom(value) when is_binary(value) do
    String.to_atom(value)
  rescue
    ArgumentError -> String.to_atom(String.downcase(value))
  end

  defp parse_evidence_types(nil), do: []
  defp parse_evidence_types(types) when is_list(types) do
    Enum.map(types, &parse_atom/1)
  end
  defp parse_evidence_types(_), do: []
end
