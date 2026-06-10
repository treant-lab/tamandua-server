defmodule TamanduaServer.Detection.DslDetection do
  @moduledoc """
  Database schema for DSL detections.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "dsl_detections" do
    field :name, :string
    field :source, :string
    field :description, :string
    field :severity, :string
    field :enabled, :boolean, default: true
    field :mitre_techniques, {:array, :string}, default: []
    field :tags, {:array, :string}, default: []
    field :created_by, :string
    field :version, :integer, default: 1
    field :compiled_ast, :map  # Stored AST for introspection
    field :last_triggered_at, :utc_datetime
    field :trigger_count, :integer, default: 0

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(detection, attrs) do
    detection
    |> cast(attrs, [
      :name,
      :source,
      :description,
      :severity,
      :enabled,
      :mitre_techniques,
      :tags,
      :created_by,
      :version,
      :compiled_ast,
      :last_triggered_at,
      :trigger_count
    ])
    |> validate_required([:name, :source, :severity])
    |> validate_inclusion(:severity, ~w(critical high medium low info))
    |> validate_dsl_source()
    |> unique_constraint(:name)
  end

  defp validate_dsl_source(changeset) do
    case get_change(changeset, :source) do
      nil ->
        changeset

      source ->
        case TamanduaServer.Detection.DSL.Parser.parse(source) do
          {:ok, ast} ->
            changeset
            |> put_change(:compiled_ast, ast)
            |> extract_metadata_from_ast(ast)

          {:error, reason} ->
            add_error(changeset, :source, "Invalid DSL: #{reason}")
        end
    end
  end

  defp extract_metadata_from_ast(changeset, ast) do
    metadata = ast.metadata || %{}

    changeset
    |> put_change(:name, ast.name)
    |> put_change(:description, metadata["description"] || metadata[:description])
    |> put_change(:severity, metadata["severity"] || metadata[:severity])
    |> put_change(:mitre_techniques, metadata["mitre"] || metadata[:mitre] || [])
  end
end
