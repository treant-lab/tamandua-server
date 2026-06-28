defmodule TamanduaServer.Mobile.AppGuardResearchProgram do
  @moduledoc """
  Customer-owned App Guard research or private bounty program.

  Mirrors `tamandua.app_guard.research_program/v1` while keeping the program
  scoped to one organization.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Mobile.AppGuardResearchSubmission

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @platforms ~w(android ios)
  @statuses ~w(draft beta active paused closed)
  @visibilities ~w(private public)
  @program_types ~w(vulnerability_disclosure bug_bounty app_guard_assessment)

  schema "app_guard_research_programs" do
    field(:program_id, :string)
    field(:name, :string)
    field(:description, :string)
    field(:status, :string)
    field(:visibility, :string)
    field(:program_type, :string, default: "vulnerability_disclosure")
    field(:app, :map, default: %{})
    field(:scope, :map, default: %{})
    field(:rules, :string)
    field(:reward, :map, default: %{})
    field(:invited_researchers, {:array, :string}, default: [])
    field(:manifest_created_at, :utc_datetime_usec)

    belongs_to(:organization, Organization)
    has_many(:submissions, AppGuardResearchSubmission, foreign_key: :research_program_id)

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(
    organization_id program_id name status visibility program_type app scope rules
    invited_researchers manifest_created_at
  )a

  def changeset(program, attrs) do
    attrs = normalize_attrs(attrs)

    program
    |> cast(attrs, @required_fields ++ [:description, :reward])
    |> validate_required(@required_fields)
    |> validate_format(:program_id, ~r/^agres_[a-zA-Z0-9_-]+$/)
    |> validate_length(:name, min: 1, max: 160)
    |> validate_length(:description, max: 4000)
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:visibility, @visibilities)
    |> validate_inclusion(:program_type, @program_types)
    |> validate_app()
    |> validate_scope()
    |> validate_length(:rules, min: 1, max: 8000)
    |> unique_constraint([:organization_id, :program_id])
    |> foreign_key_constraint(:organization_id)
  end

  def by_organization(query \\ __MODULE__, organization_id) do
    from(program in query, where: program.organization_id == ^organization_id)
  end

  def by_program_id(query \\ __MODULE__, program_id) do
    from(program in query, where: program.program_id == ^program_id)
  end

  def latest_first(query \\ __MODULE__) do
    from(program in query, order_by: [desc: program.manifest_created_at])
  end

  defp normalize_attrs(attrs) do
    attrs
    |> Map.put_new("manifest_created_at", attrs["created_at"] || attrs[:created_at])
    |> Map.put_new(
      "program_type",
      attrs["program_type"] || attrs[:program_type] || "vulnerability_disclosure"
    )
    |> Map.put_new(
      "invited_researchers",
      attrs["invited_researchers"] || attrs[:invited_researchers] || []
    )
    |> Map.update("app", %{}, &normalize_app/1)
  end

  defp normalize_app(%{} = app) do
    Map.update(app, "platform", app[:platform], fn
      value when is_binary(value) -> value |> String.trim() |> String.downcase()
      value -> value
    end)
  end

  defp normalize_app(value), do: value

  defp validate_app(changeset) do
    app = get_field(changeset, :app) || %{}

    changeset
    |> validate_nested_inclusion(app, :app, "platform", @platforms)
    |> validate_nested_string(app, :app, "package_or_bundle_id")
  end

  defp validate_scope(changeset) do
    scope = get_field(changeset, :scope) || %{}
    targets = Map.get(scope, "targets") || Map.get(scope, :targets) || []

    cond do
      not is_list(targets) or targets == [] ->
        add_error(changeset, :scope, "targets must be a non-empty list")

      not Enum.any?(targets, &target_type?(&1, "build_manifest")) ->
        add_error(changeset, :scope, "targets must include a build_manifest target")

      true ->
        changeset
    end
  end

  defp target_type?(%{} = target, expected) do
    (Map.get(target, "target_type") || Map.get(target, :target_type)) == expected
  end

  defp target_type?(_, _), do: false

  defp validate_nested_string(changeset, source, parent, field) do
    value = nested_value(source, field)

    if is_binary(value) and String.trim(value) != "" do
      changeset
    else
      add_error(changeset, parent, "#{field} is required")
    end
  end

  defp validate_nested_inclusion(changeset, source, parent, field, allowed) do
    value = nested_value(source, field)

    if value in allowed do
      changeset
    else
      add_error(changeset, parent, "#{field} must be one of: #{Enum.join(allowed, ", ")}")
    end
  end

  defp nested_value(source, field) do
    field
    |> String.split(".")
    |> Enum.reduce(source, fn key, current ->
      if is_map(current),
        do: Map.get(current, key) || Map.get(current, String.to_atom(key)),
        else: nil
    end)
  end
end
