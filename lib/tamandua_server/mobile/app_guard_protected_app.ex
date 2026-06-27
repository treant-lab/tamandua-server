defmodule TamanduaServer.Mobile.AppGuardProtectedApp do
  @moduledoc """
  Protected customer app registered for Tamandua App Guard ingestion.

  This mirrors the public `tamandua.app_guard.protected_app/v1` contract while
  keeping ingestion secrets as references only.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Mobile.AppGuardBuildManifest

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @platforms ~w(android ios)
  @statuses ~w(draft active paused revoked archived)
  @decisions ~w(allow observe warn step_up block kill_session)

  schema "app_guard_protected_apps" do
    field :app_id, :string
    field :display_name, :string
    field :platform, :string
    field :package_or_bundle_id, :string
    field :status, :string, default: "draft"
    field :ingestion, :map, default: %{}
    field :policy, :map, default: %{}
    field :manifest_created_at, :utc_datetime_usec

    belongs_to :organization, Organization
    has_many :build_manifests, AppGuardBuildManifest, foreign_key: :protected_app_id

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(
    organization_id app_id display_name platform package_or_bundle_id status
    ingestion policy manifest_created_at
  )a

  def changeset(app, attrs) do
    attrs = normalize_attrs(attrs)

    app
    |> cast(attrs, @required_fields)
    |> validate_required(@required_fields)
    |> validate_format(:app_id, ~r/^agapp_[a-zA-Z0-9_-]+$/)
    |> validate_length(:display_name, min: 1, max: 160)
    |> validate_length(:package_or_bundle_id, min: 1, max: 240)
    |> validate_inclusion(:platform, @platforms)
    |> validate_inclusion(:status, @statuses)
    |> validate_ingestion()
    |> validate_policy()
    |> unique_constraint([:organization_id, :app_id])
    |> foreign_key_constraint(:organization_id)
  end

  def by_organization(query \\ __MODULE__, organization_id) do
    from app in query, where: app.organization_id == ^organization_id
  end

  def by_app_id(query \\ __MODULE__, app_id) do
    from app in query, where: app.app_id == ^app_id
  end

  def by_platform(query \\ __MODULE__, platform) do
    from app in query, where: app.platform == ^platform
  end

  defp normalize_attrs(attrs) do
    attrs
    |> Map.put_new("manifest_created_at", attrs["created_at"] || attrs[:created_at])
    |> Map.update("platform", nil, &normalize_platform/1)
  end

  defp normalize_platform(value) when is_binary(value), do: value |> String.trim() |> String.downcase()
  defp normalize_platform(value), do: value

  defp validate_ingestion(changeset) do
    ingestion = get_field(changeset, :ingestion) || %{}

    changeset
    |> validate_nested_string(ingestion, :ingestion, "public_key_id", ~r/^agpk_[a-zA-Z0-9_-]+$/)
    |> validate_nested_string(ingestion, :ingestion, "secret_ref")
    |> validate_nested_inclusion(ingestion, :ingestion, "hmac_algorithm", ["HMAC-SHA256"])
    |> validate_nested_integer_range(ingestion, :ingestion, "rate_limit_per_minute", 1, 60000)
    |> validate_nested_list(ingestion, :ingestion, "allowed_origins")
    |> validate_nested_list(ingestion, :ingestion, "allowed_ip_cidrs")
    |> validate_rotation(ingestion)
  end

  defp validate_rotation(changeset, ingestion) do
    rotation = Map.get(ingestion, "rotation") || %{}

    changeset
    |> validate_nested_inclusion(rotation, :ingestion, "status", ["current", "rotating", "expired"])
    |> validate_nested_string(rotation, :ingestion, "last_rotated_at")
  end

  defp validate_policy(changeset) do
    policy = get_field(changeset, :policy) || %{}

    changeset
    |> validate_nested_string(policy, :policy, "policy_id")
    |> validate_nested_list(policy, :policy, "protected_workflows")
    |> validate_nested_inclusion(policy, :policy, "default_decision", @decisions)
  end

  defp validate_nested_string(changeset, source, parent, field, pattern \\ nil) do
    value = nested_value(source, field)

    cond do
      not is_binary(value) or String.trim(value) == "" ->
        add_error(changeset, parent, "#{field} is required")

      pattern && not Regex.match?(pattern, value) ->
        add_error(changeset, parent, "#{field} has invalid format")

      true ->
        changeset
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

  defp validate_nested_integer_range(changeset, source, parent, field, min, max) do
    value = nested_value(source, field)

    if is_integer(value) and value >= min and value <= max do
      changeset
    else
      add_error(changeset, parent, "#{field} must be an integer from #{min} to #{max}")
    end
  end

  defp validate_nested_list(changeset, source, parent, field) do
    if is_list(nested_value(source, field)) do
      changeset
    else
      add_error(changeset, parent, "#{field} must be a list")
    end
  end

  defp nested_value(source, field) do
    field
    |> String.split(".")
    |> Enum.reduce(source, fn key, current ->
      if is_map(current), do: Map.get(current, key), else: nil
    end)
  end
end
