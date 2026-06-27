defmodule TamanduaServer.Mobile.AppGuardBuildManifest do
  @moduledoc """
  Build manifest for a protected App Guard app artifact.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Mobile.AppGuardProtectedApp

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @platforms ~w(android ios)
  @artifact_types ~w(apk aab ipa xcarchive)
  @signing_schemes ~w(android_apk_signature_v2_v3 android_app_bundle ios_codesign)

  schema "app_guard_build_manifests" do
    field :build_id, :string
    field :app_id, :string
    field :platform, :string
    field :version, :map, default: %{}
    field :artifact, :map, default: %{}
    field :signing, :map, default: %{}
    field :sdk, :map, default: %{}
    field :policy_id, :string
    field :manifest_created_at, :utc_datetime_usec

    belongs_to :organization, Organization
    belongs_to :protected_app, AppGuardProtectedApp

    timestamps(type: :utc_datetime_usec)
  end

  @required_fields ~w(
    organization_id protected_app_id build_id app_id platform version artifact
    signing sdk policy_id manifest_created_at
  )a

  def changeset(manifest, attrs) do
    attrs = normalize_attrs(attrs)

    manifest
    |> cast(attrs, @required_fields)
    |> validate_required(@required_fields)
    |> validate_format(:build_id, ~r/^agbld_[a-zA-Z0-9_-]+$/)
    |> validate_format(:app_id, ~r/^agapp_[a-zA-Z0-9_-]+$/)
    |> validate_inclusion(:platform, @platforms)
    |> validate_version()
    |> validate_artifact()
    |> validate_signing()
    |> validate_sdk()
    |> validate_length(:policy_id, min: 1)
    |> unique_constraint([:organization_id, :build_id])
    |> foreign_key_constraint(:organization_id)
    |> foreign_key_constraint(:protected_app_id)
  end

  def by_organization(query \\ __MODULE__, organization_id) do
    from manifest in query, where: manifest.organization_id == ^organization_id
  end

  def by_app_id(query \\ __MODULE__, app_id) do
    from manifest in query, where: manifest.app_id == ^app_id
  end

  def latest_first(query \\ __MODULE__) do
    from manifest in query, order_by: [desc: manifest.manifest_created_at]
  end

  defp normalize_attrs(attrs) do
    attrs
    |> Map.put_new("manifest_created_at", attrs["created_at"] || attrs[:created_at])
    |> Map.update("platform", nil, &normalize_platform/1)
  end

  defp normalize_platform(value) when is_binary(value), do: value |> String.trim() |> String.downcase()
  defp normalize_platform(value), do: value

  defp validate_version(changeset) do
    version = get_field(changeset, :version) || %{}
    validate_nested_string(changeset, version, :version, "name")
  end

  defp validate_artifact(changeset) do
    artifact = get_field(changeset, :artifact) || %{}

    changeset
    |> validate_nested_inclusion(artifact, :artifact, "type", @artifact_types)
    |> validate_nested_sha256(artifact, :artifact, "sha256")
  end

  defp validate_signing(changeset) do
    signing = get_field(changeset, :signing) || %{}

    changeset
    |> validate_nested_inclusion(signing, :signing, "scheme", @signing_schemes)
    |> validate_nested_sha256(signing, :signing, "certificate_sha256")
  end

  defp validate_sdk(changeset) do
    sdk = get_field(changeset, :sdk) || %{}

    changeset
    |> validate_nested_string(sdk, :sdk, "version")
    |> validate_nested_sha256(sdk, :sdk, "config_sha256")
  end

  defp validate_nested_string(changeset, source, parent, field) do
    value = Map.get(source, field)

    if is_binary(value) and String.trim(value) != "" do
      changeset
    else
      add_error(changeset, parent, "#{field} is required")
    end
  end

  defp validate_nested_inclusion(changeset, source, parent, field, allowed) do
    value = Map.get(source, field)

    if value in allowed do
      changeset
    else
      add_error(changeset, parent, "#{field} must be one of: #{Enum.join(allowed, ", ")}")
    end
  end

  defp validate_nested_sha256(changeset, source, parent, field) do
    value = Map.get(source, field)

    if is_binary(value) and Regex.match?(~r/^[a-fA-F0-9]{64}$/, value) do
      changeset
    else
      add_error(changeset, parent, "#{field} must be a 64-character SHA256")
    end
  end
end
