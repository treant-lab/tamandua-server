defmodule Tamandua.Updates.Version do
  @moduledoc """
  Schema for version manifests in the updates system.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "update_versions" do
    field :version, :string
    field :platform, Ecto.Enum, values: [:windows, :linux, :macos]
    field :arch, Ecto.Enum, values: [:x86_64, :aarch64, :arm, :x86]
    field :binary_url, :string
    field :checksum_sha256, :string
    field :signature_ed25519, :string
    field :size_bytes, :integer
    field :min_version, :string
    field :release_notes, :string
    field :critical, :boolean, default: false
    field :released_at, :utc_datetime
    field :deprecated_at, :utc_datetime

    timestamps()
  end

  def changeset(version, attrs) do
    version
    |> cast(attrs, [
      :version,
      :platform,
      :arch,
      :binary_url,
      :checksum_sha256,
      :signature_ed25519,
      :size_bytes,
      :min_version,
      :release_notes,
      :critical,
      :released_at,
      :deprecated_at
    ])
    |> validate_required([
      :version,
      :platform,
      :arch,
      :binary_url,
      :checksum_sha256,
      :signature_ed25519,
      :size_bytes,
      :released_at
    ])
    |> validate_macos_product_installer_binary_url()
    |> unique_constraint([:version, :platform, :arch])
  end

  defp validate_macos_product_installer_binary_url(changeset) do
    if get_field(changeset, :platform) == :macos do
      binary_url = get_field(changeset, :binary_url)
      normalized_url = binary_url |> to_string() |> String.downcase()

      cond do
        is_nil(binary_url) or String.trim(to_string(binary_url)) == "" ->
          add_error(
            changeset,
            :binary_url,
            "is required for macOS versions and must point to a signed/notarized DMG or Cask with EndpointSecurity System Extension"
          )

        macos_standalone_binary_url?(normalized_url) ->
          add_error(
            changeset,
            :binary_url,
            "must not point to a bare macOS agent/watchdog binary; use a signed/notarized DMG or Cask with EndpointSecurity System Extension"
          )

        not macos_product_installer_binary_url?(normalized_url) ->
          add_error(
            changeset,
            :binary_url,
            "must point to a signed/notarized macOS DMG or Tamandua EDR Cask"
          )

        true ->
          changeset
      end
    else
      changeset
    end
  end

  defp macos_standalone_binary_url?(url) do
    String.contains?(url, "tamandua-agent-macos") or
      String.contains?(url, "aarch64-apple-darwin") or
      String.contains?(url, "x86_64-apple-darwin") or
      String.contains?(url, "tamandua-watchdog") or
      String.contains?(url, "tamandua%20edr_0.1.0") or
      String.contains?(url, "tamandua edr_0.1.0") or
      String.contains?(url, "tamandua_edr_0.1.0") or
      String.contains?(url, "macos-sha256sums")
  end

  defp macos_product_installer_binary_url?(url) do
    String.contains?(url, ".dmg") or
      (String.contains?(url, "cask") and String.contains?(url, "tamandua-edr"))
  end

  @doc """
  Compare two semantic versions.

  Returns :gt, :lt, or :eq.
  """
  def compare(version1, version2) do
    v1_parts = parse_version(version1)
    v2_parts = parse_version(version2)

    case {v1_parts, v2_parts} do
      {{:ok, v1}, {:ok, v2}} -> compare_parts(v1, v2)
      _ -> :eq
    end
  end

  defp parse_version(version) do
    parts =
      version
      |> String.split(".")
      |> Enum.map(&Integer.parse/1)
      |> Enum.map(fn
        {num, _} -> num
        :error -> 0
      end)

    {:ok, parts}
  end

  defp compare_parts([], []), do: :eq
  defp compare_parts([h1 | _t1], [h2 | _t2]) when h1 > h2, do: :gt
  defp compare_parts([h1 | _t1], [h2 | _t2]) when h1 < h2, do: :lt
  defp compare_parts([_ | t1], [_ | t2]), do: compare_parts(t1, t2)
  defp compare_parts([], _), do: :lt
  defp compare_parts(_, []), do: :gt
end

defmodule Tamandua.Updates.DeltaPatch do
  @moduledoc """
  Schema for delta patches between versions.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "update_delta_patches" do
    field :from_version, :string
    field :to_version, :string
    field :platform, Ecto.Enum, values: [:windows, :linux, :macos]
    field :arch, Ecto.Enum, values: [:x86_64, :aarch64, :arm, :x86]
    field :patch_url, :string
    field :checksum_sha256, :string
    field :signature_ed25519, :string
    field :size_bytes, :integer
    field :algorithm, :string, default: "bsdiff"

    timestamps()
  end

  def changeset(delta, attrs) do
    delta
    |> cast(attrs, [
      :from_version,
      :to_version,
      :platform,
      :arch,
      :patch_url,
      :checksum_sha256,
      :signature_ed25519,
      :size_bytes,
      :algorithm
    ])
    |> validate_required([
      :from_version,
      :to_version,
      :platform,
      :arch,
      :patch_url,
      :checksum_sha256,
      :signature_ed25519,
      :size_bytes
    ])
    |> unique_constraint([:from_version, :to_version, :platform, :arch])
  end
end

defmodule Tamandua.Updates.RolloutState do
  @moduledoc """
  Schema for rollout state persistence.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "update_rollouts" do
    field :rollout_id, :string
    field :version, :string
    field :platform, Ecto.Enum, values: [:windows, :linux, :macos]
    field :arch, Ecto.Enum, values: [:x86_64, :aarch64, :arm, :x86]
    field :strategy, Ecto.Enum, values: [:automatic, :manual_approval, :emergency]
    field :current_phase, Ecto.Enum, values: [:canary_1, :canary_5, :canary_25, :full, :paused, :cancelled]
    field :phase_configs, :map
    field :failure_threshold, :float
    field :started_at, :utc_datetime
    field :completed_at, :utc_datetime

    timestamps()
  end

  def changeset(rollout, attrs) do
    rollout
    |> cast(attrs, [
      :rollout_id,
      :version,
      :platform,
      :arch,
      :strategy,
      :current_phase,
      :phase_configs,
      :failure_threshold,
      :started_at,
      :completed_at
    ])
    |> validate_required([
      :rollout_id,
      :version,
      :platform,
      :arch,
      :strategy,
      :current_phase,
      :started_at
    ])
    |> unique_constraint(:rollout_id)
  end
end

defmodule Tamandua.Updates.UpdateHealth do
  @moduledoc """
  Schema for tracking update health per agent.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "update_health" do
    field :rollout_id, :string
    field :agent_id, :string
    field :status, Ecto.Enum, values: [:downloading, :installing, :verifying, :success, :failed, :rolled_back]
    field :metadata, :map
    field :created_at, :utc_datetime
  end

  def changeset(health, attrs) do
    health
    |> cast(attrs, [:rollout_id, :agent_id, :status, :metadata, :created_at])
    |> validate_required([:rollout_id, :agent_id, :status, :created_at])
  end
end
