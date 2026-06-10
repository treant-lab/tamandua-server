defmodule TamanduaServer.Deception.BreadcrumbDeployment do
  @moduledoc """
  Schema for tracking deployed breadcrumb honeypots.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "breadcrumb_deployments" do
    field :agent_id, :string
    field :type, :string
    field :path, :string
    field :content_hash, :string
    field :canary_token, :string
    field :deployed_at, :utc_datetime
    field :last_rotated_at, :utc_datetime
    field :status, :string, default: "active"
    field :access_count, :integer, default: 0
    field :metadata, :map, default: %{}

    has_many :access_logs, TamanduaServer.Deception.BreadcrumbAccessLog,
      foreign_key: :breadcrumb_id

    timestamps()
  end

  @doc false
  def changeset(breadcrumb, attrs) do
    breadcrumb
    |> cast(attrs, [
      :agent_id,
      :type,
      :path,
      :content_hash,
      :canary_token,
      :deployed_at,
      :last_rotated_at,
      :status,
      :access_count,
      :metadata
    ])
    |> validate_required([
      :agent_id,
      :type,
      :path,
      :content_hash,
      :canary_token,
      :deployed_at
    ])
    |> validate_inclusion(:type, [
      "credential",
      "document",
      "ssh_key",
      "api_token",
      "cloud_credential",
      "browser_password",
      "kube_config",
      "env_file",
      "database",
      "network_share"
    ])
    |> validate_inclusion(:status, ["active", "accessed", "rotated", "removed"])
    |> unique_constraint([:agent_id, :path])
  end
end
