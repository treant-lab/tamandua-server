defmodule TamanduaServer.Integrations.Schemas.HealthCheckHistory do
  @moduledoc """
  Schema for integration health check history.
  """

  use Ecto.Schema
  import Ecto.Changeset
  import Ecto.Query

  alias TamanduaServer.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "integration_health_checks" do
    field :integration_id, :binary_id

    field :check_type, :string
    field :success, :boolean
    field :duration_ms, :integer
    field :status_code, :integer
    field :error_message, :string
    field :response_body, :string

    field :metadata, :map
    field :checked_at, :utc_datetime
  end

  @fields [
    :integration_id, :check_type, :success, :duration_ms,
    :status_code, :error_message, :response_body, :metadata, :checked_at
  ]

  def changeset(check, attrs) do
    check
    |> cast(attrs, @fields)
    |> validate_required([:integration_id, :check_type, :success, :checked_at])
  end

  def create(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Get recent health check history.
  """
  def list_recent(integration_id, limit \\ 100) do
    from(h in __MODULE__,
      where: h.integration_id == ^integration_id,
      order_by: [desc: h.checked_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Get success rate for the last N checks.
  """
  def get_success_rate(integration_id, limit \\ 100) do
    checks = list_recent(integration_id, limit)

    if length(checks) > 0 do
      successful = Enum.count(checks, & &1.success)
      (successful / length(checks)) * 100
    else
      0.0
    end
  end
end
