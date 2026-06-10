defmodule TamanduaServer.Analytics.APIUsageMetric do
  @moduledoc """
  Schema for API usage metrics tracking.
  Used for versioning analytics, sunset planning, and performance monitoring.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime_usec]

  schema "api_usage_metrics" do
    field :version, :string
    field :method, :string
    field :path, :string
    field :endpoint, :string
    field :status_code, :integer
    field :latency_ms, :integer
    field :deprecated, :boolean, default: false
    field :user_agent, :string
    field :client_ip, :string
    field :timestamp, :utc_datetime_usec

    belongs_to :organization, TamanduaServer.Accounts.Organization
    belongs_to :user, TamanduaServer.Accounts.User

    timestamps()
  end

  @doc false
  def changeset(metric, attrs) do
    metric
    |> cast(attrs, [
      :version,
      :method,
      :path,
      :endpoint,
      :status_code,
      :latency_ms,
      :deprecated,
      :user_agent,
      :client_ip,
      :timestamp,
      :organization_id,
      :user_id
    ])
    |> validate_required([:version, :method, :path, :endpoint, :status_code, :timestamp])
    |> validate_inclusion(:method, ~w(GET POST PUT PATCH DELETE HEAD OPTIONS))
    |> validate_number(:status_code, greater_than_or_equal_to: 100, less_than: 600)
    |> validate_number(:latency_ms, greater_than_or_equal_to: 0)
  end
end
