defmodule TamanduaServer.Webhooks.Webhook do
  @moduledoc """
  Schema for webhook configuration.

  Webhooks allow external systems to receive real-time notifications about
  events in Tamandua EDR (alerts, agent status, detections, etc.).
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias TamanduaServer.Accounts.Organization

  @auth_types ~w(none basic bearer custom_headers hmac oauth2 mtls)
  @backoff_strategies ~w(exponential linear)
  @http_methods ~w(POST PUT PATCH)
  @payload_formats ~w(json xml)
  @priorities ~w(low normal high critical)
  @health_statuses ~w(healthy degraded unhealthy circuit_open)
  @event_types ~w(
    alert.created alert.updated alert.resolved
    agent.connected agent.disconnected
    detection.triggered
    response.executed
    system.health_changed
  )

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "webhooks" do
    field :name, :string
    field :url, :string
    field :enabled, :boolean, default: true
    field :secret, :string
    field :description, :string

    # Event filtering
    field :events, {:array, :string}, default: []

    # HTTP Configuration
    field :http_method, :string, default: "POST"
    field :payload_format, :string, default: "json"
    field :content_type, :string, default: "application/json"

    # Template System
    field :template, :string
    field :use_template, :boolean, default: false

    # Authentication
    field :auth_type, :string, default: "none"
    field :auth_username, :string
    field :auth_password, :string
    field :auth_token, :string
    field :custom_headers, :map, default: %{}

    # OAuth 2.0 Authentication
    field :oauth_client_id, :string
    field :oauth_client_secret, :string
    field :oauth_token_url, :string
    field :oauth_scope, :string
    field :oauth_token_cache, :map
    field :oauth_token_expires_at, :utc_datetime

    # mTLS Authentication
    field :mtls_enabled, :boolean, default: false
    field :mtls_client_cert, :string
    field :mtls_client_key, :string
    field :mtls_ca_cert, :string

    # Priority & Delivery Options
    field :priority, :string, default: "normal"
    field :async_mode, :boolean, default: true

    # Retry policy
    field :max_retries, :integer, default: 3
    field :backoff_strategy, :string, default: "exponential"
    field :timeout_seconds, :integer, default: 10

    # Health Monitoring
    field :health_status, :string, default: "healthy"
    field :consecutive_failures, :integer, default: 0
    field :circuit_breaker_open_until, :utc_datetime
    field :last_health_check_at, :utc_datetime

    # Rate Limiting
    field :rate_limit_per_minute, :integer
    field :rate_limit_per_hour, :integer

    # Statistics
    field :total_deliveries, :integer, default: 0
    field :successful_deliveries, :integer, default: 0
    field :failed_deliveries, :integer, default: 0
    field :last_delivery_at, :utc_datetime
    field :last_delivery_status, :string

    # Metadata
    field :tags, {:array, :string}, default: []
    field :metadata, :map, default: %{}

    belongs_to :organization, Organization

    timestamps()
  end

  @doc false
  def changeset(webhook, attrs) do
    webhook
    |> cast(attrs, [
      :name,
      :url,
      :enabled,
      :secret,
      :description,
      :events,
      :http_method,
      :payload_format,
      :content_type,
      :template,
      :use_template,
      :auth_type,
      :auth_username,
      :auth_password,
      :auth_token,
      :custom_headers,
      :oauth_client_id,
      :oauth_client_secret,
      :oauth_token_url,
      :oauth_scope,
      :oauth_token_cache,
      :oauth_token_expires_at,
      :mtls_enabled,
      :mtls_client_cert,
      :mtls_client_key,
      :mtls_ca_cert,
      :priority,
      :async_mode,
      :max_retries,
      :backoff_strategy,
      :timeout_seconds,
      :health_status,
      :consecutive_failures,
      :circuit_breaker_open_until,
      :last_health_check_at,
      :rate_limit_per_minute,
      :rate_limit_per_hour,
      :organization_id,
      :total_deliveries,
      :successful_deliveries,
      :failed_deliveries,
      :last_delivery_at,
      :last_delivery_status,
      :tags,
      :metadata
    ])
    |> validate_required([:name, :url, :organization_id, :events])
    |> validate_url(:url)
    |> validate_inclusion(:auth_type, @auth_types)
    |> validate_inclusion(:backoff_strategy, @backoff_strategies)
    |> validate_inclusion(:http_method, @http_methods)
    |> validate_inclusion(:payload_format, @payload_formats)
    |> validate_inclusion(:priority, @priorities)
    |> validate_inclusion(:health_status, @health_statuses)
    |> validate_number(:max_retries, greater_than_or_equal_to: 0, less_than_or_equal_to: 10)
    |> validate_number(:timeout_seconds, greater_than: 0, less_than_or_equal_to: 60)
    |> validate_events()
    |> validate_auth_credentials()
    |> validate_template()
    |> generate_secret_if_hmac()
    |> foreign_key_constraint(:organization_id)
  end

  defp validate_url(changeset, field) do
    validate_change(changeset, field, fn ^field, url ->
      uri = URI.parse(url)

      cond do
        uri.scheme not in ["http", "https"] ->
          [{field, "must be a valid HTTP or HTTPS URL"}]

        is_nil(uri.host) ->
          [{field, "must include a valid hostname"}]

        true ->
          []
      end
    end)
  end

  defp validate_events(changeset) do
    validate_change(changeset, :events, fn :events, events ->
      invalid_events = Enum.reject(events, &(&1 in @event_types))

      if Enum.empty?(invalid_events) do
        []
      else
        [{:events, "contains invalid event types: #{Enum.join(invalid_events, ", ")}"}]
      end
    end)
  end

  defp validate_auth_credentials(changeset) do
    auth_type = get_field(changeset, :auth_type)

    case auth_type do
      "basic" ->
        changeset
        |> validate_required([:auth_username, :auth_password])

      "bearer" ->
        changeset
        |> validate_required([:auth_token])

      "custom_headers" ->
        custom_headers = get_field(changeset, :custom_headers)

        if map_size(custom_headers || %{}) == 0 do
          add_error(changeset, :custom_headers, "cannot be empty for custom_headers auth type")
        else
          changeset
        end

      "oauth2" ->
        changeset
        |> validate_required([:oauth_client_id, :oauth_client_secret, :oauth_token_url])

      "mtls" ->
        if get_field(changeset, :mtls_enabled) do
          changeset
          |> validate_required([:mtls_client_cert, :mtls_client_key])
        else
          changeset
        end

      _ ->
        changeset
    end
  end

  defp validate_template(changeset) do
    use_template = get_field(changeset, :use_template)
    template = get_field(changeset, :template)

    if use_template && (is_nil(template) || template == "") do
      add_error(changeset, :template, "cannot be empty when use_template is enabled")
    else
      changeset
    end
  end

  defp generate_secret_if_hmac(changeset) do
    auth_type = get_field(changeset, :auth_type)
    secret = get_field(changeset, :secret)

    if auth_type == "hmac" and is_nil(secret) do
      put_change(changeset, :secret, generate_secret())
    else
      changeset
    end
  end

  defp generate_secret do
    :crypto.strong_rand_bytes(32)
    |> Base.encode64()
  end

  @doc """
  Returns all supported event types.
  """
  def event_types, do: @event_types

  @doc """
  Returns all supported authentication types.
  """
  def auth_types, do: @auth_types

  @doc """
  Returns all supported backoff strategies.
  """
  def backoff_strategies, do: @backoff_strategies

  @doc """
  Returns all supported HTTP methods.
  """
  def http_methods, do: @http_methods

  @doc """
  Returns all supported payload formats.
  """
  def payload_formats, do: @payload_formats

  @doc """
  Returns all supported priorities.
  """
  def priorities, do: @priorities

  @doc """
  Returns all supported health statuses.
  """
  def health_statuses, do: @health_statuses

  @doc """
  Increments delivery statistics for a webhook.
  """
  def increment_delivery_stats(webhook, success: success?) do
    webhook
    |> change(%{
      total_deliveries: webhook.total_deliveries + 1,
      successful_deliveries:
        if(success?, do: webhook.successful_deliveries + 1, else: webhook.successful_deliveries),
      failed_deliveries:
        if(success?, do: webhook.failed_deliveries, else: webhook.failed_deliveries + 1),
      last_delivery_at: DateTime.utc_now(),
      last_delivery_status: if(success?, do: "success", else: "failure")
    })
  end
end
