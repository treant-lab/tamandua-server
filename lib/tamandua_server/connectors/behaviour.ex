defmodule TamanduaServer.Connectors.Behaviour do
  @moduledoc """
  Behaviour definition for Tamandua EDR connectors.

  All connectors must implement this behaviour to be loaded dynamically.
  Supports four connector types:
  - Alert Source: Ingest alerts from external systems
  - Alert Sink: Send alerts to external systems
  - IOC Source: Ingest threat intelligence
  - Response Action: Execute actions on external systems
  """

  @type connector_type :: :alert_source | :alert_sink | :ioc_source | :response_action
  @type config :: map()
  @type event :: map()
  @type result :: {:ok, any()} | {:error, term()}

  @doc """
  Returns metadata about the connector.

  ## Required fields:
  - `:name` - Human-readable connector name
  - `:version` - Semantic version string (e.g., "1.0.0")
  - `:type` - Connector type (see `connector_type()`)
  - `:description` - Brief description
  - `:author` - Connector author
  - `:config_schema` - JSON schema for configuration validation

  ## Example:
      %{
        name: "MISP Connector",
        version: "1.0.0",
        type: :ioc_source,
        description: "Bidirectional sync with MISP threat intelligence platform",
        author: "Tamandua Team",
        config_schema: %{...}
      }
  """
  @callback metadata() :: map()

  @doc """
  Initialize the connector with configuration.

  Called once when the connector is loaded. Should validate config
  and establish any persistent connections.

  Returns `{:ok, state}` or `{:error, reason}`.
  """
  @callback init(config()) :: {:ok, state :: any()} | {:error, term()}

  @doc """
  Start the connector.

  Called after successful initialization. For polling connectors,
  this should start the polling loop. For webhook connectors,
  this might be a no-op.
  """
  @callback start(state :: any()) :: :ok | {:error, term()}

  @doc """
  Stop the connector gracefully.

  Should cleanup resources, close connections, etc.
  """
  @callback stop(state :: any()) :: :ok

  @doc """
  Health check for the connector.

  Should return current status and any diagnostic information.

  ## Example:
      {:ok, %{
        status: :healthy,
        last_sync: ~U[2024-01-20 10:00:00Z],
        events_processed: 1234
      }}
  """
  @callback health(state :: any()) :: {:ok, map()} | {:error, term()}

  @doc """
  Process an inbound event (for alert_source and ioc_source).

  Returns normalized event data or error.
  """
  @callback handle_inbound(event(), state :: any()) :: result()

  @doc """
  Process an outbound event (for alert_sink and response_action).

  Returns delivery confirmation or error.
  """
  @callback handle_outbound(event(), state :: any()) :: result()

  @doc """
  Transform event data to internal format (optional).

  Default implementation returns event unchanged.
  """
  @callback transform_inbound(event()) :: event()

  @doc """
  Transform event data to external format (optional).

  Default implementation returns event unchanged.
  """
  @callback transform_outbound(event()) :: event()

  @doc """
  Validate connector configuration (optional).

  Default implementation checks against config_schema.
  """
  @callback validate_config(config()) :: :ok | {:error, term()}

  @optional_callbacks [
    handle_inbound: 2,
    handle_outbound: 2,
    transform_inbound: 1,
    transform_outbound: 1,
    validate_config: 1
  ]

  @doc """
  Default transform_inbound - returns event unchanged.
  """
  defmacro __using__(_opts) do
    quote do
      @behaviour TamanduaServer.Connectors.Behaviour

      @impl true
      def transform_inbound(event), do: event

      @impl true
      def transform_outbound(event), do: event

      @impl true
      def validate_config(config) do
        metadata = metadata()
        schema = metadata[:config_schema]

        if schema do
          TamanduaServer.Connectors.ConfigValidator.validate(config, schema)
        else
          :ok
        end
      end

      defoverridable [transform_inbound: 1, transform_outbound: 1, validate_config: 1]
    end
  end
end
