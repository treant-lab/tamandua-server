defmodule TamanduaServer.Observability.Tracing do
  @moduledoc """
  OpenTelemetry distributed tracing for Tamandua EDR.

  Provides:
  - Request tracing across services
  - Span creation for key operations
  - Context propagation
  - Custom attributes for security context

  Note: This module provides no-op implementations when OpenTelemetry is not available.
  To enable tracing, add opentelemetry dependencies to mix.exs.
  """

  require Logger

  @doc """
  Start a new trace span for an operation.
  When OpenTelemetry is not available, just executes the block.
  """
  defmacro with_span(_name, _attributes \\ [], do: block) do
    quote do
      unquote(block)
    end
  end

  @doc """
  Add attributes to the current span.
  No-op when OpenTelemetry is not available.
  """
  @spec set_attributes(keyword()) :: :ok
  def set_attributes(_attributes) do
    :ok
  end

  @doc """
  Record an exception in the current span.
  No-op when OpenTelemetry is not available.
  """
  @spec record_exception(Exception.t(), keyword()) :: :ok
  def record_exception(_exception, _opts \\ []) do
    :ok
  end

  @doc """
  Add an event to the current span.
  No-op when OpenTelemetry is not available.
  """
  @spec add_event(String.t(), keyword()) :: :ok
  def add_event(_name, _attributes \\ []) do
    :ok
  end

  @doc """
  Set the span status.
  No-op when OpenTelemetry is not available.
  """
  @spec set_status(:ok | :error, String.t()) :: :ok
  def set_status(_status, _message \\ "") do
    :ok
  end

  @doc """
  Extract trace context from incoming request headers.
  No-op when OpenTelemetry is not available.
  """
  @spec extract_context(map() | list()) :: :ok
  def extract_context(_headers) do
    :ok
  end

  @doc """
  Inject trace context into outgoing request headers.
  Returns the headers unchanged when OpenTelemetry is not available.
  """
  @spec inject_context(map()) :: map()
  def inject_context(headers) when is_map(headers) do
    headers
  end

  @doc """
  Create a span for event processing.
  Simply executes the function when OpenTelemetry is not available.
  """
  @spec trace_event_processing(map(), function()) :: term()
  def trace_event_processing(_event, fun) do
    fun.()
  end

  @doc """
  Create a span for detection analysis.
  Simply executes the function when OpenTelemetry is not available.
  """
  @spec trace_detection(map(), function()) :: term()
  def trace_detection(_event, fun) do
    fun.()
  end

  @doc """
  Create a span for ML inference.
  Simply executes the function when OpenTelemetry is not available.
  """
  @spec trace_ml_inference(map(), function()) :: term()
  def trace_ml_inference(_sample, fun) do
    fun.()
  end

  @doc """
  Create a span for response action execution.
  Simply executes the function when OpenTelemetry is not available.
  """
  @spec trace_response_action(map(), function()) :: term()
  def trace_response_action(_action, fun) do
    fun.()
  end

  @doc """
  Create a span for database operations.
  Simply executes the function when OpenTelemetry is not available.
  """
  @spec trace_db_operation(String.t(), function()) :: term()
  def trace_db_operation(_operation, fun) do
    fun.()
  end

  @doc """
  Create a span for external API calls.
  Simply executes the function when OpenTelemetry is not available.
  """
  @spec trace_external_call(String.t(), String.t(), function()) :: term()
  def trace_external_call(_service, _endpoint, fun) do
    fun.()
  end
end
