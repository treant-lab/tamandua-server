defmodule TamanduaServer.Tracing.Telemetry do
  @moduledoc """
  OpenTelemetry distributed tracing setup for Tamandua Server.

  Provides:
  - OTLP exporter to Jaeger
  - Trace context propagation from WebSocket connections
  - Automatic instrumentation for Phoenix and Ecto
  - Custom spans for detection and ML operations
  """

  require Logger
  require OpenTelemetry.Tracer, as: Tracer

  @doc """
  Initialize OpenTelemetry tracing.

  Should be called during application startup.
  """
  def setup do
    # OpenTelemetry configuration is loaded from runtime.exs
    # We just need to attach handlers for custom instrumentation

    Logger.info("Setting up OpenTelemetry distributed tracing")

    # Attach telemetry handlers for custom events
    :telemetry.attach_many(
      "tamandua-tracing",
      [
        [:tamandua, :telemetry, :ingest, :start],
        [:tamandua, :telemetry, :ingest, :stop],
        [:tamandua, :telemetry, :ingest, :exception],
        [:tamandua, :detection, :yara, :start],
        [:tamandua, :detection, :yara, :stop],
        [:tamandua, :detection, :sigma, :start],
        [:tamandua, :detection, :sigma, :stop],
        [:tamandua, :detection, :ml, :start],
        [:tamandua, :detection, :ml, :stop],
        [:tamandua, :detection, :ml, :exception],
        [:tamandua, :response, :execute, :start],
        [:tamandua, :response, :execute, :stop],
      ],
      &handle_event/4,
      nil
    )

    Logger.info("OpenTelemetry tracing handlers attached")
  end

  @doc """
  Extract trace context from WebSocket connection parameters.

  Looks for the 'traceparent' field in connect params and
  sets it as the parent context for all subsequent operations.
  """
  def extract_trace_context(params) do
    case Map.get(params, "traceparent") do
      nil ->
        # No trace context provided
        OpenTelemetry.Ctx.new()

      traceparent ->
        # Parse W3C traceparent header: 00-<trace-id>-<span-id>-<flags>
        case parse_traceparent(traceparent) do
          {:ok, trace_id, span_id, trace_flags} ->
            # Create context with extracted trace info
            ctx = OpenTelemetry.Ctx.new()

            # Set remote parent span context
            span_ctx = OpenTelemetry.span_ctx(
              trace_id: trace_id,
              span_id: span_id,
              trace_flags: trace_flags,
              tracestate: [],
              is_remote: true
            )

            OpenTelemetry.Ctx.set_current(ctx)
            OpenTelemetry.Tracer.set_current_span(span_ctx)

            Logger.debug("Extracted trace context from agent",
              trace_id: format_trace_id(trace_id),
              span_id: format_span_id(span_id)
            )

            ctx

          {:error, reason} ->
            Logger.warning("Failed to parse traceparent header",
              traceparent: traceparent,
              reason: reason
            )
            OpenTelemetry.Ctx.new()
        end
    end
  end

  @doc """
  Create trace context for ML service request.

  Returns a map with traceparent header to include in HTTP request.
  """
  def create_ml_trace_headers do
    span_ctx = Tracer.current_span_ctx()

    if OpenTelemetry.Span.is_recording(span_ctx) do
      trace_id = span_ctx.trace_id
      span_id = span_ctx.span_id
      trace_flags = span_ctx.trace_flags

      traceparent = format_traceparent(trace_id, span_id, trace_flags)

      %{"traceparent" => traceparent}
    else
      %{}
    end
  end

  # Private functions

  defp handle_event([:tamandua, :telemetry, :ingest, :start], measurements, metadata, _config) do
    attrs = %{
      "agent_id" => metadata[:agent_id],
      "event_count" => measurements[:event_count] || 0
    }

    Tracer.set_attributes(attrs)
  end

  defp handle_event([:tamandua, :telemetry, :ingest, :stop], measurements, metadata, _config) do
    attrs = %{
      "duration_ms" => measurements[:duration],
      "processed_count" => metadata[:processed_count] || 0
    }

    Tracer.set_attributes(attrs)
  end

  defp handle_event([:tamandua, :telemetry, :ingest, :exception], _measurements, metadata, _config) do
    Tracer.set_status(:error, metadata[:reason] || "Unknown error")
    Tracer.add_event("exception", %{
      "exception.type" => metadata[:kind],
      "exception.message" => metadata[:reason]
    })
  end

  defp handle_event([:tamandua, :detection, :yara, :start], _measurements, metadata, _config) do
    attrs = %{
      "rule_count" => metadata[:rule_count] || 0,
      "file_path" => metadata[:file_path]
    }

    Tracer.set_attributes(attrs)
  end

  defp handle_event([:tamandua, :detection, :yara, :stop], measurements, metadata, _config) do
    attrs = %{
      "duration_ms" => measurements[:duration],
      "matches" => metadata[:matches] || 0
    }

    Tracer.set_attributes(attrs)
  end

  defp handle_event([:tamandua, :detection, :sigma, :start], _measurements, metadata, _config) do
    attrs = %{
      "rule_id" => metadata[:rule_id]
    }

    Tracer.set_attributes(attrs)
  end

  defp handle_event([:tamandua, :detection, :sigma, :stop], measurements, metadata, _config) do
    attrs = %{
      "duration_ms" => measurements[:duration],
      "matched" => metadata[:matched] || false
    }

    Tracer.set_attributes(attrs)
  end

  defp handle_event([:tamandua, :detection, :ml, :start], _measurements, metadata, _config) do
    attrs = %{
      "sha256" => metadata[:sha256],
      "file_size" => metadata[:file_size]
    }

    Tracer.set_attributes(attrs)
  end

  defp handle_event([:tamandua, :detection, :ml, :stop], measurements, metadata, _config) do
    attrs = %{
      "duration_ms" => measurements[:duration],
      "verdict" => metadata[:verdict],
      "confidence" => metadata[:confidence]
    }

    Tracer.set_attributes(attrs)
  end

  defp handle_event([:tamandua, :detection, :ml, :exception], _measurements, metadata, _config) do
    Tracer.set_status(:error, metadata[:reason] || "ML detection failed")
    Tracer.add_event("exception", %{
      "exception.type" => metadata[:kind],
      "exception.message" => metadata[:reason]
    })
  end

  defp handle_event([:tamandua, :response, :execute, :start], _measurements, metadata, _config) do
    attrs = %{
      "command_type" => metadata[:command_type],
      "agent_id" => metadata[:agent_id]
    }

    Tracer.set_attributes(attrs)
  end

  defp handle_event([:tamandua, :response, :execute, :stop], measurements, metadata, _config) do
    attrs = %{
      "duration_ms" => measurements[:duration],
      "success" => metadata[:success] || false
    }

    Tracer.set_attributes(attrs)
  end

  # Parse W3C traceparent header
  # Format: 00-<trace-id>-<span-id>-<trace-flags>
  defp parse_traceparent(traceparent) do
    case String.split(traceparent, "-") do
      ["00", trace_id_hex, span_id_hex, flags_hex] ->
        with {:ok, trace_id} <- parse_hex_int(trace_id_hex, 128),
             {:ok, span_id} <- parse_hex_int(span_id_hex, 64),
             {:ok, flags} <- parse_hex_int(flags_hex, 8) do
          {:ok, trace_id, span_id, flags}
        else
          {:error, reason} -> {:error, reason}
        end

      _ ->
        {:error, :invalid_format}
    end
  end

  defp parse_hex_int(hex_string, bit_size) do
    expected_length = div(bit_size, 4)

    if String.length(hex_string) == expected_length do
      case Integer.parse(hex_string, 16) do
        {int, ""} -> {:ok, int}
        _ -> {:error, :invalid_hex}
      end
    else
      {:error, :invalid_length}
    end
  end

  defp format_traceparent(trace_id, span_id, trace_flags) do
    trace_id_hex = Integer.to_string(trace_id, 16) |> String.pad_leading(32, "0")
    span_id_hex = Integer.to_string(span_id, 16) |> String.pad_leading(16, "0")
    flags_hex = Integer.to_string(trace_flags, 16) |> String.pad_leading(2, "0")

    "00-#{trace_id_hex}-#{span_id_hex}-#{flags_hex}"
  end

  defp format_trace_id(trace_id) do
    Integer.to_string(trace_id, 16) |> String.pad_leading(32, "0")
  end

  defp format_span_id(span_id) do
    Integer.to_string(span_id, 16) |> String.pad_leading(16, "0")
  end
end
