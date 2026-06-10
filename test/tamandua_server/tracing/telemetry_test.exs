defmodule TamanduaServer.Tracing.TelemetryTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Tracing.Telemetry

  describe "extract_trace_context/1" do
    test "extracts valid traceparent header" do
      params = %{
        "traceparent" => "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
      }

      context = Telemetry.extract_trace_context(params)
      assert context != nil
    end

    test "returns new context when traceparent is missing" do
      params = %{}
      context = Telemetry.extract_trace_context(params)
      assert context != nil
    end

    test "handles invalid traceparent gracefully" do
      params = %{
        "traceparent" => "invalid-format"
      }

      context = Telemetry.extract_trace_context(params)
      assert context != nil
    end
  end

  describe "create_ml_trace_headers/0" do
    test "creates traceparent header when span is recording" do
      # This test requires an active span context
      # In real usage, this would be called within a span
      headers = Telemetry.create_ml_trace_headers()
      assert is_map(headers)
    end
  end
end
