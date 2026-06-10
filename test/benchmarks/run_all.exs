defmodule TamanduaServer.Benchmarks.Runner do
  @moduledoc """
  Runs all server benchmarks and generates a comprehensive report.

  Usage:
    mix run test/benchmarks/run_all.exs
  """

  def run do
    IO.puts("=" <> String.duplicate("=", 70))
    IO.puts("  TAMANDUA SERVER - COMPREHENSIVE BENCHMARK SUITE")
    IO.puts("=" <> String.duplicate("=", 70))
    IO.puts("")

    # Create output directory
    File.mkdir_p!("benchmarks/output")

    # Run all benchmark suites
    results = []

    IO.puts("\n[1/2] Running Detection Engine Benchmarks...")
    detection_result = run_benchmark(
      "test/benchmarks/detection_bench.exs",
      "Detection Engine"
    )
    results = [detection_result | results]

    IO.puts("\n[2/2] Running Telemetry Pipeline Benchmarks...")
    telemetry_result = run_benchmark(
      "test/benchmarks/telemetry_bench.exs",
      "Telemetry Pipeline"
    )
    results = [telemetry_result | results]

    # Generate summary report
    generate_summary_report(results)

    IO.puts("\n" <> String.duplicate("=", 72))
    IO.puts("  BENCHMARK SUITE COMPLETE")
    IO.puts(String.duplicate("=", 72))
    IO.puts("\nReports saved to: benchmarks/output/")
    IO.puts("  - detection_bench.html")
    IO.puts("  - telemetry_bench.html")
    IO.puts("  - summary.txt")
    IO.puts("")
  end

  defp run_benchmark(path, name) do
    start_time = System.monotonic_time(:millisecond)

    try do
      Code.eval_file(path)
      duration = System.monotonic_time(:millisecond) - start_time

      IO.puts("  ✓ #{name} completed in #{duration}ms")
      {:ok, name, duration}
    rescue
      error ->
        duration = System.monotonic_time(:millisecond) - start_time
        IO.puts("  ✗ #{name} failed: #{inspect(error)}")
        {:error, name, duration, error}
    end
  end

  defp generate_summary_report(results) do
    summary_path = "benchmarks/output/summary.txt"

    content = """
    TAMANDUA SERVER BENCHMARK SUMMARY
    Generated: #{DateTime.utc_now() |> DateTime.to_string()}

    ============================================================

    RESULTS:

    #{Enum.map_join(results, "\n", &format_result/1)}

    ============================================================

    SYSTEM INFO:
      Elixir Version: #{System.version()}
      OTP Version: #{:erlang.system_info(:otp_release)}
      Schedulers: #{System.schedulers_online()}
      Memory: #{div(:erlang.memory(:total), 1024 * 1024)} MB

    ============================================================
    """

    File.write!(summary_path, content)
  end

  defp format_result({:ok, name, duration}) do
    "  ✓ #{name}: #{duration}ms"
  end

  defp format_result({:error, name, duration, _error}) do
    "  ✗ #{name}: Failed after #{duration}ms"
  end
end

# Run if executed directly
TamanduaServer.Benchmarks.Runner.run()
