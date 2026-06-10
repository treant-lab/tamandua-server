defmodule Mix.Tasks.Tamandua.Test.Rules do
  @moduledoc """
  Run detection rule tests.

  ## Usage

      # Run all tests
      mix tamandua.test.rules

      # Run with verbose output
      mix tamandua.test.rules --verbose

      # Run specific rule tests
      mix tamandua.test.rules --rule mimikatz

      # Run by tag
      mix tamandua.test.rules --tag credential_access

      # Generate coverage report
      mix tamandua.test.rules --coverage

      # Export report
      mix tamandua.test.rules --export junit

      # Run in parallel (default)
      mix tamandua.test.rules --parallel

      # Run sequentially
      mix tamandua.test.rules --no-parallel

      # Fail fast on first error
      mix tamandua.test.rules --fail-fast

  ## Options

  - `--verbose` - Show detailed output
  - `--rule NAME` - Run tests for specific rule
  - `--tag TAG` - Run tests with specific tag
  - `--coverage` - Generate coverage report
  - `--export FORMAT` - Export report (text, json, junit, html)
  - `--parallel` - Run tests in parallel (default)
  - `--no-parallel` - Run tests sequentially
  - `--fail-fast` - Stop on first failure
  - `--sigma` - Run only Sigma rule tests
  - `--yara` - Run only YARA rule tests
  """

  use Mix.Task

  alias TamanduaServer.Detection.TestRunner

  @shortdoc "Run detection rule tests"

  @impl Mix.Task
  def run(args) do
    # Start application for database access
    Mix.Task.run("app.start")

    # Parse options
    {opts, _args, _invalid} =
      OptionParser.parse(args,
        strict: [
          verbose: :boolean,
          rule: :string,
          tag: :string,
          coverage: :boolean,
          export: :string,
          parallel: :boolean,
          fail_fast: :boolean,
          sigma: :boolean,
          yara: :boolean
        ]
      )

    # Execute based on options
    cond do
      opts[:coverage] ->
        run_coverage(opts)

      opts[:rule] ->
        run_by_rule(opts[:rule], opts)

      opts[:tag] ->
        run_by_tag(opts[:tag], opts)

      true ->
        run_all_tests(opts)
    end
  end

  defp run_all_tests(opts) do
    Mix.shell().info("Running detection rule tests...")

    test_opts = build_test_options(opts)

    case TestRunner.run_all(test_opts) do
      {:ok, report} ->
        print_summary(report)

        if opts[:export] do
          export_report(report, opts[:export])
        end

        # Exit with error code if tests failed
        if report.failed > 0 do
          Mix.raise("#{report.failed} test(s) failed")
        end

      {:error, reason} ->
        Mix.raise("Test execution failed: #{inspect(reason)}")
    end
  end

  defp run_by_rule(rule_name, opts) do
    Mix.shell().info("Running tests for rule: #{rule_name}...")

    test_opts = build_test_options(opts)

    case TestRunner.run_by_rule(rule_name, test_opts) do
      {:ok, report} ->
        print_summary(report)

        if opts[:export] do
          export_report(report, opts[:export])
        end

        if report.failed > 0 do
          Mix.raise("#{report.failed} test(s) failed")
        end

      {:error, reason} ->
        Mix.raise("Test execution failed: #{inspect(reason)}")
    end
  end

  defp run_by_tag(tag, opts) do
    Mix.shell().info("Running tests with tag: #{tag}...")

    test_opts = build_test_options(opts)

    case TestRunner.run_by_tag(tag, test_opts) do
      {:ok, report} ->
        print_summary(report)

        if opts[:export] do
          export_report(report, opts[:export])
        end

        if report.failed > 0 do
          Mix.raise("#{report.failed} test(s) failed")
        end

      {:error, reason} ->
        Mix.raise("Test execution failed: #{inspect(reason)}")
    end
  end

  defp run_coverage(opts) do
    Mix.shell().info("Generating coverage report...")

    case TestRunner.coverage_report(verbose: true) do
      {:ok, report} ->
        print_coverage_summary(report)

        if opts[:export] do
          export_coverage(report, opts[:export])
        end

        # Check if coverage meets minimum threshold (80%)
        if report.summary.coverage_percentage < 80.0 do
          Mix.shell().error("\nWarning: Coverage below 80% threshold")
        end

      {:error, reason} ->
        Mix.raise("Coverage report failed: #{inspect(reason)}")
    end
  end

  defp build_test_options(opts) do
    [
      verbose: opts[:verbose] || false,
      parallel: Keyword.get(opts, :parallel, true),
      fail_fast: opts[:fail_fast] || false,
      rule_type: cond do
        opts[:sigma] -> :sigma
        opts[:yara] -> :yara
        true -> nil
      end
    ]
  end

  defp print_summary(report) do
    Mix.shell().info("\n" <> String.duplicate("=", 80))
    Mix.shell().info("Detection Rule Test Report")
    Mix.shell().info(String.duplicate("=", 80))

    passed_pct = percentage(report.passed, report.total)
    failed_pct = percentage(report.failed, report.total)

    Mix.shell().info("Total:    #{report.total}")
    Mix.shell().info(color("Passed:   #{report.passed} (#{passed_pct}%)", :green))
    Mix.shell().info(color("Failed:   #{report.failed} (#{failed_pct}%)", if(report.failed > 0, do: :red, else: :green)))
    Mix.shell().info("Skipped:  #{report.skipped}")
    Mix.shell().info("Duration: #{report.duration_ms}ms")
    Mix.shell().info(String.duplicate("=", 80))

    if report.failed > 0 do
      Mix.shell().info("\nFailed Tests:")
      Mix.shell().info(String.duplicate("-", 80))

      report.results
      |> Enum.filter(&(&1.status == :failed))
      |> Enum.each(fn result ->
        Mix.shell().error("  [FAIL] #{result.test_name}")
        Mix.shell().error("         Rule: #{result.rule}")
        Mix.shell().error("         Error: #{result.error}")
        Mix.shell().info("")
      end)
    end
  end

  defp print_coverage_summary(report) do
    Mix.shell().info("\n" <> String.duplicate("=", 80))
    Mix.shell().info("Detection Rule Coverage Report")
    Mix.shell().info(String.duplicate("=", 80))
    Mix.shell().info("Total Rules:    #{report.summary.total_rules}")

    coverage_color =
      cond do
        report.summary.coverage_percentage >= 80.0 -> :green
        report.summary.coverage_percentage >= 60.0 -> :yellow
        true -> :red
      end

    Mix.shell().info(
      color(
        "Coverage:       #{report.summary.total_tested}/#{report.summary.total_rules} (#{report.summary.coverage_percentage}%)",
        coverage_color
      )
    )

    Mix.shell().info("Untested:       #{report.summary.total_untested}")
    Mix.shell().info("")
    Mix.shell().info("Sigma Rules:    #{report.sigma.tested}/#{report.sigma.total} (#{report.sigma.coverage_pct}%)")
    Mix.shell().info("YARA Rules:     #{report.yara.tested}/#{report.yara.total} (#{report.yara.coverage_pct}%)")
    Mix.shell().info(String.duplicate("=", 80))

    if length(report.untested_rules) > 0 do
      Mix.shell().info("\nUntested Rules (#{length(report.untested_rules)}):")
      Mix.shell().info(String.duplicate("-", 80))

      Enum.take(report.untested_rules, 20)
      |> Enum.each(fn rule ->
        Mix.shell().info("  - #{rule}")
      end)

      if length(report.untested_rules) > 20 do
        Mix.shell().info("  ... and #{length(report.untested_rules) - 20} more")
      end
    end
  end

  defp export_report(report, format) do
    format_atom =
      case format do
        "text" -> :text
        "json" -> :json
        "junit" -> :junit
        "html" -> :html
        _ -> :text
      end

    case TestRunner.export_report(report, format_atom) do
      :ok ->
        Mix.shell().info("\nReport exported as #{format}")

      {:error, reason} ->
        Mix.shell().error("Failed to export report: #{inspect(reason)}")
    end
  end

  defp export_coverage(report, format) do
    # For coverage, we export as JSON or text
    format_atom = if format == "json", do: :json, else: :text
    output_path = "priv/detection_test_reports/coverage_#{DateTime.to_unix(DateTime.utc_now())}"

    case format_atom do
      :json ->
        File.write!("#{output_path}.json", Jason.encode!(report, pretty: true))
        Mix.shell().info("\nCoverage report exported to #{output_path}.json")

      :text ->
        content = format_coverage_text(report)
        File.write!("#{output_path}.txt", content)
        Mix.shell().info("\nCoverage report exported to #{output_path}.txt")
    end
  end

  defp format_coverage_text(report) do
    """
    Detection Rule Coverage Report
    ==============================

    Summary:
    - Total Rules:    #{report.summary.total_rules}
    - Tested:         #{report.summary.total_tested} (#{report.summary.coverage_percentage}%)
    - Untested:       #{report.summary.total_untested}

    Sigma Rules:      #{report.sigma.tested}/#{report.sigma.total} (#{report.sigma.coverage_pct}%)
    YARA Rules:       #{report.yara.tested}/#{report.yara.total} (#{report.yara.coverage_pct}%)

    Untested Rules:
    #{Enum.map_join(report.untested_rules, "\n", fn rule -> "  - #{rule}" end)}
    """
  end

  defp percentage(_part, 0), do: "0.0"

  defp percentage(part, total) do
    Float.round(part / total * 100, 1)
    |> to_string()
  end

  defp color(text, :green), do: IO.ANSI.format([:green, text])
  defp color(text, :red), do: IO.ANSI.format([:red, text])
  defp color(text, :yellow), do: IO.ANSI.format([:yellow, text])
  defp color(text, _), do: text
end
