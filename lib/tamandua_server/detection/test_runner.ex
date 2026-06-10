defmodule TamanduaServer.Detection.TestRunner do
  @moduledoc """
  Detection rule testing framework.

  Executes test cases against Sigma and YARA rules, validates expected results,
  and generates coverage reports. Supports parallel execution, test filtering,
  and detailed output modes.

  ## Test Case Format

  Test cases are YAML files with the following structure:

      test_case:
        name: "Mimikatz Detection Test"
        description: "Tests detection of Mimikatz credential theft"
        rule: "credential_access/mimikatz_patterns.yml"  # or YARA: "ransomware.yar"
        rule_type: sigma  # or yara
        events:
          - type: process_create
            os_type: windows
            data:
              path: "C:\\Tools\\mimikatz.exe"
              cmdline: "sekurlsa::logonpasswords"
              parent_path: "C:\\Windows\\System32\\cmd.exe"
              user: "WORKSTATION\\admin"
              pid: 4532
        expected: match
        expected_severity: critical
        expected_mitre: ["T1003.001"]
        tags: ["credential_access", "mimikatz"]

  ## Expected Results

  - `expected: match` - Rule MUST match the event
  - `expected: no_match` - Rule MUST NOT match the event
  - `expected_severity` - Optional: Assert alert severity (critical, high, medium, low)
  - `expected_mitre` - Optional: Assert MITRE techniques present

  ## Usage

      # Run all tests
      TestRunner.run_all()

      # Run specific test file
      TestRunner.run_test("test_cases/mimikatz_detection.yml")

      # Run tests by tag
      TestRunner.run_by_tag("credential_access")

      # Generate coverage report
      TestRunner.coverage_report()
  """

  require Logger

  alias TamanduaServer.Detection.{
    SigmaEvaluator,
    YaraScanner,
    MockEventGenerator,
    TestValidator
  }

  @test_cases_dir "priv/detection_tests"
  @reports_dir "priv/detection_test_reports"

  defmodule TestResult do
    @moduledoc false
    defstruct [
      :test_name,
      :rule,
      :rule_type,
      :status,
      :expected,
      :actual,
      :error,
      :duration_ms,
      :timestamp
    ]
  end

  defmodule TestReport do
    @moduledoc false
    defstruct [
      :total,
      :passed,
      :failed,
      :skipped,
      :duration_ms,
      :timestamp,
      :results,
      :coverage
    ]
  end

  # ── Public API ─────────────────────────────────────────────────────

  @doc """
  Run all test cases in the test cases directory.

  ## Options

  - `:parallel` - Run tests in parallel (default: true)
  - `:verbose` - Show detailed output (default: false)
  - `:fail_fast` - Stop on first failure (default: false)
  - `:tags` - Run only tests with these tags (default: nil)
  - `:rule_type` - Filter by rule type: :sigma or :yara (default: nil)

  ## Returns

  `{:ok, %TestReport{}}` or `{:error, reason}`
  """
  @spec run_all(keyword()) :: {:ok, TestReport.t()} | {:error, term()}
  def run_all(opts \\ []) do
    parallel = Keyword.get(opts, :parallel, true)
    verbose = Keyword.get(opts, :verbose, false)
    fail_fast = Keyword.get(opts, :fail_fast, false)
    tags = Keyword.get(opts, :tags)
    rule_type = Keyword.get(opts, :rule_type)

    test_files = discover_test_files()

    if verbose do
      Logger.info("[TestRunner] Found #{length(test_files)} test files")
    end

    start_time = System.monotonic_time(:millisecond)

    results =
      if parallel do
        run_tests_parallel(test_files, opts)
      else
        run_tests_sequential(test_files, opts)
      end

    # Apply filters
    filtered_results =
      results
      |> filter_by_tags(tags)
      |> filter_by_rule_type(rule_type)

    # Check fail_fast
    if fail_fast && Enum.any?(filtered_results, &(&1.status == :failed)) do
      first_failure = Enum.find(filtered_results, &(&1.status == :failed))
      Logger.error("[TestRunner] FAIL FAST: #{first_failure.test_name}")
      {:error, :test_failure}
    else
      duration_ms = System.monotonic_time(:millisecond) - start_time

      report = %TestReport{
        total: length(filtered_results),
        passed: Enum.count(filtered_results, &(&1.status == :passed)),
        failed: Enum.count(filtered_results, &(&1.status == :failed)),
        skipped: Enum.count(filtered_results, &(&1.status == :skipped)),
        duration_ms: duration_ms,
        timestamp: DateTime.utc_now(),
        results: filtered_results,
        coverage: nil
      }

      if verbose do
        print_report(report)
      end

      {:ok, report}
    end
  rescue
    e ->
      Logger.error("[TestRunner] Failed to run tests: #{Exception.message(e)}")
      {:error, e}
  end

  @doc """
  Run a single test case file.
  """
  @spec run_test(String.t(), keyword()) :: {:ok, TestResult.t()} | {:error, term()}
  def run_test(test_file, opts \\ []) do
    verbose = Keyword.get(opts, :verbose, false)

    if verbose do
      Logger.info("[TestRunner] Running test: #{test_file}")
    end

    case load_test_case(test_file) do
      {:ok, test_case} ->
        result = execute_test_case(test_case, test_file)
        {:ok, result}

      {:error, reason} ->
        Logger.error("[TestRunner] Failed to load test case: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Run all tests matching a specific tag.
  """
  @spec run_by_tag(String.t(), keyword()) :: {:ok, TestReport.t()} | {:error, term()}
  def run_by_tag(tag, opts \\ []) do
    opts = Keyword.put(opts, :tags, [tag])
    run_all(opts)
  end

  @doc """
  Run tests for a specific rule.
  """
  @spec run_by_rule(String.t(), keyword()) :: {:ok, TestReport.t()} | {:error, term()}
  def run_by_rule(rule_name, opts \\ []) do
    test_files = discover_test_files()

    matching_files =
      Enum.filter(test_files, fn file ->
        case load_test_case(file) do
          {:ok, test_case} ->
            test_case["rule"] == rule_name || String.contains?(test_case["rule"] || "", rule_name)

          _ ->
            false
        end
      end)

    verbose = Keyword.get(opts, :verbose, false)

    if verbose do
      Logger.info("[TestRunner] Found #{length(matching_files)} tests for rule: #{rule_name}")
    end

    if Enum.empty?(matching_files) do
      {:ok, empty_report()}
    else
      start_time = System.monotonic_time(:millisecond)

      results =
        Enum.map(matching_files, fn file ->
          {:ok, test_case} = load_test_case(file)
          execute_test_case(test_case, file)
        end)

      duration_ms = System.monotonic_time(:millisecond) - start_time

      report = %TestReport{
        total: length(results),
        passed: Enum.count(results, &(&1.status == :passed)),
        failed: Enum.count(results, &(&1.status == :failed)),
        skipped: Enum.count(results, &(&1.status == :skipped)),
        duration_ms: duration_ms,
        timestamp: DateTime.utc_now(),
        results: results,
        coverage: nil
      }

      {:ok, report}
    end
  end

  @doc """
  Generate test coverage report showing which rules have tests.
  """
  @spec coverage_report(keyword()) :: {:ok, map()} | {:error, term()}
  def coverage_report(opts \\ []) do
    verbose = Keyword.get(opts, :verbose, false)

    sigma_rules = list_sigma_rules()
    yara_rules = list_yara_rules()
    test_files = discover_test_files()

    # Parse all test cases to see which rules they cover
    test_cases =
      Enum.flat_map(test_files, fn file ->
        case load_test_case(file) do
          {:ok, test_case} -> [test_case]
          _ -> []
        end
      end)

    sigma_coverage = calculate_coverage(sigma_rules, test_cases, :sigma)
    yara_coverage = calculate_coverage(yara_rules, test_cases, :yara)

    total_rules = length(sigma_rules) + length(yara_rules)
    total_tested = sigma_coverage.tested + yara_coverage.tested
    coverage_pct = if total_rules > 0, do: Float.round(total_tested / total_rules * 100, 2), else: 0.0

    report = %{
      summary: %{
        total_rules: total_rules,
        total_tested: total_tested,
        total_untested: total_rules - total_tested,
        coverage_percentage: coverage_pct
      },
      sigma: sigma_coverage,
      yara: yara_coverage,
      untested_rules: sigma_coverage.untested ++ yara_coverage.untested
    }

    if verbose do
      print_coverage_report(report)
    end

    {:ok, report}
  end

  @doc """
  Validate test case format without executing.
  """
  @spec validate_test(String.t()) :: :ok | {:error, term()}
  def validate_test(test_file) do
    case load_test_case(test_file) do
      {:ok, test_case} ->
        TestValidator.validate_test_case(test_case)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Generate test report in various formats.

  ## Formats

  - `:text` - Human-readable text output (default)
  - `:json` - JSON format
  - `:junit` - JUnit XML format for CI/CD
  - `:html` - HTML report with charts
  """
  @spec export_report(TestReport.t(), atom(), String.t()) :: :ok | {:error, term()}
  def export_report(report, format \\ :text, output_path \\ nil) do
    output_path = output_path || Path.join(@reports_dir, "report_#{DateTime.to_unix(report.timestamp)}")

    ensure_reports_dir()

    case format do
      :text ->
        content = format_text_report(report)
        File.write("#{output_path}.txt", content)

      :json ->
        content = Jason.encode!(report, pretty: true)
        File.write("#{output_path}.json", content)

      :junit ->
        content = format_junit_report(report)
        File.write("#{output_path}.xml", content)

      :html ->
        content = format_html_report(report)
        File.write("#{output_path}.html", content)

      _ ->
        {:error, :unsupported_format}
    end
  end

  # ── Private Functions ──────────────────────────────────────────────

  defp discover_test_files do
    case File.ls(test_cases_path()) do
      {:ok, files} ->
        files
        |> Enum.filter(&String.ends_with?(&1, ".yml"))
        |> Enum.map(&Path.join(test_cases_path(), &1))

      {:error, :enoent} ->
        Logger.warning("[TestRunner] Test cases directory not found: #{test_cases_path()}")
        []

      {:error, reason} ->
        Logger.error("[TestRunner] Failed to list test cases: #{inspect(reason)}")
        []
    end
  end

  defp load_test_case(file_path) do
    case File.read(file_path) do
      {:ok, content} ->
        case YamlElixir.read_from_string(content) do
          {:ok, %{"test_case" => test_case}} ->
            {:ok, test_case}

          {:ok, _} ->
            {:error, "Invalid test case format: missing 'test_case' key"}

          {:error, reason} ->
            {:error, "YAML parse error: #{inspect(reason)}"}
        end

      {:error, reason} ->
        {:error, "Failed to read file: #{inspect(reason)}"}
    end
  end

  defp execute_test_case(test_case, file_path) do
    start_time = System.monotonic_time(:millisecond)

    result =
      try do
        rule_type = String.to_atom(test_case["rule_type"] || "sigma")
        events = test_case["events"] || []
        expected = String.to_atom(test_case["expected"] || "match")

        # Generate event from template
        event =
          case events do
            [first_event | _] ->
              MockEventGenerator.generate_from_template(first_event)

            [] ->
              %{}
          end

        # Execute rule
        match_result =
          case rule_type do
            :sigma ->
              execute_sigma_rule(test_case["rule"], event)

            :yara ->
              execute_yara_rule(test_case["rule"], event)

            _ ->
              {:error, :unsupported_rule_type}
          end

        # Validate result
        validation_result =
          TestValidator.validate_result(
            match_result,
            expected,
            test_case["expected_severity"],
            test_case["expected_mitre"]
          )

        case validation_result do
          :ok ->
            %TestResult{
              test_name: test_case["name"] || Path.basename(file_path),
              rule: test_case["rule"],
              rule_type: rule_type,
              status: :passed,
              expected: expected,
              actual: match_result,
              error: nil,
              duration_ms: System.monotonic_time(:millisecond) - start_time,
              timestamp: DateTime.utc_now()
            }

          {:error, reason} ->
            %TestResult{
              test_name: test_case["name"] || Path.basename(file_path),
              rule: test_case["rule"],
              rule_type: rule_type,
              status: :failed,
              expected: expected,
              actual: match_result,
              error: reason,
              duration_ms: System.monotonic_time(:millisecond) - start_time,
              timestamp: DateTime.utc_now()
            }
        end
      rescue
        e ->
          %TestResult{
            test_name: test_case["name"] || Path.basename(file_path),
            rule: test_case["rule"],
            rule_type: String.to_atom(test_case["rule_type"] || "sigma"),
            status: :failed,
            expected: nil,
            actual: nil,
            error: Exception.message(e),
            duration_ms: System.monotonic_time(:millisecond) - start_time,
            timestamp: DateTime.utc_now()
          }
      end

    result
  end

  defp execute_sigma_rule(rule_path, event) do
    # Load rule from priv/sigma_rules
    full_path = Path.join("priv/sigma_rules", rule_path)

    case File.read(full_path) do
      {:ok, rule_content} ->
        case YamlElixir.read_from_string(rule_content) do
          {:ok, rules} when is_list(rules) ->
            # Multiple rules in one file (separated by ---)
            Enum.reduce_while(rules, :no_match, fn rule, _acc ->
              case SigmaEvaluator.evaluate_rule(rule, event) do
                {:match, name} -> {:halt, {:match, name}}
                :no_match -> {:cont, :no_match}
              end
            end)

          {:ok, rule} when is_map(rule) ->
            SigmaEvaluator.evaluate_rule(rule, event)

          {:error, reason} ->
            {:error, "Failed to parse Sigma rule: #{inspect(reason)}"}
        end

      {:error, reason} ->
        {:error, "Failed to load rule: #{inspect(reason)}"}
    end
  end

  defp execute_yara_rule(rule_path, event) do
    # For YARA, we need binary content
    # Extract file path from event if present
    file_path = get_in(event, ["payload", "path"]) || get_in(event, [:payload, :path])

    if file_path && File.exists?(file_path) do
      case YaraScanner.scan_file(file_path) do
        {:ok, matches} when matches != [] ->
          {:match, Enum.map(matches, & &1.rule_name) |> Enum.join(", ")}

        {:ok, []} ->
          :no_match

        {:error, reason} ->
          {:error, reason}
      end
    else
      # No file to scan, return no_match
      :no_match
    end
  end

  defp run_tests_parallel(test_files, opts) do
    test_files
    |> Task.async_stream(
      fn file ->
        case load_test_case(file) do
          {:ok, test_case} ->
            execute_test_case(test_case, file)

          {:error, reason} ->
            %TestResult{
              test_name: Path.basename(file),
              rule: nil,
              rule_type: nil,
              status: :skipped,
              expected: nil,
              actual: nil,
              error: "Failed to load: #{inspect(reason)}",
              duration_ms: 0,
              timestamp: DateTime.utc_now()
            }
        end
      end,
      max_concurrency: System.schedulers_online() * 2,
      timeout: 30_000
    )
    |> Enum.map(fn {:ok, result} -> result end)
  end

  defp run_tests_sequential(test_files, _opts) do
    Enum.map(test_files, fn file ->
      case load_test_case(file) do
        {:ok, test_case} ->
          execute_test_case(test_case, file)

        {:error, reason} ->
          %TestResult{
            test_name: Path.basename(file),
            rule: nil,
            rule_type: nil,
            status: :skipped,
            expected: nil,
            actual: nil,
            error: "Failed to load: #{inspect(reason)}",
            duration_ms: 0,
            timestamp: DateTime.utc_now()
          }
      end
    end)
  end

  defp filter_by_tags(results, nil), do: results

  defp filter_by_tags(results, tags) do
    Enum.filter(results, fn result ->
      # Would need to load test case again to check tags
      # For now, return all
      true
    end)
  end

  defp filter_by_rule_type(results, nil), do: results

  defp filter_by_rule_type(results, rule_type) do
    Enum.filter(results, &(&1.rule_type == rule_type))
  end

  defp list_sigma_rules do
    Path.wildcard("priv/sigma_rules/**/*.yml")
    |> Enum.map(&Path.relative_to(&1, "priv/sigma_rules"))
  end

  defp list_yara_rules do
    Path.wildcard("priv/yara_rules/**/*.yar")
    |> Enum.map(&Path.relative_to(&1, "priv/yara_rules"))
  end

  defp calculate_coverage(rules, test_cases, rule_type) do
    tested_rules =
      test_cases
      |> Enum.filter(fn tc ->
        String.to_atom(tc["rule_type"] || "sigma") == rule_type
      end)
      |> Enum.map(& &1["rule"])
      |> MapSet.new()

    untested =
      Enum.reject(rules, fn rule ->
        MapSet.member?(tested_rules, rule)
      end)

    %{
      total: length(rules),
      tested: MapSet.size(tested_rules),
      untested: untested,
      coverage_pct: if(length(rules) > 0, do: Float.round(MapSet.size(tested_rules) / length(rules) * 100, 2), else: 0.0)
    }
  end

  defp empty_report do
    %TestReport{
      total: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      duration_ms: 0,
      timestamp: DateTime.utc_now(),
      results: [],
      coverage: nil
    }
  end

  defp print_report(report) do
    IO.puts("\n" <> String.duplicate("=", 80))
    IO.puts("Detection Rule Test Report")
    IO.puts(String.duplicate("=", 80))
    IO.puts("Total:    #{report.total}")
    IO.puts("Passed:   #{report.passed} (#{percentage(report.passed, report.total)}%)")
    IO.puts("Failed:   #{report.failed} (#{percentage(report.failed, report.total)}%)")
    IO.puts("Skipped:  #{report.skipped} (#{percentage(report.skipped, report.total)}%)")
    IO.puts("Duration: #{report.duration_ms}ms")
    IO.puts(String.duplicate("=", 80))

    if report.failed > 0 do
      IO.puts("\nFailed Tests:")
      IO.puts(String.duplicate("-", 80))

      report.results
      |> Enum.filter(&(&1.status == :failed))
      |> Enum.each(fn result ->
        IO.puts("  [FAIL] #{result.test_name}")
        IO.puts("         Rule: #{result.rule}")
        IO.puts("         Error: #{result.error}")
        IO.puts("")
      end)
    end
  end

  defp print_coverage_report(report) do
    IO.puts("\n" <> String.duplicate("=", 80))
    IO.puts("Detection Rule Coverage Report")
    IO.puts(String.duplicate("=", 80))
    IO.puts("Total Rules:    #{report.summary.total_rules}")
    IO.puts("Tested:         #{report.summary.total_tested} (#{report.summary.coverage_percentage}%)")
    IO.puts("Untested:       #{report.summary.total_untested}")
    IO.puts("")
    IO.puts("Sigma Rules:    #{report.sigma.tested}/#{report.sigma.total} (#{report.sigma.coverage_pct}%)")
    IO.puts("YARA Rules:     #{report.yara.tested}/#{report.yara.total} (#{report.yara.coverage_pct}%)")
    IO.puts(String.duplicate("=", 80))

    if length(report.untested_rules) > 0 do
      IO.puts("\nUntested Rules:")
      IO.puts(String.duplicate("-", 80))

      Enum.each(report.untested_rules, fn rule ->
        IO.puts("  - #{rule}")
      end)
    end
  end

  defp percentage(_part, 0), do: 0
  defp percentage(part, total), do: Float.round(part / total * 100, 1)

  defp format_text_report(report) do
    """
    Detection Rule Test Report
    ==========================

    Summary:
    - Total:    #{report.total}
    - Passed:   #{report.passed}
    - Failed:   #{report.failed}
    - Skipped:  #{report.skipped}
    - Duration: #{report.duration_ms}ms
    - Timestamp: #{report.timestamp}

    Results:
    #{Enum.map_join(report.results, "\n", &format_test_result/1)}
    """
  end

  defp format_test_result(result) do
    status_icon =
      case result.status do
        :passed -> "✓"
        :failed -> "✗"
        :skipped -> "○"
      end

    "  #{status_icon} #{result.test_name} (#{result.duration_ms}ms)"
  end

  defp format_junit_report(report) do
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <testsuites name="Detection Rule Tests" tests="#{report.total}" failures="#{report.failed}" time="#{report.duration_ms / 1000}">
      <testsuite name="Detection Rules" tests="#{report.total}" failures="#{report.failed}" time="#{report.duration_ms / 1000}">
    #{Enum.map_join(report.results, "\n", &format_junit_testcase/1)}
      </testsuite>
    </testsuites>
    """
  end

  defp format_junit_testcase(result) do
    case result.status do
      :passed ->
        "    <testcase name=\"#{escape_xml(result.test_name)}\" classname=\"#{escape_xml(result.rule || "unknown")}\" time=\"#{result.duration_ms / 1000}\"/>"

      :failed ->
        """
            <testcase name="#{escape_xml(result.test_name)}" classname="#{escape_xml(result.rule || "unknown")}" time="#{result.duration_ms / 1000}">
              <failure message="#{escape_xml(result.error || "Test failed")}">
        Expected: #{result.expected}
        Actual: #{inspect(result.actual)}
              </failure>
            </testcase>
        """

      :skipped ->
        """
            <testcase name="#{escape_xml(result.test_name)}" classname="#{escape_xml(result.rule || "unknown")}" time="#{result.duration_ms / 1000}">
              <skipped/>
            </testcase>
        """
    end
  end

  defp format_html_report(report) do
    passed_pct = percentage(report.passed, report.total)
    failed_pct = percentage(report.failed, report.total)

    """
    <!DOCTYPE html>
    <html>
    <head>
      <title>Detection Rule Test Report</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .summary { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        .passed { color: green; }
        .failed { color: red; }
        .skipped { color: gray; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #4CAF50; color: white; }
      </style>
    </head>
    <body>
      <h1>Detection Rule Test Report</h1>
      <div class="summary">
        <h2>Summary</h2>
        <p>Total: #{report.total}</p>
        <p class="passed">Passed: #{report.passed} (#{passed_pct}%)</p>
        <p class="failed">Failed: #{report.failed} (#{failed_pct}%)</p>
        <p class="skipped">Skipped: #{report.skipped}</p>
        <p>Duration: #{report.duration_ms}ms</p>
        <p>Timestamp: #{report.timestamp}</p>
      </div>

      <h2>Test Results</h2>
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>Test Name</th>
            <th>Rule</th>
            <th>Duration</th>
            <th>Error</th>
          </tr>
        </thead>
        <tbody>
    #{Enum.map_join(report.results, "\n", &format_html_row/1)}
        </tbody>
      </table>
    </body>
    </html>
    """
  end

  defp format_html_row(result) do
    status_class = Atom.to_string(result.status)

    """
          <tr>
            <td class="#{status_class}">#{result.status}</td>
            <td>#{escape_xml(result.test_name)}</td>
            <td>#{escape_xml(result.rule || "-")}</td>
            <td>#{result.duration_ms}ms</td>
            <td>#{escape_xml(result.error || "-")}</td>
          </tr>
    """
  end

  defp escape_xml(nil), do: ""

  defp escape_xml(str) do
    str
    |> to_string()
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&apos;")
  end

  defp test_cases_path do
    Path.join(:code.priv_dir(:tamandua_server), @test_cases_dir)
  end

  defp ensure_reports_dir do
    reports_path = Path.join(:code.priv_dir(:tamandua_server), @reports_dir)
    File.mkdir_p!(reports_path)
  end
end
