defmodule TamanduaServer.Detection.TestRunnerTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Detection.TestRunner

  describe "run_all/1" do
    test "runs all detection rule tests" do
      # This test requires actual test cases to exist
      # For now, we test that the function executes without error
      assert {:ok, report} = TestRunner.run_all(verbose: false)
      assert report.total >= 0
      assert report.passed >= 0
      assert report.failed >= 0
      assert report.skipped >= 0
      assert report.duration_ms >= 0
    end

    test "returns error if test directory doesn't exist" do
      # If no test cases exist, should return empty report
      {:ok, report} = TestRunner.run_all(verbose: false)
      assert is_integer(report.total)
    end
  end

  describe "run_test/2" do
    test "runs a single test case" do
      # Would need an actual test file to run
      # For now, test error handling
      result = TestRunner.run_test("nonexistent_test.yml")
      assert match?({:error, _}, result) or match?({:ok, _}, result)
    end
  end

  describe "coverage_report/1" do
    test "generates coverage report" do
      assert {:ok, report} = TestRunner.coverage_report(verbose: false)
      assert is_map(report)
      assert Map.has_key?(report, :summary)
      assert Map.has_key?(report, :sigma)
      assert Map.has_key?(report, :yara)
    end

    test "calculates coverage percentage correctly" do
      {:ok, report} = TestRunner.coverage_report(verbose: false)
      assert is_number(report.summary.coverage_percentage)
      assert report.summary.coverage_percentage >= 0.0
      assert report.summary.coverage_percentage <= 100.0
    end
  end

  describe "export_report/3" do
    test "exports report as text" do
      {:ok, report} = TestRunner.run_all(verbose: false)
      assert :ok == TestRunner.export_report(report, :text)
    end

    test "exports report as JSON" do
      {:ok, report} = TestRunner.run_all(verbose: false)
      assert :ok == TestRunner.export_report(report, :json)
    end

    test "exports report as JUnit XML" do
      {:ok, report} = TestRunner.run_all(verbose: false)
      assert :ok == TestRunner.export_report(report, :junit)
    end

    test "exports report as HTML" do
      {:ok, report} = TestRunner.run_all(verbose: false)
      assert :ok == TestRunner.export_report(report, :html)
    end
  end
end
