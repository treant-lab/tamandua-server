defmodule TamanduaServer.Detection.TestValidatorTest do
  use ExUnit.Case

  alias TamanduaServer.Detection.TestValidator

  describe "validate_test_case/1" do
    test "validates valid test case" do
      test_case = %{
        "name" => "Test Mimikatz Detection",
        "rule" => "credential_access/mimikatz_patterns.yml",
        "rule_type" => "sigma",
        "expected" => "match",
        "events" => [
          %{
            "type" => "process_create",
            "data" => %{"path" => "C:\\mimikatz.exe"}
          }
        ]
      }

      assert :ok == TestValidator.validate_test_case(test_case)
    end

    test "fails when missing required fields" do
      test_case = %{
        "name" => "Test"
      }

      assert {:error, reason} = TestValidator.validate_test_case(test_case)
      assert String.contains?(reason, "Missing required fields")
    end

    test "fails when rule_type is invalid" do
      test_case = %{
        "name" => "Test",
        "rule" => "test.yml",
        "rule_type" => "invalid",
        "expected" => "match",
        "events" => [%{"type" => "process_create"}]
      }

      assert {:error, reason} = TestValidator.validate_test_case(test_case)
      assert String.contains?(reason, "Invalid rule_type")
    end

    test "fails when expected is invalid" do
      test_case = %{
        "name" => "Test",
        "rule" => "test.yml",
        "rule_type" => "sigma",
        "expected" => "invalid",
        "events" => [%{"type" => "process_create"}]
      }

      assert {:error, reason} = TestValidator.validate_test_case(test_case)
      assert String.contains?(reason, "Invalid expected value")
    end

    test "fails when events is empty" do
      test_case = %{
        "name" => "Test",
        "rule" => "test.yml",
        "rule_type" => "sigma",
        "expected" => "match",
        "events" => []
      }

      assert {:error, reason} = TestValidator.validate_test_case(test_case)
      assert String.contains?(reason, "at least one event")
    end

    test "fails when event missing type" do
      test_case = %{
        "name" => "Test",
        "rule" => "test.yml",
        "rule_type" => "sigma",
        "expected" => "match",
        "events" => [
          %{"data" => %{}}
        ]
      }

      assert {:error, reason} = TestValidator.validate_test_case(test_case)
      assert String.contains?(reason, "missing 'type'")
    end
  end

  describe "validate_result/4" do
    test "passes when match status matches expected" do
      assert :ok == TestValidator.validate_result({:match, "Rule"}, :match, nil, nil)
      assert :ok == TestValidator.validate_result(:no_match, :no_match, nil, nil)
    end

    test "fails when match status doesn't match expected" do
      assert {:error, reason} = TestValidator.validate_result({:match, "Rule"}, :no_match, nil, nil)
      assert String.contains?(reason, "Match status mismatch")
    end

    test "fails when expecting match but got no_match" do
      assert {:error, reason} = TestValidator.validate_result(:no_match, :match, nil, nil)
      assert String.contains?(reason, "Match status mismatch")
    end

    test "handles error results" do
      assert {:error, reason} = TestValidator.validate_result({:error, "Rule not found"}, :match, nil, nil)
      assert String.contains?(reason, "Match status mismatch")
    end
  end
end
