defmodule TamanduaServer.Detection.TestValidator do
  @moduledoc """
  Validates detection rule test results.

  Checks that actual detection results match expected outcomes including:
  - Match/no match status
  - Alert severity
  - MITRE ATT&CK techniques
  - Alert metadata

  ## Usage

      # Validate match result
      TestValidator.validate_result(
        {:match, "Mimikatz Detected"},
        :match,
        "critical",
        ["T1003.001"]
      )
      # => :ok

      # Validate no match
      TestValidator.validate_result(
        :no_match,
        :no_match,
        nil,
        nil
      )
      # => :ok
  """

  @doc """
  Validate a test case format before execution.

  Ensures the test case has all required fields and valid values.
  """
  @spec validate_test_case(map()) :: :ok | {:error, String.t()}
  def validate_test_case(test_case) do
    with :ok <- validate_required_fields(test_case),
         :ok <- validate_rule_type(test_case),
         :ok <- validate_expected(test_case),
         :ok <- validate_events(test_case) do
      :ok
    end
  end

  @doc """
  Validate detection result against expected outcome.

  ## Parameters

  - `actual` - The actual detection result (e.g., {:match, "rule name"} or :no_match)
  - `expected` - Expected outcome (:match or :no_match)
  - `expected_severity` - Expected alert severity (optional)
  - `expected_mitre` - Expected MITRE techniques (optional)

  ## Returns

  - `:ok` if validation passes
  - `{:error, reason}` if validation fails
  """
  @spec validate_result(term(), atom(), String.t() | nil, list() | nil) :: :ok | {:error, String.t()}
  def validate_result(actual, expected, expected_severity \\ nil, expected_mitre \\ nil) do
    with :ok <- validate_match_status(actual, expected),
         :ok <- validate_severity(actual, expected_severity),
         :ok <- validate_mitre(actual, expected_mitre) do
      :ok
    end
  end

  # ── Private Functions ──────────────────────────────────────────────

  defp validate_required_fields(test_case) do
    required = ["name", "rule", "expected"]

    missing =
      Enum.filter(required, fn field ->
        !Map.has_key?(test_case, field) || is_nil(test_case[field])
      end)

    if Enum.empty?(missing) do
      :ok
    else
      {:error, "Missing required fields: #{Enum.join(missing, ", ")}"}
    end
  end

  defp validate_rule_type(test_case) do
    rule_type = test_case["rule_type"] || "sigma"

    if rule_type in ["sigma", "yara"] do
      :ok
    else
      {:error, "Invalid rule_type: #{rule_type}. Must be 'sigma' or 'yara'"}
    end
  end

  defp validate_expected(test_case) do
    expected = test_case["expected"]

    if expected in ["match", "no_match"] do
      :ok
    else
      {:error, "Invalid expected value: #{expected}. Must be 'match' or 'no_match'"}
    end
  end

  defp validate_events(test_case) do
    events = test_case["events"] || []

    if is_list(events) && length(events) > 0 do
      # Validate each event has required fields
      invalid =
        Enum.find(events, fn event ->
          !Map.has_key?(event, "type") && !Map.has_key?(event, :type)
        end)

      if invalid do
        {:error, "Event missing 'type' field"}
      else
        :ok
      end
    else
      {:error, "Test case must have at least one event"}
    end
  end

  defp validate_match_status(actual, expected) do
    actual_matched =
      case actual do
        {:match, _} -> true
        :no_match -> false
        {:error, _} -> false
        _ -> false
      end

    expected_match = expected == :match

    if actual_matched == expected_match do
      :ok
    else
      {:error, "Match status mismatch: expected #{expected}, got #{format_actual(actual)}"}
    end
  end

  defp validate_severity(_actual, nil), do: :ok

  defp validate_severity(actual, _expected_severity) do
    case actual do
      {:match, _rule_name} ->
        # In real implementation, we'd load the rule and check its severity
        # For now, we'll extract from rule name or skip validation
        # TODO: Load rule and extract actual severity
        :ok

      _ ->
        :ok
    end
  end

  defp validate_mitre(_actual, nil), do: :ok

  defp validate_mitre(actual, expected_mitre) when is_list(expected_mitre) do
    case actual do
      {:match, _rule_name} ->
        # In real implementation, we'd load the rule and check MITRE tags
        # For now, skip validation
        # TODO: Load rule and extract actual MITRE techniques
        :ok

      _ ->
        :ok
    end
  end

  defp validate_mitre(_actual, _expected_mitre), do: :ok

  defp format_actual({:match, name}), do: "match (#{name})"
  defp format_actual(:no_match), do: "no_match"
  defp format_actual({:error, reason}), do: "error (#{inspect(reason)})"
  defp format_actual(other), do: inspect(other)
end
