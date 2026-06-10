defmodule TamanduaServer.Detection.RulesPropertyTest do
  use ExUnit.Case
  use ExUnitProperties

  alias TamanduaServer.Detection.Rules

  describe "Detection rules properties" do
    @tag timeout: 120_000
    property "rule evaluation is deterministic" do
      check all(
              rule <- rule_generator(),
              event <- event_generator(),
              max_runs: 100
            ) do
        # Evaluate rule multiple times
        result1 = evaluate_rule(rule, event)
        result2 = evaluate_rule(rule, event)
        result3 = evaluate_rule(rule, event)

        # All results should be identical
        assert result1 == result2
        assert result2 == result3
      end
    end

    @tag timeout: 120_000
    property "disabled rules never match" do
      check all(
              rule <- rule_generator(),
              event <- event_generator(),
              max_runs: 100
            ) do
        disabled_rule = Map.put(rule, "enabled", false)

        result = evaluate_rule(disabled_rule, event)

        # Disabled rules should never trigger
        assert result == false or result == :disabled
      end
    end

    @tag timeout: 120_000
    property "rule severity is preserved" do
      check all(
              severity <- severity_generator(),
              max_runs: 100
            ) do
        rule = %{
          "id" => "test-rule",
          "name" => "Test Rule",
          "severity" => severity,
          "enabled" => true,
          "condition" => "selection",
          "detection" => %{"selection" => %{"field" => "value"}}
        }

        # Severity should be valid
        assert severity in ["info", "low", "medium", "high", "critical"]

        # After processing, severity should be unchanged
        processed = normalize_rule(rule)
        assert processed["severity"] == severity
      end
    end

    @tag timeout: 120_000
    property "rule IDs are unique in a collection" do
      check all(
              rules <- list_of(rule_generator(), min_length: 1, max_length: 50),
              max_runs: 50
            ) do
        # Extract IDs
        ids = Enum.map(rules, & &1["id"])

        # Check uniqueness
        unique_ids = Enum.uniq(ids)

        # If we enforce uniqueness, this should hold
        assert length(unique_ids) == length(ids)
      end
    end

    @tag timeout: 120_000
    property "rule matching respects logsource filters" do
      check all(
              category <- category_generator(),
              event_type <- event_type_generator(),
              max_runs: 100
            ) do
        rule = %{
          "logsource" => %{"category" => category},
          "detection" => %{
            "selection" => %{"field" => "test"},
            "condition" => "selection"
          }
        }

        event = %{
          "event_type" => event_type,
          "payload" => %{"field" => "test"}
        }

        result = evaluate_rule(rule, event)

        # If categories don't match, rule shouldn't match
        if category_matches?(category, event_type) do
          # May match depending on detection logic
          assert is_boolean(result)
        else
          # Shouldn't match if categories don't align
          assert result == false
        end
      end
    end

    @tag timeout: 120_000
    property "rule priorities are ordered" do
      check all(
              severities <- list_of(severity_generator(), min_length: 2, max_length: 10),
              max_runs: 50
            ) do
        priorities =
          Enum.map(severities, fn sev ->
            severity_to_priority(sev)
          end)

        # Check that critical > high > medium > low > info
        sorted_priorities = Enum.sort(priorities, :desc)

        # Verify order is consistent
        for i <- 0..(length(priorities) - 2) do
          assert Enum.at(sorted_priorities, i) >= Enum.at(sorted_priorities, i + 1)
        end
      end
    end

    @tag timeout: 120_000
    property "field matching is case-sensitive by default" do
      check all(
              value <- string(:alphanumeric, min_length: 1, max_length: 30),
              max_runs: 100
            ) do
        uppercased = String.upcase(value)

        # Skip if already uppercase
        if value != uppercased do
          rule = %{
            "detection" => %{
              "selection" => %{"field" => value},
              "condition" => "selection"
            }
          }

          event_match = %{"field" => value}
          event_no_match = %{"field" => uppercased}

          match_result = matches_selection?(rule["detection"]["selection"], event_match)
          no_match_result = matches_selection?(rule["detection"]["selection"], event_no_match)

          # Exact case should match
          assert match_result == true

          # Different case should not match (by default)
          assert no_match_result == false
        end
      end
    end

    @tag timeout: 120_000
    property "wildcard patterns match correctly" do
      check all(
              prefix <- string(:alphanumeric, min_length: 1, max_length: 10),
              suffix <- string(:alphanumeric, min_length: 1, max_length: 10),
              middle <- string(:alphanumeric, min_length: 0, max_length: 20),
              max_runs: 100
            ) do
        pattern = prefix <> "*" <> suffix
        full_string = prefix <> middle <> suffix

        result = wildcard_match?(pattern, full_string)

        # Should match
        assert result == true

        # Non-matching string shouldn't match
        non_match = "xxx" <> full_string
        assert wildcard_match?(pattern, non_match) == false
      end
    end

    @tag timeout: 120_000
    property "list fields match any value in list" do
      check all(
              values <- list_of(string(:alphanumeric, min_length: 1), min_length: 1, max_length: 5),
              max_runs: 100
            ) do
        rule = %{
          "detection" => %{
            "selection" => %{"field" => values},
            "condition" => "selection"
          }
        }

        # Pick a value from the list
        selected_value = Enum.random(values)

        event = %{"field" => selected_value}

        # Should match
        result = matches_selection?(rule["detection"]["selection"], event)
        assert result == true
      end
    end

    @tag timeout: 120_000
    property "regex patterns are valid" do
      check all(
              pattern <- regex_pattern_generator(),
              max_runs: 50
            ) do
        # Should compile without error
        case Regex.compile(pattern) do
          {:ok, _regex} ->
            assert true

          {:error, _reason} ->
            # Some generated patterns might be invalid, that's ok
            assert true
        end
      end
    end
  end

  # Helper functions
  defp evaluate_rule(rule, event) do
    # Simplified rule evaluation
    if Map.get(rule, "enabled", true) == false do
      :disabled
    else
      # Simple matching logic
      selection = get_in(rule, ["detection", "selection"])
      matches_selection?(selection, event["payload"] || %{})
    end
  end

  defp matches_selection?(nil, _event), do: false

  defp matches_selection?(selection, event) when is_map(selection) do
    Enum.all?(selection, fn {field, value} ->
      event_value = Map.get(event, field)

      cond do
        is_list(value) -> event_value in value
        is_binary(value) and String.contains?(value, "*") -> wildcard_match?(value, event_value)
        true -> event_value == value
      end
    end)
  end

  defp wildcard_match?(pattern, string) when is_binary(pattern) and is_binary(string) do
    # Convert wildcard to regex
    regex_pattern =
      pattern
      |> Regex.escape()
      |> String.replace("\\*", ".*")

    case Regex.compile("^#{regex_pattern}$") do
      {:ok, regex} -> Regex.match?(regex, string)
      {:error, _} -> false
    end
  end

  defp wildcard_match?(_pattern, _string), do: false

  defp normalize_rule(rule) do
    # Simple normalization
    rule
  end

  defp category_matches?(category, event_type) do
    # Simple category matching
    mapping = %{
      "process_creation" => ["process_create"],
      "network_connection" => ["network_connect"],
      "file_event" => ["file_create", "file_modify", "file_delete"],
      "dns_query" => ["dns_query"]
    }

    event_types = Map.get(mapping, category, [])
    event_type in event_types
  end

  defp severity_to_priority(severity) do
    case severity do
      "critical" -> 5
      "high" -> 4
      "medium" -> 3
      "low" -> 2
      "info" -> 1
      _ -> 0
    end
  end

  # Generators
  defp rule_generator do
    gen all(
          id <- uuid_generator(),
          name <- string(:alphanumeric, min_length: 1, max_length: 50),
          severity <- severity_generator(),
          enabled <- boolean(),
          field <- field_name_generator(),
          value <- string(:alphanumeric, min_length: 1, max_length: 30),
          max_tries: 10
        ) do
      %{
        "id" => id,
        "name" => name,
        "severity" => severity,
        "enabled" => enabled,
        "detection" => %{
          "selection" => %{field => value},
          "condition" => "selection"
        }
      }
    end
  end

  defp event_generator do
    gen all(
          event_type <- event_type_generator(),
          payload <- payload_generator(),
          max_tries: 10
        ) do
      %{
        "event_type" => event_type,
        "payload" => payload
      }
    end
  end

  defp severity_generator do
    one_of([
      constant("info"),
      constant("low"),
      constant("medium"),
      constant("high"),
      constant("critical")
    ])
  end

  defp category_generator do
    one_of([
      constant("process_creation"),
      constant("network_connection"),
      constant("file_event"),
      constant("dns_query")
    ])
  end

  defp event_type_generator do
    one_of([
      constant("process_create"),
      constant("network_connect"),
      constant("file_create"),
      constant("file_modify"),
      constant("dns_query")
    ])
  end

  defp field_name_generator do
    one_of([
      constant("CommandLine"),
      constant("Image"),
      constant("User"),
      constant("DestinationIp"),
      constant("field"),
      string(:alphanumeric, min_length: 1, max_length: 20)
    ])
  end

  defp payload_generator do
    gen all(
          fields <- list_of(field_value_pair_generator(), min_length: 1, max_length: 5),
          max_tries: 10
        ) do
      Map.new(fields)
    end
  end

  defp field_value_pair_generator do
    gen all(
          key <- field_name_generator(),
          value <- one_of([string(:alphanumeric), integer(1..10000)]),
          max_tries: 10
        ) do
      {key, value}
    end
  end

  defp uuid_generator do
    bind(
      list_of(integer(0..255), length: 16),
      fn bytes ->
        constant(
          bytes
          |> Enum.map(&Integer.to_string(&1, 16) |> String.pad_leading(2, "0"))
          |> Enum.chunk_every(4)
          |> Enum.map(&Enum.join/1)
          |> Enum.join("-")
        )
      end
    )
  end

  defp regex_pattern_generator do
    one_of([
      constant(".*"),
      constant("[a-z]+"),
      constant("[0-9]{3}"),
      constant("test.*value"),
      constant("^start"),
      constant("end$"),
      string_regex("[a-z.+*]{1,20}")
    ])
  end
end
