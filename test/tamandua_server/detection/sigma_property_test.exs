defmodule TamanduaServer.Detection.SigmaPropertyTest do
  use ExUnit.Case
  use ExUnitProperties

  alias TamanduaServer.Detection.Rules.Sigma

  describe "Sigma parser properties" do
    @tag timeout: 120_000
    property "matching is deterministic" do
      check all(
              rule <- sigma_rule_generator(),
              event <- event_generator(),
              max_runs: 100
            ) do
        result1 = Sigma.matches?(event, rule)
        result2 = Sigma.matches?(event, rule)

        assert result1 == result2
      end
    end

    @tag timeout: 120_000
    property "OR condition matches if any sub-condition matches" do
      check all(
              field <- field_name_generator(),
              value1 <- string_value_generator(),
              value2 <- string_value_generator(),
              event <- event_generator(),
              max_runs: 50
            ) do
        # Create rules with selection1 OR selection2
        or_rule = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection1" => %{field => value1},
            "selection2" => %{field => value2},
            "condition" => "selection1 or selection2"
          }
        }

        rule1 = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection1" => %{field => value1},
            "condition" => "selection1"
          }
        }

        rule2 = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection2" => %{field => value2},
            "condition" => "selection2"
          }
        }

        or_matches = Sigma.matches?(event, or_rule)
        either_matches = Sigma.matches?(event, rule1) or Sigma.matches?(event, rule2)

        assert or_matches == either_matches
      end
    end

    @tag timeout: 120_000
    property "AND condition matches only if all sub-conditions match" do
      check all(
              field1 <- field_name_generator(),
              field2 <- field_name_generator(),
              value1 <- string_value_generator(),
              value2 <- string_value_generator(),
              event <- event_generator(),
              field1 != field2,
              max_runs: 50
            ) do
        # Create rules with selection1 AND selection2
        and_rule = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection1" => %{field1 => value1},
            "selection2" => %{field2 => value2},
            "condition" => "selection1 and selection2"
          }
        }

        rule1 = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection1" => %{field1 => value1},
            "condition" => "selection1"
          }
        }

        rule2 = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection2" => %{field2 => value2},
            "condition" => "selection2"
          }
        }

        and_matches = Sigma.matches?(event, and_rule)
        both_match = Sigma.matches?(event, rule1) and Sigma.matches?(event, rule2)

        assert and_matches == both_match
      end
    end

    @tag timeout: 120_000
    property "NOT inverts the result" do
      check all(
              field <- field_name_generator(),
              value <- string_value_generator(),
              event <- event_generator(),
              max_runs: 50
            ) do
        rule = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection" => %{field => value},
            "condition" => "selection"
          }
        }

        not_rule = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection" => %{field => value},
            "condition" => "not selection"
          }
        }

        assert Sigma.matches?(event, rule) != Sigma.matches?(event, not_rule)
      end
    end

    @tag timeout: 120_000
    property "contains modifier matches substrings" do
      check all(
              field <- field_name_generator(),
              substring <- string(:alphanumeric, min_length: 1, max_length: 10),
              prefix <- string(:alphanumeric, max_length: 5),
              suffix <- string(:alphanumeric, max_length: 5),
              max_runs: 100
            ) do
        full_value = prefix <> substring <> suffix

        event = %{
          "event_type" => "process_create",
          "payload" => %{field => full_value}
        }

        rule = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection" => %{field => %{"contains" => substring}},
            "condition" => "selection"
          }
        }

        assert Sigma.matches?(event, rule) == true
      end
    end

    @tag timeout: 120_000
    property "startswith modifier matches prefixes" do
      check all(
              field <- field_name_generator(),
              prefix <- string(:alphanumeric, min_length: 1, max_length: 10),
              suffix <- string(:alphanumeric, max_length: 10),
              max_runs: 100
            ) do
        full_value = prefix <> suffix

        event = %{
          "event_type" => "process_create",
          "payload" => %{field => full_value}
        }

        rule = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection" => %{field => %{"startswith" => prefix}},
            "condition" => "selection"
          }
        }

        assert Sigma.matches?(event, rule) == true
      end
    end

    @tag timeout: 120_000
    property "endswith modifier matches suffixes" do
      check all(
              field <- field_name_generator(),
              prefix <- string(:alphanumeric, max_length: 10),
              suffix <- string(:alphanumeric, min_length: 1, max_length: 10),
              max_runs: 100
            ) do
        full_value = prefix <> suffix

        event = %{
          "event_type" => "process_create",
          "payload" => %{field => full_value}
        }

        rule = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection" => %{field => %{"endswith" => suffix}},
            "condition" => "selection"
          }
        }

        assert Sigma.matches?(event, rule) == true
      end
    end

    @tag timeout: 120_000
    property "all modifier matches when all values present" do
      check all(
              field <- field_name_generator(),
              values <- list_of(string_value_generator(), min_length: 1, max_length: 5),
              max_runs: 50
            ) do
        # Event contains all values as a list
        event = %{
          "event_type" => "process_create",
          "payload" => %{field => values}
        }

        rule = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection" => %{field => %{"all" => values}},
            "condition" => "selection"
          }
        }

        assert Sigma.matches?(event, rule) == true
      end
    end

    @tag timeout: 120_000
    property "gt modifier enforces greater than" do
      check all(
              field <- field_name_generator(),
              threshold <- integer(1..1000),
              value <- integer(1..1000),
              max_runs: 100
            ) do
        event = %{
          "event_type" => "process_create",
          "payload" => %{field => value}
        }

        rule = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection" => %{field => %{"gt" => threshold}},
            "condition" => "selection"
          }
        }

        expected = value > threshold
        assert Sigma.matches?(event, rule) == expected
      end
    end

    @tag timeout: 120_000
    property "gte modifier enforces greater than or equal" do
      check all(
              field <- field_name_generator(),
              threshold <- integer(1..1000),
              value <- integer(1..1000),
              max_runs: 100
            ) do
        event = %{
          "event_type" => "process_create",
          "payload" => %{field => value}
        }

        rule = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection" => %{field => %{"gte" => threshold}},
            "condition" => "selection"
          }
        }

        expected = value >= threshold
        assert Sigma.matches?(event, rule) == expected
      end
    end

    @tag timeout: 120_000
    property "lt modifier enforces less than" do
      check all(
              field <- field_name_generator(),
              threshold <- integer(1..1000),
              value <- integer(1..1000),
              max_runs: 100
            ) do
        event = %{
          "event_type" => "process_create",
          "payload" => %{field => value}
        }

        rule = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection" => %{field => %{"lt" => threshold}},
            "condition" => "selection"
          }
        }

        expected = value < threshold
        assert Sigma.matches?(event, rule) == expected
      end
    end

    @tag timeout: 120_000
    property "lte modifier enforces less than or equal" do
      check all(
              field <- field_name_generator(),
              threshold <- integer(1..1000),
              value <- integer(1..1000),
              max_runs: 100
            ) do
        event = %{
          "event_type" => "process_create",
          "payload" => %{field => value}
        }

        rule = %{
          "logsource" => %{"category" => "process_creation"},
          "detection" => %{
            "selection" => %{field => %{"lte" => threshold}},
            "condition" => "selection"
          }
        }

        expected = value <= threshold
        assert Sigma.matches?(event, rule) == expected
      end
    end
  end

  # Generators
  defp sigma_rule_generator do
    gen all(
          title <- string(:alphanumeric, min_length: 1, max_length: 50),
          severity <- member_of(["low", "medium", "high", "critical"]),
          category <- member_of(["process_creation", "network_connection", "file_event"]),
          field <- field_name_generator(),
          value <- one_of([string_value_generator(), integer(1..1000)]),
          max_tries: 10
        ) do
      %{
        "title" => title,
        "level" => severity,
        "logsource" => %{"category" => category},
        "detection" => %{
          "selection" => %{field => value},
          "condition" => "selection"
        }
      }
    end
  end

  defp field_name_generator do
    one_of([
      constant("CommandLine"),
      constant("Image"),
      constant("ParentImage"),
      constant("User"),
      constant("ProcessId"),
      constant("ParentProcessId"),
      constant("DestinationIp"),
      constant("DestinationPort"),
      constant("TargetFilename"),
      constant("QueryName"),
      string(:alphanumeric, min_length: 1, max_length: 20)
    ])
  end

  defp string_value_generator do
    one_of([
      string(:alphanumeric, min_length: 1, max_length: 30),
      constant("cmd.exe"),
      constant("powershell.exe"),
      constant("C:\\Windows\\System32\\"),
      constant("/bin/bash"),
      constant("192.168.1.1"),
      constant("SYSTEM"),
      constant("malicious.com")
    ])
  end

  defp event_generator do
    gen all(
          event_type <- event_type_generator(),
          payload <- payload_generator(),
          agent_id <- uuid_generator(),
          max_tries: 10
        ) do
      %{
        "event_type" => event_type,
        "payload" => payload,
        "agent_id" => agent_id,
        "timestamp" => DateTime.utc_now()
      }
    end
  end

  defp event_type_generator do
    one_of([
      constant("process_create"),
      constant("process_terminate"),
      constant("network_connect"),
      constant("dns_query"),
      constant("file_create"),
      constant("file_modify"),
      constant("registry_create")
    ])
  end

  defp payload_generator do
    gen all(
          cmdline <- string_value_generator(),
          image <- string_value_generator(),
          user <- string_value_generator(),
          pid <- integer(1..65535),
          ppid <- integer(1..65535),
          max_tries: 10
        ) do
      %{
        "CommandLine" => cmdline,
        "cmdline" => cmdline,
        "Image" => image,
        "path" => image,
        "User" => user,
        "user" => user,
        "ProcessId" => pid,
        "pid" => pid,
        "ParentProcessId" => ppid,
        "ppid" => ppid
      }
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
end
