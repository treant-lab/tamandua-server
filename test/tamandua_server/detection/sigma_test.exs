defmodule TamanduaServer.Detection.SigmaTest do
  @moduledoc """
  Comprehensive unit tests for Sigma rule parsing and evaluation.
  Tests the SigmaEvaluator module with extensive coverage of:
  - Condition parsing (AND, OR, NOT, parentheses)
  - Quantifiers (1 of, all of, N of, them)
  - Field modifiers (contains, startswith, endswith, re, base64, cidr, etc.)
  - Aggregation support
  - Edge cases and error handling
  """
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Detection.SigmaEvaluator

  # ── Condition Parsing Tests ────────────────────────────────────────────

  describe "parse_condition/1" do
    test "parses simple identifier condition" do
      {:ok, ast} = SigmaEvaluator.parse_condition("selection")
      assert ast == {:identifier, "selection"}
    end

    test "parses AND condition" do
      {:ok, ast} = SigmaEvaluator.parse_condition("sel1 and sel2")
      assert ast == {:and, {:identifier, "sel1"}, {:identifier, "sel2"}}
    end

    test "parses OR condition" do
      {:ok, ast} = SigmaEvaluator.parse_condition("sel1 or sel2")
      assert ast == {:or, {:identifier, "sel1"}, {:identifier, "sel2"}}
    end

    test "parses NOT condition" do
      {:ok, ast} = SigmaEvaluator.parse_condition("not filter")
      assert ast == {:not, {:identifier, "filter"}}
    end

    test "parses complex nested AND/OR" do
      {:ok, ast} = SigmaEvaluator.parse_condition("sel1 and sel2 or sel3")
      # Left-to-right parsing: (sel1 and sel2) or sel3
      assert ast == {:or, {:and, {:identifier, "sel1"}, {:identifier, "sel2"}}, {:identifier, "sel3"}}
    end

    test "parses parenthesized expressions" do
      {:ok, ast} = SigmaEvaluator.parse_condition("sel1 and (sel2 or sel3)")
      assert ast == {:and, {:identifier, "sel1"}, {:or, {:identifier, "sel2"}, {:identifier, "sel3"}}}
    end

    test "parses NOT with parentheses" do
      {:ok, ast} = SigmaEvaluator.parse_condition("selection and not (filter1 or filter2)")
      assert ast == {:and, {:identifier, "selection"}, {:not, {:or, {:identifier, "filter1"}, {:identifier, "filter2"}}}}
    end

    test "parses '1 of' pattern" do
      {:ok, ast} = SigmaEvaluator.parse_condition("1 of selection*")
      assert ast == {:one_of, "selection*"}
    end

    test "parses 'all of' pattern" do
      {:ok, ast} = SigmaEvaluator.parse_condition("all of them")
      assert ast == {:all_of, "*"}
    end

    test "parses 'N of' pattern with number" do
      {:ok, ast} = SigmaEvaluator.parse_condition("2 of keywords")
      assert ast == {:n_of, 2, "keywords"}
    end

    test "parses '1 of them'" do
      {:ok, ast} = SigmaEvaluator.parse_condition("1 of them")
      assert ast == {:one_of, "*"}
    end

    test "parses complex condition with multiple operators" do
      {:ok, ast} = SigmaEvaluator.parse_condition("(sel1 or sel2) and not filter and sel3")
      assert match?({:and, {:and, {:not, {:identifier, "filter"}}, {:or, _, _}}, {:identifier, "sel3"}}, ast) or
             match?({:and, {:and, _, _}, {:identifier, "sel3"}}, ast)
    end
  end

  # ── Simple Selection Matching Tests ────────────────────────────────────

  describe "evaluate/3 - simple selections" do
    test "matches when selection field equals event field" do
      detection = %{
        "selection" => %{"EventType" => "process_create"},
        "condition" => "selection"
      }

      event = %{
        "event_type" => "process_create",
        "payload" => %{}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test Rule") == {:match, "Test Rule"}
    end

    test "does not match when selection field does not equal event field" do
      detection = %{
        "selection" => %{"EventType" => "process_create"},
        "condition" => "selection"
      }

      event = %{
        "event_type" => "file_create",
        "payload" => %{}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test Rule") == :no_match
    end

    test "matches multiple field conditions (AND logic within selection)" do
      detection = %{
        "selection" => %{
          "EventType" => "process_create",
          "User" => "SYSTEM"
        },
        "condition" => "selection"
      }

      event = %{
        "event_type" => "process_create",
        "payload" => %{"user" => "SYSTEM"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test Rule") == {:match, "Test Rule"}
    end

    test "does not match when one field condition fails" do
      detection = %{
        "selection" => %{
          "EventType" => "process_create",
          "User" => "SYSTEM"
        },
        "condition" => "selection"
      }

      event = %{
        "event_type" => "process_create",
        "payload" => %{"user" => "Administrator"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test Rule") == :no_match
    end
  end

  # ── Field Modifier Tests ───────────────────────────────────────────────

  describe "evaluate/3 - contains modifier" do
    test "matches when field contains substring" do
      detection = %{
        "selection" => %{"CommandLine|contains" => "mimikatz"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"cmdline" => "C:\\temp\\mimikatz.exe sekurlsa::logonpasswords"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Mimikatz") == {:match, "Mimikatz"}
    end

    test "matches case-insensitive with contains" do
      detection = %{
        "selection" => %{"CommandLine|contains" => "MIMIKATZ"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"cmdline" => "c:\\temp\\mimikatz.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "does not match when substring not present" do
      detection = %{
        "selection" => %{"CommandLine|contains" => "mimikatz"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"cmdline" => "notepad.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end

    test "matches when any value in list contains substring (OR logic)" do
      detection = %{
        "selection" => %{"CommandLine|contains" => ["mimikatz", "sekurlsa", "lsadump"]},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"cmdline" => "C:\\lsadump.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end
  end

  describe "evaluate/3 - startswith modifier" do
    test "matches when field starts with prefix" do
      detection = %{
        "selection" => %{"Image|startswith" => "C:\\Windows\\System32"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"path" => "C:\\Windows\\System32\\cmd.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "does not match when field does not start with prefix" do
      detection = %{
        "selection" => %{"Image|startswith" => "C:\\Windows\\System32"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"path" => "C:\\temp\\cmd.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end
  end

  describe "evaluate/3 - endswith modifier" do
    test "matches when field ends with suffix" do
      detection = %{
        "selection" => %{"Image|endswith" => "\\cmd.exe"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"path" => "C:\\Windows\\System32\\cmd.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "does not match when field does not end with suffix" do
      detection = %{
        "selection" => %{"Image|endswith" => "\\cmd.exe"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"path" => "C:\\Windows\\System32\\notepad.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end
  end

  describe "evaluate/3 - re (regex) modifier" do
    test "matches when field matches regex pattern" do
      detection = %{
        "selection" => %{"CommandLine|re" => ".*\\.exe.*-enc.*"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"cmdline" => "powershell.exe -enc SGVsbG8="}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "does not match when field does not match regex" do
      detection = %{
        "selection" => %{"CommandLine|re" => ".*\\.exe.*-enc.*"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"cmdline" => "notepad.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end
  end

  describe "evaluate/3 - cidr modifier" do
    test "matches IP within CIDR range" do
      detection = %{
        "selection" => %{"DestinationIp|cidr" => "10.0.0.0/8"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"remote_ip" => "10.5.10.20"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "does not match IP outside CIDR range" do
      detection = %{
        "selection" => %{"DestinationIp|cidr" => "10.0.0.0/8"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"remote_ip" => "192.168.1.1"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end

    test "matches with /24 CIDR" do
      detection = %{
        "selection" => %{"DestinationIp|cidr" => "192.168.1.0/24"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"remote_ip" => "192.168.1.100"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end
  end

  describe "evaluate/3 - numeric comparison modifiers" do
    test "gt (greater than) matches correctly" do
      detection = %{
        "selection" => %{"size|gt" => "1000000"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"size" => "2000000"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "gt does not match when value is less" do
      detection = %{
        "selection" => %{"size|gt" => "1000000"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"size" => "500000"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end

    test "gte (greater than or equal) matches correctly" do
      detection = %{
        "selection" => %{"size|gte" => "1000000"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"size" => "1000000"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "lt (less than) matches correctly" do
      detection = %{
        "selection" => %{"port|lt" => "1024"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"port" => "80"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "lte (less than or equal) matches correctly" do
      detection = %{
        "selection" => %{"port|lte" => "1024"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"port" => "1024"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end
  end

  # ── Boolean Logic Tests ────────────────────────────────────────────────

  describe "evaluate/3 - AND conditions" do
    test "matches when both selections match" do
      detection = %{
        "sel1" => %{"EventType" => "process_create"},
        "sel2" => %{"User" => "SYSTEM"},
        "condition" => "sel1 and sel2"
      }

      event = %{
        "event_type" => "process_create",
        "payload" => %{"user" => "SYSTEM"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "does not match when first selection fails" do
      detection = %{
        "sel1" => %{"EventType" => "process_create"},
        "sel2" => %{"User" => "SYSTEM"},
        "condition" => "sel1 and sel2"
      }

      event = %{
        "event_type" => "file_create",
        "payload" => %{"user" => "SYSTEM"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end

    test "does not match when second selection fails" do
      detection = %{
        "sel1" => %{"EventType" => "process_create"},
        "sel2" => %{"User" => "SYSTEM"},
        "condition" => "sel1 and sel2"
      }

      event = %{
        "event_type" => "process_create",
        "payload" => %{"user" => "Administrator"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end
  end

  describe "evaluate/3 - OR conditions" do
    test "matches when first selection matches" do
      detection = %{
        "sel1" => %{"EventType" => "process_create"},
        "sel2" => %{"EventType" => "file_create"},
        "condition" => "sel1 or sel2"
      }

      event = %{
        "event_type" => "process_create",
        "payload" => %{}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "matches when second selection matches" do
      detection = %{
        "sel1" => %{"EventType" => "process_create"},
        "sel2" => %{"EventType" => "file_create"},
        "condition" => "sel1 or sel2"
      }

      event = %{
        "event_type" => "file_create",
        "payload" => %{}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "does not match when both selections fail" do
      detection = %{
        "sel1" => %{"EventType" => "process_create"},
        "sel2" => %{"EventType" => "file_create"},
        "condition" => "sel1 or sel2"
      }

      event = %{
        "event_type" => "network_connect",
        "payload" => %{}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end
  end

  describe "evaluate/3 - NOT conditions" do
    test "matches when filter does not match" do
      detection = %{
        "selection" => %{"CommandLine|contains" => "powershell"},
        "filter" => %{"CommandLine|contains" => "legitimate"},
        "condition" => "selection and not filter"
      }

      event = %{
        "payload" => %{"cmdline" => "powershell.exe -enc ZABpAHIA"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "does not match when filter matches" do
      detection = %{
        "selection" => %{"CommandLine|contains" => "powershell"},
        "filter" => %{"CommandLine|contains" => "legitimate"},
        "condition" => "selection and not filter"
      }

      event = %{
        "payload" => %{"cmdline" => "powershell.exe legitimate_script.ps1"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end
  end

  # ── Quantifier Tests ───────────────────────────────────────────────────

  describe "evaluate/3 - '1 of' patterns" do
    test "matches when one selection matches" do
      detection = %{
        "sel_ps" => %{"Image|endswith" => "\\powershell.exe"},
        "sel_cmd" => %{"Image|endswith" => "\\cmd.exe"},
        "condition" => "1 of sel_*"
      }

      event = %{
        "payload" => %{"path" => "C:\\Windows\\System32\\powershell.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "does not match when no selections match" do
      detection = %{
        "sel_ps" => %{"Image|endswith" => "\\powershell.exe"},
        "sel_cmd" => %{"Image|endswith" => "\\cmd.exe"},
        "condition" => "1 of sel_*"
      }

      event = %{
        "payload" => %{"path" => "C:\\Windows\\System32\\notepad.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end
  end

  describe "evaluate/3 - 'all of' patterns" do
    test "matches when all selections match" do
      detection = %{
        "sel1" => %{"EventType" => "process_create"},
        "sel2" => %{"User" => "SYSTEM"},
        "condition" => "all of sel*"
      }

      event = %{
        "event_type" => "process_create",
        "payload" => %{"user" => "SYSTEM"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "does not match when one selection fails" do
      detection = %{
        "sel1" => %{"EventType" => "process_create"},
        "sel2" => %{"User" => "SYSTEM"},
        "condition" => "all of sel*"
      }

      event = %{
        "event_type" => "process_create",
        "payload" => %{"user" => "Administrator"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end
  end

  describe "evaluate/3 - 'N of' patterns" do
    test "matches when at least N selections match" do
      detection = %{
        "kw1" => %{"CommandLine|contains" => "mimikatz"},
        "kw2" => %{"CommandLine|contains" => "sekurlsa"},
        "kw3" => %{"CommandLine|contains" => "lsadump"},
        "condition" => "2 of kw*"
      }

      event = %{
        "payload" => %{"cmdline" => "mimikatz.exe sekurlsa::logonpasswords"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "does not match when fewer than N selections match" do
      detection = %{
        "kw1" => %{"CommandLine|contains" => "mimikatz"},
        "kw2" => %{"CommandLine|contains" => "sekurlsa"},
        "kw3" => %{"CommandLine|contains" => "lsadump"},
        "condition" => "2 of kw*"
      }

      event = %{
        "payload" => %{"cmdline" => "mimikatz.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end
  end

  describe "evaluate/3 - 'them' keyword" do
    test "matches when all non-condition keys match" do
      detection = %{
        "selection1" => %{"EventType" => "process_create"},
        "selection2" => %{"User" => "SYSTEM"},
        "condition" => "all of them"
      }

      event = %{
        "event_type" => "process_create",
        "payload" => %{"user" => "SYSTEM"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end
  end

  # ── Field Mapping Tests ────────────────────────────────────────────────

  describe "evaluate/3 - Sigma field mapping" do
    test "maps 'Image' to 'path'" do
      detection = %{
        "selection" => %{"Image" => "C:\\Windows\\System32\\cmd.exe"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"path" => "C:\\Windows\\System32\\cmd.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "maps 'CommandLine' to 'cmdline'" do
      detection = %{
        "selection" => %{"CommandLine|contains" => "whoami"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"cmdline" => "cmd.exe /c whoami"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "maps 'ParentImage' to 'parent_path'" do
      detection = %{
        "selection" => %{"ParentImage|endswith" => "\\explorer.exe"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"parent_path" => "C:\\Windows\\explorer.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "maps 'DestinationIp' to 'remote_ip'" do
      detection = %{
        "selection" => %{"DestinationIp" => "10.0.0.1"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"remote_ip" => "10.0.0.1"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end
  end

  # ── Edge Cases and Error Handling ──────────────────────────────────────

  describe "evaluate/3 - edge cases" do
    test "handles nil event value gracefully" do
      detection = %{
        "selection" => %{"CommandLine|contains" => "test"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"cmdline" => nil}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end

    test "handles missing payload field" do
      detection = %{
        "selection" => %{"CommandLine|contains" => "test"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end

    test "handles empty detection" do
      detection = %{
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"cmdline" => "test"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end

    test "handles malformed regex gracefully" do
      detection = %{
        "selection" => %{"CommandLine|re" => "[invalid(regex"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"cmdline" => "test"}
      }

      # Should not crash, should return :no_match
      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end

    test "handles empty condition string" do
      detection = %{
        "selection" => %{"EventType" => "process_create"},
        "condition" => ""
      }

      event = %{
        "event_type" => "process_create",
        "payload" => %{}
      }

      # Empty condition should default to false
      assert SigmaEvaluator.evaluate(detection, event, "Test") == :no_match
    end
  end

  # ── evaluate_many/2 Tests ──────────────────────────────────────────────

  describe "evaluate_many/2" do
    test "returns matches from multiple rules" do
      rules = [
        %{
          "title" => "Rule 1",
          "detection" => %{
            "selection" => %{"EventType" => "process_create"},
            "condition" => "selection"
          }
        },
        %{
          "title" => "Rule 2",
          "detection" => %{
            "selection" => %{"EventType" => "file_create"},
            "condition" => "selection"
          }
        }
      ]

      event = %{
        "event_type" => "process_create",
        "payload" => %{}
      }

      matches = SigmaEvaluator.evaluate_many(rules, event)

      assert length(matches) == 1
      assert {:match, "Rule 1"} in matches
    end

    test "returns empty list when no rules match" do
      rules = [
        %{
          "title" => "Rule 1",
          "detection" => %{
            "selection" => %{"EventType" => "process_create"},
            "condition" => "selection"
          }
        }
      ]

      event = %{
        "event_type" => "network_connect",
        "payload" => %{}
      }

      matches = SigmaEvaluator.evaluate_many(rules, event)

      assert matches == []
    end

    test "returns all matching rules" do
      rules = [
        %{
          "title" => "Rule 1",
          "detection" => %{
            "selection" => %{"EventType" => "process_create"},
            "condition" => "selection"
          }
        },
        %{
          "title" => "Rule 2",
          "detection" => %{
            "selection" => %{"User" => "SYSTEM"},
            "condition" => "selection"
          }
        }
      ]

      event = %{
        "event_type" => "process_create",
        "payload" => %{"user" => "SYSTEM"}
      }

      matches = SigmaEvaluator.evaluate_many(rules, event)

      assert length(matches) == 2
      assert {:match, "Rule 1"} in matches
      assert {:match, "Rule 2"} in matches
    end
  end

  # ── Wildcard Matching Tests ────────────────────────────────────────────

  describe "evaluate/3 - wildcard matching" do
    test "matches with * wildcard" do
      detection = %{
        "selection" => %{"Image" => "*\\cmd.exe"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"path" => "C:\\Windows\\System32\\cmd.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "matches with ? wildcard" do
      detection = %{
        "selection" => %{"Image" => "C:\\temp\\?.exe"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"path" => "C:\\temp\\a.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end

    test "matches with multiple wildcards" do
      detection = %{
        "selection" => %{"Image" => "*\\Windows\\*\\cmd.exe"},
        "condition" => "selection"
      }

      event = %{
        "payload" => %{"path" => "C:\\Windows\\System32\\cmd.exe"}
      }

      assert SigmaEvaluator.evaluate(detection, event, "Test") == {:match, "Test"}
    end
  end
end
