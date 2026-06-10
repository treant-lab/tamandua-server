defmodule TamanduaServer.Detection.DSL.ParserTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.DSL.Parser

  describe "parse/1" do
    test "parses simple detection" do
      source = """
      detection test_detection {
        name: "Test Detection"
        description: "A test"
        severity: high
      }
      """

      assert {:ok, ast} = Parser.parse(source)
      assert ast.type == :detection
      assert ast.name == "test_detection"
      assert ast.metadata["name"] == "Test Detection"
      assert ast.metadata["severity"] == "high"
    end

    test "parses detection with sequence" do
      source = """
      detection lateral_movement {
        name: "Lateral Movement"
        severity: high

        sequence within 5m {
          event e1: process_create {
            where: process.name = "psexec.exe"
            capture: src_host
          }

          event e2: network_connect {
            where: dst_port = 445
            capture: dst_host
          }
        }
      }
      """

      assert {:ok, ast} = Parser.parse(source)
      assert ast.sequence != nil
      assert ast.sequence.temporal_constraint == 300
      assert length(ast.sequence.events) == 2

      [e1, e2] = ast.sequence.events
      assert e1.id == "e1"
      assert e1.event_type == "process_create"
      assert e1.captures == ["src_host"]
      assert e2.id == "e2"
      assert e2.event_type == "network_connect"
    end

    test "parses where clause with AND/OR" do
      source = """
      detection test {
        name: "Test"
        severity: high

        sequence within 1m {
          event e1: process_create {
            where: process.name = "cmd.exe" AND (is_elevated = true OR user = "admin")
            capture: pid
          }
        }
      }
      """

      assert {:ok, ast} = Parser.parse(source)
      [event] = ast.sequence.events
      assert event.where.type == :and
    end

    test "parses aggregation block" do
      source = """
      detection test {
        name: "Test"
        severity: high

        aggregation {
          count(*) > 10 within 1h -> escalate to critical
          count(distinct target_host) > 3 within 30m -> create_alert "Multiple targets"
        }
      }
      """

      assert {:ok, ast} = Parser.parse(source)
      assert length(ast.aggregation) == 2

      [rule1, rule2] = ast.aggregation
      assert rule1.function == "count"
      assert rule1.operator == ">"
      assert rule1.threshold == 10
      assert rule1.temporal_constraint == 3600
      assert rule1.action.type == :escalate

      assert rule2.field.distinct == true
    end

    test "parses field references" do
      source = """
      detection test {
        name: "Test"
        severity: high

        sequence within 1m {
          event e1: process_create {
            where: process.name = "test.exe"
            capture: src_host
          }

          event e2: network_connect {
            where: src_host = e1.src_host
          }
        }
      }
      """

      assert {:ok, ast} = Parser.parse(source)
      [_e1, e2] = ast.sequence.events
      assert e2.where.left.parts == ["src_host"]
      assert e2.where.right.parts == ["e1", "src_host"]
    end

    test "parses operators" do
      source = """
      detection test {
        name: "Test"
        severity: high

        sequence within 1m {
          event e1: process_create {
            where: count > 10 AND name contains "evil" AND path startswith "C:\\"
          }
        }
      }
      """

      assert {:ok, ast} = Parser.parse(source)
      [event] = ast.sequence.events
      assert event.where.type == :and
    end

    test "parses metadata arrays" do
      source = """
      detection test {
        name: "Test"
        severity: high
        mitre: ["T1234", "T5678"]
        tags: ["apt", "lateral"]
      }
      """

      assert {:ok, ast} = Parser.parse(source)
      assert ast.metadata["mitre"] == ["T1234", "T5678"]
      assert ast.metadata["tags"] == ["apt", "lateral"]
    end

    test "returns error for invalid syntax" do
      source = """
      detection invalid {
        name: "Invalid"
        severity: high

        sequence {
          # Missing event type
          event e1 {
            where: x = 1
          }
        }
      }
      """

      assert {:error, _reason} = Parser.parse(source)
    end
  end
end
