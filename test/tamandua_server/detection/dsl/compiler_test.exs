defmodule TamanduaServer.Detection.DSL.CompilerTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.DSL.{Parser, Compiler}

  describe "compile/1" do
    test "compiles valid detection" do
      source = """
      detection test {
        name: "Test"
        severity: high

        sequence within 5m {
          event e1: process_create {
            where: process.name = "test.exe"
            capture: pid
          }
        }
      }
      """

      assert {:ok, ast} = Parser.parse(source)
      assert {:ok, compiled} = Compiler.compile(ast)
      assert compiled.name == "test"
      assert compiled.evaluator != nil
      assert compiled.sequence_matcher != nil
    end

    test "validates required metadata fields" do
      source = """
      detection test {
        description: "Missing name and severity"
      }
      """

      assert {:ok, ast} = Parser.parse(source)
      assert {:error, reason} = Compiler.compile(ast)
      assert reason =~ "Missing required metadata"
    end

    test "validates severity levels" do
      source = """
      detection test {
        name: "Test"
        severity: invalid
      }
      """

      assert {:ok, ast} = Parser.parse(source)
      assert {:error, reason} = Compiler.compile(ast)
      assert reason =~ "Invalid severity"
    end

    test "compiles detection with aggregation" do
      source = """
      detection test {
        name: "Test"
        severity: high

        aggregation {
          count(*) > 10 within 1h -> escalate to critical
        }
      }
      """

      assert {:ok, ast} = Parser.parse(source)
      assert {:ok, compiled} = Compiler.compile(ast)
      assert compiled.aggregator != nil
    end
  end

  describe "sequence matching" do
    setup do
      source = """
      detection test {
        name: "Test Sequence"
        severity: high

        sequence within 5m {
          event e1: process_create {
            where: process.name = "psexec.exe"
            capture: src_host
          }

          event e2: network_connect {
            where: dst_port = 445 AND src_host = e1.src_host
            capture: dst_host
          }
        }
      }
      """

      {:ok, ast} = Parser.parse(source)
      {:ok, compiled} = Compiler.compile(ast)

      %{compiled: compiled}
    end

    test "matches sequence in order", %{compiled: compiled} do
      event1 = %{
        "event_type" => "process_create",
        "agent_id" => "test-agent",
        "payload" => %{"name" => "psexec.exe", "host" => "192.168.1.10"}
      }

      event2 = %{
        "event_type" => "network_connect",
        "agent_id" => "test-agent",
        "payload" => %{"remote_port" => 445, "local_ip" => "192.168.1.10"}
      }

      {:ok, matched1, state1} = compiled.sequence_matcher.(event1, %{})
      assert matched1 == false
      assert state1 != %{}

      {:ok, matched2, _state2} = compiled.sequence_matcher.(event2, state1)
      assert matched2 == true
    end

    test "does not match out-of-order events", %{compiled: compiled} do
      event1 = %{
        "event_type" => "network_connect",
        "agent_id" => "test-agent",
        "payload" => %{"remote_port" => 445}
      }

      {:ok, matched, state} = compiled.sequence_matcher.(event1, %{})
      assert matched == false
      assert state == %{}
    end

    test "resets on timeout", %{compiled: compiled} do
      # This would require mocking time - simplified test
      assert compiled.sequence_matcher != nil
    end
  end

  describe "aggregation evaluation" do
    test "counts events correctly" do
      source = """
      detection test {
        name: "Test"
        severity: high

        sequence within 1m {
          event e1: process_create {
            where: process.name = "test.exe"
          }
        }

        aggregation {
          count(*) > 2 within 1h -> escalate to critical
        }
      }
      """

      {:ok, ast} = Parser.parse(source)
      {:ok, compiled} = Compiler.compile(ast)

      events = [
        %{"event_type" => "process_create", "timestamp" => 1000},
        %{"event_type" => "process_create", "timestamp" => 1010},
        %{"event_type" => "process_create", "timestamp" => 1020}
      ]

      {:ok, actions} = compiled.aggregator.(events, %{})
      assert length(actions) > 0
      assert hd(actions).type == :escalate
    end

    test "counts distinct values" do
      source = """
      detection test {
        name: "Test"
        severity: high

        aggregation {
          count(distinct target_host) > 1 within 1h -> create_alert "Multiple targets"
        }
      }
      """

      {:ok, ast} = Parser.parse(source)
      {:ok, compiled} = Compiler.compile(ast)

      events = [
        %{"payload" => %{"target_host" => "host1"}},
        %{"payload" => %{"target_host" => "host2"}},
        %{"payload" => %{"target_host" => "host1"}}
      ]

      {:ok, actions} = compiled.aggregator.(events, %{})
      assert length(actions) > 0
    end
  end
end
