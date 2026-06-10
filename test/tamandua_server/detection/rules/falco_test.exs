defmodule TamanduaServer.Detection.Rules.FalcoTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.Rules.Falco

  describe "parse_string/1" do
    test "parses list definition" do
      yaml = """
      - list: shells
        items: [/bin/bash, /bin/sh]
      """

      assert {:ok, []} = Falco.parse_string(yaml)
      # Lists are consumed during macro/rule expansion
    end

    test "parses macro definition" do
      yaml = """
      - macro: spawned_process
        condition: evt.type = execve
      """

      assert {:ok, []} = Falco.parse_string(yaml)
      # Macros are consumed during rule expansion
    end

    test "parses simple rule with macro expansion" do
      yaml = """
      - macro: spawned_process
        condition: evt.type = execve
      - rule: shell_spawned
        desc: Shell process started
        condition: spawned_process
        output: "Shell: %proc.name"
        priority: WARNING
        tags: [shell]
      """

      assert {:ok, [rule]} = Falco.parse_string(yaml)
      assert rule.name == "shell_spawned"
      assert rule.description == "Shell process started"
      assert rule.condition =~ "evt.type = execve"
      assert rule.priority == :medium
      assert rule.tags == ["shell"]
    end

    test "detects circular macro reference" do
      yaml = """
      - macro: macro_a
        condition: macro_b and field = value
      - macro: macro_b
        condition: macro_a and other = thing
      """

      assert {:error, {:circular_dependency, _}} = Falco.parse_string(yaml)
    end

    test "expands nested macros" do
      yaml = """
      - macro: base_check
        condition: evt.type = execve
      - macro: container_check
        condition: base_check and container.id != host
      - rule: nested_rule
        desc: Test nested macros
        condition: container_check
        output: "Alert"
        priority: INFO
        tags: []
      """

      assert {:ok, [rule]} = Falco.parse_string(yaml)
      # Should have both conditions expanded
      assert rule.condition =~ "evt.type = execve"
      assert rule.condition =~ "container.id != host"
    end

    test "expands lists in conditions" do
      yaml = """
      - list: shell_binaries
        items: [bash, sh, zsh]
      - rule: shell_in_list
        desc: Shell from list
        condition: proc.name in (shell_binaries)
        output: "Shell detected"
        priority: NOTICE
        tags: []
      """

      assert {:ok, [rule]} = Falco.parse_string(yaml)
      # List should be expanded to items
      assert rule.condition =~ "bash"
      assert rule.condition =~ "sh"
      assert rule.condition =~ "zsh"
    end
  end

  describe "parse_file/1" do
    test "reads file and parses rules" do
      # Would need a fixture file
      # For now, test error case
      assert {:error, _} = Falco.parse_file("/nonexistent/file.yaml")
    end
  end

  describe "priority mapping" do
    test "maps Falco priorities to Sigma levels" do
      yaml = """
      - rule: critical_rule
        desc: Critical
        condition: field = value
        output: "Alert"
        priority: CRITICAL
        tags: []
      """

      assert {:ok, [rule]} = Falco.parse_string(yaml)
      assert rule.priority == :critical
    end

    test "maps WARNING to medium" do
      yaml = """
      - rule: warning_rule
        desc: Warning
        condition: field = value
        output: "Alert"
        priority: WARNING
        tags: []
      """

      assert {:ok, [rule]} = Falco.parse_string(yaml)
      assert rule.priority == :medium
    end
  end

  describe "tag normalization" do
    test "normalizes tags to lowercase with dashes" do
      yaml = """
      - rule: tagged_rule
        desc: Tagged
        condition: field = value
        output: "Alert"
        priority: INFO
        tags: [MITRE_T1611, Container_Escape]
      """

      assert {:ok, [rule]} = Falco.parse_string(yaml)
      assert "mitre-t1611" in rule.tags
      assert "container-escape" in rule.tags
    end
  end
end
