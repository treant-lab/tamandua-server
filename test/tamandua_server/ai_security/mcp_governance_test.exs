defmodule TamanduaServer.AISecurity.MCPGovernanceTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.AISecurity.MCPGovernance

  setup do
    unless Process.whereis(MCPGovernance) do
      start_supervised!(MCPGovernance)
    end

    {:ok, server_id} =
      MCPGovernance.register_server(%{
        name: "firewall-test-#{System.unique_integer([:positive])}",
        endpoint_url: "internal://mcp-firewall-test",
        tools: ["read_secret", "http_post", "run_shell_command", "query_data"],
        resources: ["vault://*", "public://*"]
      })

    on_exit(fn ->
      if Process.whereis(MCPGovernance), do: MCPGovernance.unregister_server(server_id)
    end)

    %{server_id: server_id}
  end

  test "requires approval for configured high-risk tool classes", %{server_id: server_id} do
    set_policy(server_id, %{
      high_risk_tool_classes: [:shell_execution],
      approval_required_classes: [:shell_execution]
    })

    assert {:error, {:approval_required, :shell_execution}} =
             MCPGovernance.authorize_tool_call(
               server_id,
               "run_shell_command",
               "analyst",
               %{}
             )

    assert :ok =
             MCPGovernance.authorize_tool_call(
               server_id,
               "run_shell_command",
               "analyst",
               %{approval_granted: true}
             )
  end

  test "registered policies expose firewall defaults", %{server_id: server_id} do
    assert {:ok, permissions} = MCPGovernance.get_permissions(server_id)
    assert permissions.high_risk_tool_classes == []
    assert permissions.sensitive_resource_patterns == []
    assert permissions.max_result_bytes == 10 * 1_024 * 1_024
    assert permissions.approval_required_classes == []

    assert permissions.tool_output_injection_scanning == %{
             enabled: true,
             scanner: :external,
             action: :block
           }
  end

  test "rejects unsupported risk classes explicitly", %{server_id: server_id} do
    assert {:error, {:unsupported_tool_classes, ["telepathy"]}} =
             MCPGovernance.set_permissions(server_id, %{
               high_risk_tool_classes: ["telepathy"]
             })
  end

  test "classifies sensitive resources and enforces resource policy", %{server_id: server_id} do
    set_policy(server_id, %{
      high_risk_tool_classes: [:sensitive_resource],
      sensitive_resource_patterns: ["vault://prod/*"]
    })

    assert {:error, {:high_risk_tool_class, :sensitive_resource}} =
             MCPGovernance.authorize_tool_call(server_id, "query_data", "analyst", %{
               resource_uri: "vault://prod/api-key"
             })

    assert :ok =
             MCPGovernance.authorize_tool_call(server_id, "query_data", "analyst", %{
               resource_uri: "public://detections/current"
             })
  end

  test "blocks a sensitive read followed by a network tool when context is available", %{
    server_id: server_id
  } do
    set_policy(server_id, %{sensitive_resource_patterns: ["vault://*"]})

    assert {:error, {:dangerous_tool_chain, :sensitive_read_to_network}} =
             MCPGovernance.authorize_tool_call(server_id, "http_post", "analyst", %{
               recent_tool_calls: [
                 %{tool_name: "read_secret", resource_uri: "vault://prod/api-key"}
               ]
             })
  end

  test "enforces estimated and actual result size and injection scan metadata", %{
    server_id: server_id
  } do
    set_policy(server_id, %{
      max_result_bytes: 10,
      tool_output_injection_scanning: %{enabled: true, action: :block, scanner: :external}
    })

    assert {:error, {:max_result_bytes_exceeded, 10}} =
             MCPGovernance.authorize_tool_call(server_id, "query_data", "analyst", %{
               expected_result_bytes: 11
             })

    assert {:error, :tool_output_scan_required} =
             MCPGovernance.authorize_tool_result(server_id, "query_data", 5)

    assert {:error, :tool_output_injection_detected} =
             MCPGovernance.authorize_tool_result(server_id, "query_data", 5, %{
               output_scan: %{scanner: "prompt-guard", injection_detected: true}
             })

    assert {:ok, %{output_scan: %{injection_detected: false}}} =
             MCPGovernance.authorize_tool_result(server_id, "query_data", 5, %{
               output_scan: %{scanner: "prompt-guard", injection_detected: false}
             })
  end

  test "audit records contain structural metadata but no prompt, body, secret, or result", %{
    server_id: server_id
  } do
    MCPGovernance.record_tool_call(%{
      server_id: server_id,
      tool_name: "query_data",
      caller_id: "analyst",
      params: %{
        "prompt" => "do not disclose this prompt",
        "body" => "private request body",
        "api_token" => "super-secret-token",
        "limit" => 10
      },
      result: "private tool result",
      result_status: :success,
      result_size_bytes: 19,
      output_scan: %{
        scanner: "prompt-guard",
        injection_detected: false,
        raw_content: "private tool result"
      }
    })

    Process.sleep(20)

    [entry | _] = MCPGovernance.get_audit_log(server_id: server_id)
    serialized = inspect(entry)

    assert entry.params_metadata.sensitive_field_count == 3
    assert entry.params_metadata.value_types == %{integer: 1, string: 3}
    assert entry.output_scan == %{scanner: :external, injection_detected: false}
    refute serialized =~ "do not disclose"
    refute serialized =~ "private request"
    refute serialized =~ "super-secret-token"
    refute serialized =~ "private tool result"
  end

  defp set_policy(server_id, overrides) do
    base = %{
      allowed_tools: ["read_secret", "http_post", "run_shell_command", "query_data"],
      blocked_tools: [],
      allowed_resources: ["vault://*", "public://*"],
      blocked_resources: [],
      max_calls_per_minute: 100,
      allowed_callers: []
    }

    assert :ok = MCPGovernance.set_permissions(server_id, Map.merge(base, overrides))
  end
end
