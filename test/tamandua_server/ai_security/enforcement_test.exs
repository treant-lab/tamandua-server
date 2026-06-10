defmodule TamanduaServer.AISecurity.EnforcementTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.AISecurity.Enforcement

  test "plans domain block only when policy is block and enforced" do
    event = %{
      agent_id: "agent-1",
      provider: "openai",
      domain: "ChatGPT.com.",
      policy_id: "policy-1",
      policy_decision: "block",
      policy_enforced: true,
      policy_reasons: ["blocked_provider"],
      trace_id: "trace-1"
    }

    assert {:block_domain, "chatgpt.com", payload} = Enforcement.plan_action(event)
    assert payload["domain"] == "chatgpt.com"
    assert payload["source"] == "ai_gateway"
    assert payload["reason"] == "ai_gateway_policy_block:blocked_provider"
    assert payload["direction"] == "outbound"
    refute Map.has_key?(payload, "ip")
  end

  test "does not block when policy is only decision mode" do
    event = %{
      agent_id: "agent-1",
      domain: "chatgpt.com",
      policy_decision: "block",
      policy_enforced: false
    }

    assert {:skip, :not_enforced, _} = Enforcement.plan_action(event)
  end

  test "falls back to public IP only when no safe domain is available" do
    event = %{
      agent_id: "agent-1",
      domain: nil,
      policy_decision: "block",
      policy_enforced: true,
      metadata: %{"remote_ip" => "203.0.113.44"}
    }

    assert {:block_ip, "203.0.113.44", payload} = Enforcement.plan_action(event)
    assert payload["ip"] == "203.0.113.44"
    assert payload["direction"] == "outbound"
  end

  test "does not block private or local inference targets" do
    private_ip_event = %{
      agent_id: "agent-1",
      policy_decision: "block",
      policy_enforced: true,
      metadata: %{"remote_ip" => "192.168.1.20"}
    }

    local_inference_event = %{
      agent_id: "agent-1",
      domain: "127.0.0.1:11434",
      classification: "local_inference",
      policy_decision: "block",
      policy_enforced: true
    }

    assert {:skip, :missing_target, _} = Enforcement.plan_action(private_ip_event)
    assert {:skip, :local_inference, _} = Enforcement.plan_action(local_inference_event)
  end

  test "queues a command through injectable sender and deduplicates repeated events" do
    test_pid = self()

    sender = fn agent_id, command_type, payload ->
      send(test_pid, {:queued, agent_id, command_type, payload})
      {:ok, %{id: "cmd-1"}}
    end

    event = %{
      agent_id: "agent-1",
      domain: "api.openai.com",
      policy_decision: "block",
      policy_enforced: true
    }

    assert {:ok, %{action: "block_domain", target: "api.openai.com"}} =
             Enforcement.enforce_event(event, command_sender: sender, now_ms: 1_000)

    assert_received {:queued, "agent-1", "block_domain", %{"domain" => "api.openai.com"}}

    assert {:skipped, :duplicate, _} =
             Enforcement.enforce_event(event, command_sender: sender, now_ms: 1_001)
  end
end
