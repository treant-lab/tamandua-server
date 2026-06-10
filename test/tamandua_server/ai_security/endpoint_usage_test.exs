defmodule TamanduaServer.AISecurity.EndpointUsageTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.AISecurity.EndpointUsage

  test "builds metadata-only gateway event from agent AI DNS metadata" do
    event = %{
      "event_id" => "dns-1",
      "event_type" => "dns_query",
      "timestamp" => 1_768_000_000_000,
      "agent_id" => "agent-1",
      "organization_id" => "org-1",
      "payload" => %{
        "query" => "chatgpt.com",
        "pid" => 123,
        "process_name" => "chrome.exe",
        "responses" => ["104.18.32.47"]
      },
      "metadata" => %{
        "ai_usage" => "true",
        "ai_provider" => "openai",
        "ai_category" => "remote_ai_browser",
        "ai_confidence" => "95",
        "ai_signal" => "domain"
      }
    }

    assert {:ok, gateway} = EndpointUsage.build_gateway_event(event)
    assert gateway.id == "endpoint:dns-1"
    assert gateway.provider == "openai"
    assert gateway.domain == "chatgpt.com"
    assert gateway.access_method == "endpoint_dns"
    assert gateway.process_name == "chrome.exe"
    refute Map.has_key?(gateway, :prompt_capture)
    refute Map.has_key?(gateway, :prompt)
    refute Map.has_key?(gateway, :headers)
  end

  test "classifies AI domains server-side when older agents do not send AI metadata" do
    event = %{
      event_id: "net-1",
      event_type: :network_connect,
      timestamp: 1_768_000_000_000,
      agent_id: "agent-1",
      payload: %{
        "domain" => "api.anthropic.com",
        "remote_ip" => "160.79.104.10",
        "remote_port" => 443,
        "process_name" => "python",
        "bytes_sent" => 2048
      }
    }

    assert {:ok, gateway} = EndpointUsage.build_gateway_event(event)
    assert gateway.provider == "anthropic"
    assert gateway.classification == "remote_ai_api"
    assert gateway.access_method == "endpoint_network"
    assert gateway.bytes_sent == 2048
  end

  test "detects local inference ports without inspecting traffic content" do
    event = %{
      event_id: "local-ollama",
      event_type: "network_connect",
      payload: %{
        remote_ip: "127.0.0.1",
        remote_port: 11434,
        process_name: "ollama"
      }
    }

    assert {:ok, gateway} = EndpointUsage.build_gateway_event(event)
    assert gateway.provider == "ollama"
    assert gateway.classification == "local_inference"
    assert gateway.access_method == "endpoint_local_network"
    assert gateway.metadata["content_inspection"] == false
    assert gateway.metadata["prompt_capture"] == false
  end

  test "ignores unrelated domains" do
    event = %{
      event_id: "dns-2",
      event_type: "dns_query",
      payload: %{"query" => "example.com"}
    }

    assert :ignore = EndpointUsage.build_gateway_event(event)
  end
end
