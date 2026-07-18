defmodule TamanduaServer.AISecurity.ExfiltrationCorrelatorTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.AISecurity.ExfiltrationCorrelator

  @base_ms 1_800_000_000_000

  test "correlates cloud credential access with OpenRouter egress without retaining paths or payloads" do
    report =
      ExfiltrationCorrelator.correlate(%{
        sensitive_accesses: [
          %{
            id: "file-1",
            timestamp_ms: @base_ms,
            agent_id: "agent-7",
            operation: "read",
            file_path: "C:/Users/alice/.aws/credentials"
          }
        ],
        gateway_events: [
          %{
            id: "gateway-1",
            timestamp_ms: @base_ms + 2_000,
            agent_id: "agent-7",
            domain: "https://openrouter.ai/api/v1/chat",
            bytes_sent: 12_000,
            prompt: "this input must never appear"
          }
        ]
      })

    assert [%{type: "sensitive_resource_to_ai_egress"} = detection] = report.detections
    assert detection.risk_score == 95
    assert detection.metadata_only
    refute inspect(report) =~ ".aws/credentials"
    refute inspect(report) =~ "this input must never appear"
    assert Enum.any?(detection.evidence, &(&1[:resource_category] == "cloud_credentials"))
  end

  test "correlates sensitive access with an MCP HTTP tool but not an unrelated local tool" do
    report =
      ExfiltrationCorrelator.correlate(%{
        sensitive_accesses: [
          %{
            id: "resource-1",
            timestamp_ms: @base_ms,
            user_id: "alice",
            operation: "read",
            resource_type: "secrets"
          }
        ],
        mcp_tool_calls: [
          %{
            id: "mcp-1",
            timestamp_ms: @base_ms + 1_000,
            caller_id: "alice",
            tool_name: "http_post",
            params: %{body: "discard"}
          },
          %{
            id: "mcp-2",
            timestamp_ms: @base_ms + 2_000,
            caller_id: "alice",
            tool_name: "local_search"
          }
        ]
      })

    assert [%{type: "sensitive_resource_to_mcp_http"} = detection] = report.detections
    assert Enum.any?(detection.evidence, &(&1[:tool_name] == "http_post"))
    refute inspect(report) =~ "discard"
    refute inspect(report) =~ "local_search"
  end

  test "detects relative token spikes and absolute byte spikes" do
    gateway_events = [
      %{
        id: "g1",
        timestamp_ms: @base_ms,
        agent_id: "a1",
        domain: "api.openai.com",
        total_tokens: 1_000,
        bytes_sent: 1_000
      },
      %{
        id: "g2",
        timestamp_ms: @base_ms + 1_000,
        agent_id: "a1",
        domain: "api.openai.com",
        total_tokens: 1_200,
        bytes_sent: 1_000
      },
      %{
        id: "g3",
        timestamp_ms: @base_ms + 2_000,
        agent_id: "a1",
        domain: "api.openai.com",
        total_tokens: 8_000,
        bytes_sent: 6_000_000
      }
    ]

    report = ExfiltrationCorrelator.correlate(%{gateway_events: gateway_events})

    assert [%{type: "ai_usage_volume_spike"} = detection] = report.detections
    assert hd(detection.evidence).token_spike
    assert hd(detection.evidence).byte_spike
    assert detection.risk_score == 90
  end

  test "correlates DoH or proxy routing with AI upload metadata" do
    report =
      ExfiltrationCorrelator.correlate(%{
        network_events: [
          %{
            id: "dns-1",
            timestamp_ms: @base_ms,
            hostname: "workstation",
            user_id: "bob",
            channel: "doh"
          }
        ],
        gateway_events: [
          %{
            id: "ai-1",
            timestamp_ms: @base_ms + 10_000,
            hostname: "workstation",
            user_id: "bob",
            domain: "api.anthropic.com",
            bytes_sent: 42_000
          }
        ]
      })

    assert [%{type: "doh_or_proxy_with_ai_upload"} = detection] = report.detections
    assert detection.payload_capture == false
    assert detection.prompt_capture == false
  end

  test "requires a shared entity and bounded time window for cross-source correlation" do
    report =
      ExfiltrationCorrelator.correlate(%{
        sensitive_accesses: [
          %{timestamp_ms: @base_ms, agent_id: "a1", file_path: ".env", operation: "read"}
        ],
        gateway_events: [
          %{timestamp_ms: @base_ms + 1_000, agent_id: "a2", domain: "api.openai.com"},
          %{timestamp_ms: @base_ms + 600_000, agent_id: "a1", domain: "api.openai.com"}
        ]
      })

    assert report.detections == []
  end

  test "live correlation degrades explicitly when optional collectors are not running" do
    report =
      ExfiltrationCorrelator.correlate_live(
        [%{timestamp_ms: @base_ms, agent_id: "a1", resource_type: "credentials"}],
        gateway_events: [%{timestamp_ms: @base_ms + 1, agent_id: "a1", domain: "openrouter.ai"}]
      )

    assert report.coverage.collectors.ai_gateway in ["available", "not_started", "unavailable"]

    assert report.coverage.collectors.mcp_governance in [
             "available",
             "not_started",
             "unavailable"
           ]

    assert report.coverage.collectors.interaction_monitor in [
             "available",
             "not_started",
             "unavailable"
           ]

    assert report.coverage.collectors.model_auditor in [
             "available",
             "not_started",
             "no_model_ids"
           ]

    assert report.metadata_only
  end
end
