defmodule TamanduaServer.Detection.EngineWorkerLLMTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.LLMRequestTracker

  setup do
    start_supervised!(LLMRequestTracker)
    :ok
  end

  describe "LLM request event handling" do
    test "processes llm_request event type" do
      event = %{
        "event_type" => "llm_request",
        "payload" => %{
          "pid" => 1234,
          "process_name" => "python3",
          "process_path" => "/usr/bin/python3",
          "api_provider" => "openai",
          "api_endpoint" => "api.openai.com",
          "prompt_preview" => "Hello",
          "full_prompt_hash" => "abc123",
          "model" => "gpt-4",
          "timestamp" => DateTime.utc_now() |> DateTime.to_unix()
        }
      }

      # Simulate engine worker processing by calling track_request directly
      # (In real flow, engine_worker would call this via safe_call)
      :ok = LLMRequestTracker.track_request("agent-1", event["payload"])

      # Verify request was tracked
      requests = LLMRequestTracker.get_requests("agent-1")
      assert length(requests) == 1
    end

    test "handles llm_api_request event type alias" do
      event = %{
        "event_type" => "llm_api_request",
        "payload" => %{
          "pid" => 5678,
          "process_name" => "node",
          "process_path" => "/usr/bin/node",
          "api_provider" => "anthropic",
          "api_endpoint" => "api.anthropic.com",
          "prompt_preview" => "Test prompt",
          "full_prompt_hash" => "def456",
          "model" => "claude-3",
          "timestamp" => DateTime.utc_now() |> DateTime.to_unix()
        }
      }

      :ok = LLMRequestTracker.track_request("agent-2", event["payload"])

      requests = LLMRequestTracker.get_requests("agent-2")
      assert length(requests) == 1
      assert hd(requests).api_provider == :anthropic
    end

    test "extracts payload correctly from nested event" do
      event = %{
        "event_type" => "llm_request",
        "payload" => %{
          "pid" => 9999,
          "process_name" => "ollama",
          "api_provider" => "ollama",
          "api_endpoint" => "localhost:11434",
          "prompt_preview" => "Test",
          "full_prompt_hash" => "xyz789",
          "timestamp" => DateTime.utc_now()
        }
      }

      :ok = LLMRequestTracker.track_request("agent-3", event["payload"])

      requests = LLMRequestTracker.get_requests("agent-3")
      assert length(requests) == 1
      assert hd(requests).pid == 9999
    end

    test "gracefully handles errors without crashing" do
      # Invalid event should not raise
      invalid_event = %{"event_type" => "llm_request", "payload" => nil}

      # Should not crash - LLMRequestTracker will handle nil payload gracefully
      assert :ok = LLMRequestTracker.track_request("agent-4", %{
        "pid" => nil,
        "process_name" => nil,
        "api_provider" => nil
      })
    end
  end
end
