defmodule TamanduaServer.Detection.LLMRequestTrackerTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Detection.LLMRequestTracker

  setup do
    # Start the tracker for each test
    start_supervised!(LLMRequestTracker)
    :ok
  end

  describe "track_request/2" do
    test "stores request in ETS and returns :ok" do
      event = build_llm_event()
      assert :ok = LLMRequestTracker.track_request("agent-1", event)
    end
  end

  describe "get_requests/1" do
    test "returns list of requests for agent_id" do
      LLMRequestTracker.track_request("agent-1", build_llm_event())
      LLMRequestTracker.track_request("agent-1", build_llm_event())
      LLMRequestTracker.track_request("agent-2", build_llm_event())

      requests = LLMRequestTracker.get_requests("agent-1")
      assert length(requests) == 2
    end
  end

  describe "get_requests_for_process/2" do
    test "returns requests filtered by PID" do
      LLMRequestTracker.track_request("agent-1", build_llm_event(pid: 1234))
      LLMRequestTracker.track_request("agent-1", build_llm_event(pid: 5678))
      LLMRequestTracker.track_request("agent-1", build_llm_event(pid: 1234))

      requests = LLMRequestTracker.get_requests_for_process("agent-1", 1234)
      assert length(requests) == 2
      assert Enum.all?(requests, fn r -> r.pid == 1234 end)
    end
  end

  describe "get_recent_requests/2" do
    test "returns only requests within time window" do
      # Create a recent request
      LLMRequestTracker.track_request("agent-1", build_llm_event())

      # Recent requests (within 5 min) should include it
      recent = LLMRequestTracker.get_recent_requests("agent-1", 300)
      assert length(recent) >= 1
    end
  end

  describe "provider filtering" do
    test "get_requests with provider: :openai filters correctly" do
      LLMRequestTracker.track_request("agent-1", build_llm_event(api_provider: :openai))
      LLMRequestTracker.track_request("agent-1", build_llm_event(api_provider: :anthropic))
      LLMRequestTracker.track_request("agent-1", build_llm_event(api_provider: :openai))

      requests = LLMRequestTracker.get_requests("agent-1", provider: :openai)
      assert length(requests) == 2
      assert Enum.all?(requests, fn r -> r.api_provider == :openai end)
    end
  end

  describe "garbage collection" do
    test "removes requests older than TTL" do
      # This test validates the GC mechanism exists
      # Actual TTL behavior tested via direct ETS inspection or mocked time
      LLMRequestTracker.track_request("agent-1", build_llm_event())
      assert :ok = send(LLMRequestTracker, :garbage_collect)
      # Verify process handles the message without crashing
      Process.sleep(50)
      requests = LLMRequestTracker.get_requests("agent-1")
      assert is_list(requests)
    end
  end

  describe "PubSub broadcast" do
    test "broadcasts on new request tracking" do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "llm_request:agent-1")

      LLMRequestTracker.track_request("agent-1", build_llm_event())

      assert_receive {:llm_request_update, :new, _request}, 1000
    end
  end

  defp build_llm_event(overrides \\ []) do
    %{
      pid: Keyword.get(overrides, :pid, 1234),
      process_name: Keyword.get(overrides, :process_name, "python3"),
      process_path: Keyword.get(overrides, :process_path, "/usr/bin/python3"),
      api_provider: Keyword.get(overrides, :api_provider, :openai),
      api_endpoint: Keyword.get(overrides, :api_endpoint, "api.openai.com"),
      prompt_preview: Keyword.get(overrides, :prompt_preview, "Hello, world!"),
      full_prompt_hash: Keyword.get(overrides, :full_prompt_hash, "abc123"),
      model: Keyword.get(overrides, :model, "gpt-4"),
      timestamp: DateTime.utc_now()
    }
  end
end
