defmodule TamanduaServer.Detection.MLProcessTrackerTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.MLProcessTracker

  setup do
    # Start a fresh MLProcessTracker for each test
    {:ok, pid} = start_supervised(MLProcessTracker)
    {:ok, tracker: pid}
  end

  describe "track_process/2" do
    test "identifies Python process by name pattern", %{tracker: _tracker} do
      event = %{
        "event_type" => "process_create",
        "pid" => 1234,
        "image" => "python3.exe",
        "path" => "/usr/bin/python3",
        "cmdline" => "python3 script.py",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      agent_id = "test-agent-1"
      assert :ok = MLProcessTracker.track_process(agent_id, event)

      # Verify the process was tracked
      context = MLProcessTracker.get_process_context(agent_id, 1234)
      assert context != nil
      assert context.runtime_type == :python
      assert context.name == "python3.exe"
    end

    test "identifies Ollama process by name pattern", %{tracker: _tracker} do
      event = %{
        "event_type" => "process_create",
        "pid" => 5678,
        "image" => "ollama",
        "path" => "/usr/local/bin/ollama",
        "cmdline" => "ollama serve",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      agent_id = "test-agent-2"
      assert :ok = MLProcessTracker.track_process(agent_id, event)

      context = MLProcessTracker.get_process_context(agent_id, 5678)
      assert context != nil
      assert context.runtime_type == :ollama
      assert context.name == "ollama"
    end

    test "identifies llama.cpp by name patterns", %{tracker: _tracker} do
      event = %{
        "event_type" => "process_create",
        "pid" => 9999,
        "image" => "llama-server",
        "path" => "/opt/llama.cpp/llama-server",
        "cmdline" => "llama-server --model model.gguf --port 8080",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      agent_id = "test-agent-3"
      assert :ok = MLProcessTracker.track_process(agent_id, event)

      context = MLProcessTracker.get_process_context(agent_id, 9999)
      assert context != nil
      assert context.runtime_type == :llama_cpp
      assert context.name == "llama-server"
    end

    test "detects ML framework from cmdline (--torch)", %{tracker: _tracker} do
      event = %{
        "event_type" => "process_create",
        "pid" => 1111,
        "image" => "python",
        "path" => "/usr/bin/python",
        "cmdline" => "python train.py --torch --batch-size 32",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      agent_id = "test-agent-4"
      assert :ok = MLProcessTracker.track_process(agent_id, event)

      context = MLProcessTracker.get_process_context(agent_id, 1111)
      assert context != nil
      assert context.framework == "torch"
    end
  end

  describe "get_ml_processes/1" do
    test "returns all tracked ML processes for an agent", %{tracker: _tracker} do
      agent_id = "test-agent-5"

      # Track multiple processes
      event1 = %{
        "event_type" => "process_create",
        "pid" => 100,
        "image" => "python",
        "path" => "/usr/bin/python",
        "cmdline" => "python app.py",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      event2 = %{
        "event_type" => "process_create",
        "pid" => 200,
        "image" => "ollama",
        "path" => "/usr/local/bin/ollama",
        "cmdline" => "ollama serve",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      MLProcessTracker.track_process(agent_id, event1)
      MLProcessTracker.track_process(agent_id, event2)

      processes = MLProcessTracker.get_ml_processes(agent_id)
      assert length(processes) == 2
      pids = Enum.map(processes, & &1.pid)
      assert 100 in pids
      assert 200 in pids
    end
  end

  describe "process_terminated/2" do
    test "removes process from tracking", %{tracker: _tracker} do
      agent_id = "test-agent-6"
      pid = 3000

      event = %{
        "event_type" => "process_create",
        "pid" => pid,
        "image" => "python",
        "path" => "/usr/bin/python",
        "cmdline" => "python script.py",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      MLProcessTracker.track_process(agent_id, event)
      assert MLProcessTracker.get_process_context(agent_id, pid) != nil

      # Terminate the process
      :ok = MLProcessTracker.process_terminated(agent_id, pid)

      # Should no longer be tracked
      assert MLProcessTracker.get_process_context(agent_id, pid) == nil
    end
  end

  describe "get_process_context/2" do
    test "returns ML metadata (runtime_type, framework, model_files)", %{tracker: _tracker} do
      agent_id = "test-agent-7"
      pid = 4000

      event = %{
        "event_type" => "process_create",
        "pid" => pid,
        "image" => "python3",
        "path" => "/usr/bin/python3",
        "cmdline" => "python3 -m transformers",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      MLProcessTracker.track_process(agent_id, event)

      context = MLProcessTracker.get_process_context(agent_id, pid)
      assert context != nil
      assert context.runtime_type == :python
      assert context.framework == "transformers"
      assert context.model_files == []
      assert context.agent_id == agent_id
      assert context.pid == pid
    end
  end
end
