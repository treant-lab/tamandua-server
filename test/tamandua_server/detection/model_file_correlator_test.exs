defmodule TamanduaServer.Detection.ModelFileCorrelatorTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.ModelFileCorrelator
  alias TamanduaServer.Detection.MLProcessTracker

  setup do
    # Start both correlator and tracker (dependency)
    {:ok, _tracker} = start_supervised(MLProcessTracker)
    {:ok, pid} = start_supervised(ModelFileCorrelator)
    {:ok, correlator: pid}
  end

  describe "correlate/2" do
    test "identifies .gguf file access and links to ML process", %{correlator: _correlator} do
      agent_id = "test-agent-1"
      pid = 1000

      # First, track an ML process
      process_event = %{
        "event_type" => "process_create",
        "pid" => pid,
        "image" => "ollama",
        "path" => "/usr/local/bin/ollama",
        "cmdline" => "ollama serve",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }
      MLProcessTracker.track_process(agent_id, process_event)

      # Then, correlate file access
      file_event = %{
        "event_type" => "file_access",
        "agent_id" => agent_id,
        "payload" => %{
          "path" => "/models/llama-7b.gguf",
          "pid" => pid,
          "event_type" => "read"
        },
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      correlation = ModelFileCorrelator.correlate(agent_id, file_event)
      assert correlation != nil
      assert correlation.model_format == :gguf
      assert correlation.file_path == "/models/llama-7b.gguf"
      assert correlation.accessing_pid == pid
      assert correlation.risk_level == :low
    end

    test "identifies .safetensors file access and links to ML process", %{correlator: _correlator} do
      agent_id = "test-agent-2"
      pid = 2000

      # Track Python process
      process_event = %{
        "event_type" => "process_create",
        "pid" => pid,
        "image" => "python3",
        "path" => "/usr/bin/python3",
        "cmdline" => "python3 -m transformers",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }
      MLProcessTracker.track_process(agent_id, process_event)

      # File access event
      file_event = %{
        "event_type" => "file_read",
        "agent_id" => agent_id,
        "payload" => %{
          "path" => "/cache/model.safetensors",
          "pid" => pid
        },
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      correlation = ModelFileCorrelator.correlate(agent_id, file_event)
      assert correlation != nil
      assert correlation.model_format == :safetensors
      assert correlation.risk_level == :low
    end

    test "identifies .pt/.pth (PyTorch) file access", %{correlator: _correlator} do
      agent_id = "test-agent-3"
      pid = 3000

      # Track Python process
      process_event = %{
        "event_type" => "process_create",
        "pid" => pid,
        "image" => "python",
        "path" => "/usr/bin/python",
        "cmdline" => "python train.py --torch",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }
      MLProcessTracker.track_process(agent_id, process_event)

      # File access event for .pt file
      file_event = %{
        "event_type" => "file_access",
        "agent_id" => agent_id,
        "payload" => %{
          "path" => "/models/checkpoint.pt",
          "pid" => pid
        },
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      correlation = ModelFileCorrelator.correlate(agent_id, file_event)
      assert correlation != nil
      assert correlation.model_format == :pytorch
      assert correlation.risk_level == :high  # PyTorch files can contain arbitrary code
    end

    test "identifies .onnx file access", %{correlator: _correlator} do
      agent_id = "test-agent-4"
      pid = 4000

      process_event = %{
        "event_type" => "process_create",
        "pid" => pid,
        "image" => "python",
        "path" => "/usr/bin/python",
        "cmdline" => "python infer.py",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }
      MLProcessTracker.track_process(agent_id, process_event)

      file_event = %{
        "event_type" => "file_open",
        "agent_id" => agent_id,
        "payload" => %{
          "path" => "/models/model.onnx",
          "pid" => pid
        },
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      correlation = ModelFileCorrelator.correlate(agent_id, file_event)
      assert correlation != nil
      assert correlation.model_format == :onnx
      assert correlation.risk_level == :low
    end

    test "identifies .pkl (pickle) file access with warning", %{correlator: _correlator} do
      agent_id = "test-agent-5"
      pid = 5000

      process_event = %{
        "event_type" => "process_create",
        "pid" => pid,
        "image" => "python",
        "path" => "/usr/bin/python",
        "cmdline" => "python load_model.py",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }
      MLProcessTracker.track_process(agent_id, process_event)

      file_event = %{
        "event_type" => "file_read",
        "agent_id" => agent_id,
        "payload" => %{
          "path" => "/models/model.pkl",
          "pid" => pid
        },
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      correlation = ModelFileCorrelator.correlate(agent_id, file_event)
      assert correlation != nil
      assert correlation.model_format == :pickle
      assert correlation.risk_level == :high  # Pickle files are high risk
    end

    test "returns nil for non-model files", %{correlator: _correlator} do
      agent_id = "test-agent-6"
      pid = 6000

      file_event = %{
        "event_type" => "file_read",
        "agent_id" => agent_id,
        "payload" => %{
          "path" => "/etc/config.txt",
          "pid" => pid
        },
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      correlation = ModelFileCorrelator.correlate(agent_id, file_event)
      assert correlation == nil
    end
  end

  describe "get_model_access_history/2" do
    test "returns list of model files accessed by a process", %{correlator: _correlator} do
      agent_id = "test-agent-7"
      pid = 7000

      # Track process
      process_event = %{
        "event_type" => "process_create",
        "pid" => pid,
        "image" => "python",
        "path" => "/usr/bin/python",
        "cmdline" => "python app.py",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }
      MLProcessTracker.track_process(agent_id, process_event)

      # Access multiple model files
      file1 = %{
        "event_type" => "file_read",
        "agent_id" => agent_id,
        "payload" => %{"path" => "/models/model1.gguf", "pid" => pid},
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      file2 = %{
        "event_type" => "file_read",
        "agent_id" => agent_id,
        "payload" => %{"path" => "/models/model2.safetensors", "pid" => pid},
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
      }

      ModelFileCorrelator.correlate(agent_id, file1)
      ModelFileCorrelator.correlate(agent_id, file2)

      history = ModelFileCorrelator.get_model_access_history(agent_id, pid)
      assert length(history) == 2
      paths = Enum.map(history, & &1)
      assert "/models/model1.gguf" in paths
      assert "/models/model2.safetensors" in paths
    end
  end

  describe "get_processes_for_model/2" do
    test "returns list of processes that accessed a model file", %{correlator: _correlator} do
      agent_id = "test-agent-8"
      model_path = "/shared/model.gguf"

      # Track two processes
      for pid <- [8001, 8002] do
        process_event = %{
          "event_type" => "process_create",
          "pid" => pid,
          "image" => "ollama",
          "path" => "/usr/local/bin/ollama",
          "cmdline" => "ollama serve",
          "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
        }
        MLProcessTracker.track_process(agent_id, process_event)

        # Both access the same model
        file_event = %{
          "event_type" => "file_read",
          "agent_id" => agent_id,
          "payload" => %{"path" => model_path, "pid" => pid},
          "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
        }
        ModelFileCorrelator.correlate(agent_id, file_event)
      end

      processes = ModelFileCorrelator.get_processes_for_model(agent_id, model_path)
      assert length(processes) == 2
      assert 8001 in processes
      assert 8002 in processes
    end
  end
end
