defmodule TamanduaServer.Telemetry.MLAgentDetectionAlertTest do
  use TamanduaServer.DataCase, async: false

  alias Broadway.Message
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.Ingestor

  setup do
    previous_enabled = System.get_env("TAMANDUA_AGENT_DETECTION_ALERTS")
    previous_min_confidence = System.get_env("TAMANDUA_AGENT_DETECTION_ALERT_MIN_CONFIDENCE")

    System.put_env("TAMANDUA_AGENT_DETECTION_ALERTS", "true")
    System.put_env("TAMANDUA_AGENT_DETECTION_ALERT_MIN_CONFIDENCE", "0.7")

    on_exit(fn ->
      restore_env("TAMANDUA_AGENT_DETECTION_ALERTS", previous_enabled)
      restore_env("TAMANDUA_AGENT_DETECTION_ALERT_MIN_CONFIDENCE", previous_min_confidence)
    end)

    org = insert(:organization)
    agent = insert(:agent, organization_id: org.id, os_type: "windows", hostname: "WIN-ML-E2E")

    {:ok, org: org, agent: agent}
  end

  test "agent ML detection telemetry creates an ML alert and broadcasts alerts feed", %{
    org: org,
    agent: agent
  } do
    TamanduaServerWeb.Endpoint.subscribe("alerts:feed")

    event_id = Ecto.UUID.generate()

    event = %{
      "event_id" => event_id,
      "event_type" => "ransomware_detected",
      "agent_id" => agent.id,
      "organization_id" => org.id,
      "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "severity" => "critical",
      "payload" => %{
        "detection_source" => "ml_analysis",
        "sha256" => String.duplicate("a", 64),
        "file_path" => "C:\\ProgramData\\Tamandua\\ml-bench\\malware_00000.bin",
        "ml_verdict" => "trojan",
        "model_version" => "malware_smell_knn",
        "confidence" => 1.0
      },
      "metadata" => %{
        "source" => "ml_analysis",
        "provider" => "tamandua_agent"
      },
      "detections" => [
        %{
          "detection_type" => "ml",
          "rule_name" => "agent_ml_malware_classification",
          "confidence" => 1.0,
          "description" => "ML model detected trojan malware",
          "mitre_tactics" => ["execution"],
          "mitre_techniques" => ["T1204"]
        }
      ]
    }

    ingest(event)

    alert =
      Repo.one!(
        from a in Alert,
          where: a.agent_id == ^agent.id,
          where: fragment("?->>'detection_source' = ?", a.detection_metadata, "ml"),
          order_by: [desc: a.inserted_at],
          limit: 1
      )

    assert alert.organization_id == org.id
    assert alert.severity == "critical"
    assert alert.detection_metadata["source"] == "ml"
    assert alert.detection_metadata["detection_source"] == "ml"
    assert alert.detection_metadata["detection_type"] == "ml"
    assert alert.detection_metadata["rule_name"] == "agent_ml_malware_classification"
    assert alert.detection_metadata["prediction"] == "trojan"
    assert alert.detection_metadata["model_version"] == "malware_smell_knn"

    assert_receive %Phoenix.Socket.Broadcast{
                     topic: "alerts:feed",
                     event: "new_alert",
                     payload: payload
                   },
                   1_000

    assert payload["id"] == alert.id || payload[:id] == alert.id
  end

  defp ingest(event) do
    message = %Message{
      data: event,
      acknowledger: {Broadway.NoopAcknowledger, nil, nil}
    }

    assert %Message{} = Ingestor.handle_message(:default, message, %{})
  end

  defp restore_env(key, nil), do: System.delete_env(key)
  defp restore_env(key, value), do: System.put_env(key, value)
end
