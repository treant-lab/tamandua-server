defmodule TamanduaServer.Detection.EventContextRiskScoreTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Detection.EventContext

  test "resolves family `behavioral_risk_score` for the sideband event" do
    context =
      EventContext.build(%{
        event_type: "behavioral_risk_score",
        payload: %{process_key: "powershell.exe", score: 50.0}
      })

    assert context.event_type == "behavioral_risk_score"
    assert context.family == "behavioral_risk_score"
  end

  test "does not affect other event families" do
    context =
      EventContext.build(%{
        event_type: "process_create",
        payload: %{"process_name" => "cmd.exe"}
      })

    assert context.family == "process"
  end
end
