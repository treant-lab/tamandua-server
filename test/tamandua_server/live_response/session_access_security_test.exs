defmodule TamanduaServer.LiveResponse.SessionAccessSecurityTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.LiveResponse.SessionManager

  setup do
    session_id = "lr_session_security_test_#{System.unique_integer([:positive])}"

    session = %{
      session_id: session_id,
      agent_id: "agent-a",
      user_id: "operator-a",
      organization_id: "tenant-a",
      status: :active,
      started_at: DateTime.utc_now(),
      last_activity: DateTime.utc_now(),
      ended_at: nil,
      commands_executed: 0,
      command_history: []
    }

    :ets.insert(:live_response_sessions, {session_id, session})
    on_exit(fn -> :ets.delete(:live_response_sessions, session_id) end)

    %{session_id: session_id}
  end

  test "allows the owning operator in the same tenant", %{session_id: session_id} do
    assert {:ok, _session} =
      SessionManager.get_session_for_access(
        session_id,
        "tenant-a",
        "operator-a"
      )
  end

  test "allows a supervisor only inside the same tenant", %{session_id: session_id} do
    assert {:ok, _session} =
      SessionManager.get_session_for_access(
        session_id,
        "tenant-a",
        "supervisor-a",
        true
      )

    assert {:error, :unauthorized} =
      SessionManager.get_session_for_access(
        session_id,
        "tenant-b",
        "supervisor-b",
        true
      )
  end

  test "rejects another operator in the same tenant", %{session_id: session_id} do
    assert {:error, :unauthorized} =
      SessionManager.get_session_for_access(
        session_id,
        "tenant-a",
        "operator-b"
      )
  end

  test "tenant filter excludes sessions from other organizations", %{
    session_id: session_id
  } do
    assert Enum.any?(
      SessionManager.list_sessions(organization_id: "tenant-a"),
      &(&1.session_id == session_id)
    )

    refute Enum.any?(
      SessionManager.list_sessions(organization_id: "tenant-b"),
      &(&1.session_id == session_id)
    )
  end
end
