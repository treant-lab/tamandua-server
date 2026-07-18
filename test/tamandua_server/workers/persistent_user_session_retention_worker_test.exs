defmodule TamanduaServer.Workers.PersistentUserSessionRetentionWorkerTest do
  use TamanduaServer.DataCase, async: false

  import ExUnit.CaptureLog

  alias TamanduaServer.Workers.PersistentUserSessionRetentionWorker

  test "runs the server-owned cleanup policy from an empty job payload" do
    log =
      capture_log([level: :info], fn ->
        assert :ok =
                 PersistentUserSessionRetentionWorker.perform(%Oban.Job{args: %{}})
      end)

    assert log =~ "[PersistentUserSessionRetentionWorker] status=completed"
    assert log =~ ~r/deleted_count=\d+ batches=\d+/
  end

  test "discards unexpected args so identifiers never enter the job contract" do
    assert {:discard, :unexpected_arguments} =
             PersistentUserSessionRetentionWorker.perform(%Oban.Job{
               args: %{"session_id" => "not-accepted"}
             })
  end
end
