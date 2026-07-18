defmodule TamanduaServer.Detection.StorylineRecordTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Detection.StorylineRecord

  test "organization is required by the persistence contract" do
    changeset =
      StorylineRecord.changeset(%StorylineRecord{}, %{
        id: Ecto.UUID.generate(),
        agent_id: Ecto.UUID.generate(),
        status: "active",
        severity: "high",
        total_score: 75.0
      })

    refute changeset.valid?
    assert "can't be blank" in errors_on(changeset).organization_id
  end
end
