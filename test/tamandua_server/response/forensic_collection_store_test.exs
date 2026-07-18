defmodule TamanduaServer.Response.ForensicCollectionStoreTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.Response.Executor.CollectionStore

  test "per-tenant admission is atomic and a terminal update releases capacity" do
    assert :ok = CollectionStore.start()

    organization_id = Ecto.UUID.generate()

    collection_ids =
      for _index <- 1..8 do
        collection_id = Ecto.UUID.generate()

        assert :ok =
                 CollectionStore.reserve(%{
                   id: collection_id,
                   organization_id: organization_id,
                   status: "in_progress"
                 })

        collection_id
      end

    rejected_id = Ecto.UUID.generate()

    assert {:error, :collection_admission_limited} =
             CollectionStore.reserve(%{
               id: rejected_id,
               organization_id: organization_id,
               status: "in_progress"
             })

    [completed_id | _rest] = collection_ids

    assert :ok =
             CollectionStore.finish(completed_id, %{
               status: "completed",
               completed_at: DateTime.utc_now()
             })

    assert :ok =
             CollectionStore.reserve(%{
               id: rejected_id,
               organization_id: organization_id,
               status: "in_progress"
             })

    assert {:ok, %{organization_id: ^organization_id, status: "in_progress"}} =
             CollectionStore.get(rejected_id)
  end
end
