defmodule TamanduaServer.Billing.UsageMeterTest do
  @moduledoc """
  Tests for UsageMeter GenServer.
  """

  use ExUnit.Case, async: false

  alias TamanduaServer.Billing.UsageMeter

  setup do
    # Start the UsageMeter if not already started
    case GenServer.whereis(UsageMeter) do
      nil ->
        start_supervised!(UsageMeter)

      _pid ->
        :ok
    end

    org_id = Ecto.UUID.generate()
    UsageMeter.reset(org_id)

    {:ok, org_id: org_id}
  end

  describe "record_api_call/2" do
    test "increments API call counter by 1", %{org_id: org_id} do
      assert UsageMeter.get_usage(org_id, :api_calls) == 0

      UsageMeter.record_api_call(org_id)
      assert UsageMeter.get_usage(org_id, :api_calls) == 1
    end

    test "increments API call counter by specified amount", %{org_id: org_id} do
      UsageMeter.record_api_call(org_id)
      assert UsageMeter.get_usage(org_id, :api_calls) == 1

      UsageMeter.record_api_call(org_id, 5)
      assert UsageMeter.get_usage(org_id, :api_calls) == 6
    end

    test "handles concurrent increments", %{org_id: org_id} do
      # Simulate concurrent API calls
      tasks =
        for _ <- 1..100 do
          Task.async(fn -> UsageMeter.record_api_call(org_id) end)
        end

      Task.await_many(tasks)

      assert UsageMeter.get_usage(org_id, :api_calls) == 100
    end
  end

  describe "record_scan/2" do
    test "increments scan counter by 1", %{org_id: org_id} do
      assert UsageMeter.get_usage(org_id, :model_scans) == 0

      UsageMeter.record_scan(org_id)
      assert UsageMeter.get_usage(org_id, :model_scans) == 1
    end

    test "increments scan counter by specified amount", %{org_id: org_id} do
      UsageMeter.record_scan(org_id, 10)
      assert UsageMeter.get_usage(org_id, :model_scans) == 10
    end
  end

  describe "record_storage/2" do
    test "tracks storage delta", %{org_id: org_id} do
      assert UsageMeter.get_usage(org_id, :storage_bytes) == 0

      UsageMeter.record_storage(org_id, 1024)
      assert UsageMeter.get_usage(org_id, :storage_bytes) == 1024

      # Negative delta (file deleted)
      UsageMeter.record_storage(org_id, -512)
      assert UsageMeter.get_usage(org_id, :storage_bytes) == 512
    end
  end

  describe "get_all_usage/1" do
    test "returns all metrics for an organization", %{org_id: org_id} do
      UsageMeter.record_api_call(org_id, 10)
      UsageMeter.record_scan(org_id, 5)
      UsageMeter.record_storage(org_id, 1024)

      usage = UsageMeter.get_all_usage(org_id)

      assert usage.api_calls == 10
      assert usage.model_scans == 5
      assert usage.storage_bytes == 1024
    end

    test "returns zeros for new organization" do
      new_org_id = Ecto.UUID.generate()
      usage = UsageMeter.get_all_usage(new_org_id)

      assert usage.api_calls == 0
      assert usage.model_scans == 0
      assert usage.storage_bytes == 0
    end
  end

  describe "isolation" do
    test "different organizations have separate counters" do
      org1 = Ecto.UUID.generate()
      org2 = Ecto.UUID.generate()

      UsageMeter.record_api_call(org1, 100)
      UsageMeter.record_api_call(org2, 50)
      UsageMeter.record_scan(org1, 10)

      assert UsageMeter.get_usage(org1, :api_calls) == 100
      assert UsageMeter.get_usage(org2, :api_calls) == 50
      assert UsageMeter.get_usage(org1, :model_scans) == 10
      assert UsageMeter.get_usage(org2, :model_scans) == 0
    end
  end

  describe "reset/1" do
    test "clears all counters for an organization", %{org_id: org_id} do
      UsageMeter.record_api_call(org_id, 100)
      UsageMeter.record_scan(org_id, 50)

      assert UsageMeter.get_usage(org_id, :api_calls) == 100
      assert UsageMeter.get_usage(org_id, :model_scans) == 50

      UsageMeter.reset(org_id)

      assert UsageMeter.get_usage(org_id, :api_calls) == 0
      assert UsageMeter.get_usage(org_id, :model_scans) == 0
    end

    test "does not affect other organizations", %{org_id: org_id} do
      other_org = Ecto.UUID.generate()

      UsageMeter.record_api_call(org_id, 100)
      UsageMeter.record_api_call(other_org, 200)

      UsageMeter.reset(org_id)

      assert UsageMeter.get_usage(org_id, :api_calls) == 0
      assert UsageMeter.get_usage(other_org, :api_calls) == 200
    end
  end

  describe "last_flush/0" do
    test "returns the last flush timestamp" do
      last = UsageMeter.last_flush()
      assert %DateTime{} = last
    end
  end
end
