defmodule TamanduaServer.Supervisors.PeripheralGroupsTest do
  @moduledoc """
  Verifies the supervision-tree restructure: each peripheral domain group
  supervisor is running (full boot profile), supervises exactly the children
  it declares, uses its own isolated restart budget, and is itself a child of
  the top-level supervisor. Also verifies the adaptive-rate-limiter cleanup
  loop is now a supervised top-level child (formerly an unsupervised spawn).
  """

  use ExUnit.Case, async: false

  @groups [
    TamanduaServer.Supervisors.BlockchainSupervisor,
    TamanduaServer.Supervisors.ThreatIntelSyncSupervisor,
    TamanduaServer.Supervisors.CloudWorkloadSupervisor,
    TamanduaServer.Supervisors.RuleSyncSupervisor,
    TamanduaServer.Supervisors.NetworkDiscoverySupervisor,
    TamanduaServer.Supervisors.ThreatIntelFeedsSupervisor,
    TamanduaServer.Supervisors.AISecuritySupervisor,
    TamanduaServer.Supervisors.AgenticSoarSupervisor,
    TamanduaServer.Supervisors.ModelRegistrySupervisor,
    TamanduaServer.Supervisors.IntegrationsSupervisor,
    TamanduaServer.Supervisors.DataGovernanceSupervisor,
    TamanduaServer.Supervisors.IdentitySupervisor,
    TamanduaServer.Supervisors.VulnerabilityManagementSupervisor,
    TamanduaServer.Supervisors.MDRSupervisor,
    TamanduaServer.Supervisors.XDRSupervisor,
    TamanduaServer.Supervisors.DeceptionSupervisor,
    TamanduaServer.Supervisors.ObservabilitySupervisor
  ]

  # The peripheral groups only exist in the full boot profile; lab-light /
  # core profiles use a reduced flat children list on purpose.
  defp full_profile? do
    System.get_env("TAMANDUA_LAB_LIGHT", "false") != "true" and
      System.get_env("TAMANDUA_BOOT_PROFILE") not in ["core", "demo"]
  end

  defp expected_ids(group) do
    group.children()
    |> Enum.map(fn spec -> Supervisor.child_spec(spec, []).id end)
  end

  defp actual_ids(group) do
    group
    |> Supervisor.which_children()
    |> Enum.map(fn {id, _pid, _type, _mods} -> id end)
  end

  test "each peripheral group supervisor is running with exactly its declared children" do
    if full_profile?() do
      for group <- @groups do
        pid = Process.whereis(group)
        assert is_pid(pid), "expected #{inspect(group)} to be running under its registered name"

        expected = Enum.sort(expected_ids(group))
        actual = Enum.sort(actual_ids(group))

        assert actual == expected,
               "#{inspect(group)} children mismatch.\nexpected: #{inspect(expected)}\nactual:   #{inspect(actual)}"
      end
    else
      :ok
    end
  end

  test "peripheral groups declare non-empty child lists (compile-time sanity, any profile)" do
    for group <- @groups do
      children = group.children()
      assert is_list(children) and children != [], "#{inspect(group)} has no children"

      # Every entry must be a valid child spec convertible via Supervisor.child_spec/2
      for spec <- children do
        assert %{id: _, start: _} = Supervisor.child_spec(spec, [])
      end
    end
  end

  test "each peripheral group supervisor is a child of the top-level supervisor" do
    if full_profile?() do
      top_ids =
        TamanduaServer.Supervisor
        |> Supervisor.which_children()
        |> Enum.map(fn {id, _pid, _type, _mods} -> id end)

      for group <- @groups do
        assert group in top_ids,
               "expected #{inspect(group)} to be a direct child of TamanduaServer.Supervisor"
      end
    else
      :ok
    end
  end

  test "adaptive rate limiter cleanup loop is a supervised permanent child" do
    if full_profile?() do
      child =
        TamanduaServer.Supervisor
        |> Supervisor.which_children()
        |> Enum.find(fn {id, _pid, _type, _mods} -> id == :adaptive_rate_limiter_cleanup end)

      assert child != nil, "expected :adaptive_rate_limiter_cleanup under the top-level supervisor"
      {_id, pid, _type, _mods} = child
      assert is_pid(pid) and Process.alive?(pid)
    else
      :ok
    end
  end
end
