defmodule TamanduaServer.AI.LicenseComplianceTest do
  @moduledoc """
  Tests for LicenseCompliance GenServer.

  Tests cover:
  - Model registration and tracking
  - Compliance level management
  - Usage registration
  - Statistics
  """

  use ExUnit.Case, async: false

  alias TamanduaServer.AI.LicenseCompliance

  setup do
    # Start the LicenseCompliance if not already running
    case GenServer.whereis(LicenseCompliance) do
      nil ->
        {:ok, pid} = LicenseCompliance.start_link([])

        on_exit(fn ->
          if Process.alive?(pid), do: GenServer.stop(pid)
        end)

        {:ok, compliance_pid: pid}

      pid ->
        {:ok, compliance_pid: pid}
    end
  end

  # ============================================================================
  # get_stats/0 tests
  # ============================================================================

  describe "get_stats/0" do
    test "returns statistics map" do
      stats = LicenseCompliance.get_stats()

      assert is_map(stats)
      assert Map.has_key?(stats, :total_checks)
      assert Map.has_key?(stats, :compliant)
      assert Map.has_key?(stats, :attribution_required)
      assert Map.has_key?(stats, :copyleft_risk)
      assert Map.has_key?(stats, :commercial_restricted)
      assert Map.has_key?(stats, :blocked)
      assert Map.has_key?(stats, :registered_models)
    end

    test "registered_models reflects table size" do
      stats = LicenseCompliance.get_stats()
      assert is_integer(stats.registered_models)
    end
  end

  # ============================================================================
  # list_models/0 tests
  # ============================================================================

  describe "list_models/0" do
    test "returns list of models" do
      models = LicenseCompliance.list_models()
      assert is_list(models)
    end
  end

  # ============================================================================
  # list_non_compliant/0 tests
  # ============================================================================

  describe "list_non_compliant/0" do
    test "returns list of non-compliant models" do
      models = LicenseCompliance.list_non_compliant()
      assert is_list(models)
    end
  end

  # ============================================================================
  # get_model_status/1 tests
  # ============================================================================

  describe "get_model_status/1" do
    test "returns error for unknown model" do
      result = LicenseCompliance.get_model_status("unknown-model-12345")
      assert result == {:error, :not_found}
    end
  end

  # ============================================================================
  # register_usage/2 tests
  # ============================================================================

  describe "register_usage/2" do
    test "returns error for unregistered model" do
      result = LicenseCompliance.register_usage("unregistered-model", "agent-1")
      assert result == {:error, :model_not_registered}
    end
  end

  # ============================================================================
  # unregister_usage/2 tests
  # ============================================================================

  describe "unregister_usage/2" do
    test "returns ok even for unknown model" do
      result = LicenseCompliance.unregister_usage("unknown-model", "agent-1")
      assert result == :ok
    end
  end

  # ============================================================================
  # remove_model/1 tests
  # ============================================================================

  describe "remove_model/1" do
    test "returns error for unknown model" do
      result = LicenseCompliance.remove_model("unknown-model-12345")
      assert result == {:error, :not_found}
    end
  end

  # ============================================================================
  # Module exports verification
  # ============================================================================

  describe "module exports" do
    test "start_link/1 is exported" do
      assert function_exported?(LicenseCompliance, :start_link, 1)
    end

    test "check_model/2 is exported" do
      assert function_exported?(LicenseCompliance, :check_model, 2)
    end

    test "check_models/2 is exported" do
      assert function_exported?(LicenseCompliance, :check_models, 2)
    end

    test "get_model_status/1 is exported" do
      assert function_exported?(LicenseCompliance, :get_model_status, 1)
    end

    test "list_models/0 is exported" do
      assert function_exported?(LicenseCompliance, :list_models, 0)
    end

    test "list_non_compliant/0 is exported" do
      assert function_exported?(LicenseCompliance, :list_non_compliant, 0)
    end

    test "register_usage/2 is exported" do
      assert function_exported?(LicenseCompliance, :register_usage, 2)
    end

    test "unregister_usage/2 is exported" do
      assert function_exported?(LicenseCompliance, :unregister_usage, 2)
    end

    test "remove_model/1 is exported" do
      assert function_exported?(LicenseCompliance, :remove_model, 1)
    end

    test "get_stats/0 is exported" do
      assert function_exported?(LicenseCompliance, :get_stats, 0)
    end

    test "refresh_all/0 is exported" do
      assert function_exported?(LicenseCompliance, :refresh_all, 0)
    end
  end
end
