defmodule TamanduaServer.EnrollmentLocatorAccessTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.EnrollmentLocatorAccess

  defmodule StubRepo do
    def enabled?, do: Process.get(:enrollment_locator_enabled, false)
    def transaction(fun), do: {:ok, fun.()}
    def rollback(reason), do: throw({:stub_rollback, reason})

    def query(sql, _params \\ []) do
      cond do
        String.contains?(sql, "SELECT (") ->
          {:ok, %{rows: [[true]]}}

        String.starts_with?(sql, "SET LOCAL ROLE") ->
          {:ok, %{rows: []}}

        String.contains?(sql, "authority_enrollment_locator_v1") ->
          {:ok, %{rows: Process.get(:enrollment_locator_rows, [])}}
      end
    end
  end

  setup do
    old_repo = Application.get_env(:tamandua_server, :enrollment_locator_repo)
    old_role = Application.get_env(:tamandua_server, :enrollment_locator_database_role)

    Application.put_env(:tamandua_server, :enrollment_locator_repo, StubRepo)
    Application.put_env(:tamandua_server, :enrollment_locator_database_role, "locator_login")
    Process.put(:enrollment_locator_enabled, true)

    on_exit(fn ->
      restore_env(:enrollment_locator_repo, old_repo)
      restore_env(:enrollment_locator_database_role, old_role)
    end)

    :ok
  end

  test "returns only canonical token and organization UUIDs" do
    token_id = Ecto.UUID.generate()
    organization_id = Ecto.UUID.generate()
    Process.put(:enrollment_locator_rows, [[token_id, organization_id]])

    assert {:ok, ^token_id, ^organization_id} =
             EnrollmentLocatorAccess.locate(String.duplicate("a", 64))
  end

  test "normalizes miss without returning tenant data" do
    Process.put(:enrollment_locator_rows, [])
    assert {:error, :not_found} = EnrollmentLocatorAccess.locate(String.duplicate("b", 64))
  end

  test "fails closed on duplicate, malformed, uppercase, and disabled inputs" do
    id = Ecto.UUID.generate()
    org_id = Ecto.UUID.generate()
    Process.put(:enrollment_locator_rows, [[id, org_id], [id, org_id]])

    assert {:error, :persistence_unavailable} =
             EnrollmentLocatorAccess.locate(String.duplicate("c", 64))

    assert {:error, :not_found} = EnrollmentLocatorAccess.locate(String.duplicate("A", 64))

    Process.put(:enrollment_locator_enabled, false)

    assert {:error, :persistence_unavailable} =
             EnrollmentLocatorAccess.locate(String.duplicate("d", 64))
  end

  defp restore_env(key, nil), do: Application.delete_env(:tamandua_server, key)
  defp restore_env(key, value), do: Application.put_env(:tamandua_server, key, value)
end
