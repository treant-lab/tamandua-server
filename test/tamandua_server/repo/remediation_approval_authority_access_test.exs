defmodule TamanduaServer.Repo.RemediationApprovalAuthorityAccessTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.RemediationApprovalAuthorityAccess

  defmodule StubRepo do
    def enabled?, do: true
    def transaction(callback), do: {:ok, callback.()}
    def rollback(reason), do: throw({:rollback, reason})
    def query("SET LOCAL ROLE " <> _role), do: {:ok, %{rows: []}}

    def query(_preflight, [_role, _capability, _owner, _signature]),
      do:
        {:ok,
         %{
           rows: [
             [
               true,
               """
               SELECT DISTINCT execution.organization_id
               FROM public.remediation_executions execution
               WHERE p_limit BETWEEN 1 AND 250
                 AND (p_after IS NULL OR execution.organization_id > p_after)
                 AND execution.status = 'pending_approval'
                 AND execution.approval_status = 'pending'
               ORDER BY execution.organization_id ASC
               LIMIT p_limit + 1
               """
             ]
           ]
         }}

    def query("SELECT organization_id FROM " <> _function, [cursor, _limit]) do
      rows = Process.get(:remediation_approval_authority_rows, %{}) |> Map.get(cursor, [])
      {:ok, %{rows: Enum.map(rows, &[&1])}}
    end
  end

  setup do
    previous_repo = Application.get_env(:tamandua_server, :remediation_approval_authority_repo)

    previous_role =
      Application.get_env(:tamandua_server, :remediation_approval_authority_database_role)

    Application.put_env(:tamandua_server, :remediation_approval_authority_repo, StubRepo)

    Application.put_env(
      :tamandua_server,
      :remediation_approval_authority_database_role,
      "ra_test"
    )

    on_exit(fn ->
      restore_env(:remediation_approval_authority_repo, previous_repo)
      restore_env(:remediation_approval_authority_database_role, previous_role)
    end)

    :ok
  end

  test "accepts only canonical ordered UUID rows" do
    Process.put(:remediation_approval_authority_rows, %{
      nil => [
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000002"
      ]
    })

    assert {:ok,
            [
              "00000000-0000-4000-8000-000000000001",
              "00000000-0000-4000-8000-000000000002"
            ]} = RemediationApprovalAuthorityAccess.discover_organization_ids()
  end

  test "fails closed on malformed, duplicate, and unordered rows" do
    for rows <- [
          ["not-a-uuid"],
          [
            "00000000-0000-4000-8000-000000000001",
            "00000000-0000-4000-8000-000000000001"
          ],
          [
            "00000000-0000-4000-8000-000000000002",
            "00000000-0000-4000-8000-000000000001"
          ]
        ] do
      Process.put(:remediation_approval_authority_rows, %{nil => rows})

      assert {:error, :persistence_unavailable} =
               RemediationApprovalAuthorityAccess.discover_organization_ids()
    end
  end

  test "uses the last admitted UUID as the keyset cursor" do
    ids = Enum.map(1..251, &uuid/1)
    cursor = Enum.at(ids, 249)

    Process.put(:remediation_approval_authority_rows, %{
      nil => ids,
      cursor => [List.last(ids), uuid(252)]
    })

    assert {:ok, restored_ids} =
             RemediationApprovalAuthorityAccess.discover_organization_ids()

    assert restored_ids == Enum.map(1..252, &uuid/1)
  end

  test "fails closed when a page exceeds the function contract" do
    Process.put(:remediation_approval_authority_rows, %{
      nil => Enum.map(1..252, &uuid/1)
    })

    assert {:error, :persistence_unavailable} =
             RemediationApprovalAuthorityAccess.discover_organization_ids()
  end

  defp uuid(number),
    do: "00000000-0000-4000-8000-" <> String.pad_leading(Integer.to_string(number, 16), 12, "0")

  defp restore_env(key, nil), do: Application.delete_env(:tamandua_server, key)
  defp restore_env(key, value), do: Application.put_env(:tamandua_server, key, value)
end
