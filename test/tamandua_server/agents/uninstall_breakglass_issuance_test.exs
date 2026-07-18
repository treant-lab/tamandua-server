defmodule TamanduaServer.Agents.UninstallBreakglassIssuanceTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Agents.{AgentUninstallBreakglassIssuance, UninstallBreakglass}
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  setup do
    organization = insert(:organization)
    user = insert(:user, organization: organization)
    agent = insert(:agent, organization: organization)

    %{organization: organization, user: user, agent: agent}
  end

  test "successful signing inserts the authoritative digest-only issuance first", context do
    assert {:ok, envelope} = issue(context)

    issuance =
      MultiTenant.with_organization(context.organization.id, fn ->
        Repo.one!(AgentUninstallBreakglassIssuance)
      end)

    assert issuance.organization_id == context.organization.id
    assert issuance.agent_id == context.agent.id
    assert issuance.issued_by_user_id == context.user.id
    assert issuance.platform == "windows"
    assert issuance.consumer == "windows_msi"
    assert issuance.reason == "Approved maintenance window"
    assert byte_size(issuance.nonce_sha256) == 32
    assert byte_size(issuance.payload_sha256) == 32
    refute inspect(issuance) =~ envelope.payload
    refute inspect(issuance) =~ envelope.signature
  end

  test "intent, nonce and payload collisions fail closed without a second row", context do
    assert {:ok, _first} = issue(context)
    assert {:error, :store_unavailable} = issue(context)

    count =
      MultiTenant.with_organization(context.organization.id, fn ->
        Repo.aggregate(AgentUninstallBreakglassIssuance, :count)
      end)

    assert count == 1
  end

  test "concurrent deterministic collisions commit exactly one issuance", context do
    results =
      1..2
      |> Task.async_stream(fn _ -> issue(context) end,
        max_concurrency: 2,
        timeout: 10_000
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &match?({:ok, _}, &1)) == 1
    assert Enum.count(results, &(&1 == {:error, :store_unavailable})) == 1

    count =
      MultiTenant.with_organization(context.organization.id, fn ->
        Repo.aggregate(AgentUninstallBreakglassIssuance, :count)
      end)

    assert count == 1
  end

  test "tenant-scoped runtime update and delete paths cannot mutate an issuance", context do
    assert {:ok, _envelope} = issue(context)

    MultiTenant.with_organization(context.organization.id, fn ->
      assert {0, nil} =
               Repo.update_all(AgentUninstallBreakglassIssuance,
                 set: [reason: "Altered maintenance reason"]
               )

      assert {0, nil} = Repo.delete_all(AgentUninstallBreakglassIssuance)
      assert Repo.aggregate(AgentUninstallBreakglassIssuance, :count) == 1
    end)
  end

  defp issue(context) do
    seed = :erlang.list_to_binary(Enum.to_list(0..31))

    keyring =
      Jason.encode!(%{
        "active_key_id" => "breakglass-pg-test-v1",
        "keys" => [
          %{
            "key_id" => "breakglass-pg-test-v1",
            "private_key" => Base.url_encode64(seed, padding: false)
          }
        ]
      })

    UninstallBreakglass.issue(
      context.organization.id,
      context.agent.id,
      context.user.id,
      %{
        reason: "Approved maintenance window",
        platform: "windows",
        consumer: "windows_msi"
      },
      private_keys_json: keyring,
      now: ~U[2030-01-02 03:04:05Z],
      intent_id: "55555555-5555-4555-8555-555555555555",
      nonce_bytes: :erlang.list_to_binary(Enum.to_list(32..63))
    )
  end
end
