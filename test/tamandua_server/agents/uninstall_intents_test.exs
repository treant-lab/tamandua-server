defmodule TamanduaServer.Agents.UninstallIntentsTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Agents.AgentUninstallIntent
  alias TamanduaServer.Agents.TokenManager
  alias TamanduaServer.Agents.UninstallIntents
  alias TamanduaServer.Repo.MultiTenant

  setup do
    organization = insert(:organization)
    user = insert(:user, organization: organization)
    agent = insert(:agent, organization: organization)
    {:ok, jwt, token_record} = TokenManager.issue_token(agent.id, organization.id)

    %{
      organization: organization,
      user: user,
      agent: agent,
      jwt: jwt,
      token_generation: token_record.token_generation
    }
  end

  test "issuance is idempotent and supersedes the prior pending authority", context do
    attrs = %{reason: "operator_requested", idempotency_key: "loop66-idempotency-0001"}

    assert {:ok, first, :created} =
             UninstallIntents.issue(
               context.organization.id,
               context.agent.id,
               context.user.id,
               attrs
             )

    assert first.state == "pending"
    assert DateTime.diff(first.expires_at, first.issued_at, :second) == 300

    assert {:ok, repeated, :replay} =
             UninstallIntents.issue(
               context.organization.id,
               context.agent.id,
               context.user.id,
               attrs
             )

    assert repeated.id == first.id

    other_user = insert(:user, organization: context.organization)

    assert {:error, :idempotency_conflict} =
             UninstallIntents.issue(
               context.organization.id,
               context.agent.id,
               other_user.id,
               attrs
             )

    assert {:error, :idempotency_conflict} =
             UninstallIntents.issue(
               context.organization.id,
               context.agent.id,
               context.user.id,
               %{reason: "incident_response", idempotency_key: attrs.idempotency_key}
             )

    assert {:ok, replacement, :created} =
             UninstallIntents.issue(
               context.organization.id,
               context.agent.id,
               context.user.id,
               %{reason: "device_retirement"}
             )

    assert replacement.id != first.id

    [old, current] =
      MultiTenant.with_organization(context.organization.id, fn ->
        Repo.all(from(i in AgentUninstallIntent, order_by: [asc: i.issued_at]))
      end)

    assert old.state == "superseded"
    assert old.superseded_at
    assert current.state == "pending"

    assert {:error, :idempotency_conflict} =
             UninstallIntents.issue(
               context.organization.id,
               context.agent.id,
               context.user.id,
               attrs
             )
  end

  test "consume stores only the nonce digest and is exactly once", context do
    assert {:ok, intent, :created} =
             UninstallIntents.issue(
               context.organization.id,
               context.agent.id,
               context.user.id,
               %{reason: "incident_response"}
             )

    nonce_bytes = :crypto.strong_rand_bytes(32)
    nonce = Base.url_encode64(nonce_bytes, padding: false)

    consume = %{
      nonce: nonce,
      verifier_version: "uninstall_intent_v1",
      platform: "windows",
      consumer: "windows_msi"
    }

    assert {:ok, receipt} =
             UninstallIntents.consume(
               context.organization.id,
               context.agent.id,
               context.token_generation,
               context.jwt,
               consume
             )

    assert receipt.organization_id == context.organization.id
    assert receipt.agent_id == context.agent.id
    assert receipt.action == "agent_uninstall"
    assert receipt.nonce == nonce
    assert receipt.token_generation == context.token_generation
    assert receipt.verifier_version == consume.verifier_version
    assert receipt.platform == consume.platform
    assert receipt.consumer == consume.consumer
    assert receipt.state == "consumed"
    consumed_id = receipt.id
    assert consumed_id == intent.id

    persisted =
      MultiTenant.with_organization(context.organization.id, fn ->
        Repo.get!(AgentUninstallIntent, intent.id)
      end)

    assert persisted.nonce_sha256 == :crypto.hash(:sha256, nonce_bytes)
    refute persisted.nonce_sha256 == nonce_bytes
    assert persisted.token_generation == context.token_generation
    assert persisted.verifier_version == "uninstall_intent_v1"
    assert persisted.platform == "windows"
    assert persisted.consumer == "windows_msi"

    assert {:error, :already_consumed} =
             UninstallIntents.consume(
               context.organization.id,
               context.agent.id,
               context.token_generation,
               context.jwt,
               consume
             )

    assert {:ok, _next, :created} =
             UninstallIntents.issue(
               context.organization.id,
               context.agent.id,
               context.user.id,
               %{reason: "device_retirement"}
             )

    assert {:error, :unavailable} =
             UninstallIntents.consume(
               context.organization.id,
               context.agent.id,
               context.token_generation,
               context.jwt,
               consume
             )
  end

  test "consume rejects malformed nonce and cannot select another agent's intent", context do
    other_agent = insert(:agent, organization: context.organization)

    assert {:ok, _intent, :created} =
             UninstallIntents.issue(
               context.organization.id,
               context.agent.id,
               context.user.id,
               %{reason: "agent_replacement"}
             )

    base = %{
      verifier_version: "uninstall_intent_v1",
      platform: "linux",
      consumer: "native_cli"
    }

    assert {:error, :request_invalid} =
             UninstallIntents.consume(
               context.organization.id,
               context.agent.id,
               context.token_generation,
               context.jwt,
               Map.put(base, :nonce, Base.url_encode64(:crypto.strong_rand_bytes(31), padding: false))
             )

    assert {:error, :unauthorized} =
             UninstallIntents.consume(
               context.organization.id,
               other_agent.id,
               context.token_generation,
               context.jwt,
               Map.put(base, :nonce, Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false))
             )
  end

  test "expired pending intent cannot be consumed", context do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    expired =
      MultiTenant.with_organization(context.organization.id, fn ->
        %AgentUninstallIntent{}
        |> AgentUninstallIntent.issue_changeset(%{
          organization_id: context.organization.id,
          agent_id: context.agent.id,
          issued_by_user_id: context.user.id,
          action: "agent_uninstall",
          reason: "operator_requested",
          state: "pending",
          issued_at: DateTime.add(now, -301, :second),
          expires_at: DateTime.add(now, -1, :second)
        })
        |> Repo.insert!()
      end)

    assert expired.state == "pending"

    assert {:error, :expired} =
             UninstallIntents.consume(
               context.organization.id,
               context.agent.id,
               context.token_generation,
               context.jwt,
               %{
                 nonce: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
                 verifier_version: "uninstall_intent_v1",
                 platform: "macos",
                 consumer: "native_cli"
               }
             )
  end

  test "two concurrent consumes commit exactly once", context do
    assert {:ok, _intent, :created} =
             UninstallIntents.issue(
               context.organization.id,
               context.agent.id,
               context.user.id,
               %{reason: "incident_response"}
             )

    consume = %{
      nonce: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
      verifier_version: "uninstall_intent_v1",
      platform: "linux",
      consumer: "native_cli"
    }

    results =
      1..2
      |> Task.async_stream(
        fn _ ->
          UninstallIntents.consume(
            context.organization.id,
            context.agent.id,
            context.token_generation,
            context.jwt,
            consume
          )
        end,
        max_concurrency: 2,
        timeout: 10_000
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &match?({:ok, _}, &1)) == 1
    assert Enum.count(results, &(&1 == {:error, :already_consumed})) == 1
  end
end
