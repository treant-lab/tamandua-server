defmodule TamanduaServer.Agents.UninstallIntentContractSourceTest do
  use ExUnit.Case, async: true

  @root Path.expand("../../..", __DIR__)

  test "consume revalidates the raw JWT under the tenant transaction before mutation" do
    context = File.read!(Path.join(@root, "lib/tamandua_server/agents/uninstall_intents.ex"))
    tokens = File.read!(Path.join(@root, "lib/tamandua_server/agents/token_manager.ex"))

    assert context =~ "TokenManager.validate_token_in_current_tenant("
    assert context =~ "Repo.update_all(query"
    assert tokens =~ "get_agent_for_token(expected_agent_id, expected_organization_id, lock: true)"
    assert tokens =~ "get_token_record_for_update(expected_agent_id, expected_generation)"
    assert tokens =~ "lock: true\n           ) do"
  end

  test "migration binds issuer and agent to the same tenant and stores digest-only nonce" do
    migration =
      File.read!(
        Path.join(
          @root,
          "priv/repo/migrations/20260717001000_create_agent_uninstall_intents.exs"
        )
      )

    assert migration =~ "add(:issued_by_user_id, :binary_id, null: false)"
    assert migration =~ "FOREIGN KEY (issued_by_user_id, organization_id)"
    assert migration =~ "FOREIGN KEY (agent_id, organization_id)"
    assert migration =~ "add(:nonce_sha256, :binary)"
    refute migration =~ "add(:nonce,"
    assert migration =~ "FORCE ROW LEVEL SECURITY"
    assert migration =~ "enforce_agent_uninstall_intent_transition"
  end

  test "offline issuance has a dedicated tenant-bound append-only authority" do
    migration =
      File.read!(
        Path.join(
          @root,
          "priv/repo/migrations/20260717002000_create_agent_uninstall_breakglass_issuances.exs"
        )
      )

    assert migration =~ "create table(:agent_uninstall_breakglass_issuances"
    assert migration =~ "FOREIGN KEY (agent_id, organization_id)"
    assert migration =~ "FOREIGN KEY (issued_by_user_id, organization_id)"
    assert migration =~ ":agent_uninstall_breakglass_issuances_org_intent_uidx"
    assert migration =~ ":agent_uninstall_breakglass_issuances_org_nonce_uidx"
    assert migration =~ ":agent_uninstall_breakglass_issuances_org_payload_uidx"
    assert migration =~ "consumer <> 'windows_msi' OR platform = 'windows'"
    assert migration =~ "20260717001000_create_agent_uninstall_intents.exs"
    assert migration =~ "date_trunc('second', issued_at) = issued_at"
    assert migration =~ "date_trunc('second', not_before) = not_before"
    assert migration =~ "date_trunc('second', expires_at) = expires_at"
    assert migration =~ "expires_at <= issued_at + interval '24 hours'"
    assert migration =~ "FORCE ROW LEVEL SECURITY"
    assert migration =~ "FOR SELECT"
    assert migration =~ "FOR INSERT"
    assert migration =~ "BEFORE UPDATE OR DELETE"
    assert migration =~ "BEFORE TRUNCATE"
    assert migration =~ "REVOKE UPDATE, DELETE, TRUNCATE"
  end

  test "server signs, inserts authoritative issuance, then emits without generic AuditLog authority" do
    signer =
      File.read!(Path.join(@root, "lib/tamandua_server/agents/uninstall_breakglass.ex"))

    {sign_position, _} = :binary.match(signer, "sign(payload_bytes, private_key)")
    {insert_position, _} = :binary.match(signer, "record_issuance(payload, payload_bytes")
    {emit_position, _} = :binary.match(signer, "payload: Base.url_encode64(payload_bytes")

    assert sign_position < insert_position
    assert insert_position < emit_position
    assert signer =~ "AgentUninstallBreakglassIssuance.issuance_changeset(issuance)"
    assert signer =~ "Jason.decode(encoded, objects: :ordered_objects)"
    assert signer =~ "length(keys) == MapSet.size(MapSet.new(keys))"
    assert signer =~ "validate_consumer_platform(platform, consumer)"
    refute signer =~ "alias TamanduaServer.AuditLog"
    refute signer =~ "AuditLog.log("
  end
end
