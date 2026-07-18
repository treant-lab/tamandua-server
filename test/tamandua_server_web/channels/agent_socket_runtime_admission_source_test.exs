defmodule TamanduaServerWeb.AgentSocketRuntimeAdmissionSourceTest do
  use ExUnit.Case, async: true

  @source Path.expand(
            "../../../lib/tamandua_server_web/channels/agent_socket.ex",
            __DIR__
          )

  test "heartbeat publishes same-socket runtime authority synchronously" do
    source = File.read!(@source)

    assert source =~ "Registry.update_runtime_snapshot("
    assert source =~ "socket.assigns.connection_epoch"
    assert source =~ "socket.assigns.worker_pid"
    assert source =~ "normalize_policy_hash_algorithms"
    assert source =~ "extract_agent_info(params, organization_id)"
    assert source =~ "authenticated_organization_id(claims, canonical_agent_id, jti)"
    assert source =~ "exact_agent_organization_id(agent_id)"
    assert source =~ "canonical_claimed_organization_id(claims)"
    assert source =~ "reconcile_authenticated_organization("
    assert source =~ "Registry.canonical_organization_id?(organization_id)"
    assert source =~ "when canonical === value -> {:ok, canonical}"
    assert source =~ "requested_agent_id === subject and subject === claims_agent_id"
    assert source =~ "org_id === organization_id"
    refute source =~ "extract_org_id_from_token"
    refute source =~ "resolve_lab_org_id"
    refute source =~ "LAB_LIGHT_ORG_SLUG"
    assert length(Regex.scan(~r/Guardian\.decode_and_verify\(token\)/, source)) == 1
    refute source =~ "TamanduaServer.Agents.update_runtime_capabilities("
  end

  test "tenant provenance accepts only an authenticated claim or exact authenticated agent" do
    source = File.read!(@source)

    assert source =~
             "defp reconcile_authenticated_organization({:ok, claimed}, {:ok, stored})"

    assert source =~ "when claimed === stored"

    assert source =~
             "defp reconcile_authenticated_organization({:ok, claimed}, {:error, :invalid_token})"

    assert source =~
             "defp reconcile_authenticated_organization(:absent, {:ok, stored})"

    assert source =~ "defp reconcile_authenticated_organization(_, _)"
    assert source =~ "when stored_agent_id === agent_id"
    refute source =~ "Repo.one("
  end
end
