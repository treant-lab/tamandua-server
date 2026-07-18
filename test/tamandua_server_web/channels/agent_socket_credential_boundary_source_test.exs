defmodule TamanduaServerWeb.AgentSocketCredentialBoundarySourceTest do
  use ExUnit.Case, async: true

  @socket_path Path.expand(
                 "../../../lib/tamandua_server_web/channels/agent_socket.ex",
                 __DIR__
               )

  setup_all do
    {:ok, source: File.read!(@socket_path)}
  end

  test "managed credential failures cannot fall back to an AgentToken hash", %{source: source} do
    refute source =~ "alias TamanduaServer.Agents.TokenManager.AgentToken"
    refute source =~ "validate_agent_token_record"
    refute source =~ "validate_active_token_hash_fallback"
    refute source =~ "token_hash =="

    assert source =~ "Credentials.validate_and_record_use(jti, agent_id, org_id, peer_ip)"
    assert source =~ "{:error, reason} ->"
    assert source =~ "{:error, reason}"
  end

  test "Guardian decode failures reject compact JWTs before the explicit legacy policy", %{
    source: source
  } do
    decode_failure =
      source
      |> String.split("case TamanduaServer.Guardian.decode_and_verify(token) do", parts: 2)
      |> List.last()
      |> String.split("{:error, reason} ->", parts: 2)
      |> List.last()
      |> String.split("# DB-backed credential validation", parts: 2)
      |> List.first()

    assert decode_failure =~ "if compact_jwt?(token)"
    assert decode_failure =~ "{:error, :invalid_token}"
    assert decode_failure =~ "validate_legacy_socket_token(token, agent_id, env)"
    assert source =~ "env in [:dev, :test] or lab_light_enabled?()"
  end

  test "managed JWT identity requires exact canonical duplicate claims and tenant ownership", %{
    source: source
  } do
    assert source =~ ~S|present_claim?(claims, "type", :type)|
    assert source =~ ~S|present_claim?(claims, "org_id", :org_id)|
    assert source =~ ~S|present_claim?(claims, "organization_id", :organization_id)|
    assert source =~ ~S|present_claim?(claims, "generation", :generation)|
    assert source =~ "requested_agent_id == subject and subject == claims_agent_id"
    assert source =~ "org_id == organization_id"
    assert source =~ "credential_jti == jti"
    assert source =~ ~s(with "agent" <- claims["type"])
    assert source =~ "MultiTenant.with_organization(organization_id"
    assert source =~ "Agents.get_agent_for_org(organization_id, agent_id)"
  end

  test "token and credential logs use bounded pseudonymous references", %{source: source} do
    assert source =~ "credential_reference(credential_jti)"
    assert source =~ "credential_reference(jti)"
    assert source =~ "String.slice(0, 12)"
    refute source =~ ~S(credential_jti: #{credential_jti})
    refute source =~ ~S(jti=#{jti})
  end

  test "legacy compatibility has a finite hard maximum age", %{source: source} do
    assert source =~ "defp legacy_token_max_age_seconds do"
    assert source =~ "min(configured, @max_legacy_token_age_seconds)"
    assert source =~ "max_age = legacy_token_max_age_seconds()"

    refute source =~
             ~S|Phoenix.Token.verify(TamanduaServerWeb.Endpoint, "agent_auth", token, max_age: :infinity)|
  end
end
