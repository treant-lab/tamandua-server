defmodule TamanduaServer.Agents.CredentialTenantBoundarySourceTest do
  use ExUnit.Case, async: true

  @credentials_path Path.expand(
                      "../../../lib/tamandua_server/agents/credentials.ex",
                      __DIR__
                    )
  @agents_path Path.expand("../../../lib/tamandua_server/agents.ex", __DIR__)
  @token_manager_path Path.expand(
                        "../../../lib/tamandua_server/agents/token_manager.ex",
                        __DIR__
                      )

  test "credential identity and mutation queries carry agent and tenant predicates" do
    source = File.read!(@credentials_path)

    assert source =~ "Agents.get_agent_for_org(organization_id, agent_id)"
    assert source =~ "c.jti == ^jti and c.agent_id == ^agent_id"
    assert source =~ "c.organization_id == ^organization_id"
    assert source =~ ~s(lock: "FOR UPDATE")
    assert source =~ "Repo.get_organization_id()"
    assert source =~ "Repo.in_transaction?()"
    assert source =~ "{^organization_id, true} -> fun.()"
    refute source =~ "with_bypass"
  end

  test "legacy organization-less APIs fail closed" do
    credentials = File.read!(@credentials_path)
    agents = File.read!(@agents_path)

    for contract <- [
          "def get_by_jti(_jti), do: {:error, :organization_scope_required}",
          "def revoke(_jti), do: {:error, :organization_scope_required}",
          "def revoke_all_for_agent(_agent_id), do: {:error, :organization_scope_required}",
          "def list_active_for_agent(_agent_id), do: {:error, :organization_scope_required}",
          "def get_stats(_agent_id), do: {:error, :organization_scope_required}",
          "def cleanup_expired(), do: {:error, :organization_scope_required}",
          "def cleanup_expired(_legacy_days), do: {:error, :organization_scope_required}"
        ] do
      assert credentials =~ contract
    end

    assert agents =~ "def credential_valid?(_jti), do: false"

    assert agents =~
             "def cleanup_expired_credentials(), do: {:error, :organization_scope_required}"
  end

  test "list and cleanup are bounded and cleanup is tenant-only" do
    source = File.read!(@credentials_path)

    for contract <- [
          "@maximum_list_limit 500",
          "@maximum_cleanup_limit 1_000",
          "@maximum_reason_bytes 512",
          "@maximum_jti_bytes 255",
          "@maximum_ip_bytes 64",
          "days >= 1 and days <= 365",
          "c.expires_at <= ^now",
          "c.expires_at < ^cutoff",
          "c.id in subquery(ids)"
        ] do
      assert source =~ contract
    end
  end

  test "audit events never persist the presented credential JTI" do
    source = File.read!(@credentials_path)

    assert source =~ "credential_reference = credential_reference(credential.jti)"
    assert source =~ "credential_reference = credential_reference(jti)"
    assert source =~ ":crypto.hash(:sha256, jti)"
    refute source =~ "resource_id: credential.jti"
    refute source =~ "resource_id: jti"
    refute source =~ "jti: credential.jti"
  end

  test "TokenManager uses the current-tenant issuance layer" do
    source = File.read!(@token_manager_path)
    credentials = File.read!(@credentials_path)

    assert length(
             Regex.scan(
               ~r/Credentials\.issue_credential_in_current_tenant\(agent,/,
               source
             )
           ) == 2

    refute source =~ "Credentials.issue_credential(agent.id, agent.organization_id"

    # Token refresh already holds the old credential row before issuing its
    # replacement. Per-agent issuance must not then acquire the organization
    # lock, which would invert revoke-all's Organization -> Credential order.
    issue_record =
      credentials
      |> String.split("defp issue_credential_record", parts: 2)
      |> List.last()
      |> String.split("@doc \"Validates an exact tenant credential", parts: 2)
      |> List.first()

    refute issue_record =~ "lock_organization(organization_id)"
  end

  test "TokenManager logs only a bounded pseudonymous JTI reference" do
    source = File.read!(@token_manager_path)

    assert source =~ "@maximum_jti_reference_input_bytes 255"
    assert source =~ "@jti_reference_hex_chars 12"
    assert source =~ ~S|jti_ref #{jti_reference(jti)}|
    assert source =~ "then(&:crypto.hash(:sha256, &1))"
    assert source =~ ~s|defp jti_reference(_jti), do: "unavailable"|

    refute source =~ ~S|jti #{jti}|
    refute source =~ "jti: jti_reference(jti)"

    refute source =~
             ~S|Failed to issue DB-backed credential for agent #{agent.id}: #{inspect(reason)}|

    refute source =~ ~S|Token validation failed: #{Exception.message(e)}|
    refute source =~ ~S|Token refresh failed: #{Exception.message(e)}|
    refute source =~ "Exception.message("
    refute source =~ "inspect(reason)"
    refute source =~ "inspect(changeset.errors)"

    audit_block =
      source
      |> String.split("defp audit_token_operation", parts: 2)
      |> List.last()

    refute audit_block =~ "jti"
  end

  test "caller-provided issuance time cannot move the lifetime window into the future" do
    source = File.read!(@credentials_path)

    assert source =~ "DateTime.compare(issued_at, DateTime.utc_now()) in [:lt, :eq]"
    assert source =~ "else: {:error, :invalid_credential_issued_at}"
  end

  test "changed sources remain valid Elixir AST" do
    for path <- [@credentials_path, @agents_path, @token_manager_path] do
      assert {:ok, _ast} = path |> File.read!() |> Code.string_to_quoted()
    end
  end
end
