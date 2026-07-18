defmodule TamanduaServer.EnrollmentPhase1SourceTest do
  use ExUnit.Case, async: true

  @enrollment "../../lib/tamandua_server/enrollment.ex"
  @controller "../../lib/tamandua_server_web/controllers/api/v1/enrollment_controller.ex"
  @locator "../../lib/tamandua_server/enrollment_locator_access.ex"
  @token_manager "../../lib/tamandua_server/agents/token_manager.ex"
  @bootstrap "../../../../tools/authority_enrollment_locator_v1/bootstrap_v1.sql"
  @verify "../../../../tools/authority_enrollment_locator_v1/verify_v1.sql"
  @deprovision "../../../../tools/authority_enrollment_locator_v1/deprovision_v1.sql"
  @runtime "../../config/runtime.exs"
  @application "../../lib/tamandua_server/application.ex"

  test "public enrollment uses the narrow locator and no RLS bypass" do
    source = File.read!(Path.expand(@enrollment, __DIR__))

    assert source =~ "EnrollmentLocatorAccess.locate()"
    assert source =~ "lock: \"FOR UPDATE\""
    assert source =~ "t.id == ^token_id and t.organization_id == ^organization_id"
    assert source =~ "validate_locked_token(token, cleartext)"
    assert source =~ "Argon2.no_user_verify()"
    assert source =~ "TokenManager.issue_token_in_current_tenant(locked_agent)"
    refute source =~ "def validate_token(cleartext) do\n    with_enrollment_bypass"
    refute source =~ "maybe_legacy_agent_jwt(agent_id, org_id"
    refute source =~ "with_enrollment_bypass"
    refute source =~ "cleanup_failed_enrollment"
    refute source =~ "do_enroll_with_csr"
  end

  test "legacy exchange is a single tenant transaction and CSR is unavailable" do
    source = File.read!(Path.expand(@enrollment, __DIR__))

    assert source =~ "MultiTenant.with_organization(organization_id, fn ->"
    assert source =~ "consume_locked_token(token, agent_id)"
    assert source =~ "throw({:enrollment_exchange_failed, reason})"
    assert source =~ "def enroll_with_csr(cleartext, csr_pem, agent_info"
    assert source =~ "{:error, :enrollment_unavailable}"
  end

  test "public controller is generic and validation does not reveal tenant" do
    source = File.read!(Path.expand(@controller, __DIR__))

    assert source =~ "json(conn, %{\n          valid: true\n        })"
    assert source =~ "%{error: \"invalid_enrollment_token\"}"
    assert source =~ "put_status(:service_unavailable)"
    refute source =~ "valid: true,\n          org_id:"
  end

  test "in-transaction token issuance is exact and bypasses the GenServer" do
    source = File.read!(Path.expand(@token_manager, __DIR__))

    assert source =~ "def issue_token_in_current_tenant(%TamanduaServer.Agents.Agent{} = agent"
    assert source =~ "case {Repo.get_organization_id(), Repo.in_transaction?()}"
    assert source =~ "get_agent_for_issuance(canonical_agent_id, canonical_organization_id)"
    assert source =~ "do_issue_locked_agent(locked_agent, opts)"
  end

  test "locator contract validates digest, identity, ACL and bounded result" do
    source = File.read!(Path.expand(@locator, __DIR__))

    assert source =~ "~r/^[0-9a-f]{64}$/"
    assert source =~ "defp validate_rows([[token_id, organization_id]])"
    assert source =~ "defp validate_rows(_rows), do: {:error, :persistence_unavailable}"
    assert source =~ "NOT login_role.rolbypassrls"

    assert source =~
             "NOT pg_catalog.has_column_privilege(function_owner.oid, tokens.oid, 'token_hash', 'SELECT')"

    assert source =~ "NOT pg_catalog.has_any_column_privilege("
  end

  test "external package is separate, default-off and verify-only evidenced" do
    bootstrap = File.read!(Path.expand(@bootstrap, __DIR__))
    verify = File.read!(Path.expand(@verify, __DIR__))
    deprovision = File.read!(Path.expand(@deprovision, __DIR__))

    assert bootstrap =~ "SECURITY DEFINER"
    assert bootstrap =~ "LIMIT 2"
    assert bootstrap =~ "GRANT SELECT (id, organization_id, token_digest)"
    refute bootstrap =~ "tamandua_authority_agentic_restore_v1_executor TO"
    refute bootstrap =~ "tamandua_authority_retention_v1_executor TO"
    assert verify =~ "enrollment_locator_v1_verified"

    assert verify =~
             "NOT pg_catalog.has_column_privilege(owner.oid, tokens.oid, 'token_hash', 'SELECT')"

    assert bootstrap =~ "has_any_column_privilege(login_oid"
    assert verify =~ "has_any_column_privilege(login.oid"

    assert deprovision =~
             "REVOKE SELECT (id, organization_id, token_digest) ON public.installation_tokens"
  end

  test "locator pool is dedicated and remains default-off" do
    runtime = File.read!(Path.expand(@runtime, __DIR__))
    application = File.read!(Path.expand(@application, __DIR__))

    assert runtime =~ "ENROLLMENT_LOCATOR_REPO_ENABLED"
    assert runtime =~ "ENROLLMENT_LOCATOR_DATABASE_URL"
    assert runtime =~ "ENROLLMENT_LOCATOR_DATABASE_ROLE"

    assert runtime =~
             "RUNTIME_DATABASE_ROLE is required when the enrollment locator pool is enabled"

    assert runtime =~
             "enrollment locator, runtime, migrator, retention and agentic database roles must be distinct"

    assert runtime =~ "pool_size: 1"
    assert application =~ "TamanduaServer.EnrollmentLocatorRepo.enabled?()"
  end
end
