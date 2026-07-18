defmodule TamanduaServer.Response.ResponseAuditCompletenessSourceTest do
  use ExUnit.Case, async: true

  @executor_path Path.expand(
                   "../../../lib/tamandua_server/response/executor.ex",
                   __DIR__
                 )
  @audit_path Path.expand("../../../lib/tamandua_server/response/audit.ex", __DIR__)
  @ml_response_path Path.expand("../../../lib/tamandua_server/response/ml_response.ex", __DIR__)
  @engine_worker_path Path.expand(
                        "../../../lib/tamandua_server/detection/engine_worker.ex",
                        __DIR__
                      )
  @action_path Path.expand("../../../lib/tamandua_server/response/action.ex", __DIR__)
  @resolver_path Path.expand(
                   "../../../lib/tamandua_server_web/graphql/resolvers/response_resolver.ex",
                   __DIR__
                 )
  @types_path Path.expand(
                "../../../lib/tamandua_server_web/graphql/types/response_types.ex",
                __DIR__
              )

  test "kill and quarantine persist a tenant-owned action before command execution" do
    executor = File.read!(@executor_path)

    assert executor =~ "persist_action: true"
    assert executor =~ "with {:ok, tracked_action} <- prepare_tracked_action(alert, action)"
    assert executor =~ "organization_id: organization_id"
    assert executor =~ "executed_by_id: actor_user_id(actor)"
    assert executor =~ "validate_actor_user(actor, organization_id)"
    assert executor =~ "validate_actor_user(actor, canonical_actor_org)"
    assert executor =~ "{:error, :actor_identity_required}"
    assert executor =~ "canonical_uuid(user_id)"
    assert executor =~ "validate_action_alert(action, alert, organization_id)"
    assert executor =~ "authorize_actor_for_alert(actor, alert)"
    assert executor =~ "db_org_check(actor_org, agent_id)"
    assert executor =~ "db_org_check(organization_id, agent_id)"
    assert executor =~ "nil -> {:error, :unauthorized}"
    assert executor =~ "canonical_uuid(actor_org)"
    assert executor =~ "canonical_response_organization"
    assert executor =~ "Registry state is transport presence only and never tenancy authority"
    assert executor =~ "audit_organization(actor, alert, agent_id)"
    assert executor =~ "in_tenant_scope(organization_id, fn ->"
    assert executor =~ "MultiTenant.with_organization(organization_id, fun)"

    assert :binary.match(executor, "prepare_tracked_action(alert, action)") <
             :binary.match(executor, "do_execute_response(alert, action, tracked_action)")
  end

  test "parameters retain operator reason and outcome finalization degrades explicitly" do
    executor = File.read!(@executor_path)

    assert executor =~ "maybe_put(:reason, Keyword.get(opts, :reason))"
    assert executor =~ "Action.result_changeset(attrs)"
    assert executor =~ ~s(audit_status: "degraded")
    assert executor =~ ~s|Map.get(action, :audit_status, "complete")|
    assert executor =~ "action_id: action.id"
  end

  test "audit writes require an authoritative organization" do
    audit = File.read!(@audit_path)

    assert audit =~
             "@required_fields ~w(action_type agent_id organization_id actor_type performed_at)a"

    assert audit =~ "do: {:error, :organization_scope_required}"
    assert audit =~ "canonical_uuid(organization_id)"
    assert audit =~ "get_agent_for_org(organization_id, agent_id)"
    assert audit =~ "Repo.get_by(User, id: actor_id, organization_id: organization_id)"
    assert audit =~ "MultiTenant.with_organization(organization_id, fn ->"
    refute audit =~ "with_bypass"
    refute audit =~ "OrgLookup"
    refute audit =~ "organization_for_agent"
  end

  test "ML response validates exact tenant ownership before policy, alert, audit, or dispatch" do
    ml_response = File.read!(@ml_response_path)
    engine_worker = File.read!(@engine_worker_path)

    assert ml_response =~ "def handle_ml_detection(sample, ml_result, agent_id) do"
    assert ml_response =~ "{:error, :organization_scope_required}"
    assert ml_response =~ "validate_agent_scope(organization_id, agent_id)"
    assert ml_response =~ "get_agent_for_org("
    assert ml_response =~ "organization_id: organization_id"
    assert ml_response =~ "load_policy(canonical_organization_id, canonical_agent_id)"
    assert ml_response =~ "MultiTenant.with_organization(organization_id, fn ->"
    assert ml_response =~ "execute_auto_quarantine_after_alert("
    assert ml_response =~ "{:error, {:alert_creation_failed, reason}}"
    assert ml_response =~ "%{alert_id: alert.id}"
    refute ml_response =~ "alert && alert.id"

    assert ml_response =~
             "Audit.log_action(action_type, details, agent_id, :system, organization_id)"

    refute ml_response =~ "OrgLookup"

    assert engine_worker =~
             "MLResponse.handle_ml_detection(sample, prediction, agent_id, organization_id)"

    refute engine_worker =~ "result.threat_score >= Config.threat_threshold() ->"

    assert :binary.match(ml_response, "validate_agent_scope(organization_id, agent_id)") <
             :binary.match(ml_response, "do_handle_ml_detection(sample, ml_result")
  end

  test "legacy four-argument audit calls are an explicit phase-two inventory" do
    lib_root = Path.expand("../../../lib/tamandua_server", __DIR__)

    callers =
      Path.wildcard(Path.join(lib_root, "**/*.ex"))
      |> Enum.filter(&four_argument_audit_call?/1)
      |> Enum.map(&Path.relative_to(&1, lib_root))
      |> MapSet.new()

    assert callers ==
             MapSet.new([
               "deception/breadcrumb_monitor.ex",
               "quarantine/model_quarantine_handler.ex",
               "quarantine/model_vault.ex",
               "response/rollback_manager.ex",
               "response/vss_rollback.ex"
             ])
  end

  test "GraphQL requested_by projects the persisted executed_by identity" do
    resolver = File.read!(@resolver_path)
    types = File.read!(@types_path)
    action = File.read!(@action_path)

    assert action =~ "belongs_to :executed_by"
    assert resolver =~ "action.executed_by_id"
    refute resolver =~ "action.requested_by_id"
    assert types =~ "{:ok, action.executed_by_id}"
  end

  defp four_argument_audit_call?(path) do
    {:ok, ast} = path |> File.read!() |> Code.string_to_quoted()

    {_ast, found?} =
      Macro.prewalk(ast, false, fn
        {{:., _, [{:__aliases__, _, aliases}, :log_action]}, _, args} = node, found
        when is_list(args) and length(args) == 4 ->
          {node, found or List.last(aliases) == :Audit}

        node, found ->
          {node, found}
      end)

    found?
  end
end
