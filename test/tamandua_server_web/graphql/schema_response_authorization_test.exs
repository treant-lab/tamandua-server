defmodule TamanduaServerWeb.GraphQL.SchemaResponseAuthorizationTest do
  use ExUnit.Case, async: true

  @schema_path Path.expand("../../../lib/tamandua_server_web/graphql/schema.ex", __DIR__)
  @agent_resolver_path Path.expand(
                         "../../../lib/tamandua_server_web/graphql/resolvers/agent_resolver.ex",
                         __DIR__
                       )
  @response_resolver_path Path.expand(
                            "../../../lib/tamandua_server_web/graphql/resolvers/response_resolver.ex",
                            __DIR__
                          )
  @audit_path Path.expand("../../../lib/tamandua_server/response/audit.ex", __DIR__)
  @response_path Path.expand("../../../lib/tamandua_server/response.ex", __DIR__)
  @audit_controller_path Path.expand(
                           "../../../lib/tamandua_server_web/controllers/api/v1/response_audit_controller.ex",
                           __DIR__
                         )

  test "response and agent mutations declare least-privilege authorization" do
    schema = File.read!(@schema_path)

    assert_field_permission(schema, "kill_process", "response_contain")
    assert_field_permission(schema, "quarantine_file", "response_contain")
    assert_field_permission(schema, "isolate_host", "response_isolate")
    assert_field_permission(schema, "unisolate_host", "response_isolate")
    assert_field_permission(schema, "block_ip", "response_contain")
    assert_field_permission(schema, "block_domain", "response_contain")
    assert_field_permission(schema, "scan_path", "response_execute")
    assert_field_permission(schema, "collect_forensics", "forensics_collect")
    assert_field_permission(schema, "isolate_agent", "response_isolate")
    assert_field_permission(schema, "unisolate_agent", "response_isolate")
    assert_field_permission(schema, "restart_agent", "agents_command")
  end

  test "restart verifies the target belongs to the request organization before sending" do
    resolver = File.read!(@agent_resolver_path)

    restart_block =
      Regex.run(~r/def restart_agent.*?\n  end/s, resolver)
      |> List.first()

    assert restart_block =~ "context[:organization_id]"
    assert restart_block =~ "Agents.get_agent_for_org(organization_id, agent_id)"
    assert restart_block =~ "Agents.send_command(agent_id"

    assert :binary.match(restart_block, "Agents.get_agent_for_org") <
             :binary.match(restart_block, "Agents.send_command")
  end

  test "response audit and nested identities are tenant scoped" do
    resolver = File.read!(@response_resolver_path)
    audit = File.read!(@audit_path)
    response = File.read!(@response_path)
    controller = File.read!(@audit_controller_path)

    assert resolver =~ "Response.list_actions(%{"
    assert resolver =~ "organization_id: context[:organization_id]"
    assert resolver =~ "Repo.get_by(Alert,"
    assert resolver =~ "Repo.get_by(User,"
    assert resolver =~ "alert_id_for_org(input[:alert_id], actor.organization_id)"
    refute resolver =~ "Audit.get_actions_for_alert"
    refute resolver =~ "Repo.get(Alert, action.alert_id)"

    assert audit =~ "def get_actions_for_alert(organization_id, alert_id, opts)"

    assert audit =~
             "def get_actions_for_alert(_alert_id, _organization_id),"

    assert audit =~ "a.organization_id == ^organization_id"
    assert audit =~ "|> apply_filters(opts)"

    assert response =~ "def list_actions(_filters), do: []"
    assert response =~ "where: a.organization_id == ^organization_id"

    assert controller =~ "plug(TamanduaServerWeb.Plugs.RBAC, permission: :response_view)"
    assert controller =~ "current_organization_id(conn)"
    assert controller =~ "build_filter_opts(params)"
    refute controller =~ "params[\"organization_id\"]"
  end

  defp assert_field_permission(schema, field, permission) do
    field_block =
      Regex.run(~r/field :#{field},.*?\n    end/s, schema)
      |> List.first()

    assert field_block =~
             "middleware(TamanduaServerWeb.GraphQL.Middleware.Authorization, :#{permission})"
  end
end
