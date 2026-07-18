defmodule TamanduaServerWeb.GraphQL.SchemaTenantAuthorizationTest do
  use ExUnit.Case, async: true

  @root Path.expand("../../..", __DIR__)

  test "identity, telemetry, and threat-intel roots declare explicit permissions" do
    schema = File.read!(Path.join(@root, "lib/tamandua_server_web/graphql/schema.ex"))

    mappings = [
      user: :users_read,
      users: :users_read,
      organization: :organization_read,
      dashboard_stats: :dashboard_read,
      agents: :agents_read,
      agent: :agents_read,
      agent_stats: :agents_read,
      events: :events_read,
      event: :events_read,
      event_stats: :events_read,
      search_events: :events_search,
      response_audit: :response_view,
      iocs: :threat_intel_read,
      ioc: :threat_intel_read,
      campaigns: :threat_intel_read,
      mitre_coverage: :threat_intel_read,
      mitre_technique: :threat_intel_read,
      create_ioc: :threat_intel_add,
      bulk_import_iocs: :threat_intel_add,
      delete_ioc: :threat_intel_manage,
      enrich_ioc: :threat_intel_read,
      create_user: :users_create,
      update_user: :users_update,
      delete_user: :users_delete,
      assign_role: :users_role_assign,
      revoke_role: :users_role_assign
    ]

    Enum.each(mappings, fn {field, permission} ->
      assert_field_permission(schema, field, permission)
    end)

    assert_system_operator_permission(schema, :organizations, :system_all)
    assert_system_operator_permission(schema, :threat_actors, :threat_intel_read)
    assert_system_operator_permission(schema, :threat_actor, :threat_intel_read)
    assert_system_operator_permission(schema, :threat_intel_summary, :threat_intel_read)
    assert_system_operator_permission(schema, :create_threat_actor, :threat_intel_manage)
    assert_system_operator_permission(schema, :sync_threat_feeds, :threat_intel_manage)
  end

  test "identity and threat evidence resolvers retain tenant predicates" do
    user_resolver =
      File.read!(Path.join(@root, "lib/tamandua_server_web/graphql/resolvers/user_resolver.ex"))

    threat_resolver =
      File.read!(
        Path.join(@root, "lib/tamandua_server_web/graphql/resolvers/threat_intel_resolver.ex")
      )

    assert user_resolver =~ "a.organization_id == ^org_id"
    assert user_resolver =~ "role_available_to_org?"
    assert user_resolver =~ "Accounts.get_role(role_id)"
    assert user_resolver =~ "Accounts.user_can?(caller, :users_role_assign)"
    refute user_resolver =~ "Authorization.RBAC.get_role(role_id)"

    assert schema_user_role_guards?()

    assert threat_resolver =~ "i.organization_id == ^org_id"
    assert threat_resolver =~ "a.organization_id == ^org_id"
    assert threat_resolver =~ "get_scoped_ioc"
    assert threat_resolver =~ "ThreatActor.get_for_organization(organization_id, actor_id)"

    assert threat_resolver =~
             "ThreatActor.get_by_name_for_organization(organization_id, actor_name)"

    refute threat_resolver =~ "{:ok, ThreatActor.get(actor_id)}"
    assert threat_resolver =~ "IOCs.create_ioc(attrs)"
    assert threat_resolver =~ "i.enabled == ^is_active"
    assert threat_resolver =~ "length(iocs) > 100"
    refute threat_resolver =~ "i.is_active == ^is_active"
  end

  defp schema_user_role_guards? do
    schema = File.read!(Path.join(@root, "lib/tamandua_server_web/graphql/schema.ex"))

    create_user_block =
      Regex.run(~r/field :create_user,.*?resolve\(&UserResolver.create_user\/3\)/s, schema)
      |> List.first()

    update_user_block =
      Regex.run(~r/field :update_user,.*?resolve\(&UserResolver.update_user\/3\)/s, schema)
      |> List.first()

    Enum.all?([create_user_block, update_user_block], fn block ->
      block =~ "{:users_role_assign, [:input, :role]}"
    end)
  end

  defp assert_field_permission(schema, field, permission) do
    field_block =
      Regex.run(~r/field :#{field},.*?\n    end/s, schema)
      |> List.first()

    assert field_block =~
             "middleware(TamanduaServerWeb.GraphQL.Middleware.Authorization, :#{permission})"
  end

  defp assert_system_operator_permission(schema, field, permission) do
    field_block =
      Regex.run(~r/field :#{field},.*?\n    end/s, schema)
      |> List.first()

    assert field_block =~ "TamanduaServerWeb.GraphQL.Middleware.SystemOperatorAuthorization"
    assert field_block =~ ":#{permission}"
  end
end
