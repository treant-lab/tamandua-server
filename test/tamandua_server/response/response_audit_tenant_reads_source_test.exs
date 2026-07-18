defmodule TamanduaServer.Response.ResponseAuditTenantReadsSourceTest do
  use ExUnit.Case, async: true

  @audit_path Path.expand("../../../lib/tamandua_server/response/audit.ex", __DIR__)

  @controller_path Path.expand(
                     "../../../lib/tamandua_server_web/controllers/api/v1/response_audit_controller.ex",
                     __DIR__
                   )

  test "audit read APIs require explicit organization scope and legacy arities fail closed" do
    source = File.read!(@audit_path)

    assert source =~ "def get_actions_for_agent(organization_id, agent_id, opts)"
    assert source =~ "def get_recent_actions(organization_id, opts)"
    assert source =~ "def get_action_counts(organization_id, opts)"
    assert source =~ "def get_actions_for_alert(organization_id, alert_id, opts)"
    assert source =~ "def search_by_details(organization_id, field, value, opts)"

    assert source =~
             "def get_actions_for_agent(_agent_id, _opts), do: {:error, :organization_scope_required}"

    assert source =~
             "def get_recent_actions(_opts), do: {:error, :organization_scope_required}"

    assert source =~
             "def get_action_counts(_opts), do: {:error, :organization_scope_required}"

    assert source =~
             "def search_by_details(_field, _value, _opts), do: {:error, :organization_scope_required}"

    assert source =~
             "def get_actions_for_agent(_agent_id), do: {:error, :organization_scope_required}"

    assert source =~ "def get_recent_actions, do: {:error, :organization_scope_required}"
    assert source =~ "def get_action_counts, do: {:error, :organization_scope_required}"

    assert source =~
             "def get_actions_for_alert(_alert_id, _organization_id),"

    assert source =~
             "def search_by_details(_field, _value), do: {:error, :organization_scope_required}"
  end

  test "every selected read starts with an explicit organization predicate and tenant transaction" do
    source = File.read!(@audit_path)

    assert length(Regex.scan(~r/tenant_read\(organization_id, fn ->/, source)) >= 5
    assert source =~ "a.organization_id == ^organization_id and a.agent_id == ^agent_id"
    assert length(Regex.scan(~r/a\.organization_id == \^organization_id/, source)) >= 5
    assert source =~ ~s|fragment("?->>'alert_id' = ?", a.details, ^alert_id)|
    refute source =~ "maybe_filter_organization"
    refute source =~ "with_bypass"
  end

  test "pagination, filters, and JSON detail search have hard input bounds" do
    source = File.read!(@audit_path)

    for contract <- [
          "@max_limit 500",
          "@max_offset 10_000",
          "@max_action_type_bytes 128",
          "@max_search_field_bytes 64",
          "@max_search_value_bytes 2_048",
          "bounded_integer",
          "canonical_search_field",
          "canonical_search_value",
          "valid_time_range"
        ] do
      assert source =~ contract
    end

    assert source =~
             "allowed = [:limit, :offset, :action_type, :agent_id, :actor_type, :from, :to]"
  end

  test "controller derives organization only from authenticated assigns" do
    source = File.read!(@controller_path)

    assert source =~ "current_organization_id(conn)"
    assert source =~ "Audit.get_recent_actions(organization_id, opts)"
    assert source =~ "Audit.get_actions_for_agent(organization_id, agent_id, opts)"
    assert source =~ "Audit.get_action_counts(organization_id, opts)"
    assert source =~ "Audit.get_actions_for_alert(organization_id, alert_id, [])"
    assert source =~ "Audit.search_by_details(organization_id, field, value, opts)"
    assert source =~ "{:ok, opts} <- build_filter_opts"
    assert source =~ "normalize_audit_read_result"
    assert source =~ "{:error, :audit_query_failed}"
    assert source =~ "do: {:error, :service_unavailable}"
    assert source =~ ":invalid_alert_id"
    assert source =~ "{:error, :invalid_query_parameter} -> {:error, :invalid_params}"
    refute source =~ ~s(params["organization_id"])
    refute source =~ ~s(params["org_id"])
  end

  test "changed sources remain valid Elixir AST" do
    assert {:ok, _ast} = @audit_path |> File.read!() |> Code.string_to_quoted()
    assert {:ok, _ast} = @controller_path |> File.read!() |> Code.string_to_quoted()
  end
end
