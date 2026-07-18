defmodule TamanduaServerWeb.AIModelTenantBoundarySourceTest do
  use ExUnit.Case, async: true

  @root Path.expand("../../..", __DIR__)

  test "AI model routes have exact read and containment permissions" do
    source = read("lib/tamandua_server_web/controllers/api/v1/ai_model_controller.ex")

    assert source =~ "permission: :ai_investigate"
    assert source =~ "permission: :response_contain"

    assert source =~
             "when action in [:index, :show, :scan, :bulk_scan, :history, :stats, :status]"

    assert source =~
             "when action in [:quarantine, :block, :unblock, :restore, :bulk_quarantine, :bulk_block]"
  end

  test "inventory reads fail closed without an explicit organization" do
    source = read("lib/tamandua_server/ai_security/ai_inventory.ex")

    assert source =~ "def list_inventory, do: {:error, :organization_scope_required}"
    assert source =~ "def stats, do: {:error, :organization_scope_required}"
    assert source =~ "def assess_risk(_component_id), do: {:error, :organization_scope_required}"
    assert source =~ "%{organization_id: ^organization_id} = comp"
  end

  test "containment requires actor, intent audit, tenant revalidation and governed executor" do
    source = read("lib/tamandua_server/ai_security/response_actions.ex")

    assert source =~ "{:error, :actor_scope_required}"
    assert source =~ "Audit.log_action("
    assert source =~ "action <> \".intent\""
    assert source =~ "Agents.get_agent_for_org(context.organization_id"
    assert source =~ "AIInventory.assess_risk(context.organization_id, context.model_id)"
    assert source =~ "Executor.execute_action(current_agent.id"
    assert source =~ "persist_action: true"
    refute source =~ "Agents.send_command"
  end

  test "all valid and malformed bulk clauses fail closed before any side effect" do
    source = read("lib/tamandua_server_web/controllers/api/v1/ai_model_controller.ex")
    ast = Code.string_to_quoted!(source)

    for action <- [:bulk_scan, :bulk_quarantine, :bulk_block] do
      clauses = function_clauses(ast, action)
      assert length(clauses) == 2

      assert Enum.all?(clauses, fn body ->
               match?({:bulk_action_unavailable, _, [{:conn, _, nil}]}, body)
             end)
    end

    assert source =~ "put_status(:service_unavailable)"
    assert source =~ ~s(code: "bulk_action_unavailable")
    assert source =~ "retryable: false"
    refute source =~ "ensure_bulk_models!"
    refute source =~ "bounded_model_ids!"
  end

  test "model block creation validates the endpoint in the same tenant" do
    source = read("lib/tamandua_server/ai_security/model_block.ex")

    assert source =~ "Agents.get_agent_for_org(organization_id, agent_id)"

    assert source =~
             "where([b], b.model_id == ^model_id and b.organization_id == ^organization_id)"
  end

  defp read(relative), do: File.read!(Path.join(@root, relative))

  defp function_clauses(ast, name) do
    {_ast, clauses} =
      Macro.prewalk(ast, [], fn
        {:def, _, [head, [do: body]]} = node, acc ->
          if function_name(head) == name, do: {node, [body | acc]}, else: {node, acc}

        node, acc ->
          {node, acc}
      end)

    Enum.reverse(clauses)
  end

  defp function_name({:when, _, [head | _guards]}), do: function_name(head)
  defp function_name({name, _, _args}) when is_atom(name), do: name
  defp function_name(_head), do: nil
end
