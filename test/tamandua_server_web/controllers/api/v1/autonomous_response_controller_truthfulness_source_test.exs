defmodule TamanduaServerWeb.API.V1.AutonomousResponseControllerTruthfulnessSourceTest do
  use ExUnit.Case, async: true

  @source_path Path.expand(
                 "../../../../../lib/tamandua_server_web/controllers/api/v1/autonomous_response_controller.ex",
                 __DIR__
               )

  setup_all do
    source = File.read!(@source_path)
    {:ok, ast} = Code.string_to_quoted(source)
    {:ok, source: source, ast: ast}
  end

  test "emergency endpoints use only the decision engine control plane", %{
    source: source,
    ast: ast
  } do
    disable = function_source(ast, :emergency_disable, 2)
    enable = function_source(ast, :emergency_enable, 2)

    refute source =~ "AutonomousResponseInterlock"
    assert disable =~ "DecisionEngine.emergency_disable(org_id, reason)"
    assert enable =~ "DecisionEngine.emergency_enable(org_id, approver_id)"
    refute disable =~ "AutonomousEngine"
    refute enable =~ "AutonomousEngine"
  end

  test "success is emitted only for :ok and locked enable remains locked", %{ast: ast} do
    disable = function_source(ast, :emergency_disable, 2)
    enable = function_source(ast, :emergency_enable, 2)

    assert disable =~ "case DecisionEngine.emergency_disable(org_id, reason)"
    assert disable =~ ":ok ->"
    assert disable =~ "put_status(:service_unavailable)"
    refute disable =~ "inspect(reason)"

    assert enable =~ "case DecisionEngine.emergency_enable(org_id, approver_id)"
    assert enable =~ "{:error, :autonomous_response_locked}"
    assert enable =~ "put_status(:locked)"
    assert enable =~ "put_status(:service_unavailable)"
    refute enable =~ "inspect(reason)"
    refute enable =~ "DecisionEngine.emergency_disable"
  end

  defp function_source(ast, name, arity) do
    {_ast, definition} =
      Macro.prewalk(ast, nil, fn
        {:def, _, [{^name, _, args}, _clauses]} = node, nil ->
          if length(args || []) == arity, do: {node, node}, else: {node, nil}

        node, acc ->
          {node, acc}
      end)

    assert definition != nil
    Macro.to_string(definition)
  end
end
