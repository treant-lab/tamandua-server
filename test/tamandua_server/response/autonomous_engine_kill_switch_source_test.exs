defmodule TamanduaServer.Response.AutonomousEngineKillSwitchSourceTest do
  use ExUnit.Case, async: true

  @source_path Path.expand(
                 "../../../lib/tamandua_server/response/autonomous_engine.ex",
                 __DIR__
               )

  setup_all do
    source = File.read!(@source_path)
    {:ok, ast} = Code.string_to_quoted(source)
    {:ok, ast: ast}
  end

  test "pipeline admits only enabled automatic modes", %{ast: ast} do
    pipeline = function_source(ast, :execute_pipeline, 3)

    assert occurrences(pipeline, "autonomous_execution_enabled?()") == 2
    assert occurrences(pipeline, "automatic_execution_blocked(actions, mode)") == 2
    assert pipeline =~ ":auto_execute"
    assert pipeline =~ ":auto_with_notify"
    assert pipeline =~ ~s(status: "awaiting_analyst")
    assert pipeline =~ ~s(status: "alert_only")
    assert pipeline =~ "notify_analysts(alert, actions, [])"
  end

  test "dispatch recheck and product switch fail closed", %{ast: ast} do
    action = function_source(ast, :execute_action, 3)
    guarded_dispatch = function_source(ast, :execute_if_enabled, 3)
    switch = function_source(ast, :autonomous_execution_enabled?, 0)

    assert occurrences(action, "execute_if_enabled(") == 4
    assert occurrences(action, "Executor.") == 4
    assert guarded_dispatch =~ "autonomous_execution_enabled?()"
    assert guarded_dispatch =~ "executor.()"

    assert position(guarded_dispatch, "autonomous_execution_enabled?()") <
             position(guarded_dispatch, "executor.()")

    assert switch =~
             "Application.get_env(:tamandua_server, :autonomous_execution_enabled, false) === true"

    assert switch =~ "rescue"
    assert switch =~ "catch"
  end

  defp function_source(ast, name, arity) do
    {_ast, definition} =
      Macro.prewalk(ast, nil, fn
        {:defp, _, [{^name, _, args}, _clauses]} = node, nil ->
          if length(args || []) == arity, do: {node, node}, else: {node, nil}

        node, acc ->
          {node, acc}
      end)

    assert definition != nil
    Macro.to_string(definition)
  end

  defp occurrences(source, needle), do: length(String.split(source, needle)) - 1

  defp position(source, needle) do
    {position, _length} = :binary.match(source, needle)
    position
  end
end
