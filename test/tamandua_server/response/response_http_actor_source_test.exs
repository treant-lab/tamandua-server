defmodule TamanduaServer.Response.ResponseHTTPActorSourceTest do
  use ExUnit.Case, async: true

  @response_controller Path.expand(
                         "../../../lib/tamandua_server_web/controllers/api/v1/response_controller.ex",
                         __DIR__
                       )
  @agent_controller Path.expand(
                      "../../../lib/tamandua_server_web/controllers/api/v1/agent_controller.ex",
                      __DIR__
                    )

  test "only the selected six HTTP actions build a tenant-bound response actor" do
    assert actor_functions(@response_controller) ==
             MapSet.new([:collect_artifact, :scan_path, :block_ip, :unblock_ip])

    assert actor_functions(@agent_controller) == MapSet.new([:isolate, :unisolate])
  end

  test "each selected Executor call carries the validated actor" do
    response = parsed_source(@response_controller)
    agent = parsed_source(@agent_controller)

    assert function_source(response, :collect_artifact) =~
             "Executor.collect_artifact(agent_id, path, artifact_type, actor: actor)"

    assert function_source(response, :scan_path) =~
             "Executor.scan_path(agent_id, path, Keyword.put(opts, :actor, actor))"

    assert function_source(response, :block_ip) =~
             ~s|Executor.execute_action(agent_id, "block_ip", payload, actor: actor)|

    assert function_source(response, :unblock_ip) =~
             ~s|Executor.execute_action(agent_id, "unblock_ip", payload, actor: actor)|

    assert function_source(agent, :isolate) =~
             "TamanduaServer.Response.Executor.isolate_network(id,"

    assert function_source(agent, :isolate) =~ "actor: actor"

    assert function_source(agent, :unisolate) =~
             "TamanduaServer.Response.Executor.unisolate_network(id, actor: actor)"
  end

  test "existing tenant lookup and RBAC remain ahead of the six dispatches" do
    response = parsed_source(@response_controller)
    agent = parsed_source(@agent_controller)

    for action <- [:collect_artifact, :scan_path, :block_ip, :unblock_ip] do
      source = function_source(response, action)
      assert source =~ "authorize_agent!(conn, agent_id)"
      assert source =~ "ResponseActor.from_user_scope(user, current_organization_id(conn))"
    end

    for action <- [:isolate, :unisolate] do
      source = function_source(agent, action)
      assert source =~ "authorize_agent!(conn, id)"
      assert source =~ "authorize_response_isolate(conn)"
      assert source =~ "ResponseActor.from_user_scope(user, current_organization_id(conn))"

      assert call_position(source, "authorize_response_isolate(conn)") <
               call_position(source, "authorize_agent!(conn, id)")

      assert call_position(source, "authorize_response_isolate(conn)") <
               call_position(source, "conn.assigns[:current_user]")

      assert call_position(source, "authorize_response_isolate(conn)") <
               call_position(source, "mobile_agent?(agent)")

      assert call_position(source, "authorize_response_isolate(conn)") <
               call_position(source, "ResponseActor.from_user_scope")

      assert call_position(source, "authorize_response_isolate(conn)") <
               call_position(source, "TamanduaServer.Response.Executor.")
    end

    response_source = Macro.to_string(response)
    assert response_source =~ "TamanduaServerWeb.Plugs.Authorize"
    assert response_source =~ ":response_contain"
    assert response_source =~ ":block_ip"
    assert response_source =~ ":unblock_ip"
    assert response_source =~ ":response_execute"
    assert response_source =~ ":collect_artifact"
    assert response_source =~ ":scan_path"
  end

  defp actor_functions(path) do
    path
    |> parsed_source()
    |> collect_defs_with_actor()
  end

  defp collect_defs_with_actor(ast) do
    {_ast, functions} =
      Macro.prewalk(ast, MapSet.new(), fn
        {:def, _meta, [{name, _, _args}, [do: body]]} = node, acc ->
          if Macro.to_string(body) =~ "ResponseActor.from_user_scope" do
            {node, MapSet.put(acc, name)}
          else
            {node, acc}
          end

        node, acc ->
          {node, acc}
      end)

    functions
  end

  defp function_source(ast, name) do
    {_ast, bodies} =
      Macro.prewalk(ast, [], fn
        {:def, _meta, [{^name, _, _args}, [do: body]]} = node, acc -> {node, [body | acc]}
        node, acc -> {node, acc}
      end)

    case bodies do
      [body] -> Macro.to_string(body)
      other -> flunk("expected one #{name}/2 definition, got #{length(other)}")
    end
  end

  defp parsed_source(path) do
    path
    |> File.read!()
    |> Code.string_to_quoted!()
  end

  defp call_position(source, call) do
    case :binary.match(source, call) do
      {position, _length} -> position
      :nomatch -> flunk("expected #{inspect(call)} in function source")
    end
  end
end
