defmodule TamanduaServerWeb.AIGatewayHTTPBoundarySourceTest do
  use ExUnit.Case, async: true

  @root Path.expand("../../..", __DIR__)
  @gateway_targets [
    "/api/v1/ai-security/gateway/events",
    "/api/v1/ai-security/gateway/events/batch",
    "/api/v1/ai-security/gateway/evaluate",
    "/api/v1/ai-security/gateway/usage",
    "/api/v1/ai-security/gateway/health",
    "/api/v1/ai-security/gateway/policy"
  ]
  @gateway_actions [
    :gateway_event,
    :gateway_events_batch,
    :gateway_evaluate,
    :gateway_usage,
    :gateway_health,
    :gateway_policy,
    :update_gateway_policy
  ]
  @route_methods [
    :get,
    :post,
    :put,
    :patch,
    :delete,
    :options,
    :head,
    :forward,
    :match,
    :resources
  ]

  test "global AI gateway HTTP surfaces have no exact, alias, or wildcard route" do
    routes = router_routes()

    for target <- @gateway_targets do
      refute Enum.any?(routes, &route_matches?(&1, target)),
             "unexpected route #{target} remains reachable"
    end

    refute Enum.any?(routes, fn route ->
             route.controller == "AISecurityController" and route.action in @gateway_actions
           end)
  end

  test "tenant-scoped AI model REST routes remain registered" do
    routes = router_routes()

    assert_route(routes, :get, "/api/v1/ai-security/models", "AIModelController", :index)
    assert_route(routes, :get, "/api/v1/ai-security/models/stats", "AIModelController", :stats)

    assert_route(
      routes,
      :post,
      "/api/v1/ai-security/models/scan",
      "AIModelController",
      :bulk_scan
    )

    assert_route(
      routes,
      :post,
      "/api/v1/ai-security/models/quarantine",
      "AIModelController",
      :bulk_quarantine
    )

    assert_route(
      routes,
      :post,
      "/api/v1/ai-security/models/block",
      "AIModelController",
      :bulk_block
    )

    assert_route(routes, :get, "/api/v1/ai-security/models/:id", "AIModelController", :show)

    assert_route(
      routes,
      :post,
      "/api/v1/ai-security/models/:id/scan",
      "AIModelController",
      :scan
    )

    assert_route(
      routes,
      :get,
      "/api/v1/ai-security/models/:id/history",
      "AIModelController",
      :history
    )

    assert_route(
      routes,
      :get,
      "/api/v1/ai-security/models/:id/status",
      "AIModelController",
      :status
    )

    assert_route(
      routes,
      :post,
      "/api/v1/ai-security/models/:id/quarantine",
      "AIModelController",
      :quarantine
    )

    assert_route(
      routes,
      :post,
      "/api/v1/ai-security/models/:id/block",
      "AIModelController",
      :block
    )

    assert_route(
      routes,
      :delete,
      "/api/v1/ai-security/models/:id/block",
      "AIModelController",
      :unblock
    )

    assert_route(
      routes,
      :post,
      "/api/v1/ai-security/models/:id/restore",
      "AIModelController",
      :restore
    )
  end

  test "trusted endpoint telemetry retains only the internal gateway call path" do
    endpoint_usage = read("lib/tamandua_server/ai_security/endpoint_usage.ex")

    assert endpoint_usage =~ "AIGateway.ingest_event(attrs)"
    refute endpoint_usage =~ "/api/v1/ai-security/gateway"
  end

  defp router_routes do
    source = read("lib/tamandua_server_web/router.ex")
    ast = Code.string_to_quoted!(source)

    collect_routes(ast, "")
  end

  defp collect_routes({:scope, _, args}, prefix) when is_list(args) do
    {body, scope_args} = scope_body(args)
    scope_prefix = Enum.find(scope_args, "", &is_binary/1)
    collect_routes(body, join_paths(prefix, scope_prefix))
  end

  defp collect_routes({method, _, args}, prefix)
       when method in @route_methods and is_list(args) do
    case literal_route(method, args, prefix) do
      nil -> []
      route -> [route]
    end
  end

  defp collect_routes(list, prefix) when is_list(list),
    do: Enum.flat_map(list, &collect_routes(&1, prefix))

  defp collect_routes(tuple, prefix) when is_tuple(tuple),
    do: tuple |> Tuple.to_list() |> Enum.flat_map(&collect_routes(&1, prefix))

  defp collect_routes(_node, _prefix), do: []

  defp scope_body(args) do
    case List.last(args) do
      opts when is_list(opts) ->
        if Keyword.keyword?(opts) and Keyword.has_key?(opts, :do) do
          {Keyword.fetch!(opts, :do), Enum.drop(args, -1)}
        else
          {nil, args}
        end

      _ ->
        {nil, args}
    end
  end

  defp literal_route(:match, [_verbs, path, controller, action | _], prefix)
       when is_binary(path) do
    %{
      method: :match,
      path: join_paths(prefix, path),
      controller: controller_name(controller),
      action: literal_atom(action),
      prefix: false
    }
  end

  defp literal_route(method, [path, controller, action | _], prefix) when is_binary(path) do
    %{
      method: method,
      path: join_paths(prefix, path),
      controller: controller_name(controller),
      action: literal_atom(action),
      prefix: method in [:forward, :resources]
    }
  end

  defp literal_route(method, [path | _], prefix) when is_binary(path) do
    %{
      method: method,
      path: join_paths(prefix, path),
      controller: nil,
      action: nil,
      prefix: method in [:forward, :resources]
    }
  end

  defp literal_route(_method, _args, _prefix), do: nil

  defp controller_name({:__aliases__, _, parts}), do: parts |> List.last() |> to_string()
  defp controller_name(controller) when is_atom(controller), do: to_string(controller)
  defp controller_name(_controller), do: nil

  defp literal_atom(value) when is_atom(value), do: value
  defp literal_atom(_value), do: nil

  defp route_matches?(route, target) do
    segments_match?(path_segments(route.path), path_segments(target), route.prefix)
  end

  defp segments_match?([], [], _prefix), do: true
  defp segments_match?([], _target, true), do: true
  defp segments_match?(["*" <> _glob | _], _target, _prefix), do: true

  defp segments_match?([":" <> _param | patterns], [_value | target], prefix),
    do: segments_match?(patterns, target, prefix)

  defp segments_match?([segment | patterns], [segment | target], prefix),
    do: segments_match?(patterns, target, prefix)

  defp segments_match?(_patterns, _target, _prefix), do: false

  defp path_segments(path), do: String.split(path, "/", trim: true)

  defp join_paths("", path), do: path
  defp join_paths(prefix, ""), do: prefix

  defp join_paths(prefix, path),
    do: String.trim_trailing(prefix, "/") <> "/" <> String.trim_leading(path, "/")

  defp assert_route(routes, method, path, controller, action) do
    assert Enum.any?(routes, fn route ->
             route.method == method and route_matches?(route, path) and
               route.controller == controller and route.action == action
           end), "expected #{method} #{path} to remain registered"
  end

  defp read(relative), do: File.read!(Path.join(@root, relative))
end
