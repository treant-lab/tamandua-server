defmodule TamanduaServerWeb.Components.ProcessTreeComponent do
  use TamanduaServerWeb, :live_component

  def render(assigns) do
    ~H"""
    <div class="process-tree">
      <h3 class="text-lg font-semibold mb-4">Process Genealogy</h3>

      <%= if @graph do %>
        <div class="overflow-x-auto">
          <%= render_tree(@graph) %>
        </div>
      <% else %>
        <div class="text-gray-500 italic">No process data available</div>
      <% end %>
    </div>
    """
  end

  defp render_tree(graph) do
    # Find root nodes (nodes with no incoming edges)
    roots = find_roots(graph)

    assigns = %{graph: graph, roots: roots}

    ~H"""
    <ul class="tree-list pl-4">
      <%= for root <- @roots do %>
        <%= render_node(%{graph: @graph, node: root}) %>
      <% end %>
    </ul>
    """
  end

  defp render_node(assigns) do
    node_id = assigns.node
    graph = assigns.graph

    # Get node details
    labels = Graph.vertex_labels(graph, node_id)
    info = List.first(labels) || %{}

    # Get children
    children = Graph.out_neighbors(graph, node_id)

    assigns = Map.merge(assigns, %{
      info: info,
      children: children,
      node_id: node_id
    })

    ~H"""
    <li class="mb-2">
      <div class="flex items-center gap-2 p-2 rounded hover:bg-gray-100 dark:hover:bg-gray-700 border border-gray-200 dark:border-gray-600">
        <span class="font-mono text-sm bg-gray-200 dark:bg-gray-600 px-1 rounded">
          <%= @node_id %>
        </span>
        <span class="font-semibold"><%= @info[:name] || "Unknown" %></span>
        <span class="text-xs text-gray-500"><%= @info[:path] %></span>

        <%= if @info[:user] do %>
          <span class="text-xs bg-blue-100 text-blue-800 px-1 rounded ml-auto">
            <%= @info[:user] %>
          </span>
        <% end %>
      </div>

      <%= if length(@children) > 0 do %>
        <ul class="pl-6 border-l-2 border-gray-300 dark:border-gray-600 ml-2 mt-1">
          <%= for child <- @children do %>
            <%= render_node(%{graph: @graph, node: child}) %>
          <% end %>
        </ul>
      <% end %>
    </li>
    """
  end

  defp find_roots(graph) do
    # A root is a vertex with in-degree 0
    Graph.vertices(graph)
    |> Enum.filter(fn v -> Graph.in_degree(graph, v) == 0 end)
  end
end
