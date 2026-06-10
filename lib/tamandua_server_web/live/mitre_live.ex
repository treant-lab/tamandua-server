defmodule TamanduaServerWeb.MitreLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Detection.Mitre

  @impl true
  def mount(_params, _session, socket) do
    # Fetch real coverage data from alerts
    coverage = Mitre.calculate_coverage(days: 30)

    # Convert severity atoms to strings for UI
    coverage_formatted =
      coverage
      |> Enum.map(fn {tech_id, data} ->
        {tech_id, %{count: data.count, severity: to_string(data.severity)}}
      end)
      |> Map.new()

    tactics =
      Mitre.list_tactics()
      |> Enum.map(fn t -> {t.shortname, t.name} end)

    {:ok,
     socket
     |> assign(page_title: "MITRE ATT&CK Matrix")
     |> assign(tactics: tactics)
     |> assign(coverage: coverage_formatted)
     |> assign(selected_technique: nil)
    }
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 overflow-x-auto">
      <h1 class="text-2xl font-bold mb-6">MITRE ATT&CK Coverage</h1>

      <div class="min-w-max">
        <div class="grid grid-flow-col auto-cols-max gap-4">
          <%= for {tactic_id, tactic_name} <- @tactics do %>
            <div class="w-48 flex flex-col gap-2">
              <div class="bg-gray-100 dark:bg-gray-700 p-3 rounded text-center font-bold text-sm h-16 flex items-center justify-center">
                <%= tactic_name %>
              </div>

              <div class="space-y-2">
                <%= for technique <- get_techniques(tactic_id) do %>
                  <% coverage = @coverage[technique.id] %>
                  <div class={"p-2 text-xs border rounded cursor-pointer transition-colors #{coverage_class(coverage)}"}
                       title={"#{technique.id}: #{technique.name}"}>
                    <div class="font-bold"><%= technique.id %></div>
                    <div class="truncate"><%= technique.name %></div>
                    <%= if coverage do %>
                      <div class="mt-1 flex justify-between items-center">
                        <span class="text-[10px] uppercase"><%= coverage.severity %></span>
                        <span class="bg-white/20 px-1 rounded"><%= coverage.count %></span>
                      </div>
                    <% end %>
                  </div>
                <% end %>
              </div>
            </div>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  defp coverage_class(nil), do: "bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700"
  defp coverage_class(%{severity: "critical"}), do: "bg-red-500 text-white border-red-600"
  defp coverage_class(%{severity: "high"}), do: "bg-orange-500 text-white border-orange-600"
  defp coverage_class(%{severity: "medium"}), do: "bg-yellow-500 text-white border-yellow-600"
  defp coverage_class(%{severity: "low"}), do: "bg-blue-500 text-white border-blue-600"

  # Get techniques from the real MITRE module
  defp get_techniques(tactic_shortname) do
    Mitre.get_techniques_for_tactic(tactic_shortname)
    |> Enum.reject(& &1.is_subtechnique)  # Only show parent techniques in matrix view
    |> Enum.map(fn t -> %{id: t.id, name: t.name} end)
  end
end
