defmodule TamanduaServerWeb.MlRuleReviewLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.MlRules.Generator
  alias TamanduaServer.MlRules.MlRule

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "ML Rule Review")}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, _params) do
    pending_rules = Generator.list_ml_rules(%{approved: false})
    approved_rules = Generator.list_ml_rules(%{approved: true})

    socket
    |> assign(:page_title, "ML Rule Review")
    |> assign(:pending_rules, pending_rules)
    |> assign(:approved_rules, approved_rules)
    |> assign(:selected_rule, nil)
    |> assign(:show_detail_modal, false)
    |> assign(:current_tab, "pending")
  end

  defp apply_action(socket, :show, %{"id" => id}) do
    rule = Generator.get_ml_rule(id)

    socket
    |> assign(:page_title, "Rule Details")
    |> assign(:selected_rule, rule)
    |> assign(:show_detail_modal, true)
    |> assign(:pending_rules, Generator.list_ml_rules(%{approved: false}))
    |> assign(:approved_rules, Generator.list_ml_rules(%{approved: true}))
    |> assign(:current_tab, "pending")
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold">ML-Generated Rule Review</h1>
        <div class="flex gap-2">
          <span class="px-3 py-1 bg-yellow-100 text-yellow-800 rounded-full text-sm font-medium">
            <%= length(@pending_rules) %> Pending
          </span>
          <span class="px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm font-medium">
            <%= length(@approved_rules) %> Approved
          </span>
        </div>
      </div>

      <!-- Tabs -->
      <div class="mb-6 border-b border-gray-200 dark:border-gray-700">
        <nav class="flex space-x-8">
          <button phx-click="switch_tab" phx-value-tab="pending" class={tab_class(@current_tab == "pending")}>
            Pending Review (<%= length(@pending_rules) %>)
          </button>
          <button phx-click="switch_tab" phx-value-tab="approved" class={tab_class(@current_tab == "approved")}>
            Approved (<%= length(@approved_rules) %>)
          </button>
        </nav>
      </div>

      <!-- Pending Rules Table -->
      <%= if @current_tab == "pending" do %>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead class="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Rule</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Type</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Hunt Campaign</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Metrics</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Confidence</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              <%= for rule <- @pending_rules do %>
                <tr>
                  <td class="px-6 py-4">
                    <div class="text-sm font-medium text-gray-900 dark:text-white"><%= rule.name %></div>
                    <div class="text-sm text-gray-500 dark:text-gray-400"><%= rule.rule_id %></div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class={type_badge_class(rule.rule_type)}>
                      <%= rule.rule_type %>
                    </span>
                  </td>
                  <td class="px-6 py-4">
                    <div class="text-sm text-gray-900 dark:text-white"><%= rule.hunt_campaign || "N/A" %></div>
                    <div class="text-xs text-gray-500 dark:text-gray-400"><%= rule.finding_count || 0 %> findings</div>
                  </td>
                  <td class="px-6 py-4">
                    <%= if rule.validation_passed do %>
                      <div class="text-sm">
                        <div class="flex items-center gap-2">
                          <span class="text-green-600 dark:text-green-400">✓</span>
                          <span class="text-gray-900 dark:text-white">Precision: <%= format_metric(rule.precision) %></span>
                        </div>
                        <div class="flex items-center gap-2">
                          <span class="text-green-600 dark:text-green-400">✓</span>
                          <span class="text-gray-900 dark:text-white">Recall: <%= format_metric(rule.recall) %></span>
                        </div>
                      </div>
                    <% else %>
                      <span class="text-yellow-600 dark:text-yellow-400 text-sm">Not validated</span>
                    <% end %>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="flex items-center">
                      <div class="w-16 bg-gray-200 rounded-full h-2 dark:bg-gray-700">
                        <div class={confidence_bar_class(rule.confidence_score)} style={"width: #{(rule.confidence_score || 0) * 100}%"}></div>
                      </div>
                      <span class="ml-2 text-sm text-gray-600 dark:text-gray-400"><%= format_percentage(rule.confidence_score) %></span>
                    </div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <button phx-click="view_rule" phx-value-id={rule.id} class="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300 mr-3">View</button>
                    <button phx-click="approve_rule" phx-value-id={rule.id} class="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300 mr-3">Approve</button>
                    <button phx-click="reject_rule" phx-value-id={rule.id} class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300">Reject</button>
                  </td>
                </tr>
              <% end %>
              <%= if length(@pending_rules) == 0 do %>
                <tr>
                  <td colspan="6" class="px-6 py-4 text-center text-gray-500">No pending rules for review</td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>
      <% end %>

      <!-- Approved Rules Table -->
      <%= if @current_tab == "approved" do %>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead class="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Rule</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Type</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Status</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Approved</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Performance</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              <%= for rule <- @approved_rules do %>
                <tr>
                  <td class="px-6 py-4">
                    <div class="text-sm font-medium text-gray-900 dark:text-white"><%= rule.name %></div>
                    <div class="text-sm text-gray-500 dark:text-gray-400"><%= rule.rule_id %></div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span class={type_badge_class(rule.rule_type)}>
                      <%= rule.rule_type %>
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <%= if rule.enabled do %>
                      <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Active</span>
                    <% else %>
                      <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">Inactive</span>
                    <% end %>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    <%= if rule.approved_at do %>
                      <%= Calendar.strftime(rule.approved_at, "%Y-%m-%d %H:%M") %>
                    <% else %>
                      N/A
                    <% end %>
                  </td>
                  <td class="px-6 py-4">
                    <div class="text-sm">
                      <div class="text-gray-900 dark:text-white">P: <%= format_metric(rule.precision) %> | R: <%= format_metric(rule.recall) %></div>
                      <div class="text-gray-500 dark:text-gray-400">F1: <%= format_metric(rule.f1_score) %></div>
                    </div>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <button phx-click="view_rule" phx-value-id={rule.id} class="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300 mr-3">View</button>
                    <%= if rule.enabled do %>
                      <button phx-click="disable_rule" phx-value-id={rule.id} class="text-yellow-600 hover:text-yellow-900 dark:text-yellow-400 dark:hover:text-yellow-300">Disable</button>
                    <% else %>
                      <button phx-click="enable_rule" phx-value-id={rule.id} class="text-green-600 hover:text-green-900 dark:text-green-400 dark:hover:text-green-300">Enable</button>
                    <% end %>
                  </td>
                </tr>
              <% end %>
              <%= if length(@approved_rules) == 0 do %>
                <tr>
                  <td colspan="6" class="px-6 py-4 text-center text-gray-500">No approved rules</td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>
      <% end %>

      <!-- Detail Modal -->
      <%= if @show_detail_modal && @selected_rule do %>
        <div class="fixed z-10 inset-0 overflow-y-auto">
          <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" phx-click="close_modal"></div>
            <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-4xl sm:w-full">
              <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                <div class="flex items-center justify-between mb-4">
                  <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white"><%= @selected_rule.name %></h3>
                  <button phx-click="close_modal" class="text-gray-400 hover:text-gray-500">
                    <span class="text-2xl">&times;</span>
                  </button>
                </div>

                <div class="space-y-4">
                  <!-- Rule Metadata -->
                  <div class="grid grid-cols-2 gap-4">
                    <div>
                      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Rule ID</label>
                      <p class="text-sm text-gray-900 dark:text-white"><%= @selected_rule.rule_id %></p>
                    </div>
                    <div>
                      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Type</label>
                      <span class={type_badge_class(@selected_rule.rule_type)}><%= @selected_rule.rule_type %></span>
                    </div>
                    <div>
                      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Severity</label>
                      <span class={severity_badge_class(@selected_rule.severity)}><%= @selected_rule.severity %></span>
                    </div>
                    <div>
                      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Confidence</label>
                      <p class="text-sm text-gray-900 dark:text-white"><%= format_percentage(@selected_rule.confidence_score) %></p>
                    </div>
                  </div>

                  <!-- Description -->
                  <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Description</label>
                    <p class="text-sm text-gray-900 dark:text-white"><%= @selected_rule.description %></p>
                  </div>

                  <!-- Performance Metrics -->
                  <%= if @selected_rule.validation_passed do %>
                    <div>
                      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Performance Metrics</label>
                      <div class="grid grid-cols-4 gap-4 bg-gray-50 dark:bg-gray-700 p-4 rounded-lg">
                        <div>
                          <div class="text-xs text-gray-500 dark:text-gray-400">Precision</div>
                          <div class="text-lg font-semibold text-gray-900 dark:text-white"><%= format_metric(@selected_rule.precision) %></div>
                        </div>
                        <div>
                          <div class="text-xs text-gray-500 dark:text-gray-400">Recall</div>
                          <div class="text-lg font-semibold text-gray-900 dark:text-white"><%= format_metric(@selected_rule.recall) %></div>
                        </div>
                        <div>
                          <div class="text-xs text-gray-500 dark:text-gray-400">F1 Score</div>
                          <div class="text-lg font-semibold text-gray-900 dark:text-white"><%= format_metric(@selected_rule.f1_score) %></div>
                        </div>
                        <div>
                          <div class="text-xs text-gray-500 dark:text-gray-400">FP Rate</div>
                          <div class="text-lg font-semibold text-gray-900 dark:text-white"><%= calculate_fp_rate(@selected_rule) %></div>
                        </div>
                      </div>
                    </div>
                  <% end %>

                  <!-- MITRE ATT&CK -->
                  <%= if length(@selected_rule.mitre_techniques) > 0 do %>
                    <div>
                      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">MITRE ATT&CK Techniques</label>
                      <div class="flex flex-wrap gap-2">
                        <%= for technique <- @selected_rule.mitre_techniques do %>
                          <span class="px-2 py-1 bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 rounded text-xs font-medium"><%= technique %></span>
                        <% end %>
                      </div>
                    </div>
                  <% end %>

                  <!-- Rule Content -->
                  <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Rule Content</label>
                    <pre class="bg-gray-50 dark:bg-gray-900 p-4 rounded-lg overflow-x-auto text-xs font-mono text-gray-900 dark:text-gray-100"><%= @selected_rule.content %></pre>
                  </div>
                </div>
              </div>
              <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                <%= if not @selected_rule.approved do %>
                  <button phx-click="approve_rule" phx-value-id={@selected_rule.id} class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-green-600 text-base font-medium text-white hover:bg-green-700 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm">Approve & Deploy</button>
                  <button phx-click="reject_rule" phx-value-id={@selected_rule.id} class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm">Reject</button>
                <% end %>
                <button phx-click="close_modal" type="button" class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm dark:bg-gray-800 dark:text-gray-300 dark:border-gray-600 dark:hover:bg-gray-700">Close</button>
              </div>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  @impl true
  def handle_event("switch_tab", %{"tab" => tab}, socket) do
    {:noreply, assign(socket, :current_tab, tab)}
  end

  @impl true
  def handle_event("view_rule", %{"id" => id}, socket) do
    rule = Generator.get_ml_rule(id)
    {:noreply, socket |> assign(:selected_rule, rule) |> assign(:show_detail_modal, true)}
  end

  @impl true
  def handle_event("close_modal", _params, socket) do
    {:noreply, socket |> assign(:show_detail_modal, false) |> assign(:selected_rule, nil)}
  end

  @impl true
  def handle_event("approve_rule", %{"id" => id}, socket) do
    current_user_id = socket.assigns[:current_user][:id] || nil

    case Generator.approve_rule(id, current_user_id) do
      {:ok, _rule} ->
        # Deploy the rule
        Generator.deploy_rule(id)

        socket =
          socket
          |> put_flash(:info, "Rule approved and deployed successfully")
          |> assign(:pending_rules, Generator.list_ml_rules(%{approved: false}))
          |> assign(:approved_rules, Generator.list_ml_rules(%{approved: true}))
          |> assign(:show_detail_modal, false)
          |> assign(:selected_rule, nil)

        {:noreply, socket}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to approve rule")}
    end
  end

  @impl true
  def handle_event("reject_rule", %{"id" => id}, socket) do
    case Generator.reject_rule(id) do
      {:ok, _} ->
        socket =
          socket
          |> put_flash(:info, "Rule rejected and removed")
          |> assign(:pending_rules, Generator.list_ml_rules(%{approved: false}))
          |> assign(:show_detail_modal, false)
          |> assign(:selected_rule, nil)

        {:noreply, socket}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to reject rule")}
    end
  end

  @impl true
  def handle_event("disable_rule", %{"id" => id}, socket) do
    rule = Generator.get_ml_rule(id)

    case TamanduaServer.Repo.update(MlRule.approval_changeset(rule, %{enabled: false})) do
      {:ok, _} ->
        socket =
          socket
          |> put_flash(:info, "Rule disabled")
          |> assign(:approved_rules, Generator.list_ml_rules(%{approved: true}))

        {:noreply, socket}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to disable rule")}
    end
  end

  @impl true
  def handle_event("enable_rule", %{"id" => id}, socket) do
    rule = Generator.get_ml_rule(id)

    case TamanduaServer.Repo.update(MlRule.approval_changeset(rule, %{enabled: true})) do
      {:ok, _} ->
        socket =
          socket
          |> put_flash(:info, "Rule enabled")
          |> assign(:approved_rules, Generator.list_ml_rules(%{approved: true}))

        {:noreply, socket}

      {:error, _} ->
        {:noreply, put_flash(socket, :error, "Failed to enable rule")}
    end
  end

  # Helper functions

  defp tab_class(active) do
    if active do
      "border-b-2 border-blue-500 py-4 px-1 text-sm font-medium text-blue-600 dark:text-blue-400"
    else
      "border-b-2 border-transparent py-4 px-1 text-sm font-medium text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
    end
  end

  defp type_badge_class("yara"), do: "px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-purple-100 text-purple-800"
  defp type_badge_class("sigma"), do: "px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800"
  defp type_badge_class("ml_custom"), do: "px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800"
  defp type_badge_class(_), do: "px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800"

  defp severity_badge_class("critical"), do: "px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800"
  defp severity_badge_class("high"), do: "px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-orange-100 text-orange-800"
  defp severity_badge_class("medium"), do: "px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800"
  defp severity_badge_class("low"), do: "px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800"
  defp severity_badge_class(_), do: "px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800"

  defp confidence_bar_class(score) when is_float(score) and score >= 0.8, do: "bg-green-600 h-2 rounded-full"
  defp confidence_bar_class(score) when is_float(score) and score >= 0.6, do: "bg-yellow-600 h-2 rounded-full"
  defp confidence_bar_class(_), do: "bg-red-600 h-2 rounded-full"

  defp format_metric(nil), do: "N/A"
  defp format_metric(value) when is_float(value), do: "#{Float.round(value * 100, 1)}%"
  defp format_metric(_), do: "N/A"

  defp format_percentage(nil), do: "N/A"
  defp format_percentage(value) when is_float(value), do: "#{Float.round(value * 100, 1)}%"
  defp format_percentage(_), do: "N/A"

  defp calculate_fp_rate(%{false_positives: fp, true_negatives: tn}) when is_integer(fp) and is_integer(tn) do
    total = fp + tn
    if total > 0 do
      "#{Float.round(fp / total * 100, 1)}%"
    else
      "N/A"
    end
  end
  defp calculate_fp_rate(_), do: "N/A"
end
