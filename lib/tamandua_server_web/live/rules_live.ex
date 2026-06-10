defmodule TamanduaServerWeb.RulesLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Detection
  alias TamanduaServer.Repo

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "Rules")}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, _params) do
    socket |> assign(:page_title, "Rules Overview")
  end

  defp apply_action(socket, :sigma, _params) do
    rules = Detection.list_sigma_rules()

    socket
    |> assign(:page_title, "Sigma Rules")
    |> assign(:rules, rules)
    |> assign(:rule_type, :sigma)
    |> assign(:show_edit_modal, false)
    |> assign(:rule_to_edit, nil)
  end

  defp apply_action(socket, :yara, _params) do
    rules = Repo.all(TamanduaServer.Detection.YaraRule)

    socket
    |> assign(:page_title, "YARA Rules")
    |> assign(:rules, rules)
    |> assign(:rule_type, :yara)
    |> assign(:show_edit_modal, false)
    |> assign(:rule_to_edit, nil)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold"><%= @page_title %></h1>
        <div class="flex gap-2">
          <.link navigate={~p"/rules/sigma"} class={"px-4 py-2 rounded #{if @live_action == :sigma, do: "bg-blue-600 text-white", else: "bg-gray-200 text-gray-700"}"}>
            Sigma
          </.link>
          <.link navigate={~p"/rules/yara"} class={"px-4 py-2 rounded #{if @live_action == :yara, do: "bg-blue-600 text-white", else: "bg-gray-200 text-gray-700"}"}>
            YARA
          </.link>
        </div>
      </div>

      <%= if @live_action == :index do %>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <h2 class="text-xl font-bold mb-4">Sigma Rules</h2>
            <p class="text-gray-500 mb-4">Behavioral detection rules using Sigma format.</p>
            <.link navigate={~p"/rules/sigma"} class="text-blue-600 hover:underline">Manage Sigma Rules &rarr;</.link>
          </div>

          <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <h2 class="text-xl font-bold mb-4">YARA Rules</h2>
            <p class="text-gray-500 mb-4">Pattern matching rules for file scanning.</p>
            <.link navigate={~p"/rules/yara"} class="text-blue-600 hover:underline">Manage YARA Rules &rarr;</.link>
          </div>
        </div>
      <% end %>

      <%= if @live_action in [:sigma, :yara] do %>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead class="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Name</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Description</th>
                <%= if @rule_type == :sigma do %>
                  <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Level</th>
                  <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Tactics</th>
                <% end %>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              <%= for rule <- @rules do %>
                <tr>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <div class="text-sm font-medium text-gray-900 dark:text-white"><%= rule.name %></div>
                  </td>
                  <td class="px-6 py-4">
                    <div class="text-sm text-gray-500 dark:text-gray-400"><%= rule.description %></div>
                  </td>
                  <%= if @rule_type == :sigma do %>
                    <td class="px-6 py-4 whitespace-nowrap">
                      <span class={"px-2 inline-flex text-xs leading-5 font-semibold rounded-full #{level_color(rule.level)}"}>
                        <%= rule.level %>
                      </span>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      <%= Enum.join(rule.mitre_tactics || [], ", ") %>
                    </td>
                  <% end %>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <button phx-click="edit_rule" phx-value-id={rule.id} class="text-indigo-600 hover:text-indigo-900 mr-4">Edit</button>
                    <button phx-click="toggle_rule" phx-value-id={rule.id} class={if rule.enabled, do: "text-red-600 hover:text-red-900", else: "text-green-600 hover:text-green-900"}>
                      <%= if rule.enabled, do: "Disable", else: "Enable" %>
                    </button>
                  </td>
                </tr>
              <% end %>
              <%= if length(@rules) == 0 do %>
                <tr>
                  <td colspan="5" class="px-6 py-4 text-center text-gray-500">No rules found</td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>
      <% end %>

      <%= if @show_edit_modal && @rule_to_edit do %>
        <div class="fixed z-10 inset-0 overflow-y-auto">
          <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" phx-click="hide_edit_modal"></div>
            <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-3xl sm:w-full">
              <form phx-submit="update_rule">
                <input type="hidden" name="id" value={@rule_to_edit.id} />
                <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                  <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">Edit <%= @rule_type |> to_string() |> String.upcase() %> Rule</h3>

                  <div class="space-y-4">
                    <div>
                      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Rule Name</label>
                      <input type="text" name="name" value={@rule_to_edit.name} class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white" readonly />
                    </div>

                    <div>
                      <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Rule Content</label>
                      <textarea name="content" rows="15" class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 dark:bg-gray-700 dark:text-white font-mono text-sm" required><%= get_rule_content(@rule_to_edit, @rule_type) %></textarea>
                      <p class="mt-2 text-sm text-gray-500 dark:text-gray-400">Edit the rule content carefully. Invalid syntax will be rejected.</p>
                    </div>

                    <div class="flex items-center">
                      <input type="checkbox" name="enabled" id="enabled" checked={@rule_to_edit.enabled} class="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded" />
                      <label for="enabled" class="ml-2 block text-sm text-gray-900 dark:text-gray-300">Enabled</label>
                    </div>
                  </div>
                </div>
                <div class="bg-gray-50 dark:bg-gray-700 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                  <button type="submit" class="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-indigo-600 text-base font-medium text-white hover:bg-indigo-700 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm">Save Changes</button>
                  <button phx-click="hide_edit_modal" type="button" class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm">Cancel</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  @impl true
  def handle_event("edit_rule", %{"id" => id}, socket) do
    rule_type = socket.assigns.rule_type

    rule = case rule_type do
      :sigma -> Detection.get_sigma_rule(id)
      :yara -> Detection.get_yara_rule(id)
    end

    socket =
      socket
      |> assign(:show_edit_modal, true)
      |> assign(:rule_to_edit, rule)

    {:noreply, socket}
  end

  @impl true
  def handle_event("hide_edit_modal", _params, socket) do
    socket =
      socket
      |> assign(:show_edit_modal, false)
      |> assign(:rule_to_edit, nil)

    {:noreply, socket}
  end

  @impl true
  def handle_event("update_rule", %{"id" => id, "content" => content, "enabled" => enabled}, socket) do
    rule_type = socket.assigns.rule_type

    # Validate rule syntax before saving
    case validate_rule_syntax(content, rule_type) do
      :ok ->
        result = case rule_type do
          :sigma ->
            rule = Detection.get_sigma_rule(id)
            Detection.update_sigma_rule(rule, %{raw_yaml: content, enabled: enabled == "on"})
          :yara ->
            rule = Detection.get_yara_rule(id)
            Detection.update_yara_rule(rule, %{rule_content: content, enabled: enabled == "on"})
        end

        case result do
          {:ok, _rule} ->
            rules = reload_rules(socket.assigns.rule_type)

            socket =
              socket
              |> put_flash(:info, "Rule updated successfully")
              |> assign(:show_edit_modal, false)
              |> assign(:rule_to_edit, nil)
              |> assign(:rules, rules)

            {:noreply, socket}

          {:error, changeset} ->
            socket =
              socket
              |> put_flash(:error, "Failed to update rule: #{inspect(changeset.errors)}")

            {:noreply, socket}
        end

      {:error, reason} ->
        socket =
          socket
          |> put_flash(:error, "Invalid rule syntax: #{reason}")

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("update_rule", %{"id" => id, "content" => content}, socket) do
    # Handle case when checkbox is unchecked (not sent in params)
    handle_event("update_rule", %{"id" => id, "content" => content, "enabled" => "off"}, socket)
  end

  @impl true
  def handle_event("toggle_rule", %{"id" => id}, socket) do
    rule_type = socket.assigns.rule_type

    result = case rule_type do
      :sigma ->
        rule = Detection.get_sigma_rule(id)
        Detection.update_sigma_rule(rule, %{enabled: !rule.enabled})
      :yara ->
        rule = Detection.get_yara_rule(id)
        Detection.update_yara_rule(rule, %{enabled: !rule.enabled})
    end

    case result do
      {:ok, rule} ->
        rules = reload_rules(socket.assigns.rule_type)
        action = if rule.enabled, do: "enabled", else: "disabled"

        socket =
          socket
          |> put_flash(:info, "Rule #{action} successfully")
          |> assign(:rules, rules)

        {:noreply, socket}

      {:error, changeset} ->
        socket =
          socket
          |> put_flash(:error, "Failed to toggle rule: #{inspect(changeset.errors)}")

        {:noreply, socket}
    end
  end

  defp reload_rules(:sigma), do: Detection.list_sigma_rules()
  defp reload_rules(:yara), do: Repo.all(TamanduaServer.Detection.YaraRule)

  defp get_rule_content(rule, :sigma), do: rule.raw_yaml || ""
  defp get_rule_content(rule, :yara), do: rule.rule_content || ""

  defp validate_rule_syntax(content, :sigma) do
    # Basic YAML validation
    case YamlElixir.read_from_string(content) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, "Invalid YAML: #{inspect(reason)}"}
    end
  rescue
    _ -> {:error, "Invalid YAML syntax"}
  end

  defp validate_rule_syntax(content, :yara) do
    # Basic YARA validation - check for rule keyword
    if String.contains?(content, "rule ") do
      :ok
    else
      {:error, "Invalid YARA rule: must contain 'rule' keyword"}
    end
  end

  defp level_color("critical"), do: "bg-red-100 text-red-800"
  defp level_color("high"), do: "bg-orange-100 text-orange-800"
  defp level_color("medium"), do: "bg-yellow-100 text-yellow-800"
  defp level_color("low"), do: "bg-blue-100 text-blue-800"
  defp level_color(_), do: "bg-gray-100 text-gray-800"
end
