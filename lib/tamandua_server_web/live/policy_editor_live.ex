defmodule TamanduaServerWeb.PolicyEditorLive do
  @moduledoc """
  LiveView for creating, editing, and managing agent policies.

  Features:
  - Visual policy editor with template support
  - Policy comparison (diff viewer)
  - Policy simulation (test before deploy)
  - Deployment management with phased rollout
  - Policy history viewer
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Agents.{PolicyManager, PolicyDeployer, Policy}

  @impl true
  def mount(_params, session, socket) do
    organization_id = session["organization_id"] || get_default_org_id()
    user_id = session["user_id"]

    {:ok,
     socket
     |> assign(:organization_id, organization_id)
     |> assign(:user_id, user_id)
     |> assign(:page_title, "Policy Management")
     |> assign(:policies, [])
     |> assign(:selected_policy, nil)
     |> assign(:show_create_modal, false)
     |> assign(:show_edit_modal, false)
     |> assign(:show_delete_modal, false)
     |> assign(:show_deploy_modal, false)
     |> assign(:show_compare_modal, false)
     |> assign(:show_simulate_modal, false)
     |> assign(:show_history_modal, false)
     |> assign(:comparison_policy_id, nil)
     |> assign(:comparison_diff, nil)
     |> assign(:simulation_agent_id, nil)
     |> assign(:simulation_result, nil)
     |> assign(:policy_history, [])
     |> assign(:deployments, [])
     |> assign(:form, nil)
     |> load_policies()
     |> load_deployments()}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, _params) do
    socket
    |> assign(:page_title, "Policy Management")
    |> assign(:selected_policy, nil)
  end

  defp apply_action(socket, :show, %{"id" => id}) do
    policy = PolicyManager.get_policy(id)

    if policy do
      socket
      |> assign(:page_title, "Policy: #{policy.name}")
      |> assign(:selected_policy, policy)
      |> load_policy_history(id)
    else
      socket
      |> put_flash(:error, "Policy not found")
      |> push_navigate(to: ~p"/policies")
    end
  end

  defp apply_action(socket, :edit, %{"id" => id}) do
    policy = PolicyManager.get_policy(id)

    if policy do
      form = to_form(%{"policy" => policy})

      socket
      |> assign(:page_title, "Edit Policy: #{policy.name}")
      |> assign(:selected_policy, policy)
      |> assign(:show_edit_modal, true)
      |> assign(:form, form)
    else
      socket
      |> put_flash(:error, "Policy not found")
      |> push_navigate(to: ~p"/policies")
    end
  end

  @impl true
  def handle_event("show_create_modal", _params, socket) do
    form = to_form(%{})
    {:noreply, assign(socket, show_create_modal: true, form: form)}
  end

  def handle_event("hide_create_modal", _params, socket) do
    {:noreply, assign(socket, show_create_modal: false, form: nil)}
  end

  def handle_event("show_edit_modal", %{"id" => id}, socket) do
    policy = PolicyManager.get_policy(id)
    form = to_form(%{"policy" => policy})
    {:noreply, assign(socket, show_edit_modal: true, selected_policy: policy, form: form)}
  end

  def handle_event("hide_edit_modal", _params, socket) do
    {:noreply, assign(socket, show_edit_modal: false, form: nil)}
  end

  def handle_event("show_deploy_modal", %{"id" => id}, socket) do
    policy = PolicyManager.get_policy(id)
    {:noreply, assign(socket, show_deploy_modal: true, selected_policy: policy)}
  end

  def handle_event("hide_deploy_modal", _params, socket) do
    {:noreply, assign(socket, show_deploy_modal: false)}
  end

  def handle_event("show_compare_modal", %{"id" => id}, socket) do
    policy = PolicyManager.get_policy(id)
    {:noreply, assign(socket, show_compare_modal: true, selected_policy: policy)}
  end

  def handle_event("hide_compare_modal", _params, socket) do
    {:noreply, assign(socket, show_compare_modal: false, comparison_diff: nil)}
  end

  def handle_event("show_simulate_modal", %{"id" => id}, socket) do
    policy = PolicyManager.get_policy(id)
    {:noreply, assign(socket, show_simulate_modal: true, selected_policy: policy)}
  end

  def handle_event("hide_simulate_modal", _params, socket) do
    {:noreply, assign(socket, show_simulate_modal: false, simulation_result: nil)}
  end

  def handle_event("show_history_modal", %{"id" => id}, socket) do
    policy = PolicyManager.get_policy(id)
    socket = load_policy_history(socket, id)
    {:noreply, assign(socket, show_history_modal: true, selected_policy: policy)}
  end

  def handle_event("hide_history_modal", _params, socket) do
    {:noreply, assign(socket, show_history_modal: false, policy_history: [])}
  end

  def handle_event("create_policy", params, socket) do
    attrs = %{
      name: params["name"],
      description: params["description"],
      scope: params["scope"] || "organization",
      policy_type: params["policy_type"] || "custom",
      template_name: params["template_name"],
      policy_data: parse_policy_data(params),
      organization_id: socket.assigns.organization_id
    }

    case PolicyManager.create_policy(attrs, socket.assigns.user_id) do
      {:ok, _policy} ->
        {:noreply,
         socket
         |> put_flash(:info, "Policy created successfully")
         |> assign(:show_create_modal, false)
         |> load_policies()}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:noreply, assign(socket, form: to_form(changeset))}
    end
  end

  def handle_event("create_from_template", %{"template" => template_name} = params, socket) do
    attrs = %{
      name: params["name"],
      description: params["description"],
      scope: params["scope"] || "organization"
    }

    case PolicyManager.create_from_template(
           socket.assigns.organization_id,
           template_name,
           attrs,
           socket.assigns.user_id
         ) do
      {:ok, _policy} ->
        {:noreply,
         socket
         |> put_flash(:info, "Policy created from template successfully")
         |> assign(:show_create_modal, false)
         |> load_policies()}

      {:error, changeset} ->
        {:noreply, assign(socket, form: to_form(changeset))}
    end
  end

  def handle_event("update_policy", params, socket) do
    policy = socket.assigns.selected_policy

    attrs = %{
      name: params["name"],
      description: params["description"],
      policy_data: parse_policy_data(params)
    }

    case PolicyManager.update_policy(policy, attrs, socket.assigns.user_id) do
      {:ok, _updated_policy} ->
        {:noreply,
         socket
         |> put_flash(:info, "Policy updated successfully")
         |> assign(:show_edit_modal, false)
         |> load_policies()}

      {:error, changeset} ->
        {:noreply, assign(socket, form: to_form(changeset))}
    end
  end

  def handle_event("activate_policy", %{"id" => id}, socket) do
    policy = PolicyManager.get_policy(id)

    case PolicyManager.activate_policy(policy, socket.assigns.user_id) do
      {:ok, _policy} ->
        {:noreply,
         socket
         |> put_flash(:info, "Policy activated")
         |> load_policies()}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to activate policy")}
    end
  end

  def handle_event("deactivate_policy", %{"id" => id}, socket) do
    policy = PolicyManager.get_policy(id)

    case PolicyManager.deactivate_policy(policy, socket.assigns.user_id) do
      {:ok, _policy} ->
        {:noreply,
         socket
         |> put_flash(:info, "Policy deactivated")
         |> load_policies()}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to deactivate policy")}
    end
  end

  def handle_event("delete_policy", %{"id" => id}, socket) do
    policy = PolicyManager.get_policy(id)

    case PolicyManager.delete_policy(policy) do
      {:ok, _policy} ->
        {:noreply,
         socket
         |> put_flash(:info, "Policy deleted")
         |> assign(:show_delete_modal, false)
         |> load_policies()}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to delete policy")}
    end
  end

  def handle_event("compare_policies", %{"policy_id" => policy_id}, socket) do
    selected_policy = socket.assigns.selected_policy

    case PolicyManager.compare_policies(selected_policy.id, policy_id) do
      {:ok, diff} ->
        {:noreply, assign(socket, comparison_diff: diff, comparison_policy_id: policy_id)}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to compare policies")}
    end
  end

  def handle_event("simulate_policy", %{"agent_id" => agent_id}, socket) do
    selected_policy = socket.assigns.selected_policy

    case PolicyManager.simulate_policy(agent_id, selected_policy.id) do
      {:ok, result} ->
        {:noreply, assign(socket, simulation_result: result, simulation_agent_id: agent_id)}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to simulate policy")}
    end
  end

  def handle_event("deploy_policy", params, socket) do
    policy = socket.assigns.selected_policy

    opts = [
      strategy: params["strategy"] || "immediate",
      deployed_by_id: socket.assigns.user_id,
      auto_rollback: params["auto_rollback"] != "false",
      rollback_threshold: String.to_integer(params["rollback_threshold"] || "10")
    ]

    opts =
      if params["strategy"] == "phased" do
        Keyword.put(opts, :rollout_phases, parse_rollout_phases(params["phases"]))
      else
        opts
      end

    opts =
      if params["strategy"] == "scheduled" && params["scheduled_at"] do
        {:ok, scheduled_at, _} = DateTime.from_iso8601(params["scheduled_at"])
        Keyword.put(opts, :scheduled_at, scheduled_at)
      else
        opts
      end

    case PolicyDeployer.deploy_policy(policy.id, opts) do
      {:ok, _deployment} ->
        {:noreply,
         socket
         |> put_flash(:info, "Deployment started")
         |> assign(:show_deploy_modal, false)
         |> load_deployments()}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to start deployment")}
    end
  end

  def handle_event("continue_deployment", %{"id" => deployment_id}, socket) do
    case PolicyDeployer.continue_phased_deployment(deployment_id) do
      {:ok, _deployment} ->
        {:noreply,
         socket
         |> put_flash(:info, "Deployment continued to next phase")
         |> load_deployments()}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to continue deployment")}
    end
  end

  def handle_event("rollback_deployment", %{"id" => deployment_id}, socket) do
    case PolicyDeployer.rollback_deployment(deployment_id, "Manual rollback by user") do
      {:ok, _deployment} ->
        {:noreply,
         socket
         |> put_flash(:info, "Deployment rolled back")
         |> load_deployments()}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to rollback deployment")}
    end
  end

  def handle_event("cancel_deployment", %{"id" => deployment_id}, socket) do
    case PolicyDeployer.cancel_deployment(deployment_id) do
      {:ok, _deployment} ->
        {:noreply,
         socket
         |> put_flash(:info, "Deployment cancelled")
         |> load_deployments()}

      {:error, _reason} ->
        {:noreply, put_flash(socket, :error, "Failed to cancel deployment")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6">
      <div class="flex items-center justify-between mb-6">
        <h1 class="text-2xl font-bold"><%= @page_title %></h1>
        <div class="flex gap-2">
          <button
            phx-click="show_create_modal"
            class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
          >
            Create Policy
          </button>
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Policies List -->
        <div class="lg:col-span-2">
          <%= render_policies_list(assigns) %>
        </div>

        <!-- Deployments Panel -->
        <div>
          <%= render_deployments_panel(assigns) %>
        </div>
      </div>

      <!-- Modals -->
      <%= if @show_create_modal, do: render_create_modal(assigns) %>
      <%= if @show_edit_modal, do: render_edit_modal(assigns) %>
      <%= if @show_deploy_modal, do: render_deploy_modal(assigns) %>
      <%= if @show_compare_modal, do: render_compare_modal(assigns) %>
      <%= if @show_simulate_modal, do: render_simulate_modal(assigns) %>
      <%= if @show_history_modal, do: render_history_modal(assigns) %>
    </div>
    """
  end

  defp render_policies_list(assigns) do
    ~H"""
    <div class="bg-white rounded-lg shadow">
      <div class="px-6 py-4 border-b border-gray-200">
        <h2 class="text-lg font-semibold">Policies</h2>
      </div>
      <div class="divide-y divide-gray-200">
        <%= for policy <- @policies do %>
          <div class="p-6 hover:bg-gray-50">
            <div class="flex items-start justify-between">
              <div class="flex-1">
                <div class="flex items-center gap-2">
                  <h3 class="text-lg font-medium"><%= policy.name %></h3>
                  <span class={"px-2 py-1 text-xs rounded #{status_color(policy.status)}"}>
                    <%= policy.status %>
                  </span>
                  <%= if policy.template_name do %>
                    <span class="px-2 py-1 text-xs bg-purple-100 text-purple-800 rounded">
                      <%= policy.template_name %>
                    </span>
                  <% end %>
                </div>
                <p class="text-sm text-gray-600 mt-1"><%= policy.description %></p>
                <div class="flex gap-4 mt-2 text-xs text-gray-500">
                  <span>Scope: <%= policy.scope %></span>
                  <span>Version: <%= policy.version %></span>
                  <span>Updated: <%= format_datetime(policy.updated_at) %></span>
                </div>
              </div>
              <div class="flex gap-2">
                <%= if policy.status == "draft" do %>
                  <button
                    phx-click="activate_policy"
                    phx-value-id={policy.id}
                    class="px-3 py-1 text-sm bg-green-600 text-white rounded hover:bg-green-700"
                  >
                    Activate
                  </button>
                <% else %>
                  <button
                    phx-click="deactivate_policy"
                    phx-value-id={policy.id}
                    class="px-3 py-1 text-sm bg-gray-600 text-white rounded hover:bg-gray-700"
                  >
                    Deactivate
                  </button>
                <% end %>
                <button
                  phx-click="show_edit_modal"
                  phx-value-id={policy.id}
                  class="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
                >
                  Edit
                </button>
                <button
                  phx-click="show_deploy_modal"
                  phx-value-id={policy.id}
                  class="px-3 py-1 text-sm bg-indigo-600 text-white rounded hover:bg-indigo-700"
                  disabled={policy.status != "active"}
                >
                  Deploy
                </button>
                <button
                  phx-click="show_compare_modal"
                  phx-value-id={policy.id}
                  class="px-3 py-1 text-sm bg-purple-600 text-white rounded hover:bg-purple-700"
                >
                  Compare
                </button>
                <button
                  phx-click="show_simulate_modal"
                  phx-value-id={policy.id}
                  class="px-3 py-1 text-sm bg-yellow-600 text-white rounded hover:bg-yellow-700"
                >
                  Simulate
                </button>
                <button
                  phx-click="show_history_modal"
                  phx-value-id={policy.id}
                  class="px-3 py-1 text-sm bg-gray-600 text-white rounded hover:bg-gray-700"
                >
                  History
                </button>
              </div>
            </div>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  defp render_deployments_panel(assigns) do
    ~H"""
    <div class="bg-white rounded-lg shadow">
      <div class="px-6 py-4 border-b border-gray-200">
        <h2 class="text-lg font-semibold">Recent Deployments</h2>
      </div>
      <div class="divide-y divide-gray-200">
        <%= for deployment <- @deployments do %>
          <div class="p-4">
            <div class="flex items-center justify-between mb-2">
              <span class="font-medium text-sm"><%= deployment.policy.name %></span>
              <span class={"px-2 py-1 text-xs rounded #{deployment_status_color(deployment.status)}"}>
                <%= deployment.status %>
              </span>
            </div>
            <div class="text-xs text-gray-600">
              <div>Strategy: <%= deployment.strategy %></div>
              <div>Progress: <%= deployment.successful_agents %>/<%= deployment.total_agents %></div>
              <%= if deployment.strategy == "phased" do %>
                <div>
                  Phase: <%= deployment.current_phase + 1 %>/<%= length(deployment.rollout_phases) %>
                  (<%= deployment.current_phase_percentage %>%)
                </div>
              <% end %>
            </div>
            <%= if deployment.status == "in_progress" do %>
              <div class="flex gap-2 mt-2">
                <%= if deployment.strategy == "phased" do %>
                  <button
                    phx-click="continue_deployment"
                    phx-value-id={deployment.id}
                    class="px-2 py-1 text-xs bg-green-600 text-white rounded hover:bg-green-700"
                  >
                    Continue
                  </button>
                <% end %>
                <button
                  phx-click="rollback_deployment"
                  phx-value-id={deployment.id}
                  class="px-2 py-1 text-xs bg-red-600 text-white rounded hover:bg-red-700"
                >
                  Rollback
                </button>
                <button
                  phx-click="cancel_deployment"
                  phx-value-id={deployment.id}
                  class="px-2 py-1 text-xs bg-gray-600 text-white rounded hover:bg-gray-700"
                >
                  Cancel
                </button>
              </div>
            <% end %>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  defp render_create_modal(assigns) do
    ~H"""
    <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div class="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
          <h2 class="text-xl font-bold">Create Policy</h2>
          <button phx-click="hide_create_modal" class="text-gray-400 hover:text-gray-600">
            ✕
          </button>
        </div>
        <div class="p-6">
          <div class="mb-4">
            <label class="block text-sm font-medium mb-2">Create From Template</label>
            <div class="grid grid-cols-2 gap-2">
              <%= for template <- Policy.available_templates() do %>
                <button
                  phx-click="create_from_template"
                  phx-value-template={template}
                  class="p-4 border border-gray-300 rounded-lg hover:bg-gray-50 text-left"
                >
                  <div class="font-medium"><%= humanize_template(template) %></div>
                  <div class="text-xs text-gray-600"><%= template_description(template) %></div>
                </button>
              <% end %>
            </div>
          </div>
          <div class="border-t border-gray-200 my-6"></div>
          <form phx-submit="create_policy" class="space-y-4">
            <div>
              <label class="block text-sm font-medium mb-2">Name</label>
              <input
                type="text"
                name="name"
                required
                class="w-full px-3 py-2 border border-gray-300 rounded-lg"
              />
            </div>
            <div>
              <label class="block text-sm font-medium mb-2">Description</label>
              <textarea
                name="description"
                rows="3"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg"
              ></textarea>
            </div>
            <div>
              <label class="block text-sm font-medium mb-2">Scope</label>
              <select name="scope" class="w-full px-3 py-2 border border-gray-300 rounded-lg">
                <option value="organization">Organization</option>
                <option value="group">Group</option>
                <option value="agent">Agent</option>
              </select>
            </div>
            <div class="flex justify-end gap-2">
              <button
                type="button"
                phx-click="hide_create_modal"
                class="px-4 py-2 bg-gray-300 text-gray-700 rounded-lg hover:bg-gray-400"
              >
                Cancel
              </button>
              <button
                type="submit"
                class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
              >
                Create
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end

  defp render_edit_modal(assigns) do
    ~H"""
    <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        <div class="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
          <h2 class="text-xl font-bold">Edit Policy: <%= @selected_policy.name %></h2>
          <button phx-click="hide_edit_modal" class="text-gray-400 hover:text-gray-600">
            ✕
          </button>
        </div>
        <div class="p-6">
          <form phx-submit="update_policy" class="space-y-6">
            <div>
              <label class="block text-sm font-medium mb-2">Name</label>
              <input
                type="text"
                name="name"
                value={@selected_policy.name}
                required
                class="w-full px-3 py-2 border border-gray-300 rounded-lg"
              />
            </div>
            <div>
              <label class="block text-sm font-medium mb-2">Description</label>
              <textarea
                name="description"
                rows="3"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg"
              ><%= @selected_policy.description %></textarea>
            </div>
            <!-- Policy Editor -->
            <%= render_policy_editor(assigns) %>
            <div class="flex justify-end gap-2">
              <button
                type="button"
                phx-click="hide_edit_modal"
                class="px-4 py-2 bg-gray-300 text-gray-700 rounded-lg hover:bg-gray-400"
              >
                Cancel
              </button>
              <button
                type="submit"
                class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
              >
                Save
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end

  defp render_policy_editor(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="bg-gray-50 p-4 rounded-lg">
        <h3 class="font-medium mb-4">Collectors</h3>
        <div class="space-y-2">
          <%= for collector <- ["process", "file", "network", "dns", "registry"] do %>
            <div class="flex items-center gap-4">
              <label class="flex items-center gap-2 flex-1">
                <input
                  type="checkbox"
                  name={"collectors[#{collector}][enabled]"}
                  checked={get_in(@selected_policy.policy_data, ["collectors", collector, "enabled"])}
                />
                <span class="capitalize"><%= collector %></span>
              </label>
              <input
                type="number"
                name={"collectors[#{collector}][interval_ms]"}
                value={get_in(@selected_policy.policy_data, ["collectors", collector, "interval_ms"])}
                placeholder="Interval (ms)"
                class="w-32 px-3 py-1 border border-gray-300 rounded"
              />
            </div>
          <% end %>
        </div>
      </div>

      <div class="bg-gray-50 p-4 rounded-lg">
        <h3 class="font-medium mb-4">Resource Limits</h3>
        <div class="grid grid-cols-3 gap-4">
          <div>
            <label class="block text-sm mb-1">Max CPU %</label>
            <input
              type="number"
              name="resource_limits[max_cpu_percent]"
              value={get_in(@selected_policy.policy_data, ["resource_limits", "max_cpu_percent"])}
              class="w-full px-3 py-2 border border-gray-300 rounded"
            />
          </div>
          <div>
            <label class="block text-sm mb-1">Max Memory (MB)</label>
            <input
              type="number"
              name="resource_limits[max_memory_mb]"
              value={get_in(@selected_policy.policy_data, ["resource_limits", "max_memory_mb"])}
              class="w-full px-3 py-2 border border-gray-300 rounded"
            />
          </div>
          <div>
            <label class="block text-sm mb-1">Max Disk (MB)</label>
            <input
              type="number"
              name="resource_limits[max_disk_mb]"
              value={get_in(@selected_policy.policy_data, ["resource_limits", "max_disk_mb"])}
              class="w-full px-3 py-2 border border-gray-300 rounded"
            />
          </div>
        </div>
      </div>

      <div class="bg-gray-50 p-4 rounded-lg">
        <h3 class="font-medium mb-4">Detection</h3>
        <div class="space-y-2">
          <label class="flex items-center gap-2">
            <input
              type="checkbox"
              name="detection[yara_enabled]"
              checked={get_in(@selected_policy.policy_data, ["detection", "yara_enabled"])}
            />
            <span>YARA Detection</span>
          </label>
          <label class="flex items-center gap-2">
            <input
              type="checkbox"
              name="detection[sigma_enabled]"
              checked={get_in(@selected_policy.policy_data, ["detection", "sigma_enabled"])}
            />
            <span>Sigma Detection</span>
          </label>
          <label class="flex items-center gap-2">
            <input
              type="checkbox"
              name="detection[ml_enabled]"
              checked={get_in(@selected_policy.policy_data, ["detection", "ml_enabled"])}
            />
            <span>ML Detection</span>
          </label>
        </div>
      </div>

      <div class="bg-gray-50 p-4 rounded-lg">
        <h3 class="font-medium mb-4">Response Actions</h3>
        <div class="space-y-2">
          <%= for action <- ["isolate", "kill_process", "quarantine", "delete_file"] do %>
            <label class="flex items-center gap-2">
              <input
                type="checkbox"
                name={"response[allowed_actions][#{action}]"}
                checked={action in (get_in(@selected_policy.policy_data, ["response", "allowed_actions"]) || [])}
              />
              <span class="capitalize"><%= String.replace(action, "_", " ") %></span>
            </label>
          <% end %>
        </div>
        <div class="mt-4">
          <label class="flex items-center gap-2">
            <input
              type="checkbox"
              name="response[auto_response_enabled]"
              checked={get_in(@selected_policy.policy_data, ["response", "auto_response_enabled"])}
            />
            <span>Enable Automatic Response</span>
          </label>
        </div>
      </div>
    </div>
    """
  end

  defp render_deploy_modal(assigns) do
    ~H"""
    <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg shadow-xl max-w-2xl w-full">
        <div class="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
          <h2 class="text-xl font-bold">Deploy Policy: <%= @selected_policy.name %></h2>
          <button phx-click="hide_deploy_modal" class="text-gray-400 hover:text-gray-600">
            ✕
          </button>
        </div>
        <div class="p-6">
          <form phx-submit="deploy_policy" class="space-y-4">
            <div>
              <label class="block text-sm font-medium mb-2">Deployment Strategy</label>
              <select
                name="strategy"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg"
              >
                <option value="immediate">Immediate</option>
                <option value="scheduled">Scheduled</option>
                <option value="phased">Phased Rollout</option>
              </select>
            </div>
            <div>
              <label class="flex items-center gap-2">
                <input type="checkbox" name="auto_rollback" checked />
                <span class="text-sm">Enable automatic rollback on errors</span>
              </label>
            </div>
            <div>
              <label class="block text-sm font-medium mb-2">Rollback Threshold (%)</label>
              <input
                type="number"
                name="rollback_threshold"
                value="10"
                min="0"
                max="100"
                class="w-full px-3 py-2 border border-gray-300 rounded-lg"
              />
            </div>
            <div class="flex justify-end gap-2">
              <button
                type="button"
                phx-click="hide_deploy_modal"
                class="px-4 py-2 bg-gray-300 text-gray-700 rounded-lg hover:bg-gray-400"
              >
                Cancel
              </button>
              <button
                type="submit"
                class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
              >
                Deploy
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end

  defp render_compare_modal(assigns) do
    ~H"""
    <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        <div class="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
          <h2 class="text-xl font-bold">Compare Policies</h2>
          <button phx-click="hide_compare_modal" class="text-gray-400 hover:text-gray-600">
            ✕
          </button>
        </div>
        <div class="p-6">
          <div class="mb-4">
            <label class="block text-sm font-medium mb-2">Compare with:</label>
            <select
              phx-change="compare_policies"
              name="policy_id"
              class="w-full px-3 py-2 border border-gray-300 rounded-lg"
            >
              <option value="">Select a policy...</option>
              <%= for policy <- @policies do %>
                <%= if policy.id != @selected_policy.id do %>
                  <option value={policy.id}><%= policy.name %> (v<%= policy.version %>)</option>
                <% end %>
              <% end %>
            </select>
          </div>
          <%= if @comparison_diff do %>
            <div class="mt-4">
              <h3 class="font-medium mb-2">Differences</h3>
              <pre class="bg-gray-50 p-4 rounded-lg overflow-x-auto text-sm"><%= Jason.encode!(@comparison_diff, pretty: true) %></pre>
            </div>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  defp render_simulate_modal(assigns) do
    ~H"""
    <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        <div class="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
          <h2 class="text-xl font-bold">Simulate Policy</h2>
          <button phx-click="hide_simulate_modal" class="text-gray-400 hover:text-gray-600">
            ✕
          </button>
        </div>
        <div class="p-6">
          <p class="text-sm text-gray-600 mb-4">
            Test how this policy would affect an agent without actually deploying it.
          </p>
          <!-- Agent selection and simulation results would go here -->
          <p class="text-sm text-gray-500">Simulation feature - agent selector and results viewer</p>
        </div>
      </div>
    </div>
    """
  end

  defp render_history_modal(assigns) do
    ~H"""
    <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div class="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        <div class="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
          <h2 class="text-xl font-bold">Policy History</h2>
          <button phx-click="hide_history_modal" class="text-gray-400 hover:text-gray-600">
            ✕
          </button>
        </div>
        <div class="p-6">
          <div class="space-y-4">
            <%= for history <- @policy_history do %>
              <div class="border border-gray-200 rounded-lg p-4">
                <div class="flex items-center justify-between mb-2">
                  <span class="font-medium">Version <%= history.version %></span>
                  <span class="text-sm text-gray-600"><%= format_datetime(history.inserted_at) %></span>
                </div>
                <div class="text-sm">
                  <div>Change Type: <span class="font-medium"><%= history.change_type %></span></div>
                  <%= if history.changed_by do %>
                    <div>Changed By: <%= history.changed_by.email %></div>
                  <% end %>
                  <%= if history.change_reason do %>
                    <div>Reason: <%= history.change_reason %></div>
                  <% end %>
                </div>
              </div>
            <% end %>
          </div>
        </div>
      </div>
    </div>
    """
  end

  ## Private Functions

  defp load_policies(socket) do
    policies = PolicyManager.list_policies(socket.assigns.organization_id)
    assign(socket, :policies, policies)
  end

  defp load_deployments(socket) do
    deployments =
      PolicyDeployer.list_deployments(socket.assigns.organization_id, limit: 10)
      |> Enum.take(10)

    assign(socket, :deployments, deployments)
  end

  defp load_policy_history(socket, policy_id) do
    history = PolicyManager.get_policy_history(policy_id)
    assign(socket, :policy_history, history)
  end

  defp parse_policy_data(params) do
    %{
      "collectors" => parse_collectors(params["collectors"] || %{}),
      "resource_limits" => parse_resource_limits(params["resource_limits"] || %{}),
      "detection" => parse_detection(params["detection"] || %{}),
      "response" => parse_response(params["response"] || %{})
    }
  end

  defp parse_collectors(collectors) do
    Map.new(collectors, fn {name, config} ->
      {name,
       %{
         "enabled" => config["enabled"] == "true",
         "interval_ms" => String.to_integer(config["interval_ms"] || "5000")
       }}
    end)
  end

  defp parse_resource_limits(limits) do
    %{
      "max_cpu_percent" => String.to_integer(limits["max_cpu_percent"] || "10"),
      "max_memory_mb" => String.to_integer(limits["max_memory_mb"] || "500"),
      "max_disk_mb" => String.to_integer(limits["max_disk_mb"] || "1000")
    }
  end

  defp parse_detection(detection) do
    %{
      "yara_enabled" => detection["yara_enabled"] == "true",
      "sigma_enabled" => detection["sigma_enabled"] == "true",
      "ml_enabled" => detection["ml_enabled"] == "true"
    }
  end

  defp parse_response(response) do
    allowed_actions =
      (response["allowed_actions"] || %{})
      |> Map.keys()

    %{
      "allowed_actions" => allowed_actions,
      "auto_response_enabled" => response["auto_response_enabled"] == "true",
      "max_actions_per_hour" => String.to_integer(response["max_actions_per_hour"] || "10")
    }
  end

  defp parse_rollout_phases(phases_str) when is_binary(phases_str) do
    phases_str
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.map(&String.to_integer/1)
    |> Enum.map(fn percentage ->
      %{percentage: percentage, status: "pending", started_at: nil, completed_at: nil}
    end)
  end

  defp parse_rollout_phases(_), do: PolicyDeployment.default_phased_rollout()

  defp status_color("active"), do: "bg-green-100 text-green-800"
  defp status_color("draft"), do: "bg-gray-100 text-gray-800"
  defp status_color("inactive"), do: "bg-yellow-100 text-yellow-800"
  defp status_color(_), do: "bg-gray-100 text-gray-800"

  defp deployment_status_color("completed"), do: "bg-green-100 text-green-800"
  defp deployment_status_color("in_progress"), do: "bg-blue-100 text-blue-800"
  defp deployment_status_color("failed"), do: "bg-red-100 text-red-800"
  defp deployment_status_color("rolled_back"), do: "bg-orange-100 text-orange-800"
  defp deployment_status_color(_), do: "bg-gray-100 text-gray-800"

  defp humanize_template(template) do
    template
    |> String.replace("_", " ")
    |> String.split()
    |> Enum.map(&String.capitalize/1)
    |> Enum.join(" ")
  end

  defp template_description("baseline"), do: "Balanced security and performance"
  defp template_description("high_security"), do: "Maximum protection, higher resource usage"
  defp template_description("performance"), do: "Minimal resource usage"
  defp template_description("forensics"), do: "Maximum logging for investigations"
  defp template_description("custom"), do: "Start from scratch"

  defp format_datetime(nil), do: "N/A"

  defp format_datetime(datetime) do
    datetime
    |> DateTime.from_naive!("Etc/UTC")
    |> Calendar.strftime("%Y-%m-%d %H:%M:%S UTC")
  end

  defp get_default_org_id do
    # This should be replaced with actual organization lookup
    "00000000-0000-0000-0000-000000000000"
  end
end
