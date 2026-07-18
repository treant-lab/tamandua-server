defmodule TamanduaServerWeb.RuleImportLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Detection.{RuleImporter, RuleImportJob}
  alias TamanduaServer.Repo
  import Ecto.Query

  @impl true
  def mount(_params, _session, socket) do
    organization_id = get_organization_id(socket)
    user_id = socket.assigns.current_user.id

    socket =
      socket
      |> assign(:page_title, "Import Rules")
      |> assign(:organization_id, organization_id)
      |> assign(:user_id, user_id)
      |> assign(:current_step, 1)
      |> assign(:rule_type, "yara")
      |> assign(:source_type, "file")
      |> assign(:source_url, "")
      |> assign(:conflict_resolution, "skip")
      |> assign(:validation_enabled, true)
      |> assign(:uploaded_files, [])
      |> assign(:import_job, nil)
      |> assign(:recent_jobs, load_recent_jobs(organization_id))
      |> assign(:show_github_modal, false)
      |> assign(:github_url, "")
      |> assign(:github_branch, "main")
      |> assign(:github_path, "")
      |> allow_upload(:rule_files,
        accept: :any,
        max_entries: 100,
        max_file_size: 10_000_000,
        auto_upload: true
      )

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _url, socket) do
    {:noreply, apply_action(socket, socket.assigns.live_action, params)}
  end

  defp apply_action(socket, :index, _params) do
    socket
    |> assign(:page_title, "Import Rules")
    |> assign(:current_step, 1)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <div class="mb-6">
        <h1 class="text-3xl font-bold text-gray-900 dark:text-white">Import Detection Rules</h1>
        <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
          Import YARA rules, Sigma rules, and IOCs from files, directories, or GitHub repositories.
        </p>
      </div>

      <!-- Progress Steps -->
      <div class="mb-8">
        <div class="flex items-center justify-between">
          <.step_indicator step={1} current={@current_step} label="Select Type" />
          <div class="flex-1 h-1 bg-gray-200 dark:bg-gray-700 mx-2"></div>
          <.step_indicator step={2} current={@current_step} label="Choose Source" />
          <div class="flex-1 h-1 bg-gray-200 dark:bg-gray-700 mx-2"></div>
          <.step_indicator step={3} current={@current_step} label="Configure" />
          <div class="flex-1 h-1 bg-gray-200 dark:bg-gray-700 mx-2"></div>
          <.step_indicator step={4} current={@current_step} label="Review & Import" />
        </div>
      </div>

      <!-- Import Wizard -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <%= if @current_step == 1 do %>
          <.step_select_type current_type={@rule_type} />
        <% end %>

        <%= if @current_step == 2 do %>
          <.step_select_source
            source_type={@source_type}
            rule_type={@rule_type}
            uploads={@uploads}
          />
        <% end %>

        <%= if @current_step == 3 do %>
          <.step_configure
            conflict_resolution={@conflict_resolution}
            validation_enabled={@validation_enabled}
          />
        <% end %>

        <%= if @current_step == 4 do %>
          <.step_review
            rule_type={@rule_type}
            source_type={@source_type}
            source_url={@source_url}
            conflict_resolution={@conflict_resolution}
            validation_enabled={@validation_enabled}
            uploaded_files={@uploaded_files}
            import_job={@import_job}
          />
        <% end %>

        <!-- Navigation Buttons -->
        <div class="mt-6 flex justify-between">
          <button
            :if={@current_step > 1 && is_nil(@import_job)}
            phx-click="prev_step"
            class="px-4 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300"
          >
            Previous
          </button>
          <div></div>

          <%= if @current_step < 4 do %>
            <button
              phx-click="next_step"
              class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
            >
              Next
            </button>
          <% else %>
            <%= if is_nil(@import_job) do %>
              <button
                phx-click="start_import"
                class="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700"
              >
                Start Import
              </button>
            <% else %>
              <.link
                navigate={~p"/rules"}
                class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                Go to Rules
              </.link>
            <% end %>
          <% end %>
        </div>
      </div>

      <!-- Recent Import Jobs -->
      <div class="mt-8 bg-white dark:bg-gray-800 rounded-lg shadow">
        <div class="p-6">
          <h2 class="text-xl font-semibold text-gray-900 dark:text-white mb-4">Recent Import Jobs</h2>

          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead class="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Type</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Source</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Status</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Results</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Date</th>
                </tr>
              </thead>
              <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                <%= for job <- @recent_jobs do %>
                  <tr>
                    <td class="px-6 py-4 whitespace-nowrap">
                      <span class="px-2 py-1 text-xs font-semibold rounded bg-blue-100 text-blue-800">
                        <%= String.upcase(job.type) %>
                      </span>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                      <%= job.source_type %>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap">
                      <.status_badge status={job.status} />
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      <%= job.imported_rules %> imported, <%= job.skipped_rules %> skipped, <%= job.failed_rules %> failed
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      <%= format_datetime(job.inserted_at) %>
                    </td>
                  </tr>
                <% end %>
                <%= if Enum.empty?(@recent_jobs) do %>
                  <tr>
                    <td colspan="5" class="px-6 py-4 text-center text-gray-500">
                      No import jobs yet
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- GitHub Import Modal -->
      <%= if @show_github_modal do %>
        <.github_modal github_url={@github_url} github_branch={@github_branch} github_path={@github_path} />
      <% end %>
    </div>
    """
  end

  # Step Components

  defp step_indicator(assigns) do
    ~H"""
    <div class="flex flex-col items-center">
      <div class={[
        "w-10 h-10 rounded-full flex items-center justify-center font-semibold",
        if(@step <= @current, do: "bg-blue-600 text-white", else: "bg-gray-300 text-gray-600")
      ]}>
        <%= @step %>
      </div>
      <span class="mt-2 text-xs text-gray-600 dark:text-gray-400"><%= @label %></span>
    </div>
    """
  end

  defp step_select_type(assigns) do
    ~H"""
    <div>
      <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Select Rule Type</h3>
      <p class="text-sm text-gray-600 dark:text-gray-400 mb-6">Choose the type of detection rules you want to import.</p>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <.rule_type_card
          type="yara"
          title="YARA Rules"
          description="Pattern matching rules for malware detection and file analysis"
          icon="🔍"
          current={@current_type}
        />
        <.rule_type_card
          type="sigma"
          title="Sigma Rules"
          description="Generic signature format for SIEM systems and behavioral detection"
          icon="📊"
          current={@current_type}
        />
        <.rule_type_card
          type="ioc"
          title="IOCs"
          description="Indicators of Compromise (hashes, IPs, domains, URLs)"
          icon="🚨"
          current={@current_type}
        />
      </div>
    </div>
    """
  end

  defp rule_type_card(assigns) do
    ~H"""
    <button
      phx-click="select_type"
      phx-value-type={@type}
      class={[
        "p-6 border-2 rounded-lg text-left transition-all",
        if(@type == @current,
          do: "border-blue-600 bg-blue-50 dark:bg-blue-900",
          else: "border-gray-200 dark:border-gray-700 hover:border-blue-400"
        )
      ]}
    >
      <div class="text-4xl mb-3"><%= @icon %></div>
      <h4 class="text-lg font-semibold text-gray-900 dark:text-white mb-2"><%= @title %></h4>
      <p class="text-sm text-gray-600 dark:text-gray-400"><%= @description %></p>
    </button>
    """
  end

  defp step_select_source(assigns) do
    ~H"""
    <div>
      <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Choose Import Source</h3>
      <p class="text-sm text-gray-600 dark:text-gray-400 mb-6">Select where you want to import rules from.</p>

      <div class="space-y-4 mb-6">
        <.source_option
          type="file"
          title="Upload File"
          description="Upload a single rule file from your computer"
          current={@source_type}
        />
        <.source_option
          type="directory"
          title="Upload Directory"
          description="Upload multiple rule files from a directory"
          current={@source_type}
        />
        <.source_option
          type="github"
          title="GitHub Repository"
          description="Import rules directly from a GitHub repository"
          current={@source_type}
        />
        <.source_option
          type="url"
          title="Remote URL"
          description="Download and import a rule file from a URL"
          current={@source_type}
        />
      </div>

      <%= if @source_type == "file" or @source_type == "directory" do %>
        <div class="mt-6">
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Upload Files
          </label>
          <div
            class="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-8 text-center"
            phx-drop-target={@uploads.rule_files.ref}
          >
            <div class="text-gray-400 mb-4">
              <svg class="mx-auto h-12 w-12" stroke="currentColor" fill="none" viewBox="0 0 48 48">
                <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </div>
            <form phx-change="validate_upload" phx-submit="upload">
              <label class="cursor-pointer">
                <span class="text-blue-600 hover:text-blue-700 font-medium">Click to upload</span>
                <span class="text-gray-500"> or drag and drop</span>
                <.live_file_input upload={@uploads.rule_files} class="hidden" />
              </label>
            </form>
            <p class="text-xs text-gray-500 mt-2">
              <%= if @rule_type == "yara", do: "YARA files (.yar, .yara)" %>
              <%= if @rule_type == "sigma", do: "Sigma files (.yml, .yaml)" %>
              <%= if @rule_type == "ioc", do: "IOC files (.json, .csv)" %>
            </p>
          </div>

          <%= for entry <- @uploads.rule_files.entries do %>
            <div class="mt-2 flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700 rounded">
              <span class="text-sm text-gray-700 dark:text-gray-300"><%= entry.client_name %></span>
              <button
                phx-click="cancel_upload"
                phx-value-ref={entry.ref}
                class="text-red-600 hover:text-red-700"
              >
                Remove
              </button>
            </div>
          <% end %>
        </div>
      <% end %>

      <%= if @source_type == "github" do %>
        <div class="mt-6">
          <button
            phx-click="show_github_modal"
            class="w-full px-4 py-3 bg-gray-800 text-white rounded-lg hover:bg-gray-700 flex items-center justify-center"
          >
            <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
            </svg>
            Configure GitHub Import
          </button>
        </div>
      <% end %>

      <%= if @source_type == "url" do %>
        <div class="mt-6">
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Rule File URL
          </label>
          <input
            type="url"
            phx-change="update_url"
            name="source_url"
            placeholder="https://example.com/rules/malware.yar"
            class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          />
        </div>
      <% end %>
    </div>
    """
  end

  defp source_option(assigns) do
    ~H"""
    <button
      phx-click="select_source"
      phx-value-type={@type}
      class={[
        "w-full p-4 border-2 rounded-lg text-left transition-all flex items-center",
        if(@type == @current,
          do: "border-blue-600 bg-blue-50 dark:bg-blue-900",
          else: "border-gray-200 dark:border-gray-700 hover:border-blue-400"
        )
      ]}
    >
      <div class="flex-1">
        <h4 class="text-base font-semibold text-gray-900 dark:text-white"><%= @title %></h4>
        <p class="text-sm text-gray-600 dark:text-gray-400 mt-1"><%= @description %></p>
      </div>
      <%= if @type == @current do %>
        <svg class="w-6 h-6 text-blue-600" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
        </svg>
      <% end %>
    </button>
    """
  end

  defp step_configure(assigns) do
    ~H"""
    <div>
      <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Configure Import Options</h3>
      <p class="text-sm text-gray-600 dark:text-gray-400 mb-6">Set how the import should handle conflicts and validation.</p>

      <div class="space-y-6">
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
            Conflict Resolution
          </label>
          <div class="space-y-3">
            <.radio_option
              name="conflict_resolution"
              value="skip"
              current={@conflict_resolution}
              title="Skip Duplicates"
              description="Keep existing rules and skip any duplicates"
            />
            <.radio_option
              name="conflict_resolution"
              value="overwrite"
              current={@conflict_resolution}
              title="Overwrite Existing"
              description="Replace existing rules with imported versions"
            />
            <.radio_option
              name="conflict_resolution"
              value="rename"
              current={@conflict_resolution}
              title="Rename Duplicates"
              description="Import duplicates with a new name"
            />
          </div>
        </div>

        <div>
          <label class="flex items-center">
            <input
              type="checkbox"
              phx-click="toggle_validation"
              checked={@validation_enabled}
              class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <span class="ml-2 text-sm font-medium text-gray-700 dark:text-gray-300">
              Enable Syntax Validation
            </span>
          </label>
          <p class="ml-6 text-xs text-gray-500 dark:text-gray-400 mt-1">
            Validate rule syntax before import. Invalid rules will be skipped.
          </p>
        </div>
      </div>
    </div>
    """
  end

  defp radio_option(assigns) do
    ~H"""
    <label class="flex items-start cursor-pointer">
      <input
        type="radio"
        name={@name}
        value={@value}
        phx-click="select_conflict_resolution"
        phx-value-resolution={@value}
        checked={@value == @current}
        class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 mt-1"
      />
      <div class="ml-3">
        <div class="text-sm font-medium text-gray-700 dark:text-gray-300"><%= @title %></div>
        <div class="text-xs text-gray-500 dark:text-gray-400"><%= @description %></div>
      </div>
    </label>
    """
  end

  defp step_review(assigns) do
    ~H"""
    <div>
      <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Review Import Configuration</h3>
      <p class="text-sm text-gray-600 dark:text-gray-400 mb-6">Review your settings before starting the import.</p>

      <%= if @import_job do %>
        <.import_progress job={@import_job} />
      <% else %>
        <div class="space-y-4">
          <.review_item label="Rule Type" value={String.upcase(@rule_type)} />
          <.review_item label="Source Type" value={String.capitalize(@source_type)} />

          <%= if @source_type == "url" do %>
            <.review_item label="Source URL" value={@source_url} />
          <% end %>

          <%= if @source_type in ["file", "directory"] do %>
            <.review_item label="Files to Import" value={"#{length(@uploaded_files)} file(s)"} />
          <% end %>

          <.review_item label="Conflict Resolution" value={String.capitalize(@conflict_resolution)} />
          <.review_item label="Syntax Validation" value={if @validation_enabled, do: "Enabled", else: "Disabled"} />
        </div>
      <% end %>
    </div>
    """
  end

  defp review_item(assigns) do
    ~H"""
    <div class="flex justify-between py-2 border-b border-gray-200 dark:border-gray-700">
      <span class="text-sm font-medium text-gray-700 dark:text-gray-300"><%= @label %></span>
      <span class="text-sm text-gray-900 dark:text-white"><%= @value %></span>
    </div>
    """
  end

  defp import_progress(assigns) do
    ~H"""
    <div class="space-y-4">
      <div class="flex items-center">
        <.status_badge status={@job.status} />
        <span class="ml-3 text-sm font-medium text-gray-700 dark:text-gray-300">
          Import Status
        </span>
      </div>

      <%= if @job.status == "processing" do %>
        <div class="w-full bg-gray-200 rounded-full h-2.5 dark:bg-gray-700">
          <div
            class="bg-blue-600 h-2.5 rounded-full transition-all"
            style={"width: #{calculate_progress(@job)}%"}
          >
          </div>
        </div>
      <% end %>

      <div class="grid grid-cols-4 gap-4 mt-4">
        <.stat_card label="Total" value={@job.total_rules} color="blue" />
        <.stat_card label="Imported" value={@job.imported_rules} color="green" />
        <.stat_card label="Skipped" value={@job.skipped_rules} color="yellow" />
        <.stat_card label="Failed" value={@job.failed_rules} color="red" />
      </div>

      <%= if @job.error_message do %>
        <div class="mt-4 p-4 bg-red-50 dark:bg-red-900 rounded-lg">
          <p class="text-sm text-red-800 dark:text-red-200"><%= @job.error_message %></p>
        </div>
      <% end %>
    </div>
    """
  end

  defp stat_card(assigns) do
    ~H"""
    <div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
      <p class="text-xs text-gray-500 dark:text-gray-400 uppercase"><%= @label %></p>
      <p class={"text-2xl font-bold text-#{@color}-600"}><%= @value %></p>
    </div>
    """
  end

  defp status_badge(assigns) do
    ~H"""
    <span class={[
      "px-2 py-1 text-xs font-semibold rounded",
      case @status do
        "pending" -> "bg-gray-100 text-gray-800"
        "processing" -> "bg-blue-100 text-blue-800"
        "completed" -> "bg-green-100 text-green-800"
        "failed" -> "bg-red-100 text-red-800"
        "cancelled" -> "bg-yellow-100 text-yellow-800"
        _ -> "bg-gray-100 text-gray-800"
      end
    ]}>
      <%= String.upcase(@status) %>
    </span>
    """
  end

  defp github_modal(assigns) do
    ~H"""
    <div class="fixed z-10 inset-0 overflow-y-auto">
      <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" phx-click="hide_github_modal"></div>

        <div class="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
          <div class="bg-white dark:bg-gray-800 px-4 pt-5 pb-4 sm:p-6">
            <h3 class="text-lg leading-6 font-medium text-gray-900 dark:text-white mb-4">
              Configure GitHub Import
            </h3>

            <form phx-submit="save_github_config" class="space-y-4">
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Repository URL
                </label>
                <input
                  type="url"
                  name="github_url"
                  value={@github_url}
                  placeholder="https://github.com/owner/repo"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700"
                  required
                />
                <p class="mt-1 text-xs text-gray-500">
                  Example: https://github.com/Neo23x0/signature-base
                </p>
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Branch (optional)
                </label>
                <input
                  type="text"
                  name="github_branch"
                  value={@github_branch}
                  placeholder="main"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700"
                />
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Path (optional)
                </label>
                <input
                  type="text"
                  name="github_path"
                  value={@github_path}
                  placeholder="/yara"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700"
                />
              </div>

              <div class="flex justify-end gap-3 mt-6">
                <button
                  type="button"
                  phx-click="hide_github_modal"
                  class="px-4 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                >
                  Save Configuration
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
    """
  end

  # Event Handlers

  @impl true
  def handle_event("select_type", %{"type" => type}, socket) do
    {:noreply, assign(socket, :rule_type, type)}
  end

  @impl true
  def handle_event("select_source", %{"type" => type}, socket) do
    {:noreply, assign(socket, :source_type, type)}
  end

  @impl true
  def handle_event("select_conflict_resolution", %{"resolution" => resolution}, socket) do
    {:noreply, assign(socket, :conflict_resolution, resolution)}
  end

  @impl true
  def handle_event("toggle_validation", _params, socket) do
    {:noreply, assign(socket, :validation_enabled, !socket.assigns.validation_enabled)}
  end

  @impl true
  def handle_event("next_step", _params, socket) do
    {:noreply, assign(socket, :current_step, min(socket.assigns.current_step + 1, 4))}
  end

  @impl true
  def handle_event("prev_step", _params, socket) do
    {:noreply, assign(socket, :current_step, max(socket.assigns.current_step - 1, 1))}
  end

  @impl true
  def handle_event("show_github_modal", _params, socket) do
    {:noreply, assign(socket, :show_github_modal, true)}
  end

  @impl true
  def handle_event("hide_github_modal", _params, socket) do
    {:noreply, assign(socket, :show_github_modal, false)}
  end

  @impl true
  def handle_event("save_github_config", params, socket) do
    socket =
      socket
      |> assign(:source_url, params["github_url"])
      |> assign(:github_url, params["github_url"])
      |> assign(:github_branch, params["github_branch"] || "main")
      |> assign(:github_path, params["github_path"] || "")
      |> assign(:show_github_modal, false)

    {:noreply, socket}
  end

  @impl true
  def handle_event("update_url", %{"source_url" => url}, socket) do
    {:noreply, assign(socket, :source_url, url)}
  end

  @impl true
  def handle_event("validate_upload", _params, socket) do
    {:noreply, socket}
  end

  @impl true
  def handle_event("cancel_upload", %{"ref" => ref}, socket) do
    {:noreply, cancel_upload(socket, :rule_files, ref)}
  end

  @impl true
  def handle_event("start_import", _params, socket) do
    # Consume uploaded files
    uploaded_files =
      consume_uploaded_entries(socket, :rule_files, fn %{path: path}, entry ->
        dest = Path.join(System.tmp_dir!(), entry.client_name)
        File.cp!(path, dest)
        {:ok, dest}
      end)

    # Prepare job attributes
    job_attrs = %{
      type: socket.assigns.rule_type,
      source_type: socket.assigns.source_type,
      source_url: socket.assigns.source_url,
      conflict_resolution: socket.assigns.conflict_resolution,
      validation_enabled: socket.assigns.validation_enabled,
      organization_id: socket.assigns.organization_id,
      user_id: socket.assigns.user_id,
      metadata: build_metadata(socket, uploaded_files)
    }

    case RuleImporter.start_import(job_attrs) do
      {:ok, job} ->
        # Poll for job updates
        if connected?(socket) do
          Process.send_after(self(), :poll_job, 1000)
        end

        socket =
          socket
          |> assign(:import_job, job)
          |> put_flash(:info, "Import started successfully")

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> put_flash(:error, "Failed to start import: #{inspect(reason)}")

        {:noreply, socket}
    end
  end

  @impl true
  def handle_info(:poll_job, socket) do
    job = socket.assigns.import_job

    if job do
      updated_job = Repo.get(RuleImportJob, job.id)

      socket = assign(socket, :import_job, updated_job)

      # Continue polling if still processing
      socket =
        if updated_job.status == "processing" do
          Process.send_after(self(), :poll_job, 1000)
          socket
        else
          # Reload recent jobs
          assign(socket, :recent_jobs, load_recent_jobs(socket.assigns.organization_id))
        end

      {:noreply, socket}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  # Helper Functions

  defp get_organization_id(socket) do
    # Get organization_id from current user or session
    socket.assigns.current_user.organization_id || Ecto.UUID.generate()
  end

  defp load_recent_jobs(organization_id) do
    from(j in RuleImportJob,
      where: j.organization_id == ^organization_id,
      order_by: [desc: j.inserted_at],
      limit: 10
    )
    |> Repo.all()
  end

  defp build_metadata(socket, uploaded_files) do
    metadata = %{}

    metadata = if socket.assigns.source_type in ["file", "directory"] and length(uploaded_files) > 0 do
      Map.put(metadata, "file_paths", uploaded_files)
    else
      metadata
    end

    metadata = if socket.assigns.source_type == "github" do
      metadata
      |> Map.put("github_url", socket.assigns.github_url)
      |> Map.put("github_branch", socket.assigns.github_branch)
      |> Map.put("github_path", socket.assigns.github_path)
    else
      metadata
    end

    metadata
  end

  defp calculate_progress(job) do
    if job.total_rules > 0 do
      processed = job.imported_rules + job.skipped_rules + job.failed_rules
      Float.round(processed / job.total_rules * 100, 1)
    else
      0
    end
  end

  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S")
  end
end
