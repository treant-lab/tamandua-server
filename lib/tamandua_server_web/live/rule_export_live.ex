defmodule TamanduaServerWeb.RuleExportLive do
  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Detection.{RuleExporter, YaraRule, SigmaRule, IOC}
  alias TamanduaServer.Repo

  import Ecto.Query

  @impl true
  def mount(_params, _session, socket) do
    organization_id = get_organization_id(socket)

    socket =
      socket
      |> assign(:page_title, "Export Rules")
      |> assign(:organization_id, organization_id)
      |> assign(:current_step, 1)
      |> assign(:export_type, "yara")
      |> assign(:export_scope, "selected")
      |> assign(:export_format, "native")
      |> assign(:include_metadata, false)
      |> assign(:include_stats, false)
      |> assign(:selected_rules, [])
      |> assign(:yara_rules, load_yara_rules(organization_id))
      |> assign(:sigma_rules, load_sigma_rules(organization_id))
      |> assign(:iocs, load_iocs(organization_id))
      |> assign(:template, nil)
      |> assign(:export_result, nil)

    {:ok, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-7xl mx-auto">
      <div class="mb-6">
        <h1 class="text-3xl font-bold text-gray-900 dark:text-white">Export Detection Rules</h1>
        <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
          Export YARA rules, Sigma rules, and IOCs in various formats.
        </p>
      </div>

      <!-- Progress Steps -->
      <div class="mb-8">
        <div class="flex items-center justify-between">
          <.step_indicator step={1} current={@current_step} label="Select Type" />
          <div class="flex-1 h-1 bg-gray-200 dark:bg-gray-700 mx-2"></div>
          <.step_indicator step={2} current={@current_step} label="Choose Rules" />
          <div class="flex-1 h-1 bg-gray-200 dark:bg-gray-700 mx-2"></div>
          <.step_indicator step={3} current={@current_step} label="Configure" />
          <div class="flex-1 h-1 bg-gray-200 dark:bg-gray-700 mx-2"></div>
          <.step_indicator step={4} current={@current_step} label="Download" />
        </div>
      </div>

      <!-- Export Wizard -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <%= if @current_step == 1 do %>
          <.step_select_export_type export_type={@export_type} />
        <% end %>

        <%= if @current_step == 2 do %>
          <.step_select_rules
            export_type={@export_type}
            export_scope={@export_scope}
            selected_rules={@selected_rules}
            yara_rules={@yara_rules}
            sigma_rules={@sigma_rules}
            iocs={@iocs}
            template={@template}
          />
        <% end %>

        <%= if @current_step == 3 do %>
          <.step_configure_export
            export_type={@export_type}
            export_format={@export_format}
            include_metadata={@include_metadata}
            include_stats={@include_stats}
          />
        <% end %>

        <%= if @current_step == 4 do %>
          <.step_download
            export_result={@export_result}
            export_type={@export_type}
            export_format={@export_format}
          />
        <% end %>

        <!-- Navigation Buttons -->
        <div class="mt-6 flex justify-between">
          <button
            :if={@current_step > 1 && is_nil(@export_result)}
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
            <%= if is_nil(@export_result) do %>
              <button
                phx-click="generate_export"
                class="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700"
              >
                Generate Export
              </button>
            <% else %>
              <.link
                navigate={~p"/rules"}
                class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                Done
              </.link>
            <% end %>
          <% end %>
        </div>
      </div>

      <!-- Quick Export Templates -->
      <div class="mt-8 bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h2 class="text-xl font-semibold text-gray-900 dark:text-white mb-4">Quick Export Templates</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <.template_card
            name="ransomware_detection"
            title="Ransomware Detection"
            description="Export all ransomware-related rules"
            icon="🔒"
          />
          <.template_card
            name="apt_detection"
            title="APT Detection"
            description="Export APT and threat actor rules"
            icon="🎯"
          />
          <.template_card
            name="malware_analysis"
            title="Malware Analysis"
            description="Export malware family rules"
            icon="🦠"
          />
          <.template_card
            name="lateral_movement"
            title="Lateral Movement"
            description="Export lateral movement detection rules"
            icon="↔️"
          />
        </div>
      </div>
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

  defp step_select_export_type(assigns) do
    ~H"""
    <div>
      <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Select Export Type</h3>
      <p class="text-sm text-gray-600 dark:text-gray-400 mb-6">Choose the type of rules you want to export.</p>

      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <.export_type_card
          type="yara"
          title="YARA Rules"
          icon="🔍"
          current={@export_type}
        />
        <.export_type_card
          type="sigma"
          title="Sigma Rules"
          icon="📊"
          current={@export_type}
        />
        <.export_type_card
          type="ioc"
          title="IOCs"
          icon="🚨"
          current={@export_type}
        />
        <.export_type_card
          type="bundle"
          title="Complete Bundle"
          icon="📦"
          current={@export_type}
        />
      </div>
    </div>
    """
  end

  defp export_type_card(assigns) do
    ~H"""
    <button
      phx-click="select_export_type"
      phx-value-type={@type}
      class={[
        "p-6 border-2 rounded-lg text-center transition-all",
        if(@type == @current,
          do: "border-blue-600 bg-blue-50 dark:bg-blue-900",
          else: "border-gray-200 dark:border-gray-700 hover:border-blue-400"
        )
      ]}
    >
      <div class="text-4xl mb-3"><%= @icon %></div>
      <h4 class="text-base font-semibold text-gray-900 dark:text-white"><%= @title %></h4>
    </button>
    """
  end

  defp step_select_rules(assigns) do
    ~H"""
    <div>
      <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Choose Rules to Export</h3>
      <p class="text-sm text-gray-600 dark:text-gray-400 mb-6">Select which rules you want to include in the export.</p>

      <%= if @export_type != "bundle" do %>
        <div class="space-y-4 mb-6">
          <.scope_option
            scope="all"
            title="Export All Rules"
            description={"Export all #{@export_type} rules in your organization"}
            current={@export_scope}
          />
          <.scope_option
            scope="selected"
            title="Export Selected Rules"
            description="Manually select specific rules to export"
            current={@export_scope}
          />
          <.scope_option
            scope="template"
            title="Export from Template"
            description="Use a predefined rule set template"
            current={@export_scope}
          />
        </div>

        <%= if @export_scope == "selected" do %>
          <div class="mt-6">
            <.rule_selector
              export_type={@export_type}
              selected_rules={@selected_rules}
              yara_rules={@yara_rules}
              sigma_rules={@sigma_rules}
              iocs={@iocs}
            />
          </div>
        <% end %>

        <%= if @export_scope == "template" do %>
          <div class="mt-6">
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Select Template
            </label>
            <select
              phx-change="select_template"
              name="template"
              class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700"
            >
              <option value="">Choose a template...</option>
              <option value="ransomware_detection">Ransomware Detection</option>
              <option value="apt_detection">APT Detection</option>
              <option value="malware_analysis">Malware Analysis</option>
              <option value="lateral_movement">Lateral Movement</option>
            </select>
          </div>
        <% end %>
      <% else %>
        <div class="p-4 bg-blue-50 dark:bg-blue-900 rounded-lg">
          <p class="text-sm text-blue-800 dark:text-blue-200">
            Bundle export will include all YARA rules, Sigma rules, and IOCs from your organization.
          </p>
        </div>
      <% end %>
    </div>
    """
  end

  defp scope_option(assigns) do
    ~H"""
    <button
      phx-click="select_scope"
      phx-value-scope={@scope}
      class={[
        "w-full p-4 border-2 rounded-lg text-left transition-all flex items-center",
        if(@scope == @current,
          do: "border-blue-600 bg-blue-50 dark:bg-blue-900",
          else: "border-gray-200 dark:border-gray-700 hover:border-blue-400"
        )
      ]}
    >
      <div class="flex-1">
        <h4 class="text-base font-semibold text-gray-900 dark:text-white"><%= @title %></h4>
        <p class="text-sm text-gray-600 dark:text-gray-400 mt-1"><%= @description %></p>
      </div>
      <%= if @scope == @current do %>
        <svg class="w-6 h-6 text-blue-600" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
        </svg>
      <% end %>
    </button>
    """
  end

  defp rule_selector(assigns) do
    ~H"""
    <div class="max-h-96 overflow-y-auto border border-gray-300 dark:border-gray-600 rounded-lg">
      <%= if @export_type == "yara" do %>
        <%= for rule <- @yara_rules do %>
          <.rule_checkbox
            id={rule.id}
            name={rule.name}
            description={rule.description}
            selected={rule.id in @selected_rules}
          />
        <% end %>
      <% end %>

      <%= if @export_type == "sigma" do %>
        <%= for rule <- @sigma_rules do %>
          <.rule_checkbox
            id={rule.id}
            name={rule.name}
            description={rule.description}
            selected={rule.id in @selected_rules}
          />
        <% end %>
      <% end %>

      <%= if @export_type == "ioc" do %>
        <%= for ioc <- @iocs do %>
          <.rule_checkbox
            id={ioc.id}
            name={"#{ioc.type}: #{ioc.value}"}
            description={ioc.description}
            selected={ioc.id in @selected_rules}
          />
        <% end %>
      <% end %>
    </div>

    <div class="mt-4 flex justify-between items-center">
      <span class="text-sm text-gray-600 dark:text-gray-400">
        <%= length(@selected_rules) %> rule(s) selected
      </span>
      <div class="space-x-2">
        <button
          phx-click="select_all"
          class="text-sm text-blue-600 hover:text-blue-700"
        >
          Select All
        </button>
        <button
          phx-click="deselect_all"
          class="text-sm text-blue-600 hover:text-blue-700"
        >
          Deselect All
        </button>
      </div>
    </div>
    """
  end

  defp rule_checkbox(assigns) do
    ~H"""
    <label class="flex items-center p-3 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer border-b border-gray-200 dark:border-gray-600">
      <input
        type="checkbox"
        phx-click="toggle_rule"
        phx-value-id={@id}
        checked={@selected}
        class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
      />
      <div class="ml-3 flex-1">
        <div class="text-sm font-medium text-gray-900 dark:text-white"><%= @name %></div>
        <%= if @description do %>
          <div class="text-xs text-gray-500 dark:text-gray-400"><%= @description %></div>
        <% end %>
      </div>
    </label>
    """
  end

  defp step_configure_export(assigns) do
    ~H"""
    <div>
      <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Configure Export Options</h3>
      <p class="text-sm text-gray-600 dark:text-gray-400 mb-6">Choose the export format and additional options.</p>

      <div class="space-y-6">
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
            Export Format
          </label>
          <div class="space-y-3">
            <%= if @export_type == "yara" do %>
              <.format_option
                format="native"
                title="Native YARA (.yar)"
                description="Standard YARA rule format"
                current={@export_format}
              />
              <.format_option
                format="json"
                title="JSON Bundle"
                description="Rules with metadata in JSON format"
                current={@export_format}
              />
            <% end %>

            <%= if @export_type == "sigma" do %>
              <.format_option
                format="yaml"
                title="YAML Format"
                description="Standard Sigma YAML format"
                current={@export_format}
              />
              <.format_option
                format="json"
                title="JSON Bundle"
                description="Rules with metadata in JSON format"
                current={@export_format}
              />
            <% end %>

            <%= if @export_type == "ioc" do %>
              <.format_option
                format="json"
                title="JSON Format"
                description="IOCs in JSON format"
                current={@export_format}
              />
              <.format_option
                format="csv"
                title="CSV Format"
                description="Comma-separated values"
                current={@export_format}
              />
              <.format_option
                format="stix"
                title="STIX 2.1"
                description="STIX 2.1 bundle format"
                current={@export_format}
              />
            <% end %>

            <%= if @export_type == "bundle" do %>
              <.format_option
                format="json"
                title="JSON Bundle"
                description="Complete bundle with all rule types"
                current={@export_format}
              />
            <% end %>
          </div>
        </div>

        <div class="space-y-3">
          <label class="flex items-center">
            <input
              type="checkbox"
              phx-click="toggle_metadata"
              checked={@include_metadata}
              class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <span class="ml-2 text-sm font-medium text-gray-700 dark:text-gray-300">
              Include Metadata
            </span>
          </label>
          <p class="ml-6 text-xs text-gray-500 dark:text-gray-400">
            Include rule ID, timestamps, author, and organizational context
          </p>

          <%= if @export_type in ["yara", "sigma"] do %>
            <label class="flex items-center">
              <input
                type="checkbox"
                phx-click="toggle_stats"
                checked={@include_stats}
                class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <span class="ml-2 text-sm font-medium text-gray-700 dark:text-gray-300">
                Include Performance Statistics
              </span>
            </label>
            <p class="ml-6 text-xs text-gray-500 dark:text-gray-400">
              Include execution count, match rate, and performance metrics
            </p>
          <% end %>
        </div>
      </div>
    </div>
    """
  end

  defp format_option(assigns) do
    ~H"""
    <label class="flex items-start cursor-pointer">
      <input
        type="radio"
        name="export_format"
        value={@format}
        phx-click="select_format"
        phx-value-format={@format}
        checked={@format == @current}
        class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 mt-1"
      />
      <div class="ml-3">
        <div class="text-sm font-medium text-gray-700 dark:text-gray-300"><%= @title %></div>
        <div class="text-xs text-gray-500 dark:text-gray-400"><%= @description %></div>
      </div>
    </label>
    """
  end

  defp step_download(assigns) do
    ~H"""
    <div>
      <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Download Export</h3>

      <%= if @export_result do %>
        <div class="text-center py-8">
          <div class="text-6xl mb-4">✅</div>
          <h4 class="text-xl font-semibold text-gray-900 dark:text-white mb-2">Export Ready!</h4>
          <p class="text-sm text-gray-600 dark:text-gray-400 mb-6">
            Your export has been generated and is ready to download.
          </p>

          <button
            phx-click="download_export"
            class="px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 font-semibold"
          >
            Download Export File
          </button>

          <div class="mt-6 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg text-left">
            <h5 class="text-sm font-semibold text-gray-900 dark:text-white mb-2">Export Details:</h5>
            <dl class="space-y-1 text-sm">
              <div class="flex justify-between">
                <dt class="text-gray-600 dark:text-gray-400">Type:</dt>
                <dd class="text-gray-900 dark:text-white font-medium"><%= String.upcase(@export_type) %></dd>
              </div>
              <div class="flex justify-between">
                <dt class="text-gray-600 dark:text-gray-400">Format:</dt>
                <dd class="text-gray-900 dark:text-white font-medium"><%= String.upcase(@export_format) %></dd>
              </div>
              <div class="flex justify-between">
                <dt class="text-gray-600 dark:text-gray-400">File Size:</dt>
                <dd class="text-gray-900 dark:text-white font-medium"><%= format_bytes(byte_size(@export_result)) %></dd>
              </div>
            </dl>
          </div>
        </div>
      <% else %>
        <div class="text-center py-8">
          <div class="text-4xl mb-4">⏳</div>
          <p class="text-gray-600 dark:text-gray-400">Click "Generate Export" to create your export file.</p>
        </div>
      <% end %>
    </div>
    """
  end

  defp template_card(assigns) do
    ~H"""
    <button
      phx-click="export_template"
      phx-value-template={@name}
      class="p-4 border-2 border-gray-200 dark:border-gray-700 rounded-lg hover:border-blue-400 transition-all text-left"
    >
      <div class="text-3xl mb-2"><%= @icon %></div>
      <h4 class="text-sm font-semibold text-gray-900 dark:text-white mb-1"><%= @title %></h4>
      <p class="text-xs text-gray-600 dark:text-gray-400"><%= @description %></p>
    </button>
    """
  end

  # Event Handlers

  @impl true
  def handle_event("select_export_type", %{"type" => type}, socket) do
    case parse_export_type(type) do
      nil ->
        {:noreply, put_flash(socket, :error, "Unknown export type")}

      export_type ->
        {:noreply,
         socket
         |> assign(:export_type, export_type)
         |> assign(:export_format, default_export_format(export_type))
         |> assign(:selected_rules, [])
         |> assign(:export_result, nil)}
    end
  end

  @impl true
  def handle_event("select_scope", %{"scope" => scope}, socket) do
    case parse_export_scope(scope) do
      nil ->
        {:noreply, put_flash(socket, :error, "Unknown export scope")}

      export_scope ->
        {:noreply, assign(socket, :export_scope, export_scope)}
    end
  end

  @impl true
  def handle_event("select_format", %{"format" => format}, socket) do
    case parse_export_format(format) do
      nil ->
        {:noreply, put_flash(socket, :error, "Unknown export format")}

      _format_atom ->
        {:noreply, assign(socket, :export_format, format)}
    end
  end

  @impl true
  def handle_event("toggle_metadata", _params, socket) do
    {:noreply, assign(socket, :include_metadata, !socket.assigns.include_metadata)}
  end

  @impl true
  def handle_event("toggle_stats", _params, socket) do
    {:noreply, assign(socket, :include_stats, !socket.assigns.include_stats)}
  end

  @impl true
  def handle_event("toggle_rule", %{"id" => id}, socket) do
    selected = socket.assigns.selected_rules

    new_selected =
      if id in selected do
        List.delete(selected, id)
      else
        [id | selected]
      end

    {:noreply, assign(socket, :selected_rules, new_selected)}
  end

  @impl true
  def handle_event("select_all", _params, socket) do
    all_ids = case socket.assigns.export_type do
      "yara" -> Enum.map(socket.assigns.yara_rules, & &1.id)
      "sigma" -> Enum.map(socket.assigns.sigma_rules, & &1.id)
      "ioc" -> Enum.map(socket.assigns.iocs, & &1.id)
      _ -> []
    end

    {:noreply, assign(socket, :selected_rules, all_ids)}
  end

  @impl true
  def handle_event("deselect_all", _params, socket) do
    {:noreply, assign(socket, :selected_rules, [])}
  end

  @impl true
  def handle_event("select_template", %{"template" => template}, socket) do
    {:noreply, assign(socket, :template, template)}
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
  def handle_event("generate_export", _params, socket) do
    result = perform_export(socket)

    case result do
      {:ok, content} ->
        socket =
          socket
          |> assign(:export_result, content)
          |> put_flash(:info, "Export generated successfully")

        {:noreply, socket}

      {:error, reason} ->
        socket =
          socket
          |> put_flash(:error, "Export failed: #{inspect(reason)}")

        {:noreply, socket}
    end
  end

  @impl true
  def handle_event("download_export", _params, socket) do
    if socket.assigns.export_result do
      filename = build_filename(socket)

      {:noreply,
       push_event(socket, "download", %{
         content: socket.assigns.export_result,
         filename: filename,
         mime_type: get_mime_type(socket.assigns.export_format)
       })}
    else
      {:noreply, socket}
    end
  end

  @impl true
  def handle_event("export_template", %{"template" => template}, socket) do
    case RuleExporter.export_template(template, socket.assigns.organization_id) do
      {:ok, content} ->
        filename = "#{template}_#{DateTime.utc_now() |> DateTime.to_unix()}.json"

        {:noreply,
         push_event(socket, "download", %{
           content: content,
           filename: filename,
           mime_type: "application/json"
         })}

      {:error, reason} ->
        socket = put_flash(socket, :error, "Export failed: #{inspect(reason)}")
        {:noreply, socket}
    end
  end

  # Helper Functions

  defp get_organization_id(socket) do
    socket.assigns.current_user.organization_id || Ecto.UUID.generate()
  end

  defp load_yara_rules(organization_id) do
    from(r in YaraRule, where: r.organization_id == ^organization_id, order_by: [asc: r.name])
    |> Repo.all()
  end

  defp load_sigma_rules(organization_id) do
    from(r in SigmaRule, where: r.organization_id == ^organization_id, order_by: [asc: r.name])
    |> Repo.all()
  end

  defp load_iocs(organization_id) do
    from(i in IOC, where: i.organization_id == ^organization_id, order_by: [asc: i.inserted_at], limit: 1000)
    |> Repo.all()
  end

  defp perform_export(socket) do
    with format when not is_nil(format) <- parse_export_format(socket.assigns.export_format),
         export_type when not is_nil(export_type) <- parse_export_type(socket.assigns.export_type),
         export_scope when not is_nil(export_scope) <- parse_export_scope(socket.assigns.export_scope) do
      opts = [
        include_metadata: socket.assigns.include_metadata,
        include_stats: socket.assigns.include_stats,
        format: format
      ]

      case export_type do
        "bundle" ->
          RuleExporter.export_bundle(socket.assigns.organization_id, opts)

        _ ->
          rule_ids = case export_scope do
            "all" ->
              get_all_rule_ids(export_type, socket.assigns.organization_id)

            "selected" ->
              socket.assigns.selected_rules

            "template" ->
              # Template export is handled separately
              []
          end

          case export_type do
            "yara" -> RuleExporter.export_yara_rules(rule_ids, opts)
            "sigma" -> RuleExporter.export_sigma_rules(rule_ids, opts)
            "ioc" -> RuleExporter.export_iocs(rule_ids, opts)
          end
      end
    else
      nil -> {:error, :invalid_export_options}
    end
  end

  defp parse_export_type("yara"), do: "yara"
  defp parse_export_type("sigma"), do: "sigma"
  defp parse_export_type("ioc"), do: "ioc"
  defp parse_export_type("bundle"), do: "bundle"
  defp parse_export_type(_), do: nil

  defp parse_export_scope("all"), do: "all"
  defp parse_export_scope("selected"), do: "selected"
  defp parse_export_scope("template"), do: "template"
  defp parse_export_scope(_), do: nil

  defp default_export_format("yara"), do: "native"
  defp default_export_format("sigma"), do: "yaml"
  defp default_export_format("ioc"), do: "json"
  defp default_export_format("bundle"), do: "json"

  defp parse_export_format("native"), do: :native
  defp parse_export_format("json"), do: :json
  defp parse_export_format("yaml"), do: :yaml
  defp parse_export_format("csv"), do: :csv
  defp parse_export_format("stix"), do: :stix
  defp parse_export_format(:native), do: :native
  defp parse_export_format(:json), do: :json
  defp parse_export_format(:yaml), do: :yaml
  defp parse_export_format(:csv), do: :csv
  defp parse_export_format(:stix), do: :stix
  defp parse_export_format(_), do: nil

  defp get_all_rule_ids(export_type, organization_id) do
    case export_type do
      "yara" ->
        from(r in YaraRule, where: r.organization_id == ^organization_id, select: r.id)
        |> Repo.all()

      "sigma" ->
        from(r in SigmaRule, where: r.organization_id == ^organization_id, select: r.id)
        |> Repo.all()

      "ioc" ->
        from(i in IOC, where: i.organization_id == ^organization_id, select: i.id)
        |> Repo.all()
    end
  end

  defp build_filename(socket) do
    timestamp = DateTime.utc_now() |> DateTime.to_unix()
    extension = case socket.assigns.export_format do
      "native" -> if socket.assigns.export_type == "yara", do: ".yar", else: ".yml"
      "yaml" -> ".yml"
      "json" -> ".json"
      "csv" -> ".csv"
      "stix" -> ".json"
      _ -> ".txt"
    end

    "tamandua_#{socket.assigns.export_type}_export_#{timestamp}#{extension}"
  end

  defp get_mime_type(format) do
    case format do
      "json" -> "application/json"
      "yaml" -> "text/yaml"
      "csv" -> "text/csv"
      "native" -> "text/plain"
      "stix" -> "application/json"
      _ -> "text/plain"
    end
  end

  defp format_bytes(bytes) when bytes < 1024, do: "#{bytes} B"
  defp format_bytes(bytes) when bytes < 1024 * 1024, do: "#{Float.round(bytes / 1024, 1)} KB"
  defp format_bytes(bytes), do: "#{Float.round(bytes / (1024 * 1024), 1)} MB"
end
