defmodule TamanduaServerWeb.SettingsLive do
  use TamanduaServerWeb, :live_view

  @default_settings %{
    # Detection engine toggles
    "yara_enabled" => true,
    "sigma_enabled" => true,
    "ml_enabled" => true,
    # Alert thresholds
    "threat_threshold" => "0.7",
    "critical_threshold" => "0.9",
    "max_alerts_per_hour" => "100",
    # Agent defaults
    "default_batch_size" => "100",
    "default_batch_timeout" => "5",
    "default_heartbeat_interval" => "30",
    "default_reconnect_delay" => "5"
  }

  @impl true
  def mount(_params, _session, socket) do
    settings = load_settings()

    {:ok,
     socket
     |> assign(page_title: "Settings")
     |> assign(settings: settings)
     |> assign(saved: false)
     |> assign(errors: %{})}
  end

  @impl true
  def handle_event("toggle", %{"field" => field}, socket) do
    settings = Map.update!(socket.assigns.settings, field, &(!&1))
    {:noreply, assign(socket, settings: settings, saved: false)}
  end

  def handle_event("validate", %{"settings" => params}, socket) do
    errors = validate_settings(params)
    settings = merge_text_fields(socket.assigns.settings, params)
    {:noreply, assign(socket, settings: settings, errors: errors, saved: false)}
  end

  def handle_event("save", %{"settings" => params}, socket) do
    errors = validate_settings(params)

    if map_size(errors) == 0 do
      settings = merge_text_fields(socket.assigns.settings, params)
      save_settings(settings)

      {:noreply,
       socket
       |> assign(settings: settings, saved: true, errors: %{})
       |> put_flash(:info, "Settings saved successfully.")}
    else
      {:noreply, assign(socket, errors: errors)}
    end
  end

  # -----------------------------------------------------------------------
  # Settings persistence helpers
  # -----------------------------------------------------------------------

  defp load_settings do
    # Load from application env, falling back to defaults
    stored = Application.get_env(:tamandua_server, :platform_settings, %{})

    Map.merge(@default_settings, stored)
  rescue
    _ -> @default_settings
  end

  defp save_settings(settings) do
    Application.put_env(:tamandua_server, :platform_settings, settings)

    # Broadcast settings change so other components can react
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "settings:updated",
      {:settings_updated, settings}
    )
  end

  defp merge_text_fields(settings, params) do
    # Only merge text/numeric fields from form params; booleans are toggled separately
    text_fields = [
      "threat_threshold",
      "critical_threshold",
      "max_alerts_per_hour",
      "default_batch_size",
      "default_batch_timeout",
      "default_heartbeat_interval",
      "default_reconnect_delay"
    ]

    Enum.reduce(text_fields, settings, fn field, acc ->
      case Map.get(params, field) do
        nil -> acc
        value -> Map.put(acc, field, value)
      end
    end)
  end

  defp validate_settings(params) do
    errors = %{}

    errors = validate_float(errors, params, "threat_threshold", 0.0, 1.0)
    errors = validate_float(errors, params, "critical_threshold", 0.0, 1.0)
    errors = validate_integer(errors, params, "max_alerts_per_hour", 1, 10_000)
    errors = validate_integer(errors, params, "default_batch_size", 1, 10_000)
    errors = validate_integer(errors, params, "default_batch_timeout", 1, 300)
    errors = validate_integer(errors, params, "default_heartbeat_interval", 5, 600)
    errors = validate_integer(errors, params, "default_reconnect_delay", 1, 300)

    # Critical must be >= threat
    with {:ok, threat} <- parse_float(params["threat_threshold"]),
         {:ok, critical} <- parse_float(params["critical_threshold"]) do
      if critical < threat do
        Map.put(errors, "critical_threshold", "Must be >= threat threshold")
      else
        errors
      end
    else
      _ -> errors
    end
  end

  defp validate_float(errors, params, field, min, max) do
    case parse_float(params[field]) do
      {:ok, val} when val >= min and val <= max -> errors
      {:ok, _} -> Map.put(errors, field, "Must be between #{min} and #{max}")
      :error -> Map.put(errors, field, "Must be a valid number")
    end
  end

  defp validate_integer(errors, params, field, min, max) do
    case Integer.parse(params[field] || "") do
      {val, ""} when val >= min and val <= max -> errors
      {_, ""} -> Map.put(errors, field, "Must be between #{min} and #{max}")
      _ -> Map.put(errors, field, "Must be a valid integer")
    end
  end

  defp parse_float(nil), do: :error
  defp parse_float(str) do
    case Float.parse(str) do
      {val, _} -> {:ok, val}
      :error -> :error
    end
  end

  # -----------------------------------------------------------------------
  # Render
  # -----------------------------------------------------------------------

  @impl true
  def render(assigns) do
    ~H"""
    <div class="p-6 max-w-4xl mx-auto">
      <h1 class="text-2xl font-bold mb-6">Settings</h1>

      <.form for={%{}} phx-change="validate" phx-submit="save" as={:settings}>
        <%!-- Detection Engine Settings --%>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6 mb-6">
          <h2 class="text-lg font-bold mb-4">Detection Engine</h2>
          <p class="text-sm text-gray-500 mb-4">
            Enable or disable individual detection engines.
          </p>

          <div class="space-y-4">
            <div class="flex items-center justify-between">
              <div>
                <p class="font-medium text-gray-900 dark:text-gray-100">YARA Rules</p>
                <p class="text-sm text-gray-500">File-based pattern matching for malware signatures</p>
              </div>
              <button
                type="button"
                phx-click="toggle"
                phx-value-field="yara_enabled"
                class={"relative inline-flex h-6 w-11 items-center rounded-full transition-colors #{if @settings["yara_enabled"], do: "bg-blue-600", else: "bg-gray-300"}"}
              >
                <span class={"inline-block h-4 w-4 transform rounded-full bg-white transition-transform #{if @settings["yara_enabled"], do: "translate-x-6", else: "translate-x-1"}"} />
              </button>
            </div>

            <div class="flex items-center justify-between">
              <div>
                <p class="font-medium text-gray-900 dark:text-gray-100">Sigma Rules</p>
                <p class="text-sm text-gray-500">Log-based detection rules for behavioral patterns</p>
              </div>
              <button
                type="button"
                phx-click="toggle"
                phx-value-field="sigma_enabled"
                class={"relative inline-flex h-6 w-11 items-center rounded-full transition-colors #{if @settings["sigma_enabled"], do: "bg-blue-600", else: "bg-gray-300"}"}
              >
                <span class={"inline-block h-4 w-4 transform rounded-full bg-white transition-transform #{if @settings["sigma_enabled"], do: "translate-x-6", else: "translate-x-1"}"} />
              </button>
            </div>

            <div class="flex items-center justify-between">
              <div>
                <p class="font-medium text-gray-900 dark:text-gray-100">ML Analysis</p>
                <p class="text-sm text-gray-500">Machine learning-based malware detection (Malware-SMELL)</p>
              </div>
              <button
                type="button"
                phx-click="toggle"
                phx-value-field="ml_enabled"
                class={"relative inline-flex h-6 w-11 items-center rounded-full transition-colors #{if @settings["ml_enabled"], do: "bg-blue-600", else: "bg-gray-300"}"}
              >
                <span class={"inline-block h-4 w-4 transform rounded-full bg-white transition-transform #{if @settings["ml_enabled"], do: "translate-x-6", else: "translate-x-1"}"} />
              </button>
            </div>
          </div>
        </div>

        <%!-- Alert Thresholds --%>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6 mb-6">
          <h2 class="text-lg font-bold mb-4">Alert Thresholds</h2>
          <p class="text-sm text-gray-500 mb-4">
            Configure threat score thresholds that trigger alerts and automatic responses.
          </p>

          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Threat Threshold (0.0 - 1.0)
              </label>
              <input
                type="text"
                name="settings[threat_threshold]"
                value={@settings["threat_threshold"]}
                class={"w-full rounded-md border px-3 py-2 text-sm #{if @errors["threat_threshold"], do: "border-red-500", else: "border-gray-300 dark:border-gray-600"} bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"}
              />
              <%= if @errors["threat_threshold"] do %>
                <p class="text-red-500 text-xs mt-1"><%= @errors["threat_threshold"] %></p>
              <% end %>
              <p class="text-xs text-gray-400 mt-1">Events above this score create alerts</p>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Critical Threshold (0.0 - 1.0)
              </label>
              <input
                type="text"
                name="settings[critical_threshold]"
                value={@settings["critical_threshold"]}
                class={"w-full rounded-md border px-3 py-2 text-sm #{if @errors["critical_threshold"], do: "border-red-500", else: "border-gray-300 dark:border-gray-600"} bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"}
              />
              <%= if @errors["critical_threshold"] do %>
                <p class="text-red-500 text-xs mt-1"><%= @errors["critical_threshold"] %></p>
              <% end %>
              <p class="text-xs text-gray-400 mt-1">Events above this trigger auto-response</p>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Max Alerts / Hour
              </label>
              <input
                type="text"
                name="settings[max_alerts_per_hour]"
                value={@settings["max_alerts_per_hour"]}
                class={"w-full rounded-md border px-3 py-2 text-sm #{if @errors["max_alerts_per_hour"], do: "border-red-500", else: "border-gray-300 dark:border-gray-600"} bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"}
              />
              <%= if @errors["max_alerts_per_hour"] do %>
                <p class="text-red-500 text-xs mt-1"><%= @errors["max_alerts_per_hour"] %></p>
              <% end %>
              <p class="text-xs text-gray-400 mt-1">Rate limit to prevent alert fatigue</p>
            </div>
          </div>
        </div>

        <%!-- Agent Default Configuration --%>
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6 mb-6">
          <h2 class="text-lg font-bold mb-4">Agent Default Configuration</h2>
          <p class="text-sm text-gray-500 mb-4">
            Default settings pushed to newly registered agents.
          </p>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Batch Size
              </label>
              <input
                type="text"
                name="settings[default_batch_size]"
                value={@settings["default_batch_size"]}
                class={"w-full rounded-md border px-3 py-2 text-sm #{if @errors["default_batch_size"], do: "border-red-500", else: "border-gray-300 dark:border-gray-600"} bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"}
              />
              <%= if @errors["default_batch_size"] do %>
                <p class="text-red-500 text-xs mt-1"><%= @errors["default_batch_size"] %></p>
              <% end %>
              <p class="text-xs text-gray-400 mt-1">Events per telemetry batch</p>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Batch Timeout (seconds)
              </label>
              <input
                type="text"
                name="settings[default_batch_timeout]"
                value={@settings["default_batch_timeout"]}
                class={"w-full rounded-md border px-3 py-2 text-sm #{if @errors["default_batch_timeout"], do: "border-red-500", else: "border-gray-300 dark:border-gray-600"} bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"}
              />
              <%= if @errors["default_batch_timeout"] do %>
                <p class="text-red-500 text-xs mt-1"><%= @errors["default_batch_timeout"] %></p>
              <% end %>
              <p class="text-xs text-gray-400 mt-1">Max seconds before sending partial batch</p>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Heartbeat Interval (seconds)
              </label>
              <input
                type="text"
                name="settings[default_heartbeat_interval]"
                value={@settings["default_heartbeat_interval"]}
                class={"w-full rounded-md border px-3 py-2 text-sm #{if @errors["default_heartbeat_interval"], do: "border-red-500", else: "border-gray-300 dark:border-gray-600"} bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"}
              />
              <%= if @errors["default_heartbeat_interval"] do %>
                <p class="text-red-500 text-xs mt-1"><%= @errors["default_heartbeat_interval"] %></p>
              <% end %>
              <p class="text-xs text-gray-400 mt-1">Agent heartbeat frequency</p>
            </div>

            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Reconnect Delay (seconds)
              </label>
              <input
                type="text"
                name="settings[default_reconnect_delay]"
                value={@settings["default_reconnect_delay"]}
                class={"w-full rounded-md border px-3 py-2 text-sm #{if @errors["default_reconnect_delay"], do: "border-red-500", else: "border-gray-300 dark:border-gray-600"} bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"}
              />
              <%= if @errors["default_reconnect_delay"] do %>
                <p class="text-red-500 text-xs mt-1"><%= @errors["default_reconnect_delay"] %></p>
              <% end %>
              <p class="text-xs text-gray-400 mt-1">Base delay for exponential backoff</p>
            </div>
          </div>
        </div>

        <%!-- Save Button --%>
        <div class="flex items-center justify-end gap-4">
          <%= if @saved do %>
            <span class="text-green-600 text-sm">Settings saved.</span>
          <% end %>
          <button
            type="submit"
            class="bg-blue-600 hover:bg-blue-700 text-white font-medium px-6 py-2 rounded-md transition-colors"
          >
            Save Settings
          </button>
        </div>
      </.form>
    </div>
    """
  end
end
