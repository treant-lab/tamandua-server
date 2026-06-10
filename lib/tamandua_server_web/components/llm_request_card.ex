defmodule TamanduaServerWeb.Components.LLMRequestCard do
  use Phoenix.LiveComponent

  @provider_colors %{
    openai: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
    anthropic: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200",
    ollama: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200",
    huggingface: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
    other: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200"
  }

  def render(assigns) do
    ~H"""
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 mb-2 hover:shadow-md transition-shadow">
      <div class="flex items-center justify-between mb-2">
        <span class={"px-2 py-1 rounded text-xs font-medium #{provider_color(@request.api_provider)}"}>
          <%= format_provider(@request.api_provider) %>
        </span>
        <span class="text-xs text-gray-500 dark:text-gray-400">
          <%= format_timestamp(@request.timestamp) %>
        </span>
      </div>

      <div class="text-sm">
        <div class="font-medium text-gray-900 dark:text-gray-100">
          <%= @request.process_name %> (PID: <%= @request.pid %>)
        </div>
        <div class="text-gray-600 dark:text-gray-400 truncate" title={@request.prompt_preview}>
          <%= truncate(@request.prompt_preview, 100) %>
        </div>
        <%= if @request.model do %>
          <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">
            Model: <%= @request.model %>
          </div>
        <% end %>
      </div>

      <%= if @request.ml_context do %>
        <div class="mt-2 pt-2 border-t border-gray-100 dark:border-gray-700">
          <span class="text-xs text-blue-600 dark:text-blue-400">
            ML Runtime: <%= @request.ml_context.runtime_type %>
            <%= if @request.ml_context.framework do %>
              (<%= @request.ml_context.framework %>)
            <% end %>
          </span>
        </div>
      <% end %>
    </div>
    """
  end

  defp provider_color(provider), do: Map.get(@provider_colors, provider, @provider_colors.other)

  defp format_provider(:openai), do: "OpenAI"
  defp format_provider(:anthropic), do: "Anthropic"
  defp format_provider(:ollama), do: "Ollama"
  defp format_provider(:huggingface), do: "HuggingFace"
  defp format_provider(_), do: "Other"

  defp format_timestamp(%DateTime{} = ts), do: Calendar.strftime(ts, "%H:%M:%S")
  defp format_timestamp(_), do: "N/A"

  defp truncate(nil, _len), do: ""
  defp truncate(str, len) when is_binary(str) and byte_size(str) > len, do: String.slice(str, 0, len) <> "..."
  defp truncate(str, _len) when is_binary(str), do: str
  defp truncate(_str, _len), do: ""
end
