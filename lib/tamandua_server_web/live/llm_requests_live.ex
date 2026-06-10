defmodule TamanduaServerWeb.LLMRequestsLive do
  @moduledoc """
  LLM Request Monitoring Dashboard

  Real-time monitoring of LLM API requests intercepted from agents.
  Displays request history with provider filtering, process correlation,
  and ML context integration for Phase 27 threat analysis.
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Detection.LLMRequestTracker
  alias TamanduaServer.Agents
  alias TamanduaServerWeb.Components.LLMRequestCard
  alias Phoenix.PubSub

  @refresh_interval 5_000

  @impl true
  def mount(params, _session, socket) do
    agent_id = params["agent_id"]
    agents = Agents.list_agents()

    # Use provided agent_id or default to first agent
    selected_agent_id = if agent_id do
      agent_id
    else
      if length(agents) > 0, do: hd(agents).agent_id, else: nil
    end

    if connected?(socket) do
      if selected_agent_id do
        PubSub.subscribe(TamanduaServer.PubSub, "llm_request:#{selected_agent_id}")
      end
      Process.send_after(self(), :refresh, @refresh_interval)
    end

    requests = if selected_agent_id do
      LLMRequestTracker.get_requests(selected_agent_id, limit: 50)
    else
      []
    end

    {:ok, assign(socket,
      agent_id: selected_agent_id,
      requests: requests,
      filter_provider: nil,
      search_query: "",
      auto_refresh: true,
      selected_request: nil,
      agents: agents
    )}
  end

  @impl true
  def handle_params(%{"agent_id" => agent_id}, _uri, socket) do
    # Re-subscribe when agent changes
    if socket.assigns[:agent_id] && socket.assigns.agent_id != agent_id do
      PubSub.unsubscribe(TamanduaServer.PubSub, "llm_request:#{socket.assigns.agent_id}")
      PubSub.subscribe(TamanduaServer.PubSub, "llm_request:#{agent_id}")
    end

    requests = LLMRequestTracker.get_requests(agent_id, limit: 50)
    {:noreply, assign(socket, agent_id: agent_id, requests: requests)}
  end

  def handle_params(_params, _uri, socket), do: {:noreply, socket}

  @impl true
  def handle_event("filter_provider", %{"provider" => provider}, socket) do
    filter = if provider == "", do: nil, else: String.to_existing_atom(provider)

    requests = if socket.assigns.agent_id do
      opts = if filter, do: [provider: filter, limit: 50], else: [limit: 50]
      LLMRequestTracker.get_requests(socket.assigns.agent_id, opts)
    else
      []
    end

    {:noreply, assign(socket, filter_provider: filter, requests: requests)}
  end

  def handle_event("search", %{"query" => query}, socket) do
    {:noreply, assign(socket, search_query: query)}
  end

  def handle_event("select_request", %{"id" => id}, socket) do
    request = Enum.find(socket.assigns.requests, &(&1.id == id))
    {:noreply, assign(socket, selected_request: request)}
  end

  def handle_event("toggle_refresh", _, socket) do
    auto_refresh = !socket.assigns.auto_refresh

    if auto_refresh do
      Process.send_after(self(), :refresh, @refresh_interval)
    end

    {:noreply, assign(socket, auto_refresh: auto_refresh)}
  end

  def handle_event("manual_refresh", _, socket) do
    requests = if socket.assigns.agent_id do
      LLMRequestTracker.get_requests(socket.assigns.agent_id, limit: 50)
    else
      []
    end

    {:noreply, assign(socket, requests: requests)}
  end

  def handle_event("select_agent", %{"agent_id" => agent_id}, socket) do
    # Unsubscribe from previous agent
    if socket.assigns.agent_id do
      PubSub.unsubscribe(TamanduaServer.PubSub, "llm_request:#{socket.assigns.agent_id}")
    end

    # Subscribe to new agent
    PubSub.subscribe(TamanduaServer.PubSub, "llm_request:#{agent_id}")

    requests = LLMRequestTracker.get_requests(agent_id, limit: 50)

    {:noreply, assign(socket, agent_id: agent_id, requests: requests, selected_request: nil)}
  end

  @impl true
  def handle_info({:llm_request_update, :new, request}, socket) do
    # Prepend new request, keep max 50
    requests = [request | socket.assigns.requests] |> Enum.take(50)
    {:noreply, assign(socket, requests: requests)}
  end

  def handle_info(:refresh, socket) do
    if socket.assigns.auto_refresh && socket.assigns.agent_id do
      requests = LLMRequestTracker.get_requests(socket.assigns.agent_id, limit: 50)
      Process.send_after(self(), :refresh, @refresh_interval)
      {:noreply, assign(socket, requests: requests)}
    else
      Process.send_after(self(), :refresh, @refresh_interval)
      {:noreply, socket}
    end
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    ~H"""
    <div class="llm-requests-dashboard max-w-7xl mx-auto p-6">
      <!-- Header -->
      <div class="header mb-6">
        <div class="flex justify-between items-center mb-4">
          <div>
            <h1 class="text-3xl font-bold">LLM API Requests</h1>
            <p class="text-gray-600 dark:text-gray-400">Monitor LLM API traffic intercepted from agents</p>
          </div>

          <div class="flex gap-2">
            <button
              phx-click="manual_refresh"
              class="btn btn-secondary"
            >
              <span class="heroicon-arrow-path" />
              Refresh
            </button>

            <button
              phx-click="toggle_refresh"
              class={["btn", if(@auto_refresh, do: "btn-primary", else: "btn-secondary")]}
            >
              <span class="heroicon-arrow-path" />
              Auto: <%= if @auto_refresh, do: "ON", else: "OFF" %>
            </button>
          </div>
        </div>

        <!-- Summary Stats -->
        <%= render_summary_stats(assigns) %>
      </div>

      <!-- Controls -->
      <div class="controls mb-4 flex gap-4">
        <!-- Agent Selector -->
        <div class="flex-none">
          <label class="block text-sm font-medium mb-1">Agent</label>
          <select
            phx-change="select_agent"
            name="agent_id"
            class="select select-bordered w-64"
            disabled={length(@agents) == 0}
          >
            <%= if length(@agents) == 0 do %>
              <option>No agents available</option>
            <% else %>
              <%= for agent <- @agents do %>
                <option
                  value={agent.agent_id}
                  selected={agent.agent_id == @agent_id}
                >
                  <%= agent.hostname || agent.agent_id %>
                </option>
              <% end %>
            <% end %>
          </select>
        </div>

        <!-- Provider Filter -->
        <div class="flex-none">
          <label class="block text-sm font-medium mb-1">API Provider</label>
          <select
            phx-change="filter_provider"
            name="provider"
            class="select select-bordered w-48"
          >
            <option value="" selected={is_nil(@filter_provider)}>All Providers</option>
            <option value="openai" selected={@filter_provider == :openai}>OpenAI</option>
            <option value="anthropic" selected={@filter_provider == :anthropic}>Anthropic</option>
            <option value="ollama" selected={@filter_provider == :ollama}>Ollama</option>
            <option value="huggingface" selected={@filter_provider == :huggingface}>HuggingFace</option>
            <option value="other" selected={@filter_provider == :other}>Other</option>
          </select>
        </div>

        <!-- Search -->
        <div class="flex-1">
          <label class="block text-sm font-medium mb-1">Search</label>
          <input
            type="text"
            placeholder="Search prompts or process names..."
            value={@search_query}
            phx-change="search"
            name="query"
            phx-debounce="300"
            class="input input-bordered w-full"
          />
        </div>
      </div>

      <!-- Main Content -->
      <%= if length(@requests) > 0 do %>
        <div class="grid grid-cols-1 gap-2">
          <%= for request <- filter_requests(@requests, @search_query) do %>
            <.live_component
              module={LLMRequestCard}
              id={request.id}
              request={request}
            />
          <% end %>
        </div>
      <% else %>
        <div class="text-center text-gray-500 dark:text-gray-400 py-12 bg-white dark:bg-gray-800 rounded-lg">
          <span class="text-4xl mb-2">🤖</span>
          <p class="text-lg font-medium">No LLM requests captured yet</p>
          <p class="text-sm mt-2">LLM API requests from the selected agent will appear here</p>
        </div>
      <% end %>
    </div>
    """
  end

  # Private functions

  defp render_summary_stats(assigns) do
    provider_counts = Enum.reduce(assigns.requests, %{}, fn request, acc ->
      Map.update(acc, request.api_provider, 1, &(&1 + 1))
    end)

    assigns = assign(assigns, :provider_counts, provider_counts)

    ~H"""
    <div class="stats shadow bg-white dark:bg-gray-800">
      <div class="stat">
        <div class="stat-title">Total Requests</div>
        <div class="stat-value text-primary"><%= length(@requests) %></div>
        <div class="stat-desc">Last 50 captured</div>
      </div>

      <div class="stat">
        <div class="stat-title">OpenAI</div>
        <div class="stat-value text-green-500"><%= Map.get(@provider_counts, :openai, 0) %></div>
      </div>

      <div class="stat">
        <div class="stat-title">Anthropic</div>
        <div class="stat-value text-orange-500"><%= Map.get(@provider_counts, :anthropic, 0) %></div>
      </div>

      <div class="stat">
        <div class="stat-title">Ollama</div>
        <div class="stat-value text-purple-500"><%= Map.get(@provider_counts, :ollama, 0) %></div>
      </div>

      <div class="stat">
        <div class="stat-title">HuggingFace</div>
        <div class="stat-value text-yellow-500"><%= Map.get(@provider_counts, :huggingface, 0) %></div>
      </div>
    </div>
    """
  end

  defp filter_requests(requests, ""), do: requests
  defp filter_requests(requests, search_query) do
    query_lower = String.downcase(search_query)

    Enum.filter(requests, fn request ->
      String.contains?(String.downcase(request.process_name || ""), query_lower) ||
        String.contains?(String.downcase(request.prompt_preview || ""), query_lower) ||
        String.contains?(String.downcase(request.model || ""), query_lower)
    end)
  end
end
