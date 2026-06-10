defmodule TamanduaServerWeb.LeaderboardLive do
  @moduledoc """
  LiveView for displaying the public bounty leaderboard.

  Shows top contributors by total bounties paid, with drill-down
  to individual wallet history and transaction details.
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Bounties
  alias TamanduaServer.Bounties.ContributorReputation
  alias TamanduaServer.Solana.Client

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Bounty Leaderboard")
      |> assign(:leaderboard, [])
      |> assign(:wallet_detail, nil)
      |> assign(:wallet_history, [])
      |> assign(:wallet_submissions, [])
      |> assign(:reputations_by_wallet, %{})
      |> load_leaderboard()

    {:ok, socket}
  end

  @impl true
  def handle_params(%{"wallet" => wallet}, _uri, socket) do
    socket =
      socket
      |> assign(:page_title, "Wallet: #{truncate_wallet(wallet)}")
      |> load_wallet_detail(wallet)

    {:noreply, socket}
  end

  @impl true
  def handle_params(_params, _uri, socket) do
    socket =
      socket
      |> assign(:page_title, "Bounty Leaderboard")
      |> assign(:wallet_detail, nil)
      |> assign(:wallet_history, [])
      |> assign(:wallet_submissions, [])
      |> assign(:reputations_by_wallet, %{})
      |> load_leaderboard()

    {:noreply, socket}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 py-8">
      <%= if @wallet_detail do %>
        <%= render_wallet_detail(assigns) %>
      <% else %>
        <%= render_leaderboard(assigns) %>
      <% end %>
    </div>
    """
  end

  defp render_leaderboard(assigns) do
    ~H"""
    <!-- Header -->
    <div class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
        <svg class="w-8 h-8 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M5 2a1 1 0 011 1v1h1a1 1 0 010 2H6v1a1 1 0 01-2 0V6H3a1 1 0 010-2h1V3a1 1 0 011-1zm0 10a1 1 0 011 1v1h1a1 1 0 110 2H6v1a1 1 0 11-2 0v-1H3a1 1 0 110-2h1v-1a1 1 0 011-1zM12 2a1 1 0 01.967.744L14.146 7.2 17.5 9.134a1 1 0 010 1.732l-3.354 1.935-1.18 4.455a1 1 0 01-1.933 0L9.854 12.8 6.5 10.866a1 1 0 010-1.732l3.354-1.935 1.18-4.455A1 1 0 0112 2z" clip-rule="evenodd"/>
        </svg>
        Bounty Leaderboard
      </h1>
      <p class="mt-2 text-gray-600 dark:text-gray-400">
        Top security researchers contributing to threat intelligence
      </p>
    </div>

    <!-- Stats Cards -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <div class="flex items-center">
          <div class="p-3 rounded-full bg-yellow-100 dark:bg-yellow-900">
            <svg class="w-6 h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M17 9V7a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2m2 4h10a2 2 0 002-2v-6a2 2 0 00-2-2H9a2 2 0 00-2 2v6a2 2 0 002 2zm7-5a2 2 0 11-4 0 2 2 0 014 0z"/>
            </svg>
          </div>
          <div class="ml-4">
            <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Total Distributed</p>
            <p class="text-2xl font-semibold text-gray-900 dark:text-white">
              <%= format_sol(total_distributed(@leaderboard)) %> SOL
            </p>
          </div>
        </div>
      </div>

      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <div class="flex items-center">
          <div class="p-3 rounded-full bg-blue-100 dark:bg-blue-900">
            <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"/>
            </svg>
          </div>
          <div class="ml-4">
            <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Contributors</p>
            <p class="text-2xl font-semibold text-gray-900 dark:text-white">
              <%= length(@leaderboard) %>
            </p>
          </div>
        </div>
      </div>

      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <div class="flex items-center">
          <div class="p-3 rounded-full bg-green-100 dark:bg-green-900">
            <svg class="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
            </svg>
          </div>
          <div class="ml-4">
            <p class="text-sm font-medium text-gray-500 dark:text-gray-400">Avg Bounty</p>
            <p class="text-2xl font-semibold text-gray-900 dark:text-white">
              <%= format_sol(avg_bounty(@leaderboard)) %> SOL
            </p>
          </div>
        </div>
      </div>
    </div>

    <!-- Leaderboard Table -->
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
      <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead class="bg-gray-50 dark:bg-gray-700">
          <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
              Rank
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
              Wallet
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
              Trust
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
              Total Earned
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
              Submissions
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
              Last Payment
            </th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
          <%= for {entry, index} <- Enum.with_index(@leaderboard, 1) do %>
            <tr class="hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer"
                phx-click="view_wallet" phx-value-wallet={entry.wallet}>
              <td class="px-6 py-4">
                <%= render_rank(assigns, index) %>
              </td>
              <td class="px-6 py-4">
                <div class="flex items-center">
                  <code class="text-sm font-mono text-gray-900 dark:text-white">
                    <%= truncate_wallet(entry.wallet) %>
                  </code>
                  <button phx-click="copy_wallet" phx-value-wallet={entry.wallet}
                          class="ml-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                    </svg>
                  </button>
                </div>
              </td>
              <td class="px-6 py-4">
                <%= render_trust_tier(assigns, reputation_for(@reputations_by_wallet, entry.wallet)) %>
              </td>
              <td class="px-6 py-4 text-sm font-semibold text-green-600 dark:text-green-400">
                <%= format_sol(entry.total_lamports) %> SOL
              </td>
              <td class="px-6 py-4 text-sm text-gray-900 dark:text-white">
                <%= entry.submission_count %>
              </td>
              <td class="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                <%= format_datetime(entry.last_payment) %>
              </td>
            </tr>
          <% end %>

          <%= if Enum.empty?(@leaderboard) do %>
            <tr>
              <td colspan="6" class="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                        d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <p class="mt-2 text-sm">No bounties paid yet</p>
                <p class="mt-1 text-xs text-gray-400">Be the first contributor!</p>
              </td>
            </tr>
          <% end %>
        </tbody>
      </table>
    </div>

    <!-- Info Banner -->
    <div class="mt-8 bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-4">
      <div class="flex">
        <div class="flex-shrink-0">
          <svg class="h-5 w-5 text-purple-400" fill="currentColor" viewBox="0 0 20 20">
            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"/>
          </svg>
        </div>
        <div class="ml-3">
          <h3 class="text-sm font-medium text-purple-800 dark:text-purple-200">
            Transparent Bounty System
          </h3>
          <p class="mt-1 text-sm text-purple-700 dark:text-purple-300">
            All bounty payments are recorded on Solana blockchain for transparency.
            Click any wallet to view transaction history and Solscan verification.
          </p>
        </div>
      </div>
    </div>
    """
  end

  defp render_wallet_detail(assigns) do
    ~H"""
    <!-- Back Button -->
    <div class="mb-6">
      <.link patch={~p"/live/leaderboard"} class="inline-flex items-center text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white">
        <svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
        </svg>
        Back to Leaderboard
      </.link>
    </div>

    <!-- Wallet Header -->
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-6 mb-6">
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Contributor Wallet</h1>
          <div class="flex items-center mt-2">
            <code class="text-lg font-mono text-gray-600 dark:text-gray-300">
              <%= @wallet_detail %>
            </code>
            <button phx-click="copy_wallet" phx-value-wallet={@wallet_detail}
                    class="ml-3 p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
              </svg>
            </button>
          </div>
          <div class="mt-3">
            <%= render_trust_tier(assigns, reputation_for(@reputations_by_wallet, @wallet_detail)) %>
          </div>
        </div>
        <a href={solscan_address_url(@wallet_detail)}
           target="_blank"
           class="inline-flex items-center px-4 py-2 border border-purple-600 text-purple-600 rounded-md hover:bg-purple-50 dark:hover:bg-purple-900">
          <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
          </svg>
          View on Solscan
        </a>
      </div>
    </div>

    <!-- Stats Row -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
        <p class="text-sm text-gray-500 dark:text-gray-400">Total Earned</p>
        <p class="text-xl font-bold text-green-600">
          <%= format_sol(wallet_total(@wallet_history)) %> SOL
        </p>
      </div>
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
        <p class="text-sm text-gray-500 dark:text-gray-400">Total Submissions</p>
        <p class="text-xl font-bold text-gray-900 dark:text-white">
          <%= length(@wallet_submissions) %>
        </p>
      </div>
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
        <p class="text-sm text-gray-500 dark:text-gray-400">Validated</p>
        <p class="text-xl font-bold text-blue-600">
          <%= Enum.count(@wallet_submissions, & &1.status in ["validated", "paid"]) %>
        </p>
      </div>
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
        <p class="text-sm text-gray-500 dark:text-gray-400">Paid</p>
        <p class="text-xl font-bold text-yellow-600">
          <%= length(@wallet_history) %>
        </p>
      </div>
    </div>

    <!-- Payment History -->
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden mb-8">
      <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
        <h2 class="text-lg font-medium text-gray-900 dark:text-white">Payment History</h2>
      </div>
      <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead class="bg-gray-50 dark:bg-gray-700">
          <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Submission
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Type
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Amount
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Date
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Transaction
            </th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
          <%= for payment <- @wallet_history do %>
            <tr>
              <td class="px-6 py-4 text-sm text-gray-900 dark:text-white">
                <%= payment.title %>
              </td>
              <td class="px-6 py-4">
                <span class={"px-2 py-1 text-xs font-semibold rounded-full #{type_class(payment.type)}"}>
                  <%= String.upcase(payment.type) %>
                </span>
              </td>
              <td class="px-6 py-4 text-sm font-semibold text-green-600">
                <%= format_sol(payment.amount_lamports) %> SOL
              </td>
              <td class="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                <%= format_datetime(payment.paid_at) %>
              </td>
              <td class="px-6 py-4">
                <a href={Client.solscan_url(payment.tx_id)}
                   target="_blank"
                   class="inline-flex items-center text-purple-600 hover:text-purple-800">
                  <span class="font-mono text-xs"><%= truncate_tx(payment.tx_id) %></span>
                  <svg class="w-4 h-4 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                          d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                  </svg>
                </a>
              </td>
            </tr>
          <% end %>

          <%= if Enum.empty?(@wallet_history) do %>
            <tr>
              <td colspan="5" class="px-6 py-8 text-center text-gray-500 dark:text-gray-400">
                No payments received yet
              </td>
            </tr>
          <% end %>
        </tbody>
      </table>
    </div>

    <!-- All Submissions -->
    <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
        <h2 class="text-lg font-medium text-gray-900 dark:text-white">All Submissions</h2>
      </div>
      <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead class="bg-gray-50 dark:bg-gray-700">
          <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Title
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Type
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Status
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Eligibility
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Risk Flags
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">
              Submitted
            </th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
          <%= for submission <- @wallet_submissions do %>
            <tr>
              <td class="px-6 py-4 text-sm text-gray-900 dark:text-white">
                <%= submission.title %>
              </td>
              <td class="px-6 py-4">
                <span class={"px-2 py-1 text-xs font-semibold rounded-full #{type_class(submission.type)}"}>
                  <%= String.upcase(submission.type) %>
                </span>
              </td>
              <td class="px-6 py-4">
                <span class={"px-2 py-1 text-xs font-semibold rounded-full #{status_class(submission.status)}"}>
                  <%= String.upcase(submission.status) %>
                </span>
              </td>
              <td class="px-6 py-4">
                <span class={"px-2 py-1 text-xs font-semibold rounded-full #{eligibility_class(submission.bounty_eligibility)}"}>
                  <%= format_eligibility(submission.bounty_eligibility) %>
                </span>
              </td>
              <td class="px-6 py-4">
                <%= render_risk_flags(assigns, submission.risk_flags || []) %>
              </td>
              <td class="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                <%= format_datetime(submission.inserted_at) %>
              </td>
            </tr>
          <% end %>

          <%= if Enum.empty?(@wallet_submissions) do %>
            <tr>
              <td colspan="6" class="px-6 py-8 text-center text-gray-500 dark:text-gray-400">
                No submissions from this wallet
              </td>
            </tr>
          <% end %>
        </tbody>
      </table>
    </div>
    """
  end

  defp render_rank(assigns, 1) do
    ~H"""
    <div class="flex items-center">
      <span class="text-2xl">&#129351;</span>
      <span class="ml-2 text-sm font-bold text-yellow-600">1st</span>
    </div>
    """
  end

  defp render_rank(assigns, 2) do
    ~H"""
    <div class="flex items-center">
      <span class="text-2xl">&#129352;</span>
      <span class="ml-2 text-sm font-bold text-gray-400">2nd</span>
    </div>
    """
  end

  defp render_rank(assigns, 3) do
    ~H"""
    <div class="flex items-center">
      <span class="text-2xl">&#129353;</span>
      <span class="ml-2 text-sm font-bold text-orange-600">3rd</span>
    </div>
    """
  end

  defp render_rank(assigns, n) do
    assigns = assign(assigns, :n, n)

    ~H"""
    <span class="text-sm font-medium text-gray-600 dark:text-gray-400">#<%= @n %></span>
    """
  end

  defp render_trust_tier(assigns, reputation) do
    assigns = assign(assigns, :reputation, reputation)

    ~H"""
    <span class={"px-2 py-1 text-xs font-semibold rounded-full #{trust_tier_class(@reputation && @reputation.trust_tier)}"}>
      <%= ContributorReputation.tier_display_name(@reputation && @reputation.trust_tier) %>
    </span>
    """
  end

  defp render_risk_flags(assigns, []) do
    ~H"""
    <span class="text-sm text-gray-400">-</span>
    """
  end

  defp render_risk_flags(assigns, flags) do
    assigns = assign(assigns, :flags, Enum.take(flags, 3))

    ~H"""
    <div class="flex max-w-xs flex-wrap gap-1">
      <%= for flag <- @flags do %>
        <span class="rounded bg-red-100 px-2 py-1 text-xs font-medium text-red-700 dark:bg-red-900 dark:text-red-200">
          <%= format_flag(flag) %>
        </span>
      <% end %>
    </div>
    """
  end

  # Event Handlers

  @impl true
  def handle_event("view_wallet", %{"wallet" => wallet}, socket) do
    {:noreply, push_patch(socket, to: ~p"/live/leaderboard/#{wallet}")}
  end

  @impl true
  def handle_event("copy_wallet", %{"wallet" => _wallet}, socket) do
    {:noreply, put_flash(socket, :info, "Wallet address copied!")}
  end

  # Private Functions

  defp load_leaderboard(socket) do
    leaderboard = Bounties.leaderboard_stats(limit: 50)
    reputations_by_wallet =
      leaderboard
      |> Enum.map(& &1.wallet)
      |> ContributorReputation.by_wallets()

    socket
    |> assign(:leaderboard, leaderboard)
    |> assign(:reputations_by_wallet, reputations_by_wallet)
  end

  defp load_wallet_detail(socket, wallet) do
    history = Bounties.wallet_history(wallet)
    submissions = Bounties.wallet_submissions(wallet)
    reputations_by_wallet = ContributorReputation.by_wallets([wallet])

    socket
    |> assign(:wallet_detail, wallet)
    |> assign(:wallet_history, history)
    |> assign(:wallet_submissions, submissions)
    |> assign(:reputations_by_wallet, reputations_by_wallet)
  end

  defp total_distributed(leaderboard) do
    Enum.reduce(leaderboard, 0, fn entry, acc -> acc + (entry.total_lamports || 0) end)
  end

  defp avg_bounty([]), do: 0
  defp avg_bounty(leaderboard) do
    total = total_distributed(leaderboard)
    count = Enum.reduce(leaderboard, 0, fn entry, acc -> acc + (entry.submission_count || 0) end)
    if count > 0, do: div(total, count), else: 0
  end

  defp wallet_total(history) do
    Enum.reduce(history, 0, fn entry, acc -> acc + (entry.amount_lamports || 0) end)
  end

  defp format_sol(nil), do: "0.000"
  defp format_sol(lamports) when is_integer(lamports) do
    sol = lamports / 1_000_000_000
    :erlang.float_to_binary(sol, decimals: 3)
  end

  defp format_datetime(nil), do: "-"
  defp format_datetime(dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  end

  defp truncate_wallet(nil), do: "-"
  defp truncate_wallet(wallet) when byte_size(wallet) > 12 do
    String.slice(wallet, 0, 6) <> "..." <> String.slice(wallet, -6, 6)
  end
  defp truncate_wallet(wallet), do: wallet

  defp truncate_tx(nil), do: "-"
  defp truncate_tx(tx) when byte_size(tx) > 16 do
    String.slice(tx, 0, 8) <> "..." <> String.slice(tx, -8, 8)
  end
  defp truncate_tx(tx), do: tx

  defp solscan_address_url(wallet) do
    "https://solscan.io/account/#{wallet}?cluster=devnet"
  end

  defp status_class("submitted"), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300"
  defp status_class("triaged"), do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
  defp status_class("validated"), do: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
  defp status_class("rejected"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
  defp status_class("paid"), do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
  defp status_class(_), do: "bg-gray-100 text-gray-800"

  defp type_class("ioc"), do: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200"
  defp type_class("rule"), do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
  defp type_class("sample_hash"), do: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
  defp type_class(_), do: "bg-gray-100 text-gray-800"

  defp eligibility_class("eligible"), do: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
  defp eligibility_class("ineligible"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
  defp eligibility_class("manual_review_required"), do: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
  defp eligibility_class(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300"

  defp trust_tier_class("restricted"), do: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
  defp trust_tier_class("partner"), do: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200"
  defp trust_tier_class("expert"), do: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
  defp trust_tier_class("trusted"), do: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
  defp trust_tier_class(_), do: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300"

  defp reputation_for(reputations_by_wallet, wallet) when is_binary(wallet) do
    Map.get(reputations_by_wallet, wallet) || ContributorReputation.default_for_wallet(wallet)
  end

  defp reputation_for(_reputations_by_wallet, _wallet), do: nil

  defp format_eligibility(nil), do: "PENDING"
  defp format_eligibility(value), do: value |> String.replace("_", " ") |> String.upcase()

  defp format_flag(flag), do: flag |> String.replace("_", " ") |> String.upcase()
end
