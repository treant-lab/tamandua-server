defmodule TamanduaServerWeb.SubmissionsLive do
  @moduledoc """
  LiveView for managing security researcher contributions and submissions.

  Features:
  - Submission form for IOCs, rules, and sample hashes
  - List view with status filtering
  - Admin controls for validation, rejection, and payment
  - Real-time updates when submissions change
  """

  use TamanduaServerWeb, :live_view

  alias TamanduaServer.Bounties
  alias TamanduaServer.Bounties.{ContributorReputation, Submission, SubmissionValidator}
  alias TamanduaServer.Repo

  @impl true
  def mount(_params, session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(TamanduaServer.PubSub, "submissions")
    end

    organization_id = session["organization_id"]
    user = socket.assigns[:current_user]

    # Get primary Solana wallet if user has one linked
    user_wallet = get_user_solana_wallet(user)

    socket =
      socket
      |> assign(:page_title, "Contributions")
      |> assign(:organization_id, organization_id)
      |> assign(:is_admin, admin_user?(user))
      |> assign(:user_wallet, user_wallet)
      |> assign(:show_form, false)
      |> assign(:show_reject_modal, nil)
      |> assign(:show_pay_modal, nil)
      |> assign(:changeset, Bounties.change_submission(%Submission{}))
      |> assign(:filter, %{status: nil, type: nil})
      |> assign(:rejection_reason, "")
      |> assign(:pay_amount, "0.01")
      |> assign(:reputations_by_wallet, %{})
      |> load_submissions()

    {:ok, socket}
  end

  defp get_user_solana_wallet(nil), do: nil
  defp get_user_solana_wallet(user) do
    user = Repo.preload(user, :wallet_identities)
    case Enum.find(user.wallet_identities, & &1.chain == "solana") do
      nil -> nil
      identity -> identity.wallet_address
    end
  end

  @impl true
  def handle_params(params, _uri, socket) do
    filter = %{
      status: params["status"],
      type: params["type"]
    }

    {:noreply, socket |> assign(:filter, filter) |> load_submissions()}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 py-8">
      <!-- Header -->
      <div class="flex items-center justify-between mb-8">
        <div>
          <h1 class="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            <svg class="w-8 h-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
            </svg>
            Contributions
          </h1>
          <p class="mt-2 text-gray-600 dark:text-gray-400">
            Submit IOCs, detection rules, or sample hashes for bounty consideration
          </p>
        </div>
        <button phx-click="toggle_form"
                class="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
          <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
          </svg>
          Submit New
        </button>
      </div>

      <!-- Submission Form Modal -->
      <%= if @show_form do %>
        <div class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50" phx-click="close_form">
          <div class="relative top-20 mx-auto p-5 border w-full max-w-2xl shadow-lg rounded-md bg-white dark:bg-gray-800" phx-click-away="close_form">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-lg font-medium text-gray-900 dark:text-white">Submit Contribution</h3>
              <button phx-click="close_form" class="text-gray-400 hover:text-gray-500">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
              </button>
            </div>

            <.form for={@changeset} phx-change="validate" phx-submit="save" class="space-y-4">
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Type</label>
                <select name="submission[type]" class="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                  <option value="">Select type...</option>
                  <option value="ioc">IOC (Indicator of Compromise)</option>
                  <option value="rule">Detection Rule (YARA/Sigma)</option>
                  <option value="sample_hash">Sample Hash (SHA256)</option>
                </select>
                <%= if @changeset.errors[:type] do %>
                  <p class="mt-1 text-sm text-red-600"><%= elem(@changeset.errors[:type], 0) %></p>
                <% end %>
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Solana Wallet Address</label>
                <input type="text" name="submission[contributor_wallet]"
                       placeholder="Your Solana wallet for bounty payment"
                       value={get_field(@changeset, :contributor_wallet) || @user_wallet}
                       class="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 shadow-sm focus:border-blue-500 focus:ring-blue-500"/>
                <%= if @user_wallet && !get_field(@changeset, :contributor_wallet) do %>
                  <p class="mt-1 text-xs text-green-600 flex items-center">
                    <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                      <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                    </svg>
                    Using your connected wallet
                  </p>
                <% else %>
                  <p class="mt-1 text-xs text-gray-500">Base58 encoded, 32-44 characters</p>
                <% end %>
                <%= if @changeset.errors[:contributor_wallet] do %>
                  <p class="mt-1 text-sm text-red-600"><%= elem(@changeset.errors[:contributor_wallet], 0) %></p>
                <% end %>
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Title</label>
                <input type="text" name="submission[title]"
                       placeholder="Brief description of your contribution"
                       value={get_field(@changeset, :title)}
                       class="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 shadow-sm focus:border-blue-500 focus:ring-blue-500"/>
                <%= if @changeset.errors[:title] do %>
                  <p class="mt-1 text-sm text-red-600"><%= elem(@changeset.errors[:title], 0) %></p>
                <% end %>
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Description (optional)</label>
                <textarea name="submission[description]" rows="2"
                          placeholder="Additional context about your submission"
                          class="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 shadow-sm focus:border-blue-500 focus:ring-blue-500"><%= get_field(@changeset, :description) %></textarea>
              </div>

              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Payload</label>
                <textarea name="submission[payload]" rows="6"
                          placeholder={payload_placeholder(get_field(@changeset, :type))}
                          class="mt-1 block w-full font-mono text-sm rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700 shadow-sm focus:border-blue-500 focus:ring-blue-500"><%= format_payload(get_field(@changeset, :payload)) %></textarea>
                <p class="mt-1 text-xs text-gray-500">JSON format for IOCs, rule content for rules, hash value for samples</p>
              </div>

              <div class="flex justify-end gap-3 pt-4">
                <button type="button" phx-click="close_form"
                        class="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700">
                  Cancel
                </button>
                <button type="submit"
                        class="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700">
                  Submit
                </button>
              </div>
            </.form>
          </div>
        </div>
      <% end %>

      <!-- Filters -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow p-4 mb-6">
        <div class="flex flex-wrap gap-4 items-center">
          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Status</label>
            <select phx-change="filter" name="status"
                    class="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700">
              <option value="">All</option>
              <option value="submitted" selected={@filter.status == "submitted"}>Submitted</option>
              <option value="triaged" selected={@filter.status == "triaged"}>Triaged</option>
              <option value="validated" selected={@filter.status == "validated"}>Validated</option>
              <option value="rejected" selected={@filter.status == "rejected"}>Rejected</option>
              <option value="paid" selected={@filter.status == "paid"}>Paid</option>
            </select>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Type</label>
            <select phx-change="filter" name="type"
                    class="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700">
              <option value="">All</option>
              <option value="ioc" selected={@filter.type == "ioc"}>IOC</option>
              <option value="rule" selected={@filter.type == "rule"}>Rule</option>
              <option value="sample_hash" selected={@filter.type == "sample_hash"}>Sample Hash</option>
            </select>
          </div>
        </div>
      </div>

      <!-- Submissions Table -->
      <div class="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead class="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Submission
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Type
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Status
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Eligibility
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Risk Flags
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Wallet
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Trust
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Bounty
              </th>
              <%= if @is_admin do %>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Actions
                </th>
              <% end %>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-200 dark:divide-gray-700">
            <%= for submission <- @submissions do %>
              <tr class="hover:bg-gray-50 dark:hover:bg-gray-700">
                <td class="px-6 py-4">
                  <div class="text-sm font-medium text-gray-900 dark:text-white">
                    <%= submission.title %>
                  </div>
                  <div class="text-sm text-gray-500 dark:text-gray-400">
                    <%= Calendar.strftime(submission.inserted_at, "%Y-%m-%d %H:%M") %>
                  </div>
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
                  <%= render_eligibility(assigns, submission) %>
                </td>
                <td class="px-6 py-4">
                  <%= render_risk_flags(assigns, submission.risk_flags || []) %>
                </td>
                <td class="px-6 py-4 text-sm text-gray-500 dark:text-gray-400 font-mono">
                  <%= truncate_wallet(submission.contributor_wallet) %>
                </td>
                <td class="px-6 py-4">
                  <%= render_trust_tier(assigns, reputation_for(@reputations_by_wallet, submission.contributor_wallet)) %>
                </td>
                <td class="px-6 py-4">
                  <%= render_bounty_status(assigns, submission) %>
                </td>
                <%= if @is_admin do %>
                  <td class="px-6 py-4">
                    <%= render_admin_actions(assigns, submission) %>
                  </td>
                <% end %>
              </tr>
            <% end %>

            <%= if Enum.empty?(@submissions) do %>
              <tr>
                <td colspan={if @is_admin, do: 9, else: 8} class="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                  <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                          d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                  </svg>
                  <p class="mt-2 text-sm">No submissions found</p>
                  <p class="mt-1 text-xs text-gray-400">Click "Submit New" to contribute</p>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </div>

      <!-- Rejection Modal -->
      <%= if @show_reject_modal do %>
        <div class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div class="relative top-20 mx-auto p-5 border w-full max-w-md shadow-lg rounded-md bg-white dark:bg-gray-800">
            <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Reject Submission</h3>
            <form phx-submit="reject">
              <input type="hidden" name="submission_id" value={@show_reject_modal}/>
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Reason</label>
                <textarea name="reason" rows="3" required
                          placeholder="Explain why this submission is being rejected"
                          class="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700"><%= @rejection_reason %></textarea>
              </div>
              <div class="flex justify-end gap-3 mt-4">
                <button type="button" phx-click="close_reject_modal"
                        class="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300">
                  Cancel
                </button>
                <button type="submit"
                        class="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-red-600 hover:bg-red-700">
                  Reject
                </button>
              </div>
            </form>
          </div>
        </div>
      <% end %>

      <!-- Payment Modal -->
      <%= if @show_pay_modal do %>
        <div class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div class="relative top-20 mx-auto p-5 border w-full max-w-md shadow-lg rounded-md bg-white dark:bg-gray-800">
            <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4">Pay Bounty</h3>
            <form phx-submit="pay">
              <input type="hidden" name="submission_id" value={@show_pay_modal.id}/>
              <div class="mb-4">
                <p class="text-sm text-gray-600 dark:text-gray-400">
                  Paying to: <span class="font-mono"><%= @show_pay_modal.contributor_wallet %></span>
                </p>
                <div class="mt-3 flex flex-wrap gap-2">
                  <%= render_trust_tier(assigns, reputation_for(@reputations_by_wallet, @show_pay_modal.contributor_wallet)) %>
                  <%= render_eligibility(assigns, @show_pay_modal) %>
                </div>
                <div class="mt-2">
                  <%= render_risk_flags(assigns, @show_pay_modal.risk_flags || []) %>
                </div>
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300">Amount (SOL)</label>
                <input type="number" name="amount" step="0.001" min="0.001" required
                       value={@pay_amount}
                       class="mt-1 block w-full rounded-md border-gray-300 dark:border-gray-600 dark:bg-gray-700"/>
                <p class="mt-1 text-xs text-gray-500">Minimum: 0.001 SOL</p>
              </div>
              <div class="flex justify-end gap-3 mt-4">
                <button type="button" phx-click="close_pay_modal"
                        class="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300">
                  Cancel
                </button>
                <button type="submit"
                        class="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700">
                  Pay Bounty
                </button>
              </div>
            </form>
          </div>
        </div>
      <% end %>
    </div>
    """
  end

  defp render_bounty_status(assigns, submission) do
    assigns = assign(assigns, :submission, submission)

    ~H"""
    <%= if @submission.status == "paid" do %>
      <div class="flex items-center text-green-600">
        <svg class="w-4 h-4 mr-1" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
        </svg>
        <span class="text-sm font-medium">Paid</span>
      </div>
    <% else %>
      <%= if @submission.status == "validated" do %>
        <span class="text-sm text-yellow-600">Eligible</span>
      <% else %>
        <span class="text-sm text-gray-400">-</span>
      <% end %>
    <% end %>
    """
  end

  defp render_eligibility(assigns, submission) do
    assigns = assign(assigns, :submission, submission)

    ~H"""
    <span class={"px-2 py-1 text-xs font-semibold rounded-full #{eligibility_class(@submission.bounty_eligibility)}"}>
      <%= format_eligibility(@submission.bounty_eligibility) %>
    </span>
    <%= if @submission.bounty_eligibility_reason do %>
      <p class="mt-1 max-w-xs truncate text-xs text-gray-500 dark:text-gray-400" title={@submission.bounty_eligibility_reason}>
        <%= @submission.bounty_eligibility_reason %>
      </p>
    <% end %>
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

  defp render_trust_tier(assigns, reputation) do
    assigns = assign(assigns, :reputation, reputation)

    ~H"""
    <span class={"px-2 py-1 text-xs font-semibold rounded-full #{trust_tier_class(@reputation && @reputation.trust_tier)}"}>
      <%= ContributorReputation.tier_display_name(@reputation && @reputation.trust_tier) %>
    </span>
    """
  end

  defp render_admin_actions(assigns, submission) do
    assigns = assign(assigns, :submission, submission)

    ~H"""
    <div class="flex gap-2">
      <%= if @submission.status in ["submitted", "triaged"] do %>
        <button phx-click="validate" phx-value-id={@submission.id}
                title="Validate"
                class="p-1 text-green-600 hover:bg-green-100 rounded">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
          </svg>
        </button>
        <button phx-click="show_reject_modal" phx-value-id={@submission.id}
                title="Reject"
                class="p-1 text-red-600 hover:bg-red-100 rounded">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
          </svg>
        </button>
      <% end %>
      <%= if @submission.status == "validated" do %>
        <button phx-click="show_pay_modal" phx-value-id={@submission.id}
                title="Pay Bounty"
                class="p-1 text-yellow-600 hover:bg-yellow-100 rounded">
          <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
            <path d="M8.433 7.418c.155-.103.346-.196.567-.267v1.698a2.305 2.305 0 01-.567-.267C8.07 8.34 8 8.114 8 8c0-.114.07-.34.433-.582zM11 12.849v-1.698c.22.071.412.164.567.267.364.243.433.468.433.582 0 .114-.07.34-.433.582a2.305 2.305 0 01-.567.267z"/>
            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-13a1 1 0 10-2 0v.092a4.535 4.535 0 00-1.676.662C6.602 6.234 6 7.009 6 8c0 .99.602 1.765 1.324 2.246.48.32 1.054.545 1.676.662v1.941c-.391-.127-.68-.317-.843-.504a1 1 0 10-1.51 1.31c.562.649 1.413 1.076 2.353 1.253V15a1 1 0 102 0v-.092a4.535 4.535 0 001.676-.662C13.398 13.766 14 12.991 14 12c0-.99-.602-1.765-1.324-2.246A4.535 4.535 0 0011 9.092V7.151c.391.127.68.317.843.504a1 1 0 101.511-1.31c-.563-.649-1.413-1.076-2.354-1.253V5z" clip-rule="evenodd"/>
          </svg>
        </button>
      <% end %>
    </div>
    """
  end

  # Event Handlers

  @impl true
  def handle_event("toggle_form", _params, socket) do
    {:noreply, assign(socket, :show_form, !socket.assigns.show_form)}
  end

  @impl true
  def handle_event("close_form", _params, socket) do
    {:noreply, assign(socket, :show_form, false)}
  end

  @impl true
  def handle_event("validate", %{"submission" => params}, socket) do
    changeset =
      %Submission{}
      |> Bounties.change_submission(normalize_params(params))
      |> Map.put(:action, :validate)

    {:noreply, assign(socket, :changeset, changeset)}
  end

  @impl true
  def handle_event("save", %{"submission" => params}, socket) do
    params =
      params
      |> normalize_params()
      |> Map.put("organization_id", socket.assigns.organization_id)
      |> Map.put("submitted_by_id", socket.assigns.current_user && socket.assigns.current_user.id)

    case Bounties.create_submission(params) do
      {:ok, submission} ->
        ContributorReputation.record_submission(submission.contributor_wallet, :submitted)

        {:noreply,
         socket
         |> put_flash(:info, "Submission created successfully")
         |> assign(:show_form, false)
         |> assign(:changeset, Bounties.change_submission(%Submission{}))
         |> load_submissions()}

      {:error, changeset} ->
        {:noreply, assign(socket, :changeset, changeset)}
    end
  end

  @impl true
  def handle_event("filter", params, socket) do
    filter = %{
      status: empty_to_nil(params["status"]),
      type: empty_to_nil(params["type"])
    }

    {:noreply, socket |> assign(:filter, filter) |> load_submissions()}
  end

  @impl true
  def handle_event("validate", %{"id" => id}, socket) do
    if !socket.assigns.is_admin do
      {:noreply, put_flash(socket, :error, "Admin access required")}
    else
      user_id = socket.assigns.current_user && socket.assigns.current_user.id

      case validate_submission_for_review(id, user_id) do
        {:ok, submission} ->
          ContributorReputation.record_submission(
            submission.contributor_wallet,
            :validated,
            %{
              false_positive_rate: submission.false_positive_rate || 0.0,
              coverage_delta: submission.coverage_delta || 0.0
            }
          )

          {:noreply,
           socket
           |> put_flash(:info, "Submission validated")
           |> load_submissions()}

        {:error, reason} when is_binary(reason) ->
          {:noreply,
           socket
           |> put_flash(:error, reason)
           |> load_submissions()}

        {:error, _} ->
          {:noreply, put_flash(socket, :error, "Failed to validate submission")}
      end
    end
  end

  @impl true
  def handle_event("show_reject_modal", %{"id" => id}, socket) do
    if socket.assigns.is_admin do
      {:noreply, assign(socket, :show_reject_modal, id)}
    else
      {:noreply, put_flash(socket, :error, "Admin access required")}
    end
  end

  @impl true
  def handle_event("close_reject_modal", _params, socket) do
    {:noreply, assign(socket, :show_reject_modal, nil)}
  end

  @impl true
  def handle_event("reject", %{"submission_id" => id, "reason" => reason}, socket) do
    if !socket.assigns.is_admin do
      {:noreply, put_flash(socket, :error, "Admin access required")}
    else
      user_id = socket.assigns.current_user && socket.assigns.current_user.id

      case Bounties.reject_submission(id, user_id, reason) do
        {:ok, submission} ->
          ContributorReputation.record_submission(submission.contributor_wallet, rejection_event(reason))

          {:noreply,
           socket
           |> put_flash(:info, "Submission rejected")
           |> assign(:show_reject_modal, nil)
           |> load_submissions()}

        {:error, _} ->
          {:noreply, put_flash(socket, :error, "Failed to reject submission")}
      end
    end
  end

  @impl true
  def handle_event("show_pay_modal", %{"id" => id}, socket) do
    if socket.assigns.is_admin do
      submission = Bounties.get_submission!(id)
      {:noreply, assign(socket, :show_pay_modal, submission)}
    else
      {:noreply, put_flash(socket, :error, "Admin access required")}
    end
  end

  @impl true
  def handle_event("close_pay_modal", _params, socket) do
    {:noreply, assign(socket, :show_pay_modal, nil)}
  end

  @impl true
  def handle_event("pay", %{"submission_id" => id, "amount" => amount_str}, socket) do
    if !socket.assigns.is_admin do
      {:noreply, put_flash(socket, :error, "Admin access required")}
    else
      with {:ok, amount_lamports} <- parse_sol_amount(amount_str),
           submission <- Bounties.get_submission!(id),
           {:ok, :approved} <-
             ContributorReputation.check_bounty_requirements(
               submission.contributor_wallet,
               amount_lamports,
               submission
             ),
           {:ok, claim} <- Bounties.pay_bounty(id, amount_lamports) do
        ContributorReputation.record_submission(
          submission.contributor_wallet,
          :paid,
          %{amount_lamports: amount_lamports}
        )

        {:noreply,
         socket
         |> put_flash(:info, "Bounty paid! TX: #{truncate_tx(claim.tx_id)}")
         |> assign(:show_pay_modal, nil)
         |> load_submissions()}
      else
        {:error, reason} when is_binary(reason) ->
          {:noreply, put_flash(socket, :error, reason)}

        {:error, %Ecto.Changeset{}} ->
          {:noreply, put_flash(socket, :error, "Failed to pay bounty")}

        {:error, _} ->
          {:noreply, put_flash(socket, :error, "Failed to pay bounty")}
      end
    end
  end

  @impl true
  def handle_info({:submission_updated, _submission}, socket) do
    {:noreply, load_submissions(socket)}
  end

  @impl true
  def handle_info(_msg, socket), do: {:noreply, socket}

  # Private Functions

  defp load_submissions(socket) do
    org_id = socket.assigns.organization_id
    filter = socket.assigns.filter

    opts =
      [organization_id: org_id]
      |> maybe_add_filter(:status, filter.status)
      |> maybe_add_filter(:type, filter.type)

    submissions =
      Bounties.list_submissions(opts)
      |> Enum.sort_by(& &1.inserted_at, {:desc, DateTime})

    reputations_by_wallet =
      submissions
      |> Enum.map(& &1.contributor_wallet)
      |> ContributorReputation.by_wallets()

    socket
    |> assign(:submissions, submissions)
    |> assign(:reputations_by_wallet, reputations_by_wallet)
  end

  defp maybe_add_filter(opts, _key, nil), do: opts
  defp maybe_add_filter(opts, key, value), do: [{key, value} | opts]

  defp normalize_params(params) do
    payload = params["payload"]

    payload =
      if is_binary(payload) && String.trim(payload) != "" do
        case Jason.decode(payload) do
          {:ok, decoded} -> decoded
          {:error, _} -> %{"raw" => payload}
        end
      else
        %{}
      end

    Map.put(params, "payload", payload)
  end

  defp get_field(changeset, field) do
    Ecto.Changeset.get_field(changeset, field)
  end

  defp format_payload(nil), do: ""
  defp format_payload(payload) when is_map(payload) do
    Jason.encode!(payload, pretty: true)
  end
  defp format_payload(payload), do: to_string(payload)

  defp payload_placeholder(nil), do: "Select a type first..."
  defp payload_placeholder("ioc"), do: "[{\"type\": \"sha256\", \"value\": \"abc123...\"}]"
  defp payload_placeholder("rule"), do: "rule example { strings: $a = \"malware\" condition: $a }"
  defp payload_placeholder("sample_hash"), do: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  defp payload_placeholder(_), do: ""

  defp validate_submission_for_review(id, user_id) do
    submission = Bounties.get_submission!(id)

    case SubmissionValidator.validate(submission) do
      {:ok, %{bounty_eligibility: "ineligible"} = checked} ->
        ContributorReputation.record_submission(checked.contributor_wallet, :rejected)
        {:error, checked.bounty_eligibility_reason || "Submission is not bounty eligible"}

      {:ok, _checked} ->
        Bounties.validate_submission(id, user_id)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp rejection_event(reason) when is_binary(reason) do
    reason = String.downcase(reason)

    cond do
      String.contains?(reason, "duplicate") -> :duplicate
      String.contains?(reason, "pii") -> :pii_violation
      String.contains?(reason, "fraud") -> :fraud_flag
      true -> :rejected
    end
  end

  defp parse_sol_amount(value) when is_binary(value) do
    case Float.parse(value) do
      {amount, ""} when amount > 0 ->
        {:ok, round(amount * 1_000_000_000)}

      _ ->
        {:error, "Amount must be a positive SOL value"}
    end
  end

  defp parse_sol_amount(_), do: {:error, "Amount must be a positive SOL value"}

  defp reputation_for(reputations_by_wallet, wallet) when is_binary(wallet) do
    Map.get(reputations_by_wallet, wallet) || ContributorReputation.default_for_wallet(wallet)
  end

  defp reputation_for(_reputations_by_wallet, _wallet), do: nil

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

  defp format_eligibility(nil), do: "PENDING"
  defp format_eligibility(value), do: value |> String.replace("_", " ") |> String.upcase()

  defp format_flag(flag), do: flag |> String.replace("_", " ") |> String.upcase()

  defp truncate_wallet(nil), do: "-"
  defp truncate_wallet(wallet) when byte_size(wallet) > 12 do
    String.slice(wallet, 0, 4) <> "..." <> String.slice(wallet, -4, 4)
  end
  defp truncate_wallet(wallet), do: wallet

  defp truncate_tx(nil), do: "-"
  defp truncate_tx(tx) when byte_size(tx) > 16 do
    String.slice(tx, 0, 8) <> "..." <> String.slice(tx, -8, 8)
  end
  defp truncate_tx(tx), do: tx

  defp empty_to_nil(""), do: nil
  defp empty_to_nil(value), do: value

  defp admin_user?(nil), do: false
  defp admin_user?(%{role: role}) do
    role in ["admin", "superadmin", "super_admin", "owner", :admin, :superadmin, :super_admin, :owner]
  end
end
