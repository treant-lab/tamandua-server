defmodule TamanduaServerWeb.PaginationComponent do
  @moduledoc """
  Reusable pagination component for LiveView pages.

  ## Usage

      <.pagination
        page={@page}
        per_page={@per_page}
        total_count={@total_count}
        event_name="paginate"
      />

  ## Assigns

  - `page` - Current page number (1-indexed)
  - `per_page` - Number of items per page
  - `total_count` - Total number of items
  - `event_name` - Phoenix LiveView event name to emit (default: "paginate")
  """

  use Phoenix.Component
  import TamanduaServerWeb.CoreComponents

  attr :page, :integer, required: true
  attr :per_page, :integer, required: true
  attr :total_count, :integer, required: true
  attr :event_name, :string, default: "paginate"
  attr :class, :string, default: ""

  def pagination(assigns) do
    assigns = assign_pagination_data(assigns)

    ~H"""
    <div class={["flex items-center justify-between border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-4 py-3 sm:px-6", @class]}>
      <!-- Mobile pagination -->
      <div class="flex flex-1 justify-between sm:hidden">
        <button
          :if={@page > 1}
          phx-click={@event_name}
          phx-value-page={@page - 1}
          class="relative inline-flex items-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-600"
        >
          Previous
        </button>
        <button
          :if={@page < @total_pages}
          phx-click={@event_name}
          phx-value-page={@page + 1}
          class="relative ml-3 inline-flex items-center rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-600"
        >
          Next
        </button>
      </div>

      <!-- Desktop pagination -->
      <div class="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">
        <div>
          <p class="text-sm text-gray-700 dark:text-gray-300">
            Showing
            <span class="font-medium"><%= @start_item %></span>
            to
            <span class="font-medium"><%= @end_item %></span>
            of
            <span class="font-medium"><%= @total_count %></span>
            results
          </p>
        </div>
        <div>
          <nav class="isolate inline-flex -space-x-px rounded-md shadow-sm" aria-label="Pagination">
            <!-- Previous button -->
            <button
              :if={@page > 1}
              phx-click={@event_name}
              phx-value-page={@page - 1}
              class="relative inline-flex items-center rounded-l-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 dark:ring-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 focus:z-20 focus:outline-offset-0"
            >
              <span class="sr-only">Previous</span>
              <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fill-rule="evenodd" d="M12.79 5.23a.75.75 0 01-.02 1.06L8.832 10l3.938 3.71a.75.75 0 11-1.04 1.08l-4.5-4.25a.75.75 0 010-1.08l4.5-4.25a.75.75 0 011.06.02z" clip-rule="evenodd" />
              </svg>
            </button>
            <span
              :if={@page == 1}
              class="relative inline-flex items-center rounded-l-md px-2 py-2 text-gray-300 dark:text-gray-600 ring-1 ring-inset ring-gray-300 dark:ring-gray-600 cursor-not-allowed"
            >
              <span class="sr-only">Previous</span>
              <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fill-rule="evenodd" d="M12.79 5.23a.75.75 0 01-.02 1.06L8.832 10l3.938 3.71a.75.75 0 11-1.04 1.08l-4.5-4.25a.75.75 0 010-1.08l4.5-4.25a.75.75 0 011.06.02z" clip-rule="evenodd" />
              </svg>
            </span>

            <!-- Page numbers -->
            <%= for page_num <- @page_numbers do %>
              <%= if page_num == :ellipsis do %>
                <span class="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-700 dark:text-gray-400 ring-1 ring-inset ring-gray-300 dark:ring-gray-600 cursor-default">...</span>
              <% else %>
                <button
                  phx-click={@event_name}
                  phx-value-page={page_num}
                  class={[
                    "relative inline-flex items-center px-4 py-2 text-sm font-semibold ring-1 ring-inset ring-gray-300 dark:ring-gray-600 focus:z-20 focus:outline-offset-0",
                    if(page_num == @page,
                      do: "z-10 bg-indigo-600 text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600",
                      else: "text-gray-900 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                    )
                  ]}
                  aria-current={if page_num == @page, do: "page"}
                >
                  <%= page_num %>
                </button>
              <% end %>
            <% end %>

            <!-- Next button -->
            <button
              :if={@page < @total_pages}
              phx-click={@event_name}
              phx-value-page={@page + 1}
              class="relative inline-flex items-center rounded-r-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 dark:ring-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 focus:z-20 focus:outline-offset-0"
            >
              <span class="sr-only">Next</span>
              <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clip-rule="evenodd" />
              </svg>
            </button>
            <span
              :if={@page >= @total_pages}
              class="relative inline-flex items-center rounded-r-md px-2 py-2 text-gray-300 dark:text-gray-600 ring-1 ring-inset ring-gray-300 dark:ring-gray-600 cursor-not-allowed"
            >
              <span class="sr-only">Next</span>
              <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clip-rule="evenodd" />
              </svg>
            </span>
          </nav>
        </div>
      </div>
    </div>
    """
  end

  # Calculate pagination metadata
  defp assign_pagination_data(assigns) do
    page = assigns.page
    per_page = assigns.per_page
    total_count = assigns.total_count

    total_pages = max(1, ceil(total_count / per_page))
    start_item = min((page - 1) * per_page + 1, total_count)
    end_item = min(page * per_page, total_count)

    page_numbers = calculate_page_numbers(page, total_pages)

    assigns
    |> assign(:total_pages, total_pages)
    |> assign(:start_item, start_item)
    |> assign(:end_item, end_item)
    |> assign(:page_numbers, page_numbers)
  end

  # Calculate which page numbers to display
  # Shows: 1 ... 4 5 [6] 7 8 ... 20
  defp calculate_page_numbers(current_page, total_pages) when total_pages <= 7 do
    1..total_pages |> Enum.to_list()
  end

  defp calculate_page_numbers(current_page, total_pages) do
    cond do
      # Near the start: 1 2 3 4 5 ... 20
      current_page <= 4 ->
        [1, 2, 3, 4, 5, :ellipsis, total_pages]

      # Near the end: 1 ... 16 17 18 19 20
      current_page >= total_pages - 3 ->
        [1, :ellipsis, total_pages - 4, total_pages - 3, total_pages - 2, total_pages - 1, total_pages]

      # In the middle: 1 ... 5 6 [7] 8 9 ... 20
      true ->
        [1, :ellipsis, current_page - 1, current_page, current_page + 1, :ellipsis, total_pages]
    end
  end
end
