defmodule TamanduaServer.E2ECase do
  @moduledoc """
  Base case for E2E tests with browser automation using Wallaby.

  This module provides:
  - Wallaby DSL for browser automation
  - Test database sandbox setup
  - Session management
  - Helper functions for common E2E patterns

  ## Usage

      use TamanduaServer.E2ECase, async: false

      test "user can view dashboard", %{session: session} do
        session
        |> visit("/dashboard")
        |> assert_has(Query.css(".dashboard"))
      end
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      use Wallaby.DSL

      import TamanduaServer.E2ECase
      import TamanduaServer.E2EHelpers
      import TamanduaServer.Factory

      alias TamanduaServer.Repo
      alias TamanduaServer.Accounts.{Organization, User}
      alias TamanduaServer.Agents.Agent
      alias TamanduaServer.Alerts.Alert
      alias TamanduaServer.Telemetry.Event
      alias Wallaby.Query
    end
  end

  setup tags do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(TamanduaServer.Repo)

    unless tags[:async] do
      Ecto.Adapters.SQL.Sandbox.mode(TamanduaServer.Repo, {:shared, self()})
    end

    metadata = Phoenix.Ecto.SQL.Sandbox.metadata_for(TamanduaServer.Repo, self())
    {:ok, session} = Wallaby.start_session(metadata: metadata)

    on_exit(fn ->
      Wallaby.end_session(session)
    end)

    {:ok, session: session}
  end

  @doc """
  Navigate to a path and wait for the page to load.
  """
  def visit_and_wait(session, path) do
    session
    |> Wallaby.Browser.visit(path)
    |> wait_for_page_load()
  end

  @doc """
  Wait for a page to fully load (looks for common loading indicators).
  """
  def wait_for_page_load(session) do
    # Wait for any loading spinners to disappear
    session
    |> Wallaby.Browser.execute_script("""
      return new Promise((resolve) => {
        if (document.readyState === 'complete') {
          resolve(true);
        } else {
          window.addEventListener('load', () => resolve(true));
        }
      });
    """)

    session
  end

  @doc """
  Wait for LiveView to mount and be ready.
  """
  def wait_for_live_view(session) do
    session
    |> Wallaby.Browser.assert_has(Query.css("[data-phx-main]", visible: true))
  end

  @doc """
  Wait for a specific element to appear on the page.
  """
  def wait_for(session, query, timeout \\ 5000) do
    session
    |> Wallaby.Browser.assert_has(query, count: :any, timeout: timeout)
  end

  @doc """
  Wait for a specific element to disappear from the page.
  """
  def wait_for_disappear(session, query, timeout \\ 5000) do
    session
    |> Wallaby.Browser.refute_has(query, timeout: timeout)
  end

  @doc """
  Take a screenshot for debugging.
  """
  def take_screenshot(session, name) do
    screenshot_dir = Path.join([File.cwd!(), "tmp", "screenshots"])
    File.mkdir_p!(screenshot_dir)

    path = Path.join(screenshot_dir, "#{name}_#{System.system_time(:second)}.png")
    Wallaby.Browser.take_screenshot(session, name: path)

    IO.puts("Screenshot saved to: #{path}")
    session
  end

  @doc """
  Execute JavaScript and return the result.
  """
  def execute_js(session, script) do
    Wallaby.Browser.execute_script(session, script)
  end

  @doc """
  Scroll to an element.
  """
  def scroll_to(session, query) do
    session
    |> Wallaby.Browser.execute_script(fn ->
      element = Query.compile(query)
      "arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});"
    end)
  end

  @doc """
  Drag and drop an element to a target.
  """
  def drag_and_drop(session, source_query, target_query) do
    source = Wallaby.Browser.find(session, source_query)
    target = Wallaby.Browser.find(session, target_query)

    session
    |> Wallaby.Browser.execute_script("""
      var source = arguments[0];
      var target = arguments[1];

      var dragStart = new DragEvent('dragstart', {
        bubbles: true,
        cancelable: true,
        dataTransfer: new DataTransfer()
      });

      var drop = new DragEvent('drop', {
        bubbles: true,
        cancelable: true,
        dataTransfer: dragStart.dataTransfer
      });

      source.dispatchEvent(dragStart);
      target.dispatchEvent(drop);
    """, [source, target])
  end

  @doc """
  Wait for an AJAX request to complete.
  """
  def wait_for_ajax(session, timeout \\ 5000) do
    session
    |> Wallaby.Browser.execute_script("""
      return new Promise((resolve) => {
        var start = Date.now();
        function check() {
          if (typeof jQuery !== 'undefined' && jQuery.active === 0) {
            resolve(true);
          } else if (Date.now() - start > #{timeout}) {
            resolve(true);
          } else {
            setTimeout(check, 100);
          }
        }
        check();
      });
    """)

    session
  end

  @doc """
  Fill in a form field by label.
  """
  def fill_in_by_label(session, label, value) do
    session
    |> Wallaby.Browser.fill_in(Query.fillable_field(label), with: value)
  end

  @doc """
  Select an option from a dropdown by label.
  """
  def select_by_label(session, label, option) do
    session
    |> Wallaby.Browser.select(Query.select(label), option: option)
  end

  @doc """
  Assert that a flash message is displayed.
  """
  def assert_flash(session, type, message) do
    session
    |> Wallaby.Browser.assert_has(Query.css(".alert-#{type}", text: message))
  end

  @doc """
  Assert that an error message is displayed.
  """
  def assert_error(session, message) do
    assert_flash(session, "error", message)
  end

  @doc """
  Assert that a success message is displayed.
  """
  def assert_success(session, message) do
    assert_flash(session, "success", message)
  end

  @doc """
  Click a button with specific text.
  """
  def click_button(session, text) do
    session
    |> Wallaby.Browser.click(Query.button(text))
  end

  @doc """
  Click a link with specific text.
  """
  def click_link(session, text) do
    session
    |> Wallaby.Browser.click(Query.link(text))
  end

  @doc """
  Wait for and click an element (useful for elements that appear dynamically).
  """
  def wait_and_click(session, query, timeout \\ 5000) do
    session
    |> wait_for(query, timeout)
    |> Wallaby.Browser.click(query)
  end

  @doc """
  Hover over an element.
  """
  def hover(session, query) do
    session
    |> Wallaby.Browser.hover(query)
  end

  @doc """
  Assert current path.
  """
  def assert_current_path(session, path) do
    current_path = Wallaby.Browser.current_path(session)
    assert current_path == path, "Expected to be at #{path}, but was at #{current_path}"
    session
  end

  @doc """
  Assert URL contains a substring.
  """
  def assert_path_contains(session, substring) do
    current_path = Wallaby.Browser.current_path(session)
    assert String.contains?(current_path, substring),
           "Expected path to contain '#{substring}', but path was: #{current_path}"
    session
  end
end
