defmodule TamanduaServer.LiveViewCase do
  @moduledoc """
  This module defines the test case for testing Phoenix LiveViews.

  Unlike the E2ECase which uses Wallaby for browser automation,
  this case uses Phoenix.LiveViewTest for server-side LiveView testing.

  This approach is:
  - Faster (no browser overhead)
  - Better for testing real-time features
  - Ideal for WebSocket and PubSub interactions
  - Perfect for LiveView-specific functionality

  ## Usage

      use TamanduaServer.LiveViewCase, async: false

      test "alert updates in real-time", %{conn: conn} do
        {:ok, view, _html} = live(conn, "/alerts")

        # Test interactions
        assert has_element?(view, ".alert")
      end
  """

  use ExUnit.CaseTemplate
  import ExUnit.Assertions
  import Phoenix.LiveViewTest, except: [assert_redirect: 2]

  using do
    quote do
      # Import conveniences for testing with LiveView
      import Phoenix.LiveViewTest
      import Phoenix.ConnTest
      import TamanduaServer.LiveViewCase

      # Import factory support
      import TamanduaServer.Factory

      # Alias common modules
      alias TamanduaServer.Repo
      alias TamanduaServerWeb.Endpoint

      # The default endpoint for testing
      @endpoint TamanduaServerWeb.Endpoint
    end
  end

  setup tags do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(TamanduaServer.Repo)

    unless tags[:async] do
      Ecto.Adapters.SQL.Sandbox.mode(TamanduaServer.Repo, {:shared, self()})
    end

    # Create a base connection for tests
    conn =
      Phoenix.ConnTest.build_conn()
      |> Plug.Test.init_test_session(%{})

    {:ok, conn: conn}
  end

  @doc """
  Helper to create authenticated connection for a user.
  """
  def log_in_user(conn, user) do
    token = TamanduaServer.Accounts.generate_user_session_token(user)

    conn
    |> Plug.Conn.put_session(:user_token, token)
  end

  @doc """
  Helper to wait for async operations to complete.
  """
  def wait_for(timeout \\ 1000, func) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_wait(func, deadline)
  end

  defp do_wait(func, deadline) do
    if System.monotonic_time(:millisecond) >= deadline do
      raise "Timeout waiting for condition"
    end

    if func.() do
      :ok
    else
      Process.sleep(50)
      do_wait(func, deadline)
    end
  end

  @doc """
  Helper to assert element appears within timeout.
  """
  def assert_element_appears(view, selector, timeout \\ 1000) do
    wait_for(timeout, fn ->
      has_element?(view, selector)
    end)
  end

  @doc """
  Helper to assert element disappears within timeout.
  """
  def assert_element_disappears(view, selector, timeout \\ 1000) do
    wait_for(timeout, fn ->
      not has_element?(view, selector)
    end)
  end

  @doc """
  Helper to assert text appears in view.
  """
  def assert_text_appears(view, text, timeout \\ 1000) do
    wait_for(timeout, fn ->
      render(view) =~ text
    end)
  end

  @doc """
  Helper to assert PubSub broadcast is received.
  """
  def assert_broadcast_received(topic, event, timeout \\ 1000) do
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, topic)

    receive do
      {^event, payload} -> {:ok, payload}
    after
      timeout -> raise "Did not receive broadcast #{event} on #{topic}"
    end
  end

  @doc """
  Helper to assert LiveView push event.
  """
  def assert_push_event(view, event, payload_matcher \\ %{}) do
    assert_receive {:push_event, ^event, payload}, 1000

    case payload_matcher do
      %{} when map_size(payload_matcher) == 0 ->
        # No matcher, just verify event was pushed
        :ok

      _ ->
        # Verify payload matches
        assert payload == payload_matcher
    end
  end

  @doc """
  Helper to create agent WebSocket connection for testing.
  """
  def setup_agent_socket(agent) do
    token = TamanduaServer.Agents.generate_token(agent)

    {:ok, socket} =
      Phoenix.ChannelTest.connect(TamanduaServerWeb.AgentSocket, %{"token" => token})

    {:ok, _, socket} =
      Phoenix.ChannelTest.subscribe_and_join(
        socket,
        TamanduaServerWeb.AgentChannel,
        "agent:#{agent.id}"
      )

    {:ok, socket}
  end

  @doc """
  Helper to simulate clicking and submitting a form.
  """
  def submit_form(view, form_selector, params) do
    view
    |> element(form_selector)
    |> render_submit(params)
  end

  @doc """
  Helper to fill and change form (live validation).
  """
  def change_form(view, form_selector, params) do
    view
    |> element(form_selector)
    |> render_change(params)
  end

  @doc """
  Helper to click an element.
  """
  def click_element(view, selector) do
    view
    |> element(selector)
    |> render_click()
  end

  @doc """
  Helper to assert redirect happened.
  """
  def assert_redirect(view, path) do
    Phoenix.LiveViewTest.assert_redirect(view, to: path)
  end

  @doc """
  Helper to assert flash message appears.
  """
  def assert_flash(view, type, message) do
    assert has_element?(view, ".alert-#{type}", message) or
             has_element?(view, ".flash-#{type}", message)
  end

  @doc """
  Helper to create a batch of test data.
  """
  def insert_list(count, factory_name, attrs \\ %{}) do
    for _ <- 1..count do
      TamanduaServer.Factory.insert(factory_name, attrs)
    end
  end

  @doc """
  Helper to broadcast a PubSub message.
  """
  def broadcast(topic, event, payload) do
    Phoenix.PubSub.broadcast(TamanduaServer.PubSub, topic, {event, payload})
  end

  @doc """
  Helper to subscribe to PubSub topic.
  """
  def subscribe(topic) do
    Phoenix.PubSub.subscribe(TamanduaServer.PubSub, topic)
  end

  @doc """
  Helper to unsubscribe from PubSub topic.
  """
  def unsubscribe(topic) do
    Phoenix.PubSub.unsubscribe(TamanduaServer.PubSub, topic)
  end

  @doc """
  Helper to render a LiveView hook event.
  """
  def trigger_hook(view, hook_name, params) do
    view
    |> render_hook(hook_name, params)
  end

  @doc """
  Helper to assert element count.
  """
  def assert_element_count(view, selector, count) do
    elements =
      view |> element(selector) |> render() |> Floki.parse_document!() |> Floki.find(selector)

    assert length(elements) == count
  end

  @doc """
  Helper to get element text content.
  """
  def get_text(view, selector) do
    view
    |> element(selector)
    |> render()
    |> Floki.parse_document!()
    |> Floki.find(selector)
    |> Floki.text()
  end

  @doc """
  Helper to wait for LiveView update cycle to complete.
  """
  def wait_for_update(view, timeout \\ 100) do
    Process.sleep(timeout)
    view
  end

  @doc """
  Helper to mock a real-time update via PubSub.
  """
  def simulate_realtime_update(topic, event, payload) do
    Phoenix.PubSub.broadcast!(TamanduaServer.PubSub, topic, {event, payload})
    # Give LiveView time to process
    Process.sleep(100)
  end

  @doc """
  Helper to assert that a view is still mounted (not disconnected).
  """
  def assert_view_mounted(view) do
    assert Process.alive?(view.pid)
  end

  @doc """
  Helper to simulate a file upload in LiveView.
  """
  def upload_file(view, selector, file_params) do
    view
    |> element(selector)
    |> render_upload(file_params)
  end

  @doc """
  Helper to assert form validation errors.
  """
  def assert_form_errors(view, form_selector, field, error_message) do
    assert has_element?(view, "#{form_selector} [phx-feedback-for='#{field}']", error_message)
  end

  @doc """
  Helper to render keyboard event.
  """
  def send_keydown(view, selector, key_params) do
    view
    |> element(selector)
    |> render_keydown(key_params)
  end

  @doc """
  Helper to render keyboard event.
  """
  def send_keyup(view, selector, key_params) do
    view
    |> element(selector)
    |> render_keyup(key_params)
  end

  @doc """
  Helper to focus an element.
  """
  def focus_element(view, selector) do
    view
    |> element(selector)
    |> render_focus()
  end

  @doc """
  Helper to blur an element.
  """
  def blur_element(view, selector) do
    view
    |> element(selector)
    |> render_blur()
  end
end
