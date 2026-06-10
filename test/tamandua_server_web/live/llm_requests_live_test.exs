defmodule TamanduaServerWeb.LLMRequestsLiveTest do
  use TamanduaServerWeb.ConnCase, async: false
  import Phoenix.LiveViewTest

  alias TamanduaServer.Detection.LLMRequestTracker

  setup do
    start_supervised!(LLMRequestTracker)
    :ok
  end

  describe "mount" do
    test "mounts successfully with agent_id param", %{conn: conn} do
      {:ok, view, html} = live(conn, "/llm-requests/test-agent")

      assert html =~ "LLM API Requests"
      assert view.assigns.agent_id == "test-agent"
    end

    test "mounts successfully without agent_id", %{conn: conn} do
      {:ok, view, html} = live(conn, "/llm-requests")

      assert html =~ "LLM API Requests"
      assert view.assigns.agent_id == nil
    end
  end

  describe "filter_provider event" do
    test "updates socket assigns and re-fetches requests", %{conn: conn} do
      LLMRequestTracker.track_request("test-agent", build_event(api_provider: :openai))
      LLMRequestTracker.track_request("test-agent", build_event(api_provider: :anthropic))

      {:ok, view, _html} = live(conn, "/llm-requests/test-agent")

      # Filter to OpenAI only
      view |> element("select[name=provider]") |> render_change(%{provider: "openai"})

      assert view.assigns.filter_provider == :openai
    end
  end

  describe "handle_info :llm_request_update" do
    test "prepends new request to list", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/llm-requests/test-agent")

      # Simulate PubSub message
      new_request = %{
        id: "new-1",
        agent_id: "test-agent",
        api_provider: :openai,
        prompt_preview: "New request",
        process_name: "python3",
        pid: 1234,
        timestamp: DateTime.utc_now()
      }
      send(view.pid, {:llm_request_update, :new, new_request})

      # Give it time to process
      :timer.sleep(50)

      # Request should be prepended
      assert hd(view.assigns.requests).id == "new-1"
    end
  end

  describe "LLMRequestCard component" do
    test "renders provider badge with correct color", %{conn: conn} do
      LLMRequestTracker.track_request("test-agent", build_event(api_provider: :openai))

      {:ok, _view, html} = live(conn, "/llm-requests/test-agent")

      assert html =~ "OpenAI"
      assert html =~ "bg-green-100"
    end
  end

  describe "routes" do
    test "/llm-requests route is registered", %{conn: conn} do
      conn = get(conn, "/llm-requests")
      assert html_response(conn, 200)
    end

    test "/llm-requests/:agent_id route is registered", %{conn: conn} do
      conn = get(conn, "/llm-requests/agent-123")
      assert html_response(conn, 200)
    end
  end

  defp build_event(overrides \\ []) do
    %{
      pid: Keyword.get(overrides, :pid, 1234),
      process_name: "python3",
      process_path: "/usr/bin/python3",
      api_provider: Keyword.get(overrides, :api_provider, :openai),
      api_endpoint: "api.openai.com",
      prompt_preview: "Test prompt",
      full_prompt_hash: "abc123",
      model: "gpt-4",
      timestamp: DateTime.utc_now()
    }
  end
end
