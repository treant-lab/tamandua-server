defmodule TamanduaServerWeb.RegistriesLiveTest do
  use TamanduaServerWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias TamanduaServer.Registries.ModelProvenance
  alias TamanduaServer.Policies.ModelPolicy
  alias TamanduaServer.Repo

  setup %{conn: conn} do
    # Create a test user and log them in
    user = %{
      id: Ecto.UUID.generate(),
      email: "test@example.com",
      role: "admin"
    }

    conn = conn |> Plug.Test.init_test_session(%{}) |> put_session(:user_id, user.id)

    {:ok, conn: conn, user: user}
  end

  describe "mount/3" do
    @tag :skip
    test "renders the registries dashboard", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/live/registries")

      assert html =~ "Model Registries"
      assert html =~ "HuggingFace"
      assert html =~ "MLflow"
      assert html =~ "W&B"
      assert html =~ "Ollama"
    end

    @tag :skip
    test "shows registry health cards", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/live/registries")

      # Should show 4 registry cards
      assert html =~ "huggingface"
      assert html =~ "mlflow"
      assert html =~ "wandb"
      assert html =~ "ollama"
    end

    @tag :skip
    test "shows blocked count badge", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/live/registries")

      assert html =~ "blocked"
    end
  end

  describe "filter_registry event" do
    @tag :skip
    test "filters to specific registry", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/live/registries")

      html = view
             |> element("button", "Ollama")
             |> render_click()

      # Should show only Ollama models (or empty message for Ollama)
      assert html =~ "Ollama" or html =~ "No models found"
    end

    @tag :skip
    test "shows all registries when 'all' selected", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/live/registries")

      # First filter to one registry
      view |> element("button", "Ollama") |> render_click()

      # Then back to all
      html = view |> element("button", "All Registries") |> render_click()

      # Should show all registry tabs as active possibility
      assert html =~ "All Registries"
    end
  end

  describe "block/unblock actions" do
    setup do
      {:ok, provenance} = Repo.insert(%ModelProvenance{
        model_id: "test/block-action-model",
        registry: "huggingface",
        status: "clean",
        risk_score: 0.05,
        scanned_at: DateTime.utc_now(),
        downloaded_at: DateTime.utc_now()
      })

      on_exit(fn ->
        Repo.delete(provenance)
        ModelPolicy.unblock_model("test/block-action-model")
      end)

      {:ok, provenance: provenance}
    end

    test "block_model/2 adds model to block list" do
      model_id = "test/manual-block-test"

      assert ModelPolicy.explicitly_blocked?(model_id) == false

      ModelPolicy.block_model(model_id, "test")

      assert ModelPolicy.explicitly_blocked?(model_id) == true

      ModelPolicy.unblock_model(model_id)
    end

    test "unblock_model/1 removes model from block list" do
      model_id = "test/manual-unblock-test"

      ModelPolicy.block_model(model_id, "test")
      assert ModelPolicy.explicitly_blocked?(model_id) == true

      ModelPolicy.unblock_model(model_id)
      assert ModelPolicy.explicitly_blocked?(model_id) == false
    end
  end

  describe "provenance stats" do
    setup do
      {:ok, p1} = Repo.insert(%ModelProvenance{
        model_id: "test/stats-model-1",
        registry: "huggingface",
        status: "clean",
        risk_score: 0.02,
        scanned_at: DateTime.utc_now(),
        downloaded_at: DateTime.utc_now()
      })

      {:ok, p2} = Repo.insert(%ModelProvenance{
        model_id: "test/stats-model-2",
        registry: "mlflow",
        status: "suspicious",
        risk_score: 0.2,
        scanned_at: DateTime.utc_now(),
        downloaded_at: DateTime.utc_now()
      })

      on_exit(fn ->
        Repo.delete(p1)
        Repo.delete(p2)
      end)

      :ok
    end

    @tag :skip
    test "shows provenance statistics summary", %{conn: conn} do
      {:ok, _view, html} = live(conn, "/live/registries")

      assert html =~ "Scan Statistics"
      assert html =~ "Clean"
      assert html =~ "Suspicious"
      assert html =~ "Malicious"
      assert html =~ "Pending"
    end
  end

  describe "real-time updates" do
    @tag :skip
    test "subscribes to health status changes", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/live/registries")

      # Simulate health status change
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "registries:health",
        {:health_degraded, :huggingface, :timeout}
      )

      # Give time for the message to be processed
      Process.sleep(100)

      # View should still be alive
      assert Process.alive?(view.pid)
    end

    @tag :skip
    test "subscribes to model scan events", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/live/registries")

      # Simulate model scanned event
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "registries:downloads",
        {:model_scanned, "test/model", "clean", 0.05}
      )

      # Give time for the message to be processed
      Process.sleep(100)

      # View should still be alive
      assert Process.alive?(view.pid)
    end

    @tag :skip
    test "subscribes to Ollama model pull events", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/live/registries")

      # Simulate model pulled event
      Phoenix.PubSub.broadcast(
        TamanduaServer.PubSub,
        "registries:ollama",
        {:model_pulled, "llama2:7b", %{name: "llama2", sha: "abc123"}}
      )

      # Give time for the message to be processed
      Process.sleep(100)

      # View should still be alive
      assert Process.alive?(view.pid)
    end
  end

  describe "refresh action" do
    @tag :skip
    test "refresh_all event reloads all data", %{conn: conn} do
      {:ok, view, _html} = live(conn, "/live/registries")

      html = view
             |> element("button", "Refresh")
             |> render_click()

      # Should still render properly after refresh
      assert html =~ "Model Registries"
    end
  end
end
