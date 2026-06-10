defmodule TamanduaServerWeb.BreadcrumbLiveTest do
  use TamanduaServerWeb.ConnCase

  import Phoenix.LiveViewTest
  import TamanduaServer.DeceptionFixtures

  alias TamanduaServer.Deception.Breadcrumbs

  @create_attrs %{
    type: :credential,
    agent_id: "test-agent-1",
    path: "/home/user/.config/credentials.txt",
    content_hash: "abc123",
    canary_token: "TAMANDUA-token-1",
    deployed_at: ~U[2024-01-01 00:00:00Z],
    status: :active
  }

  describe "Index" do
    test "lists all breadcrumb types", %{conn: conn} do
      {:ok, _index_live, html} = live(conn, ~p"/breadcrumbs")

      assert html =~ "Breadcrumb Gallery"
      assert html =~ "Credential File"
      assert html =~ "SSH Private Key"
      assert html =~ "Cloud Credentials"
      assert html =~ "Kubernetes Config"
    end

    test "displays deployment stats", %{conn: conn} do
      {:ok, _index_live, html} = live(conn, ~p"/breadcrumbs")

      assert html =~ "Total Deployed"
      assert html =~ "Active"
      assert html =~ "Accessed"
    end

    test "filters breadcrumbs by risk level", %{conn: conn} do
      {:ok, index_live, _html} = live(conn, ~p"/breadcrumbs")

      # Filter by critical risk
      html =
        index_live
        |> element("select[name='risk']")
        |> render_change(%{"risk" => "critical"})

      assert html =~ "SSH Private Key"
      assert html =~ "Cloud Credentials"
      refute html =~ "Network Share"
    end

    test "searches breadcrumbs", %{conn: conn} do
      {:ok, index_live, _html} = live(conn, ~p"/breadcrumbs")

      html =
        index_live
        |> element("input[name='query']")
        |> render_change(%{"query" => "ssh"})

      assert html =~ "SSH Private Key"
      refute html =~ "Browser Passwords"
    end

    test "opens preview modal", %{conn: conn} do
      {:ok, index_live, _html} = live(conn, ~p"/breadcrumbs")

      {:ok, _index_live, html} =
        index_live
        |> element("button[phx-click='preview'][phx-value-type='credential']")
        |> render_click()
        |> follow_redirect(conn)

      assert html =~ "Preview:"
      assert html =~ "system_credentials_backup"
    end

    test "navigates to deployment wizard", %{conn: conn} do
      {:ok, index_live, _html} = live(conn, ~p"/breadcrumbs")

      {:ok, deployment_live, _html} =
        index_live
        |> element("button[phx-click='deploy'][phx-value-type='ssh_key']")
        |> render_click()
        |> follow_redirect(conn)

      assert render(deployment_live) =~ "Deploy Breadcrumb"
      assert render(deployment_live) =~ "SSH Private Key"
    end
  end

  describe "Preview Modal" do
    test "displays breadcrumb content preview", %{conn: conn} do
      {:ok, _index_live, html} = live(conn, ~p"/breadcrumbs?preview=credential")

      assert html =~ "Preview:"
      assert html =~ "Suggested paths:"
      assert html =~ "VPN Access"
      assert html =~ "Production Database"
    end

    test "closes preview modal", %{conn: conn} do
      {:ok, index_live, _html} = live(conn, ~p"/breadcrumbs?preview=credential")

      {:ok, _index_live, html} =
        index_live
        |> element("button[phx-click='close_preview']")
        |> render_click()
        |> follow_redirect(conn)

      refute html =~ "Preview:"
    end

    test "navigates from preview to deployment", %{conn: conn} do
      {:ok, index_live, _html} = live(conn, ~p"/breadcrumbs?preview=api_token")

      {:ok, deployment_live, _html} =
        index_live
        |> element("button[phx-click='deploy'][phx-value-type='api_token']")
        |> render_click()
        |> follow_redirect(conn)

      assert render(deployment_live) =~ "Deploy Breadcrumb"
    end
  end
end
