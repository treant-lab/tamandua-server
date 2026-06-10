defmodule TamanduaServerWeb.API.V1.BillingControllerTest do
  @moduledoc """
  Tests for BillingController.
  """

  use TamanduaServerWeb.ConnCase

  alias TamanduaServer.Tenants
  alias TamanduaServer.Billing.UsageMeter

  setup %{conn: conn} do
    # Create test organization
    {:ok, org} =
      Tenants.create_organization(%{
        name: "Billing Test Org",
        slug: "billing-test-#{System.unique_integer([:positive])}"
      })

    # Create test user (simulated - in real tests, use fixture)
    user = %{
      id: Ecto.UUID.generate(),
      email: "admin@billing-test.com",
      role: "admin",
      organization_id: org.id
    }

    # Start UsageMeter if not started
    case GenServer.whereis(UsageMeter) do
      nil ->
        start_supervised!(UsageMeter)

      _pid ->
        :ok
    end

    conn =
      conn
      |> put_req_header("accept", "application/json")
      |> put_req_header("content-type", "application/json")
      |> assign(:current_user, user)
      |> assign(:current_organization, org)
      |> assign(:current_organization_id, org.id)

    {:ok, conn: conn, org: org, user: user}
  end

  describe "show" do
    test "returns no subscription for free tier", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/billing")

      response = json_response(conn, 200)
      assert response["data"] == nil
      assert response["message"] =~ "free tier"
      assert is_map(response["usage"])
    end

    test "returns usage metrics", %{conn: conn, org: org} do
      # Record some usage
      UsageMeter.record_api_call(org.id, 100)
      UsageMeter.record_scan(org.id, 10)

      conn = get(conn, ~p"/api/v1/billing")

      response = json_response(conn, 200)
      assert response["usage"]["api_calls"] == 100
      assert response["usage"]["model_scans"] == 10
    end
  end

  describe "usage" do
    test "returns current and historical usage", %{conn: conn, org: org} do
      # Record some usage
      UsageMeter.record_api_call(org.id, 50)
      UsageMeter.record_scan(org.id, 5)

      conn = get(conn, ~p"/api/v1/billing/usage")

      response = json_response(conn, 200)
      assert response["current"]["api_calls"] == 50
      assert response["current"]["model_scans"] == 5
      assert response["period_days"] == 30
      assert is_map(response["summary"])
    end

    test "accepts custom period days", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/billing/usage?days=7")

      response = json_response(conn, 200)
      assert response["period_days"] == 7
    end
  end

  describe "create_subscription" do
    test "requires valid tier", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/billing/subscribe", %{"tier" => "invalid"})

      response = json_response(conn, 400)
      assert response["error"] =~ "Invalid tier"
    end

    test "rejects subscription without Stripe configured", %{conn: conn} do
      # This will fail because Stripe prices aren't configured in test
      conn = post(conn, ~p"/api/v1/billing/subscribe", %{"tier" => "pro"})

      response = json_response(conn, 422)
      assert response["error"] =~ "not configured"
    end
  end

  describe "cancel_subscription" do
    test "returns error when no subscription exists", %{conn: conn} do
      conn = delete(conn, ~p"/api/v1/billing/subscribe")

      response = json_response(conn, 404)
      assert response["error"] =~ "No active subscription"
    end
  end

  describe "invoices" do
    test "returns empty list when no subscription", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/billing/invoices")

      response = json_response(conn, 200)
      assert response["data"] == []
    end
  end

  describe "portal" do
    test "returns error when no subscription exists", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/billing/portal")

      response = json_response(conn, 404)
      assert response["error"] =~ "No billing account"
    end
  end
end
