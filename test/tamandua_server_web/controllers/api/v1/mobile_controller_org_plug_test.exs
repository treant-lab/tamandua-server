defmodule TamanduaServerWeb.API.V1.MobileControllerOrgPlugTest do
  @moduledoc """
  Database-free tests for the MobileController `:require_organization` plug.

  Previously `get_organization_id/1` raised "Organization ID not found" when
  the caller had no organization context, turning every such request into a
  500. The plug now rejects those requests with a 403 JSON error before the
  action runs. These tests invoke the controller module directly (the
  project has no ConnCase; controllers are plugs).
  """

  use ExUnit.Case, async: true

  alias TamanduaServerWeb.API.V1.MobileController

  # :event_types is a static, DB-free action -- ideal for exercising the
  # plug pipeline without needing Postgres.
  defp call_event_types(conn) do
    MobileController.call(conn, MobileController.init(:event_types))
  end

  defp build_conn do
    Plug.Test.conn(:get, "/api/v1/mobile/event-types")
    |> Phoenix.Controller.put_format("json")
  end

  test "halts with 403 when no organization context is present" do
    conn = call_event_types(build_conn())

    assert conn.halted
    assert conn.status == 403
    assert Jason.decode!(conn.resp_body)["error"] == "Organization context required"
  end

  test "halts with 403 when current_user has no organization" do
    conn =
      build_conn()
      |> Plug.Conn.assign(:current_user, %{organization_id: nil})
      |> call_event_types()

    assert conn.halted
    assert conn.status == 403
  end

  test "passes and normalizes org from current_user.organization_id" do
    org_id = Ecto.UUID.generate()

    conn =
      build_conn()
      |> Plug.Conn.assign(:current_user, %{organization_id: org_id})
      |> call_event_types()

    refute conn.halted
    assert conn.status == 200
    assert conn.assigns.organization_id == org_id
    assert %{"data" => [_ | _]} = Jason.decode!(conn.resp_body)
  end

  test "passes and normalizes org from current_organization_id assign" do
    org_id = Ecto.UUID.generate()

    conn =
      build_conn()
      |> Plug.Conn.assign(:current_organization_id, org_id)
      |> call_event_types()

    refute conn.halted
    assert conn.status == 200
    assert conn.assigns.organization_id == org_id
  end

  test "prefers an explicit organization_id assign when already set" do
    org_id = Ecto.UUID.generate()
    other_org = Ecto.UUID.generate()

    conn =
      build_conn()
      |> Plug.Conn.assign(:organization_id, org_id)
      |> Plug.Conn.assign(:current_user, %{organization_id: other_org})
      |> call_event_types()

    assert conn.status == 200
    assert conn.assigns.organization_id == org_id
  end
end
