defmodule TamanduaServerWeb.Controllers.API.V1.NDRControllerTest do
  use TamanduaServerWeb.ConnCase, async: true

  import TamanduaServer.Factory

  setup %{conn: conn} do
    org = insert(:organization)
    user = insert(:user, %{organization_id: org.id, role: "analyst"})
    {:ok, token, _claims} = TamanduaServer.Guardian.encode_and_sign(user)

    %{conn: put_req_header(conn, "authorization", "Bearer #{token}")}
  end

  describe "GET /api/v1/ndr/data-sources" do
    test "exposes live, historical, capability, and gap labels without strong historical claims", %{
      conn: conn
    } do
      response =
        conn
        |> get("/api/v1/ndr/data-sources")
        |> json_response(200)

      data = response["data"]

      assert data["status"] in ["live_only", "degraded", "unavailable"]
      assert data["live"]["status"] in ["live_only", "degraded", "unavailable"]
      assert data["historical"]["status"] in ["live_only", "degraded", "unavailable"]

      assert %{
               "flows" => flows,
               "dns" => dns,
               "packet_dpi" => packet_dpi,
               "tls_metadata" => tls_metadata,
               "bytes" => bytes,
               "persistence" => persistence
             } = data["capabilities"]

      for capability <- [flows, dns, packet_dpi, tls_metadata, bytes, persistence] do
        assert capability["status"] in ["live_only", "degraded", "unavailable"]
        assert is_boolean(capability["live"])
        assert is_boolean(capability["historical"])
        assert is_list(capability["gaps"])
      end

      assert packet_dpi["status"] == "unavailable"
      assert "packet_dpi:packet_capture_not_configured" in data["gaps"]
      assert "packet_dpi:dpi_payload_visibility_unavailable" in data["gaps"]
    end
  end
end
