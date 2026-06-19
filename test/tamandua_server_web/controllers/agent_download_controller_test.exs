defmodule TamanduaServerWeb.AgentDownloadControllerTest do
  use TamanduaServerWeb.ConnCase, async: true

  describe "GET /downloads/agents/:filename" do
    test "refuses bare macOS agent binaries as product installers", %{conn: conn} do
      conn = get(conn, "/downloads/agents/tamandua-agent-macos-arm64")

      assert json_response(conn, 410)["error"] =~ "signed/notarized Tamandua EDR DMG or Cask"
    end

    test "refuses bare macOS checksum files with the same product guidance", %{conn: conn} do
      conn = get(conn, "/downloads/agents/tamandua-agent-macos-arm64.sha256")

      assert json_response(conn, 410)["error"] =~ "EndpointSecurity System Extension"
    end

    test "keeps unknown artifacts hidden", %{conn: conn} do
      conn = get(conn, "/downloads/agents/not-a-real-agent")

      assert json_response(conn, 404)["error"] == "Unknown agent binary"
    end
  end
end
