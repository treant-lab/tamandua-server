defmodule TamanduaServerWeb.API.V1.RelayControllerTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Solana.RelayBatch

  setup do
    previous_config = Application.get_env(:tamandua_server, RelayBatch)

    on_exit(fn ->
      if is_nil(previous_config) do
        Application.delete_env(:tamandua_server, RelayBatch)
      else
        Application.put_env(:tamandua_server, RelayBatch, previous_config)
      end
    end)

    :ok
  end

  test "fails closed when relay authentication is not configured", %{conn: conn} do
    Application.put_env(:tamandua_server, RelayBatch, api_key: "")

    conn = post(conn, "/api/v1/relay/attestations", valid_payload())

    assert %{"error" => "Relay authentication is not configured"} = json_response(conn, 503)
  end

  test "rejects a missing relay API key", %{conn: conn} do
    Application.put_env(:tamandua_server, RelayBatch, api_key: "expected-secret")

    conn = post(conn, "/api/v1/relay/attestations", valid_payload())

    assert %{"error" => "Invalid or missing relay API key"} = json_response(conn, 401)
  end

  test "rejects an invalid relay API key", %{conn: conn} do
    Application.put_env(:tamandua_server, RelayBatch, api_key: "expected-secret")

    conn =
      conn
      |> put_req_header("x-tamandua-relay-key", "attacker-secret")
      |> post("/api/v1/relay/attestations", valid_payload())

    assert %{"error" => "Invalid or missing relay API key"} = json_response(conn, 401)
  end

  defp valid_payload do
    %{
      "attestation" => %{
        "ih" => "0123456789abcdef",
        "s" => 8,
        "mt" => "incident"
      }
    }
  end
end
