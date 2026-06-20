defmodule TamanduaServerWeb.Controllers.API.V1.DNSControllerTest do
  use TamanduaServerWeb.ConnCase, async: true

  setup %{conn: conn} do
    {org, agent} = create_agent_with_org()
    user = insert!(:user, %{organization_id: org.id, role: "analyst"})
    {:ok, token, _claims} = TamanduaServer.Guardian.encode_and_sign(user)

    %{
      conn: put_req_header(conn, "authorization", "Bearer #{token}"),
      org: org,
      agent: agent
    }
  end

  describe "GET /api/v1/dns/queries" do
    test "surfaces DoH network telemetry as suspicious DNS records", %{
      conn: conn,
      org: org,
      agent: agent
    } do
      insert!(:network_event, %{
        agent_id: agent.id,
        organization_id: org.id,
        severity: "info",
        payload: %{
          "process_name" => "chrome.exe",
          "remote_ip" => "1.1.1.1",
          "remote_port" => 443,
          "protocol" => "tcp",
          "direction" => "outbound"
        }
      })

      conn = get(conn, "/api/v1/dns/queries?query_type=DOH")
      [record] = json_response(conn, 200)["data"]

      assert record["query_type"] == "DOH"
      assert record["transport"] == "doh"
      assert record["status"] == "suspicious"
      assert record["severity"] == "medium"
      assert record["domain"] == "DoH resolver 1.1.1.1:443"
    end

    test "filters DoT and plain DNS transport events", %{conn: conn, org: org, agent: agent} do
      insert!(:network_event, %{
        agent_id: agent.id,
        organization_id: org.id,
        payload: %{
          "process_name" => "systemd-resolved",
          "remote_ip" => "9.9.9.9",
          "remote_port" => "853"
        }
      })

      insert!(:network_event, %{
        agent_id: agent.id,
        organization_id: org.id,
        payload: %{
          "process_name" => "svchost.exe",
          "remote_ip" => "8.8.8.8",
          "remote_port" => "53"
        }
      })

      dot_conn = get(conn, "/api/v1/dns/queries?query_type=DOT")
      [dot] = json_response(dot_conn, 200)["data"]
      assert dot["query_type"] == "DOT"
      assert dot["transport"] == "dot"
      assert dot["status"] == "suspicious"

      transport_conn = get(conn, "/api/v1/dns/queries?query_type=TRANSPORT")
      [transport] = json_response(transport_conn, 200)["data"]
      assert transport["query_type"] == "TRANSPORT"
      assert transport["transport"] == "transport"
      assert transport["status"] == "allowed"
    end

    test "filters DNS records by process metadata", %{conn: conn, org: org, agent: agent} do
      insert!(:dns_event, %{
        agent_id: agent.id,
        organization_id: org.id,
        payload: %{
          "process" => %{
            "name" => "powershell.exe",
            "pid" => 4242
          },
          "query" => "beacon.example",
          "query_type" => "A"
        }
      })

      conn = get(conn, "/api/v1/dns/queries?process=powershell")
      [record] = json_response(conn, 200)["data"]

      assert record["domain"] == "beacon.example"
      assert record["process_name"] == "powershell.exe"
      assert record["pid"] == 4242
    end
  end
end
