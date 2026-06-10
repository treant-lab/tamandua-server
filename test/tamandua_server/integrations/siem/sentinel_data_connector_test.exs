defmodule TamanduaServer.Integrations.SIEM.SentinelDataConnectorTest do
  use ExUnit.Case, async: true

  import Mox

  alias TamanduaServer.Integrations.SIEM.SentinelDataConnector

  setup :verify_on_exit!

  @valid_config %{
    tenant_id: "test-tenant-id",
    client_id: "test-client-id",
    client_secret: "test-secret",
    subscription_id: "test-sub-id",
    resource_group: "test-rg",
    workspace_name: "test-workspace",
    workspace_id: "test-workspace-id"
  }

  describe "register_connector/1" do
    test "registers Tamandua as a Data Connector in Azure Sentinel" do
      # Mock OAuth token request
      TamanduaServer.HTTPMock
      |> expect(:request, fn request, _finch, _opts ->
        assert String.contains?(to_string(request.path), "oauth2")

        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{"access_token" => "test-token", "expires_in" => 3600})
        }}
      end)
      # Mock connector registration
      |> expect(:request, fn request, _finch, _opts ->
        assert request.method == :put
        assert String.contains?(to_string(request.path), "dataConnectors")

        {:ok, %Finch.Response{
          status: 201,
          body: Jason.encode!(%{
            "id" => "connector-123",
            "name" => "Tamandua-EDR-Connector",
            "properties" => %{
              "connectorUiConfig" => %{
                "title" => "Tamandua EDR"
              }
            }
          })
        }}
      end)

      assert {:ok, connector_id} = SentinelDataConnector.register_connector(@valid_config)
      assert is_binary(connector_id)
    end

    test "returns error when registration fails" do
      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{"access_token" => "test-token"})
        }}
      end)
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{status: 400, body: "Bad Request"}}
      end)

      assert {:error, _} = SentinelDataConnector.register_connector(@valid_config)
    end
  end

  describe "unregister_connector/1" do
    test "removes the Data Connector registration" do
      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{"access_token" => "test-token"})
        }}
      end)
      |> expect(:request, fn request, _finch, _opts ->
        assert request.method == :delete

        {:ok, %Finch.Response{status: 200, body: ""}}
      end)

      assert :ok = SentinelDataConnector.unregister_connector(@valid_config)
    end
  end

  describe "get_connector_status/1" do
    test "returns connection health and last sync time" do
      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{"access_token" => "test-token"})
        }}
      end)
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{
            "id" => "connector-123",
            "name" => "Tamandua-EDR-Connector",
            "properties" => %{
              "lastDataReceivedOn" => "2026-04-15T10:00:00Z",
              "connectorState" => "Connected"
            }
          })
        }}
      end)

      assert {:ok, status} = SentinelDataConnector.get_connector_status(@valid_config)
      assert status[:state]
      assert status[:last_data_received]
    end
  end

  describe "create_analytics_rule/2" do
    test "creates detection rule in Sentinel for Tamandua alerts" do
      rule_config = %{
        name: "Tamandua Critical Alert Rule",
        description: "Alert on critical Tamandua detections",
        query: "TamanduaEDR_CL | where Severity == 'critical'",
        severity: "High",
        enabled: true
      }

      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{"access_token" => "test-token"})
        }}
      end)
      |> expect(:request, fn request, _finch, _opts ->
        assert request.method == :put
        assert String.contains?(to_string(request.path), "alertRules")

        {:ok, %Finch.Response{
          status: 201,
          body: Jason.encode!(%{
            "id" => "rule-123",
            "name" => rule_config.name,
            "properties" => %{
              "enabled" => true
            }
          })
        }}
      end)

      assert {:ok, rule_id} = SentinelDataConnector.create_analytics_rule(rule_config, @valid_config)
      assert is_binary(rule_id)
    end
  end

  describe "list_analytics_rules/1" do
    test "returns all Tamandua-related rules" do
      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{"access_token" => "test-token"})
        }}
      end)
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{
            "value" => [
              %{
                "id" => "rule-1",
                "name" => "Tamandua Critical Alerts",
                "properties" => %{"enabled" => true}
              },
              %{
                "id" => "rule-2",
                "name" => "Tamandua Credential Access",
                "properties" => %{"enabled" => true}
              }
            ]
          })
        }}
      end)

      assert {:ok, rules} = SentinelDataConnector.list_analytics_rules(@valid_config)
      assert is_list(rules)
      assert length(rules) == 2
    end
  end

  describe "get_default_analytics_rules/0" do
    test "returns predefined rules for critical, credential access, and persistence" do
      rules = SentinelDataConnector.get_default_analytics_rules()

      assert is_list(rules)
      assert length(rules) >= 3

      names = Enum.map(rules, & &1.name)
      assert Enum.any?(names, &String.contains?(&1, "Critical"))
      assert Enum.any?(names, &String.contains?(&1, "Credential"))
      assert Enum.any?(names, &String.contains?(&1, "Persistence"))
    end
  end
end
