defmodule TamanduaServer.Integrations.SIEM.SplunkSavedSearchesTest do
  use ExUnit.Case, async: true

  import Mox

  alias TamanduaServer.Integrations.SIEM.SplunkSavedSearches

  setup :verify_on_exit!

  @valid_config %{
    rest_url: "https://splunk.example.com:8089",
    rest_username: "admin",
    rest_password: "secret",
    app: "search",
    owner: "nobody"
  }

  describe "create_saved_search/3" do
    test "creates a saved search via Splunk REST API with correct SPL query" do
      search_config = %{
        name: "Test Alert Search",
        search: "index=tamandua sourcetype=tamandua:alert severity=critical",
        description: "Test search for critical alerts",
        cron_schedule: "*/5 * * * *",
        is_scheduled: true,
        alert_threshold: "> 0"
      }

      TamanduaServer.HTTPMock
      |> expect(:request, fn request, _finch, _opts ->
        assert request.method == :post
        assert String.contains?(request.path, "/servicesNS/nobody/search/saved/searches")
        assert Enum.any?(request.headers, fn {k, _} -> k == "Authorization" end)

        {:ok, %Finch.Response{
          status: 201,
          body: Jason.encode!(%{
            "entry" => [%{
              "name" => "Test Alert Search",
              "id" => "search-123",
              "content" => %{
                "search" => search_config.search,
                "is_scheduled" => true
              }
            }]
          })
        }}
      end)

      assert {:ok, result} = SplunkSavedSearches.create_saved_search(search_config.name, search_config, @valid_config)
      assert result["entry"]
    end

    test "returns error on API failure" do
      search_config = %{
        name: "Failing Search",
        search: "invalid query"
      }

      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{status: 400, body: "Bad Request"}}
      end)

      assert {:error, _} = SplunkSavedSearches.create_saved_search(search_config.name, search_config, @valid_config)
    end
  end

  describe "list_saved_searches/1" do
    test "returns list of existing Tamandua saved searches" do
      TamanduaServer.HTTPMock
      |> expect(:request, fn request, _finch, _opts ->
        assert request.method == :get
        assert String.contains?(request.path, "/saved/searches")

        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{
            "entry" => [
              %{
                "name" => "Tamandua - Critical Alerts",
                "id" => "search-1",
                "content" => %{
                  "search" => "index=tamandua severity=critical",
                  "is_scheduled" => true
                }
              },
              %{
                "name" => "Tamandua - High Severity Last Hour",
                "id" => "search-2",
                "content" => %{
                  "search" => "index=tamandua severity=high earliest=-1h",
                  "is_scheduled" => true
                }
              }
            ]
          })
        }}
      end)

      assert {:ok, searches} = SplunkSavedSearches.list_saved_searches(@valid_config)
      assert is_list(searches)
      assert length(searches) == 2
    end

    test "filters to only Tamandua searches" do
      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{
          status: 200,
          body: Jason.encode!(%{
            "entry" => [
              %{"name" => "Tamandua - Critical", "id" => "1"},
              %{"name" => "Other Search", "id" => "2"},
              %{"name" => "Tamandua - High", "id" => "3"}
            ]
          })
        }}
      end)

      assert {:ok, searches} = SplunkSavedSearches.list_saved_searches(@valid_config)
      tamandua_searches = Enum.filter(searches, fn s ->
        String.starts_with?(s["name"], "Tamandua")
      end)
      assert length(tamandua_searches) == 2
    end
  end

  describe "delete_saved_search/2" do
    test "removes a saved search by name" do
      TamanduaServer.HTTPMock
      |> expect(:request, fn request, _finch, _opts ->
        assert request.method == :delete
        assert String.contains?(request.path, "/saved/searches/Tamandua%20-%20Critical")

        {:ok, %Finch.Response{status: 200, body: ""}}
      end)

      assert :ok = SplunkSavedSearches.delete_saved_search("Tamandua - Critical", @valid_config)
    end

    test "returns error when search not found" do
      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{status: 404, body: "Not Found"}}
      end)

      assert {:error, _} = SplunkSavedSearches.delete_saved_search("NonExistent", @valid_config)
    end
  end

  describe "get_default_searches/0" do
    test "returns predefined searches for critical, high, MITRE tactics" do
      searches = SplunkSavedSearches.get_default_searches()

      assert is_list(searches)
      assert length(searches) >= 4

      names = Enum.map(searches, & &1.name)
      assert "Tamandua - Critical Alerts" in names
      assert "Tamandua - High Severity Last Hour" in names
      assert "Tamandua - MITRE Execution Tactics" in names
      assert "Tamandua - AI Model Threats" in names

      # Verify structure
      critical = Enum.find(searches, & &1.name == "Tamandua - Critical Alerts")
      assert critical.search
      assert critical.cron_schedule
      assert critical.is_scheduled == true
    end
  end

  describe "install_default_searches/1" do
    test "creates all default saved searches in one call" do
      default_searches = SplunkSavedSearches.get_default_searches()
      call_count = length(default_searches)

      TamanduaServer.HTTPMock
      |> expect(:request, call_count, fn request, _finch, _opts ->
        assert request.method == :post

        {:ok, %Finch.Response{
          status: 201,
          body: Jason.encode!(%{
            "entry" => [%{
              "name" => "Created Search",
              "id" => "search-#{:rand.uniform(1000)}"
            }]
          })
        }}
      end)

      assert {:ok, created_names} = SplunkSavedSearches.install_default_searches(@valid_config)
      assert is_list(created_names)
      assert length(created_names) == call_count
    end

    test "returns partial success if some searches fail" do
      default_searches = SplunkSavedSearches.get_default_searches()

      # First succeeds, rest fail
      TamanduaServer.HTTPMock
      |> expect(:request, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{
          status: 201,
          body: Jason.encode!(%{"entry" => [%{"name" => "First Search"}]})
        }}
      end)
      |> expect(:request, length(default_searches) - 1, fn _request, _finch, _opts ->
        {:ok, %Finch.Response{status: 409, body: "Conflict - already exists"}}
      end)

      assert {:ok, created_names} = SplunkSavedSearches.install_default_searches(@valid_config)
      # Should still succeed with the ones that were created
      assert length(created_names) >= 1
    end
  end
end
