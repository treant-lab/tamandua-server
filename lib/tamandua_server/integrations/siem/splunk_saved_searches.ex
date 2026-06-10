defmodule TamanduaServer.Integrations.SIEM.SplunkSavedSearches do
  @moduledoc """
  Manage Splunk saved searches for Tamandua alerts.

  Provides:
  - `create_saved_search/3` - Create a new saved search in Splunk
  - `list_saved_searches/1` - List existing Tamandua saved searches
  - `delete_saved_search/2` - Remove a saved search by name
  - `get_default_searches/0` - Return predefined search configurations
  - `install_default_searches/1` - Install all default searches in one call

  Uses the Splunk REST API at `/servicesNS/{owner}/{app}/saved/searches`.
  """

  require Logger

  alias TamanduaServer.Integrations.IntegrationLog

  @saved_searches_endpoint "/servicesNS"
  @default_app "search"
  @default_owner "nobody"
  @default_timeout_ms 30_000

  # Default saved searches for common Tamandua alert patterns
  @default_searches [
    %{
      name: "Tamandua - Critical Alerts",
      search: "index=tamandua sourcetype=tamandua:alert severity=critical | stats count by title, hostname",
      description: "Critical severity alerts from Tamandua EDR",
      cron_schedule: "*/5 * * * *",
      is_scheduled: true,
      alert_threshold: "> 0",
      alert_type: "always",
      actions: "email"
    },
    %{
      name: "Tamandua - High Severity Last Hour",
      search: "index=tamandua sourcetype=tamandua:alert severity=high earliest=-1h | table _time, title, hostname, severity",
      description: "High severity alerts in the last hour",
      cron_schedule: "0 * * * *",
      is_scheduled: true
    },
    %{
      name: "Tamandua - MITRE Execution Tactics",
      search: "index=tamandua sourcetype=tamandua:alert mitre_tactics=*execution* | stats count by mitre_techniques, hostname",
      description: "Alerts with MITRE Execution tactics",
      cron_schedule: "*/15 * * * *",
      is_scheduled: true
    },
    %{
      name: "Tamandua - AI Model Threats",
      search: "index=tamandua sourcetype=tamandua:alert title=\"*model*\" OR title=\"*ML*\" OR title=\"*backdoor*\" OR title=\"*pickle*\" | table _time, title, hostname, threat_score",
      description: "AI/ML model security threats",
      cron_schedule: "*/10 * * * *",
      is_scheduled: true
    },
    %{
      name: "Tamandua - Credential Access",
      search: "index=tamandua sourcetype=tamandua:alert mitre_tactics=*credential_access* | stats count by mitre_techniques, hostname, title",
      description: "Credential access and theft attempts",
      cron_schedule: "*/5 * * * *",
      is_scheduled: true,
      alert_threshold: "> 0"
    },
    %{
      name: "Tamandua - Persistence Techniques",
      search: "index=tamandua sourcetype=tamandua:alert mitre_tactics=*persistence* | stats count by mitre_techniques, hostname",
      description: "Persistence mechanism detection",
      cron_schedule: "*/15 * * * *",
      is_scheduled: true
    }
  ]

  @type config :: %{
          optional(:rest_url) => String.t(),
          optional(:rest_username) => String.t(),
          optional(:rest_password) => String.t(),
          optional(:app) => String.t(),
          optional(:owner) => String.t(),
          optional(:timeout_ms) => non_neg_integer()
        }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Create a saved search in Splunk via REST API.

  ## Parameters

  - `name` - Name for the saved search
  - `search_config` - Map with `:search`, `:description`, `:cron_schedule`, `:is_scheduled`, etc.
  - `config` - Splunk REST API configuration

  ## Returns

  `{:ok, response}` on success, `{:error, reason}` on failure.
  """
  @spec create_saved_search(String.t(), map(), config()) :: {:ok, map()} | {:error, term()}
  def create_saved_search(name, search_config, config) do
    with {:ok, _} <- validate_rest_config(config) do
      owner = config[:owner] || @default_owner
      app = config[:app] || @default_app
      url = "#{config[:rest_url]}#{@saved_searches_endpoint}/#{owner}/#{app}/saved/searches?output_mode=json"

      body = build_search_params(name, search_config)
      headers = rest_auth_headers(config) ++ [{"Content-Type", "application/x-www-form-urlencoded"}]
      timeout = config[:timeout_ms] || @default_timeout_ms

      IntegrationLog.log_api_call("splunk_saved_searches", "create", name, fn ->
        case do_http(:post, url, headers, body, timeout) do
          {:ok, %{status: status, body: resp_body}} when status in [200, 201] ->
            {:ok, Jason.decode!(resp_body)}

          {:ok, %{status: status, body: resp_body}} ->
            {:error, "Create saved search failed: HTTP #{status} - #{truncate(resp_body)}"}

          {:error, reason} ->
            {:error, reason}
        end
      end)
    end
  end

  @doc """
  List existing Tamandua saved searches.

  ## Parameters

  - `config` - Splunk REST API configuration

  ## Returns

  `{:ok, searches}` list of saved search entries, `{:error, reason}` on failure.
  """
  @spec list_saved_searches(config()) :: {:ok, [map()]} | {:error, term()}
  def list_saved_searches(config) do
    with {:ok, _} <- validate_rest_config(config) do
      owner = config[:owner] || @default_owner
      app = config[:app] || @default_app
      url = "#{config[:rest_url]}#{@saved_searches_endpoint}/#{owner}/#{app}/saved/searches?output_mode=json&search=Tamandua"

      headers = rest_auth_headers(config)
      timeout = config[:timeout_ms] || @default_timeout_ms

      IntegrationLog.log_api_call("splunk_saved_searches", "list", nil, fn ->
        case do_http(:get, url, headers, nil, timeout) do
          {:ok, %{status: 200, body: resp_body}} ->
            response = Jason.decode!(resp_body)
            {:ok, response["entry"] || []}

          {:ok, %{status: status, body: resp_body}} ->
            {:error, "List saved searches failed: HTTP #{status} - #{truncate(resp_body)}"}

          {:error, reason} ->
            {:error, reason}
        end
      end)
    end
  end

  @doc """
  Delete a saved search by name.

  ## Parameters

  - `name` - Name of the saved search to delete
  - `config` - Splunk REST API configuration

  ## Returns

  `:ok` on success, `{:error, reason}` on failure.
  """
  @spec delete_saved_search(String.t(), config()) :: :ok | {:error, term()}
  def delete_saved_search(name, config) do
    with {:ok, _} <- validate_rest_config(config) do
      owner = config[:owner] || @default_owner
      app = config[:app] || @default_app
      encoded_name = URI.encode(name)
      url = "#{config[:rest_url]}#{@saved_searches_endpoint}/#{owner}/#{app}/saved/searches/#{encoded_name}"

      headers = rest_auth_headers(config)
      timeout = config[:timeout_ms] || @default_timeout_ms

      IntegrationLog.log_api_call("splunk_saved_searches", "delete", name, fn ->
        case do_http(:delete, url, headers, nil, timeout) do
          {:ok, %{status: status}} when status in 200..299 ->
            :ok

          {:ok, %{status: status, body: resp_body}} ->
            {:error, "Delete saved search failed: HTTP #{status} - #{truncate(resp_body)}"}

          {:error, reason} ->
            {:error, reason}
        end
      end)
    end
  end

  @doc """
  Get predefined default searches for Tamandua alerts.

  Returns a list of search configurations for:
  - Critical severity alerts
  - High severity alerts in the last hour
  - MITRE Execution tactics
  - AI/ML model threats
  - Credential access attempts
  - Persistence techniques

  ## Returns

  List of search configuration maps.
  """
  @spec get_default_searches() :: [map()]
  def get_default_searches do
    @default_searches
  end

  @doc """
  Install all default saved searches in Splunk.

  Creates each default search, skipping any that already exist (409 Conflict).

  ## Parameters

  - `config` - Splunk REST API configuration

  ## Returns

  `{:ok, created_names}` list of successfully created search names,
  `{:error, reason}` if all fail.
  """
  @spec install_default_searches(config()) :: {:ok, [String.t()]} | {:error, term()}
  def install_default_searches(config) do
    results = @default_searches
    |> Enum.map(fn search_def ->
      case create_saved_search(search_def.name, search_def, config) do
        {:ok, _} ->
          Logger.info("[SplunkSavedSearches] Created saved search: #{search_def.name}")
          {:ok, search_def.name}

        {:error, reason} ->
          # 409 Conflict means it already exists - treat as success
          if String.contains?(to_string(reason), "409") or String.contains?(to_string(reason), "Conflict") do
            Logger.info("[SplunkSavedSearches] Search already exists: #{search_def.name}")
            {:ok, search_def.name}
          else
            Logger.warning("[SplunkSavedSearches] Failed to create #{search_def.name}: #{inspect(reason)}")
            {:error, {search_def.name, reason}}
          end
      end
    end)

    created = results
    |> Enum.filter(&match?({:ok, _}, &1))
    |> Enum.map(fn {:ok, name} -> name end)

    if length(created) > 0 do
      {:ok, created}
    else
      {:error, :all_searches_failed}
    end
  end

  @doc """
  Get a single saved search by name.

  ## Parameters

  - `name` - Name of the saved search
  - `config` - Splunk REST API configuration

  ## Returns

  `{:ok, search}` on success, `{:error, reason}` on failure.
  """
  @spec get_saved_search(String.t(), config()) :: {:ok, map()} | {:error, term()}
  def get_saved_search(name, config) do
    with {:ok, _} <- validate_rest_config(config) do
      owner = config[:owner] || @default_owner
      app = config[:app] || @default_app
      encoded_name = URI.encode(name)
      url = "#{config[:rest_url]}#{@saved_searches_endpoint}/#{owner}/#{app}/saved/searches/#{encoded_name}?output_mode=json"

      headers = rest_auth_headers(config)
      timeout = config[:timeout_ms] || @default_timeout_ms

      IntegrationLog.log_api_call("splunk_saved_searches", "get", name, fn ->
        case do_http(:get, url, headers, nil, timeout) do
          {:ok, %{status: 200, body: resp_body}} ->
            response = Jason.decode!(resp_body)
            {:ok, hd(response["entry"] || [%{}])}

          {:ok, %{status: 404}} ->
            {:error, :not_found}

          {:ok, %{status: status, body: resp_body}} ->
            {:error, "Get saved search failed: HTTP #{status} - #{truncate(resp_body)}"}

          {:error, reason} ->
            {:error, reason}
        end
      end)
    end
  end

  @doc """
  Update an existing saved search.

  ## Parameters

  - `name` - Name of the saved search to update
  - `updates` - Map of fields to update
  - `config` - Splunk REST API configuration

  ## Returns

  `{:ok, response}` on success, `{:error, reason}` on failure.
  """
  @spec update_saved_search(String.t(), map(), config()) :: {:ok, map()} | {:error, term()}
  def update_saved_search(name, updates, config) do
    with {:ok, _} <- validate_rest_config(config) do
      owner = config[:owner] || @default_owner
      app = config[:app] || @default_app
      encoded_name = URI.encode(name)
      url = "#{config[:rest_url]}#{@saved_searches_endpoint}/#{owner}/#{app}/saved/searches/#{encoded_name}?output_mode=json"

      body = build_search_params(name, updates)
      headers = rest_auth_headers(config) ++ [{"Content-Type", "application/x-www-form-urlencoded"}]
      timeout = config[:timeout_ms] || @default_timeout_ms

      IntegrationLog.log_api_call("splunk_saved_searches", "update", name, fn ->
        case do_http(:post, url, headers, body, timeout) do
          {:ok, %{status: status, body: resp_body}} when status in 200..299 ->
            {:ok, Jason.decode!(resp_body)}

          {:ok, %{status: status, body: resp_body}} ->
            {:error, "Update saved search failed: HTTP #{status} - #{truncate(resp_body)}"}

          {:error, reason} ->
            {:error, reason}
        end
      end)
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp build_search_params(name, search_config) do
    params = %{
      "name" => name,
      "search" => search_config[:search] || search_config["search"]
    }

    params = if desc = search_config[:description] || search_config["description"] do
      Map.put(params, "description", desc)
    else
      params
    end

    params = if cron = search_config[:cron_schedule] || search_config["cron_schedule"] do
      Map.put(params, "cron_schedule", cron)
    else
      params
    end

    params = if search_config[:is_scheduled] || search_config["is_scheduled"] do
      Map.put(params, "is_scheduled", "1")
    else
      params
    end

    params = if threshold = search_config[:alert_threshold] || search_config["alert_threshold"] do
      params
      |> Map.put("alert.threshold", threshold)
      |> Map.put("alert_type", search_config[:alert_type] || "always")
    else
      params
    end

    params = if actions = search_config[:actions] || search_config["actions"] do
      Map.put(params, "actions", actions)
    else
      params
    end

    URI.encode_query(params)
  end

  defp validate_rest_config(config) do
    if config[:rest_url] && config[:rest_username] && config[:rest_password] do
      {:ok, config}
    else
      {:error, :rest_api_not_configured}
    end
  end

  defp rest_auth_headers(config) do
    auth = Base.encode64("#{config[:rest_username]}:#{config[:rest_password]}")
    [{"Authorization", "Basic #{auth}"}]
  end

  defp do_http(method, url, headers, body, timeout) do
    request = Finch.build(method, url, headers, body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: timeout) do
      {:ok, %Finch.Response{status: status, body: resp_body}} ->
        {:ok, %{status: status, body: resp_body}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp truncate(str) when is_binary(str) and byte_size(str) > 500 do
    String.slice(str, 0, 500) <> "..."
  end

  defp truncate(str) when is_binary(str), do: str
  defp truncate(other), do: inspect(other)
end
