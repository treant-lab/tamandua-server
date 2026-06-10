defmodule TamanduaServer.Integrations.CaseManagement.JiraServiceManagement do
  @moduledoc """
  Jira Service Management Integration for Case Management

  Provides case management capabilities using Jira Service Management:
  - Create service requests from security alerts
  - Update request status and priority
  - Add comments and attachments
  - Link related requests
  - Custom field support for security workflows
  - SLA tracking

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.CaseManagement.JiraServiceManagement,
        base_url: "https://your-instance.atlassian.net",
        email: "your-email@company.com",
        api_token: "your-api-token",
        project_key: "SEC",
        request_type_id: "10001",
        service_desk_id: "1"

  """

  use GenServer
  require Logger

  @default_timeout_ms 30_000

  defstruct [:config, :auth, :stats]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Create a service request from an alert.
  """
  @spec create_request(map()) :: {:ok, map()} | {:error, term()}
  def create_request(alert) do
    GenServer.call(__MODULE__, {:create_request, alert}, 30_000)
  end

  @doc """
  Get a service request by key.
  """
  @spec get_request(String.t()) :: {:ok, map()} | {:error, term()}
  def get_request(key) do
    GenServer.call(__MODULE__, {:get_request, key}, 30_000)
  end

  @doc """
  Update a service request.
  """
  @spec update_request(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def update_request(key, updates) do
    GenServer.call(__MODULE__, {:update_request, key, updates}, 30_000)
  end

  @doc """
  Transition a request to a new status.
  """
  @spec transition_request(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def transition_request(key, transition_id) do
    GenServer.call(__MODULE__, {:transition_request, key, transition_id}, 30_000)
  end

  @doc """
  Add a comment to a request.
  """
  @spec add_comment(String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def add_comment(key, body, opts \\ []) do
    GenServer.call(__MODULE__, {:add_comment, key, body, opts}, 30_000)
  end

  @doc """
  Add an attachment to a request.
  """
  @spec add_attachment(String.t(), String.t(), binary()) :: {:ok, map()} | {:error, term()}
  def add_attachment(key, filename, content) do
    GenServer.call(__MODULE__, {:add_attachment, key, filename, content}, 60_000)
  end

  @doc """
  Link two requests together.
  """
  @spec link_requests(String.t(), String.t(), String.t()) :: :ok | {:error, term()}
  def link_requests(from_key, to_key, link_type \\ "Relates") do
    GenServer.call(__MODULE__, {:link_requests, from_key, to_key, link_type}, 30_000)
  end

  @doc """
  Search for requests using JQL.
  """
  @spec search_requests(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def search_requests(jql, opts \\ []) do
    GenServer.call(__MODULE__, {:search_requests, jql, opts}, 30_000)
  end

  @doc """
  Get available transitions for a request.
  """
  @spec get_transitions(String.t()) :: {:ok, [map()]} | {:error, term()}
  def get_transitions(key) do
    GenServer.call(__MODULE__, {:get_transitions, key}, 30_000)
  end

  @doc """
  Get SLA information for a request.
  """
  @spec get_sla(String.t()) :: {:ok, [map()]} | {:error, term()}
  def get_sla(key) do
    GenServer.call(__MODULE__, {:get_sla, key}, 30_000)
  end

  @doc """
  Sync alert status with linked request.
  """
  @spec sync_alert_status(String.t(), map()) :: {:ok, map()} | {:error, term()}
  def sync_alert_status(alert_id, alert) do
    GenServer.call(__MODULE__, {:sync_alert_status, alert_id, alert}, 30_000)
  end

  @spec test_connection() :: {:ok, String.t()} | {:error, term()}
  def test_connection do
    GenServer.call(__MODULE__, :test_connection, 30_000)
  end

  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting Jira Service Management Integration")
    config = load_config(opts)

    state = %__MODULE__{
      config: config,
      auth: Base.encode64("#{config.email}:#{config.api_token}"),
      stats: %{
        requests_created: 0,
        requests_updated: 0,
        comments_added: 0,
        attachments_added: 0,
        errors: 0,
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:create_request, alert}, _from, state) do
    payload = build_request_payload(state, alert)

    case post_request(state, "/rest/servicedeskapi/request", payload) do
      {:ok, response} ->
        request = format_request(response)
        new_stats = update_stat(state.stats, :requests_created)
        {:reply, {:ok, request}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_request, key}, _from, state) do
    case get_request_api(state, "/rest/api/3/issue/#{key}") do
      {:ok, response} ->
        request = format_request(response)
        {:reply, {:ok, request}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:update_request, key, updates}, _from, state) do
    payload = build_update_payload(updates)

    case put_request(state, "/rest/api/3/issue/#{key}", payload) do
      {:ok, _} ->
        new_stats = update_stat(state.stats, :requests_updated)
        # Fetch updated request
        case get_request_api(state, "/rest/api/3/issue/#{key}") do
          {:ok, response} ->
            {:reply, {:ok, format_request(response)}, %{state | stats: new_stats}}

          _ ->
            {:reply, {:ok, %{key: key, updated: true}}, %{state | stats: new_stats}}
        end

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:transition_request, key, transition_id}, _from, state) do
    payload = %{
      transition: %{id: transition_id}
    }

    case post_request(state, "/rest/api/3/issue/#{key}/transitions", payload) do
      {:ok, _} ->
        new_stats = update_stat(state.stats, :requests_updated)
        {:reply, {:ok, %{key: key, transitioned: true}}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:add_comment, key, body, opts}, _from, state) do
    public = Keyword.get(opts, :public, false)

    payload = %{
      body: %{
        type: "doc",
        version: 1,
        content: [
          %{
            type: "paragraph",
            content: [
              %{type: "text", text: body}
            ]
          }
        ]
      },
      properties: [
        %{
          key: "sd.public.comment",
          value: %{internal: !public}
        }
      ]
    }

    case post_request(state, "/rest/api/3/issue/#{key}/comment", payload) do
      {:ok, response} ->
        comment = format_comment(response)
        new_stats = update_stat(state.stats, :comments_added)
        {:reply, {:ok, comment}, %{state | stats: new_stats}}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:add_attachment, key, filename, content}, _from, state) do
    boundary = "----TamanduaFormBoundary#{:crypto.strong_rand_bytes(16) |> Base.encode16()}"

    body =
      "--#{boundary}\r\n" <>
        "Content-Disposition: form-data; name=\"file\"; filename=\"#{filename}\"\r\n" <>
        "Content-Type: application/octet-stream\r\n\r\n" <>
        content <>
        "\r\n--#{boundary}--\r\n"

    headers = [
      {"Authorization", "Basic #{state.auth}"},
      {"Content-Type", "multipart/form-data; boundary=#{boundary}"},
      {"X-Atlassian-Token", "no-check"}
    ]

    url = "#{state.config.base_url}/rest/api/3/issue/#{key}/attachments"
    options = [timeout: 60_000, recv_timeout: 60_000]

    case Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 60_000)) do
      {:ok, %{status_code: code, body: resp_body}} when code in [200, 201] ->
        attachments = Jason.decode!(resp_body)
        new_stats = update_stat(state.stats, :attachments_added)
        {:reply, {:ok, attachments}, %{state | stats: new_stats}}

      {:ok, %{status_code: code, body: resp_body}} ->
        {:reply, {:error, "HTTP #{code}: #{resp_body}"}, update_error_stat(state)}

      {:error, %{reason: reason}} ->
        {:reply, {:error, reason}, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:link_requests, from_key, to_key, link_type}, _from, state) do
    payload = %{
      type: %{name: link_type},
      inwardIssue: %{key: from_key},
      outwardIssue: %{key: to_key}
    }

    case post_request(state, "/rest/api/3/issueLink", payload) do
      {:ok, _} -> {:reply, :ok, state}
      error -> {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:search_requests, jql, opts}, _from, state) do
    max_results = Keyword.get(opts, :max_results, 50)
    start_at = Keyword.get(opts, :start_at, 0)

    params = %{
      jql: jql,
      maxResults: max_results,
      startAt: start_at,
      fields: ["summary", "status", "priority", "created", "updated", "assignee", "reporter"]
    }

    case post_request(state, "/rest/api/3/search", params) do
      {:ok, response} ->
        requests =
          Enum.map(response["issues"] || [], fn issue ->
            format_request(issue)
          end)

        {:reply, {:ok, requests}, state}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call({:get_transitions, key}, _from, state) do
    case get_request_api(state, "/rest/api/3/issue/#{key}/transitions") do
      {:ok, response} ->
        transitions =
          Enum.map(response["transitions"] || [], fn t ->
            %{
              id: t["id"],
              name: t["name"],
              to_status: get_in(t, ["to", "name"])
            }
          end)

        {:reply, {:ok, transitions}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_sla, key}, _from, state) do
    case get_request_api(state, "/rest/servicedeskapi/request/#{key}/sla") do
      {:ok, response} ->
        slas =
          Enum.map(response["values"] || [], fn sla ->
            %{
              name: sla["name"],
              ongoing_cycle: %{
                breached: get_in(sla, ["ongoingCycle", "breached"]),
                paused: get_in(sla, ["ongoingCycle", "paused"]),
                within_calendar_hours: get_in(sla, ["ongoingCycle", "withinCalendarHours"]),
                goal_duration_minutes: get_in(sla, ["ongoingCycle", "goalDuration", "millis"]),
                elapsed_time_minutes: get_in(sla, ["ongoingCycle", "elapsedTime", "millis"]),
                remaining_time_minutes: get_in(sla, ["ongoingCycle", "remainingTime", "millis"])
              },
              completed_cycles:
                Enum.map(sla["completedCycles"] || [], fn cycle ->
                  %{
                    breached: cycle["breached"],
                    goal_duration: cycle["goalDuration"],
                    elapsed_time: cycle["elapsedTime"]
                  }
                end)
            }
          end)

        {:reply, {:ok, slas}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:sync_alert_status, alert_id, alert}, _from, state) do
    # Search for existing request linked to this alert
    jql = "\"Alert ID[Short text]\" ~ \"#{alert_id}\""

    case post_request(state, "/rest/api/3/search", %{jql: jql, maxResults: 1}) do
      {:ok, %{"issues" => [existing | _]}} ->
        key = existing["key"]
        # Update the existing request
        updates = build_alert_sync_updates(alert)

        case put_request(state, "/rest/api/3/issue/#{key}", updates) do
          {:ok, _} ->
            {:reply, {:ok, %{key: key, synced: true}}, state}

          error ->
            {:reply, error, update_error_stat(state)}
        end

      {:ok, %{"issues" => []}} ->
        {:reply, {:error, :not_found}, state}

      error ->
        {:reply, error, update_error_stat(state)}
    end
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request_api(state, "/rest/api/3/myself") do
      {:ok, user} ->
        {:reply, {:ok, "Connected as #{user["displayName"]}"}, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp load_config(opts) do
    app_config = Application.get_env(:tamandua_server, __MODULE__, [])

    %{
      base_url: opts[:base_url] || app_config[:base_url],
      email: opts[:email] || app_config[:email],
      api_token: opts[:api_token] || app_config[:api_token],
      project_key: opts[:project_key] || app_config[:project_key] || "SEC",
      request_type_id: opts[:request_type_id] || app_config[:request_type_id],
      service_desk_id: opts[:service_desk_id] || app_config[:service_desk_id],
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms
    }
  end

  defp build_request_payload(state, alert) do
    severity = alert[:severity] || alert["severity"] || "medium"

    summary =
      "[Security Alert] #{alert[:title] || alert["title"] || alert[:rule_name] || alert["rule_name"] || "Security Incident"}"

    description = build_description(alert)

    payload = %{
      serviceDeskId: state.config.service_desk_id,
      requestTypeId: state.config.request_type_id,
      requestFieldValues: %{
        summary: summary,
        description: description,
        priority: %{name: severity_to_priority(severity)}
      }
    }

    # Add custom fields if configured
    custom_fields = build_custom_fields(alert)

    if map_size(custom_fields) > 0 do
      put_in(
        payload,
        [:requestFieldValues],
        Map.merge(payload.requestFieldValues, custom_fields)
      )
    else
      payload
    end
  end

  defp build_description(alert) do
    """
    *Security Alert Details*

    ||Field||Value||
    |Alert ID|#{alert[:id] || alert["id"] || "N/A"}|
    |Severity|#{alert[:severity] || alert["severity"] || "N/A"}|
    |Source|#{alert[:source] || alert["source"] || "Tamandua EDR"}|
    |Timestamp|#{alert[:timestamp] || alert["timestamp"] || DateTime.utc_now() |> DateTime.to_iso8601()}|

    *Description:*
    #{alert[:description] || alert["description"] || "No description provided"}

    *Affected Assets:*
    #{format_affected_assets(alert)}

    *MITRE ATT&CK:*
    #{format_mitre_info(alert)}

    *Recommended Actions:*
    #{alert[:recommendations] || alert["recommendations"] || "Review the alert and take appropriate action"}
    """
  end

  defp format_affected_assets(alert) do
    hostname = alert[:hostname] || alert["hostname"]
    ip = alert[:ip_address] || alert["ip_address"]
    user = alert[:username] || alert["username"]

    [
      if(hostname, do: "* Hostname: #{hostname}"),
      if(ip, do: "* IP Address: #{ip}"),
      if(user, do: "* User: #{user}")
    ]
    |> Enum.filter(& &1)
    |> Enum.join("\n")
    |> case do
      "" -> "No affected assets identified"
      assets -> assets
    end
  end

  defp format_mitre_info(alert) do
    tactics = alert[:mitre_tactics] || alert["mitre_tactics"] || []
    techniques = alert[:mitre_techniques] || alert["mitre_techniques"] || []

    case {tactics, techniques} do
      {[], []} ->
        "No MITRE ATT&CK mapping available"

      _ ->
        tactic_str =
          if length(tactics) > 0, do: "* Tactics: #{Enum.join(tactics, ", ")}", else: nil

        technique_str =
          if length(techniques) > 0,
            do: "* Techniques: #{Enum.join(techniques, ", ")}",
            else: nil

        [tactic_str, technique_str]
        |> Enum.filter(& &1)
        |> Enum.join("\n")
    end
  end

  defp build_custom_fields(alert) do
    fields = %{}

    # Add alert ID as custom field
    fields =
      if alert[:id] || alert["id"] do
        Map.put(fields, "customfield_10001", alert[:id] || alert["id"])
      else
        fields
      end

    # Add severity as custom field
    fields =
      if alert[:severity] || alert["severity"] do
        Map.put(fields, "customfield_10002", alert[:severity] || alert["severity"])
      else
        fields
      end

    fields
  end

  defp build_update_payload(updates) do
    fields =
      updates
      |> Enum.reduce(%{}, fn
        {:summary, v}, acc -> Map.put(acc, "summary", v)
        {:description, v}, acc -> Map.put(acc, "description", v)
        {:priority, v}, acc -> Map.put(acc, "priority", %{"name" => v})
        {:assignee, v}, acc -> Map.put(acc, "assignee", %{"accountId" => v})
        {:labels, v}, acc -> Map.put(acc, "labels", v)
        {key, v}, acc when is_binary(key) -> Map.put(acc, key, v)
        _, acc -> acc
      end)

    %{fields: fields}
  end

  defp build_alert_sync_updates(alert) do
    status = alert[:status] || alert["status"]

    updates = %{}

    updates =
      if status do
        # Map alert status to request priority/labels
        Map.put(updates, :labels, ["alert-status-#{status}"])
      else
        updates
      end

    build_update_payload(updates)
  end

  defp severity_to_priority(severity) do
    case String.downcase(to_string(severity)) do
      "critical" -> "Highest"
      "high" -> "High"
      "medium" -> "Medium"
      "low" -> "Low"
      "informational" -> "Lowest"
      _ -> "Medium"
    end
  end

  defp format_request(response) do
    fields = response["fields"] || %{}

    %{
      id: response["id"],
      key: response["key"],
      self: response["self"],
      summary: fields["summary"],
      description: extract_description_text(fields["description"]),
      status: get_in(fields, ["status", "name"]),
      status_category: get_in(fields, ["status", "statusCategory", "name"]),
      priority: get_in(fields, ["priority", "name"]),
      assignee: %{
        account_id: get_in(fields, ["assignee", "accountId"]),
        display_name: get_in(fields, ["assignee", "displayName"]),
        email: get_in(fields, ["assignee", "emailAddress"])
      },
      reporter: %{
        account_id: get_in(fields, ["reporter", "accountId"]),
        display_name: get_in(fields, ["reporter", "displayName"]),
        email: get_in(fields, ["reporter", "emailAddress"])
      },
      created: fields["created"],
      updated: fields["updated"],
      resolved: fields["resolutiondate"],
      labels: fields["labels"] || [],
      components:
        Enum.map(fields["components"] || [], fn c ->
          %{id: c["id"], name: c["name"]}
        end)
    }
  end

  defp extract_description_text(nil), do: nil

  defp extract_description_text(%{"content" => content}) when is_list(content) do
    content
    |> Enum.flat_map(fn
      %{"content" => inner_content} when is_list(inner_content) ->
        Enum.map(inner_content, fn
          %{"text" => text} -> text
          _ -> ""
        end)

      _ ->
        []
    end)
    |> Enum.join("\n")
  end

  defp extract_description_text(desc) when is_binary(desc), do: desc
  defp extract_description_text(_), do: nil

  defp format_comment(response) do
    %{
      id: response["id"],
      body: extract_description_text(response["body"]),
      author: %{
        account_id: get_in(response, ["author", "accountId"]),
        display_name: get_in(response, ["author", "displayName"])
      },
      created: response["created"],
      updated: response["updated"]
    }
  end

  defp get_request_api(state, endpoint) do
    url = "#{state.config.base_url}#{endpoint}"

    headers = [
      {"Authorization", "Basic #{state.auth}"},
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    options = [timeout: state.config.timeout_ms, recv_timeout: state.config.timeout_ms]

    case Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %Finch.Response{status: 200, body: body}} ->
        {:ok, Jason.decode!(body)}

      {:ok, %Finch.Response{status: 404}} ->
        {:error, :not_found}

      {:ok, %Finch.Response{status: code, body: body}} ->
        Logger.error("Jira API error: HTTP #{code} - #{body}")
        {:error, "HTTP #{code}: #{body}"}

      {:error, reason} ->
        Logger.error("Jira connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Jira exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp post_request(state, endpoint, payload) do
    url = "#{state.config.base_url}#{endpoint}"

    headers = [
      {"Authorization", "Basic #{state.auth}"},
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    options = [timeout: state.config.timeout_ms, recv_timeout: state.config.timeout_ms]

    case Finch.build(:post, url, headers, Jason.encode!(payload)) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %Finch.Response{status: code, body: body}} when code in [200, 201, 204] ->
        if body == "" do
          {:ok, %{}}
        else
          {:ok, Jason.decode!(body)}
        end

      {:ok, %Finch.Response{status: code, body: body}} ->
        Logger.error("Jira API error: HTTP #{code} - #{body}")
        {:error, "HTTP #{code}: #{body}"}

      {:error, reason} ->
        Logger.error("Jira connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Jira exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp put_request(state, endpoint, payload) do
    url = "#{state.config.base_url}#{endpoint}"

    headers = [
      {"Authorization", "Basic #{state.auth}"},
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    options = [timeout: state.config.timeout_ms, recv_timeout: state.config.timeout_ms]

    case Finch.build(:put, url, headers, Jason.encode!(payload)) |> Finch.request(TamanduaServer.Finch, receive_timeout: Keyword.get(options, :recv_timeout, 30_000)) do
      {:ok, %{status_code: code, body: body}} when code in [200, 204] ->
        if body == "" do
          {:ok, %{}}
        else
          {:ok, Jason.decode!(body)}
        end

      {:ok, %{status_code: code, body: body}} ->
        Logger.error("Jira API error: HTTP #{code} - #{body}")
        {:error, "HTTP #{code}: #{body}"}

      {:error, %{reason: reason}} ->
        Logger.error("Jira connection error: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.error("Jira exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp update_stat(stats, key) do
    stats |> Map.update(key, 1, &(&1 + 1)) |> Map.put(:last_activity, DateTime.utc_now())
  end

  defp update_error_stat(state) do
    new_stats = Map.update(state.stats, :errors, 1, &(&1 + 1))
    %{state | stats: new_stats}
  end
end
