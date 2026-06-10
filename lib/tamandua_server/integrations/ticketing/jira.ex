defmodule TamanduaServer.Integrations.Ticketing.Jira do
  @moduledoc """
  Jira Integration

  Provides integration with Atlassian Jira:
  - Issue creation for security incidents
  - Issue updates and transitions
  - Comment and attachment management
  - Custom field support

  ## Configuration

      config :tamandua_server, TamanduaServer.Integrations.Ticketing.Jira,
        url: "https://your-domain.atlassian.net",
        email: "your-email@example.com",
        api_token: "your-api-token",
        project_key: "SEC",
        issue_type: "Security Incident",
        verify_ssl: true

  """

  use GenServer
  require Logger

  @default_timeout_ms 30_000

  defstruct [
    :config,
    :base_url,
    :auth_header,
    :stats
  ]

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Create a Jira issue for an alert.
  """
  @spec create_issue(map()) :: {:ok, String.t()} | {:error, term()}
  def create_issue(issue_data) do
    GenServer.call(__MODULE__, {:create_issue, issue_data}, 30_000)
  end

  @doc """
  Update an existing issue.
  """
  @spec update_issue(String.t(), map()) :: :ok | {:error, term()}
  def update_issue(issue_key, updates) do
    GenServer.call(__MODULE__, {:update_issue, issue_key, updates}, 30_000)
  end

  @doc """
  Get issue details.
  """
  @spec get_issue(String.t()) :: {:ok, map()} | {:error, term()}
  def get_issue(issue_key) do
    GenServer.call(__MODULE__, {:get_issue, issue_key}, 30_000)
  end

  @doc """
  Add a comment to an issue.
  """
  @spec add_comment(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def add_comment(issue_key, comment) do
    GenServer.call(__MODULE__, {:add_comment, issue_key, comment}, 30_000)
  end

  @doc """
  Transition an issue to a new status.
  """
  @spec transition_issue(String.t(), String.t()) :: :ok | {:error, term()}
  def transition_issue(issue_key, transition_name) do
    GenServer.call(__MODULE__, {:transition_issue, issue_key, transition_name}, 30_000)
  end

  @doc """
  Search for issues using JQL.
  """
  @spec search_issues(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def search_issues(jql, opts \\ []) do
    GenServer.call(__MODULE__, {:search_issues, jql, opts}, 30_000)
  end

  @doc """
  Get available transitions for an issue.
  """
  @spec get_transitions(String.t()) :: {:ok, [map()]} | {:error, term()}
  def get_transitions(issue_key) do
    GenServer.call(__MODULE__, {:get_transitions, issue_key}, 30_000)
  end

  @doc """
  Link two issues.
  """
  @spec link_issues(String.t(), String.t(), String.t()) :: :ok | {:error, term()}
  def link_issues(inward_key, outward_key, link_type \\ "Relates") do
    GenServer.call(__MODULE__, {:link_issues, inward_key, outward_key, link_type}, 30_000)
  end

  @doc """
  Test connection to Jira.
  """
  @spec test_connection() :: {:ok, String.t()} | {:error, term()}
  def test_connection do
    GenServer.call(__MODULE__, :test_connection, 30_000)
  end

  @doc """
  Get integration statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(opts) do
    Logger.info("Starting Jira Integration")

    config = load_config(opts)
    auth_header = build_auth_header(config)

    state = %__MODULE__{
      config: config,
      base_url: String.trim_trailing(config.url || "", "/"),
      auth_header: auth_header,
      stats: %{
        issues_created: 0,
        issues_updated: 0,
        comments_added: 0,
        transitions: 0,
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:create_issue, issue_data}, _from, state) do
    issue = format_issue(issue_data, state.config)

    case post_request(state, "/rest/api/3/issue", issue) do
      {:ok, response} ->
        issue_key = response["key"]
        new_stats = update_stat(state.stats, :issues_created)
        Logger.info("Created Jira issue: #{issue_key}")
        {:reply, {:ok, issue_key}, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:update_issue, issue_key, updates}, _from, state) do
    body = %{fields: format_updates(updates)}

    case put_request(state, "/rest/api/3/issue/#{issue_key}", body) do
      {:ok, _} ->
        new_stats = update_stat(state.stats, :issues_updated)
        {:reply, :ok, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_issue, issue_key}, _from, state) do
    case get_request(state, "/rest/api/3/issue/#{issue_key}") do
      {:ok, issue} ->
        {:reply, {:ok, issue}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:add_comment, issue_key, comment}, _from, state) do
    body = %{
      body: %{
        type: "doc",
        version: 1,
        content: [
          %{
            type: "paragraph",
            content: [
              %{type: "text", text: comment}
            ]
          }
        ]
      }
    }

    case post_request(state, "/rest/api/3/issue/#{issue_key}/comment", body) do
      {:ok, response} ->
        new_stats = update_stat(state.stats, :comments_added)
        {:reply, {:ok, response}, %{state | stats: new_stats}}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:transition_issue, issue_key, transition_name}, _from, state) do
    # First get available transitions
    case get_request(state, "/rest/api/3/issue/#{issue_key}/transitions") do
      {:ok, %{"transitions" => transitions}} ->
        # Find the transition by name
        transition = Enum.find(transitions, fn t ->
          String.downcase(t["name"]) == String.downcase(transition_name)
        end)

        if transition do
          body = %{transition: %{id: transition["id"]}}

          case post_request(state, "/rest/api/3/issue/#{issue_key}/transitions", body) do
            {:ok, _} ->
              new_stats = update_stat(state.stats, :transitions)
              {:reply, :ok, %{state | stats: new_stats}}

            error ->
              {:reply, error, state}
          end
        else
          {:reply, {:error, "Transition '#{transition_name}' not found"}, state}
        end

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:search_issues, jql, opts}, _from, state) do
    params = %{
      jql: jql,
      startAt: opts[:start_at] || 0,
      maxResults: opts[:max_results] || 50,
      fields: opts[:fields] || ["summary", "status", "priority", "created", "updated"]
    }

    case post_request(state, "/rest/api/3/search", params) do
      {:ok, response} ->
        {:reply, {:ok, response["issues"] || []}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:get_transitions, issue_key}, _from, state) do
    case get_request(state, "/rest/api/3/issue/#{issue_key}/transitions") do
      {:ok, %{"transitions" => transitions}} ->
        formatted = Enum.map(transitions, fn t ->
          %{
            id: t["id"],
            name: t["name"],
            to: get_in(t, ["to", "name"])
          }
        end)
        {:reply, {:ok, formatted}, state}

      error ->
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:link_issues, inward_key, outward_key, link_type}, _from, state) do
    body = %{
      type: %{name: link_type},
      inwardIssue: %{key: inward_key},
      outwardIssue: %{key: outward_key}
    }

    case post_request(state, "/rest/api/3/issueLink", body) do
      {:ok, _} -> {:reply, :ok, state}
      error -> {:reply, error, state}
    end
  end

  @impl true
  def handle_call(:test_connection, _from, state) do
    case get_request(state, "/rest/api/3/myself") do
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
      url: opts[:url] || app_config[:url],
      email: opts[:email] || app_config[:email],
      api_token: opts[:api_token] || app_config[:api_token],
      project_key: opts[:project_key] || app_config[:project_key],
      issue_type: opts[:issue_type] || app_config[:issue_type] || "Task",
      priority: opts[:priority] || app_config[:priority],
      labels: opts[:labels] || app_config[:labels] || [],
      components: opts[:components] || app_config[:components] || [],
      custom_fields: opts[:custom_fields] || app_config[:custom_fields] || %{},
      timeout_ms: opts[:timeout_ms] || app_config[:timeout_ms] || @default_timeout_ms,
      verify_ssl: opts[:verify_ssl] != false && app_config[:verify_ssl] != false
    }
  end

  defp build_auth_header(config) do
    if config.email && config.api_token do
      auth = Base.encode64("#{config.email}:#{config.api_token}")
      "Basic #{auth}"
    else
      nil
    end
  end

  defp format_issue(data, config) do
    fields = %{
      project: %{key: data[:project_key] || config.project_key},
      issuetype: %{name: data[:issue_type] || config.issue_type},
      summary: data[:title] || data["title"] || "Tamandua Alert",
      description: format_description(data)
    }

    # Add priority if specified
    fields = if priority = data[:priority] || config.priority do
      Map.put(fields, :priority, %{name: priority})
    else
      fields
    end

    # Add labels
    labels = (data[:labels] || []) ++ (config.labels || []) ++ ["tamandua"]
    fields = Map.put(fields, :labels, Enum.uniq(labels))

    # Add severity label based on alert severity
    severity = data[:severity] || data["severity"]
    fields = if severity do
      update_in(fields, [:labels], fn l -> ["severity-#{severity}" | l] end)
    else
      fields
    end

    # Add custom fields from config
    fields = Enum.reduce(config.custom_fields, fields, fn {key, value}, acc ->
      Map.put(acc, key, value)
    end)

    # Add Tamandua-specific custom fields if configured
    fields = if data[:id] do
      Map.put(fields, config.custom_fields[:alert_id_field] || :customfield_10001, data[:id])
    else
      fields
    end

    %{fields: fields}
  end

  defp format_description(data) do
    description = data[:description] || data["description"] || ""
    hostname = data[:hostname] || data["hostname"]
    agent_id = data[:agent_id] || data["agent_id"]
    mitre_tactics = data[:mitre_tactics] || data["mitre_tactics"] || []
    mitre_techniques = data[:mitre_techniques] || data["mitre_techniques"] || []
    threat_score = data[:threat_score] || data["threat_score"]

    # Build Atlassian Document Format
    content = [
      %{
        type: "paragraph",
        content: [%{type: "text", text: description}]
      },
      %{type: "rule"},
      %{
        type: "heading",
        attrs: %{level: 3},
        content: [%{type: "text", text: "Alert Details"}]
      }
    ]

    details = []

    details = if hostname do
      [%{type: "paragraph", content: [
        %{type: "text", text: "Hostname: ", marks: [%{type: "strong"}]},
        %{type: "text", text: hostname}
      ]} | details]
    else
      details
    end

    details = if agent_id do
      [%{type: "paragraph", content: [
        %{type: "text", text: "Agent ID: ", marks: [%{type: "strong"}]},
        %{type: "text", text: agent_id}
      ]} | details]
    else
      details
    end

    details = if length(mitre_tactics) > 0 do
      [%{type: "paragraph", content: [
        %{type: "text", text: "MITRE Tactics: ", marks: [%{type: "strong"}]},
        %{type: "text", text: Enum.join(mitre_tactics, ", ")}
      ]} | details]
    else
      details
    end

    details = if length(mitre_techniques) > 0 do
      [%{type: "paragraph", content: [
        %{type: "text", text: "MITRE Techniques: ", marks: [%{type: "strong"}]},
        %{type: "text", text: Enum.join(mitre_techniques, ", ")}
      ]} | details]
    else
      details
    end

    details = if threat_score do
      [%{type: "paragraph", content: [
        %{type: "text", text: "Threat Score: ", marks: [%{type: "strong"}]},
        %{type: "text", text: to_string(threat_score)}
      ]} | details]
    else
      details
    end

    content = content ++ Enum.reverse(details)

    %{
      type: "doc",
      version: 1,
      content: content
    }
  end

  defp format_updates(updates) do
    updates
    |> Enum.map(fn
      {:summary, value} -> {:summary, value}
      {:description, value} -> {:description, %{type: "doc", version: 1, content: [%{type: "paragraph", content: [%{type: "text", text: value}]}]}}
      {:priority, value} -> {:priority, %{name: value}}
      {:labels, value} -> {:labels, value}
      {key, value} -> {key, value}
    end)
    |> Map.new()
  end

  defp get_request(state, endpoint) do
    make_request(:get, state, endpoint, nil)
  end

  defp post_request(state, endpoint, body) do
    make_request(:post, state, endpoint, body)
  end

  defp put_request(state, endpoint, body) do
    make_request(:put, state, endpoint, body)
  end

  defp make_request(method, state, endpoint, body) do
    alias TamanduaServer.Integrations.IntegrationLog

    url = "#{state.base_url}#{endpoint}"

    headers = [
      {"content-type", "application/json"},
      {"accept", "application/json"}
    ]

    headers = if state.auth_header do
      [{"authorization", state.auth_header} | headers]
    else
      headers
    end

    encoded_body = if body, do: Jason.encode!(body), else: nil

    request = case method do
      :get -> Finch.build(:get, url, headers)
      :post -> Finch.build(:post, url, headers, encoded_body)
      :put -> Finch.build(:put, url, headers, encoded_body)
    end

    action = "#{method}:#{endpoint}"

    IntegrationLog.log_api_call("jira", action, body, fn ->
      case Finch.request(request, TamanduaServer.Finch, receive_timeout: state.config.timeout_ms) do
        {:ok, %Finch.Response{status: code, body: resp_body}} when code in 200..299 ->
          if resp_body == "" do
            {:ok, %{}}
          else
            {:ok, Jason.decode!(resp_body)}
          end

        {:ok, %Finch.Response{status: 204}} ->
          {:ok, %{}}

        {:ok, %Finch.Response{status: code, body: resp_body}} ->
          Logger.error("Jira API error: HTTP #{code} - #{resp_body}")
          {:error, "HTTP #{code}: #{resp_body}"}

        {:error, %Mint.TransportError{reason: reason}} ->
          Logger.error("Jira connection error: #{inspect(reason)}")
          {:error, inspect(reason)}

        {:error, reason} ->
          Logger.error("Jira connection error: #{inspect(reason)}")
          {:error, inspect(reason)}
      end
    end)
  rescue
    e ->
      Logger.error("Jira exception: #{inspect(e)}")
      {:error, Exception.message(e)}
  end

  defp update_stat(stats, key) do
    stats
    |> Map.update(key, 1, &(&1 + 1))
    |> Map.put(:last_activity, DateTime.utc_now())
  end

  # ============================================================================
  # Alert Integration Functions
  # ============================================================================

  @doc """
  Create a Jira issue from a Tamandua alert.

  Maps alert fields to Jira issue fields:
  - title -> summary
  - description -> description (ADF format)
  - severity -> priority (critical->Highest, high->High, medium->Medium, low->Low)
  - alert.id -> labels (tamandua-alert-{id})
  - mitre_tactics/techniques -> description section
  - hostname, agent_id -> description section

  ## Parameters

  - `alert` - Alert map with id, title, severity, etc.
  - `config` - Configuration map with project_key, issue_type, etc.

  ## Returns

  `{:ok, issue_key}` on success, `{:error, reason}` on failure.
  """
  @spec create_issue_from_alert(map(), map()) :: {:ok, String.t()} | {:error, term()}
  def create_issue_from_alert(alert, config) do
    issue_data = %{
      title: "[Tamandua] #{alert[:title] || alert["title"] || "Alert"}",
      description: alert[:description] || alert["description"],
      severity: alert[:severity] || alert["severity"],
      project_key: config[:project_key] || config["project_key"],
      issue_type: config[:issue_type] || config["issue_type"] || "Security Incident",
      labels: [
        "tamandua",
        "tamandua-alert-#{alert[:id] || alert["id"]}",
        "severity-#{alert[:severity] || alert["severity"]}"
      ],
      id: alert[:id] || alert["id"],
      hostname: alert[:hostname] || alert["hostname"],
      agent_id: alert[:agent_id] || alert["agent_id"],
      mitre_tactics: alert[:mitre_tactics] || alert["mitre_tactics"] || [],
      mitre_techniques: alert[:mitre_techniques] || alert["mitre_techniques"] || [],
      threat_score: alert[:threat_score] || alert["threat_score"]
    }

    # Add priority based on severity
    issue_data = Map.put(issue_data, :priority, map_severity_to_priority(issue_data.severity))

    create_issue(issue_data)
  end

  @doc """
  Search for existing Jira ticket for an alert (deduplication).

  Uses JQL to find tickets with the tamandua-alert-{id} label.

  ## Parameters

  - `alert_id` - The alert ID to search for
  - `config` - Configuration map with project_key

  ## Returns

  - `{:ok, issue_key}` if found
  - `{:ok, nil}` if not found
  - `{:error, reason}` on failure
  """
  @spec find_existing_ticket(String.t(), map()) :: {:ok, String.t() | nil} | {:error, term()}
  def find_existing_ticket(alert_id, config) do
    project_key = config[:project_key] || config["project_key"] || "SEC"
    jql = "project = #{project_key} AND labels = tamandua-alert-#{alert_id}"

    case search_issues(jql, max_results: 1) do
      {:ok, [%{"key" => key} | _]} -> {:ok, key}
      {:ok, []} -> {:ok, nil}
      error -> error
    end
  end

  @doc """
  Map Tamandua severity to Jira priority.

  ## Mapping

  - critical -> Highest
  - high -> High
  - medium -> Medium
  - low -> Low
  - other -> Medium
  """
  @spec map_severity_to_priority(String.t() | nil) :: String.t()
  defp map_severity_to_priority("critical"), do: "Highest"
  defp map_severity_to_priority("high"), do: "High"
  defp map_severity_to_priority("medium"), do: "Medium"
  defp map_severity_to_priority("low"), do: "Low"
  defp map_severity_to_priority(_), do: "Medium"
end
