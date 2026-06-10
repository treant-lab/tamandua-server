defmodule TamanduaServer.Integrations.ChatRouter do
  @moduledoc """
  Unified router for dispatching alerts and approval requests to chat platforms.

  Supports Slack and Microsoft Teams with:
  - Severity-based routing (escalation channel for critical/high)
  - Min severity filtering
  - Async dispatch using Task.async_stream
  - Per-organization configuration
  - Approval workflow notifications

  ## Routing Logic

  - **Critical/High severity** - Send to escalation channel if configured
  - **Medium/Low/Info severity** - Send to regular alert channel
  - Only send if alert severity >= min_severity config

  ## Example

      ChatRouter.route_alert(%{
        id: "alert-123",
        organization_id: "org-456",
        title: "Suspicious process detected",
        severity: "high",
        description: "..."
      })

      ChatRouter.notify_approval_required(execution, approval_request)
  """

  use GenServer
  require Logger

  alias TamanduaServer.Integrations.Chat.{SlackConfig, TeamsConfig}
  alias TamanduaServer.Integrations.{SlackBot, TeamsBot}

  @severity_order %{"critical" => 4, "high" => 3, "medium" => 2, "low" => 1, "info" => 0}

  defstruct [:stats]

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Starts the ChatRouter GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Route an alert to all enabled chat platforms for the organization.

  ## Parameters

  - `alert` - Alert map with :id, :organization_id, :title, :severity, :description, etc.
  - `opts` - Optional:
    - `:force` - Skip min_severity check (default: false)

  ## Returns

  `{:ok, results}` list of {type, result} tuples, `{:error, reason}` on failure.
  """
  @spec route_alert(map(), keyword()) :: {:ok, [tuple()]} | {:error, term()}
  def route_alert(alert, opts \\ []) do
    GenServer.call(__MODULE__, {:route_alert, alert, opts}, 60_000)
  catch
    :exit, {:noproc, _} ->
      do_route_alert(alert, opts)
  end

  @doc """
  Send approval request notification to chat platforms.

  ## Parameters

  - `execution` - Remediation execution struct
  - `approval_request` - Approval request details

  ## Returns

  `{:ok, results}` with dispatch results per platform.
  """
  @spec notify_approval_required(map(), map()) :: {:ok, [tuple()]} | {:error, term()}
  def notify_approval_required(execution, approval_request) do
    GenServer.call(__MODULE__, {:notify_approval, execution, approval_request}, 60_000)
  catch
    :exit, {:noproc, _} ->
      {:error, :not_started}
  end

  @doc """
  Get enabled chat integrations for an organization.

  ## Parameters

  - `organization_id` - Organization UUID

  ## Returns

  List of maps with :type and :config for each enabled integration.
  """
  @spec get_enabled_integrations(binary()) :: [map()]
  def get_enabled_integrations(organization_id) do
    slack_configs = SlackConfig.get_for_organization(organization_id)
    teams_configs = TeamsConfig.get_for_organization(organization_id)

    Enum.concat([
      Enum.map(slack_configs, &%{type: :slack, config: &1}),
      Enum.map(teams_configs, &%{type: :teams, config: &1})
    ])
  end

  @doc """
  Get routing statistics.

  ## Returns

  Map with alerts_sent, approvals_sent, errors counts.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  catch
    :exit, {:noproc, _} ->
      %{alerts_sent: 0, approvals_sent: 0, errors: 0, by_type: %{}}
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    Logger.info("[ChatRouter] Starting chat router")

    state = %__MODULE__{
      stats: %{
        alerts_sent: 0,
        approvals_sent: 0,
        errors: 0,
        by_type: %{},
        last_activity: nil
      }
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:route_alert, alert, opts}, _from, state) do
    org_id = get_org_id(alert)
    results = do_route_alert_internal(alert, org_id, opts)
    new_stats = update_stats(state.stats, results, :alert)
    {:reply, {:ok, results}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:notify_approval, execution, approval_request}, _from, state) do
    org_id = Map.get(execution, :organization_id) || Map.get(execution, "organization_id")
    results = send_approval_notifications(execution, approval_request, org_id)
    new_stats = update_stats(state.stats, results, :approval)
    {:reply, {:ok, results}, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    {:reply, state.stats, state}
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp do_route_alert(alert, opts) do
    org_id = get_org_id(alert)
    {:ok, do_route_alert_internal(alert, org_id, opts)}
  end

  defp do_route_alert_internal(alert, org_id, opts) do
    if is_nil(org_id) do
      Logger.warning("[ChatRouter] Alert missing organization_id: #{inspect(alert[:id])}")
      []
    else
      integrations = get_enabled_integrations(org_id)
      force = Keyword.get(opts, :force, false)

      if length(integrations) == 0 do
        Logger.debug("[ChatRouter] No chat integrations enabled for org #{org_id}")
        []
      else
        integrations
        |> Enum.filter(fn %{config: config} ->
          force or should_notify?(alert, config)
        end)
        |> Task.async_stream(fn %{type: type, config: config} ->
          result = case type do
            :slack -> send_slack_alert(alert, config)
            :teams -> send_teams_alert(alert, config)
          end
          {type, result}
        end, timeout: 30_000, on_timeout: :kill_task)
        |> Enum.map(fn
          {:ok, result} -> result
          {:exit, reason} -> {:unknown, {:error, {:timeout, reason}}}
        end)
      end
    end
  end

  @doc false
  def should_notify?(alert, config) do
    alert_severity = get_severity(alert)
    min_severity = Map.get(config, :min_severity) || "high"

    @severity_order[alert_severity] >= @severity_order[min_severity]
  end

  defp send_slack_alert(alert, config) do
    try do
      # Cast notification to SlackBot GenServer
      SlackBot.notify_alert(config.organization_id, struct_from_map(alert))
      :ok
    rescue
      e ->
        Logger.error("[ChatRouter] Slack alert failed: #{Exception.message(e)}")
        {:error, Exception.message(e)}
    end
  end

  defp send_teams_alert(alert, config) do
    try do
      # Cast notification to TeamsBot GenServer
      TeamsBot.notify_alert(config.organization_id, struct_from_map(alert))
      :ok
    rescue
      e ->
        Logger.error("[ChatRouter] Teams alert failed: #{Exception.message(e)}")
        {:error, Exception.message(e)}
    end
  end

  defp send_approval_notifications(execution, approval_request, org_id) do
    if is_nil(org_id) do
      Logger.warning("[ChatRouter] Execution missing organization_id")
      []
    else
      integrations = get_enabled_integrations(org_id)

      Enum.map(integrations, fn %{type: type, config: config} ->
        result = case type do
          :slack -> send_slack_approval_request(execution, approval_request, config)
          :teams -> send_teams_approval_request(execution, approval_request, config)
        end
        {type, result}
      end)
    end
  end

  defp send_slack_approval_request(execution, approval_request, config) do
    try do
      # Build Block Kit message with approval buttons
      # Note: This sends to the configured channel via SlackBot
      message = build_slack_approval_message(execution, approval_request)
      channel = config.escalation_channel || config.alert_channel

      if channel do
        SlackBot.send_to_channel(config.organization_id, channel, message)
        :ok
      else
        {:error, :no_channel_configured}
      end
    rescue
      e ->
        Logger.error("[ChatRouter] Slack approval request failed: #{Exception.message(e)}")
        {:error, Exception.message(e)}
    end
  end

  defp send_teams_approval_request(execution, approval_request, config) do
    try do
      # Build Adaptive Card with approval buttons
      card = build_teams_approval_card(execution, approval_request)
      channel = config.escalation_channel_id || config.alert_channel_id

      if channel && config.conversation_reference do
        TeamsBot.send_proactive(config.organization_id, channel, card)
        :ok
      else
        {:error, :no_channel_or_conversation_reference}
      end
    rescue
      e ->
        Logger.error("[ChatRouter] Teams approval request failed: #{Exception.message(e)}")
        {:error, Exception.message(e)}
    end
  end

  defp build_slack_approval_message(execution, approval_request) do
    %{
      blocks: [
        %{
          type: "header",
          text: %{
            type: "plain_text",
            text: "Approval Required: Remediation Action"
          }
        },
        %{
          type: "section",
          text: %{
            type: "mrkdwn",
            text: """
            *Playbook:* #{approval_request[:playbook_name] || "Unknown"}
            *Action:* #{approval_request[:action_type] || "Unknown"}
            *Target:* #{approval_request[:target] || "Unknown"}
            *Requested by:* #{approval_request[:requested_by] || "System"}
            """
          }
        },
        %{
          type: "section",
          text: %{
            type: "mrkdwn",
            text: "*Execution ID:* `#{execution[:id] || execution["id"]}`"
          }
        },
        %{
          type: "actions",
          elements: [
            %{
              type: "button",
              text: %{type: "plain_text", text: "Approve"},
              style: "primary",
              action_id: "remediate_approve",
              value: "#{execution[:id] || execution["id"]}"
            },
            %{
              type: "button",
              text: %{type: "plain_text", text: "Deny"},
              style: "danger",
              action_id: "remediate_deny",
              value: "#{execution[:id] || execution["id"]}"
            }
          ]
        }
      ]
    }
  end

  defp build_teams_approval_card(execution, approval_request) do
    %{
      "$schema" => "http://adaptivecards.io/schemas/adaptive-card.json",
      "type" => "AdaptiveCard",
      "version" => "1.4",
      "body" => [
        %{
          "type" => "TextBlock",
          "text" => "Approval Required: Remediation Action",
          "weight" => "bolder",
          "size" => "large"
        },
        %{
          "type" => "FactSet",
          "facts" => [
            %{"title" => "Playbook", "value" => approval_request[:playbook_name] || "Unknown"},
            %{"title" => "Action", "value" => approval_request[:action_type] || "Unknown"},
            %{"title" => "Target", "value" => approval_request[:target] || "Unknown"},
            %{"title" => "Requested by", "value" => approval_request[:requested_by] || "System"},
            %{"title" => "Execution ID", "value" => "#{execution[:id] || execution["id"]}"}
          ]
        }
      ],
      "actions" => [
        %{
          "type" => "Action.Submit",
          "title" => "Approve",
          "style" => "positive",
          "data" => %{
            "action" => "remediate_approve",
            "execution_id" => "#{execution[:id] || execution["id"]}"
          }
        },
        %{
          "type" => "Action.Submit",
          "title" => "Deny",
          "style" => "destructive",
          "data" => %{
            "action" => "remediate_deny",
            "execution_id" => "#{execution[:id] || execution["id"]}"
          }
        }
      ]
    }
  end

  defp struct_from_map(map) when is_map(map) do
    # Convert map to struct-like map with atom keys
    for {key, value} <- map, into: %{} do
      key = if is_binary(key), do: String.to_existing_atom(key), else: key
      {key, value}
    end
  rescue
    ArgumentError ->
      # If atom doesn't exist, fall back to safe conversion
      for {key, value} <- map, into: %{} do
        key = if is_binary(key), do: String.to_atom(key), else: key
        {key, value}
      end
  end

  defp get_org_id(alert) do
    alert[:organization_id] || alert["organization_id"]
  end

  defp get_severity(alert) do
    severity = alert[:severity] || alert["severity"] || "medium"
    String.downcase(to_string(severity))
  end

  defp update_stats(stats, results, type) do
    errors = Enum.count(results, fn {_, r} -> match?({:error, _}, r) end)
    successes = Enum.count(results, fn {_, r} -> r == :ok or match?({:ok, _}, r) end)

    by_type = Enum.reduce(results, stats.by_type, fn {platform, result}, acc ->
      current = Map.get(acc, platform, %{success: 0, failure: 0})

      updated =
        case result do
          :ok -> %{current | success: current.success + 1}
          {:ok, _} -> %{current | success: current.success + 1}
          {:error, _} -> %{current | failure: current.failure + 1}
        end

      Map.put(acc, platform, updated)
    end)

    case type do
      :alert ->
        %{stats |
          alerts_sent: stats.alerts_sent + successes,
          errors: stats.errors + errors,
          by_type: by_type,
          last_activity: DateTime.utc_now()
        }

      :approval ->
        %{stats |
          approvals_sent: stats.approvals_sent + successes,
          errors: stats.errors + errors,
          by_type: by_type,
          last_activity: DateTime.utc_now()
        }
    end
  end
end
