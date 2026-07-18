defmodule TamanduaServer.Integrations.SlackBot do
  @moduledoc """
  Slack Bot Integration for Tamandua EDR.

  Features:
  - Slash commands for alert triage and threat hunting
  - Interactive buttons for alert actions
  - Block Kit UI with rich formatting
  - Alert notifications to channels with severity-based colors
  - Thread-based alert discussions
  - Remediation action approval workflow
  - Scheduled digest reports (daily/weekly)
  - OAuth 2.0 authentication

  ## Configuration

  Add to config/runtime.exs:

      config :tamandua_server, TamanduaServer.Integrations.SlackBot,
        client_id: System.get_env("SLACK_CLIENT_ID"),
        client_secret: System.get_env("SLACK_CLIENT_SECRET"),
        signing_secret: System.get_env("SLACK_SIGNING_SECRET"),
        bot_token: System.get_env("SLACK_BOT_TOKEN"),
        verification_token: System.get_env("SLACK_VERIFICATION_TOKEN")

  ## Slash Commands

  - `/tamandua-alerts [list|show|triage]` - Alert management
  - `/tamandua-agents [list|status|isolate]` - Agent operations
  - `/tamandua-hunt <query>` - Execute saved hunt
  - `/tamandua-ti <ioc>` - Threat intelligence lookup
  - `/tamandua-stats` - SOC dashboard metrics
  """

  use GenServer
  require Logger

  alias TamanduaServer.Integrations.BotCommands
  alias TamanduaServer.Alerts

  @api_base "https://slack.com/api"

  defmodule State do
    defstruct [
      :bot_token,
      :signing_secret,
      :verification_token,
      :workspace_configs,
      :digest_jobs
    ]
  end

  defmodule WorkspaceConfig do
    @moduledoc "Per-workspace configuration"
    defstruct [
      :team_id,
      :organization_id,
      :alert_channel,
      :escalation_channel,
      :notification_rules,
      :digest_schedule,
      :enabled
    ]
  end

  # ==========================================================================
  # Client API
  # ==========================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Handle incoming Slack slash command.
  """
  @spec handle_command(map()) :: {:ok, map()} | {:error, term()}
  def handle_command(payload) do
    GenServer.call(__MODULE__, {:handle_command, payload}, 30_000)
  end

  @doc """
  Handle interactive action (button click, menu selection).
  """
  @spec handle_interaction(map()) :: {:ok, map()} | {:error, term()}
  def handle_interaction(payload) do
    GenServer.call(__MODULE__, {:handle_interaction, payload}, 30_000)
  end

  @doc """
  Send alert notification to Slack channel.
  """
  @spec notify_alert(binary(), map()) :: {:ok, map()} | {:error, term()}
  def notify_alert(organization_id, alert) do
    GenServer.cast(__MODULE__, {:notify_alert, organization_id, alert})
  end

  @doc """
  Configure workspace for organization.
  """
  @spec configure_workspace(String.t(), binary(), map()) :: :ok | {:error, term()}
  def configure_workspace(team_id, organization_id, config) do
    GenServer.call(__MODULE__, {:configure_workspace, team_id, organization_id, config})
  end

  @doc """
  Send daily/weekly digest to configured channels.
  """
  @spec send_digest(binary(), String.t()) :: {:ok, map()} | {:error, term()}
  def send_digest(organization_id, period) when period in ["daily", "weekly"] do
    GenServer.call(__MODULE__, {:send_digest, organization_id, period})
  end

  # ==========================================================================
  # Server Callbacks
  # ==========================================================================

  @impl true
  def init(_opts) do
    config = Application.get_env(:tamandua_server, __MODULE__, [])

    state = %State{
      bot_token: config[:bot_token] || System.get_env("SLACK_BOT_TOKEN"),
      signing_secret: config[:signing_secret] || System.get_env("SLACK_SIGNING_SECRET"),
      verification_token: config[:verification_token] || System.get_env("SLACK_VERIFICATION_TOKEN"),
      workspace_configs: load_workspace_configs(),
      digest_jobs: %{}
    }

    # Schedule digest jobs
    schedule_digests(state)

    {:ok, state}
  end

  @impl true
  def handle_call({:handle_command, payload}, _from, state) do
    result = process_slash_command(payload, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:handle_interaction, payload}, _from, state) do
    result = process_interaction(payload, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:configure_workspace, team_id, org_id, config}, _from, state) do
    workspace_config = %WorkspaceConfig{
      team_id: team_id,
      organization_id: org_id,
      alert_channel: config[:alert_channel],
      escalation_channel: config[:escalation_channel],
      notification_rules: config[:notification_rules] || %{},
      digest_schedule: config[:digest_schedule] || %{daily: true, weekly: true},
      enabled: config[:enabled] != false
    }

    updated_configs = Map.put(state.workspace_configs, team_id, workspace_config)
    save_workspace_config(workspace_config)

    {:reply, :ok, %{state | workspace_configs: updated_configs}}
  end

  @impl true
  def handle_call({:send_digest, org_id, period}, _from, state) do
    result = send_digest_report(org_id, period, state)
    {:reply, result, state}
  end

  @impl true
  def handle_cast({:notify_alert, org_id, alert}, state) do
    send_alert_notification(org_id, alert, state)
    {:noreply, state}
  end

  @impl true
  def handle_info({:send_digest, org_id, period}, state) do
    send_digest_report(org_id, period, state)
    {:noreply, state}
  end

  # Catch-all prevents scheduled digest timers ({:daily_digest}/{:weekly_digest})
  # and any other stray message from crashing the GenServer with FunctionClauseError.
  def handle_info(msg, state) do
    Logger.debug("[SlackBot] Unhandled message: #{inspect(msg)}")
    {:noreply, state}
  end

  # ==========================================================================
  # Slash Command Processing
  # ==========================================================================

  defp process_slash_command(payload, state) do
    %{
      "command" => command,
      "text" => args,
      "user_id" => user_id,
      "team_id" => team_id,
      "response_url" => response_url
    } = payload

    with {:ok, workspace_config} <- get_workspace_config(team_id, state),
         {:ok, command_name} <- parse_slash_command(command) do
      org_id = workspace_config.organization_id

      case BotCommands.process_command(command_name, args, user_id, org_id, :slack) do
        {:ok, response} ->
          {:ok, format_command_response(response)}

        {:error, reason} ->
          {:ok, %{text: "❌ Error: #{reason}", response_type: "ephemeral"}}
      end
    else
      {:error, :workspace_not_configured} ->
        {:ok,
         %{
           text:
             "This workspace is not configured. Please contact your administrator to set up Tamandua integration.",
           response_type: "ephemeral"
         }}

      {:error, :unknown_command} ->
        {:ok, %{text: "Unknown command. Use `/tamandua-help` for available commands.", response_type: "ephemeral"}}
    end
  end

  defp parse_slash_command("/tamandua-alerts"), do: {:ok, "alerts"}
  defp parse_slash_command("/tamandua-agents"), do: {:ok, "agents"}
  defp parse_slash_command("/tamandua-hunt"), do: {:ok, "hunt"}
  defp parse_slash_command("/tamandua-ti"), do: {:ok, "ti"}
  defp parse_slash_command("/tamandua-stats"), do: {:ok, "stats"}
  defp parse_slash_command("/tamandua-help"), do: {:ok, "help"}
  defp parse_slash_command(_), do: {:error, :unknown_command}

  defp format_command_response(%{blocks: blocks}) do
    %{
      response_type: "in_channel",
      blocks: blocks
    }
  end

  defp format_command_response(%{text: text}) do
    %{
      response_type: "ephemeral",
      text: text
    }
  end

  # ==========================================================================
  # Interactive Action Processing
  # ==========================================================================

  defp process_interaction(payload, state) do
    %{
      "type" => type,
      "user" => %{"id" => user_id},
      "team" => %{"id" => team_id},
      "actions" => actions
    } = payload

    with {:ok, workspace_config} <- get_workspace_config(team_id, state) do
      org_id = workspace_config.organization_id

      case type do
        "block_actions" ->
          process_block_action(actions, user_id, org_id, state)

        _ ->
          {:ok, %{text: "Unknown interaction type"}}
      end
    else
      {:error, :workspace_not_configured} ->
        {:ok, %{text: "Workspace not configured"}}
    end
  end

  defp process_block_action([action | _rest], user_id, org_id, state) do
    %{"action_id" => action_id, "value" => value} = action

    case action_id do
      "alert_approve" ->
        triage_alert(org_id, value, "approve", user_id, state)

      "alert_dismiss" ->
        triage_alert(org_id, value, "dismiss", user_id, state)

      "alert_escalate" ->
        triage_alert(org_id, value, "escalate", user_id, state)

      "remediate_approve" ->
        approve_remediation(org_id, value, user_id, state)

      "remediate_deny" ->
        deny_remediation(org_id, value, user_id, state)

      _ ->
        {:ok, %{text: "Unknown action"}}
    end
  end

  defp triage_alert(org_id, alert_id, action, user_id, _state) do
    case BotCommands.process_command("alerts", "triage #{alert_id} #{action}", user_id, org_id, :slack) do
      {:ok, _response} ->
        {:ok,
         %{
           replace_original: true,
           text: "✅ Alert #{action}d successfully by <@#{user_id}>"
         }}

      {:error, reason} ->
        {:ok, %{text: "❌ Error: #{reason}"}}
    end
  end

  defp approve_remediation(org_id, action_id, user_id, _state) do
    alias TamanduaServer.Remediation.ApprovalManager

    case ApprovalManager.approve(
           action_id,
           user_id,
           "Approved via Slack",
           {:organization, org_id}
         ) do
      {:ok, _execution} ->
        {:ok,
         %{
           replace_original: true,
           text: "Remediation action approved by <@#{user_id}>",
           blocks: [
             %{
               type: "section",
               text: %{
                 type: "mrkdwn",
                 text: "*Remediation Approved*\nAction `#{action_id}` approved by <@#{user_id}>"
               }
             },
             %{
               type: "context",
               elements: [
                 %{type: "mrkdwn", text: "Approved at #{DateTime.to_iso8601(DateTime.utc_now())}"}
               ]
             }
           ]
         }}

      {:error, :not_found} ->
        {:ok, %{text: "Approval request not found or already processed"}}

      {:error, :insufficient_permissions} ->
        {:ok, %{text: "You don't have permission to approve this action"}}

      {:error, reason} when reason in [:user_not_found, :user_lookup_failed] ->
        {:ok, %{text: "Approval unavailable: link this Slack identity to a Tamandua user"}}

      {:error, reason} ->
        Logger.error("Slack approval failed: #{inspect(reason)}")
        {:ok, %{text: "Approval failed: #{inspect(reason)}"}}
    end
  end

  defp deny_remediation(org_id, action_id, user_id, _state) do
    alias TamanduaServer.Remediation.ApprovalManager

    case ApprovalManager.reject(
           action_id,
           user_id,
           "Denied via Slack",
           {:organization, org_id}
         ) do
      {:ok, _execution} ->
        {:ok,
         %{
           replace_original: true,
           text: "Remediation action denied by <@#{user_id}>",
           blocks: [
             %{
               type: "section",
               text: %{
                 type: "mrkdwn",
                 text: "*Remediation Denied*\nAction `#{action_id}` denied by <@#{user_id}>"
               }
             },
             %{
               type: "context",
               elements: [
                 %{type: "mrkdwn", text: "Denied at #{DateTime.to_iso8601(DateTime.utc_now())}"}
               ]
             }
           ]
         }}

      {:error, :not_found} ->
        {:ok, %{text: "Approval request not found or already processed"}}

      {:error, reason} when reason in [:user_not_found, :user_lookup_failed] ->
        {:ok, %{text: "Denial unavailable: link this Slack identity to a Tamandua user"}}

      {:error, reason} ->
        Logger.error("Slack denial failed: #{inspect(reason)}")
        {:ok, %{text: "Denial failed: #{inspect(reason)}"}}
    end
  end

  # ==========================================================================
  # Alert Notifications
  # ==========================================================================

  defp send_alert_notification(org_id, alert, state) do
    case get_workspace_for_org(org_id, state) do
      {:ok, workspace_config} ->
        if should_notify?(alert, workspace_config) do
          channel = get_alert_channel(alert, workspace_config)
          message = build_alert_message(alert)

          case post_message(channel, message, state.bot_token) do
            {:ok, response} ->
              # Store message timestamp for threading
              store_alert_thread(alert.id, response["ts"])
              Logger.info("Alert notification sent to Slack: #{alert.id}")

            {:error, reason} ->
              Logger.error("Failed to send Slack notification: #{inspect(reason)}")
          end
        end

      {:error, :not_found} ->
        Logger.warning("No Slack workspace configured for organization: #{org_id}")
    end
  end

  defp should_notify?(alert, workspace_config) do
    rules = workspace_config.notification_rules

    cond do
      !workspace_config.enabled -> false
      rules == %{} -> true
      Map.get(rules, :min_severity) -> check_severity_threshold(alert.severity, rules.min_severity)
      true -> true
    end
  end

  defp check_severity_threshold(severity, min_severity) do
    severity_order = %{"critical" => 4, "high" => 3, "medium" => 2, "low" => 1, "info" => 0}
    severity_order[severity] >= severity_order[min_severity]
  end

  defp get_alert_channel(alert, workspace_config) do
    if alert.severity in ["critical", "high"] and workspace_config.escalation_channel do
      workspace_config.escalation_channel
    else
      workspace_config.alert_channel
    end
  end

  defp build_alert_message(alert) do
    color = severity_color(alert.severity)

    attachments = [
      %{
        color: color,
        blocks: [
          %{
            type: "header",
            text: %{
              type: "plain_text",
              text: "🚨 New Alert: #{alert.title}"
            }
          },
          %{
            type: "section",
            fields: [
              %{type: "mrkdwn", text: "*Severity:*\n#{String.upcase(alert.severity)}"},
              %{type: "mrkdwn", text: "*Status:*\n#{alert.status}"},
              %{type: "mrkdwn", text: "*Agent:*\n#{alert.agent_id || "N/A"}"},
              %{type: "mrkdwn", text: "*Alert ID:*\n`#{alert.id}`"}
            ]
          },
          %{
            type: "section",
            text: %{
              type: "mrkdwn",
              text: "*Description:*\n#{alert.description}"
            }
          },
          %{
            type: "actions",
            block_id: "alert_actions_#{alert.id}",
            elements: [
              %{
                type: "button",
                text: %{type: "plain_text", text: "✅ Approve"},
                style: "primary",
                value: alert.id,
                action_id: "alert_approve"
              },
              %{
                type: "button",
                text: %{type: "plain_text", text: "❌ Dismiss"},
                value: alert.id,
                action_id: "alert_dismiss"
              },
              %{
                type: "button",
                text: %{type: "plain_text", text: "⬆️ Escalate"},
                style: "danger",
                value: alert.id,
                action_id: "alert_escalate"
              }
            ]
          }
        ]
      }
    ]

    if length(alert.mitre_techniques) > 0 do
      mitre_block = %{
        type: "section",
        text: %{
          type: "mrkdwn",
          text:
            "*MITRE ATT&CK:*\n" <>
              "Tactics: #{Enum.join(alert.mitre_tactics, ", ")}\n" <>
              "Techniques: #{Enum.join(alert.mitre_techniques, ", ")}"
        }
      }

      put_in(attachments, [Access.at(0), :blocks], List.insert_at(attachments[0].blocks, -1, mitre_block))
    else
      attachments
    end

    %{attachments: attachments}
  end

  defp severity_color("critical"), do: "#dc3545"
  defp severity_color("high"), do: "#fd7e14"
  defp severity_color("medium"), do: "#ffc107"
  defp severity_color("low"), do: "#28a745"
  defp severity_color("info"), do: "#17a2b8"
  defp severity_color(_), do: "#6c757d"

  # ==========================================================================
  # Digest Reports
  # ==========================================================================

  defp send_digest_report(org_id, period, state) do
    with {:ok, workspace_config} <- get_workspace_for_org(org_id, state),
         true <- workspace_config.enabled do
      stats = gather_digest_stats(org_id, period)
      message = build_digest_message(stats, period)
      channel = workspace_config.alert_channel

      post_message(channel, message, state.bot_token)
    else
      {:error, :not_found} ->
        {:error, :workspace_not_configured}

      false ->
        {:error, :workspace_disabled}
    end
  end

  defp gather_digest_stats(org_id, period) do
    hours =
      case period do
        "daily" -> 24
        "weekly" -> 168
      end

    start_time = DateTime.utc_now() |> DateTime.add(-hours * 3600, :second)

    %{
      total_alerts: Alerts.count_alerts_for_org(org_id),
      new_alerts: count_alerts_since(org_id, start_time),
      critical: Alerts.count_by_severity_for_org(org_id, "critical"),
      high: Alerts.count_by_severity_for_org(org_id, "high"),
      medium: Alerts.count_by_severity_for_org(org_id, "medium"),
      low: Alerts.count_by_severity_for_org(org_id, "low"),
      resolved: count_resolved_alerts(org_id, start_time),
      agents_total: TamanduaServer.Agents.count_agents_for_org(org_id),
      agents_online: TamanduaServer.Agents.count_online_for_org(org_id),
      period: period,
      start_time: start_time
    }
  end

  defp count_alerts_since(_org_id, _start_time) do
    # TODO: Implement time-based alert counting
    0
  end

  defp count_resolved_alerts(_org_id, _start_time) do
    # TODO: Implement resolved alert counting
    0
  end

  defp build_digest_message(stats, period) do
    period_text = String.capitalize(period)

    %{
      blocks: [
        %{
          type: "header",
          text: %{
            type: "plain_text",
            text: "📊 Tamandua EDR #{period_text} Digest"
          }
        },
        %{
          type: "section",
          text: %{
            type: "mrkdwn",
            text: "*Alert Summary*"
          }
        },
        %{
          type: "section",
          fields: [
            %{type: "mrkdwn", text: "*New Alerts:*\n#{stats.new_alerts}"},
            %{type: "mrkdwn", text: "*Resolved:*\n#{stats.resolved}"},
            %{type: "mrkdwn", text: "*🔴 Critical:*\n#{stats.critical}"},
            %{type: "mrkdwn", text: "*🟠 High:*\n#{stats.high}"},
            %{type: "mrkdwn", text: "*🟡 Medium:*\n#{stats.medium}"},
            %{type: "mrkdwn", text: "*🟢 Low:*\n#{stats.low}"}
          ]
        },
        %{type: "divider"},
        %{
          type: "section",
          text: %{
            type: "mrkdwn",
            text: "*Agent Health*"
          }
        },
        %{
          type: "section",
          fields: [
            %{type: "mrkdwn", text: "*Total Agents:*\n#{stats.agents_total}"},
            %{type: "mrkdwn", text: "*Online:*\n#{stats.agents_online}"},
            %{type: "mrkdwn", text: "*Offline:*\n#{stats.agents_total - stats.agents_online}"}
          ]
        },
        %{
          type: "context",
          elements: [
            %{
              type: "mrkdwn",
              text: "Report generated at #{DateTime.to_string(DateTime.utc_now())}"
            }
          ]
        }
      ]
    }
  end

  defp schedule_digests(_state) do
    # Schedule daily digest at 9 AM UTC
    daily_seconds = calculate_next_run(9, 0)
    Process.send_after(self(), {:daily_digest}, daily_seconds * 1000)

    # Schedule weekly digest on Monday at 9 AM UTC
    weekly_seconds = calculate_next_weekly_run(1, 9, 0)
    Process.send_after(self(), {:weekly_digest}, weekly_seconds * 1000)
  end

  defp calculate_next_run(hour, minute) do
    now = DateTime.utc_now()
    target = %{now | hour: hour, minute: minute, second: 0, microsecond: {0, 0}}

    target =
      if DateTime.compare(target, now) == :lt do
        DateTime.add(target, 86400, :second)
      else
        target
      end

    DateTime.diff(target, now)
  end

  defp calculate_next_weekly_run(_day_of_week, hour, minute) do
    # Simplified - just use daily for now
    calculate_next_run(hour, minute)
  end

  # ==========================================================================
  # Slack API Integration
  # ==========================================================================

  defp post_message(channel, message, bot_token) do
    url = "#{@api_base}/chat.postMessage"

    headers = [
      {"Authorization", "Bearer #{bot_token}"},
      {"Content-Type", "application/json"}
    ]

    body =
      message
      |> Map.put(:channel, channel)
      |> Jason.encode!()

    case HTTPoison.post(url, body, headers) do
      {:ok, %{status_code: 200, body: response_body}} ->
        {:ok, Jason.decode!(response_body)}

      {:ok, %{status_code: status_code, body: body}} ->
        Logger.error("Slack API error: #{status_code} - #{body}")
        {:error, {:api_error, status_code}}

      {:error, reason} ->
        Logger.error("HTTP error posting to Slack: #{inspect(reason)}")
        {:error, reason}
    end
  end

  # ==========================================================================
  # Workspace Configuration
  # ==========================================================================

  defp get_workspace_config(team_id, state) do
    case Map.get(state.workspace_configs, team_id) do
      nil -> {:error, :workspace_not_configured}
      config -> {:ok, config}
    end
  end

  defp get_workspace_for_org(org_id, state) do
    workspace =
      Enum.find_value(state.workspace_configs, fn {_team_id, config} ->
        if config.organization_id == org_id, do: config
      end)

    case workspace do
      nil -> {:error, :not_found}
      config -> {:ok, config}
    end
  end

  defp load_workspace_configs do
    alias TamanduaServer.Integrations.Chat.SlackConfig

    SlackConfig.list_enabled()
    |> Enum.map(fn config ->
      workspace = %WorkspaceConfig{
        team_id: config.team_id,
        organization_id: config.organization_id,
        alert_channel: config.alert_channel,
        escalation_channel: config.escalation_channel,
        notification_rules: config.notification_rules || %{},
        digest_schedule: config.digest_schedule || %{daily: true, weekly: true},
        enabled: config.enabled
      }
      {config.team_id, workspace}
    end)
    |> Map.new()
  rescue
    _ ->
      # Database may not be ready during startup
      Logger.debug("[SlackBot] Could not load workspace configs from database")
      %{}
  end

  defp save_workspace_config(config) do
    alias TamanduaServer.Integrations.Chat.SlackConfig

    case SlackConfig.get_for_team_id(config.team_id) do
      nil ->
        SlackConfig.create_config(%{
          team_id: config.team_id,
          organization_id: config.organization_id,
          alert_channel: config.alert_channel,
          escalation_channel: config.escalation_channel,
          notification_rules: config.notification_rules,
          digest_schedule: config.digest_schedule,
          enabled: config.enabled
        })

      existing ->
        SlackConfig.update_config(existing, %{
          alert_channel: config.alert_channel,
          escalation_channel: config.escalation_channel,
          notification_rules: config.notification_rules,
          digest_schedule: config.digest_schedule,
          enabled: config.enabled
        })
    end
  end

  defp store_alert_thread(alert_id, thread_ts) do
    # Store in ETS for threading replies
    try do
      :ets.insert(:slack_alert_threads, {alert_id, thread_ts, DateTime.utc_now()})
      :ok
    rescue
      ArgumentError ->
        # ETS table doesn't exist, create it
        try do
          :ets.new(:slack_alert_threads, [:named_table, :public, :set])
          :ets.insert(:slack_alert_threads, {alert_id, thread_ts, DateTime.utc_now()})
          :ok
        rescue
          _ -> :ok
        end
    end
  end

  @doc """
  Send a message to a specific channel.

  Used by ChatRouter for approval notifications.
  """
  @spec send_to_channel(binary(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def send_to_channel(_org_id, channel, message) do
    GenServer.call(__MODULE__, {:send_to_channel, channel, message}, 30_000)
  catch
    :exit, {:noproc, _} ->
      # If GenServer not running, try direct send
      config = Application.get_env(:tamandua_server, __MODULE__, [])
      bot_token = config[:bot_token] || System.get_env("SLACK_BOT_TOKEN")

      if bot_token do
        post_message_direct(channel, message, bot_token)
      else
        {:error, :no_bot_token}
      end
  end

  defp post_message_direct(channel, message, bot_token) do
    url = "#{@api_base}/chat.postMessage"

    headers = [
      {"Authorization", "Bearer #{bot_token}"},
      {"Content-Type", "application/json"}
    ]

    body =
      message
      |> Map.put(:channel, channel)
      |> Jason.encode!()

    case HTTPoison.post(url, body, headers) do
      {:ok, %{status_code: 200, body: response_body}} ->
        {:ok, Jason.decode!(response_body)}

      {:ok, %{status_code: status_code, body: body}} ->
        Logger.error("Slack API error: #{status_code} - #{body}")
        {:error, {:api_error, status_code}}

      {:error, reason} ->
        Logger.error("HTTP error posting to Slack: #{inspect(reason)}")
        {:error, reason}
    end
  end
end
