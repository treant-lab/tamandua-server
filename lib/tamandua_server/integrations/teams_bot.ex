defmodule TamanduaServer.Integrations.TeamsBot do
  @moduledoc """
  Microsoft Teams Bot Integration for Tamandua EDR.

  Features:
  - Adaptive Cards for interactive UI
  - Action-based message responses
  - Alert notifications with priority indicators
  - Channel webhook integration
  - Bot commands (@Tamandua alerts, @Tamandua hunt)
  - Remediation approval cards
  - Threat intel lookup cards
  - Agent health cards
  - Teams authentication integration
  - Scheduled activity digests

  ## Configuration

  Add to config/runtime.exs:

      config :tamandua_server, TamanduaServer.Integrations.TeamsBot,
        app_id: System.get_env("TEAMS_APP_ID"),
        app_password: System.get_env("TEAMS_APP_PASSWORD"),
        tenant_id: System.get_env("TEAMS_TENANT_ID")

  ## Bot Commands

  Mention the bot in a channel:
  - `@Tamandua alerts list` - List recent alerts
  - `@Tamandua agents status` - Agent health status
  - `@Tamandua hunt <name>` - Execute saved hunt
  - `@Tamandua ti <ioc>` - Threat intelligence lookup
  - `@Tamandua stats` - SOC dashboard
  """

  use GenServer
  require Logger

  alias TamanduaServer.Integrations.BotCommands
  alias TamanduaServer.Alerts

  @bot_framework_api "https://smba.trafficmanager.net/api"

  defmodule State do
    defstruct [
      :app_id,
      :app_password,
      :tenant_id,
      :access_token,
      :token_expires_at,
      :team_configs,
      :conversation_references
    ]
  end

  defmodule TeamConfig do
    @moduledoc "Per-team configuration"
    defstruct [
      :team_id,
      :organization_id,
      :alert_channel_id,
      :escalation_channel_id,
      :notification_rules,
      :digest_schedule,
      :webhook_url,
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
  Handle incoming Teams activity (message, action, etc).
  """
  @spec handle_activity(map()) :: {:ok, map()} | {:error, term()}
  def handle_activity(activity) do
    GenServer.call(__MODULE__, {:handle_activity, activity}, 30_000)
  end

  @doc """
  Send alert notification to Teams channel.
  """
  @spec notify_alert(binary(), map()) :: {:ok, map()} | {:error, term()}
  def notify_alert(organization_id, alert) do
    GenServer.cast(__MODULE__, {:notify_alert, organization_id, alert})
  end

  @doc """
  Configure team for organization.
  """
  @spec configure_team(String.t(), binary(), map()) :: :ok | {:error, term()}
  def configure_team(team_id, organization_id, config) do
    GenServer.call(__MODULE__, {:configure_team, team_id, organization_id, config})
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
      app_id: config[:app_id] || System.get_env("TEAMS_APP_ID"),
      app_password: config[:app_password] || System.get_env("TEAMS_APP_PASSWORD"),
      tenant_id: config[:tenant_id] || System.get_env("TEAMS_TENANT_ID"),
      access_token: nil,
      token_expires_at: nil,
      team_configs: load_team_configs(),
      conversation_references: %{}
    }

    if teams_configured?(state) do
      # A token-endpoint failure at boot (Azure AD outage, expired secret, clock
      # skew, transient network) must not crash init into a supervisor restart
      # loop. ensure_valid_token/1 lazily refreshes on first use, so start without
      # a token if the initial refresh fails.
      case refresh_access_token(state) do
        {:ok, state} ->
          {:ok, state}

        {:error, reason} ->
          Logger.error(
            "[TeamsBot] Initial token refresh failed: #{inspect(reason)}; starting without token"
          )
          {:ok, state}
      end
    else
      Logger.warning("[TeamsBot] Disabled: TEAMS_APP_ID, TEAMS_APP_PASSWORD, or TEAMS_TENANT_ID not configured")
      {:ok, state}
    end
  end

  defp teams_configured?(%State{} = state) do
    present?(state.app_id) and present?(state.app_password) and present?(state.tenant_id)
  end

  defp present?(value), do: is_binary(value) and String.trim(value) != ""

  @impl true
  def handle_call({:handle_activity, activity}, _from, state) do
    result = process_activity(activity, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:configure_team, team_id, org_id, config}, _from, state) do
    team_config = %TeamConfig{
      team_id: team_id,
      organization_id: org_id,
      alert_channel_id: config[:alert_channel_id],
      escalation_channel_id: config[:escalation_channel_id],
      notification_rules: config[:notification_rules] || %{},
      digest_schedule: config[:digest_schedule] || %{daily: true, weekly: true},
      webhook_url: config[:webhook_url],
      enabled: config[:enabled] != false
    }

    updated_configs = Map.put(state.team_configs, team_id, team_config)
    save_team_config(team_config)

    {:reply, :ok, %{state | team_configs: updated_configs}}
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

  # ==========================================================================
  # Activity Processing
  # ==========================================================================

  defp process_activity(activity, state) do
    activity_type = activity["type"]

    case activity_type do
      "message" ->
        process_message(activity, state)

      "invoke" ->
        process_invoke(activity, state)

      "conversationUpdate" ->
        process_conversation_update(activity, state)

      _ ->
        Logger.debug("Unhandled activity type: #{activity_type}")
        {:ok, %{}}
    end
  end

  defp process_message(activity, state) do
    text = activity["text"] || ""
    user_id = get_in(activity, ["from", "id"])
    team_id = get_in(activity, ["channelData", "team", "id"])

    # Check if bot is mentioned
    mentions = activity["entities"] || []
    bot_mentioned? = Enum.any?(mentions, fn entity -> entity["type"] == "mention" end)

    if bot_mentioned? do
      # Remove bot mention from text
      clean_text = remove_bot_mention(text, activity["recipient"]["name"])

      with {:ok, team_config} <- get_team_config(team_id, state),
           {:ok, command, args} <- parse_message_command(clean_text) do
        org_id = team_config.organization_id

        case BotCommands.process_command(command, args, user_id, org_id, :teams) do
          {:ok, response} ->
            reply = build_reply(activity, response)
            send_activity(reply, state)

          {:error, reason} ->
            reply = build_error_reply(activity, reason)
            send_activity(reply, state)
        end
      else
        {:error, :team_not_configured} ->
          reply = build_error_reply(activity, "This team is not configured for Tamandua")
          send_activity(reply, state)

        {:error, :invalid_command} ->
          reply = build_error_reply(activity, "Invalid command. Mention @Tamandua help for available commands.")
          send_activity(reply, state)
      end
    else
      # Ignore messages where bot is not mentioned
      {:ok, %{}}
    end
  end

  defp process_invoke(activity, state) do
    %{"name" => invoke_name, "value" => value} = activity

    case invoke_name do
      "adaptiveCard/action" ->
        process_adaptive_card_action(value, activity, state)

      _ ->
        Logger.debug("Unhandled invoke: #{invoke_name}")
        {:ok, %{}}
    end
  end

  defp process_conversation_update(activity, _state) do
    # Handle bot added to conversation, members added/removed, etc.
    # Store conversation reference for proactive messaging
    if activity["membersAdded"] do
      conv_ref = %{
        "serviceUrl" => activity["serviceUrl"],
        "conversation" => activity["conversation"],
        "bot" => activity["recipient"],
        "user" => activity["from"]
      }

      # Store for later use in proactive messaging
      team_id = get_in(activity, ["channelData", "team", "id"])
      if team_id do
        store_conversation_reference(team_id, conv_ref)
        Logger.info("[TeamsBot] Stored conversation reference for team: #{team_id}")
      end
    end

    Logger.debug("Conversation update processed: #{activity["type"]}")
    {:ok, %{}}
  end

  defp process_adaptive_card_action(action_data, activity, state) do
    action_type = action_data["action"]
    user_id = get_in(activity, ["from", "id"])
    team_id = get_in(activity, ["channelData", "team", "id"])

    with {:ok, team_config} <- get_team_config(team_id, state) do
      org_id = team_config.organization_id

      case action_type do
        "alert_approve" ->
          triage_alert(org_id, action_data["alert_id"], "approve", user_id, activity, state)

        "alert_dismiss" ->
          triage_alert(org_id, action_data["alert_id"], "dismiss", user_id, activity, state)

        "alert_escalate" ->
          triage_alert(org_id, action_data["alert_id"], "escalate", user_id, activity, state)

        "remediate_approve" ->
          approve_remediation(org_id, action_data["action_id"], user_id, activity, state)

        "remediate_deny" ->
          deny_remediation(org_id, action_data["action_id"], user_id, activity, state)

        _ ->
          {:ok, %{}}
      end
    else
      {:error, :team_not_configured} ->
        {:error, :team_not_configured}
    end
  end

  defp triage_alert(org_id, alert_id, action, user_id, activity, state) do
    case BotCommands.process_command("alerts", "triage #{alert_id} #{action}", user_id, org_id, :teams) do
      {:ok, _response} ->
        # Update the card to show the action was taken
        updated_card = build_triage_confirmation_card(alert_id, action, user_id)
        update_activity(activity["replyToId"], updated_card, activity, state)

      {:error, reason} ->
        error_card = build_error_card(reason)
        reply = build_card_reply(activity, error_card)
        send_activity(reply, state)
    end
  end

  defp approve_remediation(org_id, action_id, user_id, activity, state) do
    alias TamanduaServer.Remediation.ApprovalManager

    case ApprovalManager.approve(
           action_id,
           user_id,
           "Approved via Teams",
           {:organization, org_id}
         ) do
      {:ok, _execution} ->
        confirmation_card = build_remediation_confirmation_card(action_id, "approved", user_id)
        # Try to update the original card, fall back to reply
        case update_activity(activity["replyToId"], confirmation_card, activity, state) do
          {:ok, _} -> {:ok, %{}}
          {:error, _} ->
            reply = build_card_reply(activity, confirmation_card)
            send_activity(reply, state)
        end

      {:error, :not_found} ->
        error_card = build_error_card("Approval request not found or already processed")
        reply = build_card_reply(activity, error_card)
        send_activity(reply, state)

      {:error, :insufficient_permissions} ->
        error_card = build_error_card("You don't have permission to approve this action")
        reply = build_card_reply(activity, error_card)
        send_activity(reply, state)

      {:error, reason} when reason in [:user_not_found, :user_lookup_failed] ->
        error_card = build_error_card("Approval unavailable: link this Teams identity to Tamandua")
        reply = build_card_reply(activity, error_card)
        send_activity(reply, state)

      {:error, reason} ->
        Logger.error("Teams approval failed: #{inspect(reason)}")
        error_card = build_error_card("Approval failed: #{inspect(reason)}")
        reply = build_card_reply(activity, error_card)
        send_activity(reply, state)
    end
  end

  defp deny_remediation(org_id, action_id, user_id, activity, state) do
    alias TamanduaServer.Remediation.ApprovalManager

    case ApprovalManager.reject(
           action_id,
           user_id,
           "Denied via Teams",
           {:organization, org_id}
         ) do
      {:ok, _execution} ->
        confirmation_card = build_remediation_confirmation_card(action_id, "denied", user_id)
        case update_activity(activity["replyToId"], confirmation_card, activity, state) do
          {:ok, _} -> {:ok, %{}}
          {:error, _} ->
            reply = build_card_reply(activity, confirmation_card)
            send_activity(reply, state)
        end

      {:error, :not_found} ->
        error_card = build_error_card("Denial request not found or already processed")
        reply = build_card_reply(activity, error_card)
        send_activity(reply, state)

      {:error, reason} when reason in [:user_not_found, :user_lookup_failed] ->
        error_card = build_error_card("Denial unavailable: link this Teams identity to Tamandua")
        reply = build_card_reply(activity, error_card)
        send_activity(reply, state)

      {:error, reason} ->
        Logger.error("Teams denial failed: #{inspect(reason)}")
        error_card = build_error_card("Denial failed: #{inspect(reason)}")
        reply = build_card_reply(activity, error_card)
        send_activity(reply, state)
    end
  end

  # ==========================================================================
  # Message Parsing
  # ==========================================================================

  defp remove_bot_mention(text, bot_name) do
    text
    |> String.replace(~r/<at>#{Regex.escape(bot_name)}<\/at>/i, "")
    |> String.trim()
  end

  defp parse_message_command(text) do
    tokens = String.split(String.trim(text), " ", parts: 2)

    case tokens do
      [command] -> {:ok, command, ""}
      [command, args] -> {:ok, command, args}
      _ -> {:error, :invalid_command}
    end
  end

  # ==========================================================================
  # Alert Notifications
  # ==========================================================================

  defp send_alert_notification(org_id, alert, state) do
    case get_team_for_org(org_id, state) do
      {:ok, team_config} ->
        if should_notify?(alert, team_config) do
          card = build_alert_card(alert)

          if team_config.webhook_url do
            send_webhook_message(team_config.webhook_url, card)
          else
            # Use conversation reference to send proactive message
            send_proactive_message(team_config, card, state)
          end

          Logger.info("Alert notification sent to Teams: #{alert.id}")
        end

      {:error, :not_found} ->
        Logger.warning("No Teams configuration found for organization: #{org_id}")
    end
  end

  defp should_notify?(alert, team_config) do
    rules = team_config.notification_rules

    cond do
      !team_config.enabled -> false
      rules == %{} -> true
      Map.get(rules, :min_severity) -> check_severity_threshold(alert.severity, rules.min_severity)
      true -> true
    end
  end

  defp check_severity_threshold(severity, min_severity) do
    severity_order = %{"critical" => 4, "high" => 3, "medium" => 2, "low" => 1, "info" => 0}
    severity_order[severity] >= severity_order[min_severity]
  end

  # ==========================================================================
  # Adaptive Cards
  # ==========================================================================

  defp build_alert_card(alert) do
    %{
      type: "message",
      attachments: [
        %{
          contentType: "application/vnd.microsoft.card.adaptive",
          content: %{
            type: "AdaptiveCard",
            version: "1.4",
            schema: "http://adaptivecards.io/schemas/adaptive-card.json",
            body: [
              %{
                type: "Container",
                style: alert_style(alert.severity),
                items: [
                  %{
                    type: "TextBlock",
                    text: "🚨 New Alert",
                    weight: "Bolder",
                    size: "Large",
                    color: "Attention"
                  },
                  %{
                    type: "TextBlock",
                    text: alert.title,
                    weight: "Bolder",
                    size: "Medium",
                    wrap: true
                  }
                ]
              },
              %{
                type: "FactSet",
                facts: [
                  %{title: "Alert ID", value: alert.id},
                  %{title: "Severity", value: String.upcase(alert.severity)},
                  %{title: "Status", value: alert.status},
                  %{title: "Agent", value: alert.agent_id || "N/A"}
                ]
              },
              %{
                type: "TextBlock",
                text: "**Description:**",
                weight: "Bolder"
              },
              %{
                type: "TextBlock",
                text: alert.description,
                wrap: true
              }
            ]
            |> maybe_add_mitre_info(alert),
            actions: [
              %{
                type: "Action.Submit",
                title: "✅ Approve",
                style: "positive",
                data: %{
                  action: "alert_approve",
                  alert_id: alert.id
                }
              },
              %{
                type: "Action.Submit",
                title: "❌ Dismiss",
                data: %{
                  action: "alert_dismiss",
                  alert_id: alert.id
                }
              },
              %{
                type: "Action.Submit",
                title: "⬆️ Escalate",
                style: "destructive",
                data: %{
                  action: "alert_escalate",
                  alert_id: alert.id
                }
              }
            ]
          }
        }
      ]
    }
  end

  defp maybe_add_mitre_info(body, alert) do
    if length(alert.mitre_techniques) > 0 do
      body ++
        [
          %{
            type: "TextBlock",
            text: "**MITRE ATT&CK:**",
            weight: "Bolder"
          },
          %{
            type: "TextBlock",
            text: "Tactics: #{Enum.join(alert.mitre_tactics, ", ")}\nTechniques: #{Enum.join(alert.mitre_techniques, ", ")}",
            wrap: true
          }
        ]
    else
      body
    end
  end

  defp alert_style("critical"), do: "attention"
  defp alert_style("high"), do: "warning"
  defp alert_style(_), do: "default"

  defp build_triage_confirmation_card(alert_id, action, user_id) do
    %{
      type: "AdaptiveCard",
      version: "1.4",
      body: [
        %{
          type: "TextBlock",
          text: "✅ Alert #{String.capitalize(action)}d",
          weight: "Bolder",
          size: "Large",
          color: "Good"
        },
        %{
          type: "TextBlock",
          text: "Alert #{alert_id} has been #{action}d by user #{user_id}",
          wrap: true
        }
      ]
    }
  end

  defp build_remediation_confirmation_card(action_id, status, user_id) do
    %{
      type: "AdaptiveCard",
      version: "1.4",
      body: [
        %{
          type: "TextBlock",
          text: if(status == "approved", do: "✅ Action Approved", else: "❌ Action Denied"),
          weight: "Bolder",
          size: "Large",
          color: if(status == "approved", do: "Good", else: "Attention")
        },
        %{
          type: "TextBlock",
          text: "Remediation action #{action_id} was #{status} by user #{user_id}",
          wrap: true
        }
      ]
    }
  end

  defp build_error_card(reason) do
    %{
      type: "AdaptiveCard",
      version: "1.4",
      body: [
        %{
          type: "TextBlock",
          text: "❌ Error",
          weight: "Bolder",
          color: "Attention"
        },
        %{
          type: "TextBlock",
          text: reason,
          wrap: true
        }
      ]
    }
  end

  defp build_digest_card(stats, period) do
    period_text = String.capitalize(period)

    %{
      type: "AdaptiveCard",
      version: "1.4",
      body: [
        %{
          type: "TextBlock",
          text: "📊 Tamandua EDR #{period_text} Digest",
          size: "Large",
          weight: "Bolder"
        },
        %{
          type: "TextBlock",
          text: "Alert Summary",
          weight: "Bolder"
        },
        %{
          type: "ColumnSet",
          columns: [
            %{
              type: "Column",
              width: "stretch",
              items: [
                %{type: "TextBlock", text: "New Alerts", weight: "Bolder"},
                %{type: "TextBlock", text: "#{stats.new_alerts}", size: "Large"}
              ]
            },
            %{
              type: "Column",
              width: "stretch",
              items: [
                %{type: "TextBlock", text: "Resolved", weight: "Bolder"},
                %{type: "TextBlock", text: "#{stats.resolved}", size: "Large"}
              ]
            }
          ]
        },
        %{
          type: "FactSet",
          facts: [
            %{title: "🔴 Critical", value: "#{stats.critical}"},
            %{title: "🟠 High", value: "#{stats.high}"},
            %{title: "🟡 Medium", value: "#{stats.medium}"},
            %{title: "🟢 Low", value: "#{stats.low}"}
          ]
        },
        %{type: "TextBlock", text: "Agent Health", weight: "Bolder"},
        %{
          type: "FactSet",
          facts: [
            %{title: "Total Agents", value: "#{stats.agents_total}"},
            %{title: "Online", value: "#{stats.agents_online}"},
            %{title: "Offline", value: "#{stats.agents_total - stats.agents_online}"}
          ]
        }
      ]
    }
  end

  # ==========================================================================
  # Message Building
  # ==========================================================================

  defp build_reply(activity, %{card: card}) do
    %{
      type: "message",
      from: activity["recipient"],
      recipient: activity["from"],
      replyToId: activity["id"],
      conversation: activity["conversation"],
      attachments: [
        %{
          contentType: "application/vnd.microsoft.card.adaptive",
          content: card
        }
      ]
    }
  end

  defp build_reply(activity, %{text: text}) do
    %{
      type: "message",
      from: activity["recipient"],
      recipient: activity["from"],
      replyToId: activity["id"],
      conversation: activity["conversation"],
      text: text
    }
  end

  defp build_error_reply(activity, reason) do
    %{
      type: "message",
      from: activity["recipient"],
      recipient: activity["from"],
      replyToId: activity["id"],
      conversation: activity["conversation"],
      text: "❌ Error: #{reason}"
    }
  end

  defp build_card_reply(activity, card) do
    %{
      type: "message",
      from: activity["recipient"],
      recipient: activity["from"],
      replyToId: activity["id"],
      conversation: activity["conversation"],
      attachments: [
        %{
          contentType: "application/vnd.microsoft.card.adaptive",
          content: card
        }
      ]
    }
  end

  # ==========================================================================
  # Digest Reports
  # ==========================================================================

  defp send_digest_report(org_id, period, state) do
    with {:ok, team_config} <- get_team_for_org(org_id, state),
         true <- team_config.enabled do
      stats = gather_digest_stats(org_id, period)
      card = build_digest_card(stats, period)

      if team_config.webhook_url do
        send_webhook_message(team_config.webhook_url, %{attachments: [%{contentType: "application/vnd.microsoft.card.adaptive", content: card}]})
      else
        send_proactive_message(team_config, card, state)
      end
    else
      {:error, :not_found} ->
        {:error, :team_not_configured}

      false ->
        {:error, :team_disabled}
    end
  end

  defp gather_digest_stats(org_id, period) do
    hours =
      case period do
        "daily" -> 24
        "weekly" -> 168
      end

    _start_time = DateTime.utc_now() |> DateTime.add(-hours * 3600, :second)

    %{
      new_alerts: 0,
      resolved: 0,
      critical: Alerts.count_by_severity_for_org(org_id, "critical"),
      high: Alerts.count_by_severity_for_org(org_id, "high"),
      medium: Alerts.count_by_severity_for_org(org_id, "medium"),
      low: Alerts.count_by_severity_for_org(org_id, "low"),
      agents_total: TamanduaServer.Agents.count_agents_for_org(org_id),
      agents_online: TamanduaServer.Agents.count_online_for_org(org_id),
      period: period
    }
  end

  # ==========================================================================
  # Teams API Integration
  # ==========================================================================

  defp send_activity(activity, state) do
    # Ensure we have a valid token
    state = ensure_valid_token(state)

    service_url = activity["conversation"]["serviceUrl"] || @bot_framework_api
    conversation_id = activity["conversation"]["id"]
    url = "#{service_url}/v3/conversations/#{conversation_id}/activities"

    headers = [
      {"Authorization", "Bearer #{state.access_token}"},
      {"Content-Type", "application/json"}
    ]

    body = Jason.encode!(activity)

    case HTTPoison.post(url, body, headers) do
      {:ok, %{status_code: status_code, body: response_body}} when status_code in 200..299 ->
        {:ok, Jason.decode!(response_body)}

      {:ok, %{status_code: status_code, body: body}} ->
        Logger.error("Teams API error: #{status_code} - #{body}")
        {:error, {:api_error, status_code}}

      {:error, reason} ->
        Logger.error("HTTP error sending to Teams: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp update_activity(activity_id, card, activity, state) do
    state = ensure_valid_token(state)

    service_url = get_in(activity, ["conversation", "serviceUrl"]) || @bot_framework_api
    conversation_id = get_in(activity, ["conversation", "id"])

    if activity_id && conversation_id do
      url = "#{service_url}/v3/conversations/#{conversation_id}/activities/#{activity_id}"

      headers = [
        {"Authorization", "Bearer #{state.access_token}"},
        {"Content-Type", "application/json"}
      ]

      body = Jason.encode!(%{
        type: "message",
        attachments: [
          %{
            contentType: "application/vnd.microsoft.card.adaptive",
            content: card
          }
        ]
      })

      case HTTPoison.put(url, body, headers) do
        {:ok, %{status_code: code}} when code in 200..299 ->
          {:ok, %{}}

        {:ok, %{status_code: code, body: resp_body}} ->
          Logger.error("Teams update activity error: #{code} - #{resp_body}")
          {:error, {:api_error, code}}

        {:error, reason} ->
          {:error, reason}
      end
    else
      Logger.warning("Cannot update activity: missing activity_id or conversation_id")
      {:error, :missing_ids}
    end
  end

  defp send_webhook_message(webhook_url, message) do
    headers = [{"Content-Type", "application/json"}]
    body = Jason.encode!(message)

    case HTTPoison.post(webhook_url, body, headers) do
      {:ok, %{status_code: 200}} ->
        {:ok, %{}}

      {:ok, %{status_code: status_code, body: body}} ->
        Logger.error("Webhook error: #{status_code} - #{body}")
        {:error, {:webhook_error, status_code}}

      {:error, reason} ->
        Logger.error("HTTP error sending webhook: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp send_proactive_message(team_config, card, state) do
    alias TamanduaServer.Integrations.Chat.TeamsConfig

    # Try to get conversation reference from database config
    db_config = TeamsConfig.get_for_team_id(team_config.team_id)
    conv_ref = db_config && db_config.conversation_reference

    case conv_ref do
      nil ->
        Logger.warning("No conversation reference for proactive message to team: #{team_config.team_id}")
        {:error, :no_conversation_reference}

      conv_ref when is_map(conv_ref) ->
        state = ensure_valid_token(state)

        service_url = conv_ref["serviceUrl"] || @bot_framework_api
        conversation_id = conv_ref["conversation"]["id"]

        url = "#{service_url}/v3/conversations/#{conversation_id}/activities"

        headers = [
          {"Authorization", "Bearer #{state.access_token}"},
          {"Content-Type", "application/json"}
        ]

        body = Jason.encode!(%{
          type: "message",
          from: conv_ref["bot"],
          recipient: conv_ref["user"],
          conversation: conv_ref["conversation"],
          attachments: [
            %{
              contentType: "application/vnd.microsoft.card.adaptive",
              content: card
            }
          ]
        })

        case HTTPoison.post(url, body, headers) do
          {:ok, %{status_code: code, body: resp_body}} when code in 200..299 ->
            {:ok, Jason.decode!(resp_body)}

          {:ok, %{status_code: code, body: resp_body}} ->
            Logger.error("Teams proactive message error: #{code} - #{resp_body}")
            {:error, {:api_error, code}}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  # ==========================================================================
  # Authentication
  # ==========================================================================

  defp refresh_access_token(state) do
    url = "https://login.microsoftonline.com/#{state.tenant_id}/oauth2/v2.0/token"

    body =
      URI.encode_query(%{
        grant_type: "client_credentials",
        client_id: state.app_id,
        client_secret: state.app_password,
        scope: "https://api.botframework.com/.default"
      })

    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case HTTPoison.post(url, body, headers) do
      {:ok, %{status_code: 200, body: response_body}} ->
        response = Jason.decode!(response_body)
        expires_in = response["expires_in"]
        expires_at = DateTime.utc_now() |> DateTime.add(expires_in - 300, :second)

        state = %{
          state
          | access_token: response["access_token"],
            token_expires_at: expires_at
        }

        {:ok, state}

      {:ok, %{status_code: status_code, body: body}} ->
        Logger.error("Token refresh error: #{status_code} - #{body}")
        {:error, {:token_error, status_code}}

      {:error, reason} ->
        Logger.error("HTTP error refreshing token: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp ensure_valid_token(state) do
    now = DateTime.utc_now()

    if state.token_expires_at && DateTime.compare(now, state.token_expires_at) == :lt do
      state
    else
      case refresh_access_token(state) do
        {:ok, new_state} -> new_state
        {:error, _reason} -> state
      end
    end
  end

  # ==========================================================================
  # Team Configuration
  # ==========================================================================

  defp get_team_config(team_id, state) do
    case Map.get(state.team_configs, team_id) do
      nil -> {:error, :team_not_configured}
      config -> {:ok, config}
    end
  end

  defp get_team_for_org(org_id, state) do
    team =
      Enum.find_value(state.team_configs, fn {_team_id, config} ->
        if config.organization_id == org_id, do: config
      end)

    case team do
      nil -> {:error, :not_found}
      config -> {:ok, config}
    end
  end

  defp load_team_configs do
    alias TamanduaServer.Integrations.Chat.TeamsConfig

    TeamsConfig.list_enabled()
    |> Enum.map(fn config ->
      team_config = %TeamConfig{
        team_id: config.team_id,
        organization_id: config.organization_id,
        alert_channel_id: config.alert_channel_id,
        escalation_channel_id: config.escalation_channel_id,
        notification_rules: config.notification_rules || %{},
        digest_schedule: config.digest_schedule || %{daily: true, weekly: true},
        webhook_url: config.webhook_url,
        enabled: config.enabled
      }
      {config.team_id, team_config}
    end)
    |> Map.new()
  rescue
    _ ->
      # Database may not be ready during startup
      Logger.debug("[TeamsBot] Could not load team configs from database")
      %{}
  end

  defp save_team_config(config) do
    alias TamanduaServer.Integrations.Chat.TeamsConfig

    case TeamsConfig.get_for_team_id(config.team_id) do
      nil ->
        TeamsConfig.create_config(%{
          team_id: config.team_id,
          organization_id: config.organization_id,
          alert_channel_id: config.alert_channel_id,
          escalation_channel_id: config.escalation_channel_id,
          notification_rules: config.notification_rules,
          digest_schedule: config.digest_schedule,
          webhook_url: config.webhook_url,
          enabled: config.enabled
        })

      existing ->
        TeamsConfig.update_config(existing, %{
          alert_channel_id: config.alert_channel_id,
          escalation_channel_id: config.escalation_channel_id,
          notification_rules: config.notification_rules,
          digest_schedule: config.digest_schedule,
          webhook_url: config.webhook_url,
          enabled: config.enabled
        })
    end
  end

  defp store_conversation_reference(team_id, conv_ref) do
    alias TamanduaServer.Integrations.Chat.TeamsConfig

    case TeamsConfig.get_for_team_id(team_id) do
      nil -> :ok
      config -> TeamsConfig.update_conversation_reference(config, conv_ref)
    end
  end

  @doc """
  Send a proactive message to a specific channel.

  Used by ChatRouter for approval notifications.
  """
  @spec send_proactive(binary(), String.t(), map()) :: {:ok, map()} | {:error, term()}
  def send_proactive(_org_id, _channel_id, card) do
    GenServer.call(__MODULE__, {:send_proactive, card}, 30_000)
  catch
    :exit, {:noproc, _} ->
      {:error, :not_started}
  end
end
