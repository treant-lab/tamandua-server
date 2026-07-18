defmodule TamanduaServer.Integrations.BotCommands do
  @moduledoc """
  Shared command processing logic for Slack and Teams bots.

  Handles command parsing, authorization, and execution for both platforms.
  Supports:
  - Alert management (list, show, triage)
  - Agent operations (list, status, isolate)
  - Threat hunting (execute saved hunts)
  - Threat intelligence lookups
  - Remediation actions
  - SOC metrics and statistics

  ## Command Authorization

  All commands check user permissions via RBAC before execution.
  Organization context is derived from the workspace/team.
  """

  require Logger
  alias TamanduaServer.{Alerts, Accounts}

  # ==========================================================================
  # Command Dispatcher
  # ==========================================================================

  @doc """
  Process a bot command and return a response.

  ## Parameters
  - `command` - Command name (e.g., "alerts", "hunt", "ti")
  - `args` - Command arguments as string
  - `user_id` - Platform-specific user ID
  - `organization_id` - Organization UUID
  - `platform` - :slack or :teams

  ## Returns
  `{:ok, response_data}` or `{:error, reason}`
  """
  @spec process_command(String.t(), String.t(), String.t(), binary(), atom()) ::
          {:ok, map()} | {:error, String.t()}
  def process_command(command, args, user_id, organization_id, platform) do
    with {:ok, user} <- get_user(user_id, organization_id, platform),
         :ok <- authorize_command(user, command, args, platform) do
      execute_command(command, args, user, organization_id, platform)
    else
      {:error, :user_not_found} ->
        {:error, "User not found or not linked to Tamandua account"}

      {:error, :unauthorized} ->
        {:error, "You don't have permission to execute this command"}

      error ->
        Logger.error("Command processing error: #{inspect(error)}")
        {:error, "An error occurred processing your command"}
    end
  end

  # ==========================================================================
  # Alert Commands
  # ==========================================================================

  defp execute_command("alerts", args, user, org_id, platform) do
    case parse_alert_command(args) do
      {:list, filters} ->
        list_alerts(org_id, filters, platform)

      {:show, alert_id} ->
        show_alert(org_id, alert_id, platform)

      {:triage, alert_id, action} ->
        triage_alert(org_id, alert_id, action, user, platform)

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ==========================================================================
  # Agent Commands
  # ==========================================================================

  defp execute_command("agents", args, user, org_id, platform) do
    case parse_agent_command(args) do
      {:list, filters} ->
        list_agents(org_id, filters, platform)

      {:status, agent_id} ->
        show_agent_status(org_id, agent_id, platform)

      {:isolate, agent_id} ->
        isolate_agent(org_id, agent_id, user, platform)

      {:unisolate, agent_id} ->
        unisolate_agent(org_id, agent_id, user, platform)

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ==========================================================================
  # Hunt Commands
  # ==========================================================================

  defp execute_command("hunt", args, user, org_id, platform) do
    case parse_hunt_command(args) do
      {:execute, hunt_name} ->
        execute_hunt(org_id, hunt_name, user, platform)

      {:list} ->
        list_hunts(org_id, platform)

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ==========================================================================
  # Threat Intelligence Commands
  # ==========================================================================

  defp execute_command("ti", args, _user, org_id, platform) do
    case parse_ti_command(args) do
      {:lookup, ioc_type, ioc_value} ->
        lookup_threat_intel(org_id, ioc_type, ioc_value, platform)

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ==========================================================================
  # Remediation Commands
  # ==========================================================================

  defp execute_command("remediate", args, user, org_id, platform) do
    case parse_remediate_command(args) do
      {:kill_process, agent_id, pid} ->
        kill_process(org_id, agent_id, pid, user, platform)

      {:quarantine, agent_id, file_path} ->
        quarantine_file(org_id, agent_id, file_path, user, platform)

      {:block_ip, ip_address} ->
        block_ip(org_id, ip_address, user, platform)

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ==========================================================================
  # Stats Commands
  # ==========================================================================

  defp execute_command("stats", _args, _user, org_id, platform) do
    get_soc_stats(org_id, platform)
  end

  # ==========================================================================
  # Help Command
  # ==========================================================================

  defp execute_command("help", _args, _user, _org_id, platform) do
    get_help(platform)
  end

  # Unknown command
  defp execute_command(command, _args, _user, _org_id, _platform) do
    {:error, "Unknown command: #{command}. Type 'help' for available commands."}
  end

  # ==========================================================================
  # Command Parsers
  # ==========================================================================

  defp parse_alert_command(args) do
    tokens = String.split(String.trim(args), " ", parts: 3)

    case tokens do
      [] -> {:list, %{}}
      ["list"] -> {:list, %{}}
      ["list", "severity=" <> severity] -> {:list, %{severity: severity}}
      ["list", "status=" <> status] -> {:list, %{status: status}}
      ["show", alert_id] -> {:show, alert_id}
      ["triage", alert_id, action] when action in ["approve", "dismiss", "escalate"] ->
        {:triage, alert_id, action}
      _ -> {:error, "Invalid alert command. Usage: alerts [list|show|triage] [options]"}
    end
  end

  defp parse_agent_command(args) do
    tokens = String.split(String.trim(args), " ", parts: 2)

    case tokens do
      [] -> {:list, %{}}
      ["list"] -> {:list, %{}}
      ["list", "status=" <> status] -> {:list, %{status: status}}
      ["status", agent_id] -> {:status, agent_id}
      ["isolate", agent_id] -> {:isolate, agent_id}
      ["unisolate", agent_id] -> {:unisolate, agent_id}
      _ -> {:error, "Invalid agent command. Usage: agents [list|status|isolate|unisolate] [options]"}
    end
  end

  defp parse_hunt_command(args) do
    tokens = String.split(String.trim(args), " ", parts: 2)

    case tokens do
      [] -> {:list}
      ["list"] -> {:list}
      [hunt_name] -> {:execute, hunt_name}
      _ -> {:error, "Invalid hunt command. Usage: hunt [hunt_name] or hunt list"}
    end
  end

  defp parse_ti_command(args) do
    tokens = String.split(String.trim(args), " ", parts: 2)

    case tokens do
      [value] -> detect_ioc_type(value)
      _ -> {:error, "Invalid TI command. Usage: ti <IP|hash|domain>"}
    end
  end

  defp detect_ioc_type(value) do
    cond do
      # IPv4 pattern
      Regex.match?(~r/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, value) ->
        {:lookup, :ip, value}

      # MD5 hash
      Regex.match?(~r/^[a-fA-F0-9]{32}$/, value) ->
        {:lookup, :md5, value}

      # SHA1 hash
      Regex.match?(~r/^[a-fA-F0-9]{40}$/, value) ->
        {:lookup, :sha1, value}

      # SHA256 hash
      Regex.match?(~r/^[a-fA-F0-9]{64}$/, value) ->
        {:lookup, :sha256, value}

      # Domain pattern
      Regex.match?(~r/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, value) ->
        {:lookup, :domain, value}

      true ->
        {:error, "Unable to detect IOC type for: #{value}"}
    end
  end

  defp parse_remediate_command(args) do
    tokens = String.split(String.trim(args), " ", parts: 3)

    case tokens do
      ["kill", agent_id, pid] -> {:kill_process, agent_id, String.to_integer(pid)}
      ["quarantine", agent_id, file_path] -> {:quarantine, agent_id, file_path}
      ["block", ip] -> {:block_ip, ip}
      _ -> {:error, "Invalid remediate command. Usage: remediate [kill|quarantine|block] <args>"}
    end
  end

  # ==========================================================================
  # Alert Operations
  # ==========================================================================

  defp list_alerts(org_id, filters, platform) do
    opts = [limit: 10] ++ Map.to_list(filters)
    alerts = Alerts.list_alerts_for_org(org_id, opts)

    if platform == :slack do
      format_alerts_slack(alerts)
    else
      format_alerts_teams(alerts)
    end
  end

  defp show_alert(org_id, alert_id, platform) do
    case Alerts.get_alert_for_org(org_id, alert_id) do
      {:ok, alert} ->
        alert = TamanduaServer.Repo.preload(alert, [:agent, :assigned_to])

        if platform == :slack do
          format_alert_detail_slack(alert)
        else
          format_alert_detail_teams(alert)
        end

      {:error, :not_found} ->
        {:error, "Alert not found"}
    end
  end

  defp triage_alert(org_id, alert_id, action, user, platform) do
    with {:ok, alert} <- Alerts.get_alert_for_org(org_id, alert_id) do
      result =
        case action do
          "approve" ->
            Alerts.update_alert(alert, %{
              verdict: "true_positive",
              verdict_by_id: user.id,
              verdict_at: DateTime.utc_now()
            })

          "dismiss" ->
            Alerts.update_alert(alert, %{
              verdict: "false_positive",
              verdict_by_id: user.id,
              verdict_at: DateTime.utc_now(),
              status: "resolved"
            })

          "escalate" ->
            TamanduaServer.Alerts.EscalationEngine.escalate_alert(alert,
              escalated_by_id: user.id,
              reason: "Escalated via #{platform} bot"
            )
        end

      case result do
        {:ok, _updated_alert} ->
          {:ok,
           %{
             text: "Alert #{alert_id} #{action}d successfully",
             alert_id: alert_id,
             action: action
           }}

        {:error, reason} ->
          {:error, "Failed to #{action} alert: #{inspect(reason)}"}
      end
    end
  end

  # ==========================================================================
  # Agent Operations
  # ==========================================================================

  defp list_agents(org_id, filters, platform) do
    # DB-backed inventory (includes offline agents); Agent.status is a string,
    # matching the "status=<value>" filter parsed from the chat command.
    agents = TamanduaServer.Agents.list_agents_for_org(org_id)

    filtered_agents =
      if status = Map.get(filters, :status) do
        Enum.filter(agents, fn agent -> agent.status == status end)
      else
        agents
      end

    if platform == :slack do
      format_agents_slack(filtered_agents)
    else
      format_agents_teams(filtered_agents)
    end
  end

  defp show_agent_status(org_id, agent_id, platform) do
    case TamanduaServer.Agents.get_agent_for_org(org_id, agent_id) do
      {:error, :not_found} ->
        {:error, "Agent not found"}

      {:ok, agent} ->
        health =
          case TamanduaServer.Agents.HealthMonitor.get_agent_health(agent_id) do
            {:ok, health} -> health
            _ -> nil
          end

        if platform == :slack do
          format_agent_status_slack(agent, health)
        else
          format_agent_status_teams(agent, health)
        end
    end
  end

  defp isolate_agent(org_id, agent_id, user, _platform) do
    case TamanduaServer.Response.Executor.isolate_network(agent_id,
           actor: %{organization_id: org_id, user_id: user.id}
         ) do
      {:ok, _command} ->
        {:ok, %{text: "Agent #{agent_id} isolated successfully"}}

      {:error, reason} ->
        {:error, "Failed to isolate agent: #{inspect(reason)}"}
    end
  end

  defp unisolate_agent(org_id, agent_id, user, _platform) do
    case TamanduaServer.Response.Executor.unisolate_network(agent_id,
           actor: %{organization_id: org_id, user_id: user.id}
         ) do
      {:ok, _command} ->
        {:ok, %{text: "Agent #{agent_id} unisolated successfully"}}

      {:error, reason} ->
        {:error, "Failed to unisolate agent: #{inspect(reason)}"}
    end
  end

  # ==========================================================================
  # Hunt Operations
  # ==========================================================================

  defp execute_hunt(_org_id, hunt_name, _user, _platform) do
    # TODO: Implement saved hunt execution
    {:ok,
     %{
       text: "Executing hunt: #{hunt_name}",
       hunt_name: hunt_name,
       status: "started"
     }}
  end

  defp list_hunts(_org_id, _platform) do
    # TODO: Implement saved hunts listing
    {:ok, %{text: "No saved hunts available", hunts: []}}
  end

  # ==========================================================================
  # Threat Intel Operations
  # ==========================================================================

  defp lookup_threat_intel(_org_id, ioc_type, ioc_value, platform) do
    # Detection.ThreatIntelCache is an Ecto schema (no lookup API); the live
    # IOC cache is TamanduaServer.ThreatIntel.lookup/2 (type-first).
    case TamanduaServer.ThreatIntel.lookup(threat_intel_type(ioc_type), ioc_value) do
      :not_found ->
        {:ok,
         %{
           text: "No threat intelligence found for #{ioc_value}",
           ioc_value: ioc_value,
           ioc_type: ioc_type,
           found: false
         }}

      {:ok, intel} ->
        if platform == :slack do
          format_threat_intel_slack(ioc_value, ioc_type, intel)
        else
          format_threat_intel_teams(ioc_value, ioc_type, intel)
        end
    end
  end

  # Map bot-detected IOC types onto ThreatIntel's indicator type atoms.
  defp threat_intel_type(:md5), do: :hash_md5
  defp threat_intel_type(:sha1), do: :hash_sha1
  defp threat_intel_type(:sha256), do: :hash_sha256
  defp threat_intel_type(type), do: type

  # ==========================================================================
  # Remediation Operations
  # ==========================================================================

  defp kill_process(org_id, agent_id, pid, user, _platform) do
    case TamanduaServer.Response.Executor.kill_process(agent_id, pid,
           actor: %{organization_id: org_id, user_id: user.id}
         ) do
      {:ok, _command} ->
        {:ok, %{text: "Process #{pid} on agent #{agent_id} terminated"}}

      {:error, reason} ->
        {:error, "Failed to kill process: #{inspect(reason)}"}
    end
  end

  defp quarantine_file(org_id, agent_id, file_path, user, _platform) do
    case TamanduaServer.Response.Executor.quarantine_file(agent_id, file_path,
           actor: %{organization_id: org_id, user_id: user.id}
         ) do
      {:ok, _command} ->
        {:ok, %{text: "File quarantined: #{file_path}"}}

      {:error, reason} ->
        {:error, "Failed to quarantine file: #{inspect(reason)}"}
    end
  end

  defp block_ip(_org_id, ip_address, _user, _platform) do
    # TODO: Implement IP blocking via firewall rules
    {:ok, %{text: "IP #{ip_address} blocked (feature in development)"}}
  end

  # ==========================================================================
  # Stats Operations
  # ==========================================================================

  defp get_soc_stats(org_id, platform) do
    stats = %{
      total_alerts: Alerts.count_alerts_for_org(org_id),
      active_alerts: Alerts.count_active_for_org(org_id),
      critical: Alerts.count_by_severity_for_org(org_id, "critical"),
      high: Alerts.count_by_severity_for_org(org_id, "high"),
      medium: Alerts.count_by_severity_for_org(org_id, "medium"),
      low: Alerts.count_by_severity_for_org(org_id, "low"),
      agents_online: TamanduaServer.Agents.count_online_for_org(org_id),
      agents_total: TamanduaServer.Agents.count_agents_for_org(org_id)
    }

    if platform == :slack do
      format_stats_slack(stats)
    else
      format_stats_teams(stats)
    end
  end

  # ==========================================================================
  # Help
  # ==========================================================================

  defp get_help(_platform) do
    help_text = """
    *Tamandua EDR Bot Commands*

    *Alerts*
    • `alerts list [severity=critical|high|medium|low]` - List recent alerts
    • `alerts show <alert_id>` - Show alert details
    • `alerts triage <alert_id> [approve|dismiss|escalate]` - Triage an alert

    *Agents*
    • `agents list [status=online|offline]` - List agents
    • `agents status <agent_id>` - Show agent status
    • `agents isolate <agent_id>` - Isolate an agent from network
    • `agents unisolate <agent_id>` - Remove agent isolation

    *Threat Hunting*
    • `hunt list` - List saved hunts
    • `hunt <hunt_name>` - Execute a saved hunt

    *Threat Intelligence*
    • `ti <IP|hash|domain>` - Lookup threat intelligence

    *Remediation*
    • `remediate kill <agent_id> <pid>` - Kill a process
    • `remediate quarantine <agent_id> <file_path>` - Quarantine a file
    • `remediate block <ip_address>` - Block an IP address

    *Other*
    • `stats` - Show SOC statistics
    • `help` - Show this help message
    """

    {:ok, %{text: help_text}}
  end

  # ==========================================================================
  # User Management
  # ==========================================================================

  defp get_user(platform_user_id, org_id, platform) do
    Logger.warning(
      "Bot command user mapping is not configured for platform=#{platform} user=#{platform_user_id} org=#{org_id}"
    )

    {:error, :user_not_found}
  end

  # ==========================================================================
  # Authorization (deny-by-default, RBAC-backed)
  # ==========================================================================
  #
  # Every bot command is mapped to the RBAC permission required to run it.
  # Authorization is delegated to the canonical RBAC engine
  # (`TamanduaServer.Accounts.user_can?/2` -> `Authorization.RBAC.can?/2`),
  # which is the single source of truth for "who is allowed to do what" across
  # the backend. We do NOT introduce a parallel allowlist here.
  #
  # Privilege classification:
  #   * Read-only / informational commands require a read-level permission that
  #     any authenticated analyst/viewer already holds.
  #   * State-changing commands (isolate, kill, quarantine, block-ip, execute
  #     hunt, triage) require operator/responder/admin level permissions.
  #
  # The mapping is keyed on `{command, subcommand}` because privilege differs
  # per subcommand (e.g. `alerts list` is read-only while `agents isolate` is a
  # containment action). Any command/subcommand not explicitly classified is
  # DENIED. `help` is the only unauthenticated-safe command.

  defp authorize_command(user, command, args, platform) do
    case required_permission(command, args) do
      :public ->
        :ok

      {:ok, permission} ->
        if Accounts.user_can?(user, permission) do
          :ok
        else
          log_denied(user, command, args, permission, platform)
          {:error, :unauthorized}
        end

      :deny ->
        # Unknown / unclassified command -> deny-by-default.
        log_denied(user, command, args, :unclassified, platform)
        {:error, :unauthorized}
    end
  end

  # Maps a command (and its first argument / subcommand) to the RBAC permission
  # required to execute it. Returns `:public` for the help command,
  # `{:ok, permission}` for a classified command, or `:deny` for anything
  # unrecognized (deny-by-default).
  defp required_permission(command, args) do
    sub = command_subaction(args)

    case {command, sub} do
      # --- Help: safe for any authenticated bot user ----------------------
      {"help", _} -> :public

      # --- Alerts ---------------------------------------------------------
      {"alerts", "list"} -> {:ok, :alerts_read}
      {"alerts", "show"} -> {:ok, :alerts_read}
      # `alerts` with no subcommand defaults to list (read-only).
      {"alerts", nil} -> {:ok, :alerts_read}
      # Triage mutates alert verdict/status -> requires update privilege.
      {"alerts", "triage"} -> {:ok, :alerts_update}

      # --- Agents ---------------------------------------------------------
      {"agents", "list"} -> {:ok, :agents_read}
      {"agents", "status"} -> {:ok, :agents_read}
      {"agents", nil} -> {:ok, :agents_read}
      # Network isolation / restoration are containment actions.
      {"agents", "isolate"} -> {:ok, :agents_isolate}
      {"agents", "unisolate"} -> {:ok, :agents_unisolate}

      # --- Threat hunting -------------------------------------------------
      {"hunt", "list"} -> {:ok, :hunting_read}
      {"hunt", nil} -> {:ok, :hunting_read}
      # Any other `hunt <name>` form executes a saved hunt.
      {"hunt", _} -> {:ok, :hunting_execute}

      # --- Threat intelligence (read-only lookups) ------------------------
      {"ti", _} -> {:ok, :threat_intel_read}

      # --- Remediation (state-changing response actions) ------------------
      {"remediate", "kill"} -> {:ok, :response_contain}
      {"remediate", "quarantine"} -> {:ok, :response_contain}
      {"remediate", "block"} -> {:ok, :response_execute}

      # --- SOC stats (read-only) ------------------------------------------
      {"stats", _} -> {:ok, :alerts_read}

      # --- Anything else: deny-by-default ---------------------------------
      _ -> :deny
    end
  end

  # Extracts the leading subcommand token from a raw args string, or nil when
  # there is no subcommand (empty args).
  defp command_subaction(args) when is_binary(args) do
    case args |> String.trim() |> String.split(~r/\s+/, parts: 2, trim: true) do
      [] -> nil
      [first | _] -> first
    end
  end

  defp command_subaction(_), do: nil

  defp log_denied(user, command, args, permission, platform) do
    Logger.warning(
      "Bot command authorization denied",
      event: "bot_command_unauthorized",
      platform: platform,
      command: command,
      subcommand: command_subaction(args),
      required_permission: permission,
      user_id: Map.get(user, :id),
      organization_id: Map.get(user, :organization_id)
    )
  end

  # ==========================================================================
  # Slack Formatters
  # ==========================================================================

  defp format_alerts_slack(alerts) do
    blocks = [
      %{
        type: "header",
        text: %{
          type: "plain_text",
          text: "Recent Alerts (#{length(alerts)})"
        }
      }
    ]

    alert_blocks =
      Enum.flat_map(alerts, fn alert ->
        [
          %{
            type: "section",
            text: %{
              type: "mrkdwn",
              text:
                "*#{severity_emoji(alert.severity)} #{alert.title}*\n" <>
                  "ID: `#{alert.id}` | Status: #{alert.status} | " <>
                  "Agent: #{alert.agent_id || "N/A"}"
            }
          },
          %{
            type: "actions",
            block_id: "alert_actions_#{alert.id}",
            elements: [
              %{
                type: "button",
                text: %{type: "plain_text", text: "Approve"},
                style: "primary",
                value: alert.id,
                action_id: "alert_approve"
              },
              %{
                type: "button",
                text: %{type: "plain_text", text: "Dismiss"},
                value: alert.id,
                action_id: "alert_dismiss"
              },
              %{
                type: "button",
                text: %{type: "plain_text", text: "Escalate"},
                style: "danger",
                value: alert.id,
                action_id: "alert_escalate"
              }
            ]
          },
          %{type: "divider"}
        ]
      end)

    {:ok, %{blocks: blocks ++ alert_blocks}}
  end

  defp format_alert_detail_slack(alert) do
    blocks = [
      %{
        type: "header",
        text: %{
          type: "plain_text",
          text: "#{severity_emoji(alert.severity)} #{alert.title}"
        }
      },
      %{
        type: "section",
        fields: [
          %{type: "mrkdwn", text: "*Alert ID:*\n`#{alert.id}`"},
          %{type: "mrkdwn", text: "*Severity:*\n#{alert.severity}"},
          %{type: "mrkdwn", text: "*Status:*\n#{alert.status}"},
          %{type: "mrkdwn", text: "*Agent:*\n#{alert.agent.hostname || "N/A"}"},
          %{
            type: "mrkdwn",
            text: "*Assigned To:*\n#{alert.assigned_to && alert.assigned_to.email || "Unassigned"}"
          },
          %{type: "mrkdwn", text: "*Created:*\n#{format_datetime(alert.inserted_at)}"}
        ]
      },
      %{
        type: "section",
        text: %{
          type: "mrkdwn",
          text: "*Description:*\n#{alert.description}"
        }
      }
    ]

    mitre_text =
      if length(alert.mitre_techniques) > 0 do
        tactics = Enum.join(alert.mitre_tactics, ", ")
        techniques = Enum.join(alert.mitre_techniques, ", ")
        "\n*MITRE ATT&CK:*\nTactics: #{tactics}\nTechniques: #{techniques}"
      else
        ""
      end

    blocks =
      if mitre_text != "" do
        blocks ++
          [
            %{
              type: "section",
              text: %{type: "mrkdwn", text: mitre_text}
            }
          ]
      else
        blocks
      end

    {:ok, %{blocks: blocks}}
  end

  defp format_agents_slack(agents) do
    blocks = [
      %{
        type: "header",
        text: %{
          type: "plain_text",
          text: "Agents (#{length(agents)})"
        }
      }
    ]

    agent_blocks =
      Enum.map(agents, fn agent ->
        %{
          type: "section",
          text: %{
            type: "mrkdwn",
            text:
              "*#{agent.hostname}*\n" <>
                "ID: `#{agent.id}` | OS: #{agent.os_type} | " <>
                "Status: #{status_emoji(agent.status)} #{agent.status}"
          }
        }
      end)

    {:ok, %{blocks: blocks ++ agent_blocks}}
  end

  defp format_agent_status_slack(agent, health) do
    health_score = (health && Map.get(health, :health_score)) || 0
    health_status = if health_score > 80, do: "Healthy", else: "Degraded"

    blocks = [
      %{
        type: "header",
        text: %{
          type: "plain_text",
          text: "Agent: #{agent.hostname}"
        }
      },
      %{
        type: "section",
        fields: [
          %{type: "mrkdwn", text: "*Agent ID:*\n`#{agent.id}`"},
          %{type: "mrkdwn", text: "*Hostname:*\n#{agent.hostname}"},
          %{type: "mrkdwn", text: "*OS:*\n#{agent.os_type} #{agent.os_version}"},
          %{type: "mrkdwn", text: "*Status:*\n#{status_emoji(agent.status)} #{agent.status}"},
          %{type: "mrkdwn", text: "*Health Score:*\n#{health_score}/100"},
          %{type: "mrkdwn", text: "*Health Status:*\n#{health_status}"},
          %{type: "mrkdwn", text: "*Last Seen:*\n#{format_datetime(agent.last_seen_at)}"},
          %{type: "mrkdwn", text: "*IP Address:*\n#{agent.ip_address || "N/A"}"}
        ]
      }
    ]

    {:ok, %{blocks: blocks}}
  end

  defp format_threat_intel_slack(ioc_value, ioc_type, intel) do
    blocks = [
      %{
        type: "header",
        text: %{
          type: "plain_text",
          text: "Threat Intelligence Lookup"
        }
      },
      %{
        type: "section",
        fields: [
          %{type: "mrkdwn", text: "*IOC:*\n`#{ioc_value}`"},
          %{type: "mrkdwn", text: "*Type:*\n#{ioc_type}"},
          %{type: "mrkdwn", text: "*Severity:*\n#{intel.severity || "Unknown"}"},
          %{type: "mrkdwn", text: "*Source:*\n#{intel.source || "Unknown"}"}
        ]
      }
    ]

    blocks =
      if intel.description do
        blocks ++
          [
            %{
              type: "section",
              text: %{
                type: "mrkdwn",
                text: "*Description:*\n#{intel.description}"
              }
            }
          ]
      else
        blocks
      end

    {:ok, %{blocks: blocks}}
  end

  defp format_stats_slack(stats) do
    blocks = [
      %{
        type: "header",
        text: %{
          type: "plain_text",
          text: "SOC Dashboard"
        }
      },
      %{
        type: "section",
        fields: [
          %{type: "mrkdwn", text: "*Total Alerts:*\n#{stats.total_alerts}"},
          %{type: "mrkdwn", text: "*Active Alerts:*\n#{stats.active_alerts}"},
          %{type: "mrkdwn", text: "*Critical:*\n🔴 #{stats.critical}"},
          %{type: "mrkdwn", text: "*High:*\n🟠 #{stats.high}"},
          %{type: "mrkdwn", text: "*Medium:*\n🟡 #{stats.medium}"},
          %{type: "mrkdwn", text: "*Low:*\n🟢 #{stats.low}"},
          %{type: "mrkdwn", text: "*Agents Online:*\n#{stats.agents_online}"},
          %{type: "mrkdwn", text: "*Total Agents:*\n#{stats.agents_total}"}
        ]
      }
    ]

    {:ok, %{blocks: blocks}}
  end

  # ==========================================================================
  # Teams Formatters (Adaptive Cards)
  # ==========================================================================

  defp format_alerts_teams(alerts) do
    card = %{
      type: "AdaptiveCard",
      version: "1.4",
      body: [
        %{
          type: "TextBlock",
          text: "Recent Alerts (#{length(alerts)})",
          size: "Large",
          weight: "Bolder"
        }
        | Enum.map(alerts, fn alert ->
            %{
              type: "Container",
              items: [
                %{
                  type: "TextBlock",
                  text: "#{severity_emoji(alert.severity)} #{alert.title}",
                  weight: "Bolder",
                  wrap: true
                },
                %{
                  type: "TextBlock",
                  text: "ID: #{alert.id} | Status: #{alert.status}",
                  isSubtle: true,
                  wrap: true
                }
              ],
              separator: true
            }
          end)
      ]
    }

    {:ok, %{card: card}}
  end

  defp format_alert_detail_teams(alert) do
    card = %{
      type: "AdaptiveCard",
      version: "1.4",
      body: [
        %{
          type: "TextBlock",
          text: "#{severity_emoji(alert.severity)} #{alert.title}",
          size: "Large",
          weight: "Bolder",
          wrap: true
        },
        %{
          type: "FactSet",
          facts: [
            %{title: "Alert ID", value: alert.id},
            %{title: "Severity", value: alert.severity},
            %{title: "Status", value: alert.status},
            %{title: "Agent", value: alert.agent.hostname || "N/A"},
            %{title: "Created", value: format_datetime(alert.inserted_at)}
          ]
        },
        %{
          type: "TextBlock",
          text: alert.description,
          wrap: true
        }
      ]
    }

    {:ok, %{card: card}}
  end

  defp format_agents_teams(agents) do
    card = %{
      type: "AdaptiveCard",
      version: "1.4",
      body: [
        %{
          type: "TextBlock",
          text: "Agents (#{length(agents)})",
          size: "Large",
          weight: "Bolder"
        }
        | Enum.map(agents, fn agent ->
            %{
              type: "Container",
              items: [
                %{
                  type: "TextBlock",
                  text: agent.hostname,
                  weight: "Bolder"
                },
                %{
                  type: "TextBlock",
                  text: "#{agent.os_type} | #{status_emoji(agent.status)} #{agent.status}",
                  isSubtle: true
                }
              ],
              separator: true
            }
          end)
      ]
    }

    {:ok, %{card: card}}
  end

  defp format_agent_status_teams(agent, health) do
    health_score = (health && Map.get(health, :health_score)) || 0

    card = %{
      type: "AdaptiveCard",
      version: "1.4",
      body: [
        %{
          type: "TextBlock",
          text: "Agent: #{agent.hostname}",
          size: "Large",
          weight: "Bolder"
        },
        %{
          type: "FactSet",
          facts: [
            %{title: "Agent ID", value: agent.id},
            %{title: "OS", value: "#{agent.os_type} #{agent.os_version}"},
            %{title: "Status", value: "#{status_emoji(agent.status)} #{agent.status}"},
            %{title: "Health Score", value: "#{health_score}/100"},
            %{title: "Last Seen", value: format_datetime(agent.last_seen_at)}
          ]
        }
      ]
    }

    {:ok, %{card: card}}
  end

  defp format_threat_intel_teams(ioc_value, ioc_type, intel) do
    card = %{
      type: "AdaptiveCard",
      version: "1.4",
      body: [
        %{
          type: "TextBlock",
          text: "Threat Intelligence Lookup",
          size: "Large",
          weight: "Bolder"
        },
        %{
          type: "FactSet",
          facts: [
            %{title: "IOC", value: ioc_value},
            %{title: "Type", value: to_string(ioc_type)},
            %{title: "Severity", value: intel.severity || "Unknown"},
            %{title: "Source", value: intel.source || "Unknown"}
          ]
        }
      ]
    }

    {:ok, %{card: card}}
  end

  defp format_stats_teams(stats) do
    card = %{
      type: "AdaptiveCard",
      version: "1.4",
      body: [
        %{
          type: "TextBlock",
          text: "SOC Dashboard",
          size: "Large",
          weight: "Bolder"
        },
        %{
          type: "ColumnSet",
          columns: [
            %{
              type: "Column",
              width: "stretch",
              items: [
                %{type: "TextBlock", text: "Total Alerts", weight: "Bolder"},
                %{type: "TextBlock", text: "#{stats.total_alerts}", size: "Large"}
              ]
            },
            %{
              type: "Column",
              width: "stretch",
              items: [
                %{type: "TextBlock", text: "Active Alerts", weight: "Bolder"},
                %{type: "TextBlock", text: "#{stats.active_alerts}", size: "Large"}
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
            %{title: "🟢 Low", value: "#{stats.low}"},
            %{title: "Agents Online", value: "#{stats.agents_online}/#{stats.agents_total}"}
          ]
        }
      ]
    }

    {:ok, %{card: card}}
  end

  # ==========================================================================
  # Helpers
  # ==========================================================================

  defp severity_emoji("critical"), do: "🔴"
  defp severity_emoji("high"), do: "🟠"
  defp severity_emoji("medium"), do: "🟡"
  defp severity_emoji("low"), do: "🟢"
  defp severity_emoji("info"), do: "🔵"
  defp severity_emoji(_), do: "⚪"

  defp status_emoji("online"), do: "🟢"
  defp status_emoji("offline"), do: "🔴"
  defp status_emoji("isolated"), do: "🔒"
  defp status_emoji(_), do: "⚪"

  defp format_datetime(nil), do: "N/A"

  defp format_datetime(datetime) do
    Calendar.strftime(datetime, "%Y-%m-%d %H:%M:%S UTC")
  end
end
