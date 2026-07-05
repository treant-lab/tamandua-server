defmodule TamanduaServer.Supervisors.IntegrationsSupervisor do
  @moduledoc """
  Peripheral supervision group: outbound/inbound third-party integrations
  (SIEM, SOAR, ticketing, chat bots, webhooks).

  Alert persistence does not depend on these children:
  `TamanduaServer.Alerts.Notifier` dispatches to TicketingRouter/ChatRouter
  via fire-and-forget `Task.start` wrapped in try/rescue, so a dead router
  degrades to a logged warning. `TamanduaServer.Notifications.Throttler` and
  `TamanduaServer.NotificationCenter.EscalationManager` intentionally stay at
  the top level (notification rate limiting / SLA escalation for alerts).

  Crash containment: a flapping connector (e.g. unreachable Jira/Slack/SIEM)
  consumes THIS group's restart budget (max_restarts: 10 / 60s) instead of
  the application-wide budget. If the group itself exceeds its budget and
  dies, the top-level supervisor restarts the whole group, which counts as
  ONE restart against the top-level budget — so a flapping cloud connector
  can no longer exhaust the shared budget and take down agent
  ingest/detection.

  Children and their relative start order are moved verbatim from
  `TamanduaServer.Application` (including the pre-existing ordering of
  IntegrationLog relative to the other integrations); this module changes
  fault isolation only, not behavior.
  """

  use Supervisor

  def start_link(init_arg) do
    Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  @impl true
  def init(_init_arg) do
    Supervisor.init(children(), strategy: :one_for_one, max_restarts: 10, max_seconds: 60)
  end

  @doc "Child specs for this group (also asserted by tests)."
  def children do
    [
      # Integration Services
      TamanduaServer.Integrations.MCPServer,
      TamanduaServer.Integrations.CollaborationSecurity,
      TamanduaServer.Integrations.AISIEM,
      TamanduaServer.Integrations.SIEM,

      # Integration Logging (ETS-backed, must start before integrations)
      TamanduaServer.Integrations.IntegrationLog,

      # Ticketing Integration Router (Jira, ServiceNow dispatch with deduplication)
      TamanduaServer.Integrations.TicketingRouter,

      # Chat Integration Router (Slack, Teams dispatch for alerts and approvals)
      TamanduaServer.Integrations.ChatRouter,

      # Slack Bot (workspace configs, slash commands, interactive approval)
      TamanduaServer.Integrations.SlackBot,

      # Teams Bot (adaptive cards, bot commands, interactive approval)
      TamanduaServer.Integrations.TeamsBot,

      # SOAR Playbook Executor (execution dispatch, status tracking, retry)
      TamanduaServer.Integrations.SOAR.Executor,

      # Integration Alert Router (SIEM, SOAR, Ticketing routing)
      TamanduaServer.Integrations.Router,

      # Inbound Webhook Router (ETS-backed audit, rate limiting)
      TamanduaServer.Integrations.Webhook.InboundRouter
    ]
  end
end
