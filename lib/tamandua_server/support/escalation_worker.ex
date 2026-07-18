defmodule TamanduaServer.Support.EscalationWorker do
  @moduledoc """
  Dormant Oban worker for support tickets approaching or exceeding SLA deadlines.

  The product lock is disabled by default and the support queue/cron are not
  registered. A manually constructed job is therefore an explicit no-op unless
  this module's `:enabled` setting is the literal value `true`.

  When explicitly enabled and scheduled, it can:
  1. Check for tickets approaching response deadline (15 min warning)
  2. Check for tickets that have breached response SLA
  3. Check for tickets approaching resolution deadline
  4. Check for tickets that have breached resolution SLA
  5. Trigger appropriate escalations based on priority

  ## Escalation Ladder

  - **P1**: Manager (15min) → VP (30min) → CEO (60min)
  - **P2**: Manager (60min) → VP (240min)
  - **P3**: Manager (480min)
  - **P4**: No auto-escalation
  """

  use Oban.Worker,
    queue: :support,
    max_attempts: 3,
    # Prevent duplicate runs within 5 minutes
    unique: [period: 300]

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Support.{Ticket, SLAConfig}
  alias TamanduaServer.NotificationCenter.Dispatcher

  @disabled_result {:ok, %{status: :disabled, reason: :product_lock}}

  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    config = Application.get_env(:tamandua_server, __MODULE__, [])

    if Keyword.get(config, :enabled, false) === true do
      perform_enabled(
        Keyword.get(config, :repo, Repo),
        Keyword.get(config, :dispatcher, Dispatcher)
      )
    else
      @disabled_result
    end
  end

  defp perform_enabled(repo, dispatcher) do
    now = DateTime.utc_now()
    # Minutes before deadline to warn
    warning_threshold = 15

    # Check response SLA
    check_response_sla(now, warning_threshold, repo, dispatcher)

    # Check resolution SLA
    check_resolution_sla(now, warning_threshold, repo, dispatcher)

    :ok
  end

  defp check_response_sla(now, warning_threshold, repo, dispatcher) do
    warning_time = DateTime.add(now, warning_threshold * 60, :second)

    # Tickets approaching response deadline
    approaching =
      from(t in Ticket,
        where: t.status == "open",
        where: is_nil(t.first_response_at),
        where: t.response_deadline > ^now,
        where: t.response_deadline <= ^warning_time,
        where: t.response_sla_breached == false
      )
      |> repo.all()

    Enum.each(approaching, fn ticket ->
      Logger.info("[Support SLA] Ticket #{ticket.id} approaching response deadline")
      send_warning_notification(ticket, :response, dispatcher)
    end)

    # Tickets that have breached response deadline
    breached =
      from(t in Ticket,
        where: t.status == "open",
        where: is_nil(t.first_response_at),
        where: t.response_deadline <= ^now,
        where: t.response_sla_breached == false
      )
      |> repo.all()

    Enum.each(breached, fn ticket ->
      Logger.warning("[Support SLA] Ticket #{ticket.id} BREACHED response SLA")
      mark_response_breached(ticket, repo)
      trigger_escalation(ticket, :response, repo, dispatcher)
    end)

    %{approaching: length(approaching), breached: length(breached)}
  end

  defp check_resolution_sla(now, warning_threshold, repo, dispatcher) do
    warning_time = DateTime.add(now, warning_threshold * 60, :second)

    # Tickets approaching resolution deadline
    approaching =
      from(t in Ticket,
        where: t.status in ["open", "in_progress", "pending_customer"],
        where: is_nil(t.resolved_at),
        where: t.resolution_deadline > ^now,
        where: t.resolution_deadline <= ^warning_time,
        where: t.resolution_sla_breached == false
      )
      |> repo.all()

    Enum.each(approaching, fn ticket ->
      Logger.info("[Support SLA] Ticket #{ticket.id} approaching resolution deadline")
      send_warning_notification(ticket, :resolution, dispatcher)
    end)

    # Tickets that have breached resolution deadline
    breached =
      from(t in Ticket,
        where: t.status in ["open", "in_progress", "pending_customer"],
        where: is_nil(t.resolved_at),
        where: t.resolution_deadline <= ^now,
        where: t.resolution_sla_breached == false
      )
      |> repo.all()

    Enum.each(breached, fn ticket ->
      Logger.warning("[Support SLA] Ticket #{ticket.id} BREACHED resolution SLA")
      mark_resolution_breached(ticket, repo)
      trigger_escalation(ticket, :resolution, repo, dispatcher)
    end)

    %{approaching: length(approaching), breached: length(breached)}
  end

  defp mark_response_breached(ticket, repo) do
    ticket
    |> Ticket.changeset(%{response_sla_breached: true})
    |> repo.update()
  end

  defp mark_resolution_breached(ticket, repo) do
    ticket
    |> Ticket.changeset(%{resolution_sla_breached: true})
    |> repo.update()
  end

  # Dispatcher's real API is dispatch(type, title, body, attrs); the
  # Notification schema has no support-specific type, so support SLA notices
  # go out as "system_event" with the ticket as the related resource.
  defp send_warning_notification(ticket, sla_type, dispatcher) do
    deadline =
      if(sla_type == :response, do: ticket.response_deadline, else: ticket.resolution_deadline)

    dispatcher.dispatch(
      "system_event",
      "Support SLA warning: ticket #{ticket.id} (#{ticket.priority})",
      "Ticket \"#{ticket.subject}\" is approaching its #{sla_type} SLA deadline (#{deadline}).",
      %{
        organization_id: ticket.organization_id,
        related_resource_type: "support_ticket",
        related_resource_id: ticket.id,
        priority: notification_priority(ticket.priority)
      }
    )
  end

  defp trigger_escalation(ticket, sla_type, repo, dispatcher) do
    priority = String.to_existing_atom(ticket.priority)
    escalation_config = SLAConfig.get_escalation_config(priority)

    # Get appropriate escalation level based on breach severity
    current_level = ticket.escalation_level
    next_escalation = Enum.at(escalation_config, current_level)

    if next_escalation do
      # Update ticket escalation level
      ticket
      |> Ticket.changeset(%{
        escalation_level: current_level + 1,
        escalated_at: DateTime.utc_now(),
        escalation_reason: "#{sla_type} SLA breached"
      })
      |> repo.update()

      # Send a single escalation notification. Dispatcher resolves delivery
      # channels from each recipient's NotificationCenter preferences, so the
      # per-channel forced routing (next_escalation.channels/.to) that the old
      # nonexistent dispatch/1 implied is not expressible through the real API;
      # recipients fall back to org admins via the organization_id.
      dispatcher.dispatch(
        "system_event",
        "Support ticket escalated: #{ticket.id} (#{ticket.priority})",
        "Ticket \"#{ticket.subject}\" breached its #{sla_type} SLA and was escalated " <>
          "to #{next_escalation.to} (level #{current_level + 1}).",
        %{
          organization_id: ticket.organization_id,
          related_resource_type: "support_ticket",
          related_resource_id: ticket.id,
          priority: notification_priority(ticket.priority)
        }
      )

      Logger.warning(
        "[Support Escalation] Ticket #{ticket.id} escalated to #{next_escalation.to}"
      )
    end
  end

  # Ticket priorities are p1..p4; Notification priorities are
  # low/normal/high/critical.
  defp notification_priority("p1"), do: "critical"
  defp notification_priority("p2"), do: "high"
  defp notification_priority("p3"), do: "normal"
  defp notification_priority(_), do: "low"
end
