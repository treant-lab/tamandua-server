defmodule TamanduaServer.Support.EscalationWorker do
  @moduledoc """
  Oban worker that checks for support tickets approaching or exceeding SLA deadlines.

  Runs every 5 minutes to:
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
    unique: [period: 300]  # Prevent duplicate runs within 5 minutes

  import Ecto.Query
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Support.{Ticket, SLAConfig}
  alias TamanduaServer.NotificationCenter.Dispatcher

  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    now = DateTime.utc_now()
    warning_threshold = 15  # Minutes before deadline to warn

    # Check response SLA
    check_response_sla(now, warning_threshold)

    # Check resolution SLA
    check_resolution_sla(now, warning_threshold)

    :ok
  end

  defp check_response_sla(now, warning_threshold) do
    warning_time = DateTime.add(now, warning_threshold * 60, :second)

    # Tickets approaching response deadline
    approaching = from(t in Ticket,
      where: t.status == "open",
      where: is_nil(t.first_response_at),
      where: t.response_deadline > ^now,
      where: t.response_deadline <= ^warning_time,
      where: t.response_sla_breached == false
    )
    |> Repo.all()

    Enum.each(approaching, fn ticket ->
      Logger.info("[Support SLA] Ticket #{ticket.id} approaching response deadline")
      send_warning_notification(ticket, :response)
    end)

    # Tickets that have breached response deadline
    breached = from(t in Ticket,
      where: t.status == "open",
      where: is_nil(t.first_response_at),
      where: t.response_deadline <= ^now,
      where: t.response_sla_breached == false
    )
    |> Repo.all()

    Enum.each(breached, fn ticket ->
      Logger.warning("[Support SLA] Ticket #{ticket.id} BREACHED response SLA")
      mark_response_breached(ticket)
      trigger_escalation(ticket, :response)
    end)

    %{approaching: length(approaching), breached: length(breached)}
  end

  defp check_resolution_sla(now, warning_threshold) do
    warning_time = DateTime.add(now, warning_threshold * 60, :second)

    # Tickets approaching resolution deadline
    approaching = from(t in Ticket,
      where: t.status in ["open", "in_progress", "pending_customer"],
      where: is_nil(t.resolved_at),
      where: t.resolution_deadline > ^now,
      where: t.resolution_deadline <= ^warning_time,
      where: t.resolution_sla_breached == false
    )
    |> Repo.all()

    Enum.each(approaching, fn ticket ->
      Logger.info("[Support SLA] Ticket #{ticket.id} approaching resolution deadline")
      send_warning_notification(ticket, :resolution)
    end)

    # Tickets that have breached resolution deadline
    breached = from(t in Ticket,
      where: t.status in ["open", "in_progress", "pending_customer"],
      where: is_nil(t.resolved_at),
      where: t.resolution_deadline <= ^now,
      where: t.resolution_sla_breached == false
    )
    |> Repo.all()

    Enum.each(breached, fn ticket ->
      Logger.warning("[Support SLA] Ticket #{ticket.id} BREACHED resolution SLA")
      mark_resolution_breached(ticket)
      trigger_escalation(ticket, :resolution)
    end)

    %{approaching: length(approaching), breached: length(breached)}
  end

  defp mark_response_breached(ticket) do
    ticket
    |> Ticket.changeset(%{response_sla_breached: true})
    |> Repo.update()
  end

  defp mark_resolution_breached(ticket) do
    ticket
    |> Ticket.changeset(%{resolution_sla_breached: true})
    |> Repo.update()
  end

  defp send_warning_notification(ticket, sla_type) do
    priority = String.to_existing_atom(ticket.priority)

    Dispatcher.dispatch(%{
      type: :support_sla_warning,
      priority: priority,
      ticket_id: ticket.id,
      sla_type: sla_type,
      deadline: if(sla_type == :response, do: ticket.response_deadline, else: ticket.resolution_deadline),
      subject: ticket.subject
    })
  end

  defp trigger_escalation(ticket, sla_type) do
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
      |> Repo.update()

      # Send escalation notifications
      Enum.each(next_escalation.channels, fn channel ->
        Dispatcher.dispatch(%{
          type: :support_escalation,
          channel: channel,
          to: next_escalation.to,
          ticket_id: ticket.id,
          priority: priority,
          sla_type: sla_type,
          subject: ticket.subject
        })
      end)

      Logger.warning("[Support Escalation] Ticket #{ticket.id} escalated to #{next_escalation.to}")
    end
  end
end
