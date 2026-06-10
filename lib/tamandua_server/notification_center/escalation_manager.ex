defmodule TamanduaServer.NotificationCenter.EscalationManager do
  @moduledoc """
  Manages escalation policies and instances.
  Handles escalation timers and auto-escalation for critical alerts.
  """

  use GenServer
  require Logger

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.NotificationCenter.{
    EscalationPolicy,
    EscalationInstance,
    Dispatcher
  }

  alias TamanduaServer.Alerts.Alert

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Start escalation for an alert.
  """
  def start_escalation(alert_id, policy_id) do
    GenServer.cast(__MODULE__, {:start_escalation, alert_id, policy_id})
  end

  @doc """
  Acknowledge an escalation (stops further escalation).
  """
  def acknowledge_escalation(instance_id, user_id) do
    GenServer.cast(__MODULE__, {:acknowledge, instance_id, user_id})
  end

  @doc """
  Cancel an escalation.
  """
  def cancel_escalation(instance_id) do
    GenServer.cast(__MODULE__, {:cancel, instance_id})
  end

  # Server callbacks

  @impl true
  def init(_opts) do
    # Schedule periodic check for pending escalations
    schedule_check()
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:start_escalation, alert_id, policy_id}, state) do
    case Repo.get(Alert, alert_id) do
      nil ->
        Logger.error("[EscalationManager] Alert not found: #{alert_id}")

      alert ->
        case Repo.get(EscalationPolicy, policy_id) do
          nil ->
            Logger.error("[EscalationManager] Policy not found: #{policy_id}")

          policy ->
            create_escalation_instance(alert, policy)
        end
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast({:acknowledge, instance_id, user_id}, state) do
    case Repo.get(EscalationInstance, instance_id) do
      nil ->
        Logger.error("[EscalationManager] Instance not found: #{instance_id}")

      instance ->
        instance
        |> EscalationInstance.acknowledge_changeset(user_id)
        |> Repo.update()

        Logger.info("[EscalationManager] Escalation #{instance_id} acknowledged by #{user_id}")
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast({:cancel, instance_id}, state) do
    case Repo.get(EscalationInstance, instance_id) do
      nil ->
        Logger.error("[EscalationManager] Instance not found: #{instance_id}")

      instance ->
        instance
        |> EscalationInstance.cancel_changeset()
        |> Repo.update()

        Logger.info("[EscalationManager] Escalation #{instance_id} cancelled")
    end

    {:noreply, state}
  end

  @impl true
  def handle_info(:check_escalations, state) do
    check_pending_escalations()
    schedule_check()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private functions

  defp create_escalation_instance(alert, policy) do
    attrs = %{
      organization_id: alert.organization_id,
      escalation_policy_id: policy.id,
      alert_id: alert.id,
      max_level: length(policy.escalation_chain),
      started_at: DateTime.utc_now(),
      state: "pending"
    }

    case %EscalationInstance{}
         |> EscalationInstance.changeset(attrs)
         |> Repo.insert() do
      {:ok, instance} ->
        Logger.info(
          "[EscalationManager] Started escalation for alert #{alert.id} with policy #{policy.id}"
        )

        # Immediately escalate to first level
        escalate_to_next_level(instance, policy)
        instance

      {:error, changeset} ->
        Logger.error(
          "[EscalationManager] Failed to create escalation instance: #{inspect(changeset.errors)}"
        )

        nil
    end
  end

  defp check_pending_escalations do
    # Get all active escalation instances
    instances =
      EscalationInstance
      |> where([i], i.state in ["pending", "in_progress"])
      |> preload(:escalation_policy)
      |> Repo.all()

    Enum.each(instances, fn instance ->
      policy = instance.escalation_policy

      # Check if it's time to escalate to next level
      if should_escalate?(instance, policy) do
        escalate_to_next_level(instance, policy)
      end
    end)
  end

  defp should_escalate?(instance, policy) do
    # Get the delay for current level
    current_level_config = Enum.at(policy.escalation_chain, instance.current_level)

    if current_level_config do
      delay_minutes = current_level_config["delay_minutes"]
      threshold = DateTime.add(instance.updated_at, delay_minutes * 60, :second)

      DateTime.compare(DateTime.utc_now(), threshold) == :gt
    else
      false
    end
  end

  defp escalate_to_next_level(instance, policy) do
    next_level = instance.current_level + 1

    if next_level > instance.max_level do
      # Max level reached, complete escalation
      instance
      |> EscalationInstance.complete_changeset()
      |> Repo.update()

      Logger.info("[EscalationManager] Escalation #{instance.id} completed (max level reached)")
    else
      # Escalate to next level
      instance
      |> EscalationInstance.escalate_changeset()
      |> Repo.update()

      # Get user at this level
      level_config = Enum.at(policy.escalation_chain, instance.current_level)
      user_id = level_config["user_id"]

      # Send notification
      alert = Repo.get(Alert, instance.alert_id)

      Dispatcher.dispatch(
        "alert_escalated",
        "Alert Escalated: #{alert.title}",
        "This alert has been escalated to you (Level #{next_level}).",
        %{
          organization_id: alert.organization_id,
          users: [user_id],
          priority: "high",
          related_resource_type: "alert",
          related_resource_id: alert.id,
          metadata: %{
            escalation_instance_id: instance.id,
            escalation_level: next_level
          }
        }
      )

      Logger.info(
        "[EscalationManager] Escalated alert #{alert.id} to level #{next_level} (user: #{user_id})"
      )
    end
  end

  defp schedule_check do
    # Check every minute
    Process.send_after(self(), :check_escalations, 60_000)
  end
end
