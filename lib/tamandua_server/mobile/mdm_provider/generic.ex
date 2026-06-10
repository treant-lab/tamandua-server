defmodule TamanduaServer.Mobile.MDMProvider.Generic do
  @moduledoc """
  Generic MDM provider that queues commands for manual execution.

  Used when no specific MDM provider is configured, or as a fallback.
  Commands are queued in the database and can be processed manually
  by administrators or through a custom integration.

  All commands are logged and broadcast via PubSub for real-time
  visibility in the dashboard.
  """

  @behaviour TamanduaServer.Mobile.MDMProvider

  require Logger

  # ---------------------------------------------------------------------------
  # Behaviour Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def lock_device(device_id, opts) do
    queue_command("lock", device_id, %{
      message: opts["message"] || "Remote lock requested",
      pin: opts["pin"]
    })
  end

  @impl true
  def wipe_device(device_id, opts) do
    queue_command("wipe", device_id, %{
      wipe_type: opts["wipe_type"] || "enterprise_only",
      reason: opts["reason"] || "Wipe requested by security team"
    })
  end

  @impl true
  def push_policy(device_id, policy) do
    queue_command("push_policy", device_id, %{
      policy_id: policy["policy_id"],
      policy_name: policy["policy_name"],
      policy_type: policy["policy_type"]
    })
  end

  @impl true
  def remove_app(device_id, app_id) do
    queue_command("remove_app", device_id, %{
      app_id: app_id
    })
  end

  @impl true
  def enable_vpn(device_id, opts) do
    queue_command("enable_vpn", device_id, %{
      vpn_profile: opts["vpn_profile"],
      vpn_server: opts["vpn_server"]
    })
  end

  @impl true
  def get_compliance_status(device_id) do
    # Generic provider cannot query compliance remotely. Return unknown.
    {:ok, %{
      provider: "generic",
      device_id: device_id,
      compliance_state: "unknown",
      compliant: false,
      note: "No MDM provider configured. Compliance status unavailable."
    }}
  end

  # ---------------------------------------------------------------------------
  # Command Queue
  # ---------------------------------------------------------------------------

  defp queue_command(action, device_id, details) do
    command_id = Ecto.UUID.generate()

    command = %{
      command_id: command_id,
      action: action,
      provider: "generic",
      device_id: device_id,
      details: details,
      status: "queued",
      queued_at: DateTime.utc_now(),
      timestamp: DateTime.utc_now()
    }

    Logger.info("[MDM:Generic] Command queued: action=#{action} device=#{device_id} command_id=#{command_id}")

    # Broadcast to PubSub so dashboard can show pending commands
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "mobile:mdm_commands",
      {:mdm_command_queued, command}
    )

    {:ok, command}
  end
end
