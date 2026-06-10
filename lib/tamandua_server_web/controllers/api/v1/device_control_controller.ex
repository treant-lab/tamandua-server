defmodule TamanduaServerWeb.API.V1.DeviceControlController do
  @moduledoc """
  API controller for USB device control and policy management.

  Provides endpoints for:
  - Managing USB device policies per device group
  - Viewing connected USB devices
  - Managing whitelists/blocklists
  - Encryption enforcement configuration
  """

  use TamanduaServerWeb, :controller

  alias TamanduaServer.DeviceControl
  alias TamanduaServer.Agents

  action_fallback TamanduaServerWeb.FallbackController

  # ===========================================================================
  # USB Device Policies
  # ===========================================================================

  @doc """
  List all device group policies.
  """
  def list_policies(conn, _params) do
    policies = DeviceControl.list_policies()
    json(conn, %{policies: policies})
  end

  @doc """
  Get policy for a specific device group.
  """
  def get_policy(conn, %{"group" => group}) do
    case DeviceControl.get_policy(group) do
      {:ok, policy} ->
        json(conn, %{policy: policy})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Policy not found for group: #{group}"})
    end
  end

  @doc """
  Create or update a device group policy.
  """
  def upsert_policy(conn, %{"group" => group} = params) do
    policy_params = %{
      group: group,
      allowed_classes: Map.get(params, "allowed_classes", []),
      blocked_classes: Map.get(params, "blocked_classes", []),
      allowed_devices: Map.get(params, "allowed_devices", []),
      blocked_devices: Map.get(params, "blocked_devices", []),
      write_protection: Map.get(params, "write_protection", "none"),
      require_encryption: Map.get(params, "require_encryption", false),
      max_storage_size_gb: Map.get(params, "max_storage_size_gb", 0),
      allow_network_adapters: Map.get(params, "allow_network_adapters", false),
      allow_wireless: Map.get(params, "allow_wireless", false),
      audit_all: Map.get(params, "audit_all", true)
    }

    case DeviceControl.upsert_policy(policy_params) do
      {:ok, policy} ->
        # Broadcast policy update to all agents
        broadcast_policy_update(group, policy)

        conn
        |> put_status(:ok)
        |> json(%{policy: policy, message: "Policy updated successfully"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: format_errors(changeset)})
    end
  end

  @doc """
  Delete a device group policy.
  """
  def delete_policy(conn, %{"group" => group}) do
    case DeviceControl.delete_policy(group) do
      {:ok, _} ->
        json(conn, %{message: "Policy deleted successfully"})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Policy not found"})

      {:error, :cannot_delete_default} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Cannot delete default policies"})
    end
  end

  # ===========================================================================
  # Device Whitelist/Blocklist
  # ===========================================================================

  @doc """
  Get the global device whitelist.
  """
  def get_whitelist(conn, _params) do
    whitelist = DeviceControl.get_whitelist()
    json(conn, %{whitelist: whitelist})
  end

  @doc """
  Add devices to whitelist.
  """
  def add_to_whitelist(conn, %{"devices" => devices}) when is_list(devices) do
    case DeviceControl.add_to_whitelist(devices) do
      {:ok, updated_whitelist} ->
        broadcast_whitelist_update()
        json(conn, %{whitelist: updated_whitelist, added: length(devices)})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: reason})
    end
  end

  @doc """
  Remove devices from whitelist.
  """
  def remove_from_whitelist(conn, %{"devices" => devices}) when is_list(devices) do
    case DeviceControl.remove_from_whitelist(devices) do
      {:ok, updated_whitelist} ->
        broadcast_whitelist_update()
        json(conn, %{whitelist: updated_whitelist, removed: length(devices)})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: reason})
    end
  end

  @doc """
  Get the global device blocklist.
  """
  def get_blocklist(conn, _params) do
    blocklist = DeviceControl.get_blocklist()
    json(conn, %{blocklist: blocklist})
  end

  @doc """
  Add devices to blocklist.
  """
  def add_to_blocklist(conn, %{"devices" => devices}) when is_list(devices) do
    case DeviceControl.add_to_blocklist(devices) do
      {:ok, updated_blocklist} ->
        broadcast_blocklist_update()
        json(conn, %{blocklist: updated_blocklist, added: length(devices)})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: reason})
    end
  end

  @doc """
  Remove devices from blocklist.
  """
  def remove_from_blocklist(conn, %{"devices" => devices}) when is_list(devices) do
    case DeviceControl.remove_from_blocklist(devices) do
      {:ok, updated_blocklist} ->
        broadcast_blocklist_update()
        json(conn, %{blocklist: updated_blocklist, removed: length(devices)})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: reason})
    end
  end

  # ===========================================================================
  # Agent Device Assignment
  # ===========================================================================

  @doc """
  Assign an agent to a device group.
  """
  def assign_agent_group(conn, %{"agent_id" => agent_id, "group" => group}) do
    case DeviceControl.assign_agent_group(agent_id, group) do
      {:ok, _} ->
        # Send policy update to the specific agent
        send_policy_to_agent(agent_id, group)
        json(conn, %{message: "Agent assigned to group #{group}"})

      {:error, :agent_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent not found"})

      {:error, :invalid_group} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Invalid device group"})
    end
  end

  @doc """
  Get the device group for an agent.
  """
  def get_agent_group(conn, %{"agent_id" => agent_id}) do
    case DeviceControl.get_agent_group(agent_id) do
      {:ok, group} ->
        json(conn, %{agent_id: agent_id, group: group})

      {:error, :agent_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent not found"})
    end
  end

  # ===========================================================================
  # Connected USB Devices
  # ===========================================================================

  @doc """
  List all USB devices currently connected across all agents.
  """
  def list_connected_devices(conn, params) do
    filters = %{
      agent_id: Map.get(params, "agent_id"),
      device_class: Map.get(params, "device_class"),
      blocked: Map.get(params, "blocked"),
      limit: Map.get(params, "limit", 100) |> parse_int(100)
    }

    devices = DeviceControl.list_connected_devices(filters)
    json(conn, %{devices: devices, count: length(devices)})
  end

  @doc """
  Get USB device history for an agent.
  """
  def device_history(conn, %{"agent_id" => agent_id} = params) do
    filters = %{
      from: Map.get(params, "from"),
      to: Map.get(params, "to"),
      device_class: Map.get(params, "device_class"),
      blocked_only: Map.get(params, "blocked_only", false),
      limit: Map.get(params, "limit", 100) |> parse_int(100)
    }

    case DeviceControl.get_device_history(agent_id, filters) do
      {:ok, history} ->
        json(conn, %{agent_id: agent_id, history: history})

      {:error, :agent_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Agent not found"})
    end
  end

  # ===========================================================================
  # Encryption Enforcement
  # ===========================================================================

  @doc """
  Get encryption enforcement status across agents.
  """
  def encryption_status(conn, _params) do
    status = DeviceControl.get_encryption_status()
    json(conn, status)
  end

  @doc """
  Configure encryption enforcement settings.
  """
  def configure_encryption(conn, params) do
    settings = %{
      require_bitlocker: Map.get(params, "require_bitlocker", false),
      require_veracrypt: Map.get(params, "require_veracrypt", false),
      allow_luks: Map.get(params, "allow_luks", true),
      block_unencrypted: Map.get(params, "block_unencrypted", false),
      grace_period_minutes: Map.get(params, "grace_period_minutes", 0)
    }

    case DeviceControl.configure_encryption(settings) do
      {:ok, updated_settings} ->
        json(conn, %{settings: updated_settings})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: reason})
    end
  end

  # ===========================================================================
  # Write Protection
  # ===========================================================================

  @doc """
  Get write protection status for agents.
  """
  def write_protection_status(conn, params) do
    agent_id = Map.get(params, "agent_id")
    status = DeviceControl.get_write_protection_status(agent_id)
    json(conn, status)
  end

  @doc """
  Set write protection mode for a device group.
  """
  def set_write_protection(conn, %{"group" => group, "mode" => mode}) do
    case DeviceControl.set_write_protection(group, mode) do
      {:ok, _} ->
        broadcast_policy_update(group, nil)
        json(conn, %{message: "Write protection mode set to #{mode} for group #{group}"})

      {:error, :invalid_mode} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Invalid write protection mode. Use: none, read_only, audit_only, block_executables"})

      {:error, :group_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Device group not found"})
    end
  end

  # ===========================================================================
  # Predefined Policies (Templates)
  # ===========================================================================

  @doc """
  Get predefined policy templates.
  """
  def policy_templates(conn, _params) do
    templates = [
      %{
        name: "it_admin",
        description: "Full access for IT administrators",
        allowed_classes: ["mass_storage", "hid", "hub", "audio", "video", "network_adapter", "wireless_controller", "smart_card", "communications", "printer"],
        blocked_classes: [],
        write_protection: "none",
        require_encryption: false
      },
      %{
        name: "developer",
        description: "Developer workstation - storage with audit",
        allowed_classes: ["mass_storage", "hid", "hub", "audio", "video", "communications"],
        blocked_classes: [],
        write_protection: "audit_only",
        require_encryption: false,
        max_storage_size_gb: 128
      },
      %{
        name: "standard",
        description: "Standard user - basic peripherals only",
        allowed_classes: ["hid", "hub", "audio"],
        blocked_classes: ["mass_storage", "network_adapter", "wireless_controller"],
        write_protection: "read_only",
        require_encryption: false
      },
      %{
        name: "kiosk",
        description: "Kiosk/shared device - very restricted",
        allowed_classes: ["hid", "hub"],
        blocked_classes: ["mass_storage", "network_adapter", "wireless_controller"],
        write_protection: "read_only",
        require_encryption: true
      },
      %{
        name: "executive",
        description: "Executive - business devices with encryption",
        allowed_classes: ["mass_storage", "hid", "hub", "audio"],
        blocked_classes: ["network_adapter", "wireless_controller"],
        write_protection: "none",
        require_encryption: true
      }
    ]

    json(conn, %{templates: templates})
  end

  @doc """
  Apply a predefined policy template to a group.
  """
  def apply_template(conn, %{"group" => group, "template" => template_name}) do
    case DeviceControl.apply_template(group, template_name) do
      {:ok, policy} ->
        broadcast_policy_update(group, policy)
        json(conn, %{policy: policy, message: "Template #{template_name} applied to #{group}"})

      {:error, :template_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Template not found"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: reason})
    end
  end

  # ===========================================================================
  # Statistics
  # ===========================================================================

  @doc """
  Get USB device control statistics.
  """
  def stats(conn, params) do
    time_range = Map.get(params, "range", "24h")

    stats = DeviceControl.get_stats(time_range)
    json(conn, stats)
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp broadcast_policy_update(group, policy) do
    TamanduaServerWeb.Endpoint.broadcast!(
      "config:updates",
      "usb_policy_updated",
      %{group: group, policy: policy}
    )
  end

  defp broadcast_whitelist_update do
    whitelist = DeviceControl.get_whitelist()
    TamanduaServerWeb.Endpoint.broadcast!(
      "config:updates",
      "usb_whitelist_updated",
      %{whitelist: whitelist}
    )
  end

  defp broadcast_blocklist_update do
    blocklist = DeviceControl.get_blocklist()
    TamanduaServerWeb.Endpoint.broadcast!(
      "config:updates",
      "usb_blocklist_updated",
      %{blocklist: blocklist}
    )
  end

  defp send_policy_to_agent(agent_id, group) do
    case DeviceControl.get_policy(group) do
      {:ok, policy} ->
        Agents.send_command(agent_id, %{
          type: "update_usb_policy",
          payload: policy
        })

      _ ->
        :ok
    end
  end

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp parse_int(nil, default), do: default
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(val, _default) when is_integer(val), do: val
  defp parse_int(_, default), do: default
end
