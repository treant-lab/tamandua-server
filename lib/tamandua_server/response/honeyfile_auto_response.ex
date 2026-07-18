defmodule TamanduaServer.Response.HoneyfileAutoResponse do
  @moduledoc """
  Policy-gated defensive response planning for honeyfile access.

  Honeyfile access is a high-confidence deception signal, but containment
  actions are still destructive. This module keeps the default behavior safe:
  build an auditable response plan in dry-run mode unless an operator has
  explicitly enabled autonomous containment.
  """

  @type response_plan :: %{
          trigger: :honeyfile_access,
          dry_run: boolean(),
          policy_gate: :dry_run | :approval_required | :auto_execute_disabled | :auto_execute,
          confidence: float(),
          actions: [map()],
          metadata: map()
        }

  @default_config %{
    enabled: true,
    mode: :dry_run,
    dry_run: true,
    require_policy_gate: true,
    allow_autonomous_containment: false,
    kill_process: true,
    isolate_agent: true,
    create_snapshot: true,
    escalate_to_soc: true,
    trigger_playbook_id: nil
  }

  @doc """
  Merge operator configuration with the safe honeyfile defaults.
  """
  @spec normalize_config(map() | nil) :: map()
  def normalize_config(config) when is_map(config) do
    Map.merge(@default_config, config)
  end

  def normalize_config(_), do: @default_config

  @doc """
  Build a response plan for a honeyfile access event.
  """
  @spec plan(map(), map(), map() | nil, map() | nil) :: response_plan()
  def plan(breadcrumb, event, alert, config \\ %{}) do
    config = normalize_config(config)
    agent_id = value(event, :agent_id) || value(breadcrumb, :agent_id)
    alert_id = value(alert || %{}, :id)

    actions =
      []
      |> maybe_add_kill(config, event, agent_id)
      |> maybe_add_isolate(config, agent_id)
      |> maybe_add_snapshot(config, agent_id)
      |> Enum.reverse()

    dry_run = dry_run?(config)
    policy_gate = policy_gate(config, dry_run)

    %{
      trigger: :honeyfile_access,
      dry_run: dry_run,
      policy_gate: policy_gate,
      confidence: 1.0,
      actions: actions,
      metadata: %{
        alert_id: alert_id,
        agent_id: agent_id,
        breadcrumb_id: value(breadcrumb, :id),
        breadcrumb_type: value(breadcrumb, :type),
        breadcrumb_path: value(breadcrumb, :path),
        process_name: value(event, :process_name),
        pid: value(event, :pid),
        user: value(event, :user),
        access_type: value(event, :access_type) || "read",
        reason: "honeyfile_access",
        mitre_techniques: ["T1083", "T1486"]
      }
    }
  end

  @doc """
  True only when the operator explicitly allowed autonomous containment.
  """
  @spec executable?(response_plan()) :: boolean()
  def executable?(%{dry_run: false, policy_gate: :auto_execute, actions: actions}) when actions != [],
    do: true

  def executable?(_), do: false

  defp maybe_add_kill(actions, %{kill_process: true}, event, agent_id) do
    case value(event, :pid) do
      pid when is_integer(pid) ->
        [
          %{
            action_type: "kill_process",
            agent_id: agent_id,
            params: %{pid: pid, force: true},
            reason: "terminate process that accessed honeyfile"
          }
          | actions
        ]

      _ ->
        actions
    end
  end

  defp maybe_add_kill(actions, _config, _event, _agent_id), do: actions

  defp maybe_add_isolate(actions, %{isolate_agent: true}, agent_id) when is_binary(agent_id) do
    [
      %{
        action_type: "isolate_network",
        agent_id: agent_id,
        params: %{allowed_ips: [], duration_seconds: 0},
        reason: "contain host after high-confidence honeyfile access"
      }
      | actions
    ]
  end

  defp maybe_add_isolate(actions, _config, _agent_id), do: actions

  defp maybe_add_snapshot(actions, %{create_snapshot: true}, agent_id) when is_binary(agent_id) do
    [
      %{
        action_type: "collect_forensics",
        agent_id: agent_id,
        params: %{
          type: "honeyfile_access",
          memory_dump: false,
          process_list: true,
          network_connections: true,
          event_logs: true
        },
        reason: "preserve context after honeyfile access"
      }
      | actions
    ]
  end

  defp maybe_add_snapshot(actions, _config, _agent_id), do: actions

  defp dry_run?(config) do
    mode = normalize_mode(config[:mode] || config["mode"])
    allowed? = config[:allow_autonomous_containment] == true or config["allow_autonomous_containment"] == true

    cond do
      config[:enabled] == false or config["enabled"] == false -> true
      config[:dry_run] == false or config["dry_run"] == false -> mode != :auto_execute or not allowed?
      true -> true
    end
  end

  defp policy_gate(config, true) do
    mode = normalize_mode(config[:mode] || config["mode"])

    case mode do
      :disabled -> :auto_execute_disabled
      :approval_required -> :approval_required
      _ -> :dry_run
    end
  end

  defp policy_gate(config, false) do
    mode = normalize_mode(config[:mode] || config["mode"])
    allowed? = config[:allow_autonomous_containment] == true or config["allow_autonomous_containment"] == true

    cond do
      config[:enabled] == false or config["enabled"] == false -> :auto_execute_disabled
      mode == :auto_execute and allowed? -> :auto_execute
      mode == :approval_required -> :approval_required
      true -> :dry_run
    end
  end

  defp normalize_mode(mode) when mode in [:auto_execute, :approval_required, :dry_run, :disabled],
    do: mode

  defp normalize_mode(mode) when is_binary(mode) do
    case mode do
      "auto_execute" -> :auto_execute
      "approval_required" -> :approval_required
      "dry_run" -> :dry_run
      "disabled" -> :disabled
      _ -> :dry_run
    end
  end

  defp normalize_mode(_), do: :dry_run

  defp value(nil, _key), do: nil
  defp value(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, Atom.to_string(key))
end
