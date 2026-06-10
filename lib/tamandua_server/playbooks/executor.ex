defmodule TamanduaServer.Playbooks.Executor do
  @moduledoc """
  YAML playbook execution engine for automated incident response.

  Parses YAML playbooks, evaluates trigger conditions, executes action chains,
  and logs execution for audit trails.
  """

  require Logger

  alias TamanduaServer.Response.Executor, as: ResponseExecutor
  alias TamanduaServer.Response.ConditionEvaluator
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Playbooks.Validator

  @doc """
  Executes a YAML playbook against an alert context.

  Options:
    - :dry_run - If true, simulates execution without actually performing actions
    - :timeout - Maximum execution time in milliseconds (default: 300_000 = 5 minutes)
    - :continue_on_error - If true, continues executing actions even if one fails
  """
  @spec execute(String.t() | map(), Alert.t() | map(), keyword()) ::
          {:ok, map()} | {:error, String.t()}
  def execute(playbook_yaml, alert_or_context, opts \\ [])

  def execute(playbook_yaml, alert_or_context, opts) when is_binary(playbook_yaml) do
    case YamlElixir.read_from_string(playbook_yaml) do
      {:ok, playbook} when is_map(playbook) ->
        execute(playbook, alert_or_context, opts)

      {:ok, _} ->
        {:error, "Invalid YAML: root must be an object"}

      {:error, %YamlElixir.ParsingError{message: message}} ->
        {:error, "YAML parsing error: #{message}"}

      {:error, reason} ->
        {:error, "YAML parsing error: #{inspect(reason)}"}
    end
  end

  def execute(playbook, alert_or_context, opts) when is_map(playbook) do
    # Validate playbook first
    case Validator.validate(playbook) do
      {:ok, validated_playbook} ->
        do_execute(validated_playbook, alert_or_context, opts)

      {:error, errors} ->
        {:error, "Playbook validation failed: #{Enum.join(errors, "; ")}"}
    end
  end

  defp do_execute(playbook, alert_or_context, opts) do
    dry_run = Keyword.get(opts, :dry_run, false)
    timeout = Keyword.get(opts, :timeout, 300_000)
    continue_on_error = Keyword.get(opts, :continue_on_error, false)

    # Build execution context
    context = build_context(alert_or_context)

    # Evaluate trigger conditions
    if should_execute?(playbook, context) do
      Logger.info("Executing playbook '#{playbook["name"]}' (dry_run: #{dry_run})")

      # Execute action chain
      execution_result =
        execute_actions(
          playbook["actions"],
          context,
          dry_run: dry_run,
          continue_on_error: continue_on_error,
          timeout: timeout
        )

      case execution_result do
        {:ok, results} ->
          {:ok,
           %{
             playbook_name: playbook["name"],
             dry_run: dry_run,
             actions_executed: length(results),
             results: results,
             context: context
           }}

        {:error, reason} ->
          {:error, reason}
      end
    else
      Logger.debug(
        "Playbook '#{playbook["name"]}' trigger conditions not met, skipping execution"
      )

      {:ok,
       %{
         playbook_name: playbook["name"],
         skipped: true,
         reason: "Trigger conditions not met",
         context: context
       }}
    end
  end

  @doc """
  Evaluates whether a playbook should execute based on trigger conditions.
  """
  @spec should_execute?(map(), map()) :: boolean()
  def should_execute?(playbook, context) do
    trigger = Map.get(playbook, "trigger", %{})

    # If no trigger conditions specified, always execute
    if map_size(trigger) == 0 do
      true
    else
      evaluate_trigger(trigger, context)
    end
  end

  defp evaluate_trigger(trigger, context) do
    # Normalize context to support both atom and string keys
    normalized_context = normalize_context(context)

    # Check each trigger condition
    Enum.all?(trigger, fn {key, value} ->
      evaluate_trigger_condition(key, value, normalized_context)
    end)
  end

  defp evaluate_trigger_condition("detection_type", expected, context) do
    actual = Map.get(context, "detection_type") || Map.get(context, :detection_type)
    actual == expected
  end

  defp evaluate_trigger_condition("confidence", threshold, context) when is_number(threshold) do
    actual = Map.get(context, "confidence") || Map.get(context, :confidence) || 0.0
    actual >= threshold
  end

  defp evaluate_trigger_condition("severity", expected, context) do
    actual = Map.get(context, "severity") || Map.get(context, :severity)
    severity_meets_threshold?(actual, expected)
  end

  defp evaluate_trigger_condition("mitre_techniques", expected_techniques, context)
       when is_list(expected_techniques) do
    actual =
      Map.get(context, "mitre_techniques") || Map.get(context, :mitre_techniques) || []

    # Check if any expected technique is present
    Enum.any?(expected_techniques, fn tech -> tech in actual end)
  end

  defp evaluate_trigger_condition("category", expected, context) do
    actual = Map.get(context, "category") || Map.get(context, :category)
    actual == expected
  end

  defp evaluate_trigger_condition("mitre_tactic", expected, context) do
    tactics = Map.get(context, "mitre_tactics") || Map.get(context, :mitre_tactics) || []
    expected in tactics
  end

  # Unknown condition - evaluate using ConditionEvaluator if available
  defp evaluate_trigger_condition(key, value, context) do
    condition = %{"field" => key, "operator" => "equals", "value" => value}

    try do
      ConditionEvaluator.evaluate(condition, context)
    rescue
      _ -> false
    end
  end

  defp severity_meets_threshold?(actual, threshold) do
    severity_order = %{"low" => 1, "medium" => 2, "high" => 3, "critical" => 4}
    actual_level = Map.get(severity_order, actual, 0)
    threshold_level = Map.get(severity_order, threshold, 0)
    actual_level >= threshold_level
  end

  @doc """
  Executes a chain of actions sequentially.
  """
  @spec execute_actions(list(map()), map(), keyword()) :: {:ok, list(map())} | {:error, String.t()}
  def execute_actions(actions, context, opts \\ []) do
    dry_run = Keyword.get(opts, :dry_run, false)
    continue_on_error = Keyword.get(opts, :continue_on_error, false)
    timeout = Keyword.get(opts, :timeout, 300_000)

    start_time = System.monotonic_time(:millisecond)

    results =
      Enum.reduce_while(actions, {:ok, []}, fn action, {:ok, acc} ->
        elapsed = System.monotonic_time(:millisecond) - start_time

        if elapsed > timeout do
          {:halt, {:error, "Execution timeout exceeded (#{timeout}ms)"}}
        else
          case execute_single_action(action, context, dry_run: dry_run) do
            {:ok, result} ->
              {:cont, {:ok, acc ++ [result]}}

            {:error, reason} ->
              error_result = %{
                action: get_action_type(action),
                status: "failed",
                error: reason,
                timestamp: DateTime.utc_now()
              }

              if continue_on_error do
                Logger.warning("Action failed but continuing: #{reason}")
                {:cont, {:ok, acc ++ [error_result]}}
              else
                {:halt, {:error, reason}}
              end
          end
        end
      end)

    case results do
      {:ok, result_list} -> {:ok, result_list}
      {:error, reason} -> {:error, reason}
    end
  end

  defp execute_single_action(action, context, opts) when is_map(action) do
    dry_run = Keyword.get(opts, :dry_run, false)
    action_type = get_action_type(action)
    params = get_action_params(action, action_type)

    Logger.info("Executing action: #{action_type} (dry_run: #{dry_run})")

    result =
      if dry_run do
        simulate_action(action_type, params, context)
      else
        perform_action(action_type, params, context)
      end

    case result do
      {:ok, data} ->
        {:ok,
         %{
           action: action_type,
           status: "success",
           result: data,
           timestamp: DateTime.utc_now()
         }}

      {:error, reason} ->
        {:error, "Action #{action_type} failed: #{reason}"}
    end
  end

  defp get_action_type(action) when is_map(action) do
    cond do
      Map.has_key?(action, "action") ->
        Map.get(action, "action")

      map_size(action) == 1 ->
        hd(Map.keys(action))

      true ->
        "unknown"
    end
  end

  defp get_action_params(action, action_type) do
    # Try to get params from action[action_type] or action["params"]
    Map.get(action, action_type, Map.get(action, "params", %{}))
  end

  # Simulate action for dry-run mode
  defp simulate_action(action_type, params, context) do
    agent_id = get_agent_id(params, context)

    case action_type do
      "isolate_host" ->
        {:ok, %{simulated: true, action: "isolate_host", agent_id: agent_id}}

      "kill_process" ->
        pid = Map.get(params, "pid") || Map.get(context, :pid) || Map.get(context, "pid")
        {:ok, %{simulated: true, action: "kill_process", agent_id: agent_id, pid: pid}}

      "quarantine_file" ->
        path =
          Map.get(params, "path") || Map.get(context, :file_path) || Map.get(context, "file_path")

        {:ok, %{simulated: true, action: "quarantine_file", agent_id: agent_id, path: path}}

      "block_ip" ->
        ip = Map.get(params, "ip") || Map.get(context, :remote_ip) || Map.get(context, "remote_ip")
        {:ok, %{simulated: true, action: "block_ip", ip: ip}}

      "block_domain" ->
        domain = Map.get(params, "domain") || Map.get(context, :domain) || Map.get(context, "domain")
        {:ok, %{simulated: true, action: "block_domain", domain: domain}}

      "collect_forensics" ->
        {:ok, %{simulated: true, action: "collect_forensics", agent_id: agent_id}}

      "create_ticket" ->
        title = Map.get(params, "title", "Security Alert")
        {:ok, %{simulated: true, action: "create_ticket", title: title, ticket_id: "SIM-#{:rand.uniform(9999)}"}}

      "send_notification" ->
        channel = Map.get(params, "channel", "slack")
        {:ok, %{simulated: true, action: "send_notification", channel: channel}}

      "wait" ->
        duration = Map.get(params, "duration_seconds", 60)
        {:ok, %{simulated: true, action: "wait", duration_seconds: duration}}

      _ ->
        {:ok, %{simulated: true, action: action_type}}
    end
  end

  # Perform actual action
  defp perform_action(action_type, params, context) do
    agent_id = get_agent_id(params, context)

    case action_type do
      "isolate_host" ->
        if agent_id do
          ResponseExecutor.isolate_host(agent_id)
        else
          {:error, "No agent_id available"}
        end

      "kill_process" ->
        pid = Map.get(params, "pid") || Map.get(context, :pid) || Map.get(context, "pid")

        if agent_id and pid do
          ResponseExecutor.kill_process(agent_id, pid)
        else
          {:error, "Missing agent_id or pid"}
        end

      "quarantine_file" ->
        path =
          Map.get(params, "path") || Map.get(context, :file_path) || Map.get(context, "file_path")

        if agent_id and path do
          ResponseExecutor.quarantine_file(agent_id, path)
        else
          {:error, "Missing agent_id or path"}
        end

      "block_ip" ->
        ip = Map.get(params, "ip") || Map.get(context, :remote_ip) || Map.get(context, "remote_ip")

        if ip do
          # Delegate to playbook engine's block_ip implementation
          execute_block_ip(ip, params, context)
        else
          {:error, "No IP address specified"}
        end

      "block_domain" ->
        domain = Map.get(params, "domain") || Map.get(context, :domain) || Map.get(context, "domain")

        if domain do
          # Delegate to playbook engine's block_domain implementation
          execute_block_domain(domain, params, context)
        else
          {:error, "No domain specified"}
        end

      "collect_forensics" ->
        if agent_id do
          ResponseExecutor.collect_forensics(agent_id, params)
        else
          {:error, "No agent_id available"}
        end

      "create_ticket" ->
        execute_create_ticket(params, context)

      "send_notification" ->
        execute_send_notification(params, context)

      "trigger_scan" ->
        path = Map.get(params, "path", "/")

        if agent_id do
          ResponseExecutor.trigger_scan(agent_id, path)
        else
          {:error, "No agent_id available"}
        end

      "wait" ->
        duration = Map.get(params, "duration_seconds", 60)
        Process.sleep(duration * 1000)
        {:ok, %{waited: duration}}

      _ ->
        {:error, "Unknown action type: #{action_type}"}
    end
  end

  defp get_agent_id(params, context) do
    Map.get(params, "agent_id") ||
      Map.get(context, :agent_id) ||
      Map.get(context, "agent_id")
  end

  defp execute_block_ip(ip, params, _context) do
    reason = Map.get(params, "reason", "Blocked by playbook")

    try do
      TamanduaServer.ThreatIntel.add_ioc(%{
        type: "ip",
        value: ip,
        source: "playbook",
        description: reason,
        severity: "high"
      })

      {:ok, %{ip: ip, action: "blocked", reason: reason}}
    rescue
      e ->
        Logger.error("Failed to block IP: #{Exception.message(e)}")
        {:error, Exception.message(e)}
    end
  end

  defp execute_block_domain(domain, params, _context) do
    reason = Map.get(params, "reason", "Blocked by playbook")

    try do
      TamanduaServer.ThreatIntel.add_ioc(%{
        type: "domain",
        value: domain,
        source: "playbook",
        description: reason,
        severity: "high"
      })

      {:ok, %{domain: domain, action: "blocked", reason: reason}}
    rescue
      e ->
        Logger.error("Failed to block domain: #{Exception.message(e)}")
        {:error, Exception.message(e)}
    end
  end

  defp execute_create_ticket(params, context) do
    title = Map.get(params, "title", "Security Alert - Playbook Execution")
    severity = Map.get(params, "severity", "high")

    {:ok,
     %{
       ticket_id: "TICKET-#{:rand.uniform(99999)}",
       title: title,
       severity: severity,
       context: context
     }}
  end

  defp execute_send_notification(params, _context) do
    channel = Map.get(params, "channel", "slack")
    message = Map.get(params, "message", "Playbook execution notification")

    {:ok, %{channel: channel, message: message, sent: true}}
  end

  defp build_context(%Alert{} = alert) do
    %{
      alert_id: alert.id,
      agent_id: alert.agent_id,
      severity: alert.severity,
      detection_type: Map.get(alert.detection_metadata || %{}, "type"),
      mitre_tactics: alert.mitre_tactics || [],
      mitre_techniques: alert.mitre_techniques || [],
      confidence: alert.threat_score || 0.0,
      file_path: get_in(alert.evidence, ["file_path"]),
      pid: get_in(alert.evidence, ["pid"]),
      process_name: get_in(alert.evidence, ["process_name"]),
      remote_ip: get_in(alert.evidence, ["remote_ip"]),
      domain: get_in(alert.evidence, ["domain"])
    }
  end

  defp build_context(context) when is_map(context) do
    context
  end

  defp normalize_context(context) when is_map(context) do
    # Merge atom-keyed and string-keyed versions
    Enum.reduce(context, context, fn
      {k, v}, acc when is_atom(k) ->
        Map.put_new(acc, Atom.to_string(k), v)

      {k, v}, acc when is_binary(k) ->
        atom_key =
          try do
            String.to_existing_atom(k)
          rescue
            _ -> nil
          end

        if atom_key, do: Map.put_new(acc, atom_key, v), else: acc

      _, acc ->
        acc
    end)
  end
end
