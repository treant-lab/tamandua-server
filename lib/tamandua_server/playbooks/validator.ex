defmodule TamanduaServer.Playbooks.Validator do
  @moduledoc """
  YAML playbook validation for automated incident response.

  Validates playbook structure, trigger conditions, and action chains
  to ensure they can be safely executed by the playbook engine.
  """

  require Logger

  @valid_actions [
    "isolate_host",
    "kill_process",
    "quarantine_file",
    "block_ip",
    "block_domain",
    "collect_forensics",
    "create_ticket",
    "send_notification",
    "run_script",
    "enrich_ioc",
    "update_blocklist",
    "trigger_scan",
    "disable_user",
    "conditional",
    "wait",
    "human_approval",
    "parallel"
  ]

  @valid_detection_types [
    "ransomware",
    "malware",
    "lateral_movement",
    "credential_theft",
    "data_exfiltration",
    "command_and_control",
    "privilege_escalation",
    "persistence",
    "defense_evasion"
  ]

  @valid_severities ["low", "medium", "high", "critical"]

  @doc """
  Validates a YAML playbook string or parsed map.

  Returns {:ok, playbook_map} if valid, {:error, reasons} if invalid.
  """
  @spec validate(String.t() | map()) :: {:ok, map()} | {:error, list(String.t())}
  def validate(yaml_string) when is_binary(yaml_string) do
    case YamlElixir.read_from_string(yaml_string) do
      {:ok, playbook} when is_map(playbook) ->
        validate(playbook)

      {:ok, _} ->
        {:error, ["Invalid YAML: root must be an object/map"]}

      {:error, %YamlElixir.ParsingError{message: message}} ->
        {:error, ["YAML parsing error: #{message}"]}

      {:error, reason} ->
        {:error, ["YAML parsing error: #{inspect(reason)}"]}
    end
  end

  def validate(playbook) when is_map(playbook) do
    errors =
      []
      |> validate_required_fields(playbook)
      |> validate_name(playbook)
      |> validate_trigger(playbook)
      |> validate_actions(playbook)

    if Enum.empty?(errors) do
      {:ok, playbook}
    else
      {:error, errors}
    end
  end

  def validate(_) do
    {:error, ["Playbook must be a map/object"]}
  end

  # Private validation functions

  defp validate_required_fields(errors, playbook) do
    required = ["name", "trigger", "actions"]

    missing =
      Enum.filter(required, fn field ->
        not Map.has_key?(playbook, field)
      end)

    if Enum.empty?(missing) do
      errors
    else
      errors ++ ["Missing required fields: #{Enum.join(missing, ", ")}"]
    end
  end

  defp validate_name(errors, playbook) do
    case Map.get(playbook, "name") do
      name when is_binary(name) and byte_size(name) > 0 ->
        errors

      name when is_binary(name) ->
        errors ++ ["Name cannot be empty"]

      _ ->
        errors ++ ["Name must be a string"]
    end
  end

  defp validate_trigger(errors, playbook) do
    case Map.get(playbook, "trigger") do
      nil ->
        errors

      trigger when is_map(trigger) ->
        errors
        |> validate_detection_type(trigger)
        |> validate_confidence(trigger)
        |> validate_mitre_techniques(trigger)
        |> validate_severity(trigger)

      _ ->
        errors ++ ["Trigger must be an object/map"]
    end
  end

  defp validate_detection_type(errors, trigger) do
    case Map.get(trigger, "detection_type") do
      nil ->
        errors

      type when is_binary(type) ->
        if type in @valid_detection_types do
          errors
        else
          errors ++
            [
              "Invalid detection_type '#{type}'. Must be one of: #{Enum.join(@valid_detection_types, ", ")}"
            ]
        end

      _ ->
        errors ++ ["detection_type must be a string"]
    end
  end

  defp validate_confidence(errors, trigger) do
    case Map.get(trigger, "confidence") do
      nil ->
        errors

      conf when is_number(conf) and conf >= 0.0 and conf <= 1.0 ->
        errors

      conf when is_number(conf) ->
        errors ++ ["confidence must be between 0.0 and 1.0, got #{conf}"]

      _ ->
        errors ++ ["confidence must be a number between 0.0 and 1.0"]
    end
  end

  defp validate_mitre_techniques(errors, trigger) do
    case Map.get(trigger, "mitre_techniques") do
      nil ->
        errors

      techniques when is_list(techniques) ->
        invalid =
          Enum.filter(techniques, fn tech ->
            not is_binary(tech) or not String.match?(tech, ~r/^T\d{4}(\.\d{3})?$/)
          end)

        if Enum.empty?(invalid) do
          errors
        else
          errors ++
            [
              "Invalid MITRE technique IDs: #{inspect(invalid)}. Must match pattern T1234 or T1234.001"
            ]
        end

      _ ->
        errors ++ ["mitre_techniques must be an array of strings"]
    end
  end

  defp validate_severity(errors, trigger) do
    case Map.get(trigger, "severity") do
      nil ->
        errors

      severity when is_binary(severity) ->
        if severity in @valid_severities do
          errors
        else
          errors ++
            [
              "Invalid severity '#{severity}'. Must be one of: #{Enum.join(@valid_severities, ", ")}"
            ]
        end

      _ ->
        errors ++ ["severity must be a string"]
    end
  end

  defp validate_actions(errors, playbook) do
    case Map.get(playbook, "actions") do
      nil ->
        errors

      actions when is_list(actions) and length(actions) > 0 ->
        errors
        |> validate_action_chain(actions)

      actions when is_list(actions) ->
        errors ++ ["actions cannot be empty"]

      _ ->
        errors ++ ["actions must be an array"]
    end
  end

  defp validate_action_chain(errors, actions) do
    actions
    |> Enum.with_index()
    |> Enum.reduce(errors, fn {action, index}, acc ->
      validate_single_action(acc, action, index)
    end)
  end

  defp validate_single_action(errors, action, index) when is_map(action) do
    position = "actions[#{index}]"

    # Extract action type from the map (could be the key or a field)
    action_type =
      cond do
        Map.has_key?(action, "action") -> Map.get(action, "action")
        map_size(action) == 1 -> hd(Map.keys(action))
        true -> nil
      end

    case action_type do
      nil ->
        errors ++ ["#{position}: action type not specified (use 'action' field or single key)"]

      type when is_binary(type) ->
        if type in @valid_actions do
          validate_action_params(errors, type, action, position)
        else
          errors ++
            [
              "#{position}: invalid action type '#{type}'. Must be one of: #{Enum.join(@valid_actions, ", ")}"
            ]
        end

      _ ->
        errors ++ ["#{position}: action type must be a string"]
    end
  end

  defp validate_single_action(errors, _action, index) do
    errors ++ ["actions[#{index}]: each action must be an object/map"]
  end

  defp validate_action_params(errors, action_type, action, position) do
    case action_type do
      "kill_process" ->
        # Can reference context variables
        errors

      "quarantine_file" ->
        # Can reference context variables
        errors

      "isolate_host" ->
        # No required params - uses agent_id from context
        errors

      "block_ip" ->
        validate_has_param_or_context(errors, action, "ip", position)

      "block_domain" ->
        validate_has_param_or_context(errors, action, "domain", position)

      "collect_forensics" ->
        # Optional params only
        errors

      "create_ticket" ->
        # Optional params (title, priority, etc.)
        errors

      "send_notification" ->
        params = Map.get(action, Map.get(action, "action", action_type), %{})

        if is_map(params) do
          channel = Map.get(params, "channel")

          if channel in [nil, "slack", "email", "webhook"] do
            errors
          else
            errors ++
              [
                "#{position}: invalid notification channel '#{channel}'. Must be one of: slack, email, webhook"
              ]
          end
        else
          errors
        end

      "wait" ->
        params = Map.get(action, "wait", %{})

        if is_map(params) do
          case Map.get(params, "duration_seconds") do
            nil ->
              errors ++ ["#{position}: wait action requires duration_seconds parameter"]

            duration when is_number(duration) and duration > 0 ->
              errors

            _ ->
              errors ++ ["#{position}: duration_seconds must be a positive number"]
          end
        else
          errors
        end

      "conditional" ->
        params = Map.get(action, "conditional", %{})

        if is_map(params) do
          cond do
            not Map.has_key?(params, "condition") ->
              errors ++ ["#{position}: conditional action requires 'condition' parameter"]

            not Map.has_key?(params, "true_step") or not Map.has_key?(params, "false_step") ->
              errors ++
                ["#{position}: conditional action requires 'true_step' and 'false_step' parameters"]

            true ->
              errors
          end
        else
          errors
        end

      "parallel" ->
        params = Map.get(action, "parallel", %{})

        case Map.get(params, "steps") do
          nil ->
            errors ++ ["#{position}: parallel action requires 'steps' parameter"]

          steps when is_list(steps) and length(steps) > 0 ->
            # Recursively validate nested steps
            validate_action_chain(errors, steps)

          _ ->
            errors ++ ["#{position}: parallel 'steps' must be a non-empty array"]
        end

      _ ->
        # Other actions are valid with optional params
        errors
    end
  end

  defp validate_has_param_or_context(errors, action, param_name, position) do
    # Check if the parameter is provided directly or can be inferred from context
    action_params = Map.get(action, Map.keys(action) |> List.first(), %{})

    has_param =
      is_map(action_params) and
        (Map.has_key?(action_params, param_name) or
           String.contains?(inspect(action_params), "${#{param_name}}") or
           String.contains?(inspect(action_params), "context.#{param_name}"))

    if has_param do
      errors
    else
      # This is a warning, not a hard error - the param might come from context at runtime
      errors
    end
  end

  @doc """
  Validates an action chain for logical consistency.

  Ensures actions are in a sensible order (e.g., isolate before collect_forensics).
  """
  @spec validate_action_order(list(map())) :: {:ok, :valid} | {:warning, list(String.t())}
  def validate_action_order(actions) when is_list(actions) do
    warnings =
      actions
      |> Enum.map(fn action ->
        get_action_type(action)
      end)
      |> check_order_warnings([])

    if Enum.empty?(warnings) do
      {:ok, :valid}
    else
      {:warning, warnings}
    end
  end

  defp get_action_type(action) when is_map(action) do
    cond do
      Map.has_key?(action, "action") -> Map.get(action, "action")
      map_size(action) == 1 -> hd(Map.keys(action))
      true -> "unknown"
    end
  end

  defp check_order_warnings([], warnings), do: warnings

  defp check_order_warnings([action | rest], warnings) do
    new_warnings =
      case action do
        "collect_forensics" ->
          if "isolate_host" not in Enum.take(rest, -length(rest)) do
            [
              "Consider isolating the host before collecting forensics to prevent evidence tampering"
            ]
          else
            []
          end

        "quarantine_file" ->
          if "kill_process" in rest do
            [
              "Consider killing the process before quarantining the file for better effectiveness"
            ]
          else
            []
          end

        _ ->
          []
      end

    check_order_warnings(rest, warnings ++ new_warnings)
  end

  @doc """
  Quick validation that returns true/false without error details.
  """
  @spec valid?(String.t() | map()) :: boolean()
  def valid?(playbook) do
    case validate(playbook) do
      {:ok, _} -> true
      {:error, _} -> false
    end
  end

  @doc """
  Returns a list of valid action types.
  """
  @spec valid_actions() :: list(String.t())
  def valid_actions, do: @valid_actions

  @doc """
  Returns a list of valid detection types.
  """
  @spec valid_detection_types() :: list(String.t())
  def valid_detection_types, do: @valid_detection_types

  @doc """
  Returns a list of valid severity levels.
  """
  @spec valid_severities() :: list(String.t())
  def valid_severities, do: @valid_severities
end
