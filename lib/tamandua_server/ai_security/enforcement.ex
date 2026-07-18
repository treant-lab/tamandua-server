defmodule TamanduaServer.AISecurity.Enforcement do
  @moduledoc """
  Endpoint enforcement bridge for AI Gateway policy decisions.

  The AI Gateway remains metadata-only. When a policy explicitly decides to
  block and `enforce_block` is enabled, this module translates that decision
  into conservative endpoint response actions. It prefers domain blocking over
  IP blocking because AI providers commonly sit behind shared cloud/CDN IPs.
  """

  require Logger

  import Ecto.Query

  alias TamanduaServer.Agents.{AgentCommand, CommandManager}
  alias TamanduaServer.Repo

  @dedup_table :ai_gateway_endpoint_enforcement
  @dedup_ttl_ms :timer.minutes(30)
  @source "ai_gateway"

  @type action ::
          {:block_domain, String.t(), map()}
          | {:block_ip, String.t(), map()}
          | {:skip, atom(), String.t()}

  @doc """
  Plans the safest endpoint action for an AI Gateway event.
  """
  @spec plan_action(map()) :: action()
  def plan_action(event) when is_map(event) do
    decision = normalize_string(field(event, :policy_decision) || field(event, :decision))
    enforced? = truthy?(field(event, :policy_enforced))
    agent_id = field(event, :agent_id)
    classification = normalize_string(field(event, :classification))
    domain = normalize_domain(field(event, :domain))
    remote_ip = metadata_field(event, :remote_ip)

    cond do
      decision != "block" or not enforced? ->
        {:skip, :not_enforced, "Policy did not request enforced blocking"}

      blank?(agent_id) ->
        {:skip, :missing_agent, "Endpoint block requires an agent_id"}

      classification in ["local_inference", "local_ai_workspace"] ->
        {:skip, :local_inference, "Local AI usage requires process/app-control enforcement"}

      valid_block_domain?(domain) ->
        {:block_domain, domain, action_payload(event, "block_domain", domain)}

      public_ip?(remote_ip) ->
        {:block_ip, remote_ip, action_payload(event, "block_ip", remote_ip)}

      true ->
        {:skip, :missing_target, "No safe domain or public IP target available"}
    end
  end

  def plan_action(_), do: {:skip, :invalid_event, "Invalid AI Gateway event"}

  @doc """
  Applies a planned endpoint enforcement action.

  By default this queues a persistent agent command through `CommandManager`.
  Tests can pass `command_sender: fun` to avoid touching the database or agent
  registry.
  """
  @spec enforce_event(map(), keyword()) ::
          {:ok, map()}
          | {:skipped, atom(), String.t()}
          | {:error, term()}
  def enforce_event(event, opts \\ [])

  def enforce_event(event, opts) when is_map(event) do
    case plan_action(event) do
      {:block_domain, domain, payload} ->
        queue_once(event, "block_domain", domain, payload, opts)

      {:block_ip, ip, payload} ->
        queue_once(event, "block_ip", ip, payload, opts)

      {:skip, reason, message} ->
        {:skipped, reason, message}
    end
  rescue
    e ->
      Logger.debug("[AIEnforcement] Enforcement skipped: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  catch
    _, reason -> {:error, reason}
  end

  def enforce_event(_, _), do: {:skipped, :invalid_event, "Invalid AI Gateway event"}

  @doc """
  Returns the operator-facing enforcement state for an AI Gateway event.

  The AI Gateway itself is not an inline proxy. This summary only reports the
  endpoint action bridge plan and, when available, the persisted AgentCommand
  lifecycle for the deterministic action key.
  """
  @spec summarize_event(map()) :: map()
  def summarize_event(event) when is_map(event) do
    base = %{
      requested: field(event, :policy_enforced) == true,
      mode: "endpoint_action_bridge",
      target_agent_id: field(event, :agent_id),
      inline_proxy: false,
      result_tracked: false,
      rollback_available: false
    }

    case plan_action(event) do
      {:block_domain, domain, _payload} ->
        summarize_planned_action(event, base, "block_domain", domain)

      {:block_ip, ip, _payload} ->
        summarize_planned_action(event, base, "block_ip", ip)

      {:skip, :not_enforced, message} ->
        Map.merge(base, %{
          status: "decision_only",
          reason: message
        })

      {:skip, reason, message} ->
        Map.merge(base, %{
          status: if(field(event, :policy_enforced) == true, do: "failed", else: "decision_only"),
          reason: message,
          failure_code: reason
        })
    end
  rescue
    e ->
      %{
        requested: field(event, :policy_enforced) == true,
        mode: "endpoint_action_bridge",
        target_agent_id: field(event, :agent_id),
        inline_proxy: false,
        result_tracked: false,
        rollback_available: false,
        status: "failed",
        reason: Exception.message(e),
        failure_code: :summary_failed
      }
  end

  def summarize_event(_), do: summarize_event(%{})

  defp queue_once(event, command_type, target, payload, opts) do
    agent_id = field(event, :agent_id)
    dedup_key = {agent_id, command_type, target}
    idempotency_key = action_idempotency_key(agent_id, command_type, target)
    payload = Map.put(payload, "idempotency_key", idempotency_key)

    case remember_once(dedup_key, Keyword.get(opts, :now_ms, now_ms())) do
      :duplicate ->
        {:skipped, :duplicate, "Equivalent endpoint enforcement action was already queued"}

      :ok ->
        sender = Keyword.get(opts, :command_sender, &default_command_sender/3)

        case sender.(agent_id, command_type, payload) do
          {:ok, command} ->
            Logger.info(
              "[AIEnforcement] Queued #{command_type} for #{agent_id} target=#{target}"
            )

            {:ok,
             %{
               agent_id: agent_id,
               action: command_type,
               target: target,
               command: command
             }}

          {:error, reason} ->
            forget(dedup_key)
            Logger.warning(
              "[AIEnforcement] Failed to queue #{command_type} for #{agent_id}: #{inspect(reason)}"
            )

            {:error, reason}

          other ->
            {:ok, %{agent_id: agent_id, action: command_type, target: target, command: other}}
        end
    end
  end

  defp default_command_sender(agent_id, command_type, payload) do
    CommandManager.queue_command(agent_id, command_type, payload,
      priority: 8,
      timeout: 3600,
      idempotency_key: Map.get(payload, "idempotency_key")
    )
  end

  defp summarize_planned_action(event, base, command_type, target) do
    key = action_idempotency_key(field(event, :agent_id), command_type, target)

    base
    |> Map.merge(%{
      action: command_type,
      target: target,
      action_id: key,
      idempotency_key: key,
      rollback_available: true
    })
    |> merge_command_status(latest_command(field(event, :agent_id), key))
  end

  defp latest_command(agent_id, idempotency_key) when is_binary(agent_id) and is_binary(idempotency_key) do
    Repo.one(
      from(c in AgentCommand,
        where: c.agent_id == ^agent_id and c.idempotency_key == ^idempotency_key,
        order_by: [desc: c.inserted_at],
        limit: 1
      )
    )
  rescue
    _ -> nil
  end

  defp latest_command(_, _), do: nil

  defp merge_command_status(summary, nil) do
    Map.merge(summary, %{
      status: "requested",
      result_tracked: false,
      reason: "endpoint_action_requested_async"
    })
  end

  defp merge_command_status(summary, %AgentCommand{} = command) do
    Map.merge(summary, %{
      status: command_status(command.status),
      result_tracked: true,
      command_status: command.status,
      command_id: command.id,
      queued_at: command.inserted_at,
      sent_at: command.sent_at,
      acknowledged_at: command.acknowledged_at,
      completed_at: command.completed_at,
      failed_reason: command.error,
      result: command.result,
      reason: command_reason(command)
    })
  end

  defp command_status("completed"), do: "succeeded"
  defp command_status("failed"), do: "failed"
  defp command_status(status) when status in ["pending", "sent", "acknowledged"], do: "pending"
  defp command_status(_), do: "requested"

  defp command_reason(%AgentCommand{status: "completed"}), do: "agent_command_completed"
  defp command_reason(%AgentCommand{status: "failed", error: error}) when not is_nil(error), do: error
  defp command_reason(%AgentCommand{status: status}), do: "agent_command_#{status}"

  defp action_idempotency_key(agent_id, command_type, target) do
    material =
      ["ai_gateway", agent_id, command_type, target]
      |> Enum.map(&to_string/1)
      |> Enum.join(":")

    digest =
      :crypto.hash(:sha256, material)
      |> Base.encode16(case: :lower)

    "ai_gateway:" <> digest
  end

  defp action_payload(event, command_type, target) do
    %{
      "source" => @source,
      "reason" => reason(event),
      "policy_id" => field(event, :policy_id),
      "policy_decision" => field(event, :policy_decision),
      "provider" => field(event, :provider),
      "domain" => if(command_type == "block_domain", do: target, else: field(event, :domain)),
      "ip" => if(command_type == "block_ip", do: target, else: nil),
      "direction" => "outbound",
      "trace_id" => field(event, :trace_id) || field(event, :id)
    }
    |> reject_blank_values()
  end

  defp reason(event) do
    reasons =
      event
      |> field(:policy_reasons)
      |> List.wrap()
      |> Enum.map(&to_string/1)
      |> Enum.reject(&blank?/1)

    case reasons do
      [] -> "ai_gateway_policy_block"
      values -> "ai_gateway_policy_block:" <> Enum.join(values, ",")
    end
  end

  defp remember_once(key, now) do
    ensure_table()
    prune(now)

    case :ets.lookup(@dedup_table, key) do
      [{^key, expires_at}] when expires_at > now ->
        :duplicate

      _ ->
        :ets.insert(@dedup_table, {key, now + @dedup_ttl_ms})
        :ok
    end
  end

  defp forget(key) do
    ensure_table()
    :ets.delete(@dedup_table, key)
  end

  defp prune(now) do
    @dedup_table
    |> :ets.tab2list()
    |> Enum.each(fn
      {key, expires_at} when expires_at <= now -> :ets.delete(@dedup_table, key)
      _ -> :ok
    end)
  end

  defp ensure_table do
    if :ets.whereis(@dedup_table) == :undefined do
      :ets.new(@dedup_table, [:set, :named_table, :public, read_concurrency: true])
    end

    :ok
  end

  defp valid_block_domain?(domain) do
    not blank?(domain) and
      not String.contains?(domain, ":") and
      not local_domain?(domain) and
      String.contains?(domain, ".")
  end

  defp local_domain?(domain),
    do: domain in ["localhost"] or String.ends_with?(domain, ".local")

  defp public_ip?(value) when is_binary(value) do
    with {:ok, ip} <- value |> String.to_charlist() |> :inet.parse_address() do
      not private_ip?(ip)
    else
      _ -> false
    end
  end

  defp public_ip?(_), do: false

  defp private_ip?({10, _, _, _}), do: true
  defp private_ip?({127, _, _, _}), do: true
  defp private_ip?({169, 254, _, _}), do: true
  defp private_ip?({172, second, _, _}) when second >= 16 and second <= 31, do: true
  defp private_ip?({192, 168, _, _}), do: true
  defp private_ip?({0, _, _, _}), do: true
  defp private_ip?({224, _, _, _}), do: true
  defp private_ip?({255, 255, 255, 255}), do: true
  defp private_ip?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  defp private_ip?({0xFE80, _, _, _, _, _, _, _}), do: true
  defp private_ip?({0xFC00, _, _, _, _, _, _, _}), do: true
  defp private_ip?({0xFD00, _, _, _, _, _, _, _}), do: true
  defp private_ip?(_), do: false

  defp metadata_field(event, key) do
    metadata = field(event, :metadata) || %{}
    field(metadata, key)
  end

  defp field(map, key) when is_map(map), do: Map.get(map, key) || Map.get(map, to_string(key))
  defp field(_, _), do: nil

  defp normalize_domain(value) when is_binary(value) do
    value
    |> String.trim()
    |> String.downcase()
    |> String.trim_trailing(".")
    |> String.trim_leading(".")
  end

  defp normalize_domain(_), do: nil

  defp normalize_string(value) when is_binary(value), do: value |> String.trim() |> String.downcase()
  defp normalize_string(value) when is_atom(value), do: value |> Atom.to_string() |> normalize_string()
  defp normalize_string(_), do: ""

  defp truthy?(value), do: value in [true, "true", "1", 1]

  defp blank?(value), do: value in [nil, ""]

  defp reject_blank_values(map) do
    map
    |> Enum.reject(fn {_key, value} -> value in [nil, ""] end)
    |> Map.new()
  end

  defp now_ms, do: System.system_time(:millisecond)
end
