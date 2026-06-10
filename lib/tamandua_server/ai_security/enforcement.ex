defmodule TamanduaServer.AISecurity.Enforcement do
  @moduledoc """
  Endpoint enforcement bridge for AI Gateway policy decisions.

  The AI Gateway remains metadata-only. When a policy explicitly decides to
  block and `enforce_block` is enabled, this module translates that decision
  into conservative endpoint response actions. It prefers domain blocking over
  IP blocking because AI providers commonly sit behind shared cloud/CDN IPs.
  """

  require Logger

  alias TamanduaServer.Agents.CommandManager

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

  defp queue_once(event, command_type, target, payload, opts) do
    agent_id = field(event, :agent_id)
    dedup_key = {agent_id, command_type, target}

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
    CommandManager.queue_command(agent_id, command_type, payload, priority: 8, timeout: 3600)
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
