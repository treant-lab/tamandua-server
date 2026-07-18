defmodule TamanduaServer.LiveResponse.EvidenceSessionContext do
  @moduledoc """
  Bounded, tenant-scoped process/network telemetry context for an evidence session.

  A successful query with no matching rows is `not_observed`. Repository or
  collector failure is `unavailable`; the two states are never conflated.
  """

  import Ecto.Query

  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Telemetry.Event

  @schema_version "tamandua.evidence_session_context/v1"
  @default_limit 250
  @max_limit 500
  @max_window_seconds 3_600
  @max_context_events 50

  @process_types ~w(process_create process_start process_exec process_terminate)
  @network_types ~w(network_connect network_listen network_flow network_accept network_close dns_query dns_response dns)
  @event_types @process_types ++ @network_types
  @payload_atom_keys ~w(
    pid process_id ppid parent_pid parent_process_id process_name name image exe
    executable_path path image_path command_line cmdline commandline username user user_name
    source_ip local_ip source_port local_port dest_ip destination_ip remote_ip dest_port
    destination_port remote_port protocol query_name query domain dns_query
  )a
  @payload_atom_key_by_string Map.new(@payload_atom_keys, &{Atom.to_string(&1), &1})

  def schema_version, do: @schema_version

  @spec build(String.t(), String.t(), DateTime.t(), DateTime.t(), keyword()) ::
          {:ok, map()} | {:error, atom()}
  def build(organization_id, agent_id, window_start, window_end, opts \\ []) do
    with {:ok, organization_id} <- cast_uuid(organization_id),
         {:ok, agent_id} <- cast_uuid(agent_id),
         {:ok, window_start} <- cast_datetime(window_start),
         {:ok, window_end} <- cast_datetime(window_end),
         :ok <- validate_window(window_start, window_end),
         {:ok, limit} <- normalize_limit(Keyword.get(opts, :limit, @default_limit)) do
      loader = Keyword.get(opts, :loader, &load_scoped_events/5)

      generated_at =
        Keyword.get(opts, :now, DateTime.utc_now()) |> DateTime.truncate(:microsecond)

      case safe_load(loader, organization_id, agent_id, window_start, window_end, limit) do
        {:ok, events} when is_list(events) ->
          {:ok,
           context(
             organization_id,
             agent_id,
             window_start,
             window_end,
             generated_at,
             Enum.take(events, limit),
             limit
           )}

        {:error, :agent_not_found} ->
          {:error, :not_found}

        {:error, _reason} ->
          {:ok,
           unavailable_context(
             organization_id,
             agent_id,
             window_start,
             window_end,
             generated_at,
             limit
           )}
      end
    end
  end

  defp load_scoped_events(organization_id, agent_id, window_start, window_end, limit) do
    MultiTenant.with_organization(organization_id, fn ->
      agent_exists? =
        Agent
        |> where([agent], agent.id == ^agent_id and agent.organization_id == ^organization_id)
        |> select([agent], agent.id)
        |> Repo.one()

      if is_nil(agent_exists?) do
        {:error, :agent_not_found}
      else
        events =
          Event
          |> where(
            [event],
            event.organization_id == ^organization_id and event.agent_id == ^agent_id and
              event.timestamp >= ^window_start and event.timestamp <= ^window_end and
              event.event_type in ^@event_types
          )
          |> order_by([event], asc: event.timestamp, asc: event.id)
          |> limit(^limit)
          |> Repo.all()

        {:ok, events}
      end
    end)
  end

  defp safe_load(loader, organization_id, agent_id, window_start, window_end, limit) do
    loader.(organization_id, agent_id, window_start, window_end, limit)
  rescue
    _ -> {:error, :query_failed}
  catch
    :exit, _ -> {:error, :query_failed}
  end

  defp context(organization_id, agent_id, window_start, window_end, generated_at, events, limit) do
    process_events = Enum.filter(events, &(&1.event_type in @process_types))
    network_events = Enum.filter(events, &(&1.event_type in @network_types))

    base_context(organization_id, agent_id, window_start, window_end, generated_at, limit)
    |> Map.put(:process, observed_source(process_events, &process_summary/1))
    |> Map.put(:network, observed_source(network_events, &network_summary/1))
  end

  defp unavailable_context(
         organization_id,
         agent_id,
         window_start,
         window_end,
         generated_at,
         limit
       ) do
    unavailable = %{
      state: "unavailable",
      reason: "telemetry_query_unavailable",
      observed_count: nil,
      events: [],
      truncated: false
    }

    base_context(organization_id, agent_id, window_start, window_end, generated_at, limit)
    |> Map.put(:process, unavailable)
    |> Map.put(:network, unavailable)
  end

  defp base_context(organization_id, agent_id, window_start, window_end, generated_at, limit) do
    %{
      schema_version: @schema_version,
      organization_id: organization_id,
      agent_id: agent_id,
      window: %{
        from: DateTime.to_iso8601(window_start),
        to: DateTime.to_iso8601(window_end),
        inclusive: true
      },
      query_limit: limit,
      generated_at: DateTime.to_iso8601(generated_at)
    }
  end

  defp observed_source([], _mapper) do
    %{
      state: "not_observed",
      reason: "no_matching_events_in_window",
      observed_count: 0,
      events: [],
      truncated: false
    }
  end

  defp observed_source(events, mapper) do
    %{
      state: "observed",
      reason: nil,
      observed_count: length(events),
      events: events |> Enum.take(@max_context_events) |> Enum.map(mapper),
      truncated: length(events) > @max_context_events
    }
  end

  defp process_summary(event) do
    payload = payload(event)

    compact(%{
      event_id: event.id,
      event_type: event.event_type,
      timestamp: iso8601(event.timestamp),
      pid: bounded_integer(value(payload, ~w(pid process_id))),
      parent_pid: bounded_integer(value(payload, ~w(ppid parent_pid parent_process_id))),
      process_name: bounded_string(value(payload, ~w(process_name name image exe)), 512),
      executable_path: bounded_string(value(payload, ~w(executable_path path image_path)), 2_048),
      command_line: bounded_string(value(payload, ~w(command_line cmdline commandline)), 2_048),
      user: bounded_string(value(payload, ~w(username user user_name)), 256)
    })
  end

  defp network_summary(event) do
    payload = payload(event)

    compact(%{
      event_id: event.id,
      event_type: event.event_type,
      timestamp: iso8601(event.timestamp),
      pid: bounded_integer(value(payload, ~w(pid process_id))),
      process_name: bounded_string(value(payload, ~w(process_name name)), 512),
      source_ip: bounded_string(value(payload, ~w(source_ip local_ip)), 128),
      source_port: bounded_integer(value(payload, ~w(source_port local_port))),
      destination_ip: bounded_string(value(payload, ~w(dest_ip destination_ip remote_ip)), 128),
      destination_port:
        bounded_integer(value(payload, ~w(dest_port destination_port remote_port))),
      protocol: bounded_string(value(payload, ~w(protocol)), 32),
      domain: bounded_string(value(payload, ~w(query_name query domain dns_query)), 512)
    })
  end

  defp payload(%{payload: payload}) when is_map(payload), do: payload
  defp payload(_event), do: %{}

  defp value(payload, keys) do
    Enum.find_value(keys, fn key ->
      Map.get(payload, key) || Map.get(payload, Map.fetch!(@payload_atom_key_by_string, key))
    end)
  end

  defp bounded_string(nil, _limit), do: nil

  defp bounded_string(value, limit) do
    value
    |> to_string()
    |> redact_secrets()
    |> String.slice(0, limit)
  end

  defp redact_secrets(value) do
    value
    |> then(&Regex.replace(~r/(?i)(bearer\s+)[^\s]+/, &1, "\\1[REDACTED]"))
    |> then(
      &Regex.replace(
        ~r/(?i)((?:token|password|passwd|secret|api[_-]?key)\s*[=:]\s*)[^\s&]+/,
        &1,
        "\\1[REDACTED]"
      )
    )
    |> then(
      &Regex.replace(
        ~r/(?i)(--(?:token|password|secret|api-key)\s+)[^\s]+/,
        &1,
        "\\1[REDACTED]"
      )
    )
  end

  defp bounded_integer(value) when is_integer(value) and value >= 0, do: value

  defp bounded_integer(value) when is_binary(value) do
    case Integer.parse(value) do
      {integer, ""} when integer >= 0 -> integer
      _ -> nil
    end
  end

  defp bounded_integer(_value), do: nil
  defp compact(map), do: Map.reject(map, fn {_key, value} -> is_nil(value) or value == "" end)
  defp iso8601(%DateTime{} = value), do: DateTime.to_iso8601(value)
  defp iso8601(_value), do: nil

  defp cast_uuid(value) do
    case Ecto.UUID.cast(value) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, :invalid_scope}
    end
  end

  defp cast_datetime(%DateTime{} = value), do: {:ok, DateTime.truncate(value, :microsecond)}

  defp cast_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> {:ok, DateTime.truncate(datetime, :microsecond)}
      _ -> {:error, :invalid_window}
    end
  end

  defp cast_datetime(_value), do: {:error, :invalid_window}

  defp validate_window(window_start, window_end) do
    duration = DateTime.diff(window_end, window_start, :second)

    if duration >= 0 and duration <= @max_window_seconds,
      do: :ok,
      else: {:error, :invalid_window}
  end

  defp normalize_limit(limit) when is_integer(limit) and limit > 0,
    do: {:ok, min(limit, @max_limit)}

  defp normalize_limit(_limit), do: {:error, :invalid_limit}
end
