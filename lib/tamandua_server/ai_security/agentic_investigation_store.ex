defmodule TamanduaServer.AISecurity.AgenticInvestigationStore do
  @moduledoc """
  Tenant-scoped durable source for AgenticAnalyst investigation snapshots.

  ETS remains the runtime cache. This store persists a bounded, versioned JSON
  representation and restores only non-terminal records during startup.
  """

  import Ecto.Query

  alias TamanduaServer.AgenticRestoreAuthorityAccess
  alias TamanduaServer.AISecurity.AgenticInvestigationSnapshot
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant

  @snapshot_version 1
  @terminal_states ~w(resolved escalated)
  @max_snapshot_bytes 524_288
  @max_depth 8
  @max_collection_items 200
  @max_string_characters 8_192
  @sensitive_key_fragments ~w(
    password passwordhash mfasecret mfaseed totpsecret recoverycode privatekey
    clientsecret apikey accesstoken refreshtoken authorization credential
  )
  @snapshot_fields ~w(
    id organization_id alert_id state started_at created_at updated_at triage_result
    hypotheses evidence correlations recommendations explanation confidence analyst_feedback
    resolution source analyst_notes timeline persistence_status persistence_error
  )a
  @alert_fields ~w(
    id organization_id agent_id severity mitre_techniques event_ids title description
  )a
  @plain_snapshot_keys Enum.map(@snapshot_fields ++ @alert_fields ++ [:alert], &Atom.to_string/1)

  @spec upsert(map()) :: {:ok, AgenticInvestigationSnapshot.t()} | {:error, atom()}
  def upsert(investigation) when is_map(investigation) do
    with {:ok, attrs} <- snapshot_attrs(investigation) do
      MultiTenant.with_organization(attrs.organization_id, fn ->
        now = DateTime.utc_now()

        if alert_belongs_to_organization?(attrs.alert_id, attrs.organization_id) do
          %AgenticInvestigationSnapshot{}
          |> AgenticInvestigationSnapshot.changeset(attrs)
          |> Repo.insert(
            on_conflict: [
              set: [
                alert_id: attrs.alert_id,
                state: attrs.state,
                terminal: attrs.terminal,
                snapshot_version: attrs.snapshot_version,
                snapshot: attrs.snapshot,
                snapshot_sha256: attrs.snapshot_sha256,
                updated_at: now
              ]
            ],
            conflict_target: [:organization_id, :investigation_id],
            returning: true
          )
        else
          {:error, :alert_not_found_in_organization}
        end
      end)
      |> normalize_write_result()
    end
  rescue
    _error -> {:error, :persistence_unavailable}
  catch
    :exit, _reason -> {:error, :persistence_unavailable}
  end

  def upsert(_investigation), do: {:error, :invalid_snapshot}

  @doc false
  @spec restore_non_terminal(:system_startup, keyword()) ::
          {:ok, [map()], map()} | {:error, atom()}
  def restore_non_terminal(scope, opts \\ [])

  def restore_non_terminal(:system_startup, opts) do
    authority = authority_access()

    with {:ok, tenant_limit} <- strict_limit(opts, :tenant_limit, 100, 1, 500),
         {:ok, per_tenant_limit} <- strict_limit(opts, :per_tenant_limit, 10, 1, 100),
         {:ok, tenant_ids, authority_meta} <-
           authority.discover_non_terminal_organization_ids(
             @snapshot_version,
             tenant_limit
           ) do
      restore_tenants(tenant_ids, tenant_limit, per_tenant_limit, authority_meta)
    else
      _error -> {:error, :persistence_unavailable}
    end
  rescue
    _error -> {:error, :persistence_unavailable}
  catch
    :exit, _reason -> {:error, :persistence_unavailable}
  end

  def restore_non_terminal(_scope, _opts), do: {:error, :system_scope_required}

  defp restore_tenants(tenant_ids, tenant_limit, per_tenant_limit, authority_meta) do
    tenants_truncated = authority_meta == %{truncated: true}

    rows =
      tenant_ids
      |> Enum.flat_map(fn organization_id ->
        MultiTenant.with_organization(organization_id, fn ->
          Repo.all(
            from(snapshot in AgenticInvestigationSnapshot,
              where:
                snapshot.organization_id == ^organization_id and
                  snapshot.terminal == false and
                  snapshot.snapshot_version == @snapshot_version,
              order_by: [desc: snapshot.updated_at, desc: snapshot.id],
              limit: ^per_tenant_limit
            )
          )
        end)
      end)

    restored =
      Enum.flat_map(rows, fn row ->
        case decode_row(row) do
          {:ok, investigation} -> [investigation]
          {:error, _reason} -> []
        end
      end)

    {:ok, restored,
     %{
       tenant_limit: tenant_limit,
       per_tenant_limit: per_tenant_limit,
       tenants_loaded: length(tenant_ids),
       tenants_truncated: tenants_truncated
     }}
  end

  defp snapshot_attrs(investigation) do
    organization_id = Map.get(investigation, :organization_id)
    investigation_id = Map.get(investigation, :id)
    alert_id = Map.get(investigation, :alert_id)
    state = investigation |> Map.get(:state) |> state_string()

    with :ok <- valid_uuid(organization_id),
         true <- is_binary(investigation_id) and investigation_id != "",
         :ok <- valid_uuid(alert_id),
         true <- is_binary(state) and state != "" do
      snapshot = encode_snapshot(investigation)
      encoded_snapshot = Jason.encode!(snapshot)

      if byte_size(encoded_snapshot) <= @max_snapshot_bytes do
        {:ok,
         %{
           organization_id: organization_id,
           investigation_id: investigation_id,
           alert_id: alert_id,
           state: state,
           terminal: state in @terminal_states,
           snapshot_version: @snapshot_version,
           snapshot: snapshot,
           snapshot_sha256: hash_encoded_snapshot(encoded_snapshot)
         }}
      else
        {:error, :snapshot_too_large}
      end
    else
      _ -> {:error, :invalid_snapshot}
    end
  end

  defp encode_snapshot(investigation) do
    base =
      @snapshot_fields
      |> Map.new(fn field ->
        {Atom.to_string(field), safe_json(Map.get(investigation, field))}
      end)

    alert =
      investigation
      |> Map.get(:alert)
      |> case do
        value when is_map(value) ->
          @alert_fields
          |> Map.new(fn field -> {Atom.to_string(field), safe_json(Map.get(value, field))} end)

        _ ->
          %{}
      end

    Map.put(base, "alert", alert)
  end

  defp decode_row(%AgenticInvestigationSnapshot{} = row) do
    with true <- is_map(row.snapshot),
         true <- snapshot_hash(row.snapshot) == row.snapshot_sha256,
         {:ok, decoded} <- safe_decode(row.snapshot),
         true <- decoded[:id] == row.investigation_id,
         true <- decoded[:organization_id] == row.organization_id,
         true <- decoded[:alert_id] == row.alert_id,
         true <- state_string(decoded[:state]) == row.state,
         false <- row.state in @terminal_states,
         :ok <- valid_uuid(row.organization_id) do
      {:ok, decoded}
    else
      _ -> {:error, :invalid_snapshot}
    end
  end

  defp snapshot_hash(snapshot), do: snapshot |> Jason.encode!() |> hash_encoded_snapshot()

  defp hash_encoded_snapshot(encoded_snapshot) do
    encoded_snapshot
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp safe_json(value), do: safe_json(value, 0)

  defp safe_json(_value, depth) when depth > @max_depth, do: "[TRUNCATED]"

  defp safe_json(%DateTime{} = value, _depth),
    do: %{"__tamandua_type__" => "datetime", "value" => DateTime.to_iso8601(value)}

  defp safe_json(%NaiveDateTime{} = value, _depth),
    do: %{"__tamandua_type__" => "naive_datetime", "value" => NaiveDateTime.to_iso8601(value)}

  defp safe_json(value, _depth) when is_number(value) or is_boolean(value) or is_nil(value),
    do: value

  defp safe_json(value, _depth) when is_binary(value),
    do: String.slice(value, 0, @max_string_characters)

  defp safe_json(value, _depth) when is_atom(value),
    do: %{"__tamandua_type__" => "atom", "value" => Atom.to_string(value)}

  defp safe_json(value, depth) when is_struct(value),
    do: value |> Map.from_struct() |> safe_json(depth + 1)

  defp safe_json(value, depth) when is_list(value) do
    value
    |> Enum.take(@max_collection_items)
    |> Enum.map(&safe_json(&1, depth + 1))
  end

  defp safe_json(value, depth) when is_map(value) do
    entries =
      value
      |> Enum.take(@max_collection_items)
      |> Enum.flat_map(fn {key, nested} ->
        case storage_key(key) do
          nil ->
            []

          {key_type, encoded_key} ->
            encoded_value =
              if sensitive_key?(encoded_key),
                do: "[REDACTED]",
                else: safe_json(nested, depth + 1)

            [[key_type, encoded_key, encoded_value]]
        end
      end)

    %{"__tamandua_type__" => "map", "entries" => entries}
  end

  defp safe_json(_unsupported, _depth), do: nil

  defp storage_key(key) when is_atom(key), do: {"atom", Atom.to_string(key)}
  defp storage_key(key) when is_binary(key), do: {"string", key}
  defp storage_key(key) when is_integer(key), do: {"string", Integer.to_string(key)}
  defp storage_key(_key), do: nil

  defp sensitive_key?(key) do
    normalized = key |> String.downcase() |> String.replace(~r/[^a-z0-9]/, "")
    Enum.any?(@sensitive_key_fragments, &String.contains?(normalized, &1))
  end

  defp safe_decode(%{"__tamandua_type__" => "datetime", "value" => value} = wrapper)
       when map_size(wrapper) == 2 do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> {:ok, datetime}
      _ -> {:error, :invalid_snapshot}
    end
  end

  defp safe_decode(%{"__tamandua_type__" => "naive_datetime", "value" => value} = wrapper)
       when map_size(wrapper) == 2 do
    case NaiveDateTime.from_iso8601(value) do
      {:ok, datetime} -> {:ok, datetime}
      _ -> {:error, :invalid_snapshot}
    end
  end

  defp safe_decode(%{"__tamandua_type__" => "atom", "value" => value} = wrapper)
       when map_size(wrapper) == 2 do
    try do
      {:ok, String.to_existing_atom(value)}
    rescue
      ArgumentError -> {:error, :invalid_snapshot}
    end
  end

  defp safe_decode(%{"__tamandua_type__" => "map", "entries" => entries} = wrapper)
       when map_size(wrapper) == 2 and is_list(entries) do
    Enum.reduce_while(entries, {:ok, %{}}, fn
      [key_type, key, nested], {:ok, decoded}
      when key_type in ["atom", "string"] and is_binary(key) ->
        with {:ok, decoded_key} <- decode_storage_key(key_type, key),
             {:ok, decoded_value} <- safe_decode(nested) do
          {:cont, {:ok, Map.put(decoded, decoded_key, decoded_value)}}
        else
          _ -> {:halt, {:error, :invalid_snapshot}}
        end

      _entry, _acc ->
        {:halt, {:error, :invalid_snapshot}}
    end)
  end

  defp safe_decode(value)
       when is_binary(value) or is_number(value) or is_boolean(value) or is_nil(value),
       do: {:ok, value}

  defp safe_decode(values) when is_list(values), do: decode_list(values, [])

  defp safe_decode(value) when is_map(value) do
    Enum.reduce_while(value, {:ok, %{}}, fn {key, nested}, {:ok, decoded} ->
      with {:ok, decoded_key} <- safe_key(key),
           {:ok, decoded_value} <- safe_decode(nested) do
        {:cont, {:ok, Map.put(decoded, decoded_key, decoded_value)}}
      else
        _ -> {:halt, {:error, :invalid_snapshot}}
      end
    end)
  end

  defp safe_decode(_unsupported), do: {:error, :invalid_snapshot}

  defp decode_storage_key("string", key), do: {:ok, key}

  defp decode_storage_key("atom", key) do
    try do
      {:ok, String.to_existing_atom(key)}
    rescue
      ArgumentError -> {:error, :invalid_snapshot}
    end
  end

  defp decode_list([], decoded), do: {:ok, Enum.reverse(decoded)}

  defp decode_list([value | rest], decoded) do
    case safe_decode(value) do
      {:ok, item} -> decode_list(rest, [item | decoded])
      {:error, reason} -> {:error, reason}
    end
  end

  defp safe_key(key) when key in @plain_snapshot_keys,
    do: {:ok, String.to_existing_atom(key)}

  defp safe_key(_key), do: {:error, :invalid_snapshot}

  defp normalize_write_result({:ok, %AgenticInvestigationSnapshot{} = snapshot}),
    do: {:ok, snapshot}

  defp normalize_write_result({:error, :alert_not_found_in_organization}),
    do: {:error, :alert_not_found_in_organization}

  defp normalize_write_result(_result), do: {:error, :persistence_unavailable}

  defp state_string(value) when is_atom(value), do: Atom.to_string(value)
  defp state_string(value) when is_binary(value), do: value
  defp state_string(_value), do: nil

  defp alert_belongs_to_organization?(alert_id, organization_id) do
    Repo.exists?(
      from(alert in Alert,
        where: alert.id == ^alert_id and alert.organization_id == ^organization_id
      )
    )
  end

  defp valid_uuid(value) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, _uuid} -> :ok
      :error -> {:error, :invalid_uuid}
    end
  end

  defp valid_uuid(_value), do: {:error, :invalid_uuid}

  defp strict_limit(opts, key, default, minimum, maximum) do
    case Keyword.get(opts, key, default) do
      value when is_integer(value) and value >= minimum and value <= maximum -> {:ok, value}
      _value -> {:error, :invalid_restore_limit}
    end
  end

  defp authority_access do
    Application.get_env(
      :tamandua_server,
      :agentic_restore_authority_access,
      AgenticRestoreAuthorityAccess
    )
  end
end
