defmodule TamanduaServer.Mobile.AppGuardReplayGuard do
  @moduledoc """
  Defensive App Guard anti-replay reservations.

  Uses the persistent reservation table when it is available. If an environment
  has not run that migration yet, falls back to an ETS window so signed App
  Guard ingestion degrades to process-local replay protection instead of a 500.
  """

  use GenServer

  import Ecto.Query

  require Logger

  alias TamanduaServer.Mobile.MobileEvent
  alias TamanduaServer.Repo

  @reservation_table "app_guard_replay_reservations"
  @fallback_table :tamandua_app_guard_replay_reservations
  @event_id_scope "__app_guard_event_id__"
  @event_id_reservation_seconds 365 * 24 * 60 * 60

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    {:ok, create_ets_table_if_missing()}
  end

  @impl true
  def handle_call(:ensure_table, _from, _state) do
    table = create_ets_table_if_missing()
    {:reply, table, table}
  end

  @doc """
  Returns true when an App Guard event_id has already been ingested for the org.
  """
  def event_id_seen?(_organization_id, event_id) when event_id in [nil, ""], do: false

  def event_id_seen?(organization_id, event_id) when is_binary(event_id) do
    MobileEvent
    |> MobileEvent.by_organization(organization_id)
    |> where([event], fragment("?->>? = ?", event.payload, "event_id", ^event_id))
    |> Repo.exists?()
  end

  @doc """
  Reserves an event_id as a race guard before inserting the MobileEvent row.

  The MobileEvent payload remains the durable source of truth for duplicate
  event IDs; this reservation closes the concurrent-submit gap when the
  reservation table exists.
  """
  def reserve_event_id(organization_id, event_id, opts \\ []) do
    reserve_value(
      organization_id,
      @event_id_scope,
      "event_id",
      event_id,
      @event_id_reservation_seconds,
      opts
    )
  end

  @doc """
  Reserves signed replay metadata such as payload SHA256 or nonce.
  """
  def reserve_signed_value(
        organization_id,
        signing_key_id,
        reservation_type,
        value,
        ttl_seconds,
        opts \\ []
      ) do
    reserve_value(organization_id, signing_key_id, reservation_type, value, ttl_seconds, opts)
  end

  defp reserve_value(_organization_id, _scope, _type, value, _ttl_seconds, _opts)
       when value in [nil, ""],
       do: :duplicate

  defp reserve_value(organization_id, scope, reservation_type, value, ttl_seconds, opts) do
    case Keyword.get(opts, :store, configured_store()) do
      :ets -> reserve_ets_value(organization_id, scope, reservation_type, value, ttl_seconds)
      _ -> reserve_db_value(organization_id, scope, reservation_type, value, ttl_seconds)
    end
  end

  defp reserve_db_value(organization_id, scope, reservation_type, value, ttl_seconds) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    expires_at = DateTime.add(now, ttl_seconds, :second)

    delete_expired_db_reservations(now)

    {inserted, _result} =
      Repo.insert_all(
        @reservation_table,
        [
          %{
            id: dump_uuid!(Ecto.UUID.generate()),
            organization_id: dump_uuid!(organization_id),
            signing_key_id: scope,
            reservation_type: reservation_type,
            reservation_value: value,
            expires_at: expires_at,
            inserted_at: now,
            updated_at: now
          }
        ],
        on_conflict: :nothing,
        conflict_target: [
          :organization_id,
          :signing_key_id,
          :reservation_type,
          :reservation_value
        ]
      )

    if inserted == 1, do: :reserved, else: :duplicate
  rescue
    error in Postgrex.Error ->
      if recoverable_reservation_store_error?(error) do
        Logger.warning(
          "[AppGuardReplayGuard] persistent reservation table unavailable; using ETS fallback"
        )

        reserve_ets_value(organization_id, scope, reservation_type, value, ttl_seconds)
      else
        reraise(error, __STACKTRACE__)
      end
  end

  defp delete_expired_db_reservations(now) do
    Repo.query!(
      "DELETE FROM #{@reservation_table} WHERE expires_at IS NOT NULL AND expires_at <= $1",
      [now]
    )
  end

  defp reserve_ets_value(organization_id, scope, reservation_type, value, ttl_seconds) do
    table = ensure_ets_table()
    now = System.system_time(:second)
    expires_at = now + ttl_seconds
    key = {organization_id, scope, reservation_type, value}

    case :ets.lookup(table, key) do
      [{^key, existing_expires_at}] when existing_expires_at > now ->
        :duplicate

      [{^key, _expired}] ->
        :ets.delete(table, key)
        insert_ets_reservation(table, key, expires_at)

      [] ->
        insert_ets_reservation(table, key, expires_at)
    end
  end

  defp insert_ets_reservation(table, key, expires_at) do
    if :ets.insert_new(table, {key, expires_at}), do: :reserved, else: :duplicate
  end

  defp ensure_ets_table do
    case :ets.whereis(@fallback_table) do
      :undefined ->
        ensure_ets_owner()
        GenServer.call(__MODULE__, :ensure_table)

      table ->
        table
    end
  end

  defp ensure_ets_owner do
    case Process.whereis(__MODULE__) do
      nil ->
        case GenServer.start(__MODULE__, [], name: __MODULE__) do
          {:ok, _pid} -> :ok
          {:error, {:already_started, _pid}} -> :ok
        end

      _pid ->
        :ok
    end
  end

  defp create_ets_table_if_missing do
    case :ets.whereis(@fallback_table) do
      :undefined ->
        :ets.new(@fallback_table, [
          :named_table,
          :set,
          :public,
          read_concurrency: true,
          write_concurrency: true
        ])

      table ->
        table
    end
  end

  defp dump_uuid!(value) do
    case Ecto.UUID.dump(value) do
      {:ok, dumped} -> dumped
      :error -> value
    end
  end

  defp configured_store do
    Application.get_env(:tamandua_server, :app_guard_replay_reservation_store, :db)
  end

  defp recoverable_reservation_store_error?(%Postgrex.Error{postgres: %{code: code}})
       when code in [:undefined_table, :undefined_column],
       do: true

  defp recoverable_reservation_store_error?(error) do
    message = Exception.message(error)

    String.contains?(message, @reservation_table) and
      (String.contains?(message, "does not exist") or String.contains?(message, "undefined"))
  end
end
