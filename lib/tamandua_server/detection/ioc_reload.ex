defmodule TamanduaServer.Detection.IOCReload do
  @moduledoc """
  Durable database authority and local-node reconciliation for IOC snapshots.

  Every committed IOC mutation advances `ioc_authority_epochs` through a
  statement trigger. Jobs and notifications are wake-up hints only; periodic
  reconciliation against that epoch is the correctness mechanism.
  """

  require Logger
  import Ecto.Query

  alias TamanduaServer.Detection.{IOC, IOCReconciler, IOCSnapshotProvider, RuleLoader}
  alias TamanduaServer.Repo
  alias TamanduaServer.Workers.IOCReloadWorker

  @global_index "iocs_global_type_value_unique_index"
  @tenant_index "iocs_type_value_organization_id_index"
  @legacy_index "iocs_type_value_unique_index"
  @authority_function "public.bump_ioc_authority_epoch()"
  @authority_function_source """
  DECLARE
    next_epoch bigint;
  BEGIN
    UPDATE public.ioc_authority_epochs
    SET epoch = epoch + 1, updated_at = NOW()
    WHERE singleton = TRUE
    RETURNING epoch INTO next_epoch;

    PERFORM pg_catalog.pg_notify('tamandua_ioc_authority_epoch', next_epoch::text);
    RETURN NULL;
  END;
  """
  @authority_triggers %{
    "iocs_authority_epoch_after_insert" => "INSERT",
    "iocs_authority_epoch_after_update" => "UPDATE",
    "iocs_authority_epoch_after_delete" => "DELETE",
    "iocs_authority_epoch_after_truncate" => "TRUNCATE"
  }

  @spec schedule() :: {:ok, map()} | {:error, term()}
  def schedule do
    with {:ok, epoch} <- IOCSnapshotProvider.probe(),
         :ok <- request_local_reconcile() do
      queue = enqueue_wakeup()

      {:ok,
       %{
         mode: :authority_epoch_reconciler,
         authority_epoch: epoch,
         pending: RuleLoader.published_ioc_epoch() != epoch,
         local_node: node(),
         queue: queue
       }}
    end
  rescue
    error -> {:error, {:reload_schedule_failed, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:reload_schedule_exit, reason}}
  end

  @doc false
  def schedule(insert_fun, preflight_fun, running_fun, reload_fun)
      when is_function(insert_fun, 1) and is_function(preflight_fun, 0) and
             is_function(running_fun, 0) and is_function(reload_fun, 0) do
    with :ok <- preflight_fun.(),
         {:ok, job} <- insert_fun.(IOCReloadWorker.new(%{"scope" => "all"})) do
      if running_fun.() do
        {:ok, %{mode: :durable, job_id: Map.get(job, :id)}}
      else
        case reload_fun.() do
          {:ok, count} ->
            {:ok,
             %{mode: :durable_with_synchronous_refresh, job_id: Map.get(job, :id), count: count}}

          {:error, reason} ->
            {:error, {:reload_queued_but_synchronous_refresh_failed, Map.get(job, :id), reason}}
        end
      end
    end
  rescue
    error -> {:error, {:reload_schedule_failed, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:reload_schedule_exit, reason}}
  end

  @spec reconcile() :: {:ok, map()} | {:error, term()}
  def reconcile do
    reconcile(&load_authoritative_snapshot/0, &RuleLoader.reload_ioc_rules_atomic/2)
  end

  @doc false
  def reconcile(snapshot_fun, publish_fun)
      when is_function(snapshot_fun, 0) and is_function(publish_fun, 2) do
    with {:ok, {epoch, rules}} <- snapshot_fun.() do
      published_before = RuleLoader.published_ioc_epoch()

      if published_before > epoch do
        {:error, {:epoch_regression, epoch, published_before}}
      else
        case publish_fun.(rules, epoch) do
          {:ok, count} ->
            {:ok, %{authority_epoch: epoch, published_epoch: epoch, count: count}}

          {:stale, published} ->
            {:ok, %{authority_epoch: epoch, published_epoch: published, stale: true}}

          {:error, reason} ->
            {:error, reason}
        end
      end
    end
  end

  @spec load_authoritative_snapshot() :: {:ok, {non_neg_integer(), list()}} | {:error, term()}
  def load_authoritative_snapshot do
    Repo.transaction(
      fn ->
        Repo.query!("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ", [])
        Repo.query!("SET LOCAL app.rls_bypass = TRUE", [])

        epoch =
          Repo.query!("SELECT epoch FROM public.ioc_authority_epochs WHERE singleton = TRUE", []).rows

        epoch =
          case epoch do
            [[value]] when is_integer(value) -> value
            _ -> Repo.rollback(:missing_ioc_epoch)
          end

        rules =
          from(i in IOC,
            prefix: "public",
            where: i.enabled == true,
            order_by: [asc: i.id],
            select: %{
              id: i.id,
              organization_id: i.organization_id,
              type: i.type,
              value: i.value,
              severity: i.severity,
              description: i.description,
              source: i.source
            }
          )
          |> Repo.all(timeout: 60_000)
          |> Enum.map(&to_runtime_rule/1)

        {epoch, rules}
      end,
      timeout: 60_000
    )
    |> case do
      {:ok, result} -> {:ok, result}
      {:error, reason} -> {:error, reason}
    end
  rescue
    error -> {:error, {:snapshot_query_failed, Exception.message(error)}}
  catch
    :exit, reason -> {:error, {:snapshot_query_exit, reason}}
  end

  @doc false
  def to_runtime_rules(rows) when is_list(rows) do
    {:ok, Enum.map(rows, &to_runtime_rule/1)}
  rescue
    _error -> {:error, :invalid_ioc_snapshot_rows}
  end

  @spec current_epoch() :: {:ok, non_neg_integer()} | {:error, term()}
  def current_epoch do
    case Repo.query("SELECT epoch FROM public.ioc_authority_epochs WHERE singleton = TRUE", []) do
      {:ok, %{rows: [[epoch]]}} when is_integer(epoch) -> {:ok, epoch}
      {:ok, _} -> {:error, :missing_ioc_epoch}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec preflight() :: :ok | {:error, term()}
  def preflight do
    if Application.get_env(:tamandua_server, :ioc_partial_global_unique_index, false) do
      with :ok <- verify_indexes(&index_definition/1),
           :ok <- verify_authority_triggers(&authority_trigger_definitions/0),
           {:ok, _epoch} <- current_epoch() do
        :ok
      else
        {:error, _} = error -> error
      end
    else
      {:error, {:ioc_authority_preflight_failed, :feature_disabled}}
    end
  end

  @doc false
  def verify_indexes(index_lookup) when is_function(index_lookup, 1) do
    global = index_lookup.(@global_index)
    tenant = index_lookup.(@tenant_index)
    legacy = index_lookup.(@legacy_index)

    cond do
      not valid_global_index?(global) ->
        {:error, {:ioc_index_preflight_failed, :missing_or_invalid_partial_global_index}}

      not valid_tenant_index?(tenant) ->
        {:error, {:ioc_index_preflight_failed, :missing_or_invalid_tenant_index}}

      present_index?(legacy) ->
        {:error, {:ioc_index_preflight_failed, :legacy_global_unique_index_still_present}}

      true ->
        :ok
    end
  end

  @doc false
  def verify_authority_triggers(trigger_lookup) when is_function(trigger_lookup, 0) do
    with {:ok, triggers} when is_list(triggers) <- trigger_lookup.(),
         true <- length(triggers) == map_size(@authority_triggers),
         [function_oid] <- triggers |> Enum.map(& &1.function_oid) |> Enum.uniq(),
         true <- is_integer(function_oid) do
      valid? =
        Enum.all?(@authority_triggers, fn {name, operation} ->
          Enum.any?(triggers, fn trigger ->
            definition = normalize_definition(trigger.definition || "")

            trigger.name == name and trigger.enabled == "A" and
              trigger.internal == false and
              trigger.function == @authority_function and
              valid_authority_function?(trigger) and
              String.contains?(definition, "after #{String.downcase(operation)} on") and
              String.contains?(definition, "for each statement") and
              String.contains?(definition, "execute function") and
              String.contains?(definition, "bump_ioc_authority_epoch()")
          end)
        end)

      if valid?, do: :ok, else: {:error, {:ioc_trigger_preflight_failed, :invalid_definition}}
    else
      _ -> {:error, {:ioc_trigger_preflight_failed, :missing_disabled_or_mismatched}}
    end
  end

  @doc false
  def queue_available?(check_fun \\ &Oban.check_queue/1) when is_function(check_fun, 1) do
    case check_fun.(queue: :threat_intel) do
      %{paused: false} -> true
      %{paused?: false} -> true
      _ -> false
    end
  rescue
    _ -> false
  catch
    :exit, _ -> false
  end

  defp index_definition(index_name) do
    sql = """
    SELECT pg_catalog.pg_get_indexdef(i.indexrelid), i.indisvalid, i.indisready
    FROM pg_catalog.pg_index i
    JOIN pg_catalog.pg_class idx ON idx.oid = i.indexrelid
    JOIN pg_catalog.pg_namespace idx_ns ON idx_ns.oid = idx.relnamespace
    JOIN pg_catalog.pg_class tbl ON tbl.oid = i.indrelid
    JOIN pg_catalog.pg_namespace tbl_ns ON tbl_ns.oid = tbl.relnamespace
    WHERE tbl_ns.nspname = 'public'
      AND idx_ns.nspname = 'public'
      AND tbl.relname = 'iocs'
      AND idx.relname = $1
    LIMIT 1
    """

    case Ecto.Adapters.SQL.query(Repo, sql, [index_name]) do
      {:ok, %{rows: [[definition, valid, ready]]}} ->
        {:ok, %{definition: definition, valid: valid, ready: ready}}

      {:ok, %{rows: []}} ->
        :missing

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp authority_trigger_definitions do
    sql = """
    SELECT t.tgname,
           t.tgenabled::text,
           t.tgisinternal,
           p.oid,
           n.nspname || '.' || p.proname || '()',
           pg_catalog.pg_get_triggerdef(t.oid),
           p.prosrc,
           pg_catalog.pg_get_functiondef(p.oid),
           l.lanname,
           p.prosecdef
    FROM pg_catalog.pg_trigger t
    JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_catalog.pg_language l ON l.oid = p.prolang
    WHERE t.tgrelid = 'public.iocs'::pg_catalog.regclass
      AND t.tgname = ANY($1)
    ORDER BY t.tgname
    """

    names = Map.keys(@authority_triggers)

    case Ecto.Adapters.SQL.query(Repo, sql, [names]) do
      {:ok, %{rows: rows}} ->
        {:ok,
         Enum.map(rows, fn [
                             name,
                             enabled,
                             internal,
                             function_oid,
                             function,
                             definition,
                             function_source,
                             function_definition,
                             function_language,
                             security_definer
                           ] ->
           %{
             name: name,
             enabled: enabled,
             internal: internal,
             function_oid: function_oid,
             function: function,
             definition: definition,
             function_source: function_source,
             function_definition: function_definition,
             function_language: function_language,
             security_definer: security_definer
           }
         end)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp valid_global_index?(entry) do
    with {:ok, definition} <- ready_definition(entry) do
      normalized = normalize_definition(definition)

      String.contains?(normalized, "unique index") and
        String.contains?(normalized, "(type, value)") and
        String.contains?(normalized, "organization_id is null")
    else
      _ -> false
    end
  end

  defp valid_tenant_index?(entry) do
    with {:ok, definition} <- ready_definition(entry) do
      normalized = normalize_definition(definition)

      String.contains?(normalized, "unique index") and
        String.contains?(normalized, "(type, value, organization_id)")
    else
      _ -> false
    end
  end

  # String compatibility is retained for isolated source tests. Production
  # index discovery always supplies validity/readiness metadata.
  defp ready_definition({:ok, definition}) when is_binary(definition), do: {:ok, definition}

  defp ready_definition({:ok, %{definition: definition, valid: true, ready: true}}),
    do: {:ok, definition}

  defp ready_definition(_), do: :error

  defp present_index?({:ok, _}), do: true
  defp present_index?(_), do: false

  defp normalize_definition(definition) do
    definition
    |> String.downcase()
    |> String.replace("\"", "")
    |> String.replace(~r/\s+/, " ")
    |> String.replace(~r/\(\s+/, "(")
    |> String.replace(~r/\s+\)/, ")")
    |> String.replace(~r/\s*,\s*/, ", ")
    |> String.replace("(organization_id is null)", "organization_id is null")
  end

  defp valid_authority_function?(trigger) do
    definition = normalize_definition(Map.get(trigger, :function_definition, "") || "")

    Map.get(trigger, :function_language) == "plpgsql" and
      Map.get(trigger, :security_definer) == false and
      normalize_function_source(Map.get(trigger, :function_source, "") || "") ==
        normalize_function_source(@authority_function_source) and
      String.contains?(
        definition,
        "function public.bump_ioc_authority_epoch() returns trigger"
      ) and
      String.contains?(definition, "language plpgsql")
  end

  defp normalize_function_source(source) do
    source
    |> String.downcase()
    |> String.replace(~r/\s+/, " ")
    |> String.trim()
  end

  defp request_local_reconcile do
    if Process.whereis(IOCReconciler) do
      IOCReconciler.request_reconcile()
    else
      case IOCSnapshotProvider.reconcile() do
        {:ok, _} -> :ok
        {:error, reason} -> {:error, {:local_reconciler_unavailable, reason}}
      end
    end
  end

  defp enqueue_wakeup do
    if queue_available?() do
      case Oban.insert(IOCReloadWorker.new(%{"scope" => "all"})) do
        {:ok, job} -> %{available: true, job_id: job.id}
        {:error, reason} -> %{available: true, admitted: false, error: inspect(reason)}
      end
    else
      %{available: false, authority_reconciler: true}
    end
  end

  defp to_runtime_rule(ioc) do
    scope = if ioc.organization_id, do: {:tenant, ioc.organization_id}, else: :global
    type = normalize_ioc_type(ioc.type)
    value = String.downcase(ioc.value)

    {{scope, type, value},
     %{
       id: ioc.id,
       scope: scope,
       organization_id: ioc.organization_id,
       type: type,
       value: value,
       confidence: severity_to_confidence(ioc.severity),
       description: ioc.description || ioc.source || "IOC from threat feed"
     }}
  end

  defp normalize_ioc_type("hash_sha256"), do: :sha256
  defp normalize_ioc_type("hash_sha1"), do: :sha1
  defp normalize_ioc_type("hash_md5"), do: :md5
  defp normalize_ioc_type("sha256"), do: :sha256
  defp normalize_ioc_type("sha1"), do: :sha1
  defp normalize_ioc_type("md5"), do: :md5
  defp normalize_ioc_type("ip"), do: :ip
  defp normalize_ioc_type("ipv4"), do: :ip
  defp normalize_ioc_type("ipv6"), do: :ip
  defp normalize_ioc_type("domain"), do: :domain
  defp normalize_ioc_type("url"), do: :url
  defp normalize_ioc_type("email"), do: :email
  defp normalize_ioc_type("filename"), do: :filename
  defp normalize_ioc_type(_), do: :indicator

  defp severity_to_confidence("critical"), do: 95
  defp severity_to_confidence("high"), do: 85
  defp severity_to_confidence("medium"), do: 70
  defp severity_to_confidence("low"), do: 50
  defp severity_to_confidence(_), do: 60
end
