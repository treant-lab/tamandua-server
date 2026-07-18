defmodule TamanduaServer.Detection.IOCSnapshotProvider do
  @moduledoc """
  Boot-immutable provider boundary for IOC runtime snapshots.

  `:legacy` remains the default. `:authority_v1` is explicit, uses only the
  dedicated authority pool, and never falls back to the runtime repository.
  """

  alias TamanduaServer.Detection.{IOCReload, RuleLoader}
  alias TamanduaServer.IocSnapshotAuthorityAccess

  @persistent_key {__MODULE__, :provider}
  @providers [:legacy, :authority_v1]

  @spec initialize!() :: :ok
  def initialize! do
    configured = configured_provider!()
    authority_enabled = TamanduaServer.IocSnapshotAuthorityRepo.enabled?()

    unless (configured == :authority_v1 and authority_enabled) or
             (configured == :legacy and not authority_enabled) do
      raise "IOC snapshot provider and dedicated authority repository must be enabled together"
    end

    case :persistent_term.get(@persistent_key, :unset) do
      :unset -> :persistent_term.put(@persistent_key, configured)
      ^configured -> :ok
      _other -> raise "IOC snapshot provider cannot change after application boot"
    end

    :ok
  end

  @spec provider() :: :legacy | :authority_v1
  def provider do
    :persistent_term.get(@persistent_key, configured_provider!())
  end

  @doc false
  def validate_provider(value) when value in @providers, do: {:ok, value}
  def validate_provider(_value), do: {:error, :invalid_ioc_snapshot_provider}

  @spec preflight() :: :ok | {:error, term()}
  def preflight do
    case provider() do
      :legacy -> IOCReload.preflight()
      :authority_v1 -> IocSnapshotAuthorityAccess.preflight()
    end
  end

  @spec current_epoch() :: {:ok, non_neg_integer()} | {:error, term()}
  def current_epoch do
    case provider() do
      :legacy -> IOCReload.current_epoch()
      :authority_v1 -> IocSnapshotAuthorityAccess.current_epoch()
    end
  end

  @doc "Runs the provider-specific readiness and epoch probe without duplicate authority transactions."
  @spec probe() :: {:ok, non_neg_integer()} | {:error, term()}
  def probe do
    case provider() do
      :legacy ->
        with :ok <- IOCReload.preflight(), do: IOCReload.current_epoch()

      # The dedicated authority epoch call performs its complete identity,
      # grant, function and policy preflight in the same read-only transaction.
      :authority_v1 ->
        IocSnapshotAuthorityAccess.current_epoch()
    end
  end

  @spec reconcile() :: {:ok, map()} | {:error, term()}
  def reconcile do
    selected = provider()

    with :ok <- snapshot_preflight(selected),
         {:ok, snapshot} <- load_snapshot(selected),
         {:ok, rules} <- normalize_rows(snapshot.rows),
         metadata = %{
           provider: selected,
           authority_epoch: snapshot.authority_epoch,
           digest: snapshot.sha256
         },
         result <- RuleLoader.reload_ioc_rules_atomic(rules, metadata) do
      publication_result(result, metadata)
    end
  rescue
    _error -> {:error, :ioc_snapshot_provider_failure}
  catch
    :exit, _reason -> {:error, :ioc_snapshot_provider_unavailable}
  end

  defp load_snapshot(:legacy) do
    with {:ok, {epoch, rules}} <- IOCReload.load_authoritative_snapshot() do
      {:ok, %{authority_epoch: epoch, sha256: RuleLoader.ioc_rules_digest(rules), rows: rules}}
    end
  end

  defp load_snapshot(:authority_v1), do: IocSnapshotAuthorityAccess.load_snapshot()

  defp snapshot_preflight(:legacy), do: IOCReload.preflight()

  # load_snapshot/1 performs the full authority preflight inside the same
  # repeatable-read transaction, so a separate probe would only double cost.
  defp snapshot_preflight(:authority_v1), do: :ok

  defp normalize_rows([]), do: {:ok, []}
  defp normalize_rows([{_key, _rule} | _rest] = rows), do: {:ok, rows}
  defp normalize_rows(rows) when is_list(rows), do: IOCReload.to_runtime_rules(rows)
  defp normalize_rows(_rows), do: {:error, :invalid_ioc_snapshot_rows}

  defp publication_result({:ok, count}, metadata) do
    {:ok,
     %{
       authority_epoch: metadata.authority_epoch,
       published_epoch: metadata.authority_epoch,
       digest: metadata.digest,
       provider: metadata.provider,
       count: count
     }}
  end

  defp publication_result({:stale, published}, metadata) do
    {:ok,
     %{
       authority_epoch: metadata.authority_epoch,
       published_epoch: published,
       provider: metadata.provider,
       stale: true
     }}
  end

  defp publication_result({:error, reason}, _metadata), do: {:error, reason}

  defp configured_provider! do
    value = Application.get_env(:tamandua_server, :ioc_snapshot_provider, :legacy)

    case validate_provider(value) do
      {:ok, provider} ->
        provider

      {:error, _reason} ->
        raise "invalid :ioc_snapshot_provider; expected :legacy or :authority_v1"
    end
  end
end
