defmodule TamanduaServer.AISecurity.ScanHistory do
  @moduledoc """
  Context for managing AI model scan history.

  Provides functions to record, query, and analyze the history of security
  scans performed on AI/ML model files across monitored endpoints.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.AISecurity.ScanHistory.ScanRecord

  @doc """
  List scan history for a model, ordered by scanned_at descending.

  ## Options
    * `:limit` - Maximum number of records to return (default: 5)
    * `:offset` - Number of records to skip (default: 0)

  ## Examples

      iex> list_history("model_123")
      [%ScanRecord{}, ...]

      iex> list_history("model_123", limit: 10)
      [%ScanRecord{}, ...]
  """
  @spec list_history(String.t(), keyword()) :: [ScanRecord.t()]
  def list_history(model_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 5)
    offset = Keyword.get(opts, :offset, 0)

    ScanRecord
    |> where([r], r.model_id == ^model_id)
    |> order_by([r], desc: r.scanned_at)
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  @doc """
  Record a new scan result.

  Automatically sets `scanned_at` to current UTC time if not provided.

  ## Examples

      iex> record_scan(%{model_id: "model_123", agent_id: "agent_456", file_hash: "abc...", scan_status: "safe"})
      {:ok, %ScanRecord{}}

      iex> record_scan(%{model_id: "model_123"})
      {:error, %Ecto.Changeset{}}
  """
  @spec record_scan(map()) :: {:ok, ScanRecord.t()} | {:error, Ecto.Changeset.t()}
  def record_scan(attrs) do
    attrs = Map.put_new(attrs, :scanned_at, DateTime.utc_now())

    %ScanRecord{}
    |> ScanRecord.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Get the most recent scan for a model.

  Returns `nil` if no scans exist for the model.

  ## Examples

      iex> get_latest_scan("model_123")
      %ScanRecord{}

      iex> get_latest_scan("unknown_model")
      nil
  """
  @spec get_latest_scan(String.t()) :: ScanRecord.t() | nil
  def get_latest_scan(model_id) do
    ScanRecord
    |> where([r], r.model_id == ^model_id)
    |> order_by([r], desc: r.scanned_at)
    |> limit(1)
    |> Repo.one()
  end

  @doc """
  Get scan statistics for a model.

  Returns a map with:
    * `:total_scans` - Total number of scans performed
    * `:threats_found` - Number of scans that found threats
    * `:safe_scans` - Number of scans with "safe" status
    * `:avg_duration_ms` - Average scan duration in milliseconds
    * `:last_scanned` - Timestamp of most recent scan

  ## Examples

      iex> scan_stats("model_123")
      %{total_scans: 10, threats_found: 2, safe_scans: 8, avg_duration_ms: 1500.0, last_scanned: ~U[2026-03-29 10:00:00Z]}
  """
  @spec scan_stats(String.t()) :: map()
  def scan_stats(model_id) do
    query = from r in ScanRecord,
      where: r.model_id == ^model_id,
      select: %{
        total_scans: count(r.id),
        threats_found: count(fragment("CASE WHEN ? = 'threats' THEN 1 END", r.scan_status)),
        safe_scans: count(fragment("CASE WHEN ? = 'safe' THEN 1 END", r.scan_status)),
        avg_duration_ms: avg(r.scan_duration_ms),
        last_scanned: max(r.scanned_at)
      }

    Repo.one(query) || %{
      total_scans: 0,
      threats_found: 0,
      safe_scans: 0,
      avg_duration_ms: nil,
      last_scanned: nil
    }
  end

  @doc """
  Get aggregate statistics across all models.

  Returns global scan statistics for dashboards and metrics.
  """
  @spec global_stats() :: map()
  def global_stats do
    query = from r in ScanRecord,
      select: %{
        total_scans: count(r.id),
        unique_models: count(r.model_id, :distinct),
        threats_found: count(fragment("CASE WHEN ? = 'threats' THEN 1 END", r.scan_status)),
        avg_duration_ms: avg(r.scan_duration_ms)
      }

    Repo.one(query) || %{
      total_scans: 0,
      unique_models: 0,
      threats_found: 0,
      avg_duration_ms: nil
    }
  end

  @doc """
  Get recent scans across all models.

  Useful for activity feeds and audit views.

  ## Options
    * `:limit` - Maximum number of records (default: 20)
    * `:status` - Filter by scan status
    * `:agent_id` - Filter by agent
  """
  @spec list_recent(keyword()) :: [ScanRecord.t()]
  def list_recent(opts \\ []) do
    limit = Keyword.get(opts, :limit, 20)
    status = Keyword.get(opts, :status)
    agent_id = Keyword.get(opts, :agent_id)

    ScanRecord
    |> maybe_filter_status(status)
    |> maybe_filter_agent(agent_id)
    |> order_by([r], desc: r.scanned_at)
    |> limit(^limit)
    |> Repo.all()
  end

  @doc """
  Count scans by status for a time period.

  ## Examples

      iex> count_by_status(hours: 24)
      %{"safe" => 100, "threats" => 5, "suspicious" => 2, "error" => 1}
  """
  @spec count_by_status(keyword()) :: map()
  def count_by_status(opts \\ []) do
    since = calculate_since(opts)

    query = from r in ScanRecord,
      where: r.scanned_at >= ^since,
      group_by: r.scan_status,
      select: {r.scan_status, count(r.id)}

    query
    |> Repo.all()
    |> Enum.into(%{})
  end

  @doc """
  Delete old scan history records.

  Useful for data retention policies.

  ## Options
    * `:older_than_days` - Delete records older than this many days (default: 90)
  """
  @spec cleanup_old_records(keyword()) :: {non_neg_integer(), nil | [term()]}
  def cleanup_old_records(opts \\ []) do
    days = Keyword.get(opts, :older_than_days, 90)
    cutoff = DateTime.add(DateTime.utc_now(), -days * 24 * 60 * 60, :second)

    ScanRecord
    |> where([r], r.scanned_at < ^cutoff)
    |> Repo.delete_all()
  end

  # Private helpers

  defp maybe_filter_status(query, nil), do: query
  defp maybe_filter_status(query, status) do
    where(query, [r], r.scan_status == ^status)
  end

  defp maybe_filter_agent(query, nil), do: query
  defp maybe_filter_agent(query, agent_id) do
    where(query, [r], r.agent_id == ^agent_id)
  end

  defp calculate_since(opts) do
    cond do
      hours = opts[:hours] ->
        DateTime.add(DateTime.utc_now(), -hours * 60 * 60, :second)
      days = opts[:days] ->
        DateTime.add(DateTime.utc_now(), -days * 24 * 60 * 60, :second)
      true ->
        DateTime.add(DateTime.utc_now(), -24 * 60 * 60, :second)
    end
  end
end
