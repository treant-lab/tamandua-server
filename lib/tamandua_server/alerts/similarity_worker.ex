defmodule TamanduaServer.Alerts.SimilarityWorker do
  @moduledoc """
  Background worker for computing alert similarities.

  Runs periodically to:
  1. Embed new alerts
  2. Detect duplicates
  3. Cluster similar alerts
  4. Update alert metadata

  Scheduled via Quantum or Oban.
  """

  use GenServer
  require Logger

  import Ecto.Query
  alias TamanduaServer.Alerts.{Alert, SimilarityDetector}
  alias TamanduaServer.Repo

  @interval :timer.hours(1)  # Run every hour
  @batch_size 500  # Process 500 alerts at a time
  @lookback_days 30  # Only process alerts from last 30 days

  # ==================== GenServer Callbacks ====================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    Logger.info("SimilarityWorker started")

    # Schedule first run
    schedule_next_run()

    {:ok, %{last_run: nil, alerts_processed: 0, errors: 0}}
  end

  @impl true
  def handle_info(:run, state) do
    Logger.info("SimilarityWorker: Starting similarity computation")

    start_time = System.monotonic_time(:millisecond)

    # Process alerts
    result = process_alerts()

    elapsed = System.monotonic_time(:millisecond) - start_time

    Logger.info(
      "SimilarityWorker: Completed",
      alerts_processed: result.alerts_processed,
      duplicates_found: result.duplicates_found,
      clusters_found: result.clusters_found,
      elapsed_ms: elapsed
    )

    # Schedule next run
    schedule_next_run()

    new_state = %{
      last_run: DateTime.utc_now(),
      alerts_processed: state.alerts_processed + result.alerts_processed,
      errors: state.errors + result.errors
    }

    {:noreply, new_state}
  end

  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ==================== Public API ====================

  @doc """
  Manually trigger similarity computation.
  """
  def run_now do
    send(__MODULE__, :run)
  end

  @doc """
  Get worker status.
  """
  def status do
    GenServer.call(__MODULE__, :status)
  end

  @impl true
  def handle_call(:status, _from, state) do
    {:reply, state, state}
  end

  # ==================== Private Functions ====================

  defp schedule_next_run do
    Process.send_after(self(), :run, @interval)
  end

  defp process_alerts do
    # Query alerts that need similarity computation
    alerts = query_unprocessed_alerts()

    if Enum.empty?(alerts) do
      Logger.debug("SimilarityWorker: No alerts to process")

      %{
        alerts_processed: 0,
        duplicates_found: 0,
        clusters_found: 0,
        errors: 0
      }
    else
      # Process in batches
      alerts
      |> Enum.chunk_every(@batch_size)
      |> Enum.reduce(
        %{alerts_processed: 0, duplicates_found: 0, clusters_found: 0, errors: 0},
        fn batch, acc ->
          result = process_batch(batch)

          %{
            alerts_processed: acc.alerts_processed + result.alerts_processed,
            duplicates_found: acc.duplicates_found + result.duplicates_found,
            clusters_found: acc.clusters_found + result.clusters_found,
            errors: acc.errors + result.errors
          }
        end
      )
    end
  end

  defp query_unprocessed_alerts do
    # Query alerts that:
    # 1. Were created in the last N days
    # 2. Haven't been processed yet OR were processed more than 24 hours ago
    # 3. Are not already marked as duplicates

    from(a in Alert,
      where: a.inserted_at >= ago(@lookback_days, "day"),
      where: a.is_duplicate == false,
      where:
        is_nil(a.similarity_computed_at) or
          a.similarity_computed_at < ago(24, "hour"),
      order_by: [desc: a.inserted_at],
      limit: 5000,
      preload: [:agent]
    )
    |> Repo.all()
  end

  defp process_batch(alerts) do
    Logger.debug("SimilarityWorker: Processing batch of #{length(alerts)} alerts")

    try do
      # 1. Generate embeddings
      {:ok, %{embeddings: embeddings, alert_ids: alert_ids}} =
        SimilarityDetector.embed_alerts(alerts)

      # 2. Detect duplicates
      {:ok, duplicate_result} =
        SimilarityDetector.detect_duplicates(alerts, embeddings: embeddings)

      # 3. Mark duplicates in database
      mark_duplicates(duplicate_result)

      # 4. Cluster non-duplicate alerts
      non_duplicate_indices =
        Enum.with_index(alerts)
        |> Enum.reject(fn {_alert, idx} ->
          is_duplicate?(idx, duplicate_result.exact_duplicates, duplicate_result.near_duplicates)
        end)
        |> Enum.map(fn {_alert, idx} -> idx end)

      cluster_result =
        if length(non_duplicate_indices) >= 2 do
          non_duplicate_embeddings =
            Enum.map(non_duplicate_indices, fn idx -> Enum.at(embeddings, idx) end)

          non_duplicate_alert_ids =
            Enum.map(non_duplicate_indices, fn idx -> Enum.at(alert_ids, idx) end)

          {:ok, result} =
            SimilarityDetector.cluster_alerts(
              non_duplicate_embeddings,
              non_duplicate_alert_ids,
              min_cluster_size: 2
            )

          result
        else
          %{cluster_labels: [], cluster_info: %{"num_clusters" => 0}}
        end

      # 5. Update cluster assignments
      update_cluster_assignments(non_duplicate_indices, cluster_result, alerts)

      # 6. Update similarity metadata
      update_similarity_metadata(alerts, embeddings)

      %{
        alerts_processed: length(alerts),
        duplicates_found:
          map_size(duplicate_result.exact_duplicates) +
            map_size(duplicate_result.near_duplicates),
        clusters_found: cluster_result.cluster_info["num_clusters"],
        errors: 0
      }
    rescue
      error ->
        Logger.error(
          "SimilarityWorker: Error processing batch",
          error: inspect(error),
          stacktrace: __STACKTRACE__
        )

        %{
          alerts_processed: 0,
          duplicates_found: 0,
          clusters_found: 0,
          errors: 1
        }
    end
  end

  defp is_duplicate?(idx, exact_duplicates, near_duplicates) do
    _idx_str = to_string(idx)

    # Check if this index is in any duplicate list
    Enum.any?(Map.values(exact_duplicates), fn dups -> idx in dups end) or
      Enum.any?(Map.values(near_duplicates), fn dups -> idx in dups end)
  end

  defp mark_duplicates(duplicate_result) do
    # Mark exact duplicates
    Enum.each(duplicate_result.exact_duplicates, fn {original_idx, duplicate_indices} ->
      original_alert = Enum.at(duplicate_result.marked_alerts, String.to_integer(original_idx))

      Enum.each(duplicate_indices, fn dup_idx ->
        dup_alert = Enum.at(duplicate_result.marked_alerts, dup_idx)

        if dup_alert && dup_alert["id"] do
          case Repo.get(Alert, dup_alert["id"]) do
            nil ->
              nil

            alert ->
              alert
              |> Ecto.Changeset.change(%{
                is_duplicate: true,
                duplicate_type: "exact",
                duplicate_of_alert_id: original_alert["id"],
                status: "false_positive"
              })
              |> Repo.update()
          end
        end
      end)
    end)

    # Mark near-duplicates
    Enum.each(duplicate_result.near_duplicates, fn {original_idx, duplicate_indices} ->
      original_alert = Enum.at(duplicate_result.marked_alerts, String.to_integer(original_idx))

      Enum.each(duplicate_indices, fn dup_idx ->
        dup_alert = Enum.at(duplicate_result.marked_alerts, dup_idx)

        if dup_alert && dup_alert["id"] do
          case Repo.get(Alert, dup_alert["id"]) do
            nil ->
              nil

            alert ->
              alert
              |> Ecto.Changeset.change(%{
                is_duplicate: true,
                duplicate_type: "near",
                duplicate_of_alert_id: original_alert["id"]
              })
              |> Repo.update()
          end
        end
      end)
    end)
  end

  defp update_cluster_assignments(non_duplicate_indices, cluster_result, alerts) do
    # Update cluster assignments for non-duplicate alerts
    Enum.zip(non_duplicate_indices, cluster_result.cluster_labels || [])
    |> Enum.each(fn {alert_idx, cluster_id} ->
      alert = Enum.at(alerts, alert_idx)

      if alert && cluster_id != -1 do
        # Check if this alert is a cluster leader
        is_leader =
          Enum.any?(cluster_result.cluster_leaders || %{}, fn {cid, leader_idx} ->
            cid == cluster_id && Enum.at(non_duplicate_indices, leader_idx) == alert_idx
          end)

        alert
        |> Ecto.Changeset.change(%{
          similarity_cluster_id: cluster_id,
          is_cluster_leader: is_leader
        })
        |> Repo.update()
      end
    end)
  end

  defp update_similarity_metadata(alerts, embeddings) do
    # Update similarity_computed_at timestamp and store embeddings
    Enum.zip(alerts, embeddings)
    |> Enum.each(fn {alert, embedding} ->
      alert
      |> Ecto.Changeset.change(%{
        embedding: %{"vector" => embedding, "model" => "all-MiniLM-L6-v2"},
        similarity_computed_at: DateTime.utc_now(),
        last_similarity_check_at: DateTime.utc_now()
      })
      |> Repo.update()
    end)
  end
end
