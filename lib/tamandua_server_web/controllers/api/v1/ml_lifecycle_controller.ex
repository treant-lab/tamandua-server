defmodule TamanduaServerWeb.API.V1.MLLifecycleController do
  @moduledoc """
  Controller for ML Model Lifecycle Management API.

  Provides endpoints for:
  - Listing all model versions and their status
  - Getting the active model for a model type
  - Viewing model metrics (precision, recall, F1, FPR)
  - Promoting models through canary -> active
  - Rolling back to previous model versions
  - Triggering retraining
  - Canary deployment status
  - Analyst feedback collection and statistics
  """

  use TamanduaServerWeb, :controller
  require Logger

  alias TamanduaServer.ML.{ModelManager, AnalystFeedback, TrainingScheduler}

  action_fallback TamanduaServerWeb.FallbackController

  @valid_feedback_verdicts %{
    "true_positive" => :true_positive,
    "false_positive" => :false_positive,
    "true_negative" => :true_negative,
    "false_negative" => :false_negative
  }

  def action(conn, _opts) do
    apply(__MODULE__, action_name(conn), [conn, conn.params])
  rescue
    exception ->
      Logger.warning("ML lifecycle action #{action_name(conn)} failed: #{Exception.message(exception)}")

      conn
      |> put_status(:service_unavailable)
      |> json(%{
        error: "ml_lifecycle_unavailable",
        message: "ML lifecycle service is unavailable",
        detail: Exception.message(exception)
      })
  catch
    :exit, {:noproc, _} ->
      conn
      |> put_status(:service_unavailable)
      |> json(%{
        error: "ml_lifecycle_unavailable",
        message: "ML lifecycle service is not running in this boot profile"
      })

    :exit, {:timeout, _} ->
      conn
      |> put_status(:gateway_timeout)
      |> json(%{
        error: "ml_lifecycle_timeout",
        message: "ML lifecycle service timed out"
      })

    kind, reason ->
      Logger.warning("ML lifecycle action #{action_name(conn)} failed: #{inspect(kind)} #{inspect(reason)}")

      conn
      |> put_status(:service_unavailable)
      |> json(%{
        error: "ml_lifecycle_unavailable",
        message: "ML lifecycle service is unavailable"
      })
  end

  # ── Model Listing ─────────────────────────────────────────────────────

  @doc """
  GET /api/v1/ml/models

  List all model versions across all model types.
  Supports optional `?model_type=...` filter.
  """
  def list_models(conn, params) do
    models = ModelManager.list_all_models()

    models = case params["model_type"] do
      nil -> models
      type -> Enum.filter(models, &(&1.model_type == type))
    end

    data = Enum.map(models, &serialize_model/1)
    json(conn, %{data: data, total: length(data)})
  end

  @doc """
  GET /api/v1/ml/models/:model_type/active

  Get the currently active model for a model type.
  """
  def get_active(conn, %{"model_type" => model_type}) do
    case ModelManager.get_active_model(model_type) do
      {:ok, model} ->
        metrics = case ModelManager.get_model_metrics(model_type, model.version) do
          {:ok, m} -> serialize_metrics(m)
          {:error, _} -> nil
        end

        json(conn, %{data: Map.put(serialize_model(model), :metrics, metrics)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "not_found", message: "No active model found for #{model_type}"})
    end
  end

  @doc """
  GET /api/v1/ml/models/:model_type/:version/metrics

  Get performance metrics for a specific model version.
  """
  def get_metrics(conn, %{"model_type" => model_type, "version" => version}) do
    case ModelManager.get_model_metrics(model_type, version) do
      {:ok, metrics} ->
        json(conn, %{data: serialize_metrics(metrics)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "not_found", message: "No metrics found for #{model_type} v#{version}"})
    end
  end

  # ── Model Promotion ──────────────────────────────────────────────────

  @doc """
  POST /api/v1/ml/models/:model_type/:version/promote

  Promote a model to canary or active status.

  ## Request Body
  - target: "canary" | "active"
  """
  def promote(conn, %{"model_type" => model_type, "version" => version} = params) do
    target = params["target"] || "canary"

    result = case target do
      "canary" -> ModelManager.promote_to_canary(model_type, version)
      "active" -> ModelManager.promote_to_active(model_type, version)
      other ->
        {:error, {:invalid_target, other}}
    end

    case result do
      :ok ->
        json(conn, %{
          data: %{
            model_type: model_type,
            version: version,
            promoted_to: target,
            message: "Model promoted to #{target}"
          }
        })

      {:error, :model_not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "not_found", message: "Model #{model_type} v#{version} not found"})

      {:error, {:invalid_target, t}} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_target", message: "Invalid promotion target: #{t}. Use 'canary' or 'active'."})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "promotion_failed", message: inspect(reason)})
    end
  end

  @doc """
  POST /api/v1/ml/models/:model_type/rollback

  Rollback the active model to the previous version.
  """
  def rollback_model(conn, %{"model_type" => model_type}) do
    case ModelManager.rollback(model_type) do
      {:ok, version} ->
        json(conn, %{
          data: %{
            model_type: model_type,
            rolled_back_to: version,
            message: "Successfully rolled back to v#{version}"
          }
        })

      {:error, :no_previous_version} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "no_previous_version", message: "No previous version to roll back to for #{model_type}"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "rollback_failed", message: inspect(reason)})
    end
  end

  # ── Retraining ───────────────────────────────────────────────────────

  @doc """
  POST /api/v1/ml/models/:model_type/retrain

  Trigger retraining for a model type.

  ## Request Body (optional)
  - epochs: Number of training epochs (default 50)
  - batch_size: Training batch size (default 32)
  - reason: Reason for retraining (default "manual")
  """
  def trigger_retrain(conn, %{"model_type" => model_type} = params) do
    opts = %{
      reason: params["reason"] || :manual,
      epochs: parse_int(params["epochs"], 50),
      batch_size: parse_int(params["batch_size"], 32)
    }

    case TrainingScheduler.schedule_retraining(model_type, opts) do
      {:ok, job_id} ->
        conn
        |> put_status(:accepted)
        |> json(%{
          data: %{
            job_id: job_id,
            model_type: model_type,
            status: "queued",
            message: "Retraining job queued"
          }
        })

      {:error, :training_already_in_progress} ->
        conn
        |> put_status(:conflict)
        |> json(%{error: "already_in_progress", message: "A training job is already running for #{model_type}"})

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "retrain_failed", message: inspect(reason)})
    end
  end

  # ── Canary Deployment ────────────────────────────────────────────────

  @doc """
  GET /api/v1/ml/canary/status

  Get canary deployment status across all model types, or for a specific
  model type via `?model_type=...`.
  """
  def canary_status(conn, params) do
    model_type = params["model_type"]

    if model_type do
      case ModelManager.get_canary_status(model_type) do
        {:ok, status} ->
          json(conn, %{data: status})

        {:error, :no_canary} ->
          json(conn, %{data: %{active: false, message: "No canary deployment for #{model_type}"}})
      end
    else
      # Get canary status for all model types
      all_models = ModelManager.list_all_models()
      model_types = all_models |> Enum.map(& &1.model_type) |> Enum.uniq()

      statuses = Enum.map(model_types, fn type ->
        case ModelManager.get_canary_status(type) do
          {:ok, status} -> Map.put(status, :model_type, type)
          {:error, _} -> %{model_type: type, active: false}
        end
      end)

      json(conn, %{data: statuses})
    end
  end

  # ── Analyst Feedback ─────────────────────────────────────────────────

  @doc """
  GET /api/v1/ml/feedback/stats

  Get analyst feedback statistics. Supports optional `?model_type=...` filter.
  """
  def feedback_stats(conn, params) do
    case params["model_type"] do
      nil ->
        stats = AnalystFeedback.get_all_feedback_stats()
        json(conn, %{data: stats})

      model_type ->
        version = params["version"] || "unknown"
        case AnalystFeedback.get_feedback_stats(model_type, version) do
          {:ok, stats} -> json(conn, %{data: stats})
          {:error, :not_found} -> json(conn, %{data: %{message: "No feedback data for #{model_type} v#{version}"}})
        end
    end
  end

  @doc """
  POST /api/v1/ml/feedback

  Submit analyst feedback for an alert/prediction.

  ## Request Body
  - alert_id: ID of the alert
  - verdict: "true_positive" | "false_positive" | "true_negative" | "false_negative"
  - analyst_id: (optional) ID of the analyst
  - model_type: (optional) Model type, defaults to "malware_smell"
  - model_version: (optional) Model version
  - sample_hash: (optional) SHA256 of the sample
  - confidence: (optional) Model's original confidence score
  """
  def submit_feedback(conn, params) do
    alert_id = params["alert_id"]
    verdict_str = params["verdict"]

    cond do
      is_nil(alert_id) or is_nil(verdict_str) ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_request", message: "alert_id and verdict are required"})

      is_nil(Map.get(@valid_feedback_verdicts, verdict_str)) ->
        conn
        |> put_status(:bad_request)
        |> json(%{
          error: "invalid_verdict",
          message: "Invalid verdict. Use: true_positive, false_positive, true_negative, false_negative"
        })

      true ->
        verdict = Map.fetch!(@valid_feedback_verdicts, verdict_str)
        analyst_id = params["analyst_id"] || get_current_user_id(conn)

        opts = %{
          model_type: params["model_type"] || "malware_smell",
          model_version: params["model_version"],
          sample_hash: params["sample_hash"],
          confidence: parse_float(params["confidence"])
        }

        AnalystFeedback.record_verdict(alert_id, verdict, analyst_id, opts)

        json(conn, %{data: %{status: "recorded", alert_id: alert_id, verdict: verdict_str}})
    end
  end

  # ── Model Manager Stats ──────────────────────────────────────────────

  @doc """
  GET /api/v1/ml/stats

  Get overall ML model management statistics.
  """
  def ml_stats(conn, _params) do
    manager_stats = ModelManager.stats()
    feedback_stats = AnalystFeedback.stats()
    scheduler_stats = TrainingScheduler.stats()

    json(conn, %{
      data: %{
        model_manager: manager_stats,
        feedback: feedback_stats,
        training_scheduler: scheduler_stats
      }
    })
  end

  @doc """
  GET /api/v1/ml/training/jobs

  List all training jobs.
  """
  def list_training_jobs(conn, _params) do
    jobs = TrainingScheduler.list_jobs()
    json(conn, %{data: jobs, total: length(jobs)})
  end

  @doc """
  GET /api/v1/ml/training/jobs/:job_id

  Get status of a specific training job.
  """
  def get_training_job(conn, %{"job_id" => job_id}) do
    case TrainingScheduler.get_job_status(job_id) do
      {:ok, job} ->
        json(conn, %{data: job})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "not_found", message: "Training job #{job_id} not found"})
    end
  end

  @doc """
  GET /api/v1/ml/models/:model_type/history

  Get full version history for a model type.
  """
  def model_history(conn, %{"model_type" => model_type}) do
    history = ModelManager.get_model_history(model_type)
    data = Enum.map(history, fn model ->
      metrics = case ModelManager.get_model_metrics(model_type, model.version) do
        {:ok, m} -> serialize_metrics(m)
        {:error, _} -> nil
      end

      serialize_model(model) |> Map.put(:metrics, metrics)
    end)

    json(conn, %{data: data, total: length(data)})
  end

  # ── Private helpers ──────────────────────────────────────────────────

  defp serialize_model(model) do
    %{
      model_type: model.model_type,
      version: model.version,
      status: model.status,
      registered_at: model.registered_at,
      promoted_at: model.promoted_at,
      retired_at: model.retired_at,
      metadata: model.metadata
    }
  end

  defp serialize_metrics(metrics) do
    %{
      true_positives: metrics.true_positives,
      false_positives: metrics.false_positives,
      true_negatives: metrics.true_negatives,
      false_negatives: metrics.false_negatives,
      total_predictions: metrics.total_predictions,
      precision: Float.round(metrics.precision * 100, 2),
      recall: Float.round(metrics.recall * 100, 2),
      f1: Float.round(metrics.f1 * 100, 2),
      fpr: Float.round(metrics.fpr * 100, 4),
      last_updated: metrics.last_updated
    }
  end

  defp get_current_user_id(conn) do
    case conn.assigns[:current_user] do
      %{id: id} -> id
      %{"id" => id} -> id
      _ -> nil
    end
  end

  defp parse_int(nil, default), do: default
  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(val, _) when is_integer(val), do: val
  defp parse_int(_, default), do: default

  defp parse_float(nil), do: nil
  defp parse_float(val) when is_float(val), do: val
  defp parse_float(val) when is_integer(val), do: val / 1
  defp parse_float(val) when is_binary(val) do
    case Float.parse(val) do
      {f, _} -> f
      :error -> nil
    end
  end
  defp parse_float(_), do: nil
end
