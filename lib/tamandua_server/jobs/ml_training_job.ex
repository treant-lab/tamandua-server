defmodule TamanduaServer.Jobs.MLTrainingJob do
  @moduledoc """
  Oban job for triggering ML model training.

  This job:
  1. Prepares training data from telemetry or synthetic generation
  2. Calls the ML service training endpoint
  3. Monitors training progress
  4. Reloads the model when complete
  """

  use Oban.Worker,
    queue: :ml_training,
    max_attempts: 1,
    unique: [period: 3600]  # Only one training job per hour

  require Logger

  alias TamanduaServer.Detection.ML.Client, as: MLClient

  @ml_service_url System.get_env("ML_SERVICE_URL", "http://localhost:8000")

  @impl Oban.Worker
  def perform(%Oban.Job{args: args}) do
    dataset_id = args["dataset_id"] || "synthetic"
    epochs = args["epochs"] || 50
    batch_size = args["batch_size"] || 32

    Logger.info("Starting ML training job",
      dataset: dataset_id,
      epochs: epochs,
      batch_size: batch_size
    )

    with :ok <- validate_ml_service(),
         {:ok, data_path} <- prepare_training_data(dataset_id),
         {:ok, result} <- trigger_training(data_path, epochs, batch_size),
         :ok <- wait_for_completion(result["job_id"]),
         :ok <- reload_model() do

      Logger.info("ML training job completed successfully",
        result: result
      )

      {:ok, %{status: "completed", result: result}}
    else
      {:error, reason} = error ->
        Logger.error("ML training job failed", reason: inspect(reason))
        error
    end
  end

  # -------------------------------------------------------------------
  # Private Functions
  # -------------------------------------------------------------------

  defp validate_ml_service do
    if MLClient.healthy?() do
      :ok
    else
      {:error, :ml_service_unavailable}
    end
  end

  defp prepare_training_data("synthetic") do
    # For synthetic data, the ML service generates it
    {:ok, "synthetic"}
  end

  defp prepare_training_data("telemetry") do
    # Export telemetry samples to a temporary location
    export_dir = Path.join(System.tmp_dir!(), "tamandua_training_#{:rand.uniform(10000)}")
    File.mkdir_p!(export_dir)

    malware_dir = Path.join(export_dir, "malware")
    goodware_dir = Path.join(export_dir, "goodware")
    File.mkdir_p!(malware_dir)
    File.mkdir_p!(goodware_dir)

    # Export samples from database (files stored in quarantine or sample storage)
    export_labeled_samples(malware_dir, goodware_dir)

    {:ok, export_dir}
  end

  defp prepare_training_data(dataset_id) do
    {:error, {:unknown_dataset, dataset_id}}
  end

  defp export_labeled_samples(malware_dir, goodware_dir) do
    import Ecto.Query

    # Get samples that were flagged as malicious
    malicious_files = from(a in TamanduaServer.Alerts.Alert,
      where: a.severity in [:critical, :high],
      where: not is_nil(a.file_sha256),
      select: %{sha256: a.file_sha256, path: a.file_path},
      limit: 500
    )
    |> TamanduaServer.Repo.all()

    Enum.each(malicious_files, fn file ->
      if file.path && File.exists?(file.path) do
        dest = Path.join(malware_dir, "#{file.sha256}.bin")
        File.cp(file.path, dest)
      end
    end)

    # Get samples from verified goodware (system files, signed executables)
    # This would typically come from a curated list or baseline
    Logger.info("Exported #{length(malicious_files)} malware samples")
  rescue
    e ->
      Logger.warning("Failed to export samples: #{Exception.message(e)}")
  end

  defp trigger_training(data_path, epochs, batch_size) do
    url = "#{@ml_service_url}/training/start"

    body = Jason.encode!(%{
      data_path: data_path,
      epochs: epochs,
      batch_size: batch_size,
      mode: if(data_path == "synthetic", do: "synthetic", else: "production")
    })

    request = Finch.build(:post, url, [
      {"content-type", "application/json"}
    ], body)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 30_000) do
      {:ok, %{status: 200, body: response_body}} ->
        Jason.decode(response_body)

      {:ok, %{status: 202, body: response_body}} ->
        Jason.decode(response_body)

      {:ok, %{status: status, body: body}} ->
        Logger.error("Training request failed", status: status, body: body)
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp wait_for_completion(nil) do
    # No job ID, training was synchronous
    :ok
  end

  defp wait_for_completion(job_id) do
    url = "#{@ml_service_url}/training/status/#{job_id}"

    # Poll for completion (max 30 minutes)
    wait_for_completion_loop(url, 0, 1800)
  end

  defp wait_for_completion_loop(_url, elapsed, max_wait) when elapsed >= max_wait do
    {:error, :training_timeout}
  end

  defp wait_for_completion_loop(url, elapsed, max_wait) do
    request = Finch.build(:get, url)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 5_000) do
      {:ok, %{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, %{"status" => "completed"}} ->
            :ok

          {:ok, %{"status" => "failed", "error" => error}} ->
            {:error, {:training_failed, error}}

          {:ok, %{"status" => status}} ->
            Logger.debug("Training status: #{status}, elapsed: #{elapsed}s")
            Process.sleep(10_000)  # Check every 10 seconds
            wait_for_completion_loop(url, elapsed + 10, max_wait)

          {:error, _} ->
            {:error, :invalid_response}
        end

      {:error, reason} ->
        Logger.warning("Failed to check training status: #{inspect(reason)}")
        Process.sleep(10_000)
        wait_for_completion_loop(url, elapsed + 10, max_wait)
    end
  end

  defp reload_model do
    url = "#{@ml_service_url}/model/reload"
    request = Finch.build(:post, url)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: 30_000) do
      {:ok, %{status: 200}} ->
        Logger.info("ML model reloaded successfully")
        :ok

      {:ok, %{status: status}} ->
        Logger.warning("Model reload returned status #{status}")
        :ok  # Non-fatal

      {:error, reason} ->
        Logger.warning("Model reload failed: #{inspect(reason)}")
        :ok  # Non-fatal
    end
  end
end
