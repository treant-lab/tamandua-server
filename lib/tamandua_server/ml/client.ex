defmodule TamanduaServer.ML.Client do
  @moduledoc """
  Alias for ML client to provide cleaner imports.

  This module delegates to TamanduaServer.Detection.ML.Client.
  """

  defdelegate predict(sample), to: TamanduaServer.Detection.ML.Client
  defdelegate predict_batch(samples), to: TamanduaServer.Detection.ML.Client
  defdelegate healthy?(), to: TamanduaServer.Detection.ML.Client
  defdelegate model_info(), to: TamanduaServer.Detection.ML.Client
  defdelegate generate_embeddings(text), to: TamanduaServer.Detection.ML.Client
  defdelegate get_metrics(), to: TamanduaServer.Detection.ML.Client
  defdelegate get_training_status(job_id), to: TamanduaServer.Detection.ML.Client
  defdelegate submit_sample(content, file_type \\ "unknown", metadata \\ %{}),
    to: TamanduaServer.Detection.ML.Client
  defdelegate post(path, body), to: TamanduaServer.Detection.ML.Client
end
