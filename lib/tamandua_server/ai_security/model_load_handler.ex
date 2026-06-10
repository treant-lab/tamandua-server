defmodule TamanduaServer.AISecurity.ModelLoadHandler do
  @moduledoc """
  Handles AI model load events from agents.

  Persists model load events to the database and creates alerts
  for high-risk indicators such as unknown formats, large models,
  or models loaded from temporary directories.

  ## Event Flow

  1. Agent detects model load (dual-signal: library + file access)
  2. Agent sends `ai_model_load` event via WebSocket
  3. AgentChannel routes to `handle_event/2`
  4. Handler persists to `model_loads` table
  5. Handler evaluates risk indicators and creates alerts if needed

  ## Risk Indicators

  - `unknown_format` - Model format could not be determined (medium severity)
  - `large_model_*GB` - Model exceeds 10GB (low severity)
  - `hash_unavailable` - Could not compute file hash (low severity)
  - `elevated_privileges` - Model loaded by root/admin process
  - `model_in_temp_directory` - Model in /tmp or similar
  - `network_exposed_model_serving` - Process binding to network

  ## Example

      iex> ModelLoadHandler.handle_event(agent_id, %{
      ...>   "timestamp" => 1714484400000,
      ...>   "process" => %{"pid" => 1234, "name" => "python"},
      ...>   "model" => %{"path" => "/models/llama.gguf", "format" => "gguf"}
      ...> })
      {:ok, %ModelLoad{}}
  """

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.AISecurity.ModelLoad
  alias TamanduaServer.Alerts

  @doc """
  Handle an AI model load event from an agent.

  ## Parameters
    - agent_id: The UUID of the reporting agent
    - event: The model load event payload

  ## Returns
    - {:ok, model_load} on success
    - {:error, changeset} on validation failure
  """
  @spec handle_event(String.t(), map()) :: {:ok, ModelLoad.t()} | {:error, Ecto.Changeset.t()}
  def handle_event(agent_id, event) when is_binary(agent_id) and is_map(event) do
    # Parse event timestamp from milliseconds
    event_timestamp = parse_timestamp(event["timestamp"])

    # Build changeset attributes from event
    attrs = %{
      agent_id: agent_id,
      # Process context
      process_pid: get_in(event, ["process", "pid"]),
      process_name: get_in(event, ["process", "name"]),
      process_path: get_in(event, ["process", "path"]),
      process_cmdline: get_in(event, ["process", "cmdline"]),
      process_user: get_in(event, ["process", "user"]),
      # Model info
      model_path: get_in(event, ["model", "path"]),
      model_filename: get_in(event, ["model", "filename"]),
      model_format: format_to_string(get_in(event, ["model", "format"])),
      model_size_bytes: get_in(event, ["model", "size_bytes"]),
      model_hash_sha256: get_in(event, ["model", "hash_sha256"]),
      # Metadata
      architecture: get_in(event, ["model", "architecture"]),
      parameters: get_in(event, ["model", "parameters"]),
      quantization: get_in(event, ["model", "quantization"]),
      # Loading context
      loading_method: format_loading_method(event["loading_method"]),
      libraries_loaded: event["libraries_loaded"] || [],
      risk_indicators: event["risk_indicators"] || [],
      # Timestamp
      event_timestamp: event_timestamp
    }

    # Insert record
    result =
      %ModelLoad{}
      |> ModelLoad.changeset(attrs)
      |> Repo.insert()

    case result do
      {:ok, model_load} ->
        Logger.info(
          "Model load event persisted: #{model_load.model_filename} by #{model_load.process_name} (PID: #{model_load.process_pid})"
        )

        # Check for high-risk indicators and create alert if needed
        maybe_create_alert(agent_id, model_load)
        {:ok, model_load}

      {:error, changeset} ->
        Logger.warning("Failed to persist model load event: #{inspect(changeset.errors)}")
        {:error, changeset}
    end
  end

  # Parse millisecond timestamp to DateTime
  defp parse_timestamp(nil), do: DateTime.utc_now()

  defp parse_timestamp(ms) when is_integer(ms) do
    case DateTime.from_unix(div(ms, 1000)) do
      {:ok, dt} -> dt
      _ -> DateTime.utc_now()
    end
  end

  defp parse_timestamp(_), do: DateTime.utc_now()

  # Convert format atom/string to lowercase string
  defp format_to_string(nil), do: "unknown"
  defp format_to_string(format) when is_atom(format), do: Atom.to_string(format) |> String.downcase()
  defp format_to_string(format) when is_binary(format), do: String.downcase(format)

  # Normalize loading method
  defp format_loading_method(nil), do: "file_read"
  defp format_loading_method(method) when is_binary(method), do: String.downcase(method)
  defp format_loading_method(_), do: "file_read"

  # Create alert for high-risk model loads
  defp maybe_create_alert(agent_id, model_load) do
    risk_indicators = model_load.risk_indicators || []

    cond do
      "unknown_format" in risk_indicators ->
        create_alert(agent_id, model_load, "Unknown AI model format detected", :medium)

      Enum.any?(risk_indicators, &String.starts_with?(&1, "large_model_")) ->
        create_alert(agent_id, model_load, "Large AI model loaded", :low)

      "hash_unavailable" in risk_indicators ->
        create_alert(agent_id, model_load, "AI model hash unavailable", :low)

      "elevated_privileges" in risk_indicators and "model_in_temp_directory" in risk_indicators ->
        create_alert(agent_id, model_load, "AI model loaded from temp directory with elevated privileges", :high)

      "network_exposed_model_serving" in risk_indicators ->
        create_alert(agent_id, model_load, "Network-exposed AI model serving detected", :medium)

      true ->
        :ok
    end
  end

  defp create_alert(agent_id, model_load, message, severity) do
    severity_str = Atom.to_string(severity)

    alert_attrs = %{
      agent_id: agent_id,
      severity: severity_str,
      title: message,
      description:
        "Model: #{model_load.model_filename} (#{model_load.model_format}) loaded by #{model_load.process_name} (PID: #{model_load.process_pid})",
      enrichment: %{
        model_path: model_load.model_path,
        model_format: model_load.model_format,
        architecture: model_load.architecture,
        parameters: model_load.parameters,
        quantization: model_load.quantization,
        risk_indicators: model_load.risk_indicators,
        libraries_loaded: model_load.libraries_loaded
      },
      mitre_techniques: ["T1059"],  # Command and Scripting Interpreter (for model execution)
      mitre_tactics: ["execution"]
    }

    case Alerts.create_alert(alert_attrs) do
      {:ok, alert} ->
        Logger.info("Created alert #{alert.id} for model load: #{message}")
        {:ok, alert}

      {:error, reason} ->
        Logger.warning("Failed to create alert for model load: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.warning("Exception creating alert for model load: #{Exception.message(e)}")
      :ok
  end
end
