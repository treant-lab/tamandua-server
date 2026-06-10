defmodule TamanduaServer.Federated.Coordinator do
  @moduledoc """
  Federated Learning Coordinator

  Manages federated learning server lifecycle and client coordination.
  Acts as bridge between Elixir backend and Python ML service.
  """

  use GenServer
  require Logger

  alias TamanduaServer.Federated.Analytics

  @ml_service_url Application.compile_env(:tamandua_server, :ml_service_url, "http://localhost:8000")

  defmodule State do
    @moduledoc false
    defstruct [
      :status,
      :current_round,
      :total_rounds,
      :registered_clients,
      :selected_clients,
      :submitted_updates,
      :config,
      :start_time,
      :metrics_history,
      :privacy_stats,
      :security_stats
    ]
  end

  defmodule Config do
    @moduledoc false
    defstruct [
      num_rounds: 100,
      clients_per_round: 10,
      min_clients: 5,
      local_epochs: 1,
      learning_rate: 0.001,
      selection_strategy: "random",
      aggregation_method: "fedavg",
      enable_privacy: true,
      privacy_epsilon: 1.0,
      privacy_delta: 1.0e-5,
      clipping_threshold: 1.0,
      noise_multiplier: 1.0,
      enable_attack_detection: true,
      byzantine_tolerance: 2
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Start federated training round.
  """
  def start_training(config \\ %{}) do
    GenServer.call(__MODULE__, {:start_training, config}, :infinity)
  end

  @doc """
  Stop federated training.
  """
  def stop_training do
    GenServer.call(__MODULE__, :stop_training)
  end

  @doc """
  Register client for federated learning.
  """
  def register_client(client_id, metadata \\ %{}) do
    GenServer.call(__MODULE__, {:register_client, client_id, metadata})
  end

  @doc """
  Submit client update for current round.
  """
  def submit_update(client_id, update_data) do
    GenServer.call(__MODULE__, {:submit_update, client_id, update_data})
  end

  @doc """
  Get current training status.
  """
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  @doc """
  Get training metrics for a specific round.
  """
  def get_round_metrics(round_number) do
    GenServer.call(__MODULE__, {:get_round_metrics, round_number})
  end

  @doc """
  Get all training metrics history.
  """
  def get_metrics_history do
    GenServer.call(__MODULE__, :get_metrics_history)
  end

  @doc """
  Get privacy statistics.
  """
  def get_privacy_stats do
    GenServer.call(__MODULE__, :get_privacy_stats)
  end

  @doc """
  Get security statistics.
  """
  def get_security_stats do
    GenServer.call(__MODULE__, :get_security_stats)
  end

  @doc """
  Get client reputation scores.
  """
  def get_client_reputations do
    GenServer.call(__MODULE__, :get_client_reputations)
  end

  @doc """
  Update federated learning configuration.
  """
  def update_config(new_config) do
    GenServer.call(__MODULE__, {:update_config, new_config})
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    state = %State{
      status: :idle,
      current_round: 0,
      total_rounds: 0,
      registered_clients: %{},
      selected_clients: [],
      submitted_updates: %{},
      config: struct(Config),
      start_time: nil,
      metrics_history: [],
      privacy_stats: %{},
      security_stats: %{}
    }

    Logger.info("Federated Learning Coordinator started")

    {:ok, state}
  end

  @impl true
  def handle_call({:start_training, config_map}, _from, state) do
    if state.status == :training do
      {:reply, {:error, :already_training}, state}
    else
      config = merge_config(state.config, config_map)

      # Initialize ML service federated server
      case init_ml_server(config) do
        {:ok, _response} ->
          new_state = %{
            state
            | status: :training,
              current_round: 0,
              total_rounds: config.num_rounds,
              config: config,
              start_time: DateTime.utc_now(),
              metrics_history: [],
              submitted_updates: %{}
          }

          # Start first round
          schedule_next_round(0)

          Logger.info("Federated training started",
            num_rounds: config.num_rounds,
            clients_per_round: config.clients_per_round
          )

          {:reply, {:ok, :started}, new_state}

        {:error, reason} ->
          Logger.error("Failed to initialize ML server", error: inspect(reason))
          {:reply, {:error, reason}, state}
      end
    end
  end

  @impl true
  def handle_call(:stop_training, _from, state) do
    if state.status == :training do
      # Finalize training in ML service
      finalize_ml_training()

      new_state = %{state | status: :stopped}

      Logger.info("Federated training stopped at round #{state.current_round}")

      {:reply, {:ok, :stopped}, new_state}
    else
      {:reply, {:error, :not_training}, state}
    end
  end

  @impl true
  def handle_call({:register_client, client_id, metadata}, _from, state) do
    if Map.has_key?(state.registered_clients, client_id) do
      {:reply, {:error, :already_registered}, state}
    else
      # Register with ML service
      case register_ml_client(client_id, metadata) do
        {:ok, response} ->
          new_clients = Map.put(state.registered_clients, client_id, %{
            metadata: metadata,
            registered_at: DateTime.utc_now(),
            rounds_participated: 0,
            total_samples: 0
          })

          new_state = %{state | registered_clients: new_clients}

          Logger.info("Client registered for federated learning",
            client_id: client_id,
            total_clients: map_size(new_clients)
          )

          Analytics.track_client_registration(client_id, metadata)

          {:reply, {:ok, response}, new_state}

        {:error, reason} ->
          {:reply, {:error, reason}, state}
      end
    end
  end

  @impl true
  def handle_call({:submit_update, client_id, update_data}, _from, state) do
    if state.status != :training do
      {:reply, {:error, :not_training}, state}
    else
      if client_id not in state.selected_clients do
        {:reply, {:error, :not_selected_for_round}, state}
      else
        if Map.has_key?(state.submitted_updates, client_id) do
          {:reply, {:error, :already_submitted}, state}
        else
          # Submit to ML service
          case submit_ml_update(client_id, update_data, state.current_round) do
            {:ok, response} ->
              new_updates = Map.put(state.submitted_updates, client_id, %{
                submitted_at: DateTime.utc_now(),
                num_samples: update_data[:num_samples] || 0,
                loss: update_data[:loss] || 0.0,
                accuracy: update_data[:accuracy]
              })

              # Update client stats
              client_info = state.registered_clients[client_id]
              updated_client = %{
                client_info
                | rounds_participated: client_info.rounds_participated + 1,
                  total_samples: client_info.total_samples + (update_data[:num_samples] || 0)
              }

              new_clients = Map.put(state.registered_clients, client_id, updated_client)

              new_state = %{
                state
                | submitted_updates: new_updates,
                  registered_clients: new_clients
              }

              Logger.info("Client update submitted",
                client_id: client_id,
                round: state.current_round,
                num_updates: map_size(new_updates)
              )

              Analytics.track_update_submission(client_id, state.current_round, update_data)

              # Check if round is complete
              if map_size(new_updates) >= state.config.min_clients do
                schedule_round_completion(100)
              end

              {:reply, {:ok, response}, new_state}

            {:error, reason} ->
              {:reply, {:error, reason}, state}
          end
        end
      end
    end
  end

  @impl true
  def handle_call(:get_status, _from, state) do
    status = %{
      status: state.status,
      current_round: state.current_round,
      total_rounds: state.total_rounds,
      registered_clients: map_size(state.registered_clients),
      selected_clients: length(state.selected_clients),
      submitted_updates: map_size(state.submitted_updates),
      config: struct_to_map(state.config),
      start_time: state.start_time
    }

    {:reply, status, state}
  end

  @impl true
  def handle_call({:get_round_metrics, round_number}, _from, state) do
    metrics = Enum.find(state.metrics_history, fn m -> m.round == round_number end)
    {:reply, metrics, state}
  end

  @impl true
  def handle_call(:get_metrics_history, _from, state) do
    {:reply, state.metrics_history, state}
  end

  @impl true
  def handle_call(:get_privacy_stats, _from, state) do
    # Fetch from ML service
    case fetch_privacy_stats() do
      {:ok, stats} ->
        {:reply, stats, %{state | privacy_stats: stats}}

      {:error, _reason} ->
        {:reply, state.privacy_stats, state}
    end
  end

  @impl true
  def handle_call(:get_security_stats, _from, state) do
    # Fetch from ML service
    case fetch_security_stats() do
      {:ok, stats} ->
        {:reply, stats, %{state | security_stats: stats}}

      {:error, _reason} ->
        {:reply, state.security_stats, state}
    end
  end

  @impl true
  def handle_call(:get_client_reputations, _from, state) do
    case fetch_client_reputations() do
      {:ok, reputations} ->
        {:reply, reputations, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:update_config, new_config}, _from, state) do
    updated_config = merge_config(state.config, new_config)
    new_state = %{state | config: updated_config}

    Logger.info("Federated config updated", config: inspect(updated_config))

    {:reply, {:ok, updated_config}, new_state}
  end

  @impl true
  def handle_info({:start_round, round_number}, state) do
    if state.status == :training and round_number < state.total_rounds do
      # Select clients for this round
      case select_clients(state.config.clients_per_round, state.config.selection_strategy) do
        {:ok, selected} ->
          new_state = %{
            state
            | current_round: round_number + 1,
              selected_clients: selected,
              submitted_updates: %{}
          }

          Logger.info("Round started",
            round: round_number + 1,
            selected_clients: length(selected)
          )

          # Broadcast to selected clients
          broadcast_round_start(round_number + 1, selected)

          # Schedule timeout for stragglers
          schedule_straggler_timeout(300_000)

          {:noreply, new_state}

        {:error, reason} ->
          Logger.error("Failed to select clients", error: inspect(reason))
          {:noreply, state}
      end
    else
      # Training complete
      finalize_training(state)
      {:noreply, %{state | status: :completed}}
    end
  end

  @impl true
  def handle_info(:complete_round, state) do
    # Aggregate updates in ML service
    case aggregate_round(state.current_round) do
      {:ok, metrics} ->
        # Store metrics
        round_metrics = %{
          round: state.current_round,
          num_clients: map_size(state.submitted_updates),
          average_loss: metrics["average_loss"],
          aggregated_at: DateTime.utc_now()
        }

        new_history = [round_metrics | state.metrics_history]

        Logger.info("Round completed",
          round: state.current_round,
          loss: metrics["average_loss"],
          num_clients: map_size(state.submitted_updates)
        )

        Analytics.track_round_completion(state.current_round, metrics)

        # Broadcast completion
        broadcast_round_complete(state.current_round, metrics)

        # Schedule next round
        schedule_next_round(state.current_round)

        {:noreply, %{state | metrics_history: new_history}}

      {:error, reason} ->
        Logger.error("Round aggregation failed", round: state.current_round, error: inspect(reason))
        {:noreply, state}
    end
  end

  @impl true
  def handle_info(:straggler_timeout, state) do
    num_submitted = map_size(state.submitted_updates)

    if num_submitted >= state.config.min_clients do
      Logger.warning("Straggler timeout - proceeding with available updates",
        submitted: num_submitted,
        expected: length(state.selected_clients)
      )

      send(self(), :complete_round)
    else
      Logger.error("Insufficient updates after timeout",
        submitted: num_submitted,
        required: state.config.min_clients
      )

      # Skip round and continue
      schedule_next_round(state.current_round)
    end

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp merge_config(base, new_config) do
    Enum.reduce(new_config, base, fn {key, value}, acc ->
      if Map.has_key?(acc, key) do
        Map.put(acc, key, value)
      else
        acc
      end
    end)
  end

  defp struct_to_map(struct) do
    Map.from_struct(struct)
  end

  defp schedule_next_round(current_round) do
    Process.send_after(self(), {:start_round, current_round}, 1000)
  end

  defp schedule_round_completion(delay) do
    Process.send_after(self(), :complete_round, delay)
  end

  defp schedule_straggler_timeout(delay) do
    Process.send_after(self(), :straggler_timeout, delay)
  end

  # ML Service Communication

  defp init_ml_server(config) do
    url = "#{@ml_service_url}/federated/start"
    body = Jason.encode!(%{
      num_rounds: config.num_rounds,
      clients_per_round: config.clients_per_round,
      min_clients: config.min_clients,
      local_epochs: config.local_epochs,
      learning_rate: config.learning_rate,
      aggregation_method: config.aggregation_method,
      enable_privacy: config.enable_privacy,
      privacy_epsilon: config.privacy_epsilon,
      privacy_delta: config.privacy_delta,
      enable_attack_detection: config.enable_attack_detection
    })

    case TamanduaServer.HttpClient.post(url, body, [{"Content-Type", "application/json"}]) do
      {:ok, %{status_code: 200, body: response_body}} ->
        {:ok, Jason.decode!(response_body)}

      {:ok, %{status_code: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp register_ml_client(client_id, metadata) do
    url = "#{@ml_service_url}/federated/register"
    body = Jason.encode!(%{
      client_id: client_id,
      metadata: metadata
    })

    case TamanduaServer.HttpClient.post(url, body, [{"Content-Type", "application/json"}]) do
      {:ok, %{status_code: 200, body: response_body}} ->
        {:ok, Jason.decode!(response_body)}

      {:ok, %{status_code: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp submit_ml_update(client_id, update_data, round_number) do
    url = "#{@ml_service_url}/federated/submit_update"
    body = Jason.encode!(%{
      client_id: client_id,
      round_number: round_number,
      num_samples: update_data[:num_samples],
      loss: update_data[:loss],
      accuracy: update_data[:accuracy]
    })

    case TamanduaServer.HttpClient.post(url, body, [{"Content-Type", "application/json"}]) do
      {:ok, %{status_code: 200, body: response_body}} ->
        {:ok, Jason.decode!(response_body)}

      {:ok, %{status_code: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp select_clients(num_clients, strategy) do
    url = "#{@ml_service_url}/federated/select_clients"
    body = Jason.encode!(%{
      num_clients: num_clients,
      strategy: strategy
    })

    case TamanduaServer.HttpClient.post(url, body, [{"Content-Type", "application/json"}]) do
      {:ok, %{status_code: 200, body: response_body}} ->
        response = Jason.decode!(response_body)
        {:ok, response["selected_clients"] || []}

      {:ok, %{status_code: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp aggregate_round(round_number) do
    url = "#{@ml_service_url}/federated/aggregate"
    body = Jason.encode!(%{round_number: round_number})

    case TamanduaServer.HttpClient.post(url, body, [{"Content-Type", "application/json"}]) do
      {:ok, %{status_code: 200, body: response_body}} ->
        {:ok, Jason.decode!(response_body)}

      {:ok, %{status_code: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_privacy_stats do
    url = "#{@ml_service_url}/federated/privacy_stats"

    case HTTPoison.get(url) do
      {:ok, %{status_code: 200, body: response_body}} ->
        {:ok, Jason.decode!(response_body)}

      {:ok, %{status_code: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_security_stats do
    url = "#{@ml_service_url}/federated/security_stats"

    case HTTPoison.get(url) do
      {:ok, %{status_code: 200, body: response_body}} ->
        {:ok, Jason.decode!(response_body)}

      {:ok, %{status_code: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_client_reputations do
    url = "#{@ml_service_url}/federated/client_reputations"

    case HTTPoison.get(url) do
      {:ok, %{status_code: 200, body: response_body}} ->
        {:ok, Jason.decode!(response_body)}

      {:ok, %{status_code: status}} ->
        {:error, "HTTP #{status}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp finalize_ml_training do
    url = "#{@ml_service_url}/federated/finalize"

    case TamanduaServer.HttpClient.post(url, "", []) do
      {:ok, _response} ->
        :ok

      {:error, _reason} ->
        :error
    end
  end

  defp finalize_training(state) do
    Logger.info("Federated training completed",
      total_rounds: state.current_round,
      total_clients: map_size(state.registered_clients)
    )

    finalize_ml_training()

    # Broadcast completion
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "federated:training",
      {:training_complete, %{
        total_rounds: state.current_round,
        metrics: state.metrics_history
      }}
    )
  end

  defp broadcast_round_start(round_number, selected_clients) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "federated:training",
      {:round_started, %{
        round: round_number,
        selected_clients: selected_clients
      }}
    )
  end

  defp broadcast_round_complete(round_number, metrics) do
    Phoenix.PubSub.broadcast(
      TamanduaServer.PubSub,
      "federated:training",
      {:round_completed, %{
        round: round_number,
        metrics: metrics
      }}
    )
  end
end
