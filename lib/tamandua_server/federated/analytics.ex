defmodule TamanduaServer.Federated.Analytics do
  @moduledoc """
  Analytics for Federated Learning

  Tracks and analyzes:
  - Per-client contribution metrics
  - Fairness metrics across clients
  - Convergence analysis
  - Privacy budget utilization
  - Training performance metrics
  """

  use GenServer
  require Logger


  defmodule State do
    @moduledoc false
    defstruct [
      :client_contributions,
      :round_metrics,
      :fairness_metrics,
      :convergence_data
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Track client registration event.
  """
  def track_client_registration(client_id, metadata) do
    GenServer.cast(__MODULE__, {:track_registration, client_id, metadata})
  end

  @doc """
  Track client update submission.
  """
  def track_update_submission(client_id, round_number, update_data) do
    GenServer.cast(__MODULE__, {:track_update, client_id, round_number, update_data})
  end

  @doc """
  Track round completion.
  """
  def track_round_completion(round_number, metrics) do
    GenServer.cast(__MODULE__, {:track_round, round_number, metrics})
  end

  @doc """
  Get contribution metrics for all clients.
  """
  def get_client_contributions do
    GenServer.call(__MODULE__, :get_contributions)
  end

  @doc """
  Get fairness metrics.
  """
  def get_fairness_metrics do
    GenServer.call(__MODULE__, :get_fairness)
  end

  @doc """
  Get convergence analysis.
  """
  def get_convergence_analysis do
    GenServer.call(__MODULE__, :get_convergence)
  end

  @doc """
  Get complete analytics report.
  """
  def get_report do
    GenServer.call(__MODULE__, :get_report)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    state = %State{
      client_contributions: %{},
      round_metrics: [],
      fairness_metrics: %{},
      convergence_data: %{
        losses: [],
        moving_average: [],
        variance: []
      }
    }

    Logger.info("Federated Analytics started")

    {:ok, state}
  end

  @impl true
  def handle_cast({:track_registration, client_id, metadata}, state) do
    contribution = %{
      client_id: client_id,
      metadata: metadata,
      rounds_participated: 0,
      total_samples: 0,
      total_loss: 0.0,
      average_loss: 0.0,
      contribution_score: 0.0,
      registered_at: DateTime.utc_now()
    }

    new_contributions = Map.put(state.client_contributions, client_id, contribution)

    {:noreply, %{state | client_contributions: new_contributions}}
  end

  @impl true
  def handle_cast({:track_update, client_id, _round_number, update_data}, state) do
    case Map.get(state.client_contributions, client_id) do
      nil ->
        Logger.warning("Update from unregistered client", client_id: client_id)
        {:noreply, state}

      contribution ->
        num_samples = update_data[:num_samples] || 0
        loss = update_data[:loss] || 0.0

        updated_contribution = %{
          contribution
          | rounds_participated: contribution.rounds_participated + 1,
            total_samples: contribution.total_samples + num_samples,
            total_loss: contribution.total_loss + loss,
            average_loss: (contribution.total_loss + loss) / (contribution.rounds_participated + 1),
            contribution_score: calculate_contribution_score(
              contribution.rounds_participated + 1,
              contribution.total_samples + num_samples,
              loss
            )
        }

        new_contributions = Map.put(state.client_contributions, client_id, updated_contribution)

        {:noreply, %{state | client_contributions: new_contributions}}
    end
  end

  @impl true
  def handle_cast({:track_round, round_number, metrics}, state) do
    round_metric = %{
      round: round_number,
      average_loss: metrics["average_loss"] || 0.0,
      num_clients: metrics["num_clients"] || 0,
      timestamp: DateTime.utc_now()
    }

    new_round_metrics = [round_metric | state.round_metrics]

    # Update convergence data
    losses = [round_metric.average_loss | state.convergence_data.losses]
    moving_avg = calculate_moving_average(losses, 5)
    variance = calculate_variance(losses)

    new_convergence = %{
      state.convergence_data
      | losses: Enum.take(losses, 100),
        moving_average: moving_avg,
        variance: variance
    }

    # Update fairness metrics
    new_fairness = calculate_fairness_metrics(state.client_contributions)

    new_state = %{
      state
      | round_metrics: Enum.take(new_round_metrics, 100),
        convergence_data: new_convergence,
        fairness_metrics: new_fairness
    }

    {:noreply, new_state}
  end

  @impl true
  def handle_call(:get_contributions, _from, state) do
    {:reply, state.client_contributions, state}
  end

  @impl true
  def handle_call(:get_fairness, _from, state) do
    {:reply, state.fairness_metrics, state}
  end

  @impl true
  def handle_call(:get_convergence, _from, state) do
    {:reply, state.convergence_data, state}
  end

  @impl true
  def handle_call(:get_report, _from, state) do
    report = %{
      client_contributions: state.client_contributions,
      fairness_metrics: state.fairness_metrics,
      convergence_data: state.convergence_data,
      round_metrics: Enum.take(state.round_metrics, 10),
      total_rounds: length(state.round_metrics),
      total_clients: map_size(state.client_contributions),
      generated_at: DateTime.utc_now()
    }

    {:reply, report, state}
  end

  # Private Functions

  defp calculate_contribution_score(rounds, samples, loss) do
    # Score = (rounds * log(samples + 1)) / (loss + 1)
    # Higher score = more rounds, more data, lower loss
    rounds * :math.log(samples + 1) / (loss + 1)
  end

  defp calculate_fairness_metrics(contributions) do
    if map_size(contributions) == 0 do
      %{}
    else
      rounds_list = Enum.map(contributions, fn {_id, c} -> c.rounds_participated end)
      samples_list = Enum.map(contributions, fn {_id, c} -> c.total_samples end)

      %{
        gini_coefficient_rounds: gini_coefficient(rounds_list),
        gini_coefficient_samples: gini_coefficient(samples_list),
        participation_variance: variance(rounds_list),
        samples_variance: variance(samples_list),
        min_participation: Enum.min(rounds_list),
        max_participation: Enum.max(rounds_list),
        avg_participation: Enum.sum(rounds_list) / length(rounds_list)
      }
    end
  end

  defp gini_coefficient(values) do
    # Gini coefficient measures inequality (0 = perfect equality, 1 = perfect inequality)
    n = length(values)

    if n == 0 do
      0.0
    else
      sorted = Enum.sort(values)
      sum_values = Enum.sum(sorted)

      if sum_values == 0 do
        0.0
      else
        numerator =
          sorted
          |> Enum.with_index(1)
          |> Enum.map(fn {v, i} -> (2 * i - n - 1) * v end)
          |> Enum.sum()

        numerator / (n * sum_values)
      end
    end
  end

  defp variance(values) do
    if length(values) == 0 do
      0.0
    else
      mean = Enum.sum(values) / length(values)
      sum_sq_diff = Enum.reduce(values, 0, fn v, acc -> acc + :math.pow(v - mean, 2) end)
      sum_sq_diff / length(values)
    end
  end

  defp calculate_moving_average(values, window_size) do
    if length(values) < window_size do
      []
    else
      values
      |> Enum.chunk_every(window_size, 1, :discard)
      |> Enum.map(fn chunk -> Enum.sum(chunk) / window_size end)
    end
  end

  defp calculate_variance(values) do
    if length(values) < 2 do
      []
    else
      # Rolling variance with window of 5
      values
      |> Enum.chunk_every(5, 1, :discard)
      |> Enum.map(&variance/1)
    end
  end
end
