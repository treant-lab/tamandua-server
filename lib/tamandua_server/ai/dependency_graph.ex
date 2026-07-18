defmodule TamanduaServer.AI.DependencyGraph do
  @moduledoc """
  AI Model Dependency Graph Analysis.

  Maintains a directed graph of dependencies between:
  - Processes and AI models (process loads model)
  - AI models and their lineage (fine-tuned from parent model)

  ## Use Cases

  1. **Impact Analysis**: If a base model is compromised, identify all downstream
     models and processes that may be affected.

  2. **Supply Chain Risk**: Detect unusual dependency chains that may indicate
     supply chain attacks (e.g., model loaded from untrusted source feeding
     into production inference).

  3. **Critical Model Identification**: Find models that are dependencies for
     many processes (single points of failure).

  4. **Lineage Tracking**: Trace fine-tuned models back to their base models
     to understand provenance.

  ## Graph Structure

  Nodes:
  - {:process, process_id} - A process that loads models
  - {:model, model_id} - An AI/ML model file

  Edges:
  - {:loads, attrs} - Process loads a model
  - {:derived_from, attrs} - Model fine-tuned from parent model
  - {:distilled_from, attrs} - Model distilled from teacher model

  ## Example

      # Process loads a model
      add_dependency(
        "agent1:1234",
        "llama-7b-chat.gguf",
        :loads,
        %{loaded_at: DateTime.utc_now(), libraries: ["llama.cpp"]}
      )

      # Model derived from parent
      add_dependency(
        "llama-7b-chat.gguf",
        "llama-7b-base.gguf",
        :derived_from,
        %{method: "fine_tune", dataset: "chat-instruct-v1"}
      )

      # Get all processes using a model
      get_model_consumers("llama-7b-base.gguf")
      # => [%{process_id: "agent1:1234", ...}, ...]

      # Propagate risk when base model is compromised
      propagate_risk("llama-7b-base.gguf", 0.9)
      # => %{affected_models: [...], affected_processes: [...], ...}
  """

  use GenServer
  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.AI.DependencyGraph.{Edge}

  @nodes_table :ai_dependency_nodes
  @edges_table :ai_dependency_edges
  @adj_table :ai_dependency_adjacency
  @reverse_adj_table :ai_dependency_reverse_adj

  # Risk propagation decay factor (risk reduces as distance increases)
  @risk_decay_factor 0.7

  # Maximum depth for risk propagation
  @max_propagation_depth 10

  # Unusual chain detection thresholds
  @unusual_chain_length 5
  @unusual_model_load_count 10

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Add a dependency relationship to the graph.

  ## Parameters
  - `source_id` - Source node ID (process_id for loads, model_id for derivation)
  - `target_id` - Target node ID (model_id being loaded or parent model)
  - `dependency_type` - One of: :loads, :derived_from, :distilled_from
  - `attrs` - Optional attributes map

  ## Examples

      # Process loads model
      add_dependency("agent1:1234", "model.gguf", :loads)

      # Model fine-tuned from parent
      add_dependency("child-model.gguf", "parent-model.gguf", :derived_from)
  """
  @spec add_dependency(String.t(), String.t(), atom(), map()) :: :ok
  def add_dependency(source_id, target_id, dependency_type, attrs \\ %{})
      when dependency_type in [:loads, :derived_from, :distilled_from] do
    GenServer.cast(__MODULE__, {:add_dependency, source_id, target_id, dependency_type, attrs})
  end

  @doc """
  Remove a dependency relationship.
  """
  @spec remove_dependency(String.t(), String.t(), atom()) :: :ok
  def remove_dependency(source_id, target_id, dependency_type) do
    GenServer.cast(__MODULE__, {:remove_dependency, source_id, target_id, dependency_type})
  end

  @doc """
  Get all processes that consume (load) a given model.

  Returns processes that directly load the model and processes that load
  models derived from it.
  """
  @spec get_model_consumers(String.t()) :: [map()]
  def get_model_consumers(model_id) do
    GenServer.call(__MODULE__, {:get_model_consumers, model_id}, 30_000)
  end

  @doc """
  Get all models loaded by a given process.
  """
  @spec get_process_models(String.t()) :: [map()]
  def get_process_models(process_id) do
    GenServer.call(__MODULE__, {:get_process_models, process_id}, 30_000)
  end

  @doc """
  Get the lineage (parent chain) of a model.

  Traces back through :derived_from and :distilled_from edges to find
  all parent models.
  """
  @spec get_model_lineage(String.t()) :: [map()]
  def get_model_lineage(model_id) do
    GenServer.call(__MODULE__, {:get_model_lineage, model_id}, 30_000)
  end

  @doc """
  Get all derivatives (child models) of a model.
  """
  @spec get_model_derivatives(String.t()) :: [map()]
  def get_model_derivatives(model_id) do
    GenServer.call(__MODULE__, {:get_model_derivatives, model_id}, 30_000)
  end

  @doc """
  Propagate a risk score through the dependency graph.

  When a model is identified as compromised or vulnerable, this function
  calculates the impact on all dependent models and processes.

  ## Parameters
  - `model_id` - The model with the known risk
  - `risk_score` - Risk score from 0.0 to 1.0

  ## Returns
  Map containing:
  - `:affected_models` - List of models with propagated risk
  - `:affected_processes` - List of processes with propagated risk
  - `:total_impact_score` - Aggregate impact score
  - `:critical_paths` - Highest-risk dependency paths
  """
  @spec propagate_risk(String.t(), float()) :: map()
  def propagate_risk(model_id, risk_score) when risk_score >= 0.0 and risk_score <= 1.0 do
    GenServer.call(__MODULE__, {:propagate_risk, model_id, risk_score}, 60_000)
  end

  @doc """
  Find critical models - models that have the most dependents.

  These are single points of failure that, if compromised, would affect
  many downstream models and processes.

  ## Options
  - `:limit` - Maximum number of results (default: 10)
  - `:min_dependents` - Minimum number of dependents to be considered critical (default: 3)
  """
  @spec find_critical_models(keyword()) :: [map()]
  def find_critical_models(opts \\ []) do
    GenServer.call(__MODULE__, {:find_critical_models, opts}, 30_000)
  end

  @doc """
  Detect unusual dependency chains that may indicate supply chain attacks.

  Looks for:
  - Unusually long derivation chains
  - Models loaded from many different processes
  - Processes loading models from unexpected sources
  - Circular dependencies (which shouldn't exist but would indicate tampering)
  """
  @spec detect_unusual_chains() :: [map()]
  def detect_unusual_chains do
    GenServer.call(__MODULE__, :detect_unusual_chains, 60_000)
  end

  @doc """
  Export the dependency graph in a specified format.

  ## Formats
  - `:dot` - Graphviz DOT format
  - `:json` - JSON format suitable for D3.js visualization
  """
  @spec export_graph(format :: :dot | :json) :: String.t()
  def export_graph(format) when format in [:dot, :json] do
    GenServer.call(__MODULE__, {:export_graph, format}, 30_000)
  end

  @doc """
  Get graph statistics.
  """
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  @doc """
  Get the full subgraph centered on a node.
  """
  @spec get_subgraph(String.t(), non_neg_integer()) :: map()
  def get_subgraph(node_id, depth \\ 3) do
    GenServer.call(__MODULE__, {:get_subgraph, node_id, depth}, 30_000)
  end

  # ---------------------------------------------------------------------------
  # Server Callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Create ETS tables
    :ets.new(@nodes_table, [:set, :public, :named_table, read_concurrency: true])
    :ets.new(@edges_table, [:bag, :public, :named_table, read_concurrency: true])
    :ets.new(@adj_table, [:bag, :public, :named_table, read_concurrency: true])
    :ets.new(@reverse_adj_table, [:bag, :public, :named_table, read_concurrency: true])

    # Load existing data from database
    load_from_database()

    Logger.info("[AI.DependencyGraph] Started with #{:ets.info(@nodes_table, :size)} nodes, #{:ets.info(@edges_table, :size)} edges")

    {:ok, %{
      stats: %{
        dependencies_added: 0,
        queries_executed: 0,
        risk_propagations: 0
      }
    }}
  end

  @impl true
  def handle_cast({:add_dependency, source_id, target_id, dep_type, attrs}, state) do
    do_add_dependency(source_id, target_id, dep_type, attrs)
    persist_dependency(source_id, target_id, dep_type, attrs)
    new_stats = Map.update!(state.stats, :dependencies_added, &(&1 + 1))
    {:noreply, %{state | stats: new_stats}}
  end

  @impl true
  def handle_cast({:remove_dependency, source_id, target_id, dep_type}, state) do
    do_remove_dependency(source_id, target_id, dep_type)
    {:noreply, state}
  end

  @impl true
  def handle_call({:get_model_consumers, model_id}, _from, state) do
    result = do_get_model_consumers(model_id)
    new_stats = Map.update!(state.stats, :queries_executed, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_process_models, process_id}, _from, state) do
    result = do_get_process_models(process_id)
    new_stats = Map.update!(state.stats, :queries_executed, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_model_lineage, model_id}, _from, state) do
    result = do_get_model_lineage(model_id)
    new_stats = Map.update!(state.stats, :queries_executed, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:get_model_derivatives, model_id}, _from, state) do
    result = do_get_model_derivatives(model_id)
    new_stats = Map.update!(state.stats, :queries_executed, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:propagate_risk, model_id, risk_score}, _from, state) do
    result = do_propagate_risk(model_id, risk_score)
    new_stats = Map.update!(state.stats, :risk_propagations, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:find_critical_models, opts}, _from, state) do
    result = do_find_critical_models(opts)
    new_stats = Map.update!(state.stats, :queries_executed, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call(:detect_unusual_chains, _from, state) do
    result = do_detect_unusual_chains()
    new_stats = Map.update!(state.stats, :queries_executed, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  @impl true
  def handle_call({:export_graph, format}, _from, state) do
    result = do_export_graph(format)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    graph_stats = %{
      node_count: :ets.info(@nodes_table, :size),
      edge_count: :ets.info(@edges_table, :size),
      model_count: count_nodes_by_type(:model),
      process_count: count_nodes_by_type(:process),
      counters: state.stats,
      memory_bytes: calculate_memory_usage()
    }
    {:reply, graph_stats, state}
  end

  @impl true
  def handle_call({:get_subgraph, node_id, depth}, _from, state) do
    result = do_get_subgraph(node_id, depth)
    new_stats = Map.update!(state.stats, :queries_executed, &(&1 + 1))
    {:reply, result, %{state | stats: new_stats}}
  end

  # ---------------------------------------------------------------------------
  # Private: Graph Operations
  # ---------------------------------------------------------------------------

  defp do_add_dependency(source_id, target_id, dep_type, attrs) do
    now = DateTime.utc_now()

    # Determine node types based on dependency type
    {source_type, target_type} = case dep_type do
      :loads -> {:process, :model}
      :derived_from -> {:model, :model}
      :distilled_from -> {:model, :model}
    end

    # Ensure nodes exist
    ensure_node_exists(source_id, source_type)
    ensure_node_exists(target_id, target_type)

    # Create edge
    edge_key = {source_id, target_id, dep_type}
    edge_data = attrs
    |> Map.put(:source_id, source_id)
    |> Map.put(:target_id, target_id)
    |> Map.put(:dependency_type, dep_type)
    |> Map.put(:created_at, now)

    # Remove existing edge of same type (upsert)
    :ets.match_delete(@edges_table, {edge_key, :_})
    :ets.insert(@edges_table, {edge_key, edge_data})

    # Update adjacency lists
    :ets.insert(@adj_table, {source_id, {target_id, dep_type, edge_data}})
    :ets.insert(@reverse_adj_table, {target_id, {source_id, dep_type, edge_data}})
  end

  defp do_remove_dependency(source_id, target_id, dep_type) do
    edge_key = {source_id, target_id, dep_type}
    :ets.match_delete(@edges_table, {edge_key, :_})
    :ets.match_delete(@adj_table, {source_id, {target_id, dep_type, :_}})
    :ets.match_delete(@reverse_adj_table, {target_id, {source_id, dep_type, :_}})
  end

  defp ensure_node_exists(node_id, node_type) do
    case :ets.lookup(@nodes_table, node_id) do
      [] ->
        node_data = %{
          id: node_id,
          type: node_type,
          created_at: DateTime.utc_now()
        }
        :ets.insert(@nodes_table, {node_id, node_data})
      _ ->
        :ok
    end
  end

  defp do_get_model_consumers(model_id) do
    # Find direct consumers (processes that load this model)
    direct_consumers = :ets.lookup(@reverse_adj_table, model_id)
    |> Enum.filter(fn {_target, {_source, dep_type, _data}} -> dep_type == :loads end)
    |> Enum.map(fn {_target, {source_id, _dep_type, edge_data}} ->
      case :ets.lookup(@nodes_table, source_id) do
        [{^source_id, node_data}] ->
          Map.merge(node_data, %{
            relationship: :direct,
            edge: edge_data
          })
        [] -> nil
      end
    end)
    |> Enum.reject(&is_nil/1)

    # Find models that are derived from this model
    derivatives = do_get_model_derivatives(model_id)

    # Find consumers of derived models (indirect consumers)
    indirect_consumers = Enum.flat_map(derivatives, fn derivative ->
      :ets.lookup(@reverse_adj_table, derivative.id)
      |> Enum.filter(fn {_target, {_source, dep_type, _data}} -> dep_type == :loads end)
      |> Enum.map(fn {_target, {source_id, _dep_type, edge_data}} ->
        case :ets.lookup(@nodes_table, source_id) do
          [{^source_id, node_data}] ->
            Map.merge(node_data, %{
              relationship: :indirect,
              via_model: derivative.id,
              edge: edge_data
            })
          [] -> nil
        end
      end)
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq_by(& &1.id)

    direct_consumers ++ indirect_consumers
  end

  defp do_get_process_models(process_id) do
    :ets.lookup(@adj_table, process_id)
    |> Enum.filter(fn {_source, {_target, dep_type, _data}} -> dep_type == :loads end)
    |> Enum.map(fn {_source, {target_id, _dep_type, edge_data}} ->
      case :ets.lookup(@nodes_table, target_id) do
        [{^target_id, node_data}] ->
          Map.merge(node_data, %{edge: edge_data})
        [] ->
          %{id: target_id, type: :model, edge: edge_data}
      end
    end)
  end

  defp do_get_model_lineage(model_id) do
    do_get_lineage_recursive(model_id, MapSet.new(), [])
  end

  defp do_get_lineage_recursive(model_id, visited, acc) do
    if MapSet.member?(visited, model_id) do
      # Cycle detected - shouldn't happen but handle gracefully
      acc
    else
      visited = MapSet.put(visited, model_id)

      # Find parent models
      parents = :ets.lookup(@adj_table, model_id)
      |> Enum.filter(fn {_source, {_target, dep_type, _data}} ->
        dep_type in [:derived_from, :distilled_from]
      end)
      |> Enum.flat_map(fn {_source, {target_id, dep_type, edge_data}} ->
        case :ets.lookup(@nodes_table, target_id) do
          [{^target_id, node_data}] ->
            parent = Map.merge(node_data, %{
              derivation_type: dep_type,
              edge: edge_data
            })
            # Recurse to get the parent's lineage
            [parent | do_get_lineage_recursive(target_id, visited, [])]
          [] ->
            []
        end
      end)

      acc ++ parents
    end
  end

  defp do_get_model_derivatives(model_id) do
    do_get_derivatives_recursive(model_id, MapSet.new(), [])
  end

  defp do_get_derivatives_recursive(model_id, visited, acc) do
    if MapSet.member?(visited, model_id) do
      acc
    else
      visited = MapSet.put(visited, model_id)

      # Find child models (those derived from this model)
      children = :ets.lookup(@reverse_adj_table, model_id)
      |> Enum.filter(fn {_target, {_source, dep_type, _data}} ->
        dep_type in [:derived_from, :distilled_from]
      end)
      |> Enum.flat_map(fn {_target, {source_id, dep_type, edge_data}} ->
        case :ets.lookup(@nodes_table, source_id) do
          [{^source_id, node_data}] ->
            child = Map.merge(node_data, %{
              derivation_type: dep_type,
              edge: edge_data
            })
            [child | do_get_derivatives_recursive(source_id, visited, [])]
          [] ->
            []
        end
      end)

      acc ++ children
    end
  end

  defp do_propagate_risk(model_id, initial_risk) do
    # BFS to propagate risk through the graph
    queue = :queue.in({model_id, initial_risk, 0, [model_id]}, :queue.new())
    visited = MapSet.new([model_id])

    affected_models = []
    affected_processes = []

    {affected_models, affected_processes, critical_paths} =
      propagate_risk_bfs(queue, visited, affected_models, affected_processes, [])

    # Calculate total impact
    total_model_risk = Enum.reduce(affected_models, 0.0, fn m, acc -> acc + m.propagated_risk end)
    total_process_risk = Enum.reduce(affected_processes, 0.0, fn p, acc -> acc + p.propagated_risk end)

    %{
      source_model: model_id,
      initial_risk: initial_risk,
      affected_models: Enum.sort_by(affected_models, & &1.propagated_risk, :desc),
      affected_processes: Enum.sort_by(affected_processes, & &1.propagated_risk, :desc),
      total_impact_score: total_model_risk + total_process_risk,
      model_count: length(affected_models),
      process_count: length(affected_processes),
      critical_paths: Enum.take(Enum.sort_by(critical_paths, & &1.risk, :desc), 5)
    }
  end

  defp propagate_risk_bfs(queue, visited, affected_models, affected_processes, critical_paths) do
    case :queue.out(queue) do
      {:empty, _} ->
        {affected_models, affected_processes, critical_paths}

      {{:value, {node_id, risk, depth, path}}, rest_queue} ->
        if depth >= @max_propagation_depth do
          propagate_risk_bfs(rest_queue, visited, affected_models, affected_processes, critical_paths)
        else
          # Get neighbors (reverse direction - find nodes that depend on this one)
          neighbors = :ets.lookup(@reverse_adj_table, node_id)

          {new_queue, new_visited, new_models, new_processes, new_paths} =
            Enum.reduce(neighbors, {rest_queue, visited, affected_models, affected_processes, critical_paths},
              fn {_target, {source_id, dep_type, edge_data}}, {q, v, m, p, paths} ->
                if MapSet.member?(v, source_id) do
                  {q, v, m, p, paths}
                else
                  # Calculate decayed risk
                  decayed_risk = risk * @risk_decay_factor
                  new_path = path ++ [source_id]

                  case :ets.lookup(@nodes_table, source_id) do
                    [{^source_id, node_data}] ->
                      affected = Map.merge(node_data, %{
                        propagated_risk: decayed_risk,
                        distance: depth + 1,
                        dependency_type: dep_type,
                        path: new_path,
                        edge: edge_data
                      })

                      # Track as model or process
                      {new_m, new_p} = case node_data.type do
                        :model -> {[affected | m], p}
                        :process -> {m, [affected | p]}
                        _ -> {m, p}
                      end

                      # Track high-risk paths
                      new_paths = if decayed_risk > 0.5 do
                        [%{path: new_path, risk: decayed_risk, length: length(new_path)} | paths]
                      else
                        paths
                      end

                      {:queue.in({source_id, decayed_risk, depth + 1, new_path}, q),
                       MapSet.put(v, source_id), new_m, new_p, new_paths}

                    [] ->
                      {q, v, m, p, paths}
                  end
                end
              end)

          propagate_risk_bfs(new_queue, new_visited, new_models, new_processes, new_paths)
        end
    end
  end

  defp do_find_critical_models(opts) do
    limit = Keyword.get(opts, :limit, 10)
    min_dependents = Keyword.get(opts, :min_dependents, 3)

    # Count dependents for each model
    :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {_id, data} -> data.type == :model end)
    |> Enum.map(fn {model_id, model_data} ->
      # Count direct loads
      direct_loads = :ets.lookup(@reverse_adj_table, model_id)
      |> Enum.count(fn {_target, {_source, dep_type, _data}} -> dep_type == :loads end)

      # Count derived models
      derivatives = length(do_get_model_derivatives(model_id))

      # Count indirect consumers
      consumers = length(do_get_model_consumers(model_id))

      total_dependents = direct_loads + derivatives

      Map.merge(model_data, %{
        direct_loads: direct_loads,
        derivative_count: derivatives,
        total_consumers: consumers,
        total_dependents: total_dependents,
        criticality_score: calculate_criticality_score(direct_loads, derivatives, consumers)
      })
    end)
    |> Enum.filter(fn m -> m.total_dependents >= min_dependents end)
    |> Enum.sort_by(& &1.criticality_score, :desc)
    |> Enum.take(limit)
  end

  defp calculate_criticality_score(direct_loads, derivatives, consumers) do
    # Weighted score: direct loads are most critical, derivatives matter, consumers indicate usage
    direct_loads * 3.0 + derivatives * 2.0 + consumers * 1.0
  end

  defp do_detect_unusual_chains do
    anomalies = []

    # Detect long derivation chains
    models = :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {_id, data} -> data.type == :model end)

    long_chains = Enum.flat_map(models, fn {model_id, _data} ->
      lineage = do_get_model_lineage(model_id)
      if length(lineage) >= @unusual_chain_length do
        [%{
          type: :long_derivation_chain,
          severity: :medium,
          model_id: model_id,
          chain_length: length(lineage),
          lineage: Enum.map(lineage, & &1.id),
          description: "Model has unusually long derivation chain (#{length(lineage)} ancestors)"
        }]
      else
        []
      end
    end)

    # Detect models loaded by many processes
    high_load_models = Enum.flat_map(models, fn {model_id, _data} ->
      load_count = :ets.lookup(@reverse_adj_table, model_id)
      |> Enum.count(fn {_target, {_source, dep_type, _data}} -> dep_type == :loads end)

      if load_count >= @unusual_model_load_count do
        [%{
          type: :high_load_count,
          severity: :low,
          model_id: model_id,
          load_count: load_count,
          description: "Model loaded by #{load_count} processes (potential single point of failure)"
        }]
      else
        []
      end
    end)

    # Detect circular dependencies (should not exist)
    circular = detect_cycles()

    anomalies ++ long_chains ++ high_load_models ++ circular
  end

  defp detect_cycles do
    # DFS-based cycle detection
    models = :ets.tab2list(@nodes_table)
    |> Enum.filter(fn {_id, data} -> data.type == :model end)
    |> Enum.map(fn {id, _data} -> id end)

    Enum.flat_map(models, fn start ->
      case find_cycle_from(start, MapSet.new(), []) do
        nil -> []
        cycle ->
          [%{
            type: :circular_dependency,
            severity: :high,
            cycle: cycle,
            description: "Circular dependency detected: #{Enum.join(cycle, " -> ")}"
          }]
      end
    end)
    |> Enum.uniq_by(fn c -> Enum.sort(c.cycle) end)
  end

  defp find_cycle_from(node, visited, path) do
    if MapSet.member?(visited, node) do
      # Found a cycle - return the cycle portion of the path
      cycle_start = Enum.find_index(path, &(&1 == node))
      if cycle_start do
        Enum.drop(path, cycle_start) ++ [node]
      else
        nil
      end
    else
      visited = MapSet.put(visited, node)
      path = path ++ [node]

      # Get derivation edges
      neighbors = :ets.lookup(@adj_table, node)
      |> Enum.filter(fn {_source, {_target, dep_type, _data}} ->
        dep_type in [:derived_from, :distilled_from]
      end)
      |> Enum.map(fn {_source, {target_id, _dep_type, _data}} -> target_id end)

      Enum.find_value(neighbors, fn neighbor ->
        find_cycle_from(neighbor, visited, path)
      end)
    end
  end

  defp do_export_graph(:dot) do
    nodes = :ets.tab2list(@nodes_table)
    edges = :ets.tab2list(@edges_table)

    node_lines = Enum.map(nodes, fn {id, data} ->
      shape = if data.type == :process, do: "box", else: "ellipse"
      color = if data.type == :process, do: "#3b82f6", else: "#22c55e"
      ~s|  "#{escape_dot(id)}" [shape=#{shape}, style=filled, fillcolor="#{color}", label="#{escape_dot(truncate(id, 30))}"];|
    end)

    edge_lines = Enum.map(edges, fn {{source, target, dep_type}, _data} ->
      style = case dep_type do
        :loads -> "solid"
        :derived_from -> "dashed"
        :distilled_from -> "dotted"
      end
      color = case dep_type do
        :loads -> "#94a3b8"
        :derived_from -> "#f97316"
        :distilled_from -> "#a855f7"
      end
      ~s|  "#{escape_dot(source)}" -> "#{escape_dot(target)}" [style=#{style}, color="#{color}", label="#{dep_type}"];|
    end)

    """
    digraph AIModelDependencies {
      rankdir=TB;
      node [fontname="Inter", fontsize=10];
      edge [fontname="Inter", fontsize=8];

    #{Enum.join(node_lines, "\n")}

    #{Enum.join(edge_lines, "\n")}
    }
    """
  end

  defp do_export_graph(:json) do
    nodes = :ets.tab2list(@nodes_table)
    |> Enum.map(fn {id, data} ->
      %{
        id: id,
        type: data.type,
        label: truncate(id, 30),
        created_at: data[:created_at]
      }
    end)

    edges = :ets.tab2list(@edges_table)
    |> Enum.map(fn {{source, target, dep_type}, data} ->
      %{
        source: source,
        target: target,
        type: dep_type,
        created_at: data[:created_at]
      }
    end)

    Jason.encode!(%{
      nodes: nodes,
      edges: edges,
      metadata: %{
        node_count: length(nodes),
        edge_count: length(edges),
        exported_at: DateTime.utc_now()
      }
    })
  end

  defp do_get_subgraph(node_id, max_depth) do
    # BFS to collect nodes and edges within depth
    queue = :queue.in({node_id, 0}, :queue.new())
    visited = MapSet.new([node_id])

    {collected_nodes, collected_edges} = subgraph_bfs(queue, visited, %{}, [], max_depth)

    # Resolve node data
    resolved_nodes = Enum.map(collected_nodes, fn {id, depth} ->
      case :ets.lookup(@nodes_table, id) do
        [{^id, data}] -> Map.merge(data, %{depth: depth})
        [] -> %{id: id, type: :unknown, depth: depth}
      end
    end)

    %{
      center: node_id,
      depth: max_depth,
      nodes: resolved_nodes,
      edges: collected_edges,
      node_count: map_size(collected_nodes),
      edge_count: length(collected_edges)
    }
  end

  defp subgraph_bfs(queue, visited, nodes, edges, max_depth) do
    case :queue.out(queue) do
      {:empty, _} ->
        {nodes, edges}

      {{:value, {current, depth}}, rest_queue} ->
        nodes = Map.put(nodes, current, depth)

        if depth >= max_depth do
          subgraph_bfs(rest_queue, visited, nodes, edges, max_depth)
        else
          # Get outgoing edges
          outgoing = :ets.lookup(@adj_table, current)

          # Get incoming edges
          incoming = :ets.lookup(@reverse_adj_table, current)

          all_neighbors = outgoing ++ incoming

          {new_queue, new_visited, new_edges} =
            Enum.reduce(all_neighbors, {rest_queue, visited, edges}, fn
              {_source, {neighbor_id, dep_type, data}}, {q, v, e} ->
                edge = %{
                  source: current,
                  target: neighbor_id,
                  type: dep_type,
                  data: data
                }
                new_e = [edge | e]

                if MapSet.member?(v, neighbor_id) do
                  {q, v, new_e}
                else
                  {:queue.in({neighbor_id, depth + 1}, q), MapSet.put(v, neighbor_id), new_e}
                end
            end)

          subgraph_bfs(new_queue, new_visited, nodes, new_edges, max_depth)
        end
    end
  end

  # ---------------------------------------------------------------------------
  # Private: Helpers
  # ---------------------------------------------------------------------------

  defp count_nodes_by_type(type) do
    :ets.tab2list(@nodes_table)
    |> Enum.count(fn {_id, data} -> data.type == type end)
  end

  defp calculate_memory_usage do
    [:ets.info(@nodes_table, :memory),
     :ets.info(@edges_table, :memory),
     :ets.info(@adj_table, :memory),
     :ets.info(@reverse_adj_table, :memory)]
    |> Enum.sum()
    |> Kernel.*(:erlang.system_info(:wordsize))
  end

  defp escape_dot(str) do
    str
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
    |> String.replace("\n", "\\n")
  end

  defp truncate(str, max_len) when byte_size(str) > max_len do
    String.slice(str, 0, max_len - 3) <> "..."
  end
  defp truncate(str, _max_len), do: str

  # ---------------------------------------------------------------------------
  # Private: Persistence
  # ---------------------------------------------------------------------------

  defp load_from_database do
    try do
      # Load edges from database
      edges = Repo.all(Edge)

      Enum.each(edges, fn edge ->
        do_add_dependency(
          edge.source_id,
          edge.target_id,
          String.to_existing_atom(edge.dependency_type),
          edge.attributes || %{}
        )
      end)

      Logger.debug("[AI.DependencyGraph] Loaded #{length(edges)} edges from database")
    rescue
      e ->
        Logger.warning("[AI.DependencyGraph] Failed to load from database: #{inspect(e)}")
    end
  end

  defp persist_dependency(source_id, target_id, dep_type, attrs) do
    Task.start(fn ->
      try do
        edge_attrs = %{
          source_id: source_id,
          target_id: target_id,
          dependency_type: Atom.to_string(dep_type),
          attributes: attrs
        }

        %Edge{}
        |> Edge.changeset(edge_attrs)
        |> Repo.insert(
          on_conflict: {:replace, [:attributes, :updated_at]},
          conflict_target: [:source_id, :target_id, :dependency_type]
        )
      rescue
        e ->
          Logger.debug("[AI.DependencyGraph] Failed to persist edge: #{inspect(e)}")
      end
    end)
  end
end
