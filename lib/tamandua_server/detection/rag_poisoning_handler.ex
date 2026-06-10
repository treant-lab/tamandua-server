defmodule TamanduaServer.Detection.RagPoisoningHandler do
  @moduledoc """
  Handles RAG (Retrieval-Augmented Generation) poisoning detection.

  Integrates with the ML service to detect poisoning attacks in RAG systems:
  - Instruction override hidden in "facts"
  - Delimiter injection in documents
  - Hidden unicode/zero-width characters
  - Confidence manipulation phrases
  - Cross-document contradiction detection
  - Data exfiltration URLs
  - Source spoofing attempts

  Provides document source registry for integrity validation and alert
  generation for detected poisoning attempts.
  """

  use GenServer
  require Logger
  alias Phoenix.PubSub
  alias TamanduaServer.Detection.ML.Client, as: MLClient
  alias TamanduaServer.Alerts

  @ets_table :rag_source_registry
  @garbage_collection_interval :timer.hours(24)
  @source_ttl_seconds 86_400 * 30  # 30 days

  # ============================================================================
  # Types
  # ============================================================================

  @type poisoning_risk :: %{
    category: String.t(),
    description: String.t(),
    confidence: float(),
    technique_id: String.t(),
    matched_text: String.t(),
    document_index: non_neg_integer()
  }

  @type scan_result :: %{
    safe: boolean(),
    risks: [poisoning_risk()],
    risk_score: float(),
    scan_time_ms: float(),
    documents_scanned: non_neg_integer(),
    high_risk_documents: [non_neg_integer()],
    context_query_alignment: float() | nil
  }

  @type source_entry :: %{
    source: String.t(),
    trusted: boolean(),
    registered_at: DateTime.t(),
    last_verified: DateTime.t() | nil,
    scan_count: non_neg_integer(),
    last_risk_score: float()
  }

  # ============================================================================
  # Client API
  # ============================================================================

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Scan RAG context documents for poisoning risks.

  Calls the ML service to detect instruction overrides, delimiter injection,
  hidden unicode characters, confidence manipulation, and other poisoning
  attack patterns.

  ## Parameters
    - documents: List of context document strings
    - query: Optional original query for alignment analysis
    - opts: Additional options
      - agent_id: Agent that triggered the scan (for alerts)
      - generate_alerts: Whether to create alerts (default: true)

  ## Returns
    {:ok, scan_result} | {:error, reason}
  """
  @spec scan_documents([String.t()], String.t() | nil, keyword()) ::
    {:ok, scan_result()} | {:error, term()}
  def scan_documents(documents, query \\ nil, opts \\ []) do
    GenServer.call(__MODULE__, {:scan_documents, documents, query, opts}, 30_000)
  end

  @doc """
  Register a document source for integrity tracking.

  ## Parameters
    - doc_hash: SHA-256 hash of the document content
    - source: Source identifier (URL, file path, etc.)
    - trusted: Whether the source is trusted

  ## Returns
    :ok
  """
  @spec register_source(String.t(), String.t(), boolean()) :: :ok
  def register_source(doc_hash, source, trusted \\ true) do
    GenServer.call(__MODULE__, {:register_source, doc_hash, source, trusted})
  end

  @doc """
  Validate a document source.

  ## Parameters
    - doc_hash: SHA-256 hash of the document content
    - source: Source identifier to validate against

  ## Returns
    {:ok, validation_result} | {:error, :not_found}
  """
  @spec validate_source(String.t(), String.t()) ::
    {:ok, %{valid: boolean(), hash_match: boolean(), source_trusted: boolean()}}
    | {:error, :not_found}
  def validate_source(doc_hash, source) do
    GenServer.call(__MODULE__, {:validate_source, doc_hash, source})
  end

  @doc """
  Get registry statistics.
  """
  @spec get_stats() :: map()
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  @doc """
  Get all registered sources.
  """
  @spec list_sources() :: [source_entry()]
  def list_sources do
    GenServer.call(__MODULE__, :list_sources)
  end

  @doc """
  Remove a source from the registry.
  """
  @spec remove_source(String.t()) :: :ok | {:error, :not_found}
  def remove_source(doc_hash) do
    GenServer.call(__MODULE__, {:remove_source, doc_hash})
  end

  # ============================================================================
  # Server Callbacks
  # ============================================================================

  @impl true
  def init(_opts) do
    table = :ets.new(@ets_table, [
      :set,
      :named_table,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Schedule garbage collection
    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)

    state = %{
      table: table,
      stats: %{
        total_scans: 0,
        documents_scanned: 0,
        risks_detected: 0,
        alerts_generated: 0,
        sources_registered: 0,
        validations_performed: 0
      }
    }

    Logger.info("[RagPoisoningHandler] Started")
    {:ok, state}
  end

  @impl true
  def handle_call({:scan_documents, documents, query, opts}, _from, state) do
    agent_id = Keyword.get(opts, :agent_id)
    generate_alerts = Keyword.get(opts, :generate_alerts, true)

    # Call ML service
    result = call_ml_service(documents, query)

    case result do
      {:ok, scan_result} ->
        # Update stats
        state = update_stats(state, scan_result)

        # Generate alerts if needed
        alerts_generated = if generate_alerts && not scan_result.safe do
          generate_poisoning_alerts(scan_result, agent_id, documents)
        else
          0
        end

        state = put_in(state, [:stats, :alerts_generated],
          state.stats.alerts_generated + alerts_generated)

        # Broadcast event
        broadcast_scan_result(scan_result, agent_id)

        {:reply, {:ok, scan_result}, state}

      {:error, reason} = error ->
        Logger.error("[RagPoisoningHandler] ML service error: #{inspect(reason)}")
        {:reply, error, state}
    end
  end

  @impl true
  def handle_call({:register_source, doc_hash, source, trusted}, _from, state) do
    now = DateTime.utc_now()

    entry = %{
      source: source,
      trusted: trusted,
      registered_at: now,
      last_verified: nil,
      scan_count: 0,
      last_risk_score: 0.0
    }

    :ets.insert(@ets_table, {doc_hash, entry})

    state = update_in(state, [:stats, :sources_registered], & &1 + 1)

    Logger.debug("[RagPoisoningHandler] Source registered: #{String.slice(doc_hash, 0, 16)}...")

    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:validate_source, doc_hash, source}, _from, state) do
    result = case :ets.lookup(@ets_table, doc_hash) do
      [{^doc_hash, entry}] ->
        hash_match = entry.source == source

        # Update last verified timestamp
        updated_entry = %{entry | last_verified: DateTime.utc_now()}
        :ets.insert(@ets_table, {doc_hash, updated_entry})

        {:ok, %{
          valid: hash_match && entry.trusted,
          hash_match: hash_match,
          source_trusted: entry.trusted,
          last_verified: entry.last_verified
        }}

      [] ->
        {:error, :not_found}
    end

    state = update_in(state, [:stats, :validations_performed], & &1 + 1)

    {:reply, result, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    source_count = :ets.info(@ets_table, :size)
    stats = Map.put(state.stats, :active_sources, source_count)
    {:reply, stats, state}
  end

  @impl true
  def handle_call(:list_sources, _from, state) do
    sources = :ets.foldl(fn {hash, entry}, acc ->
      [Map.put(entry, :hash, hash) | acc]
    end, [], @ets_table)

    {:reply, Enum.reverse(sources), state}
  end

  @impl true
  def handle_call({:remove_source, doc_hash}, _from, state) do
    result = case :ets.lookup(@ets_table, doc_hash) do
      [{^doc_hash, _}] ->
        :ets.delete(@ets_table, doc_hash)
        :ok

      [] ->
        {:error, :not_found}
    end

    {:reply, result, state}
  end

  @impl true
  def handle_info(:garbage_collect, state) do
    now = DateTime.utc_now()
    cutoff = DateTime.add(now, -@source_ttl_seconds, :second)

    # Find and remove stale entries
    stale_keys = :ets.foldl(fn {hash, entry}, acc ->
      if DateTime.compare(entry.registered_at, cutoff) == :lt do
        [hash | acc]
      else
        acc
      end
    end, [], @ets_table)

    Enum.each(stale_keys, fn hash -> :ets.delete(@ets_table, hash) end)

    if length(stale_keys) > 0 do
      Logger.debug("[RagPoisoningHandler] Garbage collected #{length(stale_keys)} stale sources")
    end

    # Schedule next garbage collection
    Process.send_after(self(), :garbage_collect, @garbage_collection_interval)
    {:noreply, state}
  end

  # Catch-all: ignore unexpected messages so the singleton never crashes.
  @impl true
  def handle_info(_msg, state), do: {:noreply, state}

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp call_ml_service(documents, query) do
    payload = %{
      "documents" => documents,
      "query" => query || ""
    }

    case MLClient.post("/ai-security/rag-scan", payload, timeout: 30_000) do
      {:ok, %{"safe" => safe, "risks" => risks} = response} ->
        scan_result = %{
          safe: safe,
          risks: Enum.map(risks, &normalize_risk/1),
          risk_score: response["risk_score"] || 0.0,
          scan_time_ms: response["scan_time_ms"] || 0.0,
          documents_scanned: response["documents_scanned"] || length(documents),
          high_risk_documents: response["high_risk_documents"] || [],
          context_query_alignment: response["context_query_alignment"]
        }

        {:ok, scan_result}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp normalize_risk(risk) when is_map(risk) do
    %{
      category: risk["category"] || "unknown",
      description: risk["description"] || "",
      confidence: risk["confidence"] || 0.0,
      technique_id: risk["technique_id"] || "RAG-XXX",
      matched_text: risk["matched_text"] || "",
      document_index: risk["document_index"] || 0
    }
  end

  defp update_stats(state, scan_result) do
    state
    |> update_in([:stats, :total_scans], & &1 + 1)
    |> update_in([:stats, :documents_scanned], & &1 + scan_result.documents_scanned)
    |> update_in([:stats, :risks_detected], & &1 + length(scan_result.risks))
  end

  defp generate_poisoning_alerts(scan_result, agent_id, documents) do
    # Group risks by document and create alerts
    risks_by_doc = Enum.group_by(scan_result.risks, & &1.document_index)

    alerts = Enum.flat_map(scan_result.high_risk_documents, fn doc_index ->
      doc_risks = Map.get(risks_by_doc, doc_index, [])
      doc_preview = Enum.at(documents, doc_index, "") |> String.slice(0, 200)

      if length(doc_risks) > 0 do
        # Create single alert per high-risk document
        highest_risk = Enum.max_by(doc_risks, & &1.confidence)

        severity = cond do
          highest_risk.confidence >= 0.9 -> :critical
          highest_risk.confidence >= 0.7 -> :high
          highest_risk.confidence >= 0.5 -> :medium
          true -> :low
        end

        alert_params = %{
          type: :rag_poisoning,
          severity: severity,
          agent_id: agent_id,
          title: "RAG Poisoning Detected: #{highest_risk.category}",
          description: build_alert_description(doc_risks, doc_preview),
          metadata: %{
            document_index: doc_index,
            risk_count: length(doc_risks),
            risks: doc_risks,
            risk_score: scan_result.risk_score,
            technique_ids: Enum.map(doc_risks, & &1.technique_id) |> Enum.uniq()
          },
          mitre_techniques: ["AML.T0019", "AML.T0043"]  # Data poisoning, indirect prompt injection
        }

        case Alerts.create_alert(alert_params) do
          {:ok, alert} ->
            Logger.info(
              "[RagPoisoningHandler] Alert created: #{alert.id} for document #{doc_index}"
            )
            [alert]

          {:error, reason} ->
            Logger.error(
              "[RagPoisoningHandler] Failed to create alert: #{inspect(reason)}"
            )
            []
        end
      else
        []
      end
    end)

    length(alerts)
  end

  defp build_alert_description(risks, doc_preview) do
    risk_summary = risks
    |> Enum.take(3)
    |> Enum.map(fn r ->
      "- #{r.category}: #{r.description} (confidence: #{Float.round(r.confidence * 100, 1)}%)"
    end)
    |> Enum.join("\n")

    """
    Potential RAG poisoning detected in retrieved document.

    **Detected Risks:**
    #{risk_summary}

    **Document Preview:**
    #{String.slice(doc_preview, 0, 150)}...

    **Recommendation:** Review the document source and remove from knowledge base if malicious.
    """
  end

  defp broadcast_scan_result(scan_result, agent_id) do
    topic = if agent_id, do: "rag_security:#{agent_id}", else: "rag_security:global"

    PubSub.broadcast(
      TamanduaServer.PubSub,
      topic,
      {:rag_scan_complete, scan_result}
    )
  end
end
