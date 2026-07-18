defmodule TamanduaServer.Investigations.ShadowOrchestrator do
  @moduledoc """
  Durable admission and observation boundary for AI investigations.

  This module is the bounded admission boundary for explicit and opted-in alert
  creation requests. It remains disconnected from the response engine. It
  verifies tenant ownership, persists one idempotent receipt and schedules only
  a non-enforcing observation worker.

  `shadow` records evidence only. `recommendation` reserves a future governed
  lane for recommendations, but this foundation does not generate or execute
  actions in either mode.
  """

  import Ecto.Query
  require Logger

  alias Ecto.Multi
  alias TamanduaServer.Accounts.Organization
  alias TamanduaServer.Agents.Agent
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Investigations.DetectorObservationConsensusV1
  alias TamanduaServer.Investigations.DetectorProducerRegistry
  alias TamanduaServer.Investigations.{InvestigationEvidence, InvestigationRun}
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.Workers.ShadowInvestigationWorker

  @policy_version "shadow-v2"
  @terminal_statuses ~w(observed abstained failed)

  @type mode :: :shadow | :recommendation | String.t()

  @doc """
  Governed alert-creation admission boundary.

  This trigger is disabled by default and can only enqueue `shadow` runs. Any
  other configured value is rejected; alert creation callers should treat the
  result as degraded enrichment and must never roll back the persisted alert.
  """
  @spec enqueue_from_alert_creation(Alert.t()) ::
          {:ok, InvestigationRun.t()} | {:disabled, atom()} | {:error, term()}
  def enqueue_from_alert_creation(%Alert{} = alert) do
    if policy_config()[:alert_creation_trigger] == :off do
      emit_admission_telemetry(:filtered, alert, %{
        mode: :shadow,
        disposition: "disabled",
        reason: "global_policy_off",
        policy_version: @policy_version
      })

      {:disabled, :policy_off}
    else
      do_enqueue_from_alert_creation(alert)
    end
  end

  defp do_enqueue_from_alert_creation(alert) do
    with {:ok, run} <- persist_alert_creation_admission(alert) do
      case run.admission_disposition do
        "enqueued" ->
          case schedule_admitted_run(run) do
            {:ok, scheduled_run} ->
              emit_admission_telemetry(:queued, alert, receipt_metadata(scheduled_run))
              {:ok, scheduled_run}

            {:error, reason} ->
              degraded_run = mark_admission_degraded(run, reason)
              log_degraded_admission(alert, reason)
              {:error, {:scheduling_failed, degraded_run && degraded_run.id}}
          end

        "disabled" ->
          emit_admission_telemetry(:filtered, alert, receipt_metadata(run))
          {:disabled, safe_reason_atom(run.admission_reason)}

        "capacity_limited" ->
          emit_admission_telemetry(:capacity_limited, alert, receipt_metadata(run))
          {:ok, run}

        disposition when disposition in ["ineligible", "degraded"] ->
          emit_admission_telemetry(:filtered, alert, receipt_metadata(run))
          {:ok, run}
      end
    else
      {:error, reason} = error ->
        log_degraded_admission(alert, reason)
        error
    end
  rescue
    error ->
      reason = {:exception, Exception.message(error)}
      log_degraded_admission(alert, reason)
      {:error, reason}
  catch
    :exit, reason ->
      degraded_reason = {:exit, reason}
      log_degraded_admission(alert, degraded_reason)
      {:error, degraded_reason}
  end

  @spec enqueue(Ecto.UUID.t(), Ecto.UUID.t(), keyword()) ::
          {:ok, InvestigationRun.t()} | {:error, term()}
  def enqueue(organization_id, alert_id, opts \\ []) do
    mode = opts |> Keyword.get(:mode, "shadow") |> to_string()
    source = opts |> Keyword.get(:source, "explicit") |> to_string()

    with :ok <- valid_uuid(organization_id, :invalid_organization_id),
         :ok <- valid_uuid(alert_id, :invalid_alert_id),
         :ok <- validate_mode(mode),
         :ok <- validate_source(source) do
      idempotency_key = idempotency_key(organization_id, alert_id, mode)

      Multi.new()
      |> Multi.run(:alert, fn repo, _changes ->
        scoped_alert(repo, organization_id, alert_id)
      end)
      |> Multi.run(:run, fn repo, _changes ->
        get_or_insert_run(repo, organization_id, alert_id, idempotency_key, mode, source,
          admission_disposition: "enqueued",
          admission_reason: "explicit_request"
        )
      end)
      |> Multi.merge(fn %{run: run} -> maybe_enqueue_job(run) end)
      |> then(&MultiTenant.transaction(organization_id, &1))
      |> case do
        {:ok, %{run: run}} -> {:ok, run}
        {:error, _step, reason, _changes} -> {:error, reason}
      end
    end
  end

  @doc "Attaches a data-only detector observation envelope to a tenant alert."
  @spec attach_detector_observation(Ecto.UUID.t(), Ecto.UUID.t(), map(), Ecto.UUID.t() | nil) ::
          {:ok, %{run: InvestigationRun.t(), contract_hash: String.t()}}
          | {:error, term()}
  def attach_detector_observation(
        organization_id,
        alert_id,
        envelope,
        producer_attestation_ids \\ nil
      ) do
    producer_attestation_ids = List.wrap(producer_attestation_ids)

    with :ok <- valid_uuid(organization_id, :invalid_organization_id),
         :ok <- valid_uuid(alert_id, :invalid_alert_id),
         :ok <- valid_attestation_ids(producer_attestation_ids) do
      contract_admission = DetectorObservationConsensusV1.validate_and_normalize(envelope)

      Multi.new()
      |> Multi.run(:alert, fn repo, _changes ->
        scoped_alert(repo, organization_id, alert_id, lock: :for_update)
      end)
      |> Multi.run(:admission, fn repo, %{alert: alert} ->
        admission =
          with {:ok, normalized} <- contract_admission,
               {:ok, attestations} <-
                 DetectorProducerRegistry.authorize_many_scoped(
                   repo,
                   organization_id,
                   producer_attestation_ids,
                   normalized
                 ) do
            {:ok, normalized, attestations}
          end

        persist_detector_admission(repo, alert, admission)
      end)
      |> then(&MultiTenant.transaction(organization_id, &1))
      |> case do
        {:ok, %{admission: {:validated, contract_hash}}} ->
          with {:ok, run} <- enqueue(organization_id, alert_id, mode: :shadow) do
            {:ok, %{run: run, contract_hash: contract_hash}}
          end

        {:ok, %{admission: {:rejected, errors}}} ->
          _ = enqueue(organization_id, alert_id, mode: :shadow)
          {:error, {:invalid_envelope, errors}}

        {:error, _step, reason, _changes} ->
          {:error, reason}
      end
    end
  end

  @doc "Processes one persisted run without invoking an action or response subsystem."
  @spec process(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, InvestigationRun.t()} | {:error, term()}
  def process(organization_id, run_id) do
    with :ok <- valid_uuid(organization_id, :invalid_organization_id),
         :ok <- valid_uuid(run_id, :invalid_run_id) do
      Multi.new()
      |> Multi.run(:run, fn repo, _changes -> locked_run(repo, organization_id, run_id) end)
      |> Multi.run(:alert, fn repo, %{run: run} ->
        scoped_alert(repo, organization_id, run.alert_id)
      end)
      |> Multi.run(:started_run, fn repo, %{run: run} -> mark_running(repo, run) end)
      |> Multi.run(:collection, fn repo, %{alert: alert, started_run: run} ->
        collect_observational_evidence(repo, organization_id, run, alert)
      end)
      |> Multi.run(:completed_run, fn repo, %{started_run: run, collection: collection} ->
        complete_observation(repo, run, collection)
      end)
      |> then(&MultiTenant.transaction(organization_id, &1))
      |> case do
        {:ok, %{completed_run: run}} -> {:ok, run}
        {:error, _step, reason, _changes} -> {:error, reason}
      end
    end
  end

  @spec get_run(Ecto.UUID.t(), Ecto.UUID.t()) :: InvestigationRun.t() | nil
  def get_run(organization_id, run_id) do
    with :ok <- valid_uuid(organization_id, :invalid_organization_id),
         :ok <- valid_uuid(run_id, :invalid_run_id) do
      MultiTenant.with_organization(organization_id, fn ->
        Repo.one(
          from(run in InvestigationRun,
            where: run.organization_id == ^organization_id and run.id == ^run_id
          )
        )
      end)
    else
      _ -> nil
    end
  end

  @spec list_runs_for_alert(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, [InvestigationRun.t()]} | {:error, term()}
  def list_runs_for_alert(organization_id, alert_id) do
    with :ok <- valid_uuid(organization_id, :invalid_organization_id),
         :ok <- valid_uuid(alert_id, :invalid_alert_id) do
      MultiTenant.with_organization(organization_id, fn ->
        with {:ok, _alert} <- scoped_alert(Repo, organization_id, alert_id) do
          {:ok,
           Repo.all(
             from(run in InvestigationRun,
               where: run.organization_id == ^organization_id and run.alert_id == ^alert_id,
               order_by: [desc: run.inserted_at, desc: run.id]
             )
           )}
        end
      end)
    end
  end

  @spec list_evidence(Ecto.UUID.t(), Ecto.UUID.t()) :: [InvestigationEvidence.t()]
  def list_evidence(organization_id, run_id) do
    with :ok <- valid_uuid(organization_id, :invalid_organization_id),
         :ok <- valid_uuid(run_id, :invalid_run_id) do
      MultiTenant.with_organization(organization_id, fn ->
        Repo.all(
          from(evidence in InvestigationEvidence,
            where: evidence.organization_id == ^organization_id and evidence.run_id == ^run_id,
            order_by: [asc: evidence.observed_at, asc: evidence.id]
          )
        )
      end)
    else
      _ -> []
    end
  end

  @doc "Serializes the stable, model-agnostic investigation run API contract."
  @spec serialize_run(InvestigationRun.t()) :: map()
  def serialize_run(%InvestigationRun{} = run) do
    %{
      id: run.id,
      alert_id: run.alert_id,
      mode: run.mode,
      status: run.status,
      source: run.source,
      policy_version: run.policy_version,
      admission_disposition: run.admission_disposition,
      admission_reason: run.admission_reason,
      enforcement: "disabled",
      summary: run.summary,
      started_at: run.started_at,
      completed_at: run.completed_at,
      inserted_at: run.inserted_at,
      updated_at: run.updated_at
    }
  end

  @doc "Serializes only persisted evidence, excluding tenant and dedupe internals."
  @spec serialize_evidence(InvestigationEvidence.t()) :: map()
  def serialize_evidence(%InvestigationEvidence{} = evidence) do
    %{
      id: evidence.id,
      run_id: evidence.run_id,
      kind: evidence.kind,
      source: evidence.source,
      source_ref: evidence.source_ref,
      payload: evidence.payload,
      observed_at: evidence.observed_at,
      inserted_at: evidence.inserted_at
    }
  end

  @spec idempotency_key(Ecto.UUID.t(), Ecto.UUID.t(), String.t()) :: String.t()
  def idempotency_key(organization_id, alert_id, mode) do
    :crypto.hash(:sha256, "#{@policy_version}:#{organization_id}:#{alert_id}:#{mode}")
    |> Base.encode16(case: :lower)
  end

  defp validate_mode(mode) when mode in ["shadow", "recommendation"], do: :ok
  defp validate_mode(_mode), do: {:error, :unsupported_mode}

  defp validate_source(source) when source in ["explicit", "alert_creation"], do: :ok
  defp validate_source(_source), do: {:error, :unsupported_source}

  defp valid_uuid(value, error) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, _uuid} -> :ok
      :error -> {:error, error}
    end
  end

  defp valid_uuid(_value, error), do: {:error, error}

  defp scoped_alert(repo, organization_id, alert_id, opts \\ []) do
    for_update? = Keyword.get(opts, :lock) == :for_update

    query =
      from(alert in Alert,
        where: alert.organization_id == ^organization_id and alert.id == ^alert_id
      )

    query = if for_update?, do: lock(query, "FOR UPDATE"), else: query

    case repo.one(query) do
      nil -> {:error, :alert_not_found_in_organization}
      alert -> {:ok, alert}
    end
  end

  defp persist_alert_creation_admission(alert) do
    idempotency_key = idempotency_key(alert.organization_id, alert.id, "automatic-shadow")

    Multi.new()
    |> Multi.run(:alert, fn repo, _changes ->
      scoped_alert(repo, alert.organization_id, alert.id, lock: :for_update)
    end)
    |> Multi.run(:organization, fn repo, _changes ->
      case repo.one(
             from(organization in Organization,
               where: organization.id == ^alert.organization_id,
               lock: "FOR UPDATE"
             )
           ) do
        nil -> {:error, :organization_not_found}
        organization -> {:ok, organization}
      end
    end)
    |> Multi.run(:run, fn repo, %{alert: persisted_alert, organization: organization} ->
      case find_run(repo, alert.organization_id, idempotency_key) do
        %InvestigationRun{} = run ->
          {:ok, run}

        nil ->
          {disposition, reason} =
            automatic_admission_decision(repo, organization, persisted_alert)

          insert_admission_receipt(
            repo,
            persisted_alert,
            idempotency_key,
            disposition,
            reason
          )
      end
    end)
    |> then(&MultiTenant.transaction(alert.organization_id, &1))
    |> case do
      {:ok, %{run: run}} -> {:ok, run}
      {:error, _step, reason, _changes} -> {:error, reason}
    end
  end

  @doc "Marks an exhausted shadow worker run failed without producing a decision or action."
  @spec mark_failed(Ecto.UUID.t(), Ecto.UUID.t(), term()) ::
          {:ok, InvestigationRun.t()} | {:error, term()}
  def mark_failed(organization_id, run_id, reason) do
    with :ok <- valid_uuid(organization_id, :invalid_organization_id),
         :ok <- valid_uuid(run_id, :invalid_run_id) do
      MultiTenant.with_organization(organization_id, fn ->
        case get_run(organization_id, run_id) do
          nil ->
            {:error, :run_not_found_in_organization}

          %InvestigationRun{status: status} = run when status in @terminal_statuses ->
            {:ok, run}

          run ->
            run
            |> Ecto.Changeset.change(
              status: "failed",
              error_code: safe_reason(reason),
              completed_at: DateTime.utc_now(),
              summary: %{
                "admission" => %{
                  "disposition" => run.admission_disposition,
                  "reason" => run.admission_reason
                },
                "decision" => "not_evaluated",
                "enforcement" => "disabled",
                "observation_state" => "failed"
              }
            )
            |> Repo.update()
        end
      end)
    end
  end

  defp automatic_admission_decision(repo, organization, alert) do
    config = policy_config()
    severity = alert.severity |> to_string() |> String.downcase()

    cond do
      config[:alert_creation_trigger] == :off ->
        {"disabled", "global_policy_off"}

      config[:alert_creation_trigger] != :shadow ->
        {"degraded", "unsupported_trigger_configuration"}

      not tenant_opted_in?(organization) ->
        {"disabled", "tenant_not_opted_in"}

      severity not in config[:eligible_severities] ->
        {"ineligible", "severity_not_eligible"}

      active_admission_count(repo, organization.id) >= config[:max_active_per_tenant] ->
        {"capacity_limited", "tenant_active_limit"}

      recent_admission_count(repo, organization.id) >= config[:max_admissions_per_minute] ->
        {"capacity_limited", "tenant_rate_limit"}

      true ->
        {"enqueued", "eligible_shadow_observation"}
    end
  end

  defp tenant_opted_in?(organization) do
    features = normalize_map(organization.features)

    map_value(features, "automatic_investigation_shadow_v2") == true
  end

  defp active_admission_count(repo, organization_id) do
    repo.aggregate(
      from(run in InvestigationRun,
        where:
          run.organization_id == ^organization_id and
            run.source == "alert_creation" and
            run.admission_disposition == "enqueued" and
            run.status in ["queued", "running"]
      ),
      :count
    )
  end

  defp recent_admission_count(repo, organization_id) do
    cutoff = DateTime.add(DateTime.utc_now(), -60, :second)

    repo.aggregate(
      from(run in InvestigationRun,
        where:
          run.organization_id == ^organization_id and
            run.source == "alert_creation" and
            run.admission_disposition == "enqueued" and
            run.inserted_at >= ^cutoff
      ),
      :count
    )
  end

  defp insert_admission_receipt(repo, alert, idempotency_key, disposition, reason) do
    enqueued? = disposition == "enqueued"
    now = DateTime.utc_now()

    attrs = %{
      organization_id: alert.organization_id,
      alert_id: alert.id,
      idempotency_key: idempotency_key,
      mode: "shadow",
      status: if(enqueued?, do: "queued", else: "abstained"),
      source: "alert_creation",
      policy_version: @policy_version,
      admission_disposition: disposition,
      admission_reason: reason,
      completed_at: if(enqueued?, do: nil, else: now),
      summary: %{
        "admission" => %{"disposition" => disposition, "reason" => reason},
        "decision" => "not_evaluated",
        "enforcement" => "disabled",
        "mode" => "shadow"
      }
    }

    %InvestigationRun{}
    |> InvestigationRun.create_changeset(attrs)
    |> repo.insert(
      on_conflict: :nothing,
      conflict_target: [:organization_id, :idempotency_key]
    )
    |> case do
      {:ok, _run} -> {:ok, find_run(repo, alert.organization_id, idempotency_key)}
      {:error, changeset} -> {:error, changeset}
    end
  end

  defp find_run(repo, organization_id, idempotency_key) do
    repo.one(
      from(run in InvestigationRun,
        where:
          run.organization_id == ^organization_id and
            run.idempotency_key == ^idempotency_key
      )
    )
  end

  defp schedule_admitted_run(%InvestigationRun{admission_disposition: "enqueued"} = run) do
    args = %{"organization_id" => run.organization_id, "run_id" => run.id}

    case Oban.insert(ShadowInvestigationWorker.new(args)) do
      {:ok, _job} -> {:ok, run}
      {:error, reason} -> {:error, reason}
    end
  rescue
    error -> {:error, error}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp mark_admission_degraded(run, reason) do
    degraded_summary =
      Map.merge(run.summary || %{}, %{
        "admission" => %{
          "disposition" => "degraded",
          "reason" => "worker_scheduling_failed"
        },
        "decision" => "not_evaluated",
        "enforcement" => "disabled",
        "observation_state" => "failed"
      })

    MultiTenant.with_organization(run.organization_id, fn ->
      run
      |> Ecto.Changeset.change(
        admission_disposition: "degraded",
        admission_reason: "worker_scheduling_failed",
        status: "failed",
        error_code: safe_reason(reason),
        completed_at: DateTime.utc_now(),
        summary: degraded_summary
      )
      |> Repo.update()
      |> case do
        {:ok, updated} -> updated
        {:error, _changeset} -> nil
      end
    end)
  rescue
    _error -> nil
  end

  defp get_or_insert_run(
         repo,
         organization_id,
         alert_id,
         idempotency_key,
         mode,
         source,
         admission_attrs
       ) do
    query =
      from(run in InvestigationRun,
        where:
          run.organization_id == ^organization_id and
            run.idempotency_key == ^idempotency_key
      )

    case repo.one(query) do
      %InvestigationRun{} = run ->
        {:ok, run}

      nil ->
        %InvestigationRun{}
        |> InvestigationRun.create_changeset(%{
          organization_id: organization_id,
          alert_id: alert_id,
          idempotency_key: idempotency_key,
          mode: mode,
          status: "queued",
          source: source,
          policy_version: @policy_version,
          admission_disposition: Keyword.fetch!(admission_attrs, :admission_disposition),
          admission_reason: Keyword.fetch!(admission_attrs, :admission_reason),
          summary: %{"enforcement" => "disabled"}
        })
        |> repo.insert(
          on_conflict: :nothing,
          conflict_target: [:organization_id, :idempotency_key]
        )
        |> case do
          {:ok, _run} ->
            # A concurrent insert with ON CONFLICT returns a non-loaded struct;
            # always re-read under the tenant scope to return the durable row.
            {:ok, repo.one!(query)}

          {:error, changeset} ->
            {:error, changeset}
        end
    end
  end

  defp maybe_enqueue_job(%InvestigationRun{status: status}) when status in @terminal_statuses,
    do: Multi.new()

  defp maybe_enqueue_job(run) do
    args = %{"organization_id" => run.organization_id, "run_id" => run.id}
    Multi.new() |> Oban.insert(:job, ShadowInvestigationWorker.new(args))
  end

  defp locked_run(repo, organization_id, run_id) do
    case repo.one(
           from(run in InvestigationRun,
             where: run.organization_id == ^organization_id and run.id == ^run_id,
             lock: "FOR UPDATE"
           )
         ) do
      nil ->
        {:error, :run_not_found_in_organization}

      %InvestigationRun{admission_disposition: disposition} when disposition != "enqueued" ->
        {:error, :run_not_admitted}

      run ->
        {:ok, run}
    end
  end

  defp mark_running(_repo, %InvestigationRun{status: status} = run)
       when status in @terminal_statuses,
       do: {:ok, run}

  defp mark_running(repo, run) do
    now = DateTime.utc_now()

    run
    |> Ecto.Changeset.change(status: "running", started_at: run.started_at || now)
    |> repo.update()
  end

  defp collect_observational_evidence(
         repo,
         organization_id,
         %InvestigationRun{status: status} = run,
         _alert
       )
       when status in @terminal_statuses do
    {:ok,
     %{
       evidence_count: evidence_count(repo, organization_id, run.id),
       degraded_sources: run.summary["degraded_sources"] || [],
       confidence: run.summary["confidence"]
     }}
  end

  defp collect_observational_evidence(repo, organization_id, run, alert) do
    {agent, initial_degraded} = scoped_agent_posture(repo, organization_id, alert.agent_id)

    {sources, contract_degraded} = observational_sources(alert, agent)

    degraded_sources =
      Enum.reduce(sources, initial_degraded ++ contract_degraded, fn source, degraded ->
        case persist_evidence_source(repo, organization_id, run, alert.id, source) do
          :ok ->
            degraded

          {:error, reason} ->
            [%{"source" => source.kind, "reason" => safe_reason(reason)} | degraded]
        end
      end)
      |> Enum.reverse()
      |> Enum.uniq_by(& &1["source"])

    {:ok,
     %{
       evidence_count: evidence_count(repo, organization_id, run.id),
       degraded_sources: degraded_sources,
       confidence: observation_confidence(alert)
     }}
  rescue
    error ->
      {:ok,
       %{
         evidence_count: evidence_count(repo, organization_id, run.id),
         degraded_sources: [
           %{"source" => "collection", "reason" => safe_reason(error)}
         ],
         confidence: observation_confidence(alert)
       }}
  end

  defp complete_observation(_repo, %InvestigationRun{status: status} = run, _collection)
       when status in @terminal_statuses,
       do: {:ok, run}

  defp complete_observation(repo, run, collection) do
    observation_state =
      cond do
        collection.evidence_count == 0 -> "abstained"
        collection.degraded_sources != [] -> "degraded"
        true -> "observed"
      end

    run
    |> Ecto.Changeset.change(
      status: if(collection.evidence_count == 0, do: "abstained", else: "observed"),
      completed_at: DateTime.utc_now(),
      summary: %{
        "decision" => "not_evaluated",
        "enforcement" => "disabled",
        "mode" => run.mode,
        "observation_state" => observation_state,
        "evidence_count" => collection.evidence_count,
        "degraded_sources" => collection.degraded_sources,
        "confidence" => collection.confidence
      }
    )
    |> repo.update()
  end

  defp persist_detector_admission(repo, alert, {:ok, normalized, attestations}) do
    contract_hash = DetectorObservationConsensusV1.hash(normalized)
    enrichment = normalize_map(alert.enrichment)
    section = enrichment |> map_value("detector_observation_consensus_v1") |> normalize_map()

    envelopes =
      [
        %{
          "contract_hash_sha256" => contract_hash,
          "validated" => true,
          "envelope" => normalized,
          "consensus_claim" => DetectorObservationConsensusV1.consensus_claim_status(normalized),
          "producer_attestations" => Enum.map(attestations, &producer_attestation_binding/1),
          "admitted_at" => DateTime.utc_now() |> DateTime.to_iso8601()
        }
        | list_or_empty(map_value(section, "validated_envelopes"))
      ]
      |> Enum.uniq_by(&map_value(&1, "contract_hash_sha256"))
      |> Enum.take(4)

    updated_section = Map.put(section, "validated_envelopes", envelopes)
    updated_enrichment = Map.put(enrichment, "detector_observation_consensus_v1", updated_section)

    case alert |> Ecto.Changeset.change(enrichment: updated_enrichment) |> repo.update() do
      {:ok, _alert} -> {:ok, {:validated, contract_hash}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp persist_detector_admission(repo, alert, {:error, errors}) when is_list(errors) do
    enrichment = normalize_map(alert.enrichment)
    section = enrichment |> map_value("detector_observation_consensus_v1") |> normalize_map()

    rejection = %{
      "reason" => "invalid_envelope",
      "errors" => errors |> Enum.take(10) |> Enum.map(&bounded_string(&1, 256)),
      "rejected_at" => DateTime.utc_now() |> DateTime.to_iso8601()
    }

    rejections =
      [rejection | list_or_empty(map_value(section, "degraded_reasons"))] |> Enum.take(10)

    updated_section = Map.put(section, "degraded_reasons", rejections)
    updated_enrichment = Map.put(enrichment, "detector_observation_consensus_v1", updated_section)

    case alert |> Ecto.Changeset.change(enrichment: updated_enrichment) |> repo.update() do
      {:ok, _alert} -> {:ok, {:rejected, errors}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp persist_detector_admission(repo, alert, {:error, reason}) when is_atom(reason) do
    persist_detector_admission(repo, alert, {:error, [Atom.to_string(reason)]})
  end

  defp persist_detector_admission(repo, alert, {:error, {:unauthorized_detector_claim, errors}}) do
    persist_detector_admission(repo, alert, {:error, errors})
  end

  defp scoped_agent_posture(_repo, _organization_id, nil) do
    {nil, [%{"source" => "agent_posture", "reason" => "agent_not_associated"}]}
  end

  defp scoped_agent_posture(repo, organization_id, agent_id) do
    agent =
      repo.one(
        from(agent in Agent,
          where: agent.organization_id == ^organization_id and agent.id == ^agent_id
        )
      )

    case agent do
      %Agent{} -> {agent, []}
      nil -> {nil, [%{"source" => "agent_posture", "reason" => "agent_not_found"}]}
    end
  rescue
    error -> {nil, [%{"source" => "agent_posture", "reason" => safe_reason(error)}]}
  end

  defp observational_sources(alert, agent) do
    {contract_sources, contract_degraded} = detector_contract_sources(alert)

    sources =
      [
        evidence_source("alert_normalized", "tamandua.alerts", alert.id, %{
          "alert_id" => alert.id,
          "severity" => alert.severity,
          "status" => alert.status,
          "title" => bounded_string(alert.title, 256),
          "threat_score" => alert.threat_score,
          "verdict" => alert.verdict,
          "occurrence_count" => alert.occurrence_count,
          "mitre_tactics" => Enum.take(alert.mitre_tactics || [], 20),
          "mitre_techniques" => Enum.take(alert.mitre_techniques || [], 30),
          "source_event_id" => alert.source_event_id
        }),
        maybe_agent_source(alert, agent),
        maybe_collection_source(
          "contributing_events",
          "tamandua.alerts.correlation",
          alert.id,
          contributing_event_ids(alert),
          "event_ids"
        ),
        maybe_collection_source(
          "process_chain",
          "tamandua.alerts.evidence",
          alert.id,
          sanitized_process_chain(alert.process_chain),
          "processes"
        ),
        maybe_collection_source(
          "indicators",
          "tamandua.alerts.evidence",
          alert.id,
          extract_indicators(alert.evidence),
          "indicators"
        ),
        maybe_analysis_source(alert)
        | contract_sources
      ]
      |> Enum.reject(&is_nil/1)

    {sources, contract_degraded}
  end

  defp detector_contract_sources(alert) do
    section =
      alert.enrichment
      |> normalize_map()
      |> map_value("detector_observation_consensus_v1")
      |> normalize_map()

    {sources, validation_degraded} =
      section
      |> map_value("validated_envelopes")
      |> list_or_empty()
      |> Enum.take(4)
      |> Enum.reduce({[], []}, fn entry, {sources, degraded} ->
        entry = normalize_map(entry)
        envelope = map_value(entry, "envelope")
        expected_hash = map_value(entry, "contract_hash_sha256")

        producer_attestation_ids =
          entry
          |> map_value("producer_attestations")
          |> list_or_empty()
          |> Enum.map(&(&1 |> normalize_map() |> map_value("id")))

        case DetectorObservationConsensusV1.validate_and_normalize(envelope) do
          {:ok, normalized} ->
            actual_hash = DetectorObservationConsensusV1.hash(normalized)

            registry_authorization =
              DetectorProducerRegistry.authorize_many_scoped(
                Repo,
                alert.organization_id,
                producer_attestation_ids,
                normalized
              )

            if entry_validated?(entry) and actual_hash == expected_hash and
                 match?({:ok, _}, registry_authorization) do
              {:ok, attestations} = registry_authorization

              source =
                evidence_source(
                  "detector_observation_consensus",
                  "tamandua.detector_observation_consensus_v1",
                  alert.id,
                  %{
                    "contract_hash_sha256" => actual_hash,
                    "envelope" => normalized,
                    "consensus_claim" =>
                      DetectorObservationConsensusV1.consensus_claim_status(normalized),
                    "producer_attestations" =>
                      Enum.map(attestations, &producer_attestation_binding/1),
                    "enforcement" => "disabled"
                  }
                )
                |> Map.put(:dedupe_suffix, actual_hash)

              {[source | sources], degraded}
            else
              {sources,
               [
                 %{
                   "source" => "detector_observation_contract",
                   "reason" => "provenance_or_registry_attestation_invalid"
                 }
                 | degraded
               ]}
            end

          {:error, _errors} ->
            {sources,
             [
               %{
                 "source" => "detector_observation_contract",
                 "reason" => "stored_envelope_failed_validation"
               }
               | degraded
             ]}
        end
      end)

    admission_degraded =
      section
      |> map_value("degraded_reasons")
      |> list_or_empty()
      |> Enum.take(10)
      |> Enum.map(fn _rejection ->
        %{"source" => "detector_observation_contract", "reason" => "invalid_envelope"}
      end)

    {Enum.reverse(sources), Enum.reverse(validation_degraded) ++ admission_degraded}
  end

  defp entry_validated?(entry), do: map_value(entry, "validated") == true

  defp producer_attestation_binding(attestation) do
    %{
      "id" => attestation.id,
      "producer_id" => attestation.producer_id,
      "attestation_sha256" => attestation.attestation_sha256
    }
  end

  defp valid_attestation_ids(ids) when is_list(ids) and length(ids) in 1..32 do
    if Enum.all?(ids, &(valid_uuid(&1, :invalid) == :ok)),
      do: :ok,
      else: {:error, :producer_attestation_required}
  end

  defp valid_attestation_ids(_ids), do: {:error, :producer_attestation_required}

  defp evidence_source(kind, source, source_ref, payload) do
    %{kind: kind, source: source, source_ref: source_ref, payload: payload}
  end

  defp maybe_agent_source(_alert, nil), do: nil

  defp maybe_agent_source(alert, agent) do
    isolation = normalize_map(agent.isolation_status)

    evidence_source("agent_posture", "tamandua.agents", alert.id, %{
      "agent_id" => agent.id,
      "status" => agent.status,
      "os_type" => agent.os_type,
      "os_version" => bounded_string(agent.os_version, 128),
      "agent_version" => bounded_string(agent.agent_version, 64),
      "last_seen_at" => timestamp_value(agent.last_seen_at),
      "isolation" => %{
        "state" => map_value(isolation, "state") || map_value(isolation, "status"),
        "isolated" => map_value(isolation, "isolated")
      },
      "certificate_valid_until" => timestamp_value(agent.certificate_valid_until),
      "token_rotation_enabled" => agent.token_rotation_enabled
    })
  end

  defp maybe_collection_source(_kind, _source, _ref, [], _payload_key), do: nil

  defp maybe_collection_source(kind, source, source_ref, items, payload_key) do
    evidence_source(kind, source, source_ref, %{payload_key => items})
  end

  defp maybe_analysis_source(alert) do
    enrichment =
      alert.enrichment
      |> normalize_map()
      |> Map.drop(["detector_observation_consensus_v1", :detector_observation_consensus_v1])

    analysis_maps = [alert.detection_metadata, enrichment, alert.evidence]
    signals = analysis_maps |> Enum.flat_map(&analysis_signals(&1, 0)) |> Enum.take(30)

    triage =
      analysis_maps
      |> Enum.map(&find_nested_map(&1, ["triage_agent", "triage", "triage_result"]))
      |> Enum.find(&is_map/1)
      |> sanitize_triage()

    plan =
      alert.detection_metadata
      |> find_nested_map(["investigation_enrichment"])
      |> sanitize_enrichment_plan()

    if signals == [] and triage == %{} and plan == %{} do
      nil
    else
      evidence_source("analysis_context", "tamandua.alert_analysis", alert.id, %{
        "triage" => triage,
        "enrichment" => plan,
        "signals" => signals
      })
    end
  end

  defp contributing_event_ids(alert) do
    [alert.source_event_id | (alert.event_ids || []) ++ (alert.contributing_events || [])]
    |> Enum.filter(&(is_binary(&1) and &1 != ""))
    |> Enum.uniq()
    |> Enum.take(50)
  end

  defp sanitized_process_chain(chain) when is_list(chain) do
    chain
    |> Enum.take(25)
    |> Enum.filter(&is_map/1)
    |> Enum.map(fn process ->
      %{
        "pid" => map_value(process, "pid"),
        "ppid" => map_value(process, "ppid") || map_value(process, "parent_pid"),
        "name" =>
          bounded_string(map_value(process, "name") || map_value(process, "process_name"), 128),
        "path" =>
          bounded_string(map_value(process, "path") || map_value(process, "image_path"), 384),
        "command_line" =>
          redact_command_line(map_value(process, "command_line") || map_value(process, "cmdline")),
        "signed" => map_value(process, "signed") || map_value(process, "is_signed")
      }
      |> compact_map()
    end)
  end

  defp sanitized_process_chain(_chain), do: []

  defp extract_indicators(evidence) do
    evidence = normalize_map(evidence)
    direct = map_value(evidence, "iocs")

    direct_indicators =
      if is_list(direct) do
        Enum.map(direct, fn indicator ->
          indicator = normalize_map(indicator)

          %{
            "type" => bounded_string(map_value(indicator, "type"), 32),
            "value" => bounded_string(map_value(indicator, "value"), 512),
            "source" => bounded_string(map_value(indicator, "source"), 64),
            "confidence" => map_value(indicator, "confidence")
          }
          |> compact_map()
        end)
      else
        []
      end

    file_indicators =
      evidence
      |> map_value("file_hashes")
      |> list_or_empty()
      |> Enum.flat_map(fn file ->
        file = normalize_map(file)

        for type <- ["sha256", "sha1", "md5"],
            value = map_value(file, type),
            is_binary(value) and value != "" do
          %{"type" => type, "value" => bounded_string(value, 128), "source" => "file_hashes"}
        end
      end)

    (direct_indicators ++ file_indicators)
    |> Enum.filter(&(is_binary(&1["value"]) and &1["value"] != ""))
    |> Enum.uniq_by(&{&1["type"], &1["value"]})
    |> Enum.take(50)
  end

  defp analysis_signals(value, depth) when depth <= 3 and is_map(value) do
    value
    |> Enum.take(60)
    |> Enum.flat_map(fn {key, nested} ->
      metric = key |> to_string() |> String.downcase()

      if signal_key?(metric) and (is_number(nested) or is_binary(nested) or is_boolean(nested)) do
        [%{"metric" => bounded_string(metric, 64), "value" => bounded_scalar(nested)}]
      else
        analysis_signals(nested, depth + 1)
      end
    end)
  end

  defp analysis_signals(value, depth) when depth <= 3 and is_list(value) do
    value |> Enum.take(20) |> Enum.flat_map(&analysis_signals(&1, depth + 1))
  end

  defp analysis_signals(_value, _depth), do: []

  defp signal_key?(key) do
    Enum.any?(
      ["score", "confidence", "decision", "priority", "consensus", "risk"],
      &String.contains?(key, &1)
    )
  end

  defp find_nested_map(value, keys) when is_map(value) do
    normalized = normalize_map(value)

    Enum.find_value(keys, fn key ->
      case map_value(normalized, key) do
        nested when is_map(nested) -> nested
        _ -> nil
      end
    end)
  end

  defp find_nested_map(_value, _keys), do: nil

  defp sanitize_triage(nil), do: %{}

  defp sanitize_triage(triage) do
    triage = normalize_map(triage)

    ["status", "decision", "priority", "confidence", "evidence_quality", "claimable"]
    |> Map.new(fn key -> {key, bounded_scalar(map_value(triage, key))} end)
    |> compact_map()
  end

  defp sanitize_enrichment_plan(nil), do: %{}

  defp sanitize_enrichment_plan(plan) do
    plan = normalize_map(plan)

    ["status", "mode", "requested_at", "completed_at", "degraded", "evidence_count"]
    |> Map.new(fn key -> {key, bounded_scalar(map_value(plan, key))} end)
    |> compact_map()
  end

  defp persist_evidence_source(repo, organization_id, run, alert_id, source) do
    attrs = %{
      organization_id: organization_id,
      run_id: run.id,
      kind: source.kind,
      source: source.source,
      source_ref: alert_id,
      dedupe_key: "#{source.kind}:v1:#{Map.get(source, :dedupe_suffix, alert_id)}",
      observed_at: DateTime.utc_now(),
      payload: source.payload
    }

    case %InvestigationEvidence{}
         |> InvestigationEvidence.changeset(attrs)
         |> repo.insert(
           on_conflict: :nothing,
           conflict_target: [:organization_id, :run_id, :dedupe_key]
         ) do
      {:ok, _evidence} -> :ok
      {:error, reason} -> {:error, reason}
    end
  rescue
    error -> {:error, error}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp evidence_count(repo, organization_id, run_id) do
    repo.aggregate(
      from(evidence in InvestigationEvidence,
        where: evidence.organization_id == ^organization_id and evidence.run_id == ^run_id
      ),
      :count
    )
  rescue
    _error -> 0
  end

  defp observation_confidence(alert) do
    value =
      [alert.attribution_confidence, alert.attestation_confidence, alert.threat_score]
      |> Enum.find(&is_number/1)

    case value do
      nil -> nil
      score when score > 1 -> min(score / 100, 1.0)
      score when score < 0 -> 0.0
      score -> score / 1
    end
  end

  defp normalize_map(value) when is_map(value), do: value
  defp normalize_map(_value), do: %{}

  defp map_value(map, key) when is_map(map) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, safe_existing_atom(key))
    end
  end

  defp map_value(_map, _key), do: nil

  defp safe_existing_atom(key) do
    String.to_existing_atom(key)
  rescue
    ArgumentError -> :__missing_key__
  end

  defp list_or_empty(value) when is_list(value), do: value
  defp list_or_empty(_value), do: []

  defp compact_map(map), do: Map.reject(map, fn {_key, value} -> is_nil(value) or value == "" end)

  defp bounded_scalar(value) when is_binary(value), do: bounded_string(value, 256)
  defp bounded_scalar(value) when is_number(value) or is_boolean(value), do: value
  defp bounded_scalar(_value), do: nil

  defp bounded_string(value, limit) when is_binary(value), do: String.slice(value, 0, limit)

  defp bounded_string(value, limit) when is_atom(value),
    do: value |> Atom.to_string() |> String.slice(0, limit)

  defp bounded_string(_value, _limit), do: nil

  defp redact_command_line(value) when is_binary(value) do
    value
    |> String.slice(0, 2_048)
    |> then(
      &Regex.replace(
        ~r{([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^@\s/]+@}i,
        &1,
        "\\1[REDACTED]@"
      )
    )
    |> then(
      &Regex.replace(
        ~r/(\bauthorization\s*[:=]\s*)(?:bearer\s+)?[^\s"']+/i,
        &1,
        "\\1[REDACTED]"
      )
    )
    |> then(
      &Regex.replace(
        ~r/((?:--?)(?:password|passwd|token|api[_-]?key|authorization)(?:\s+|=))(?:"[^"]*"|'[^']*'|\S+)/i,
        &1,
        "\\1[REDACTED]"
      )
    )
    |> then(&Regex.replace(~r/\bbearer\s+[^\s"']+/i, &1, "Bearer [REDACTED]"))
    |> String.slice(0, 512)
  end

  defp redact_command_line(_value), do: nil

  defp timestamp_value(%DateTime{} = value), do: DateTime.to_iso8601(value)
  defp timestamp_value(%NaiveDateTime{} = value), do: NaiveDateTime.to_iso8601(value)
  defp timestamp_value(_value), do: nil

  defp safe_reason(%Ecto.Changeset{} = changeset),
    do: "validation_failed:#{inspect(changeset.errors)}"

  defp safe_reason(error) when is_exception(error),
    do: error |> Exception.message() |> bounded_string(256)

  defp safe_reason(reason),
    do: reason |> inspect(limit: 8, printable_limit: 128) |> bounded_string(256)

  defp policy_config do
    config = Application.get_env(:tamandua_server, __MODULE__, [])

    %{
      alert_creation_trigger: Keyword.get(config, :alert_creation_trigger, :off),
      eligible_severities:
        config
        |> Keyword.get(:eligible_severities, ["critical", "high"])
        |> Enum.map(&(to_string(&1) |> String.downcase())),
      max_active_per_tenant:
        config |> Keyword.get(:max_active_per_tenant, 2) |> bounded_positive_integer(2, 100),
      max_admissions_per_minute:
        config
        |> Keyword.get(:max_admissions_per_minute, 10)
        |> bounded_positive_integer(10, 1_000)
    }
  end

  defp bounded_positive_integer(value, _default, maximum)
       when is_integer(value) and value > 0,
       do: min(value, maximum)

  defp bounded_positive_integer(_value, default, _maximum), do: default

  defp receipt_metadata(run) do
    %{
      run_id: run.id,
      mode: :shadow,
      disposition: run.admission_disposition,
      reason: run.admission_reason,
      policy_version: run.policy_version
    }
  end

  defp safe_reason_atom("global_policy_off"), do: :policy_off
  defp safe_reason_atom("tenant_not_opted_in"), do: :tenant_not_opted_in
  defp safe_reason_atom(_reason), do: :disabled

  defp log_degraded_admission(alert, reason) do
    Logger.warning(
      "[ShadowOrchestrator] Shadow investigation admission degraded; alert remains persisted " <>
        "organization_id=#{alert.organization_id} alert_id=#{alert.id} reason=#{inspect(reason)}"
    )

    emit_admission_telemetry(:degraded, alert, %{reason: reason})
  end

  defp emit_admission_telemetry(status, alert, metadata) do
    :telemetry.execute(
      [:tamandua_server, :investigations, :shadow, :alert_admission],
      %{count: 1},
      Map.merge(metadata, %{
        status: status,
        organization_id: alert.organization_id,
        alert_id: alert.id,
        enforcement: :disabled
      })
    )
  end
end
