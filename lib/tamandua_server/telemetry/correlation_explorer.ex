defmodule TamanduaServer.Telemetry.CorrelationExplorer do
  @moduledoc """
  Persistence boundary for correlation explorer results.

  This module persists conservative event-correlation output without creating
  alerts or changing event severity. It is deliberately idempotent so timeline
  or worker runs can safely repeat over the same event window.
  """

  import Ecto.Query, warn: false

  alias Ecto.Multi
  alias TamanduaServer.Repo

  alias TamanduaServer.Telemetry.{
    CorrelationEvidence,
    CorrelationFeedback,
    EventCorrelation,
    IncidentCandidate
  }

  @doc """
  Correlates events and persists both event links and incident candidates.
  """
  def persist_analysis(events, organization_id, opts \\ []) when is_list(events) do
    evidence = CorrelationEvidence.correlate_events(events, opts)

    with {:ok, correlations} <-
           persist_event_correlations(evidence.correlations, organization_id),
         {:ok, candidates} <-
           persist_incident_candidates(evidence.incident_candidates, organization_id) do
      {:ok,
       %{
         evidence: evidence,
         correlations: correlations,
         incident_candidates: candidates
       }}
    end
  end

  @doc """
  Upserts event correlation links produced by `CorrelationEvidence`.
  """
  def persist_event_correlations(correlations, organization_id) when is_list(correlations) do
    correlations
    |> Enum.reduce_while({:ok, []}, fn link, {:ok, persisted} ->
      case upsert_event_correlation(link, organization_id) do
        {:ok, correlation} -> {:cont, {:ok, [correlation | persisted]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, persisted} -> {:ok, Enum.reverse(persisted)}
      error -> error
    end
  end

  @doc """
  Upserts incident candidates produced by `CorrelationEvidence`.
  """
  def persist_incident_candidates(candidates, organization_id) when is_list(candidates) do
    candidates
    |> Enum.reduce_while({:ok, []}, fn candidate, {:ok, persisted} ->
      case upsert_incident_candidate(candidate, organization_id) do
        {:ok, incident_candidate} -> {:cont, {:ok, [incident_candidate | persisted]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, persisted} -> {:ok, Enum.reverse(persisted)}
      error -> error
    end
  end

  @doc """
  Records analyst feedback for an event correlation or incident candidate.
  """
  def record_feedback(attrs) when is_map(attrs) do
    attrs = normalize_feedback_attrs(attrs)

    Multi.new()
    |> Multi.insert(:feedback, CorrelationFeedback.changeset(%CorrelationFeedback{}, attrs))
    |> maybe_update_feedback_target(attrs)
    |> Repo.transaction()
    |> case do
      {:ok, %{feedback: feedback}} -> {:ok, feedback}
      {:error, _step, reason, _changes} -> {:error, reason}
    end
  end

  def list_incident_candidates(organization_id, opts \\ []) do
    limit = Keyword.get(opts, :limit, 50)
    status = Keyword.get(opts, :status)

    IncidentCandidate
    |> where([c], c.organization_id == ^organization_id)
    |> maybe_where_status(status)
    |> order_by([c], desc: c.score, desc: c.inserted_at)
    |> limit(^limit)
    |> Repo.all()
  end

  def list_feedback(organization_id, opts \\ []) do
    target_type = Keyword.get(opts, :target_type)
    target_id = Keyword.get(opts, :target_id)

    CorrelationFeedback
    |> where([f], f.organization_id == ^organization_id)
    |> maybe_where_target_type(target_type)
    |> maybe_where_target_id(target_id)
    |> order_by([f], desc: f.inserted_at)
    |> Repo.all()
  end

  defp upsert_event_correlation(link, organization_id) do
    [source_id, target_id] = Enum.sort([link.source, link.target])

    attrs = %{
      source_event_id: source_id,
      target_event_id: target_id,
      organization_id: organization_id,
      score: link.score,
      relation_types: link.relationTypes || [],
      reasons: link.reasons || [],
      shared_entities: link.sharedEntities || [],
      metadata: %{
        "time_delta_minutes" => link.timeDeltaMinutes,
        "scoring" => Map.get(link, :scoring, %{})
      }
    }

    %EventCorrelation{}
    |> EventCorrelation.changeset(attrs)
    |> Repo.insert(
      on_conflict:
        {:replace, [:score, :relation_types, :reasons, :shared_entities, :metadata, :updated_at]},
      conflict_target: [:source_event_id, :target_event_id]
    )
  end

  defp upsert_incident_candidate(candidate, organization_id) do
    event_ids = Map.get(candidate, :eventIds, [])

    attrs = %{
      organization_id: organization_id,
      fingerprint: incident_fingerprint(event_ids),
      title: Map.get(candidate, :title, "Related event cluster"),
      status: "candidate",
      severity: Map.get(candidate, :severity, "info"),
      score: Map.get(candidate, :score, 0),
      scoring_version: Map.get(candidate, :scoringVersion, "unknown"),
      event_ids: event_ids,
      relation_types: Map.get(candidate, :relationTypes, []),
      supporting_entities: Map.get(candidate, :supportingEntities, []),
      metadata: %{
        "source_id" => Map.get(candidate, :id),
        "event_count" => Map.get(candidate, :eventCount, length(event_ids))
      }
    }

    %IncidentCandidate{}
    |> IncidentCandidate.changeset(attrs)
    |> Repo.insert(
      on_conflict:
        {:replace,
         [
           :title,
           :severity,
           :score,
           :scoring_version,
           :event_ids,
           :relation_types,
           :supporting_entities,
           :metadata,
           :updated_at
         ]},
      conflict_target: [:organization_id, :fingerprint]
    )
  end

  defp maybe_update_feedback_target(multi, %{target_type: "incident_candidate"} = attrs) do
    Multi.update_all(
      multi,
      :target_update,
      from(c in IncidentCandidate,
        where: c.id == ^attrs.target_id and c.organization_id == ^attrs.organization_id
      ),
      set: [
        feedback_verdict: attrs.verdict,
        feedback_notes: attrs[:notes],
        feedback_by_id: attrs[:user_id],
        feedback_at: DateTime.utc_now() |> DateTime.truncate(:second),
        status: feedback_status(attrs.verdict)
      ]
    )
  end

  defp maybe_update_feedback_target(multi, %{target_type: "event_correlation"} = attrs) do
    feedback = %{
      "verdict" => attrs.verdict,
      "notes" => attrs[:notes],
      "user_id" => attrs[:user_id],
      "recorded_at" => DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()
    }

    query =
      from(c in EventCorrelation,
        where: c.id == ^attrs.target_id and c.organization_id == ^attrs.organization_id,
        update: [
          set: [
            metadata:
              fragment("COALESCE(?, '{}'::jsonb) || ?", c.metadata, ^%{"feedback" => feedback})
          ]
        ]
      )

    Multi.update_all(
      multi,
      :target_update,
      query,
      []
    )
  end

  defp normalize_feedback_attrs(attrs) do
    %{
      organization_id: value(attrs, :organization_id),
      target_type: value(attrs, :target_type),
      target_id: value(attrs, :target_id),
      verdict: value(attrs, :verdict),
      notes: value(attrs, :notes),
      user_id: value(attrs, :user_id),
      metadata: value(attrs, :metadata) || %{}
    }
  end

  defp incident_fingerprint(event_ids) do
    event_ids
    |> Enum.map(&to_string/1)
    |> Enum.sort()
    |> Enum.join(":")
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp feedback_status("false_positive"), do: "false_positive"
  defp feedback_status("benign"), do: "dismissed"
  defp feedback_status("true_positive"), do: "promoted"
  defp feedback_status("suspicious"), do: "promoted"
  defp feedback_status(_), do: "candidate"

  defp maybe_where_status(query, nil), do: query
  defp maybe_where_status(query, status), do: where(query, [c], c.status == ^status)

  defp maybe_where_target_type(query, nil), do: query

  defp maybe_where_target_type(query, target_type),
    do: where(query, [f], f.target_type == ^target_type)

  defp maybe_where_target_id(query, nil), do: query
  defp maybe_where_target_id(query, target_id), do: where(query, [f], f.target_id == ^target_id)

  defp value(%{} = map, key) when is_atom(key),
    do: Map.get(map, key) || Map.get(map, Atom.to_string(key))

  defp value(_, _), do: nil
end
