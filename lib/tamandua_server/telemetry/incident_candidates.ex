defmodule TamanduaServer.Telemetry.IncidentCandidates do
  @moduledoc """
  Persistence and analyst feedback for correlation-derived incident candidates.

  Candidates are investigation objects, not alerts. Analyst feedback is stored
  here so future scoring/tuning can consume it without silently changing alert
  severity.
  """

  import Ecto.Query

  alias TamanduaServer.Repo
  alias TamanduaServer.Telemetry.IncidentCandidate

  def upsert_candidates(candidates, organization_id) when is_list(candidates) do
    candidates
    |> Enum.map(&candidate_attrs(&1, organization_id))
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&upsert_candidate/1)
  end

  def list(organization_id, opts \\ []) do
    limit = opts |> Keyword.get(:limit, 50) |> min(200)
    status = Keyword.get(opts, :status)

    IncidentCandidate
    |> where([c], c.organization_id == ^organization_id)
    |> maybe_status(status)
    |> order_by([c], desc: c.score, desc: c.updated_at)
    |> limit(^limit)
    |> Repo.all()
  end

  def get(id, organization_id) do
    Repo.get_by(IncidentCandidate, id: id, organization_id: organization_id)
  end

  def feedback(id, organization_id, attrs) do
    with %IncidentCandidate{} = candidate <-
           Repo.get_by(IncidentCandidate, id: id, organization_id: organization_id) do
      verdict = normalize_verdict(attrs["verdict"] || attrs[:verdict])

      status =
        case verdict do
          "true_positive" -> "promoted"
          "false_positive" -> "false_positive"
          "benign" -> "dismissed"
          "suspicious" -> "candidate"
          _ -> candidate.status
        end

      candidate
      |> IncidentCandidate.changeset(%{
        status: status,
        feedback_verdict: verdict,
        feedback_notes: attrs["notes"] || attrs[:notes],
        feedback_by_id: attrs["user_id"] || attrs[:user_id],
        feedback_at: DateTime.utc_now()
      })
      |> Repo.update()
    else
      nil -> {:error, :not_found}
    end
  end

  def serialize(%IncidentCandidate{} = candidate) do
    %{
      id: candidate.id,
      fingerprint: candidate.fingerprint,
      title: candidate.title,
      status: candidate.status,
      severity: candidate.severity,
      score: candidate.score,
      scoringVersion: candidate.scoring_version,
      eventIds: candidate.event_ids || [],
      relationTypes: candidate.relation_types || [],
      supportingEntities: candidate.supporting_entities || [],
      metadata: candidate.metadata || %{},
      feedbackVerdict: candidate.feedback_verdict,
      feedbackNotes: candidate.feedback_notes,
      feedbackAt: format_datetime(candidate.feedback_at),
      updatedAt: format_datetime(candidate.updated_at),
      insertedAt: format_datetime(candidate.inserted_at)
    }
  end

  defp upsert_candidate(attrs) do
    %IncidentCandidate{}
    |> IncidentCandidate.changeset(attrs)
    |> Repo.insert(
      on_conflict: [
        set: [
          title: attrs.title,
          severity: attrs.severity,
          score: attrs.score,
          scoring_version: attrs.scoring_version,
          event_ids: attrs.event_ids,
          relation_types: attrs.relation_types,
          supporting_entities: attrs.supporting_entities,
          metadata: attrs.metadata,
          updated_at: DateTime.utc_now()
        ]
      ],
      conflict_target: [:organization_id, :fingerprint]
    )
  end

  defp candidate_attrs(candidate, organization_id) when is_map(candidate) do
    event_ids = Map.get(candidate, :eventIds) || Map.get(candidate, "eventIds") || []

    relation_types =
      Map.get(candidate, :relationTypes) || Map.get(candidate, "relationTypes") || []

    supporting_entities =
      Map.get(candidate, :supportingEntities) || Map.get(candidate, "supportingEntities") || []

    scoring_version =
      Map.get(candidate, :scoringVersion) || Map.get(candidate, "scoringVersion") || "unknown"

    %{
      organization_id: organization_id,
      fingerprint: fingerprint(event_ids, relation_types, supporting_entities),
      title: Map.get(candidate, :title) || Map.get(candidate, "title") || "Correlation candidate",
      status: "candidate",
      severity:
        normalize_severity(Map.get(candidate, :severity) || Map.get(candidate, "severity")),
      score: normalize_score(Map.get(candidate, :score) || Map.get(candidate, "score")),
      scoring_version: scoring_version,
      event_ids: valid_uuids(event_ids),
      relation_types: Enum.map(relation_types, &to_string/1),
      supporting_entities: Enum.map(supporting_entities, &to_string/1),
      metadata: %{
        "source" => "timeline_correlation",
        "source_candidate_id" => Map.get(candidate, :id) || Map.get(candidate, "id")
      }
    }
  end

  defp candidate_attrs(_, _), do: nil

  defp fingerprint(event_ids, relation_types, supporting_entities) do
    material =
      [
        event_ids |> Enum.map(&to_string/1) |> Enum.sort() |> Enum.join(","),
        relation_types |> Enum.map(&to_string/1) |> Enum.sort() |> Enum.join(","),
        supporting_entities |> Enum.map(&to_string/1) |> Enum.sort() |> Enum.join(",")
      ]
      |> Enum.join("|")

    :crypto.hash(:sha256, material)
    |> Base.encode16(case: :lower)
  end

  defp valid_uuids(values) do
    values
    |> List.wrap()
    |> Enum.map(&to_string/1)
    |> Enum.filter(&(Ecto.UUID.cast(&1) != :error))
    |> Enum.uniq()
  end

  defp normalize_score(score) when is_integer(score), do: max(0, min(100, score))
  defp normalize_score(score) when is_float(score), do: score |> round() |> normalize_score()

  defp normalize_score(score) when is_binary(score) do
    case Integer.parse(score) do
      {value, _} -> normalize_score(value)
      _ -> 0
    end
  end

  defp normalize_score(_), do: 0

  defp normalize_severity(severity)
       when severity in ["critical", "high", "medium", "low", "info"],
       do: severity

  defp normalize_severity(severity) when is_atom(severity),
    do: normalize_severity(Atom.to_string(severity))

  defp normalize_severity(_), do: "info"

  defp normalize_verdict(verdict)
       when verdict in ["true_positive", "false_positive", "benign", "suspicious"],
       do: verdict

  defp normalize_verdict(verdict) when is_atom(verdict),
    do: normalize_verdict(Atom.to_string(verdict))

  defp normalize_verdict(_), do: nil

  defp maybe_status(query, nil), do: query
  defp maybe_status(query, ""), do: query
  defp maybe_status(query, status), do: where(query, [c], c.status == ^status)

  defp format_datetime(nil), do: nil
  defp format_datetime(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  defp format_datetime(%NaiveDateTime{} = dt),
    do: dt |> DateTime.from_naive!("Etc/UTC") |> DateTime.to_iso8601()
end
