defmodule TamanduaServer.Telemetry.CorrelationExplorerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Repo

  alias TamanduaServer.Telemetry.{
    CorrelationExplorer,
    CorrelationFeedback,
    EventCorrelation,
    IncidentCandidate
  }

  describe "persist_analysis/3" do
    test "persists event correlations and incident candidates idempotently" do
      org = insert(:organization)
      agent = insert(:agent, organization: org)
      sha256 = String.duplicate("f", 64)

      events =
        for index <- 1..3 do
          insert(:event,
            agent: agent,
            organization: org,
            event_type: "file_create",
            timestamp: DateTime.add(DateTime.utc_now(), index, :second),
            payload: %{sha256: sha256}
          )
        end

      assert {:ok, %{correlations: correlations, incident_candidates: candidates}} =
               CorrelationExplorer.persist_analysis(events, org.id)

      assert length(correlations) == 3
      assert [%IncidentCandidate{supporting_entities: ["file_hash"]}] = candidates

      assert {:ok, %{correlations: correlations_again, incident_candidates: candidates_again}} =
               CorrelationExplorer.persist_analysis(events, org.id)

      assert length(correlations_again) == 3
      assert length(candidates_again) == 1
      assert Repo.aggregate(EventCorrelation, :count) == 3
      assert Repo.aggregate(IncidentCandidate, :count) == 1
    end

    test "stores event correlation pairs in a stable order" do
      org = insert(:organization)
      left_id = Ecto.UUID.generate()
      right_id = Ecto.UUID.generate()

      link = %{
        source: right_id,
        target: left_id,
        score: 70,
        relationTypes: ["process_tree"],
        reasons: ["same process tree"],
        sharedEntities: ["process"],
        timeDeltaMinutes: 1,
        scoring: %{"version" => "test"}
      }

      assert {:ok, [_]} = CorrelationExplorer.persist_event_correlations([link], org.id)

      reversed = %{link | source: left_id, target: right_id}
      assert {:ok, [_]} = CorrelationExplorer.persist_event_correlations([reversed], org.id)

      [stored] = Repo.all(EventCorrelation)
      [expected_source, expected_target] = Enum.sort([left_id, right_id])

      assert stored.source_event_id == expected_source
      assert stored.target_event_id == expected_target
      assert Repo.aggregate(EventCorrelation, :count) == 1
    end
  end

  describe "record_feedback/1" do
    test "records candidate feedback and updates candidate status" do
      org = insert(:organization)
      user = insert(:user, organization: org)

      candidate =
        insert_candidate(%{
          organization_id: org.id,
          event_ids: [Ecto.UUID.generate(), Ecto.UUID.generate()]
        })

      assert {:ok, %CorrelationFeedback{verdict: "false_positive"}} =
               CorrelationExplorer.record_feedback(%{
                 organization_id: org.id,
                 target_type: "incident_candidate",
                 target_id: candidate.id,
                 verdict: "false_positive",
                 notes: "Benign admin activity",
                 user_id: user.id
               })

      updated = Repo.get!(IncidentCandidate, candidate.id)
      assert updated.status == "false_positive"
      assert updated.feedback_verdict == "false_positive"
      assert updated.feedback_by_id == user.id
      assert updated.feedback_notes == "Benign admin activity"
    end

    test "records event correlation feedback and annotates correlation metadata" do
      org = insert(:organization)
      agent = insert(:agent, organization: org)
      sha256 = String.duplicate("a", 64)

      [left, right] =
        for index <- 1..2 do
          insert(:event,
            agent: agent,
            organization: org,
            event_type: "file_create",
            timestamp: DateTime.add(DateTime.utc_now(), index, :second),
            payload: %{sha256: sha256}
          )
        end

      {:ok, %{correlations: [correlation]}} =
        CorrelationExplorer.persist_analysis([left, right], org.id)

      assert {:ok, %CorrelationFeedback{verdict: "useful"}} =
               CorrelationExplorer.record_feedback(%{
                 organization_id: org.id,
                 target_type: "event_correlation",
                 target_id: correlation.id,
                 verdict: "useful",
                 notes: "Good pivot"
               })

      updated = Repo.get!(EventCorrelation, correlation.id)
      assert get_in(updated.metadata, ["feedback", "verdict"]) == "useful"
      assert get_in(updated.metadata, ["feedback", "notes"]) == "Good pivot"
    end
  end

  defp insert_candidate(attrs) do
    defaults = %{
      fingerprint: Ecto.UUID.generate(),
      title: "Related event cluster",
      status: "candidate",
      severity: "medium",
      score: 80,
      scoring_version: "correlation-scoring/v2",
      relation_types: ["file_hash"],
      supporting_entities: ["file_hash"],
      metadata: %{}
    }

    %IncidentCandidate{}
    |> IncidentCandidate.changeset(Map.merge(defaults, attrs))
    |> Repo.insert!()
  end
end
