defmodule TamanduaServer.ForensicsTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Forensics
  alias TamanduaServer.Forensics.Artifact
  alias TamanduaServer.{Agents, Organizations, Accounts}

  setup do
    # Create organization
    {:ok, org} = Organizations.create_organization(%{
      name: "Test Org",
      slug: "test-org"
    })

    # Create user
    {:ok, user} = Accounts.create_user(%{
      email: "test@example.com",
      name: "Test User",
      organization_id: org.id
    })

    # Create agent
    {:ok, agent} = Agents.create_agent(%{
      id: "agent-#{:rand.uniform(1000000)}",
      hostname: "test-host",
      os_type: "linux",
      os_version: "Ubuntu 22.04",
      ip_address: "192.168.1.100",
      organization_id: org.id
    })

    {:ok, org: org, user: user, agent: agent}
  end

  describe "request_collection/4" do
    test "creates artifact collection request", %{agent: agent, user: user} do
      opts = [
        requested_by_id: user.id,
        requested_by_name: user.name,
        compression: "gzip"
      ]

      assert {:ok, artifact} = Forensics.request_collection(
        agent.id,
        "memory_dump",
        %{},
        opts
      )

      assert artifact.artifact_type == "memory_dump"
      assert artifact.agent_id == agent.id
      assert artifact.status == "queued"
      assert artifact.compression_type == "gzip"
      assert artifact.requested_by_id == user.id
    end

    test "validates artifact type", %{agent: agent, user: user} do
      assert {:error, changeset} = Forensics.request_collection(
        agent.id,
        "invalid_type",
        %{},
        [requested_by_id: user.id]
      )

      assert "is invalid" in errors_on(changeset).artifact_type
    end

    test "adds chain of custody entry", %{agent: agent, user: user} do
      {:ok, artifact} = Forensics.request_collection(
        agent.id,
        "process_list",
        %{},
        [requested_by_id: user.id, requested_by_name: user.name]
      )

      artifact = Repo.get!(Artifact, artifact.id)
      assert length(artifact.custody_chain) > 0

      first_entry = List.first(artifact.custody_chain)
      assert first_entry["action"] == "collection_requested"
      assert first_entry["user"] == user.name
    end
  end

  describe "request_batch_collection/3" do
    test "creates multiple artifacts with shared case ID", %{agent: agent, user: user} do
      artifact_configs = [
        %{artifact_type: "memory_dump", parameters: %{}},
        %{artifact_type: "process_list", parameters: %{}},
        %{artifact_type: "network_capture", parameters: %{}}
      ]

      {:ok, artifacts, case_id} = Forensics.request_batch_collection(
        agent.id,
        artifact_configs,
        [requested_by_id: user.id]
      )

      assert length(artifacts) == 3
      assert String.starts_with?(case_id, "CASE-")

      for artifact <- artifacts do
        assert artifact.case_id == case_id
        assert artifact.agent_id == agent.id
      end
    end

    test "uses provided case ID", %{agent: agent, user: user} do
      artifact_configs = [
        %{artifact_type: "memory_dump", parameters: %{}}
      ]

      custom_case_id = "CASE-CUSTOM-123"

      {:ok, artifacts, case_id} = Forensics.request_batch_collection(
        agent.id,
        artifact_configs,
        [requested_by_id: user.id, case_id: custom_case_id]
      )

      assert case_id == custom_case_id
      assert List.first(artifacts).case_id == custom_case_id
    end
  end

  describe "update_progress/2" do
    setup %{agent: agent, user: user} do
      {:ok, artifact} = Forensics.request_collection(
        agent.id,
        "memory_dump",
        %{},
        [requested_by_id: user.id]
      )

      {:ok, artifact: artifact}
    end

    test "updates progress percentage", %{artifact: artifact} do
      {:ok, updated} = Forensics.update_progress(artifact.id, %{
        progress_percent: 50,
        progress_bytes: 1024 * 1024 * 500,
        total_bytes: 1024 * 1024 * 1000,
        eta_seconds: 120
      })

      assert updated.progress_percent == 50
      assert updated.progress_bytes == 1024 * 1024 * 500
      assert updated.eta_seconds == 120
    end

    test "validates progress percent range", %{artifact: artifact} do
      assert {:error, changeset} = Forensics.update_progress(artifact.id, %{
        progress_percent: 150
      })

      assert "must be less than or equal to 100" in errors_on(changeset).progress_percent
    end
  end

  describe "mark_completed/2" do
    setup %{agent: agent, user: user} do
      {:ok, artifact} = Forensics.request_collection(
        agent.id,
        "memory_dump",
        %{},
        [requested_by_id: user.id]
      )

      artifact
      |> Artifact.mark_started()
      |> Repo.update!()

      {:ok, artifact: Repo.reload!(artifact)}
    end

    test "marks artifact as completed with metadata", %{artifact: artifact} do
      completion_data = %{
        file_path: "/tmp/memory_dump.bin",
        file_size: 1024 * 1024 * 1000,
        sha256_hash: "abc123def456",
        compression_type: "gzip"
      }

      {:ok, updated} = Forensics.mark_completed(artifact.id, completion_data)

      assert updated.status == "completed"
      assert updated.file_path == "/tmp/memory_dump.bin"
      assert updated.file_size == 1024 * 1024 * 1000
      assert updated.sha256_hash == "abc123def456"
      assert updated.progress_percent == 100
      assert updated.evidence_integrity_verified == true
      refute is_nil(updated.collection_completed_at)
      refute is_nil(updated.collection_duration_ms)
    end

    test "adds completion custody entry", %{artifact: artifact} do
      completion_data = %{
        file_path: "/tmp/test.bin",
        file_size: 1024,
        sha256_hash: "hash123"
      }

      {:ok, updated} = Forensics.mark_completed(artifact.id, completion_data)

      artifact = Repo.reload!(updated)
      last_entry = List.last(artifact.custody_chain)

      assert last_entry["action"] == "collection_completed"
      assert last_entry["sha256"] == "hash123"
    end
  end

  describe "mark_failed/3" do
    setup %{agent: agent, user: user} do
      {:ok, artifact} = Forensics.request_collection(
        agent.id,
        "memory_dump",
        %{},
        [requested_by_id: user.id]
      )

      {:ok, artifact: artifact}
    end

    test "marks artifact as failed with error details", %{artifact: artifact} do
      {:ok, updated} = Forensics.mark_failed(
        artifact.id,
        "Collection timed out",
        %{"timeout_seconds" => 3600}
      )

      assert updated.status == "failed"
      assert updated.error_message == "Collection timed out"
      assert updated.error_details["timeout_seconds"] == 3600
    end
  end

  describe "cancel_collection/1" do
    test "cancels pending collection", %{agent: agent, user: user} do
      {:ok, artifact} = Forensics.request_collection(
        agent.id,
        "memory_dump",
        %{},
        [requested_by_id: user.id]
      )

      {:ok, updated} = Forensics.cancel_collection(artifact.id)

      assert updated.status == "cancelled"
    end

    test "cannot cancel in-progress collection", %{agent: agent, user: user} do
      {:ok, artifact} = Forensics.request_collection(
        agent.id,
        "memory_dump",
        %{},
        [requested_by_id: user.id]
      )

      artifact
      |> Artifact.mark_started()
      |> Repo.update!()

      assert {:error, :cannot_cancel_in_progress} = Forensics.cancel_collection(artifact.id)
    end
  end

  describe "list_artifacts/2" do
    setup %{agent: agent, user: user} do
      # Create multiple artifacts
      {:ok, artifact1} = Forensics.request_collection(
        agent.id,
        "memory_dump",
        %{},
        [requested_by_id: user.id]
      )

      {:ok, artifact2} = Forensics.request_collection(
        agent.id,
        "process_list",
        %{},
        [requested_by_id: user.id]
      )

      artifact2
      |> Artifact.mark_started()
      |> Repo.update!()

      artifact1
      |> Artifact.mark_completed(%{
        file_path: "/tmp/test.bin",
        file_size: 1024,
        sha256_hash: "hash123"
      })
      |> Repo.update!()

      {:ok, artifact1: artifact1, artifact2: artifact2}
    end

    test "lists all artifacts for organization", %{agent: agent} do
      artifacts = Forensics.list_artifacts(%{organization_id: agent.organization_id})

      assert length(artifacts) >= 2
    end

    test "filters by status", %{agent: agent} do
      completed = Forensics.list_artifacts(%{
        organization_id: agent.organization_id,
        status: "completed"
      })

      assert length(completed) >= 1
      assert Enum.all?(completed, fn a -> a.status == "completed" end)
    end

    test "filters by agent", %{agent: agent} do
      artifacts = Forensics.list_artifacts(%{agent_id: agent.id})

      assert length(artifacts) >= 2
      assert Enum.all?(artifacts, fn a -> a.agent_id == agent.id end)
    end
  end

  describe "get_organization_stats/1" do
    setup %{agent: agent, user: user} do
      # Create artifacts with different statuses
      {:ok, pending} = Forensics.request_collection(
        agent.id,
        "memory_dump",
        %{},
        [requested_by_id: user.id]
      )

      {:ok, collecting} = Forensics.request_collection(
        agent.id,
        "process_list",
        %{},
        [requested_by_id: user.id]
      )

      collecting
      |> Artifact.mark_started()
      |> Repo.update!()

      {:ok, completed} = Forensics.request_collection(
        agent.id,
        "network_capture",
        %{},
        [requested_by_id: user.id]
      )

      completed
      |> Artifact.mark_started()
      |> then(fn c ->
        Artifact.mark_completed(c, %{
          file_path: "/tmp/test.pcap",
          file_size: 2048,
          sha256_hash: "hash456"
        })
      end)
      |> Repo.update!()

      :ok
    end

    test "returns accurate statistics", %{agent: agent} do
      stats = Forensics.get_organization_stats(agent.organization_id)

      assert stats.total >= 3
      assert stats.pending >= 1
      assert stats.in_progress >= 1
      assert stats.completed >= 1
      assert stats.total_size_bytes >= 2048
    end
  end

  describe "chain of custody" do
    test "tracks full artifact lifecycle", %{agent: agent, user: user} do
      # Request collection
      {:ok, artifact} = Forensics.request_collection(
        agent.id,
        "memory_dump",
        %{},
        [requested_by_id: user.id, requested_by_name: user.name]
      )

      # Start collection
      artifact = artifact
      |> Artifact.mark_started()
      |> Repo.update!()

      # Complete collection
      artifact = artifact
      |> Artifact.mark_completed(%{
        file_path: "/tmp/dump.mem",
        file_size: 1024 * 1024,
        sha256_hash: "abc123"
      })
      |> Repo.update!()

      # Add access log
      artifact = artifact
      |> Artifact.add_custody_entry(%{
        "action" => "downloaded",
        "user" => "analyst@example.com"
      })
      |> Repo.update!()

      artifact = Repo.reload!(artifact)

      assert length(artifact.custody_chain) >= 3

      actions = Enum.map(artifact.custody_chain, fn entry -> entry["action"] end)
      assert "collection_requested" in actions
      assert "collection_completed" in actions
      assert "downloaded" in actions
    end
  end

  describe "integrity verification" do
    setup %{agent: agent, user: user} do
      {:ok, artifact} = Forensics.request_collection(
        agent.id,
        "process_list",
        %{},
        [requested_by_id: user.id]
      )

      artifact
      |> Artifact.mark_started()
      |> then(fn a ->
        Artifact.mark_completed(a, %{
          file_path: "/tmp/processes.json",
          file_size: 512,
          sha256_hash: "sha256hash123"
        })
      end)
      |> Repo.update!()

      {:ok, artifact: Repo.reload!(artifact)}
    end

    test "marks artifact as verified", %{artifact: artifact} do
      {:ok, :verified} = Forensics.verify_integrity(artifact.id)

      artifact = Repo.reload!(artifact)
      assert artifact.evidence_integrity_verified == true
    end
  end
end
