defmodule TamanduaServer.Repo.Migrations.HardenEvidenceSessionTenantRelationships do
  use Ecto.Migration

  @constraints [
    {:screen_capture_evidence_sessions, :evidence_sessions_agent_tenant_fkey},
    {:screen_capture_evidence_sessions, :evidence_sessions_mobile_command_tenant_fkey},
    {:screen_capture_evidence_sessions, :evidence_sessions_alert_tenant_fkey},
    {:screen_capture_evidence_sessions, :evidence_sessions_investigation_tenant_fkey},
    {:screen_capture_evidence_sessions, :evidence_sessions_case_tenant_fkey},
    {:screen_capture_artifacts, :screen_capture_artifacts_agent_tenant_fkey},
    {:screen_capture_artifacts, :screen_capture_artifacts_mobile_command_tenant_fkey},
    {:screen_capture_artifacts, :screen_capture_artifacts_session_tenant_agent_fkey},
    {:evidence_session_exports, :evidence_session_exports_session_tenant_fkey},
    {:evidence_session_diffs, :evidence_session_diffs_session_tenant_fkey},
    {:evidence_session_diffs, :evidence_session_diffs_left_artifact_scope_fkey},
    {:evidence_session_diffs, :evidence_session_diffs_right_artifact_scope_fkey}
  ]

  def up do
    # PostgreSQL requires an explicit unique key matching every referenced composite.
    # Keeping id first makes these indexes cheap to validate and preserves the existing
    # globally unique UUID access path.
    create(unique_index(:agents, [:id, :organization_id], name: :agents_id_organization_uidx))

    create(
      unique_index(:mdm_commands, [:id, :organization_id],
        name: :mdm_commands_id_organization_uidx
      )
    )

    create(unique_index(:alerts, [:id, :organization_id], name: :alerts_id_organization_uidx))

    create(
      unique_index(:investigations, [:id, :organization_id],
        name: :investigations_id_organization_uidx
      )
    )

    create(
      unique_index(:case_investigations, [:id, :organization_id],
        name: :case_investigations_id_organization_uidx
      )
    )

    create(
      unique_index(:screen_capture_evidence_sessions, [:id, :organization_id],
        name: :evidence_sessions_id_organization_uidx
      )
    )

    create(
      unique_index(:screen_capture_evidence_sessions, [:id, :organization_id, :agent_id],
        name: :evidence_sessions_id_organization_agent_uidx
      )
    )

    create(
      unique_index(
        :screen_capture_artifacts,
        [:id, :organization_id, :evidence_session_id],
        name: :screen_capture_artifacts_id_org_session_uidx
      )
    )

    add_foreign_keys_not_valid()

    create(
      constraint(:screen_capture_artifacts, :screen_capture_artifacts_session_frame_pair_check,
        check:
          "(evidence_session_id IS NULL AND frame_index IS NULL) OR (evidence_session_id IS NOT NULL AND frame_index IS NOT NULL)"
      )
    )

    create(
      constraint(:evidence_session_diffs, :evidence_session_diffs_distinct_artifacts_check,
        check: "left_artifact_id <> right_artifact_id"
      )
    )

    # NOT VALID avoids a long ACCESS EXCLUSIVE lock while each FK is installed. Validation
    # still runs in this migration, so deployment fails closed if historical cross-tenant
    # rows exist instead of silently grandfathering them.
    Enum.each(@constraints, fn {table, name} ->
      execute("ALTER TABLE #{table} VALIDATE CONSTRAINT #{name}")
    end)
  end

  def down do
    drop(constraint(:evidence_session_diffs, :evidence_session_diffs_distinct_artifacts_check))

    drop(
      constraint(:screen_capture_artifacts, :screen_capture_artifacts_session_frame_pair_check)
    )

    Enum.reverse(@constraints)
    |> Enum.each(fn {table, name} ->
      execute("ALTER TABLE #{table} DROP CONSTRAINT IF EXISTS #{name}")
    end)

    drop(
      index(:screen_capture_artifacts, [:id, :organization_id, :evidence_session_id],
        name: :screen_capture_artifacts_id_org_session_uidx
      )
    )

    drop(
      index(:screen_capture_evidence_sessions, [:id, :organization_id, :agent_id],
        name: :evidence_sessions_id_organization_agent_uidx
      )
    )

    drop(
      index(:screen_capture_evidence_sessions, [:id, :organization_id],
        name: :evidence_sessions_id_organization_uidx
      )
    )

    drop(
      index(:case_investigations, [:id, :organization_id],
        name: :case_investigations_id_organization_uidx
      )
    )

    drop(
      index(:investigations, [:id, :organization_id], name: :investigations_id_organization_uidx)
    )

    drop(index(:alerts, [:id, :organization_id], name: :alerts_id_organization_uidx))

    drop(index(:mdm_commands, [:id, :organization_id], name: :mdm_commands_id_organization_uidx))

    drop(index(:agents, [:id, :organization_id], name: :agents_id_organization_uidx))
  end

  defp add_foreign_keys_not_valid do
    execute("""
    ALTER TABLE screen_capture_evidence_sessions
      ADD CONSTRAINT evidence_sessions_agent_tenant_fkey
        FOREIGN KEY (agent_id, organization_id)
        REFERENCES agents (id, organization_id) NOT VALID,
      ADD CONSTRAINT evidence_sessions_mobile_command_tenant_fkey
        FOREIGN KEY (mobile_command_id, organization_id)
        REFERENCES mdm_commands (id, organization_id) NOT VALID,
      ADD CONSTRAINT evidence_sessions_alert_tenant_fkey
        FOREIGN KEY (alert_id, organization_id)
        REFERENCES alerts (id, organization_id) NOT VALID,
      ADD CONSTRAINT evidence_sessions_investigation_tenant_fkey
        FOREIGN KEY (investigation_id, organization_id)
        REFERENCES investigations (id, organization_id) NOT VALID,
      ADD CONSTRAINT evidence_sessions_case_tenant_fkey
        FOREIGN KEY (case_id, organization_id)
        REFERENCES case_investigations (id, organization_id) NOT VALID
    """)

    execute("""
    ALTER TABLE screen_capture_artifacts
      ADD CONSTRAINT screen_capture_artifacts_agent_tenant_fkey
        FOREIGN KEY (agent_id, organization_id)
        REFERENCES agents (id, organization_id) NOT VALID,
      ADD CONSTRAINT screen_capture_artifacts_mobile_command_tenant_fkey
        FOREIGN KEY (mobile_command_id, organization_id)
        REFERENCES mdm_commands (id, organization_id) NOT VALID,
      ADD CONSTRAINT screen_capture_artifacts_session_tenant_agent_fkey
        FOREIGN KEY (evidence_session_id, organization_id, agent_id)
        REFERENCES screen_capture_evidence_sessions (id, organization_id, agent_id) NOT VALID
    """)

    execute("""
    ALTER TABLE evidence_session_exports
      ADD CONSTRAINT evidence_session_exports_session_tenant_fkey
        FOREIGN KEY (evidence_session_id, organization_id)
        REFERENCES screen_capture_evidence_sessions (id, organization_id) NOT VALID
    """)

    execute("""
    ALTER TABLE evidence_session_diffs
      ADD CONSTRAINT evidence_session_diffs_session_tenant_fkey
        FOREIGN KEY (evidence_session_id, organization_id)
        REFERENCES screen_capture_evidence_sessions (id, organization_id) NOT VALID,
      ADD CONSTRAINT evidence_session_diffs_left_artifact_scope_fkey
        FOREIGN KEY (left_artifact_id, organization_id, evidence_session_id)
        REFERENCES screen_capture_artifacts (id, organization_id, evidence_session_id) NOT VALID,
      ADD CONSTRAINT evidence_session_diffs_right_artifact_scope_fkey
        FOREIGN KEY (right_artifact_id, organization_id, evidence_session_id)
        REFERENCES screen_capture_artifacts (id, organization_id, evidence_session_id) NOT VALID
    """)
  end
end
